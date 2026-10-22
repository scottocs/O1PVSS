//! Shared polynomial/LDEI arithmetic for the two comparison baselines.
//! Additive notation; evaluations use party indices 1..=n, secrets 0,-1,... .
use super::context;
use ark_ec::PrimeGroup;
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{rand::RngCore, UniformRand, Zero};
use std::{collections::HashSet, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidParameters,
    InvalidProof,
    InvalidKey,
    InvalidShares,
    CommitmentMismatch,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Immutable public registry. Constructors bind every parameter and key into a
/// cached transcript digest. A network/PKI registration protocol is not supplied.
#[derive(Clone)]
pub struct Parameters<G: PrimeGroup> {
    pub(crate) generator: G,
    pub(crate) public_keys: Vec<G>,
    pub(crate) threshold: usize,
    pub(crate) batch_size: usize,
    pub(crate) origin_base: Option<G>,
    digest: [u8; 32],
    epoch: u64,
    domain: &'static [u8],
    evaluation_points: std::sync::Arc<Vec<G::ScalarField>>,
}
#[derive(Clone)]
pub struct SecretKey<G: PrimeGroup> {
    id: usize,
    value: G::ScalarField,
    generator: G,
    public_key: G,
}
impl<G: ark_ec::CurveGroup> SecretKey<G> {
    pub fn id(&self) -> usize {
        self.id
    }
    /// Independent local key generation. `id` is a public evaluation index.
    pub fn generate<R: RngCore>(generator: G, id: usize, rng: &mut R) -> Result<(Self, G), Error> {
        if generator.is_zero() || id == 0 {
            return Err(Error::InvalidKey);
        }
        let mut value = G::ScalarField::rand(rng);
        while value.is_zero() {
            value = G::ScalarField::rand(rng);
        }
        let public_key = generator * value;
        Ok((
            Self {
                id,
                value,
                generator,
                public_key,
            },
            public_key,
        ))
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PolynomialProof<F: PrimeField> {
    pub challenge: F,
    /// Exactly `threshold` coefficients, including any trailing zeroes.
    pub response: Vec<F>,
}
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Sharing<G: PrimeGroup> {
    /// Present only for pre-constructed PVSS: origin_base * f(0).
    pub preconstruction: Option<G>,
    pub encrypted_shares: Vec<G>,
    pub proof: PolynomialProof<G::ScalarField>,
}
/// Compact Fiat--Shamir Chaum--Pedersen proof (challenge, response).
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DecryptionShare<G: PrimeGroup> {
    pub id: usize,
    pub value: G,
    pub challenge: G::ScalarField,
    pub response: G::ScalarField,
}

/// A sharing that has passed its LDEI proof. Borrows prevent changing the
/// statement/registry while cached per-instance proof context is in use.
pub struct VerifiedSharing<'a, G: ark_ec::CurveGroup> {
    pp: &'a Parameters<G>,
    sharing: &'a Sharing<G>,
    instance: [u8; 32],
    fixed: std::sync::Arc<crate::arithmetic::FixedBases<G>>,
}
/// Reusable interpolation for one ordered qualified index set. Computing this
/// plan is offline work; `reconstruct` performs only the group interpolation.
pub struct ReconstructionPlan<F: PrimeField> {
    ids: Vec<usize>,
    weights: std::sync::Arc<Vec<Vec<F>>>,
    setup: [u8; 32],
}

pub(crate) fn evaluate<F: PrimeField>(p: &[F], x: F) -> F {
    p.iter().rev().fold(F::zero(), |v, a| v * x + a)
}
fn constrained_polynomial<F: PrimeField, R: RngCore>(
    secrets: &[F],
    threshold: usize,
    rng: &mut R,
) -> Vec<F> {
    let mut p = vec![F::zero(); threshold];
    let mut vanishing = vec![F::from(1u64)];
    for (j, secret) in secrets.iter().enumerate() {
        let x = -F::from(j as u64);
        let delta = (*secret - evaluate(&p, x)) * evaluate(&vanishing, x).inverse().unwrap();
        for (a, b) in p.iter_mut().zip(&vanishing) {
            *a += delta * b;
        }
        let mut next = vec![F::zero(); vanishing.len() + 1];
        for (k, a) in vanishing.iter().enumerate() {
            next[k] -= x * a;
            next[k + 1] += a;
        }
        vanishing = next;
    }
    // p + prod_j (X+j) * r; r has threshold-batch_size uniform coefficients.
    for k in 0..threshold - secrets.len() {
        let r = F::rand(rng);
        for (j, a) in vanishing.iter().enumerate() {
            p[k + j] += r * a;
        }
    }
    p
}

impl<G: ark_ec::CurveGroup> Parameters<G> {
    fn fixed_bases(&self) -> std::sync::Arc<crate::arithmetic::FixedBases<G>> {
        let mut bases = vec![self.generator];
        bases.extend_from_slice(&self.public_keys);
        bases.extend(self.origin_base);
        crate::arithmetic::fixed_bases(&bases)
    }
    pub(crate) fn new(
        domain: &'static [u8],
        generator: G,
        public_keys: Vec<G>,
        threshold: usize,
        batch_size: usize,
        origin_base: Option<G>,
        epoch: u64,
    ) -> Result<Self, Error> {
        let n = public_keys.len();
        if generator.check().is_err()
            || public_keys.check().is_err()
            || origin_base.check().is_err()
            || generator.is_zero()
            || public_keys.iter().any(Zero::is_zero)
            || origin_base.is_some_and(|g| g.is_zero())
            || threshold < 2
            || threshold > n
            || batch_size == 0
            || batch_size >= threshold
            || (origin_base.is_some() && batch_size != 1)
            || n.checked_add(batch_size)
                .is_none_or(|v| v > u32::MAX as usize)
            || G::ScalarField::MODULUS_BIT_SIZE <= 32
        {
            return Err(Error::InvalidParameters);
        }
        let digest = context::digest(
            domain,
            &(
                generator,
                public_keys.clone(),
                (threshold as u64, batch_size as u64),
                origin_base,
                epoch,
            ),
        );
        Ok(Self {
            generator,
            public_keys,
            threshold,
            batch_size,
            origin_base,
            digest,
            epoch,
            domain,
            evaluation_points: crate::cache::evaluation_points(n, 1),
        })
    }
    pub fn n(&self) -> usize {
        self.public_keys.len()
    }
    pub fn threshold(&self) -> usize {
        self.threshold
    }
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
    /// Packed-polynomial privacy bound: this many revealed scalar shares leave
    /// the secret vector hidden. Computational assumptions are scheme-specific.
    pub fn privacy_threshold(&self) -> usize {
        self.threshold - self.batch_size
    }
    pub fn generator(&self) -> G {
        self.generator
    }
    pub fn public_keys(&self) -> &[G] {
        &self.public_keys
    }
    pub fn preconstruction_base(&self) -> Option<G> {
        self.origin_base
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn equations(&self, sharing: &Sharing<G>) -> Result<Vec<(G, G::ScalarField, G)>, Error> {
        if sharing.encrypted_shares.len() != self.n()
            || sharing.proof.response.len() != self.threshold
            || sharing.preconstruction.is_some() != self.origin_base.is_some()
        {
            return Err(Error::InvalidProof);
        }
        let mut equations = Vec::with_capacity(self.n() + 1);
        if let (Some(base), Some(y)) = (self.origin_base, sharing.preconstruction) {
            equations.push((base, G::ScalarField::zero(), y));
        }
        equations.extend(
            self.public_keys
                .iter()
                .zip(&sharing.encrypted_shares)
                .enumerate()
                .map(|(i, (pk, y))| (*pk, self.evaluation_points[i], *y)),
        );
        Ok(equations)
    }
    fn proof_challenge(&self, sharing: &Sharing<G>, commitments: &[G]) -> G::ScalarField {
        let mut tr = context::transcript(self.domain, &self.digest, self.epoch);
        context::append(&mut tr, b"preconstruction", &sharing.preconstruction);
        context::append(&mut tr, b"encrypted-shares", &sharing.encrypted_shares);
        context::append(&mut tr, b"commitments", &commitments.to_vec());
        context::challenge(&mut tr)
    }
    pub(crate) fn share<R: RngCore>(
        &self,
        secrets: &[G::ScalarField],
        expected: Option<G>,
        rng: &mut R,
    ) -> Result<Sharing<G>, Error> {
        let fixed = self.fixed_bases();
        if secrets.len() != self.batch_size || expected.is_some() != self.origin_base.is_some() {
            return Err(Error::InvalidParameters);
        }
        if let Some(base) = self.origin_base {
            if Some(fixed.mul(base, secrets[0])) != expected {
                return Err(Error::CommitmentMismatch);
            }
        }
        let p = constrained_polynomial(secrets, self.threshold, rng);
        let r: Vec<_> = (0..self.threshold)
            .map(|_| G::ScalarField::rand(rng))
            .collect();
        let encrypted_shares = self
            .public_keys
            .iter()
            .enumerate()
            .map(|(i, pk)| fixed.mul(*pk, evaluate(&p, self.evaluation_points[i])))
            .collect();
        let mut sharing = Sharing {
            preconstruction: expected,
            encrypted_shares,
            proof: PolynomialProof {
                challenge: G::ScalarField::zero(),
                response: vec![G::ScalarField::zero(); self.threshold],
            },
        };
        let commitments: Vec<_> = self
            .equations(&sharing)?
            .iter()
            .map(|(base, x, _)| fixed.mul(*base, evaluate(&r, *x)))
            .collect();
        let c = self.proof_challenge(&sharing, &commitments);
        sharing.proof = PolynomialProof {
            challenge: c,
            response: p.iter().zip(&r).map(|(a, b)| c * a + b).collect(),
        };
        Ok(sharing)
    }
    pub(crate) fn validate<'a>(
        &'a self,
        sharing: &'a Sharing<G>,
        expected: Option<G>,
    ) -> Result<VerifiedSharing<'a, G>, Error> {
        if sharing.check().is_err() {
            return Err(Error::InvalidProof);
        }
        if sharing.preconstruction != expected {
            return Err(Error::CommitmentMismatch);
        }
        let fixed = self.fixed_bases();
        let commitments: Vec<_> = self
            .equations(sharing)?
            .iter()
            .map(|(base, x, y)| {
                fixed.mul(*base, evaluate(&sharing.proof.response, *x))
                    - *y * sharing.proof.challenge
            })
            .collect();
        if self.proof_challenge(sharing, &commitments) != sharing.proof.challenge {
            return Err(Error::InvalidProof);
        }
        let instance = context::digest(
            b"ldeipoly-accepted-instance",
            &(self.digest, sharing.clone()),
        );
        Ok(VerifiedSharing {
            pp: self,
            sharing,
            instance,
            fixed,
        })
    }
    pub fn prepare_reconstruction(
        &self,
        ids: &[usize],
    ) -> Result<ReconstructionPlan<G::ScalarField>, Error> {
        let mut seen = HashSet::new();
        if ids.len() < self.threshold
            || ids
                .iter()
                .any(|i| *i == 0 || *i > self.n() || !seen.insert(*i))
        {
            return Err(Error::InvalidShares);
        }
        let xs: Vec<_> = ids.iter().map(|i| self.evaluation_points[*i - 1]).collect();
        let targets: Vec<_> = (0..self.batch_size)
            .map(|j| -G::ScalarField::from(j as u64))
            .collect();
        let weights =
            crate::cache::interpolation_weights(&xs, &targets).ok_or(Error::InvalidShares)?;
        Ok(ReconstructionPlan {
            ids: ids.to_vec(),
            weights,
            setup: self.digest,
        })
    }
}

impl<'a, G: ark_ec::CurveGroup> VerifiedSharing<'a, G> {
    fn decryption_challenge(&self, id: usize, value: G, a: G, b: G) -> G::ScalarField {
        let mut tr =
            context::transcript(b"ldeipoly-share-decryption", &self.instance, self.pp.epoch);
        tr.append_u64(b"party", id as u64);
        context::append(&mut tr, b"decrypted-share", &value);
        context::append(&mut tr, b"commitment-1", &a);
        context::append(&mut tr, b"commitment-2", &b);
        context::challenge(&mut tr)
    }
    /// Decrypt after public sharing verification; does not repeat that proof.
    pub fn pre_recon<R: RngCore>(
        &self,
        key: &SecretKey<G>,
        rng: &mut R,
    ) -> Result<DecryptionShare<G>, Error> {
        if !self.pp.validate_key(key) {
            return Err(Error::InvalidKey);
        }
        let y = self.sharing.encrypted_shares[key.id - 1];
        let value = y * key.value.inverse().ok_or(Error::InvalidKey)?;
        let r = G::ScalarField::rand(rng);
        let challenge = self.decryption_challenge(
            key.id,
            value,
            self.fixed.mul(self.pp.generator, r),
            value * r,
        );
        Ok(DecryptionShare {
            id: key.id,
            value,
            challenge,
            response: r + challenge * key.value,
        })
    }
    pub fn dec_vrf(&self, share: &DecryptionShare<G>) -> bool {
        if share.id == 0 || share.id > self.pp.n() || share.check().is_err() {
            return false;
        }
        let a = self.fixed.mul(self.pp.generator, share.response)
            - self
                .fixed
                .mul(self.pp.public_keys[share.id - 1], share.challenge);
        let b = share.value * share.response
            - self.sharing.encrypted_shares[share.id - 1] * share.challenge;
        self.decryption_challenge(share.id, share.value, a, b) == share.challenge
    }
    /// Combine previously verified shares in the exact order of the plan.
    /// Verification is deliberately separate from interpolation/timing.
    pub fn reconstruct(
        &self,
        shares: &[(usize, G)],
        plan: &ReconstructionPlan<G::ScalarField>,
    ) -> Result<Vec<G>, Error>
    where
        G: ark_ec::CurveGroup,
    {
        if plan.setup != self.pp.digest
            || shares.len() != plan.ids.len()
            || shares
                .iter()
                .zip(&plan.ids)
                .any(|((i, s), j)| i != j || s.check().is_err())
        {
            return Err(Error::InvalidShares);
        }
        let bases: Vec<_> = shares.iter().map(|(_, s)| *s).collect();
        Ok(plan
            .weights
            .iter()
            .map(|row| crate::arithmetic::public_msm(&bases, row))
            .collect())
    }
    /// ALBATROSS LocalLDEI reconstruction check (Figs. 3,6). The share values
    /// must already have passed dec_vrf. Verifier randomness must be fresh.
    pub fn verify_reconstruction<R: RngCore>(
        &self,
        shares: &[(usize, G)],
        outputs: &[G],
        rng: &mut R,
    ) -> bool {
        let mut seen = HashSet::new();
        if outputs.len() != self.pp.batch_size
            || shares.len() < self.pp.threshold
            || shares
                .iter()
                .any(|(id, _)| *id == 0 || *id > self.pp.n() || !seen.insert(*id))
        {
            return false;
        }
        let mut points: Vec<_> = outputs
            .iter()
            .enumerate()
            .map(|(j, y)| (-G::ScalarField::from(j as u64), *y))
            .collect();
        points.extend(
            shares
                .iter()
                .map(|(i, y)| (G::ScalarField::from(*i as u64), *y)),
        );
        let mut random: Vec<_> = (0..points.len() - self.pp.threshold)
            .map(|_| G::ScalarField::rand(rng))
            .collect();
        while random.iter().all(Zero::is_zero) {
            random
                .iter_mut()
                .for_each(|v| *v = G::ScalarField::rand(rng));
        }
        points
            .iter()
            .enumerate()
            .fold(G::zero(), |acc, (i, (x, y))| {
                let denominator = points
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .fold(G::ScalarField::from(1u64), |v, (_, (other, _))| {
                        v * (*x - other)
                    });
                acc + *y * (evaluate(&random, *x) * denominator.inverse().unwrap())
            })
            .is_zero()
    }
}
impl<G: ark_ec::CurveGroup> Parameters<G> {
    pub fn validate_key(&self, key: &SecretKey<G>) -> bool {
        key.id != 0
            && key.id <= self.n()
            && !key.value.is_zero()
            && key.generator == self.generator
            && key.public_key == self.public_keys[key.id - 1]
    }
}

pub(crate) fn local_setup<G: ark_ec::CurveGroup, R: RngCore>(
    domain: &'static [u8],
    n: usize,
    threshold: usize,
    batch_size: usize,
    origin_base: Option<G>,
    epoch: u64,
    rng: &mut R,
) -> Result<(Parameters<G>, Vec<SecretKey<G>>), Error> {
    // Check sizes before allocations. The same validation runs on the registry.
    if n < 2
        || threshold < 2
        || threshold > n
        || batch_size == 0
        || batch_size >= threshold
        || n > u32::MAX as usize
    {
        return Err(Error::InvalidParameters);
    }
    let generator = G::generator();
    let pairs: Vec<_> = (1..=n)
        .map(|id| SecretKey::generate(generator, id, rng).unwrap())
        .collect();
    let (keys, pks) = pairs.into_iter().unzip();
    let pp = Parameters::new(
        domain,
        generator,
        pks,
        threshold,
        batch_size,
        origin_base,
        epoch,
    )?;
    Ok((pp, keys))
}
