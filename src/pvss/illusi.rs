//! Illusi: Bacho--Chen--Loss, CRYPTO 2026, Section 4.2, equations (1),(2).
//! Pairing-free DDH construction; `threshold` denotes the number of recovery
//! shares (source t+1). Linear-relation NIZKs use compact Fiat--Shamir Schnorr
//! proofs. This is a local arithmetic implementation, not a network/PKI layer.
pub use super::ldeipoly::Error;
use super::{context, ldeipoly::evaluate};
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{rand::RngCore, UniformRand, Zero};
use std::{collections::HashSet, sync::Arc};

#[derive(Clone)]
pub struct Parameters<G: PrimeGroup> {
    g: G,
    h: G,
    u: G,
    keys: Vec<G>,
    threshold: usize,
    digest: [u8; 32],
    points: Arc<Vec<G::ScalarField>>,
    dual_weights: Arc<Vec<G::ScalarField>>,
    encryption_bases: Vec<[[G; 2]; 4]>,
}
pub struct SecretKey<G: PrimeGroup> {
    id: usize,
    x: G::ScalarField,
    y: G::ScalarField,
    setup: [u8; 32],
}
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct LinearProof<F: PrimeField> {
    pub challenge: F,
    pub response: [F; 2],
}
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Sharing<G: PrimeGroup> {
    /// g^{a(i)} for i=0,...,n; the output secret is h^{a(0)}.
    pub commitments: Vec<G>,
    pub ciphertexts: Vec<[G; 3]>,
    pub proofs: Vec<LinearProof<G::ScalarField>>,
}
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DecryptionShare<G: PrimeGroup> {
    pub id: usize,
    pub value: G,
    pub proof: LinearProof<G::ScalarField>,
}
pub struct VerifiedSharing<'a, G: ark_ec::CurveGroup> {
    pp: &'a Parameters<G>,
    sharing: &'a Sharing<G>,
    fixed: Arc<crate::arithmetic::FixedBases<G>>,
}
pub struct ReconstructionPlan<F: PrimeField> {
    ids: Vec<usize>,
    weights: Arc<Vec<Vec<F>>>,
    setup: [u8; 32],
}

fn linear<G: ark_ec::CurveGroup>(
    row: &[G; 2],
    x: &[G::ScalarField; 2],
    fixed: &crate::arithmetic::FixedBases<G>,
) -> G {
    row.iter()
        .zip(x)
        .filter(|(b, _)| !b.is_zero())
        .fold(G::zero(), |s, (b, x)| s + fixed.mul(*b, *x))
}
fn challenge<G: PrimeGroup>(
    domain: &'static [u8],
    setup: &[u8; 32],
    id: usize,
    bases: &[[G; 2]],
    targets: &[G],
    commitments: &[G],
) -> G::ScalarField {
    let mut tr = context::transcript(domain, setup, 0);
    tr.append_u64(b"party", id as u64);
    context::append(&mut tr, b"bases", &bases.to_vec());
    context::append(&mut tr, b"targets", &targets.to_vec());
    context::append(&mut tr, b"commitments", &commitments.to_vec());
    context::challenge(&mut tr)
}
fn prove<G: ark_ec::CurveGroup, R: RngCore>(
    domain: &'static [u8],
    setup: &[u8; 32],
    id: usize,
    bases: &[[G; 2]],
    targets: &[G],
    witness: [G::ScalarField; 2],
    rng: &mut R,
    fixed: &crate::arithmetic::FixedBases<G>,
) -> LinearProof<G::ScalarField> {
    let nonce = [G::ScalarField::rand(rng), G::ScalarField::rand(rng)];
    let a: Vec<_> = bases.iter().map(|b| linear(b, &nonce, fixed)).collect();
    let c = challenge(domain, setup, id, bases, targets, &a);
    LinearProof {
        challenge: c,
        response: [nonce[0] + c * witness[0], nonce[1] + c * witness[1]],
    }
}
fn verify_proof<G: ark_ec::CurveGroup>(
    domain: &'static [u8],
    setup: &[u8; 32],
    id: usize,
    bases: &[[G; 2]],
    targets: &[G],
    proof: &LinearProof<G::ScalarField>,
    fixed: &crate::arithmetic::FixedBases<G>,
) -> bool {
    let a: Vec<_> = bases
        .iter()
        .zip(targets)
        .map(|(b, t)| linear(b, &proof.response, fixed) - fixed.mul(*t, proof.challenge))
        .collect();
    challenge(domain, setup, id, bases, targets, &a) == proof.challenge
}

pub struct Illusi;
impl Illusi {
    pub fn setup<G: ark_ec::CurveGroup, R: RngCore>(
        n: usize,
        threshold: usize,
        rng: &mut R,
    ) -> Result<(Parameters<G>, Vec<SecretKey<G>>), Error> {
        if n == 0 || n > u32::MAX as usize || threshold == 0 || threshold > n {
            return Err(Error::InvalidParameters);
        }
        let mut random_base = || loop {
            let b = G::rand(rng);
            if !b.is_zero() {
                break b;
            }
        };
        let (g, h, u) = (random_base(), random_base(), random_base());
        let mut pairs = Vec::with_capacity(n);
        let keys = (0..n)
            .map(|_| {
                let x = G::ScalarField::rand(rng);
                let y = G::ScalarField::rand(rng);
                pairs.push((x, y));
                g * x + u * y
            })
            .collect();
        let pp = Parameters::from_public_keys(g, h, u, keys, threshold)?;
        let sk = pairs
            .into_iter()
            .enumerate()
            .map(|(i, (x, y))| SecretKey {
                id: i + 1,
                x,
                y,
                setup: pp.digest,
            })
            .collect();
        Ok((pp, sk))
    }
    pub fn share<G: ark_ec::CurveGroup, R: RngCore>(
        secret: G::ScalarField,
        pp: &Parameters<G>,
        rng: &mut R,
    ) -> Sharing<G> {
        let fixed = pp.fixed_bases();
        let mut polynomial: Vec<_> = (0..pp.threshold)
            .map(|_| G::ScalarField::rand(rng))
            .collect();
        polynomial[0] = secret;
        let shares: Vec<_> = pp
            .points
            .iter()
            .map(|x| evaluate(&polynomial, *x))
            .collect();
        let commitments: Vec<_> = shares.iter().map(|s| fixed.mul(pp.g, *s)).collect();
        let bases = &pp.encryption_bases;
        let mut ciphertexts = Vec::with_capacity(pp.n());
        let mut proofs = Vec::with_capacity(pp.n());
        for i in 1..=pp.n() {
            let r = G::ScalarField::rand(rng);
            let ct = [
                fixed.mul(pp.g, r),
                fixed.mul(pp.u, r),
                fixed.mul(pp.keys[i - 1], r) + fixed.mul(pp.h, shares[i]),
            ];
            let targets = [commitments[i], ct[0], ct[1], ct[2]];
            proofs.push(prove(
                b"illusi-encryption",
                &pp.digest,
                i,
                &bases[i - 1],
                &targets,
                [shares[i], r],
                rng,
                &fixed,
            ));
            ciphertexts.push(ct);
        }
        Sharing {
            commitments,
            ciphertexts,
            proofs,
        }
    }
    /// Cascudo--David randomized dual-code low-degree test, including index 0.
    /// Verifier randomness is fresh; neither the test nor NIZK results are cached.
    pub fn verify<'a, G: ark_ec::CurveGroup, R: RngCore>(
        sharing: &'a Sharing<G>,
        pp: &'a Parameters<G>,
        rng: &mut R,
    ) -> Result<VerifiedSharing<'a, G>, Error> {
        if sharing.commitments.len() != pp.n() + 1
            || sharing.ciphertexts.len() != pp.n()
            || sharing.proofs.len() != pp.n()
            || sharing.commitments.check().is_err()
            || sharing.ciphertexts.check().is_err()
        {
            return Err(Error::InvalidProof);
        }
        let q: Vec<_> = (0..=pp.n() - pp.threshold)
            .map(|_| G::ScalarField::rand(rng))
            .collect();
        let coefficients: Vec<_> = pp
            .points
            .iter()
            .zip(pp.dual_weights.iter())
            .map(|(x, w)| evaluate(&q, *x) * w)
            .collect();
        let test = crate::arithmetic::public_msm(&sharing.commitments, &coefficients);
        if !test.is_zero() {
            return Err(Error::InvalidProof);
        }
        let bases = &pp.encryption_bases;
        let fixed = pp.fixed_bases();
        for i in 1..=pp.n() {
            let ct = sharing.ciphertexts[i - 1];
            if !verify_proof(
                b"illusi-encryption",
                &pp.digest,
                i,
                &bases[i - 1],
                &[sharing.commitments[i], ct[0], ct[1], ct[2]],
                &sharing.proofs[i - 1],
                &fixed,
            ) {
                return Err(Error::InvalidProof);
            }
        }
        Ok(VerifiedSharing { pp, sharing, fixed })
    }
}
impl<G: ark_ec::CurveGroup> Parameters<G> {
    fn fixed_bases(&self) -> Arc<crate::arithmetic::FixedBases<G>> {
        let mut bases = vec![self.g, self.h, self.u];
        bases.extend_from_slice(&self.keys);
        crate::arithmetic::fixed_bases(&bases)
    }
    pub fn from_public_keys(
        g: G,
        h: G,
        u: G,
        keys: Vec<G>,
        threshold: usize,
    ) -> Result<Self, Error> {
        let n = keys.len();
        if n == 0
            || n > u32::MAX as usize
            || threshold == 0
            || threshold > n
            || [g, h, u].iter().any(Zero::is_zero)
            || [g, h, u].check().is_err()
            || keys.check().is_err()
        {
            return Err(Error::InvalidParameters);
        }
        let digest = context::digest(b"illusi-setup", &(g, h, u, keys.clone(), threshold as u64));
        let points = crate::cache::evaluation_points(n + 1, 0);
        let dual_weights =
            crate::cache::barycentric_weights(&points).ok_or(Error::InvalidParameters)?;
        let encryption_bases = keys
            .iter()
            .map(|pk| [[g, G::zero()], [G::zero(), g], [G::zero(), u], [h, *pk]])
            .collect();
        Ok(Self {
            g,
            h,
            u,
            keys,
            threshold,
            digest,
            points,
            dual_weights,
            encryption_bases,
        })
    }
    pub fn n(&self) -> usize {
        self.keys.len()
    }
    pub fn encode(&self, secret: G::ScalarField) -> G {
        self.h * secret
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
        let xs: Vec<_> = ids.iter().map(|i| self.points[*i]).collect();
        let weights = crate::cache::interpolation_weights(&xs, &[G::ScalarField::zero()])
            .ok_or(Error::InvalidShares)?;
        Ok(ReconstructionPlan {
            ids: ids.to_vec(),
            weights,
            setup: self.digest,
        })
    }
}
impl<G: ark_ec::CurveGroup> VerifiedSharing<'_, G> {
    pub fn pre_recon<R: RngCore>(
        &self,
        key: &SecretKey<G>,
        rng: &mut R,
    ) -> Result<DecryptionShare<G>, Error> {
        if key.setup != self.pp.digest || key.id == 0 || key.id > self.pp.n() {
            return Err(Error::InvalidKey);
        }
        let ct = self.sharing.ciphertexts[key.id - 1];
        let value = ct[2] - ct[0] * key.x - ct[1] * key.y;
        let bases = [[self.pp.g, self.pp.u], [ct[0], ct[1]]];
        let proof = prove(
            b"illusi-decryption",
            &self.pp.digest,
            key.id,
            &bases,
            &[self.pp.keys[key.id - 1], ct[2] - value],
            [key.x, key.y],
            rng,
            &self.fixed,
        );
        Ok(DecryptionShare {
            id: key.id,
            value,
            proof,
        })
    }
    pub fn dec_vrf(&self, share: &DecryptionShare<G>) -> bool {
        if share.id == 0 || share.id > self.pp.n() || share.value.check().is_err() {
            return false;
        }
        let ct = self.sharing.ciphertexts[share.id - 1];
        verify_proof(
            b"illusi-decryption",
            &self.pp.digest,
            share.id,
            &[[self.pp.g, self.pp.u], [ct[0], ct[1]]],
            &[self.pp.keys[share.id - 1], ct[2] - share.value],
            &share.proof,
            &self.fixed,
        )
    }
    /// Inputs must have passed `dec_vrf`; proof verification is timed separately.
    pub fn reconstruct(
        &self,
        shares: &[(usize, G)],
        plan: &ReconstructionPlan<G::ScalarField>,
    ) -> Result<G, Error>
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
        Ok(crate::arithmetic::public_msm(&bases, &plan.weights[0]))
    }
}
