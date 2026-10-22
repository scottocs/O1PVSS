//! Instantiation I: public committee audit, labelled sharing proof and DLEQ shares.
//! Rust IDs 0..n correspond to manuscript indices 1..=n.
use super::context;
use crate::elgamal_te::{
    decryption::{decrypt_with_points, partial_decrypt},
    encryption::{encrypt_with_randomness, Ciphertext},
    setup::{MasterPublicKey, PublicKey, SecretKey, VerifiableSecretSharing},
};
use crate::utils::{dleq_prove_with_context, dleq_verify_with_context, DleqProof};
use ark_ec::PrimeGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{rand::Rng, UniformRand, Zero};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct CommitteeContribution<G: PrimeGroup> {
    pub sender_id: usize,
    pub commitments: Vec<G>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, Default)]
pub struct SetupAudit<G: PrimeGroup> {
    /// Accepted Feldman coefficient commitments. No private shares or master secret.
    pub contributions: Vec<CommitteeContribution<G>>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct ElGamalPVSSParams<G: PrimeGroup> {
    pub security_param: usize,
    pub threshold: usize,
    pub n: usize,
    pub generator: G,
    pub master_pk_key: MasterPublicKey<G>,
    pub root_powers: Vec<G::ScalarField>,
    pub lagrange_coeffs: Vec<Vec<G::ScalarField>>,
    pub public_keys: Vec<PublicKey<G>>,
    pub audit: SetupAudit<G>,
    pub epoch: u64,
    pub setup_digest: [u8; 32],
}

impl<G: ark_ec::CurveGroup> ElGamalPVSSParams<G> {
    pub fn new(
        security_param: usize,
        threshold: usize,
        n: usize,
        generator: G,
        master_pk_key: MasterPublicKey<G>,
        root_powers: Vec<G::ScalarField>,
        lagrange_coeffs: Vec<Vec<G::ScalarField>>,
        public_keys: Vec<PublicKey<G>>,
        audit: SetupAudit<G>,
        epoch: u64,
    ) -> Self {
        let mut pp = Self {
            security_param,
            threshold,
            n,
            generator,
            master_pk_key,
            root_powers,
            lagrange_coeffs,
            public_keys,
            audit,
            epoch,
            setup_digest: [0; 32],
        };
        pp.setup_digest = pp.digest();
        pp
    }

    fn digest(&self) -> [u8; 32] {
        // The digest itself is excluded. Includes all public setup and interpolation data.
        let mut public = self.clone();
        public.setup_digest = [0; 32];
        context::digest(b"pvss-instantiation-i-setup", &public)
    }

    fn valid_shape(&self) -> bool {
        self.security_param > 0
            && self.threshold > 0
            && self.threshold <= self.n
            && !self.generator.is_zero()
            && crate::cache::valid_public_element(&self.generator)
            && self.public_keys.len() == self.n
            && self.root_powers.len() == self.n
            && self.lagrange_coeffs.len() == self.n
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Proof<G: PrimeGroup> {
    pub commitment: Ciphertext<G>,
    pub challenge: G::ScalarField,
    pub response_w: G::ScalarField,
    pub response_s: G::ScalarField,
}

/// Full sharing verification is reusable only while ct and pp remain borrowed
/// immutably. Secret keys, proof randomness and decryption shares are not cached.
pub struct VerifiedSharing<'a, G: PrimeGroup> {
    ct: &'a Ciphertext<G>,
    pp: &'a ElGamalPVSSParams<G>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElGamalPVSSError {
    InvalidParameters,
    InvalidThreshold,
    InvalidParticipantCount,
    InvalidSecret,
    InvalidCiphertext,
    InvalidProof,
    InsufficientDecryptions,
    DKGError,
}

pub struct ElGamalPVSS<G: PrimeGroup> {
    _phantom: std::marker::PhantomData<G>,
}

impl<G: ark_ec::CurveGroup> ElGamalPVSS<G> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Local honest-committee setup simulator; private delivery messages are not public outputs.
    pub fn setup<R: Rng>(
        security_param: usize,
        threshold: usize,
        n: usize,
        points: Vec<G::ScalarField>,
        coefficients: Vec<Vec<G::ScalarField>>,
        rng: &mut R,
    ) -> Result<(ElGamalPVSSParams<G>, Vec<(SecretKey<G>, PublicKey<G>)>), ElGamalPVSSError> {
        Self::setup_with_committee_size(security_param, threshold, n, n, points, coefficients, rng)
    }

    pub fn setup_with_committee_size<R: Rng>(
        security_param: usize,
        threshold: usize,
        n: usize,
        committee_size: usize,
        points: Vec<G::ScalarField>,
        coefficients: Vec<Vec<G::ScalarField>>,
        rng: &mut R,
    ) -> Result<(ElGamalPVSSParams<G>, Vec<(SecretKey<G>, PublicKey<G>)>), ElGamalPVSSError> {
        if threshold == 0 || threshold > n || committee_size == 0 {
            return Err(ElGamalPVSSError::InvalidThreshold);
        }
        let (expected_points, expected_coefficients) =
            crate::utils::precompute_lagrange_coefficients::<G::ScalarField>(n);
        if security_param == 0 || points != expected_points || coefficients != expected_coefficients
        {
            return Err(ElGamalPVSSError::InvalidParameters);
        }
        let vss =
            VerifiableSecretSharing::<G>::new(threshold, n, points.clone(), coefficients.clone());
        let mut shares = vec![G::ScalarField::zero(); n];
        let mut audit = SetupAudit {
            contributions: Vec::new(),
        };
        let mut master_pk = G::zero();
        for sender_id in 0..committee_size {
            let secret = G::ScalarField::rand(rng);
            let (delivery, commitments) = vss.share_secret(secret, rng);
            master_pk += commitments[0];
            for (share, value) in shares.iter_mut().zip(delivery) {
                *share += value;
            }
            audit.contributions.push(CommitteeContribution {
                sender_id,
                commitments,
            });
        }
        let mut keys: Vec<_> = shares
            .into_iter()
            .enumerate()
            .map(|(id, sk_i)| {
                (
                    SecretKey {
                        id,
                        sk_i,
                        setup_digest: [0; 32],
                    },
                    PublicKey {
                        id,
                        pk_i: G::generator() * sk_i,
                    },
                )
            })
            .collect();
        let pp = ElGamalPVSSParams::new(
            security_param,
            threshold,
            n,
            G::generator(),
            MasterPublicKey { pk: master_pk },
            points,
            coefficients,
            keys.iter().map(|(_, pk)| pk.clone()).collect(),
            audit,
            0,
        );
        for (sk, _) in &mut keys {
            sk.setup_digest = pp.setup_digest;
        }
        Ok((pp, keys))
    }

    /// Public algebraic audit; cannot certify entropy, private delivery or erasure.
    pub fn verify_setup(pp: &ElGamalPVSSParams<G>, public_keys: &[PublicKey<G>]) -> bool {
        if !pp.valid_shape()
            || pp.digest() != pp.setup_digest
            || pp.audit.contributions.is_empty()
            || public_keys.len() != pp.n
        {
            return false;
        }
        let (points, coefficients) =
            crate::utils::precompute_lagrange_coefficients::<G::ScalarField>(pp.n);
        if points != pp.root_powers || coefficients != pp.lagrange_coeffs {
            return false;
        }
        let mut aggregate = vec![G::zero(); pp.threshold];
        let mut senders = std::collections::HashSet::new();
        for contribution in &pp.audit.contributions {
            if !senders.insert(contribution.sender_id)
                || contribution.commitments.len() != pp.threshold
            {
                return false;
            }
            for (a, c) in aggregate.iter_mut().zip(&contribution.commitments) {
                if c.check().is_err() {
                    return false;
                }
                *a += c;
            }
        }
        if aggregate[0] != pp.master_pk_key.pk {
            return false;
        }
        public_keys.iter().enumerate().all(|(id, pk)| {
            let expected = aggregate
                .iter()
                .rev()
                .fold(G::zero(), |acc, c| acc * points[id] + c);
            pk.id == id
                && pk.pk_i.check().is_ok()
                && pk.pk_i == expected
                && pp.public_keys[id].id == id
                && pp.public_keys[id].pk_i == pk.pk_i
        })
    }

    fn sharing_challenge(
        pp: &ElGamalPVSSParams<G>,
        ct: &Ciphertext<G>,
        commitment: &Ciphertext<G>,
    ) -> G::ScalarField {
        let mut transcript =
            context::transcript(b"pvss-instantiation-i-sharing", &pp.setup_digest, pp.epoch);
        context::append(&mut transcript, b"ciphertext", ct);
        context::append(&mut transcript, b"commitment", commitment);
        context::challenge(&mut transcript)
    }

    pub fn share<R: Rng>(
        secret: G::ScalarField,
        pp: &ElGamalPVSSParams<G>,
        rng: &mut R,
    ) -> Result<(Ciphertext<G>, Proof<G>), ElGamalPVSSError>
    where
        G: ark_ec::scalar_mul::ScalarMul,
    {
        if !pp.valid_shape() {
            return Err(ElGamalPVSSError::InvalidParameters);
        }
        let w = G::ScalarField::rand(rng);
        let w_prime = G::ScalarField::rand(rng);
        let s_prime = G::ScalarField::rand(rng);
        let ct = encrypt_with_randomness(
            pp.generator,
            &pp.master_pk_key,
            crate::arithmetic::fixed_base_mul(pp.generator, secret),
            w,
        );
        let commitment = encrypt_with_randomness(
            pp.generator,
            &pp.master_pk_key,
            crate::arithmetic::fixed_base_mul(pp.generator, s_prime),
            w_prime,
        );
        let c = Self::sharing_challenge(pp, &ct, &commitment);
        Ok((
            ct,
            Proof {
                commitment,
                challenge: c,
                response_w: w_prime - c * w,
                response_s: s_prime - c * secret,
            },
        ))
    }

    pub fn verify(ct: &Ciphertext<G>, proof: &Proof<G>, pp: &ElGamalPVSSParams<G>) -> bool
    where
        G: ark_ec::scalar_mul::ScalarMul,
    {
        if !pp.valid_shape() || ct.check().is_err() || proof.check().is_err() {
            return false;
        }
        let c = Self::sharing_challenge(pp, ct, &proof.commitment);
        c == proof.challenge
            && proof.commitment.c_0
                == ct.c_0 * c
                    + crate::arithmetic::fixed_base_mul(pp.generator, proof.response_s)
                    + crate::arithmetic::fixed_base_mul(pp.master_pk_key.pk, proof.response_w)
            && proof.commitment.c_1
                == ct.c_1 * c + crate::arithmetic::fixed_base_mul(pp.generator, proof.response_w)
    }

    pub fn verify_sharing<'a>(
        ct: &'a Ciphertext<G>,
        proof: &Proof<G>,
        pp: &'a ElGamalPVSSParams<G>,
    ) -> Result<VerifiedSharing<'a, G>, ElGamalPVSSError>
    where
        G: ark_ec::scalar_mul::ScalarMul,
    {
        if !Self::verify(ct, proof, pp) {
            return Err(ElGamalPVSSError::InvalidProof);
        }
        Ok(VerifiedSharing { ct, pp })
    }

    fn reconstruction_context(
        pp: &ElGamalPVSSParams<G>,
        ct: &Ciphertext<G>,
        pk: &PublicKey<G>,
    ) -> Vec<u8> {
        let mut transcript = context::transcript(
            b"pvss-instantiation-i-reconstruction",
            &pp.setup_digest,
            pp.epoch,
        );
        context::append(&mut transcript, b"ciphertext", ct);
        context::append(&mut transcript, b"indexed-public-key", pk);
        let mut bytes = vec![0; 32];
        transcript.challenge_bytes(b"dleq-context", &mut bytes);
        bytes
    }

    /// Caller has accepted (ct, sharing_proof) for this setup/epoch. No sharing verification here.
    pub fn pre_recon<R: Rng>(
        ct: &Ciphertext<G>,
        _sharing_proof: &Proof<G>,
        sk: &SecretKey<G>,
        pp: &ElGamalPVSSParams<G>,
        rng: &mut R,
    ) -> Result<(G, DleqProof<G>), ElGamalPVSSError> {
        if ct.check().is_err() {
            return Err(ElGamalPVSSError::InvalidParameters);
        }
        Self::pre_recon_validated(ct, sk, pp, rng)
    }

    fn pre_recon_validated<R: Rng>(
        ct: &Ciphertext<G>,
        sk: &SecretKey<G>,
        pp: &ElGamalPVSSParams<G>,
        rng: &mut R,
    ) -> Result<(G, DleqProof<G>), ElGamalPVSSError> {
        if !pp.valid_shape() || sk.setup_digest != pp.setup_digest {
            return Err(ElGamalPVSSError::InvalidParameters);
        }
        let pk = pp
            .public_keys
            .get(sk.id)
            .ok_or(ElGamalPVSSError::InvalidParticipantCount)?;
        if pk.id != sk.id {
            return Err(ElGamalPVSSError::InvalidParameters);
        }
        let d = partial_decrypt(ct, sk);
        let context = Self::reconstruction_context(pp, ct, pk);
        let proof =
            dleq_prove_with_context(pp.generator, ct.c_1, sk.sk_i, (pk.pk_i, d), &context, rng);
        Ok((d, proof))
    }

    pub fn dec_vrf(
        d: G,
        proof: &DleqProof<G>,
        pk: &PublicKey<G>,
        ct: &Ciphertext<G>,
        pp: &ElGamalPVSSParams<G>,
    ) -> bool {
        ct.check().is_ok() && Self::dec_vrf_validated(d, proof, pk, ct, pp)
    }

    fn dec_vrf_validated(
        d: G,
        proof: &DleqProof<G>,
        pk: &PublicKey<G>,
        ct: &Ciphertext<G>,
        pp: &ElGamalPVSSParams<G>,
    ) -> bool {
        if !pp.valid_shape() {
            return false;
        }
        let Some(expected) = pp.public_keys.get(pk.id) else {
            return false;
        };
        if expected.id != pk.id
            || expected.pk_i != pk.pk_i
            || d.check().is_err()
            || pk.check().is_err()
            || proof.check().is_err()
        {
            return false;
        }
        dleq_verify_with_context(
            pp.generator,
            ct.c_1,
            (pk.pk_i, d),
            proof,
            &Self::reconstruction_context(pp, ct, pk),
        )
    }

    /// Shares must already have passed DecVrf; duplicate indices never count toward t.
    pub fn reconstruct<R: Rng>(
        ct: &Ciphertext<G>,
        shares: &[(usize, G)],
        pp: &ElGamalPVSSParams<G>,
        _rng: &mut R,
    ) -> Result<G, ElGamalPVSSError>
    where
        G: ark_ec::CurveGroup,
    {
        if ct.check().is_err() {
            return Err(ElGamalPVSSError::InvalidParticipantCount);
        }
        Self::reconstruct_validated(ct, shares, pp)
    }

    fn reconstruct_validated(
        ct: &Ciphertext<G>,
        shares: &[(usize, G)],
        pp: &ElGamalPVSSParams<G>,
    ) -> Result<G, ElGamalPVSSError>
    where
        G: ark_ec::CurveGroup,
    {
        if !pp.valid_shape() {
            return Err(ElGamalPVSSError::InvalidParameters);
        }
        if shares.len() < pp.threshold {
            return Err(ElGamalPVSSError::InsufficientDecryptions);
        }
        if shares
            .iter()
            .any(|(id, d)| *id >= pp.n || d.check().is_err())
        {
            return Err(ElGamalPVSSError::InvalidParticipantCount);
        }
        decrypt_with_points(ct, shares, pp.threshold, &pp.root_powers)
            .ok_or(ElGamalPVSSError::InvalidParticipantCount)
    }
}

impl<G: ark_ec::CurveGroup> VerifiedSharing<'_, G> {
    pub fn pre_recon<R: Rng>(
        &self,
        sk: &SecretKey<G>,
        rng: &mut R,
    ) -> Result<(G, DleqProof<G>), ElGamalPVSSError> {
        ElGamalPVSS::<G>::pre_recon_validated(self.ct, sk, self.pp, rng)
    }

    pub fn dec_vrf(&self, d: G, proof: &DleqProof<G>, pk: &PublicKey<G>) -> bool {
        ElGamalPVSS::<G>::dec_vrf_validated(d, proof, pk, self.ct, self.pp)
    }

    pub fn reconstruct(&self, shares: &[(usize, G)]) -> Result<G, ElGamalPVSSError>
    where
        G: ark_ec::CurveGroup,
    {
        ElGamalPVSS::<G>::reconstruct_validated(self.ct, shares, self.pp)
    }
}
