//! Separate split-key variant from the adaptive appendix, with ideal setup.
//! Only (alpha_i,beta_i) is retained as shareholder secret state. This module does
//! not implement a distributed setup or the secure-erasure mechanism assumed by the proof.
use super::{context, elgamal_pvss::ElGamalPVSSError};
use crate::{
    elgamal_te::{decryption::decrypt_with_points, encryption::Ciphertext as ElGamalCiphertext},
    utils::precompute_lagrange_coefficients,
};
use ark_ec::PrimeGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{rand::RngCore, UniformRand, Zero};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct SecretKey<G: PrimeGroup> {
    pub id: usize,
    pub setup_digest: [u8; 32],
    pub alpha: G::ScalarField,
    pub beta: G::ScalarField,
}
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct PublicKey<G: PrimeGroup> {
    pub id: usize,
    pub key: G,
}
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Params<G: PrimeGroup> {
    pub security_param: usize,
    pub n: usize,
    pub threshold: usize,
    pub g: G,
    pub h: G,
    pub master_pk: G,
    pub commitments: Vec<G>,
    pub public_keys: Vec<PublicKey<G>>,
    pub lagrange_coeffs: Vec<Vec<G::ScalarField>>,
    pub epoch: u64,
    pub setup_digest: [u8; 32],
}
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Ciphertext<G: PrimeGroup> {
    pub c_0: G,
    pub c_1: G,
    pub c_2: G,
}
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct RepresentationProof<G: PrimeGroup> {
    pub commitments: Vec<G>,
    pub responses: [G::ScalarField; 2],
}

pub struct AdaptiveElGamalPVSS<G: PrimeGroup> {
    _phantom: std::marker::PhantomData<G>,
}
impl<G: ark_ec::CurveGroup> AdaptiveElGamalPVSS<G> {
    fn digest(pp: &Params<G>) -> [u8; 32] {
        let mut public = pp.clone();
        public.setup_digest = [0; 32];
        context::digest(b"pvss-adaptive-i-setup", &public)
    }
    pub fn setup<R: RngCore>(
        security_param: usize,
        threshold: usize,
        n: usize,
        rng: &mut R,
    ) -> Result<(Params<G>, Vec<(SecretKey<G>, PublicKey<G>)>), ElGamalPVSSError> {
        if security_param == 0 || threshold == 0 || threshold > n {
            return Err(ElGamalPVSSError::InvalidThreshold);
        }
        let g = G::generator();
        let mut h = G::rand(rng);
        while h.is_zero() {
            h = G::rand(rng);
        }
        let a: Vec<_> = (0..threshold).map(|_| G::ScalarField::rand(rng)).collect();
        let b: Vec<_> = (0..threshold).map(|_| G::ScalarField::rand(rng)).collect();
        let commitments: Vec<_> = a.iter().zip(&b).map(|(a, b)| g * a + h * b).collect();
        let mut keys: Vec<_> = (0..n)
            .map(|id| {
                let point = G::ScalarField::from((id + 1) as u64);
                let alpha = a
                    .iter()
                    .rev()
                    .fold(G::ScalarField::zero(), |acc, c| acc * point + c);
                let beta = b
                    .iter()
                    .rev()
                    .fold(G::ScalarField::zero(), |acc, c| acc * point + c);
                (
                    SecretKey {
                        id,
                        setup_digest: [0; 32],
                        alpha,
                        beta,
                    },
                    PublicKey {
                        id,
                        key: g * alpha + h * beta,
                    },
                )
            })
            .collect();
        let mut pp = Params {
            security_param,
            n,
            threshold,
            g,
            h,
            master_pk: commitments[0],
            commitments,
            public_keys: keys.iter().map(|(_, pk)| pk.clone()).collect(),
            lagrange_coeffs: precompute_lagrange_coefficients::<G::ScalarField>(n).1,
            epoch: 0,
            setup_digest: [0; 32],
        };
        pp.setup_digest = Self::digest(&pp);
        for (sk, _) in &mut keys {
            sk.setup_digest = pp.setup_digest;
        }
        Ok((pp, keys))
    }
    fn valid_shape(pp: &Params<G>) -> bool {
        pp.security_param > 0
            && pp.threshold > 0
            && pp.threshold <= pp.n
            && !pp.g.is_zero()
            && !pp.h.is_zero()
            && pp.commitments.len() == pp.threshold
            && pp.public_keys.len() == pp.n
            && pp.lagrange_coeffs.len() == pp.n
    }
    pub fn verify_setup(pp: &Params<G>, keys: &[PublicKey<G>]) -> bool {
        if !Self::valid_shape(pp)
            || pp.threshold == 0
            || pp.threshold > pp.n
            || pp.commitments.len() != pp.threshold
            || keys.len() != pp.n
            || pp.public_keys.len() != pp.n
            || pp.g.is_zero()
            || pp.h.is_zero()
            || pp.check().is_err()
            || pp.setup_digest != Self::digest(pp)
            || pp.master_pk != pp.commitments[0]
            || pp.lagrange_coeffs != precompute_lagrange_coefficients::<G::ScalarField>(pp.n).1
        {
            return false;
        }
        keys.iter().enumerate().all(|(id, pk)| {
            let point = G::ScalarField::from((id + 1) as u64);
            let expected = pp
                .commitments
                .iter()
                .rev()
                .fold(G::zero(), |acc, c| acc * point + c);
            pk.id == id
                && pk.key == expected
                && pp.public_keys[id].id == id
                && pp.public_keys[id].key == pk.key
        })
    }
    fn fs_challenge(
        pp: &Params<G>,
        ct: &Ciphertext<G>,
        pk: Option<&PublicKey<G>>,
        statements: &[G],
        commitments: &[G],
        domain: &'static [u8],
    ) -> G::ScalarField {
        let mut transcript = context::transcript(domain, &pp.setup_digest, pp.epoch);
        context::append(&mut transcript, b"ciphertext", ct);
        if let Some(pk) = pk {
            context::append(&mut transcript, b"indexed-public-key", pk);
        }
        context::append(&mut transcript, b"statements", &statements);
        context::append(&mut transcript, b"commitments", &commitments);
        context::challenge(&mut transcript)
    }
    fn prove<R: RngCore>(
        pp: &Params<G>,
        ct: &Ciphertext<G>,
        pk: Option<&PublicKey<G>>,
        rows: &[[G; 2]],
        statements: &[G],
        witness: [G::ScalarField; 2],
        domain: &'static [u8],
        rng: &mut R,
    ) -> RepresentationProof<G> {
        let fixed = crate::arithmetic::fixed_bases(&[pp.g, pp.h, pp.master_pk]);
        let random = [G::ScalarField::rand(rng), G::ScalarField::rand(rng)];
        let commitments: Vec<_> = rows
            .iter()
            .map(|row| fixed.mul(row[0], random[0]) + fixed.mul(row[1], random[1]))
            .collect();
        let c = Self::fs_challenge(pp, ct, pk, statements, &commitments, domain);
        RepresentationProof {
            commitments,
            responses: std::array::from_fn(|i| random[i] - c * witness[i]),
        }
    }
    fn verify_representation(
        pp: &Params<G>,
        ct: &Ciphertext<G>,
        pk: Option<&PublicKey<G>>,
        rows: &[[G; 2]],
        statements: &[G],
        proof: &RepresentationProof<G>,
        domain: &'static [u8],
    ) -> bool {
        if proof.commitments.len() != rows.len() || proof.check().is_err() || ct.check().is_err() {
            return false;
        }
        let c = Self::fs_challenge(pp, ct, pk, statements, &proof.commitments, domain);
        let fixed = crate::arithmetic::fixed_bases(&[pp.g, pp.h, pp.master_pk]);
        rows.iter()
            .zip(statements)
            .zip(&proof.commitments)
            .all(|((row, statement), commitment)| {
                *commitment
                    == fixed.mul(*statement, c)
                        + fixed.mul(row[0], proof.responses[0])
                        + fixed.mul(row[1], proof.responses[1])
            })
    }
    pub fn share<R: RngCore>(
        secret: G::ScalarField,
        pp: &Params<G>,
        rng: &mut R,
    ) -> Result<(Ciphertext<G>, RepresentationProof<G>), ElGamalPVSSError> {
        if !Self::valid_shape(pp) {
            return Err(ElGamalPVSSError::InvalidParameters);
        }
        let w = G::ScalarField::rand(rng);
        let fixed = crate::arithmetic::fixed_bases(&[pp.g, pp.h, pp.master_pk]);
        let ct = Ciphertext {
            c_0: fixed.mul(pp.g, secret) + fixed.mul(pp.master_pk, w),
            c_1: fixed.mul(pp.g, w),
            c_2: fixed.mul(pp.h, w),
        };
        let proof = Self::prove(
            pp,
            &ct,
            None,
            &[[pp.g, pp.master_pk], [G::zero(), pp.g], [G::zero(), pp.h]],
            &[ct.c_0, ct.c_1, ct.c_2],
            [secret, w],
            b"pvss-adaptive-i-sharing",
            rng,
        );
        Ok((ct, proof))
    }
    pub fn verify(ct: &Ciphertext<G>, proof: &RepresentationProof<G>, pp: &Params<G>) -> bool {
        Self::valid_shape(pp)
            && Self::verify_representation(
                pp,
                ct,
                None,
                &[[pp.g, pp.master_pk], [G::zero(), pp.g], [G::zero(), pp.h]],
                &[ct.c_0, ct.c_1, ct.c_2],
                proof,
                b"pvss-adaptive-i-sharing",
            )
    }
    pub fn pre_recon<R: RngCore>(
        ct: &Ciphertext<G>,
        _sharing_proof: &RepresentationProof<G>,
        sk: &SecretKey<G>,
        pp: &Params<G>,
        rng: &mut R,
    ) -> Result<(G, RepresentationProof<G>), ElGamalPVSSError> {
        if !Self::valid_shape(pp) || sk.setup_digest != pp.setup_digest {
            return Err(ElGamalPVSSError::InvalidParameters);
        }
        let pk = pp
            .public_keys
            .get(sk.id)
            .ok_or(ElGamalPVSSError::InvalidParticipantCount)?;
        if ct.check().is_err() {
            return Err(ElGamalPVSSError::InvalidCiphertext);
        }
        let d = ct.c_1 * sk.alpha + ct.c_2 * sk.beta;
        let proof = Self::prove(
            pp,
            ct,
            Some(pk),
            &[[pp.g, pp.h], [ct.c_1, ct.c_2]],
            &[pk.key, d],
            [sk.alpha, sk.beta],
            b"pvss-adaptive-i-reconstruction",
            rng,
        );
        Ok((d, proof))
    }
    pub fn dec_vrf(
        d: G,
        proof: &RepresentationProof<G>,
        pk: &PublicKey<G>,
        ct: &Ciphertext<G>,
        pp: &Params<G>,
    ) -> bool {
        if !Self::valid_shape(pp) {
            return false;
        }
        let Some(expected) = pp.public_keys.get(pk.id) else {
            return false;
        };
        pk.id == expected.id
            && pk.key == expected.key
            && pk.check().is_ok()
            && d.check().is_ok()
            && Self::verify_representation(
                pp,
                ct,
                Some(pk),
                &[[pp.g, pp.h], [ct.c_1, ct.c_2]],
                &[pk.key, d],
                proof,
                b"pvss-adaptive-i-reconstruction",
            )
    }
    pub fn reconstruct<R: RngCore>(
        ct: &Ciphertext<G>,
        shares: &[(usize, G)],
        pp: &Params<G>,
        _rng: &mut R,
    ) -> Result<G, ElGamalPVSSError>
    where
        G: ark_ec::CurveGroup,
    {
        if !Self::valid_shape(pp) {
            return Err(ElGamalPVSSError::InvalidParameters);
        }
        if shares.len() < pp.threshold {
            return Err(ElGamalPVSSError::InsufficientDecryptions);
        }
        if ct.check().is_err()
            || shares
                .iter()
                .any(|(id, d)| *id >= pp.n || d.check().is_err())
        {
            return Err(ElGamalPVSSError::InvalidParticipantCount);
        }
        decrypt_with_points(
            &ElGamalCiphertext {
                c_0: ct.c_0,
                c_1: ct.c_1,
            },
            shares,
            pp.threshold,
            &crate::cache::evaluation_points::<G::ScalarField>(pp.n, 1),
        )
        .ok_or(ElGamalPVSSError::InvalidParticipantCount)
    }
}
