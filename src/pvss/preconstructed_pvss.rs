//! Baghery--Knapen--Nicolas--Rahimi, ACNS 2025, RO PPVSS (Fig. 3).
//! https://eprint.iacr.org/2025/576 ; author reference: KULeuven-COSIC/ppvss-evoting.
//! Independent arkworks implementation, with Merlin setup/epoch-bound hashes
//! instead of the reference's Blake3. Pessimistic recovery returns g*f(0);
//! optimistic opening reveals f(0), checked against pk0*f(0).
pub use super::ldeipoly::Parameters as PPVSSParameters;
use super::ldeipoly::{local_setup, Parameters};
pub use super::ldeipoly::{
    DecryptionShare, Error, PolynomialProof, ReconstructionPlan, SecretKey, Sharing,
    VerifiedSharing,
};
use ark_std::rand::RngCore;

pub struct PreconstructedPVSS;
impl PreconstructedPVSS {
    /// pk0 must have no known discrete log for public secrecy. An owner knowing
    /// that log can decrypt the preconstruction without threshold assistance.
    pub fn from_public_keys<G: ark_ec::CurveGroup>(
        generator: G,
        public_keys: Vec<G>,
        commitment_base: G,
        threshold: usize,
        epoch: u64,
    ) -> Result<Parameters<G>, Error> {
        Parameters::new(
            b"baghery-ppvss-ro",
            generator,
            public_keys,
            threshold,
            1,
            Some(commitment_base),
            epoch,
        )
    }
    pub fn setup<G: ark_ec::CurveGroup, R: RngCore>(
        n: usize,
        threshold: usize,
        epoch: u64,
        rng: &mut R,
    ) -> Result<(Parameters<G>, Vec<SecretKey<G>>), Error> {
        let mut base = G::rand(rng);
        while base.is_zero() {
            base = G::rand(rng);
        }
        local_setup(b"baghery-ppvss-ro", n, threshold, 1, Some(base), epoch, rng)
    }
    pub fn preconstruct<G: ark_ec::CurveGroup>(
        secret: G::ScalarField,
        pp: &Parameters<G>,
    ) -> Result<G, Error> {
        Ok(crate::arithmetic::fixed_base_mul(
            pp.origin_base.ok_or(Error::InvalidParameters)?,
            secret,
        ))
    }
    /// The externally supplied preconstruction is part of the proved statement.
    pub fn share<G: ark_ec::CurveGroup, R: RngCore>(
        secret: G::ScalarField,
        preconstruction: G,
        pp: &Parameters<G>,
        rng: &mut R,
    ) -> Result<Sharing<G>, Error> {
        if pp.origin_base.is_none() {
            return Err(Error::InvalidParameters);
        }
        pp.share(&[secret], Some(preconstruction), rng)
    }
    pub fn verify<'a, G: ark_ec::CurveGroup>(
        sharing: &'a Sharing<G>,
        expected: G,
        pp: &'a Parameters<G>,
    ) -> Result<VerifiedSharing<'a, G>, Error> {
        if pp.origin_base.is_none() {
            return Err(Error::InvalidParameters);
        }
        pp.validate(sharing, Some(expected))
    }
    /// Constant-size dealer opening; no shareholder decryption is required.
    pub fn optimistic_open<G: ark_ec::CurveGroup>(
        secret: G::ScalarField,
        expected: G,
        pp: &Parameters<G>,
    ) -> Result<G, Error> {
        if Self::preconstruct(secret, pp)? != expected {
            return Err(Error::CommitmentMismatch);
        }
        Ok(crate::arithmetic::fixed_base_mul(pp.generator, secret))
    }
}
