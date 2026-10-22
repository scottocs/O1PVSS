//! ALBATROSS packed-PVSS core: Cascudo--David, ASIACRYPT 2020, Figs. 2,5,6.
//! https://eprint.iacr.org/2020/644
//! This implements sharing/LDEI, individual DLEQ decryption and interpolation;
//! not the distributed randomness-beacon protocol or its randomness extractor.
//! `threshold` = source t+ell, privacy threshold = threshold-ell.
use super::ldeipoly::{self, local_setup};
pub use super::ldeipoly::{
    DecryptionShare, Error, Parameters, PolynomialProof, ReconstructionPlan, SecretKey, Sharing,
    VerifiedSharing,
};
use ark_std::rand::RngCore;

pub struct Albatross;
impl Albatross {
    /// Local fixture that simulates independent party key generation.
    pub fn setup<G: ark_ec::CurveGroup, R: RngCore>(
        n: usize,
        threshold: usize,
        batch_size: usize,
        epoch: u64,
        rng: &mut R,
    ) -> Result<(Parameters<G>, Vec<SecretKey<G>>), Error> {
        local_setup(
            b"albatross-packed-pvss",
            n,
            threshold,
            batch_size,
            None,
            epoch,
            rng,
        )
    }
    pub fn from_public_keys<G: ark_ec::CurveGroup>(
        generator: G,
        public_keys: Vec<G>,
        threshold: usize,
        batch_size: usize,
        epoch: u64,
    ) -> Result<Parameters<G>, Error> {
        Parameters::new(
            b"albatross-packed-pvss",
            generator,
            public_keys,
            threshold,
            batch_size,
            None,
            epoch,
        )
    }
    /// Uniform polynomial conditioned on the supplied secret evaluations.
    pub fn share<G: ark_ec::CurveGroup, R: RngCore>(
        secrets: &[G::ScalarField],
        pp: &Parameters<G>,
        rng: &mut R,
    ) -> Result<Sharing<G>, Error> {
        if pp.origin_base.is_some() {
            return Err(ldeipoly::Error::InvalidParameters);
        }
        pp.share(secrets, None, rng)
    }
    pub fn verify<'a, G: ark_ec::CurveGroup>(
        sharing: &'a Sharing<G>,
        pp: &'a Parameters<G>,
    ) -> Result<VerifiedSharing<'a, G>, Error> {
        if pp.origin_base.is_some() {
            return Err(Error::InvalidParameters);
        }
        pp.validate(sharing, None)
    }
}
