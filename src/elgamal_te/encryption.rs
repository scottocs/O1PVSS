//! Ordinary threshold ElGamal: ciphertexts only; proofs belong to PVSS.
use super::setup::MasterPublicKey;
use ark_ec::PrimeGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, UniformRand};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Ciphertext<G: PrimeGroup> {
    pub c_0: G,
    pub c_1: G,
}

pub fn encrypt_with_randomness<G: ark_ec::scalar_mul::ScalarMul>(
    generator: G,
    mpk: &MasterPublicKey<G>,
    message: G,
    randomness: G::ScalarField,
) -> Ciphertext<G> {
    Ciphertext {
        c_0: message + crate::arithmetic::fixed_base_mul(mpk.pk, randomness),
        c_1: crate::arithmetic::fixed_base_mul(generator, randomness),
    }
}

pub fn encrypt<G: ark_ec::scalar_mul::ScalarMul, R: RngCore>(
    generator: G,
    mpk: &MasterPublicKey<G>,
    message: G,
    rng: &mut R,
) -> Ciphertext<G> {
    encrypt_with_randomness(generator, mpk, message, G::ScalarField::rand(rng))
}
