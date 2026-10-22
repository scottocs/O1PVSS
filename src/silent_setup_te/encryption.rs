//! Ordinary CPA-STE. The matrix uses tau^t, and t counts real shareholders.
use super::{kzg::PowersOfTau, setup::AggregateKey};
use crate::arithmetic::fixed_base_mul;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, UniformRand};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    pub gamma_g2: E::G2,
    /// Columns 1 and 6 of A^v.
    pub sa1: [E::G1; 2],
    /// Columns 2, 3, 4, 5, 7 and 8 of A^v.
    pub sa2: [E::G2; 6],
    pub c_3: PairingOutput<E>,
}

/// Column-wise exponentiation of A(statement_gamma)^v. Identity cells contribute zero
/// in arkworks' additive notation, corresponding to multiplicative 1 in the paper.
pub fn matrix_image<E: Pairing>(
    apk: &AggregateKey<E>,
    t: usize,
    params: &PowersOfTau<E>,
    statement_gamma: E::G2,
    v: &[E::ScalarField; 5],
) -> ([E::G1; 2], [E::G2; 6], PairingOutput<E>) {
    let g = params.powers_of_g[0];
    let h = params.powers_of_h[0];
    (
        [
            fixed_base_mul(apk.ask, v[0])
                + fixed_base_mul(params.powers_of_g[t].into_group(), v[3])
                + fixed_base_mul(g.into_group(), v[4]),
            fixed_base_mul(g.into_group(), v[2]),
        ],
        [
            fixed_base_mul(h.into_group(), v[0]) + statement_gamma * v[2],
            fixed_base_mul(apk.z_g2, v[0]),
            fixed_base_mul(params.powers_of_h[1].into_group(), v[0] + v[1]),
            fixed_base_mul(h.into_group(), v[1]),
            fixed_base_mul(h.into_group(), v[3]),
            fixed_base_mul(params.powers_of_h[1] + apk.h_minus1, v[4]),
        ],
        fixed_base_mul(apk.e_gh, v[4]),
    )
}

pub fn encrypt_with_randomness<E: Pairing>(
    apk: &AggregateKey<E>,
    t: usize,
    params: &PowersOfTau<E>,
    message: PairingOutput<E>,
    gamma: E::ScalarField,
    v: &[E::ScalarField; 5],
) -> Ciphertext<E> {
    let gamma_g2 = fixed_base_mul(params.powers_of_h[0].into_group(), gamma);
    let (sa1, sa2, mask) = matrix_image(apk, t, params, gamma_g2, v);
    Ciphertext {
        gamma_g2,
        sa1,
        sa2,
        c_3: message + mask,
    }
}

pub fn encrypt<E: Pairing, R: RngCore>(
    apk: &AggregateKey<E>,
    t: usize,
    params: &PowersOfTau<E>,
    message: PairingOutput<E>,
    rng: &mut R,
) -> Ciphertext<E> {
    let gamma = E::ScalarField::rand(rng);
    let v = std::array::from_fn(|_| E::ScalarField::rand(rng));
    encrypt_with_randomness(apk, t, params, message, gamma, &v)
}
