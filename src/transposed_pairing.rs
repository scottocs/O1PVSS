//! Reverse protocol source-group roles while retaining the physical pairing.
//!
//! All protocol material, including the degree-capped CRS and secret-key hints,
//! is generated through this engine. No element is mapped between source groups.
use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use std::marker::PhantomData;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transposed<E: Pairing>(PhantomData<E>);

impl<E: Pairing> Pairing for Transposed<E> {
    type BaseField = E::BaseField;
    type ScalarField = E::ScalarField;
    type G1 = E::G2;
    type G1Affine = E::G2Affine;
    type G1Prepared = E::G2Prepared;
    type G2 = E::G1;
    type G2Affine = E::G1Affine;
    type G2Prepared = E::G1Prepared;
    type TargetField = E::TargetField;

    fn multi_miller_loop(
        a: impl IntoIterator<Item = impl Into<Self::G1Prepared>>,
        b: impl IntoIterator<Item = impl Into<Self::G2Prepared>>,
    ) -> MillerLoopOutput<Self> {
        MillerLoopOutput(E::multi_miller_loop(b, a).0)
    }

    fn final_exponentiation(mlo: MillerLoopOutput<Self>) -> Option<PairingOutput<Self>> {
        E::final_exponentiation(MillerLoopOutput(mlo.0)).map(|out| PairingOutput(out.0))
    }
}

/// Online-oriented BLS12-381 configuration for Instantiation II.
pub type OnlineBls12_381 = Transposed<ark_bls12_381::Bls12_381>;
