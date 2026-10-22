//! Proof-free partial decryption and combination of previously validated shares.
use super::{encryption::Ciphertext, setup::SecretKey};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::One;

pub fn partial_decrypt<G: PrimeGroup>(ciphertext: &Ciphertext<G>, sk: &SecretKey<G>) -> G {
    ciphertext.c_1 * sk.sk_i
}

/// Returns None for duplicate/ineligible indices or malformed interpolation data.
/// The caller supplies the audited threshold and validates the supplied shares.
pub fn decrypt<G: PrimeGroup>(
    ciphertext: &Ciphertext<G>,
    shares: &[(usize, G)],
    threshold: usize,
    coefficients: &[Vec<G::ScalarField>],
) -> Option<G> {
    if threshold == 0 || shares.len() < threshold {
        return None;
    }
    let mut mask = G::zero();
    for (i, (id, share)) in shares.iter().enumerate() {
        let row = coefficients.get(*id)?;
        let mut coefficient = G::ScalarField::one();
        for (j, (other_id, _)) in shares.iter().enumerate() {
            if i != j {
                if id == other_id {
                    return None;
                }
                coefficient *= row.get(*other_id)?;
            }
        }
        mask += *share * coefficient;
    }
    Some(ciphertext.c_0 - mask)
}

/// Reusable public interpolation; each invocation still combines the supplied
/// fresh shares. Zero-based Rust IDs correspond to points 1,...,n.
pub fn decrypt_with_points<G: CurveGroup>(
    ciphertext: &Ciphertext<G>,
    shares: &[(usize, G)],
    threshold: usize,
    points: &[G::ScalarField],
) -> Option<G> {
    if threshold == 0 || shares.len() < threshold {
        return None;
    }
    let xs: Option<Vec<_>> = shares
        .iter()
        .map(|(id, _)| points.get(*id).copied())
        .collect();
    let weights = crate::cache::interpolation_weights(&xs?, &[G::ScalarField::from(0u64)])?;
    let bases: Vec<_> = shares.iter().map(|(_, d)| *d).collect();
    let mask = crate::arithmetic::public_msm(&bases, &weights[0]);
    Some(ciphertext.c_0 - mask)
}
