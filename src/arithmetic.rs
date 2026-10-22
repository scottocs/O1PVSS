//! Algebraic accelerators. Tables contain public bases only, never witnesses,
//! nonces, ciphertexts, verification decisions or decryption shares.
use ark_ec::{
    scalar_mul::{BatchMulPreprocessing, ScalarMul},
    CurveGroup,
};
use ark_serialize::CanonicalSerialize;
use std::{collections::HashMap, sync::Arc};

/// One cache entry for an entire public registry avoids per-key LRU thrashing.
pub(crate) struct FixedBases<G: ScalarMul> {
    tables: HashMap<G, BatchMulPreprocessing<G>>,
}

impl<G: ScalarMul> FixedBases<G> {
    pub(crate) fn mul(&self, base: G, scalar: G::ScalarField) -> G {
        match self.tables.get(&base) {
            Some(table) => G::from(table.batch_mul(&[scalar])[0]),
            None => base * scalar, // dynamic transcript bases are never retained
        }
    }
}

pub(crate) fn fixed_bases<G: ScalarMul>(bases: &[G]) -> Arc<FixedBases<G>> {
    let mut key = Vec::new();
    bases
        .serialize_uncompressed(&mut key)
        .expect("public registry encoding");
    crate::cache::get_or_try_insert("fixed-public-registry", key, || {
        Some(FixedBases {
            tables: bases
                .iter()
                .copied()
                .map(|base| (base, BatchMulPreprocessing::new(base, 128)))
                .collect(),
        })
    })
    .expect("public registry tables")
}

/// Reuse arkworks' fixed-base preprocessing without changing scalar arithmetic.
/// Bind both coordinates: compressed encodings can collide on malformed inputs.
pub(crate) fn fixed_base_mul<G: ScalarMul>(base: G, scalar: G::ScalarField) -> G {
    let mut key = Vec::new();
    base.serialize_uncompressed(&mut key)
        .expect("public base encoding");
    let table = crate::cache::get_or_try_insert("fixed-base-multiplication", key, || {
        Some(BatchMulPreprocessing::new(base, 128))
    })
    .expect("public multiplication table");
    G::from(table.batch_mul(&[scalar])[0])
}

/// Variable-base MSM for public proof responses or interpolation weights.
/// Callers validate incoming points before invoking this arithmetic kernel.
pub(crate) fn public_msm<G: CurveGroup>(bases: &[G], scalars: &[G::ScalarField]) -> G {
    assert_eq!(bases.len(), scalars.len());
    if bases.len() < 4 {
        return bases
            .iter()
            .zip(scalars)
            .fold(G::zero(), |sum, (b, s)| sum + *b * s);
    }
    G::msm_unchecked(&G::normalize_batch(bases), scalars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    use ark_ec::pairing::PairingOutput;
    use ark_ff::PrimeField;
    use ark_std::{test_rng, UniformRand, Zero};

    fn fixed_matches_reference<G: ScalarMul>() {
        let mut rng = test_rng();
        for base in [G::zero(), G::rand(&mut rng), G::rand(&mut rng)] {
            for scalar in [
                G::ScalarField::zero(),
                G::ScalarField::from(1),
                -G::ScalarField::from(1),
                G::ScalarField::rand(&mut rng),
            ] {
                assert_eq!(fixed_base_mul(base, scalar), base * scalar);
            }
        }
    }
    #[test]
    fn public_fixed_tables_match_all_three_group_operations() {
        fixed_matches_reference::<G1Projective>();
        fixed_matches_reference::<G2Projective>();
        fixed_matches_reference::<PairingOutput<Bls12_381>>();
    }
    fn msm_matches_reference<G: CurveGroup<ScalarField = Fr>>() {
        let mut rng = test_rng();
        for n in [0, 1, 3, 4, 17, 129] {
            let mut bases: Vec<G> = (0..n).map(|_| G::rand(&mut rng)).collect();
            let mut scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            if n > 1 {
                bases[0] = G::zero();
                scalars[1] = Fr::zero();
            }
            let expected = bases
                .iter()
                .zip(&scalars)
                .fold(G::zero(), |sum, (b, s)| sum + b.mul_bigint(s.into_bigint()));
            assert_eq!(public_msm(&bases, &scalars), expected);
        }
    }
    #[test]
    fn public_msm_matches_independent_scalar_products() {
        msm_matches_reference::<G1Projective>();
        msm_matches_reference::<G2Projective>();
    }

    #[test]
    fn registry_tables_bind_public_bases_and_never_retain_dynamic_fallbacks() {
        let mut rng = test_rng();
        let a = G1Projective::rand(&mut rng);
        let b = G1Projective::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        let first = fixed_bases(&[a]);
        let second = fixed_bases(&[b]);
        assert_eq!(first.mul(a, s), a * s);
        assert_eq!(first.mul(b, s), b * s);
        assert_eq!(second.mul(b, s), b * s);
        assert_eq!(first.tables.len(), 1);
        assert!(!first.tables.contains_key(&b));
    }
}
