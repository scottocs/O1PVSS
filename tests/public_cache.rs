use ark_bls12_381::{Bls12_381 as E, Fr, G1Projective as G};
use ark_serialize::CanonicalSerialize;
use ark_std::{test_rng, UniformRand};
use o1pvss::{
    elgamal_te::decryption::{decrypt, decrypt_with_points},
    pvss::{elgamal_pvss::ElGamalPVSS as First, silent_setup_pvss::SilentSetupPVSS as Second},
    silent_setup_te::decryption::{decrypt as reference_ste, prepare_reconstruction},
    utils::precompute_lagrange_coefficients,
};

fn bytes(value: &impl CanonicalSerialize) -> Vec<u8> {
    let mut out = vec![];
    value.serialize_compressed(&mut out).unwrap();
    out
}

#[test]
fn cached_scalar_interpolation_matches_reference_for_fresh_shares_and_orders() {
    let mut rng = test_rng();
    let (points, matrix) = precompute_lagrange_coefficients::<Fr>(7);
    let (pp, keys) =
        First::<G>::setup_with_committee_size(128, 3, 7, 2, points, matrix, &mut rng).unwrap();
    for _ in 0..2 {
        let secret = Fr::rand(&mut rng);
        let (ct, proof) = First::<G>::share(secret, &pp, &mut rng).unwrap();
        let shares: Vec<_> = keys
            .iter()
            .map(|(sk, _)| {
                (
                    sk.id,
                    First::<G>::pre_recon(&ct, &proof, sk, &pp, &mut rng)
                        .unwrap()
                        .0,
                )
            })
            .collect();
        for ids in [
            vec![0, 1, 2],
            vec![2, 1, 0],
            vec![0, 3, 6],
            vec![0, 1, 3, 5],
        ] {
            let subset: Vec<_> = ids.iter().map(|id| shares[*id]).collect();
            assert_eq!(
                decrypt_with_points(&ct, &subset, 3, &pp.root_powers),
                decrypt(&ct, &subset, 3, &pp.lagrange_coeffs)
            );
        }
        assert!(decrypt_with_points(&ct, &[shares[0]; 3], 3, &pp.root_powers).is_none());
        assert!(decrypt_with_points(
            &ct,
            &[(7, shares[0].1), shares[1], shares[2]],
            3,
            &pp.root_powers
        )
        .is_none());
    }
}

#[test]
fn cached_ste_plans_bind_setup_subset_and_threshold_but_not_ciphertexts() {
    let mut rng = test_rng();
    // Independent setups with identical n,t must not share public-key aggregates.
    for _ in 0..2 {
        let (pp, keys) = Second::<E>::setup(128, 3, 8, &mut rng).unwrap();
        let before = bytes(&pp);
        for _ in 0..2 {
            let secret = Fr::rand(&mut rng);
            let (ct, proof) = Second::<E>::share(secret, &pp, &mut rng).unwrap();
            let shares: Vec<_> = keys
                .iter()
                .map(|(sk, _)| {
                    (
                        sk.id,
                        Second::<E>::pre_recon(&ct, &proof, sk, &pp, &mut rng)
                            .unwrap()
                            .0,
                    )
                })
                .collect();
            for ids in [
                vec![1, 2, 3],
                vec![3, 2, 1],
                vec![1, 4, 7],
                vec![1, 2, 4, 6],
            ] {
                let subset: Vec<_> = ids.iter().map(|id| shares[*id - 1]).collect();
                let expected =
                    reference_ste(&ct, &subset, 3, &pp.aggregate_key, &pp.powers_of_tau).unwrap();
                assert_eq!(
                    Second::<E>::reconstruct(&ct, &subset, &pp, &mut rng).unwrap(),
                    expected
                );
                assert_eq!(
                    Second::<E>::reconstruct(&ct, &subset, &pp, &mut rng).unwrap(),
                    pp.generator_t1 * secret
                );
            }
            assert!(prepare_reconstruction(
                &[1, 1, 2],
                3,
                &pp.aggregate_key,
                &pp.powers_of_tau,
                &pp.setup_digest
            )
            .is_none());
            assert!(prepare_reconstruction(
                &[0, 1, 2],
                3,
                &pp.aggregate_key,
                &pp.powers_of_tau,
                &pp.setup_digest
            )
            .is_none());
            assert!(prepare_reconstruction(
                &[1, 2, 3],
                4,
                &pp.aggregate_key,
                &pp.powers_of_tau,
                &pp.setup_digest
            )
            .is_none());
        }
        assert_eq!(
            bytes(&pp),
            before,
            "runtime caches must not change serialized setup material"
        );
    }
}

#[test]
fn cached_generator_validation_still_rejects_malformed_coordinates() {
    use ark_serialize::Valid;
    let mut rng = test_rng();
    let (points, matrix) = precompute_lagrange_coefficients::<Fr>(5);
    let (pp, _) =
        First::<G>::setup_with_committee_size(128, 3, 5, 2, points, matrix, &mut rng).unwrap();
    First::<G>::share(Fr::from(7u64), &pp, &mut rng).unwrap();
    let mut malformed = pp.clone();
    malformed.generator.y += ark_bls12_381::Fq::from(2u64);
    assert!(malformed.generator.check().is_err());
    assert!(First::<G>::share(Fr::from(7u64), &malformed, &mut rng).is_err());
}
