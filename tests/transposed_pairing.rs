use ark_bls12_381::{Bls12_381 as Physical, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{One, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::{test_rng, UniformRand};
use o1pvss::{
    pvss::silent_setup_pvss::SilentSetupPVSS as PVSS,
    silent_setup_te::{ceremony, kzg::KZG10},
    transposed_pairing::OnlineBls12_381 as E,
};

#[test]
fn transposed_pairing_preserves_physical_pairing_and_products() {
    let mut rng = test_rng();
    let p = G1Projective::rand(&mut rng);
    let q = G2Projective::rand(&mut rng);
    let a = Fr::rand(&mut rng);
    assert_eq!(E::pairing(q, p).0, Physical::pairing(p, q).0);
    assert_eq!(E::pairing(q * a, p).0, (Physical::pairing(p, q) * a).0);
    assert!(E::multi_pairing([q, -q], [p, p]).is_zero());
}

#[test]
fn transposed_full_setup_all_subsets_and_tampering() {
    let mut rng = test_rng();
    let (pp, keys) = PVSS::<E>::setup_with_capacity(128, 3, 8, 5, &mut rng).unwrap();
    assert!(PVSS::<E>::verify_setup(&pp, &pp.public_keys));
    // Logical G1 now uses physical G2; its degree cap remains n-1.
    assert_eq!(
        (
            pp.powers_of_tau.powers_of_g.len(),
            pp.powers_of_tau.powers_of_h.len()
        ),
        (8, 9)
    );
    let too_high = DensePolynomial::from_coefficients_vec(vec![Fr::one(); 9]);
    assert!(KZG10::<E, DensePolynomial<Fr>>::commit_g1(&pp.powers_of_tau, &too_high).is_err());
    let secret = Fr::rand(&mut rng);
    let (ct, proof) = PVSS::<E>::share(secret, &pp, &mut rng).unwrap();
    assert!(PVSS::<E>::verify(&ct, &proof, &pp));
    // Physical group sizes match the communication formulas.
    assert_eq!(ct.compressed_size() + proof.compressed_size(), 2464);
    let verified = PVSS::<E>::verify_sharing(&ct, &proof, &pp).unwrap();
    let mut all = Vec::new();
    for (sk, pk) in &keys {
        let (d, pi) = verified.pre_recon(sk, &mut rng).unwrap();
        assert_eq!(d.compressed_size(), 48);
        assert!(verified.dec_vrf(d, &pi, pk));
        assert!(!verified.dec_vrf(d + G1Projective::generator(), &pi, pk));
        assert!(!verified.dec_vrf(d, &Some(()), pk));
        all.push((sk.id, d));
    }
    for mask in 0..32 {
        let shares: Vec<_> = all
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, d)| *d)
            .rev()
            .collect();
        if shares.len() >= 3 {
            assert_eq!(
                verified.reconstruct(&shares).unwrap(),
                pp.generator_t1 * secret
            );
        } else {
            assert!(verified.reconstruct(&shares).is_err());
        }
    }
    assert!(verified.reconstruct(&[all[0]; 3]).is_err());
    assert!(verified
        .reconstruct(&[(0, ct.gamma_g2), all[0], all[1]])
        .is_err());
    let mut bad = ct.clone();
    bad.sa1[0] += G2Projective::generator();
    assert!(!PVSS::<E>::verify(&bad, &proof, &pp));
    let mut bad = proof.clone();
    bad.response_s += Fr::one();
    assert!(!PVSS::<E>::verify(&ct, &bad, &pp));
    let mut epoch = pp.clone();
    epoch.epoch += 1;
    assert!(!PVSS::<E>::verify(&ct, &proof, &epoch));
    let mut crs = pp.powers_of_tau.clone();
    crs.powers_of_g.push(G2Projective::generator().into());
    assert!(!ceremony::verify_final(&crs));
}

#[test]
fn transposed_public_ceremony_and_threshold_one() {
    let mut rng = test_rng();
    let initial = ceremony::initial::<E>(4);
    let one = ceremony::contribute(&initial, Fr::from(2u64), &mut rng).unwrap();
    let two = ceremony::contribute(&one.crs, Fr::from(3u64), &mut rng).unwrap();
    let record = ceremony::CeremonyRecord {
        initial,
        contributions: vec![one, two],
    };
    let crs = record.contributions[1].crs.clone();
    assert!(ceremony::verify_record(&crs, &record));
    let (pp, keys) = PVSS::<E>::setup_from_crs(128, 1, crs, record, 3, &mut rng).unwrap();
    assert!(PVSS::<E>::verify_setup(&pp, &pp.public_keys));
    for secret in [Fr::zero(), Fr::one()] {
        let (ct, proof) = PVSS::<E>::share(secret, &pp, &mut rng).unwrap();
        let v = PVSS::<E>::verify_sharing(&ct, &proof, &pp).unwrap();
        let (d, pi) = v.pre_recon(&keys[0].0, &mut rng).unwrap();
        assert!(v.dec_vrf(d, &pi, &keys[0].1));
        assert_eq!(
            v.reconstruct(&[(keys[0].0.id, d)]).unwrap(),
            pp.generator_t1 * secret
        );
    }
}
