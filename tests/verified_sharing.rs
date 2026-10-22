use ark_bls12_381::{Bls12_381 as E, Fr, G1Projective as G};
use ark_ec::PrimeGroup;
use ark_std::{test_rng, UniformRand};
use o1pvss::{
    pvss::{elgamal_pvss::ElGamalPVSS as First, silent_setup_pvss::SilentSetupPVSS as Second},
    utils::precompute_lagrange_coefficients,
};

#[test]
fn first_receipt_reuses_only_immutable_validated_input() {
    let mut rng = test_rng();
    let (points, coefficients) = precompute_lagrange_coefficients::<Fr>(5);
    let (pp, keys) =
        First::<G>::setup_with_committee_size(128, 3, 5, 2, points, coefficients, &mut rng)
            .unwrap();
    for _ in 0..2 {
        let secret = Fr::rand(&mut rng);
        let (ct, proof) = First::<G>::share(secret, &pp, &mut rng).unwrap();
        let verified = First::<G>::verify_sharing(&ct, &proof, &pp).unwrap();
        let mut shares = vec![];
        for (sk, pk) in &keys[..3] {
            let (d, pi) = verified.pre_recon(sk, &mut rng).unwrap();
            assert!(verified.dec_vrf(d, &pi, pk));
            assert!(First::<G>::dec_vrf(d, &pi, pk, &ct, &pp));
            assert!(!verified.dec_vrf(d + G::generator(), &pi, pk));
            let mut foreign = pk.clone();
            foreign.pk_i += G::generator();
            assert!(!verified.dec_vrf(d, &pi, &foreign));
            let mut wrong_epoch = sk.clone();
            wrong_epoch.setup_digest[0] ^= 1;
            assert!(verified.pre_recon(&wrong_epoch, &mut rng).is_err());
            shares.push((sk.id, d));
        }
        assert_eq!(
            verified.reconstruct(&shares).unwrap(),
            pp.generator * secret
        );
        assert_eq!(
            verified.reconstruct(&shares).unwrap(),
            First::<G>::reconstruct(&ct, &shares, &pp, &mut rng).unwrap()
        );
        assert!(verified.reconstruct(&[shares[0]; 3]).is_err());
        let mut changed = ct.clone();
        changed.c_0 += G::generator();
        assert!(First::<G>::verify_sharing(&changed, &proof, &pp).is_err());
        let mut bad = ct.clone();
        bad.c_1.y += ark_bls12_381::Fq::from(1);
        assert!(First::<G>::verify_sharing(&bad, &proof, &pp).is_err());
    }
}

#[test]
fn second_receipt_preserves_eligibility_proof_and_pairing_checks() {
    let mut rng = test_rng();
    let (pp, keys) = Second::<E>::setup(128, 3, 8, &mut rng).unwrap();
    for _ in 0..2 {
        let secret = Fr::rand(&mut rng);
        let (ct, proof) = Second::<E>::share(secret, &pp, &mut rng).unwrap();
        let verified = Second::<E>::verify_sharing(&ct, &proof, &pp).unwrap();
        let mut shares = vec![];
        for (sk, pk) in &keys[..3] {
            let (d, pi) = verified.pre_recon(sk, &mut rng).unwrap();
            assert!(verified.dec_vrf(d, &pi, pk));
            assert!(Second::<E>::dec_vrf(d, &pi, pk, &ct, &pp));
            assert!(!verified.dec_vrf(d + ct.gamma_g2, &pi, pk));
            assert!(!verified.dec_vrf(d, &Some(()), pk));
            let mut dummy = pk.clone();
            dummy.id = 0;
            assert!(!verified.dec_vrf(d, &pi, &dummy));
            let mut foreign = pk.clone();
            foreign.bls_pk += pp.powers_of_tau.powers_of_g[0];
            assert!(!verified.dec_vrf(d, &pi, &foreign));
            let mut wrong_epoch = sk.clone();
            wrong_epoch.setup_digest[0] ^= 1;
            assert!(verified.pre_recon(&wrong_epoch, &mut rng).is_err());
            shares.push((sk.id, d));
        }
        assert_eq!(
            verified.reconstruct(&shares).unwrap(),
            pp.generator_t1 * secret
        );
        assert_eq!(
            verified.reconstruct(&shares).unwrap(),
            Second::<E>::reconstruct(&ct, &shares, &pp, &mut rng).unwrap()
        );
        assert!(verified.reconstruct(&[shares[0]; 3]).is_err());
        let mut changed = ct.clone();
        changed.c_3 += pp.generator_t1;
        assert!(Second::<E>::verify_sharing(&changed, &proof, &pp).is_err());
        let mut bad = ct.clone();
        bad.c_3.0 = ark_bls12_381::Fq12::default();
        assert!(Second::<E>::verify_sharing(&bad, &proof, &pp).is_err());
    }
}

#[test]
fn all_comparison_verifiers_reject_malformed_dynamic_group_elements() {
    use o1pvss::pvss::{
        albatross::Albatross, dhpvss::DHPVSS, illusi::Illusi,
        preconstructed_pvss::PreconstructedPVSS,
    };
    let mut rng = test_rng();
    let (_, coefficients) = precompute_lagrange_coefficients::<Fr>(5);
    let pp = DHPVSS::<G>::setup(128, 2, 5, coefficients, &mut rng).unwrap();
    let dealer = DHPVSS::<G>::d_key_gen(&pp, &mut rng);
    let keys: Vec<_> = (0..5)
        .map(|i| DHPVSS::<G>::key_gen(&pp, i, &mut rng))
        .collect();
    let ct = DHPVSS::<G>::dist(
        &pp,
        &dealer.pk_d,
        &dealer.sk_d,
        &keys,
        G::rand(&mut rng),
        &mut rng,
    )
    .unwrap();
    let receipt = DHPVSS::<G>::verify_sharing(&pp, &dealer.pk_d, &keys, &ct).unwrap();
    let (d, proof) = receipt.pre_recon(0, &keys[0], &mut rng).unwrap();
    assert!(receipt.dec_vrf(0, &d, &proof));
    assert!(receipt.pre_recon(0, &keys[1], &mut rng).is_err());
    let mut bad_d = d;
    bad_d.y += ark_bls12_381::Fq::from(1);
    assert!(!receipt.dec_vrf(0, &bad_d, &proof));
    let mut bad = ct.clone();
    bad.ciphertexts[0].y += ark_bls12_381::Fq::from(1);
    assert!(DHPVSS::<G>::verify_sharing(&pp, &dealer.pk_d, &keys, &bad).is_err());

    let (pp, _) = Albatross::setup::<G, _>(5, 3, 1, 0, &mut rng).unwrap();
    let ct = Albatross::share(&[Fr::rand(&mut rng)], &pp, &mut rng).unwrap();
    Albatross::verify(&ct, &pp).unwrap();
    let mut bad = ct;
    bad.encrypted_shares[0].y += ark_bls12_381::Fq::from(1);
    assert!(Albatross::verify(&bad, &pp).is_err());

    let (pp, _) = PreconstructedPVSS::setup::<G, _>(5, 3, 0, &mut rng).unwrap();
    let s = Fr::rand(&mut rng);
    let anchor = PreconstructedPVSS::preconstruct(s, &pp).unwrap();
    let ct = PreconstructedPVSS::share(s, anchor, &pp, &mut rng).unwrap();
    PreconstructedPVSS::verify(&ct, anchor, &pp).unwrap();
    let mut bad = ct;
    bad.encrypted_shares[0].y += ark_bls12_381::Fq::from(1);
    assert!(PreconstructedPVSS::verify(&bad, anchor, &pp).is_err());

    let (pp, _) = Illusi::setup::<G, _>(5, 3, &mut rng).unwrap();
    let ct = Illusi::share(Fr::rand(&mut rng), &pp, &mut rng);
    Illusi::verify(&ct, &pp, &mut rng).unwrap();
    let mut bad = ct;
    bad.ciphertexts[0][0].y += ark_bls12_381::Fq::from(1);
    assert!(Illusi::verify(&bad, &pp, &mut rng).is_err());
}
