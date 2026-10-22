use ark_bls12_381::{Fr, G1Projective};
use ark_std::{test_rng, UniformRand};
use o1pvss::pvss::illusi::Illusi;

#[test]
fn distinct_subsets_and_fresh_transcripts_recover_source_encoding() {
    let mut rng = test_rng();
    for (n, t) in [(1, 1), (7, 1), (7, 4), (7, 7)] {
        let (pp, keys) = Illusi::setup::<G1Projective, _>(n, t, &mut rng).unwrap();
        let ids: Vec<_> = (n - t + 1..=n).rev().collect();
        let plan = pp.prepare_reconstruction(&ids).unwrap();
        for _ in 0..2 {
            let s = Fr::rand(&mut rng);
            let trx = Illusi::share(s, &pp, &mut rng);
            let verified = Illusi::verify(&trx, &pp, &mut rng).unwrap();
            let shares: Vec<_> = ids
                .iter()
                .map(|i| verified.pre_recon(&keys[i - 1], &mut rng).unwrap())
                .collect();
            assert!(shares.iter().all(|share| verified.dec_vrf(share)));
            let values: Vec<_> = shares.iter().map(|d| (d.id, d.value)).collect();
            assert_eq!(verified.reconstruct(&values, &plan).unwrap(), pp.encode(s));
        }
    }
}

#[test]
fn rejects_changed_statements_proofs_keys_and_reconstruction_contexts() {
    let mut rng = test_rng();
    let (pp, keys) = Illusi::setup::<G1Projective, _>(7, 4, &mut rng).unwrap();
    let (other, other_keys) = Illusi::setup::<G1Projective, _>(7, 4, &mut rng).unwrap();
    let trx = Illusi::share(Fr::rand(&mut rng), &pp, &mut rng);
    let delta = G1Projective::rand(&mut rng);
    let mut bad = trx.clone();
    bad.commitments[0] += delta;
    assert!(Illusi::verify(&bad, &pp, &mut rng).is_err()); // low-degree test includes 0
    for component in 0..3 {
        let mut bad = trx.clone();
        bad.ciphertexts[2][component] += delta;
        assert!(Illusi::verify(&bad, &pp, &mut rng).is_err());
    }
    let mut bad = trx.clone();
    bad.proofs[2].response[1] += Fr::from(1u64);
    assert!(Illusi::verify(&bad, &pp, &mut rng).is_err());
    let mut bad = trx.clone();
    bad.proofs.swap(0, 1);
    assert!(Illusi::verify(&bad, &pp, &mut rng).is_err());
    let mut bad = trx.clone();
    bad.ciphertexts.pop();
    assert!(Illusi::verify(&bad, &pp, &mut rng).is_err());
    assert!(Illusi::verify(&trx, &other, &mut rng).is_err());
    let verified = Illusi::verify(&trx, &pp, &mut rng).unwrap();
    assert!(verified.pre_recon(&other_keys[0], &mut rng).is_err());
    let mut share = verified.pre_recon(&keys[0], &mut rng).unwrap();
    share.value += delta;
    assert!(!verified.dec_vrf(&share));
    let mut share = verified.pre_recon(&keys[0], &mut rng).unwrap();
    share.id = 2;
    assert!(!verified.dec_vrf(&share));
    assert!(pp.prepare_reconstruction(&[1, 2, 3]).is_err());
    assert!(pp.prepare_reconstruction(&[1, 2, 3, 3]).is_err());
    assert!(pp.prepare_reconstruction(&[0, 1, 2, 3]).is_err());
    let values: Vec<_> = keys[..4]
        .iter()
        .map(|k| {
            let d = verified.pre_recon(k, &mut rng).unwrap();
            (d.id, d.value)
        })
        .collect();
    let plan = other.prepare_reconstruction(&[1, 2, 3, 4]).unwrap();
    assert!(verified.reconstruct(&values, &plan).is_err());
    let plan = pp.prepare_reconstruction(&[4, 3, 2, 1]).unwrap();
    assert!(verified.reconstruct(&values, &plan).is_err());
}
