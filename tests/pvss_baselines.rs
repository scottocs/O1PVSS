use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::PrimeGroup;
use ark_ff::{One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{test_rng, UniformRand};
use o1pvss::pvss::{
    albatross::{Albatross, Parameters, Sharing},
    preconstructed_pvss::PreconstructedPVSS,
};

fn exercise(pp: &Parameters<G>, ct: &Sharing<G>, secrets: &[Fr], preconstructed: bool) {
    let accepted = if preconstructed {
        PreconstructedPVSS::verify(ct, ct.preconstruction.unwrap(), pp).unwrap()
    } else {
        Albatross::verify(ct, pp).unwrap()
    };
    let mut rng = test_rng();
    // This helper intentionally tests rejection of shares, not decryption;
    // actual decryption keys are exercised by the end-to-end tests below.
    assert!(pp.prepare_reconstruction(&vec![1; pp.threshold()]).is_err());
    assert!(pp.prepare_reconstruction(&[1]).is_err());
    let ids: Vec<_> = (1..=pp.threshold()).collect();
    let plan = pp.prepare_reconstruction(&ids).unwrap();
    assert!(accepted.reconstruct(&[], &plan).is_err());
    assert!(!accepted.verify_reconstruction(&[], &vec![G::zero(); secrets.len()], &mut rng));
    let mut bytes = vec![];
    ct.serialize_compressed(&mut bytes).unwrap();
    let decoded = Sharing::<G>::deserialize_compressed(bytes.as_slice()).unwrap();
    assert_eq!(decoded.encrypted_shares, ct.encrypted_shares);
    assert_eq!(decoded.proof.response, ct.proof.response);
}

#[test]
fn albatross_packed_all_qualified_subsets_and_tampering() {
    let mut rng = test_rng();
    for ell in [1, 2] {
        let (pp, keys) = Albatross::setup::<G, _>(5, 3, ell, 4, &mut rng).unwrap();
        let secrets = if ell == 1 {
            vec![Fr::rand(&mut rng)]
        } else {
            vec![Fr::zero(), Fr::from(19u64)]
        };
        let ct = Albatross::share(&secrets, &pp, &mut rng).unwrap();
        let accepted = Albatross::verify(&ct, &pp).unwrap();
        let mut decrypted = vec![];
        for key in &keys {
            assert!(pp.validate_key(key));
            let d = accepted.pre_recon(key, &mut rng).unwrap();
            assert!(accepted.dec_vrf(&d));
            let mut bad = d.clone();
            bad.value += G::generator();
            assert!(!accepted.dec_vrf(&bad));
            bad = d.clone();
            bad.id = d.id % 5 + 1;
            assert!(!accepted.dec_vrf(&bad));
            bad = d.clone();
            bad.response += Fr::one();
            assert!(!accepted.dec_vrf(&bad));
            decrypted.push((d.id, d.value));
        }
        let expected: Vec<_> = secrets.iter().map(|s| G::generator() * s).collect();
        for mask in 0u32..32 {
            let shares: Vec<_> = decrypted
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, s)| *s)
                .rev()
                .collect();
            let ids: Vec<_> = shares.iter().map(|s| s.0).collect();
            if shares.len() < 3 {
                assert!(pp.prepare_reconstruction(&ids).is_err());
                continue;
            }
            let plan = pp.prepare_reconstruction(&ids).unwrap();
            let output = accepted.reconstruct(&shares, &plan).unwrap();
            assert_eq!(output, expected);
            assert!(accepted.verify_reconstruction(&shares, &output, &mut rng));
            let mut bad = output;
            bad[0] += G::generator();
            assert!(!accepted.verify_reconstruction(&shares, &bad, &mut rng));
            let mut bad = shares.clone();
            bad.swap(0, 1);
            assert!(accepted.reconstruct(&bad, &plan).is_err());
        }
        let mut bad = ct.clone();
        bad.encrypted_shares[0] += G::generator();
        assert!(Albatross::verify(&bad, &pp).is_err());
        bad = ct.clone();
        bad.proof.response.push(Fr::zero());
        assert!(Albatross::verify(&bad, &pp).is_err());
        bad = ct.clone();
        bad.proof.response[0] += Fr::one();
        assert!(Albatross::verify(&bad, &pp).is_err());
        bad = ct.clone();
        bad.encrypted_shares.pop();
        assert!(Albatross::verify(&bad, &pp).is_err());
        bad = ct.clone();
        bad.preconstruction = Some(G::generator());
        assert!(Albatross::verify(&bad, &pp).is_err());
        let epoch =
            Albatross::from_public_keys(pp.generator(), pp.public_keys().to_vec(), 3, ell, 5)
                .unwrap();
        assert!(Albatross::verify(&ct, &epoch).is_err());
        let other = Albatross::share(&secrets, &pp, &mut rng).unwrap();
        let other = Albatross::verify(&other, &pp).unwrap();
        assert!(!other.dec_vrf(&accepted.pre_recon(&keys[0], &mut rng).unwrap()));
        exercise(&pp, &ct, &secrets, false);
    }
}

#[test]
fn ppvss_preconstruction_and_both_reconstruction_paths() {
    let mut rng = test_rng();
    let (pp, keys) = PreconstructedPVSS::setup::<G, _>(5, 3, 0, &mut rng).unwrap();
    let secret = Fr::rand(&mut rng);
    let anchor = PreconstructedPVSS::preconstruct(secret, &pp).unwrap();
    let ct = PreconstructedPVSS::share(secret, anchor, &pp, &mut rng).unwrap();
    let accepted = PreconstructedPVSS::verify(&ct, anchor, &pp).unwrap();
    let shares: Vec<_> = keys
        .iter()
        .map(|key| {
            assert!(pp.validate_key(key));
            let share = accepted.pre_recon(key, &mut rng).unwrap();
            assert!(accepted.dec_vrf(&share));
            (share.id, share.value)
        })
        .collect();
    for ids in [vec![1, 3, 5], vec![5, 4, 2], vec![5, 4, 3, 2, 1]] {
        let plan = pp.prepare_reconstruction(&ids).unwrap();
        let subset: Vec<_> = ids.iter().map(|i| shares[*i - 1]).collect();
        assert_eq!(
            accepted.reconstruct(&subset, &plan).unwrap(),
            vec![pp.generator() * secret]
        );
    }
    assert_eq!(
        PreconstructedPVSS::optimistic_open(secret, anchor, &pp).unwrap(),
        pp.generator() * secret
    );
    assert!(PreconstructedPVSS::optimistic_open(secret + Fr::one(), anchor, &pp).is_err());
    assert!(PreconstructedPVSS::share(secret, anchor + G::generator(), &pp, &mut rng).is_err());
    assert!(PreconstructedPVSS::verify(&ct, anchor + G::generator(), &pp).is_err());
    let mut bad = ct.clone();
    bad.preconstruction = Some(anchor + G::generator());
    assert!(PreconstructedPVSS::verify(&bad, bad.preconstruction.unwrap(), &pp).is_err());
    bad = ct.clone();
    bad.encrypted_shares[4] += G::generator();
    assert!(PreconstructedPVSS::verify(&bad, anchor, &pp).is_err());
    bad = ct.clone();
    bad.proof.challenge += Fr::one();
    assert!(PreconstructedPVSS::verify(&bad, anchor, &pp).is_err());
    let epoch = PreconstructedPVSS::from_public_keys(
        pp.generator(),
        pp.public_keys().to_vec(),
        pp.preconstruction_base().unwrap(),
        3,
        1,
    )
    .unwrap();
    assert!(PreconstructedPVSS::verify(&ct, anchor, &epoch).is_err());
    let alb =
        Albatross::from_public_keys(pp.generator(), pp.public_keys().to_vec(), 3, 1, 0).unwrap();
    assert!(Albatross::verify(&ct, &alb).is_err());
    assert!(Albatross::share(&[secret], &pp, &mut rng).is_err());
    assert!(PreconstructedPVSS::share(secret, anchor, &alb, &mut rng).is_err());
    exercise(&pp, &ct, &[secret], true);
}

#[test]
fn baseline_parameter_validation_and_registry_keys() {
    let mut rng = test_rng();
    for (n, t, l) in [(0, 0, 0), (3, 0, 1), (3, 4, 1), (3, 3, 0), (3, 3, 3)] {
        assert!(Albatross::setup::<G, _>(n, t, l, 0, &mut rng).is_err());
    }
    let (pp, keys) = Albatross::setup::<G, _>(3, 2, 1, 0, &mut rng).unwrap();
    let (other, _) = Albatross::setup::<G, _>(3, 2, 1, 0, &mut rng).unwrap();
    assert!(!other.validate_key(&keys[0]));
    let mut pks = pp.public_keys().to_vec();
    pks[0] = G::zero();
    assert!(Albatross::from_public_keys(pp.generator(), pks, 2, 1, 0).is_err());
    assert!(PreconstructedPVSS::from_public_keys(
        pp.generator(),
        pp.public_keys().to_vec(),
        G::zero(),
        2,
        0
    )
    .is_err());
    assert!(pp.prepare_reconstruction(&[0, 1]).is_err());
    assert!(pp.prepare_reconstruction(&[1, 4]).is_err());
}
