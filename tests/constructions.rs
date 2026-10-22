use ark_bls12_381::{Bls12_381 as E, Fr, G1Projective as G};
use ark_ec::PrimeGroup;
use ark_ff::{One, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::{test_rng, UniformRand};
use o1pvss::{
    pvss::{
        adaptive_elgamal_pvss::AdaptiveElGamalPVSS as Adaptive,
        elgamal_pvss::{ElGamalPVSS as First, ElGamalPVSSParams},
        silent_setup_pvss::{SilentSetupPVSS as Second, SilentSetupPVSSParams},
    },
    silent_setup_te::{ceremony, kzg::KZG10},
    utils::precompute_lagrange_coefficients,
};

fn digest<T: CanonicalSerialize>(value: &T, domain: &'static [u8]) -> [u8; 32] {
    let mut transcript = merlin::Transcript::new(domain);
    let mut bytes = vec![];
    value.serialize_compressed(&mut bytes).unwrap();
    transcript.append_message(b"public-setup", &bytes);
    let mut result = [0; 32];
    transcript.challenge_bytes(b"setup-digest", &mut result);
    result
}
fn rebind_first(pp: &mut ElGamalPVSSParams<G>) {
    pp.setup_digest = [0; 32];
    pp.setup_digest = digest(pp, b"pvss-instantiation-i-setup");
}
fn rebind_second(pp: &mut SilentSetupPVSSParams<E>) {
    pp.setup_digest = [0; 32];
    pp.setup_digest = digest(pp, b"pvss-instantiation-ii-setup");
}

#[test]
fn test_elgamal_pvss_e2e_all_qualified_sets() {
    let mut rng = test_rng();
    let (points, coefficients) = precompute_lagrange_coefficients::<Fr>(5);
    let (pp, keys) =
        First::<G>::setup_with_committee_size(128, 3, 5, 2, points, coefficients, &mut rng)
            .unwrap();
    assert!(First::<G>::verify_setup(&pp, &pp.public_keys));
    let secret = Fr::rand(&mut rng);
    let (ct, proof) = First::<G>::share(secret, &pp, &mut rng).unwrap();
    assert!(First::<G>::verify(&ct, &proof, &pp));
    let mut all_shares = vec![];
    for (sk, pk) in &keys {
        let (d, pi) = First::<G>::pre_recon(&ct, &proof, sk, &pp, &mut rng).unwrap();
        assert!(First::<G>::dec_vrf(d, &pi, pk, &ct, &pp));
        assert!(!First::<G>::dec_vrf(d + G::generator(), &pi, pk, &ct, &pp));
        all_shares.push((sk.id, d));
    }
    for mask in 0u32..32 {
        let shares: Vec<_> = all_shares
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, share)| *share)
            .rev()
            .collect();
        if shares.len() >= 3 {
            assert_eq!(
                First::<G>::reconstruct(&ct, &shares, &pp, &mut rng).unwrap(),
                pp.generator * secret
            );
        } else {
            assert!(First::<G>::reconstruct(&ct, &shares, &pp, &mut rng).is_err());
        }
    }
    assert!(First::<G>::reconstruct(&ct, &[all_shares[0]; 3], &pp, &mut rng).is_err());
    assert!(First::<G>::reconstruct(
        &ct,
        &[(5, all_shares[0].1), all_shares[1], all_shares[2]],
        &pp,
        &mut rng
    )
    .is_err());
}

#[test]
fn first_proofs_bind_epoch_ciphertext_and_registered_keys() {
    let mut rng = test_rng();
    let (points, coefficients) = precompute_lagrange_coefficients::<Fr>(3);
    let (pp, keys) = First::<G>::setup(128, 2, 3, points, coefficients, &mut rng).unwrap();
    let (ct, proof) = First::<G>::share(Fr::one(), &pp, &mut rng).unwrap();
    let (d, pi) = First::<G>::pre_recon(&ct, &proof, &keys[0].0, &pp, &mut rng).unwrap();
    let mut epoch = pp.clone();
    epoch.epoch += 1;
    rebind_first(&mut epoch);
    assert!(First::<G>::verify_setup(&epoch, &epoch.public_keys));
    assert!(!First::<G>::verify(&ct, &proof, &epoch));
    assert!(!First::<G>::dec_vrf(d, &pi, &keys[0].1, &ct, &epoch));
    let mut altered = ct.clone();
    altered.c_0 += G::generator();
    assert!(!First::<G>::verify(&altered, &proof, &pp));
    assert!(!First::<G>::dec_vrf(d, &pi, &keys[0].1, &altered, &pp));
    let mut foreign = keys[0].1.clone();
    foreign.pk_i += G::generator();
    assert!(!First::<G>::dec_vrf(d, &pi, &foreign, &ct, &pp));
    foreign = keys[0].1.clone();
    foreign.id = 1;
    assert!(!First::<G>::dec_vrf(d, &pi, &foreign, &ct, &pp));
    // PreRecon keeps pi_s as an input but must not repeat sharing verification.
    let mut invalid_proof = proof.clone();
    invalid_proof.response_s += Fr::one();
    assert!(!First::<G>::verify(&ct, &invalid_proof, &pp));
    let (d, pi) = First::<G>::pre_recon(&ct, &invalid_proof, &keys[0].0, &pp, &mut rng).unwrap();
    assert!(First::<G>::dec_vrf(d, &pi, &keys[0].1, &ct, &pp));
}

#[test]
fn first_public_audit_checks_equations_without_private_delivery() {
    let mut rng = test_rng();
    let (points, coefficients) = precompute_lagrange_coefficients::<Fr>(3);
    let (pp, _) = First::<G>::setup(128, 2, 3, points, coefficients, &mut rng).unwrap();
    let mut altered = pp.clone();
    altered.public_keys[0].pk_i += G::generator();
    rebind_first(&mut altered);
    assert!(!First::<G>::verify_setup(&altered, &altered.public_keys));
    altered = pp.clone();
    altered.master_pk_key.pk += G::generator();
    rebind_first(&mut altered);
    assert!(!First::<G>::verify_setup(&altered, &altered.public_keys));
    altered = pp.clone();
    altered
        .audit
        .contributions
        .push(altered.audit.contributions[0].clone());
    rebind_first(&mut altered);
    assert!(!First::<G>::verify_setup(&altered, &altered.public_keys));
    altered = pp.clone();
    altered.lagrange_coeffs[0][1] += Fr::one();
    rebind_first(&mut altered);
    assert!(!First::<G>::verify_setup(&altered, &altered.public_keys));
}

#[test]
fn test_silent_setup_pvss_e2e_exact_t_and_sparse_sets() {
    let mut rng = test_rng();
    let (pp, keys) = Second::<E>::setup_with_capacity(128, 3, 8, 5, &mut rng).unwrap();
    assert_eq!(keys.len(), 5);
    assert!(keys.iter().all(|(sk, _)| sk.id != 0));
    assert_eq!(pp.powers_of_tau.powers_of_g.len(), 8);
    assert_eq!(pp.powers_of_tau.powers_of_h.len(), 9);
    assert!(Second::<E>::verify_setup(&pp, &pp.public_keys));
    let secret = Fr::rand(&mut rng);
    let (ct, proof) = Second::<E>::share(secret, &pp, &mut rng).unwrap();
    assert!(Second::<E>::verify(&ct, &proof, &pp));
    let mut all_shares = vec![];
    for (sk, pk) in &keys {
        let (d, pi) = Second::<E>::pre_recon(&ct, &proof, sk, &pp, &mut rng).unwrap();
        assert!(pi.is_none());
        assert!(Second::<E>::dec_vrf(d, &pi, pk, &ct, &pp));
        assert!(!Second::<E>::dec_vrf(d, &Some(()), pk, &ct, &pp));
        all_shares.push((sk.id, d));
    }
    for mask in 0u32..32 {
        let shares: Vec<_> = all_shares
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, share)| *share)
            .rev()
            .collect();
        if shares.len() >= 3 {
            assert_eq!(
                Second::<E>::reconstruct(&ct, &shares, &pp, &mut rng).unwrap(),
                pp.generator_t1 * secret
            );
        } else {
            assert!(Second::<E>::reconstruct(&ct, &shares, &pp, &mut rng).is_err());
        }
    }
    assert!(Second::<E>::reconstruct(&ct, &[all_shares[0]; 3], &pp, &mut rng).is_err());
    let dummy = (0, ct.gamma_g2);
    assert!(
        Second::<E>::reconstruct(&ct, &[dummy, all_shares[0], all_shares[1]], &pp, &mut rng)
            .is_err()
    );
    assert!(Second::<E>::reconstruct(
        &ct,
        &[(6, all_shares[0].1), all_shares[1], all_shares[2]],
        &pp,
        &mut rng
    )
    .is_err());
}

#[test]
fn second_share_check_and_sharing_proof_reject_tampering() {
    let mut rng = test_rng();
    let (pp, keys) = Second::<E>::setup(128, 2, 4, &mut rng).unwrap();
    let (ct, proof) = Second::<E>::share(Fr::one(), &pp, &mut rng).unwrap();
    let (d, pi) = Second::<E>::pre_recon(&ct, &proof, &keys[0].0, &pp, &mut rng).unwrap();
    let mut epoch = pp.clone();
    epoch.epoch += 1;
    rebind_second(&mut epoch);
    assert!(!Second::<E>::verify(&ct, &proof, &epoch));
    let mut altered = ct.clone();
    altered.sa1[0] += G::generator();
    assert!(!Second::<E>::verify(&altered, &proof, &pp));
    let mut foreign = keys[0].1.clone();
    foreign.bls_pk += G::generator();
    assert!(!Second::<E>::dec_vrf(d, &pi, &foreign, &ct, &pp));
    assert!(!Second::<E>::dec_vrf(
        d + <E as ark_ec::pairing::Pairing>::G2::generator(),
        &pi,
        &keys[0].1,
        &ct,
        &pp
    ));
    let mut dummy = pp.aggregate_key.pk[0].clone();
    dummy.id = 0;
    assert!(!Second::<E>::dec_vrf(ct.gamma_g2, &pi, &dummy, &ct, &pp));
    let mut invalid_proof = proof.clone();
    invalid_proof.response_s += Fr::one();
    assert!(!Second::<E>::verify(&ct, &invalid_proof, &pp));
    let (d, pi) = Second::<E>::pre_recon(&ct, &invalid_proof, &keys[0].0, &pp, &mut rng).unwrap();
    assert!(Second::<E>::dec_vrf(d, &pi, &keys[0].1, &ct, &pp));
}

#[test]
fn second_audit_checks_crs_cached_basis_dummy_and_aggregates() {
    let mut rng = test_rng();
    let (pp, _) = Second::<E>::setup(128, 2, 4, &mut rng).unwrap();
    let mut altered = pp.clone();
    altered.aggregate_key.ask += G::generator();
    rebind_second(&mut altered);
    assert!(!Second::<E>::verify_setup(&altered, &altered.public_keys));
    altered = pp.clone();
    altered.aggregate_key.pk[0].bls_pk += G::generator();
    rebind_second(&mut altered);
    assert!(!Second::<E>::verify_setup(&altered, &altered.public_keys));
    altered = pp.clone();
    altered.lagrange_params.li_g2[1] += <E as ark_ec::pairing::Pairing>::G2::generator();
    rebind_second(&mut altered);
    assert!(!Second::<E>::verify_setup(&altered, &altered.public_keys));
    altered = pp.clone();
    altered.public_keys[0].sk_li_lj_z[2] += G::generator();
    rebind_second(&mut altered);
    assert!(!Second::<E>::verify_setup(&altered, &altered.public_keys));
    altered = pp.clone();
    altered.key_indices[1] = Some(2);
    rebind_second(&mut altered);
    assert!(!Second::<E>::verify_setup(&altered, &altered.public_keys));
    altered = pp.clone();
    altered
        .powers_of_tau
        .powers_of_g
        .push(G::generator().into());
    rebind_second(&mut altered);
    assert!(!Second::<E>::verify_setup(&altered, &altered.public_keys));
    altered = pp.clone();
    altered.ceremony_record.contributions[0].proof.response += Fr::one();
    rebind_second(&mut altered);
    assert!(!Second::<E>::verify_setup(&altered, &altered.public_keys));
    let high_degree = DensePolynomial::from_coefficients_vec(vec![Fr::one(); 5]);
    assert!(KZG10::<E, DensePolynomial<Fr>>::commit_g1(&pp.powers_of_tau, &high_degree).is_err());
}

#[test]
fn public_only_crs_key_generation_and_multiple_contributions() {
    let mut rng = test_rng();
    let initial = ceremony::initial::<E>(4);
    let one = ceremony::contribute(&initial, Fr::from(2u64), &mut rng).unwrap();
    let two = ceremony::contribute(&one.crs, Fr::from(3u64), &mut rng).unwrap();
    let crs = two.crs.clone();
    let record = ceremony::CeremonyRecord {
        initial,
        contributions: vec![one, two],
    };
    assert!(ceremony::verify_record(&crs, &record));
    let (pp, keys) = Second::<E>::setup_from_crs(128, 2, crs, record, 3, &mut rng).unwrap();
    assert!(Second::<E>::verify_setup(&pp, &pp.public_keys));
    let (ct, proof) = Second::<E>::share(Fr::from(7u64), &pp, &mut rng).unwrap();
    let shares: Vec<_> = keys
        .iter()
        .take(2)
        .map(|(sk, pk)| {
            let (d, pi) = Second::<E>::pre_recon(&ct, &proof, sk, &pp, &mut rng).unwrap();
            assert!(Second::<E>::dec_vrf(d, &pi, pk, &ct, &pp));
            (sk.id, d)
        })
        .collect();
    assert_eq!(
        Second::<E>::reconstruct(&ct, &shares, &pp, &mut rng).unwrap(),
        pp.generator_t1 * Fr::from(7u64)
    );
}

#[test]
fn threshold_one_and_exact_domain_boundaries() {
    let mut rng = test_rng();
    let (points, coefficients) = precompute_lagrange_coefficients::<Fr>(1);
    let (pp, keys) = First::<G>::setup(128, 1, 1, points, coefficients, &mut rng).unwrap();
    assert!(First::<G>::verify_setup(&pp, &pp.public_keys));
    let (ct, proof) = First::<G>::share(Fr::zero(), &pp, &mut rng).unwrap();
    let (d, _) = First::<G>::pre_recon(&ct, &proof, &keys[0].0, &pp, &mut rng).unwrap();
    assert_eq!(
        First::<G>::reconstruct(&ct, &[(0, d)], &pp, &mut rng).unwrap(),
        G::zero()
    );
    assert!(Second::<E>::setup(128, 1, 3, &mut rng).is_err()); // no implicit rounding
    assert!(Second::<E>::setup(128, 4, 4, &mut rng).is_err()); // dummy cannot be a shareholder
    let (pp, keys) = Second::<E>::setup(128, 1, 2, &mut rng).unwrap();
    assert!(Second::<E>::verify_setup(&pp, &pp.public_keys));
    let (ct, proof) = Second::<E>::share(Fr::one(), &pp, &mut rng).unwrap();
    assert!(Second::<E>::verify(&ct, &proof, &pp));
    let (d, pi) = Second::<E>::pre_recon(&ct, &proof, &keys[0].0, &pp, &mut rng).unwrap();
    assert!(Second::<E>::dec_vrf(d, &pi, &keys[0].1, &ct, &pp));
    assert_eq!(
        Second::<E>::reconstruct(&ct, &[(1, d)], &pp, &mut rng).unwrap(),
        pp.generator_t1
    );
}

#[test]
fn adaptive_appendix_variant_preserves_split_key_interfaces() {
    let mut rng = test_rng();
    let (pp, keys) = Adaptive::<G>::setup(128, 3, 5, &mut rng).unwrap();
    assert!(Adaptive::<G>::verify_setup(&pp, &pp.public_keys));
    let secret = Fr::from(9u64);
    let (ct, proof) = Adaptive::<G>::share(secret, &pp, &mut rng).unwrap();
    assert!(Adaptive::<G>::verify(&ct, &proof, &pp));
    let mut shares = vec![];
    for id in [4, 0, 2] {
        let (d, pi) = Adaptive::<G>::pre_recon(&ct, &proof, &keys[id].0, &pp, &mut rng).unwrap();
        assert!(Adaptive::<G>::dec_vrf(d, &pi, &keys[id].1, &ct, &pp));
        assert!(!Adaptive::<G>::dec_vrf(
            d + G::generator(),
            &pi,
            &keys[id].1,
            &ct,
            &pp
        ));
        shares.push((id, d));
    }
    assert_eq!(
        Adaptive::<G>::reconstruct(&ct, &shares, &pp, &mut rng).unwrap(),
        pp.g * secret
    );
    assert!(Adaptive::<G>::reconstruct(&ct, &[shares[0]; 3], &pp, &mut rng).is_err());
    let mut epoch = pp.clone();
    epoch.epoch += 1;
    assert!(!Adaptive::<G>::verify(&ct, &proof, &epoch));
    let mut malformed = proof.clone();
    malformed.commitments.clear();
    assert!(!Adaptive::<G>::verify(&ct, &malformed, &pp));
    let mut inconsistent = ct.clone();
    inconsistent.c_2 += G::generator();
    assert!(!Adaptive::<G>::verify(&inconsistent, &proof, &pp));
}

#[test]
fn ordinary_te_encrypts_group_messages_without_proofs() {
    let mut rng = test_rng();
    let (points, coefficients) = precompute_lagrange_coefficients::<Fr>(3);
    let (pp, keys) = First::<G>::setup(128, 2, 3, points, coefficients, &mut rng).unwrap();
    let message = G::rand(&mut rng);
    let ct =
        o1pvss::elgamal_te::encryption::encrypt(pp.generator, &pp.master_pk_key, message, &mut rng);
    let shares: Vec<_> = keys
        .iter()
        .take(2)
        .map(|(sk, _)| {
            (
                sk.id,
                o1pvss::elgamal_te::decryption::partial_decrypt(&ct, sk),
            )
        })
        .collect();
    assert_eq!(
        o1pvss::elgamal_te::decryption::decrypt(&ct, &shares, pp.threshold, &pp.lagrange_coeffs)
            .unwrap(),
        message
    );
    assert!(o1pvss::elgamal_te::decryption::decrypt(
        &ct,
        &shares[..1],
        pp.threshold,
        &pp.lagrange_coeffs
    )
    .is_none());
    let (pp, keys) = Second::<E>::setup(128, 2, 4, &mut rng).unwrap();
    let message = ark_ec::pairing::PairingOutput::<E>::rand(&mut rng);
    let ct = o1pvss::silent_setup_te::encryption::encrypt(
        &pp.aggregate_key,
        pp.threshold,
        &pp.powers_of_tau,
        message,
        &mut rng,
    );
    let shares: Vec<_> = keys
        .iter()
        .take(2)
        .map(|(sk, _)| {
            (
                sk.id,
                o1pvss::silent_setup_te::decryption::partial_decrypt(&ct, sk),
            )
        })
        .collect();
    assert_eq!(
        o1pvss::silent_setup_te::decryption::decrypt(
            &ct,
            &shares,
            pp.threshold,
            &pp.aggregate_key,
            &pp.powers_of_tau
        )
        .unwrap(),
        message
    );
}

struct ZeroRandomness;
impl ark_std::rand::RngCore for ZeroRandomness {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[test]
fn zero_encryption_randomness_is_correct_and_not_rejected() {
    let mut setup_rng = test_rng();
    let mut zero = ZeroRandomness;
    let (pp, keys) = Second::<E>::setup(128, 2, 4, &mut setup_rng).unwrap();
    let (ct, proof) = Second::<E>::share(Fr::one(), &pp, &mut zero).unwrap();
    assert!(ct.gamma_g2.is_zero());
    assert!(Second::<E>::verify(&ct, &proof, &pp));
    let shares: Vec<_> = keys
        .iter()
        .take(2)
        .map(|(sk, pk)| {
            let (d, pi) = Second::<E>::pre_recon(&ct, &proof, sk, &pp, &mut zero).unwrap();
            assert!(d.is_zero());
            assert!(Second::<E>::dec_vrf(d, &pi, pk, &ct, &pp));
            (sk.id, d)
        })
        .collect();
    assert_eq!(
        Second::<E>::reconstruct(&ct, &shares, &pp, &mut zero).unwrap(),
        pp.generator_t1
    );
}

#[test]
fn pre_recon_rejects_secret_key_records_from_another_setup() {
    let mut rng = test_rng();
    let (points, coefficients) = precompute_lagrange_coefficients::<Fr>(3);
    let (pp, keys) = First::<G>::setup(128, 2, 3, points, coefficients, &mut rng).unwrap();
    let (ct, proof) = First::<G>::share(Fr::one(), &pp, &mut rng).unwrap();
    let mut sk = keys[0].0.clone();
    sk.setup_digest[0] ^= 1;
    assert!(First::<G>::pre_recon(&ct, &proof, &sk, &pp, &mut rng).is_err());
    let (pp, keys) = Second::<E>::setup(128, 2, 4, &mut rng).unwrap();
    let (ct, proof) = Second::<E>::share(Fr::one(), &pp, &mut rng).unwrap();
    let mut sk = keys[0].0.clone();
    sk.setup_digest[0] ^= 1;
    assert!(Second::<E>::pre_recon(&ct, &proof, &sk, &pp, &mut rng).is_err());
    sk = keys[0].0.clone();
    sk.id = 0;
    assert!(Second::<E>::pre_recon(&ct, &proof, &sk, &pp, &mut rng).is_err());
}

#[test]
fn second_epoch_audit_excludes_invalid_keys_and_retains_full_view() {
    let mut rng = test_rng();
    let (pp, mut keys) = Second::<E>::setup(128, 2, 4, &mut rng).unwrap();
    let mut registry = pp.public_keys.clone();
    registry[0].sk_li += G::generator();
    let next = Second::<E>::reconfigure_epoch(&pp, registry.clone(), 1).unwrap();
    assert_eq!(next.public_keys.len(), 3); // rejected record remains in the public view
    assert_eq!(next.aggregate_key.pk.len(), 3); // two real keys plus dummy
    assert!(next.key_indices[1].is_none());
    assert!(Second::<E>::verify_setup(&next, &registry));
    let secret = Fr::from(11u64);
    let (ct, proof) = Second::<E>::share(secret, &next, &mut rng).unwrap();
    assert!(Second::<E>::verify(&ct, &proof, &next));
    for (sk, _) in &mut keys {
        sk.setup_digest = next.setup_digest;
    }
    assert!(Second::<E>::pre_recon(&ct, &proof, &keys[0].0, &next, &mut rng).is_err());
    let shares: Vec<_> = keys
        .iter()
        .skip(1)
        .map(|(sk, pk)| {
            let (d, pi) = Second::<E>::pre_recon(&ct, &proof, sk, &next, &mut rng).unwrap();
            assert!(Second::<E>::dec_vrf(d, &pi, pk, &ct, &next));
            (sk.id, d)
        })
        .collect();
    assert_eq!(
        Second::<E>::reconstruct(&ct, &shares, &next, &mut rng).unwrap(),
        next.generator_t1 * secret
    );
    registry[1].sk_li += G::generator(); // only one valid real key remains
    assert!(Second::<E>::reconfigure_epoch(&pp, registry, 1).is_err());
    assert!(Second::<E>::reconfigure_epoch(&pp, pp.public_keys.clone(), 0).is_err());
}
