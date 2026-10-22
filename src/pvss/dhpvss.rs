use crate::utils::{dl_prove, dl_verify, dleq_prove, dleq_verify, DlProof, DleqProof};
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::*;
use ark_std::{rand::Rng, UniformRand};
use merlin::Transcript;

/// DHPVSS Public Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct DHPVSSParams<G: PrimeGroup> {
    pub security_param: usize,
    pub threshold: usize,
    pub n: usize,
    pub generator: G,
    pub alpha_0: G::ScalarField,
    pub alpha_values: Vec<G::ScalarField>, // α₁, α₂, ..., αₙ
    pub v_values: Vec<G::ScalarField>,     // v₁, v₂, ..., vₙ
    pub lagrange_coeffs: Vec<Vec<G::ScalarField>>, // Lagrange coefficients for efficient secret recovery
}

impl<G: ark_ec::CurveGroup> DHPVSSParams<G> {
    pub fn new(
        security_param: usize,
        threshold: usize,
        n: usize,
        generator: G,
        alpha_0: G::ScalarField,
        alpha_values: Vec<G::ScalarField>,
        v_values: Vec<G::ScalarField>,
        lagrange_coeffs: Vec<Vec<G::ScalarField>>,
    ) -> Self {
        Self {
            security_param,
            threshold,
            n,
            generator,
            alpha_0,
            alpha_values,
            v_values,
            lagrange_coeffs,
        }
    }
}

/// DHPVSS Distributor Key Pair
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct DistributorKeyPair<G: PrimeGroup> {
    pub pk_d: G,              // pkD = skD · G
    pub sk_d: G::ScalarField, // skD
}

/// DHPVSS Participant Key Pair
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct ParticipantKeyPair<G: PrimeGroup> {
    pub pk: ParticipantPublicKey<G>,
    pub sk: G::ScalarField,
}

/// DHPVSS Participant Public Key
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct ParticipantPublicKey<G: PrimeGroup> {
    pub e: G,              // E = sk · G
    pub omega: DlProof<G>, // Ω = DL(sk; G, E)
}

/// DHPVSS Distribution Result
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct DHPVSSDistribution<G: PrimeGroup> {
    pub ciphertexts: Vec<G>, // {Cᵢ : i ∈ [n]}
    pub proof: DleqProof<G>, // Pfsh = DLEQ(skD; G, pkD, U, V)
}

pub struct VerifiedDistribution<'a, G: ark_ec::CurveGroup> {
    pp: &'a DHPVSSParams<G>,
    pk_d: &'a G,
    public_keys: Vec<ParticipantPublicKey<G>>,
    distribution: &'a DHPVSSDistribution<G>,
}

/// DHPVSS Error Types
#[derive(Debug, Clone)]
pub enum DHPVSSError {
    InvalidParameters,
    InvalidThreshold,
    InvalidParticipantCount,
    InvalidSecret,
    InvalidCiphertext,
    InvalidProof,
    InsufficientShares,
    VerificationFailed,
}

/// DHPVSS Implementation
pub struct DHPVSS<G: PrimeGroup> {
    _phantom: std::marker::PhantomData<G>,
}

impl<G: ark_ec::CurveGroup> DHPVSS<G> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// DHPVSS.Setup(1^λ, t, n)
    /// Generates public parameters for the DHPVSS scheme
    pub fn setup<R: Rng>(
        security_param: usize,
        threshold: usize,
        n: usize,
        lagrange_coeffs: Vec<Vec<G::ScalarField>>,
        _rng: &mut R,
    ) -> Result<DHPVSSParams<G>, DHPVSSError> {
        if threshold > n || threshold == 0 {
            return Err(DHPVSSError::InvalidThreshold);
        }

        let generator = G::generator();

        // Choose pairwise distinct α₀, α₁, ..., αₙ ∈ Zp.
        let mut alpha_values = Vec::with_capacity(n + 1);
        let alpha_0 = G::ScalarField::zero();
        alpha_values.push(alpha_0);
        for i in 0..n {
            alpha_values.push(G::ScalarField::from((i + 1) as u64));
        }

        let v_values = crate::cache::barycentric_weights(&alpha_values[1..])
            .unwrap()
            .as_ref()
            .clone();

        Ok(DHPVSSParams::new(
            security_param,
            threshold,
            n,
            generator,
            alpha_0,
            alpha_values,
            v_values,
            lagrange_coeffs,
        ))
    }

    /// DHPVSS.DKeyGen(pp)
    /// Generates distributor key pair
    pub fn d_key_gen<R: Rng>(pp: &DHPVSSParams<G>, rng: &mut R) -> DistributorKeyPair<G> {
        let sk_d = G::ScalarField::rand(rng);
        let pk_d = pp.generator * sk_d;

        DistributorKeyPair { pk_d, sk_d }
    }

    /// DHPVSS.KeyGen(pp, id)
    /// Generates participant key pair with identity
    pub fn key_gen<R: Rng>(pp: &DHPVSSParams<G>, _id: usize, rng: &mut R) -> ParticipantKeyPair<G> {
        let sk = G::ScalarField::rand(rng);
        let e = pp.generator * sk;

        // Create DL proof Ω = DL(sk; G, E)
        let omega = dl_prove(pp.generator, e, sk, rng);

        ParticipantKeyPair {
            pk: ParticipantPublicKey { e, omega },
            sk,
        }
    }

    /// DHPVSS.VerifyKey(pp, id, pk)
    /// Verifies participant public key
    pub fn verify_key(pp: &DHPVSSParams<G>, _id: usize, pk: &ParticipantPublicKey<G>) -> bool {
        // Verify DL proof Ω = DL(sk; G, E)
        pk.check().is_ok() && dl_verify(pp.generator, pk.e, &pk.omega)
    }

    /// Group Shamir Sharing
    /// Implements GShamir.Share(pp, S) from the paper
    pub fn group_shamir_share<R: Rng>(
        pp: &DHPVSSParams<G>,
        secret: G,
        rng: &mut R,
    ) -> Vec<(usize, G)>
    where
        G: ark_ec::scalar_mul::ScalarMul,
    {
        // Generate random polynomial m(X) ∈ Z_p[X]_<t such that m(α₀) = 0
        // This means m(X) has degree < t and evaluates to 0 at α₀ = 0
        let mut coeffs = vec![G::ScalarField::zero()];

        // Generate random coefficients for degree 0 to t-1
        for _ in 0..pp.threshold {
            coeffs.push(G::ScalarField::rand(rng));
        }

        let powers = crate::cache::evaluation_powers(&pp.alpha_values[1..], coeffs.len());
        let mut shares = Vec::with_capacity(pp.n);
        for (i, row) in powers.iter().enumerate() {
            let eval_i = coeffs
                .iter()
                .zip(row)
                .fold(G::ScalarField::zero(), |sum, (c, p)| sum + *c * p);
            shares.push((
                i,
                secret + crate::arithmetic::fixed_base_mul(pp.generator, eval_i),
            ));
        }

        shares
    }

    pub fn group_shamir_recon(pp: &DHPVSSParams<G>, shares: &[(usize, G)]) -> G
    where
        G: ark_ec::CurveGroup,
    {
        if shares.len() <= pp.threshold
            || shares
                .iter()
                .any(|(id, s)| *id >= pp.n || s.check().is_err())
        {
            return G::zero();
        }
        let points: Vec<_> = shares
            .iter()
            .map(|(id, _)| pp.alpha_values[*id + 1])
            .collect();
        let Some(weights) = crate::cache::interpolation_weights(&points, &[pp.alpha_0]) else {
            return G::zero();
        };
        let bases: Vec<_> = shares.iter().map(|(_, value)| *value).collect();
        crate::arithmetic::public_msm(&bases, &weights[0])
    }

    /// Random Oracle H mapping {0,1}* to Zp[X]≤n-t-2
    fn random_oracle_h(
        pp: &DHPVSSParams<G>,
        pk_d: &G,
        participant_data: &[(G, G)],
    ) -> DensePolynomial<G::ScalarField> {
        // Simple hash-based random oracle implementation
        let mut input = Vec::new();

        // Serialize pk_d
        let mut pk_d_bytes = Vec::new();
        pk_d.serialize_compressed(&mut pk_d_bytes).unwrap();
        input.extend_from_slice(&pk_d_bytes);

        // Serialize participant data
        for (pk, c) in participant_data {
            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes).unwrap();
            input.extend_from_slice(&pk_bytes);

            let mut c_bytes = Vec::new();
            c.serialize_compressed(&mut c_bytes).unwrap();
            input.extend_from_slice(&c_bytes);
        }

        let mut transcript = Transcript::new(b"dhpvss_random_oracle_h");

        transcript.append_message(b"input", &input);

        let mut coeffs = Vec::new();

        for _ in 0..(participant_data.len() - pp.threshold - 1) {
            let mut buf = [0u8; 64];
            transcript.challenge_bytes(b"challenge", &mut buf);
            let challenge = G::ScalarField::from_be_bytes_mod_order(&mut buf);
            coeffs.push(challenge);
        }
        DensePolynomial::from_coefficients_vec(coeffs)
    }

    /// DHPVSS.Dist(pp, pkD, skD, {pkᵢ : i ∈ [n]}, S)
    /// Distributes secret S among participants
    pub fn dist<R: Rng>(
        pp: &DHPVSSParams<G>,
        pk_d: &G,
        sk_d: &G::ScalarField,
        participant_keys: &[ParticipantKeyPair<G>],
        secret: G,
        rng: &mut R,
    ) -> Result<DHPVSSDistribution<G>, DHPVSSError>
    where
        G: ark_ec::CurveGroup,
    {
        if participant_keys.len() != pp.n {
            return Err(DHPVSSError::InvalidParticipantCount);
        }

        // Perform generalized Shamir sharing
        let shares = Self::group_shamir_share(pp, secret, rng);
        let mut bases = vec![pp.generator, *pk_d];
        bases.extend(participant_keys.iter().map(|key| key.pk.e));
        let fixed = crate::arithmetic::fixed_bases(&bases);

        // Calculate Cᵢ ← skD · Eᵢ + Aᵢ for each i ∈ [n]
        let mut ciphertexts = Vec::new();
        let mut participant_data = Vec::new();

        for (i, share) in shares.iter() {
            let c_i = fixed.mul(participant_keys[*i].pk.e, *sk_d) + *share;
            ciphertexts.push(c_i);
            participant_data.push((participant_keys[*i].pk.e.clone(), c_i));
        }
        assert_eq!(ciphertexts.len(), pp.n);
        // Calculate m* ← H(pkD, {(pkᵢ, Cᵢ) : i ∈ [n]})
        let m_star = Self::random_oracle_h(pp, pk_d, &participant_data);

        // Calculate V ← Σ_{i=1}^n vᵢ · m*(αᵢ) · Cᵢ
        let coefficients: Vec<_> = (0..pp.n)
            .map(|i| pp.v_values[i] * m_star.evaluate(&pp.alpha_values[i + 1]))
            .collect();
        let v = crate::arithmetic::public_msm(&ciphertexts, &coefficients);

        // Calculate U ← Σ_{i=1}^n vᵢ · m*(αᵢ) · Eᵢ
        let bases: Vec<_> = participant_keys.iter().map(|key| key.pk.e).collect();
        let u = crate::arithmetic::public_msm(&bases, &coefficients);

        // Calculate DLEQ proof Pfsh ← DLEQ(skD; G, pkD, U, V)
        let proof = dleq_prove(pp.generator, u, *sk_d, (*pk_d, v), rng);

        Ok(DHPVSSDistribution { ciphertexts, proof })
    }

    /// Verify distribution (wrapper for the verify method)
    pub fn verify_distribution(
        pp: &DHPVSSParams<G>,
        pk_d: &G,
        participant_keys: &[ParticipantKeyPair<G>],
        distribution: &DHPVSSDistribution<G>,
    ) -> bool
    where
        G: ark_ec::CurveGroup,
    {
        if participant_keys.len() != pp.n
            || distribution.ciphertexts.len() != pp.n
            || distribution.check().is_err()
        {
            return false;
        }
        // Reconstruct participant data
        let mut participant_data = Vec::new();
        for i in 0..pp.n {
            participant_data.push((
                participant_keys[i].pk.e.clone(),
                distribution.ciphertexts[i],
            ));
        }
        if participant_data.len() != pp.n {
            return false;
        }

        // Calculate m* ← H(pkD, {(pkᵢ, Cᵢ) : i ∈ [n]})
        let m_star = Self::random_oracle_h(pp, pk_d, &participant_data);
        // Calculate V ← Σ_{i=1}^n vᵢ · m*(αᵢ) · Cᵢ
        let coefficients: Vec<_> = (0..pp.n)
            .map(|i| pp.v_values[i] * m_star.evaluate(&pp.alpha_values[i + 1]))
            .collect();
        let v = crate::arithmetic::public_msm(&distribution.ciphertexts, &coefficients);

        // Calculate U ← Σ_{i=1}^n vᵢ · m*(αᵢ) · Eᵢ
        let bases: Vec<_> = participant_keys.iter().map(|key| key.pk.e).collect();
        let u = crate::arithmetic::public_msm(&bases, &coefficients);

        // Verify DLEQ proof Pfsh ← DLEQ(skD; G, pkD, U, V)
        dleq_verify(pp.generator, u, (*pk_d, v), &distribution.proof)
    }

    pub fn verify_sharing<'a>(
        pp: &'a DHPVSSParams<G>,
        pk_d: &'a G,
        keys: &'a [ParticipantKeyPair<G>],
        distribution: &'a DHPVSSDistribution<G>,
    ) -> Result<VerifiedDistribution<'a, G>, DHPVSSError> {
        if !Self::verify_distribution(pp, pk_d, keys, distribution) {
            return Err(DHPVSSError::InvalidProof);
        }
        Ok(VerifiedDistribution {
            pp,
            pk_d,
            public_keys: keys.iter().map(|key| key.pk.clone()).collect(),
            distribution,
        })
    }

    /// Reconstruct secret from shares
    /// Implements GShamir.Rec(pp, I, (A_i)_i∈I) from the paper
    pub fn reconstruct(pp: &DHPVSSParams<G>, shares: &[(usize, G)]) -> G
    where
        G: ark_ec::CurveGroup,
    {
        // Use Lagrange interpolation to reconstruct the secret
        // S' ← Σ_{i∈I} λ_{i,I} A_i
        Self::group_shamir_recon(pp, shares)
    }

    /// DHPVSS.DecShare(pp, pkD, pk, sk, C)
    /// Allows a participant to partially decrypt their share
    pub fn dec_share(
        pp: &DHPVSSParams<G>,
        pk_d: &G,
        pk: &ParticipantPublicKey<G>,
        sk: &G::ScalarField,
        c: &G,
        rng: &mut impl Rng,
    ) -> (G, DleqProof<G>) {
        // Compute A' ← C - sk · pkD

        let a_prime = *c - crate::arithmetic::fixed_base_mul(*pk_d, *sk);

        // Generate DLEQ proof PfDec ← DLEQ(sk; G, E, pkD, C - A')
        let proof = dleq_prove(pp.generator, *pk_d, *sk, (pk.e, *c - a_prime), rng);

        (a_prime, proof)
    }

    /// DHPVSS.VerifyDec(pp, pkD, pkᵢ, Cᵢ, Aᵢ, PfDecᵢ)
    /// Verifies the validity of a participant's partial decryption
    pub fn verify_dec(
        pp: &DHPVSSParams<G>,
        pk_d: &G,
        pk_i: &ParticipantPublicKey<G>,
        c_i: &G,
        a_i: &G,
        proof_dec_i: &DleqProof<G>,
    ) -> bool {
        c_i.check().is_ok() && Self::verify_dec_validated(pp, pk_d, pk_i, c_i, a_i, proof_dec_i)
    }

    fn verify_dec_validated(
        pp: &DHPVSSParams<G>,
        pk_d: &G,
        pk_i: &ParticipantPublicKey<G>,
        c_i: &G,
        a_i: &G,
        proof_dec_i: &DleqProof<G>,
    ) -> bool {
        // Verify DLEQ proof PfDecᵢ ← DLEQ(skᵢ; G, Eᵢ, pkD, Cᵢ - Aᵢ)
        a_i.check().is_ok()
            && pk_i.e.check().is_ok()
            && proof_dec_i.check().is_ok()
            && dleq_verify(pp.generator, *pk_d, (pk_i.e, *c_i - (*a_i)), proof_dec_i)
    }
}

impl<G: ark_ec::CurveGroup> VerifiedDistribution<'_, G> {
    pub fn pre_recon(
        &self,
        id: usize,
        key: &ParticipantKeyPair<G>,
        rng: &mut impl Rng,
    ) -> Result<(G, DleqProof<G>), DHPVSSError> {
        let expected = self
            .public_keys
            .get(id)
            .ok_or(DHPVSSError::InvalidParticipantCount)?;
        if expected.e != key.pk.e {
            return Err(DHPVSSError::InvalidParameters);
        }
        let ct = self
            .distribution
            .ciphertexts
            .get(id)
            .ok_or(DHPVSSError::InvalidCiphertext)?;
        Ok(DHPVSS::<G>::dec_share(
            self.pp, self.pk_d, &key.pk, &key.sk, ct, rng,
        ))
    }
    pub fn dec_vrf(&self, id: usize, d: &G, proof: &DleqProof<G>) -> bool {
        let Some(key) = self.public_keys.get(id) else {
            return false;
        };
        let Some(ct) = self.distribution.ciphertexts.get(id) else {
            return false;
        };
        DHPVSS::<G>::verify_dec_validated(self.pp, self.pk_d, key, ct, d, proof)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::precompute_lagrange_coefficients;

    use super::*;
    use ark_bls12_381::Fr;
    use ark_bls12_381::G1Projective as G1;
    use ark_std::test_rng;

    type G = G1;

    #[test]
    fn test_dhpvss_setup() {
        let mut rng = test_rng();
        let security_param = 128;
        let threshold = 3;
        let n = 8;

        let (_, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(n);

        let pp =
            DHPVSS::<G>::setup(security_param, threshold, n, lagrange_coeffs, &mut rng).unwrap();

        assert_eq!(pp.security_param, security_param);
        assert_eq!(pp.threshold, threshold);
        assert_eq!(pp.n, n);
        assert_eq!(pp.alpha_values.len(), n + 1);
        assert_eq!(pp.v_values.len(), n);
    }

    #[test]
    fn test_group_shamir_share_and_recon() {
        let mut rng = test_rng();
        let n = 4;
        let (_, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(n);
        let pp = DHPVSS::<G>::setup(128, 3, n, lagrange_coeffs, &mut rng).unwrap(); // n=4 (2^2)
        let secret = pp.generator * <G as PrimeGroup>::ScalarField::rand(&mut rng);

        // Test group Shamir sharing
        let shares = DHPVSS::<G>::group_shamir_share(&pp, secret, &mut rng);

        // Verify that we have the correct number of shares
        assert_eq!(shares.len(), pp.n);

        // Test reconstruction with threshold shares
        let threshold_shares: Vec<(usize, G)> =
            shares.iter().take(pp.threshold + 1).cloned().collect();
        let reconstructed = DHPVSS::<G>::group_shamir_recon(&pp, &threshold_shares);

        // Verify that reconstruction works
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_dhpvss_key_generation() {
        let mut rng = test_rng();
        let n = 8;
        let (_, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(n);
        let pp = DHPVSS::<G>::setup(128, 3, n, lagrange_coeffs, &mut rng).unwrap();

        // Test distributor key generation
        let distributor_keys = DHPVSS::<G>::d_key_gen(&pp, &mut rng);
        assert_eq!(distributor_keys.pk_d, pp.generator * distributor_keys.sk_d);

        // Test participant key generation
        let participant_keys = DHPVSS::<G>::key_gen(&pp, 0, &mut rng);
        assert_eq!(participant_keys.pk.e, pp.generator * participant_keys.sk);

        // Test key verification
        assert!(DHPVSS::<G>::verify_key(&pp, 0, &participant_keys.pk));
    }

    #[test]
    fn test_dhpvss_distribution() {
        let mut rng = test_rng();
        let n = 8;
        let (_, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(n);
        let pp = DHPVSS::<G>::setup(128, 3, n, lagrange_coeffs, &mut rng).unwrap();

        // Generate distributor and participant keys
        let distributor_keys = DHPVSS::<G>::d_key_gen(&pp, &mut rng);
        let mut participant_keys = Vec::new();
        for i in 0..pp.n {
            participant_keys.push(DHPVSS::<G>::key_gen(&pp, i, &mut rng));
        }

        // Test distribution
        let secret = pp.generator * <G as PrimeGroup>::ScalarField::rand(&mut rng);
        let distribution = DHPVSS::<G>::dist(
            &pp,
            &distributor_keys.pk_d,
            &distributor_keys.sk_d,
            &participant_keys,
            secret,
            &mut rng,
        )
        .unwrap();

        assert_eq!(distribution.ciphertexts.len(), pp.n);

        // Test verification
        assert!(DHPVSS::<G>::verify_distribution(
            &pp,
            &distributor_keys.pk_d,
            &participant_keys,
            &distribution,
        ));
    }

    #[test]
    fn test_dhpvss_verify() {
        let mut rng = test_rng();
        let n = 8;
        let (_, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(n);
        let pp = DHPVSS::<G>::setup(128, 3, n, lagrange_coeffs, &mut rng).unwrap();

        // Generate distributor and participant keys
        let distributor_keys = DHPVSS::<G>::d_key_gen(&pp, &mut rng);
        let mut participant_keys = Vec::new();
        for i in 0..pp.n {
            participant_keys.push(DHPVSS::<G>::key_gen(&pp, i, &mut rng));
        }

        // Distribute secret
        let secret = pp.generator * <G as PrimeGroup>::ScalarField::rand(&mut rng);
        let distribution = DHPVSS::<G>::dist(
            &pp,
            &distributor_keys.pk_d,
            &distributor_keys.sk_d,
            &participant_keys,
            secret,
            &mut rng,
        )
        .unwrap();

        // Test verify method
        let mut participant_data = Vec::new();
        for i in 0..pp.n {
            participant_data.push((
                participant_keys[i].pk.e.clone(),
                distribution.ciphertexts[i],
            ));
        }

        assert!(DHPVSS::<G>::verify_distribution(
            &pp,
            &distributor_keys.pk_d,
            &participant_keys,
            &distribution,
        ));
    }

    #[test]
    fn test_dhpvss_dec_share() {
        let mut rng = test_rng();
        let n = 8;
        let (_, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(n);
        let pp = DHPVSS::<G>::setup(128, 3, n, lagrange_coeffs, &mut rng).unwrap();

        // Generate distributor and participant keys
        let distributor_keys = DHPVSS::<G>::d_key_gen(&pp, &mut rng);
        let participant_keys = DHPVSS::<G>::key_gen(&pp, 0, &mut rng);

        // Distribute secret
        let secret = pp.generator * <G as PrimeGroup>::ScalarField::rand(&mut rng);
        let mut participant_keys_vec = vec![participant_keys.clone()];
        for i in 1..pp.n {
            participant_keys_vec.push(DHPVSS::<G>::key_gen(&pp, i, &mut rng));
        }

        let distribution = DHPVSS::<G>::dist(
            &pp,
            &distributor_keys.pk_d,
            &distributor_keys.sk_d,
            &participant_keys_vec,
            secret,
            &mut rng,
        )
        .unwrap();

        assert!(DHPVSS::<G>::verify_distribution(
            &pp,
            &distributor_keys.pk_d,
            &participant_keys_vec,
            &distribution,
        ));
        // Test dec_share
        let (a_prime, proof_dec) = DHPVSS::<G>::dec_share(
            &pp,
            &distributor_keys.pk_d,
            &participant_keys.pk,
            &participant_keys.sk,
            &distribution.ciphertexts[0],
            &mut rng,
        );

        // Test verify_dec
        assert!(DHPVSS::<G>::verify_dec(
            &pp,
            &distributor_keys.pk_d,
            &participant_keys.pk,
            &distribution.ciphertexts[0],
            &a_prime,
            &proof_dec,
        ));
    }

    #[test]
    fn test_dhpvss_complete_workflow() {
        let mut rng = test_rng();
        let n = 16;
        let (_, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(n);
        let pp = DHPVSS::<G>::setup(128, 4, n, lagrange_coeffs, &mut rng).unwrap();

        // Generate distributor and participant keys
        let distributor_keys = DHPVSS::<G>::d_key_gen(&pp, &mut rng);
        let mut participant_keys = Vec::new();
        for i in 0..pp.n {
            participant_keys.push(DHPVSS::<G>::key_gen(&pp, i, &mut rng));
        }

        // Distribute secret
        let secret = pp.generator * <G as PrimeGroup>::ScalarField::rand(&mut rng);
        let distribution = DHPVSS::<G>::dist(
            &pp,
            &distributor_keys.pk_d,
            &distributor_keys.sk_d,
            &participant_keys,
            secret,
            &mut rng,
        )
        .unwrap();

        // Verify distribution
        assert!(DHPVSS::<G>::verify_distribution(
            &pp,
            &distributor_keys.pk_d,
            &participant_keys,
            &distribution,
        ));

        // Participants decrypt their shares
        let mut partial_decryptions = Vec::new();
        for i in 0..(pp.threshold + 1) {
            let (a_prime, proof_dec) = DHPVSS::<G>::dec_share(
                &pp,
                &distributor_keys.pk_d,
                &participant_keys[i].pk,
                &participant_keys[i].sk,
                &distribution.ciphertexts[i],
                &mut rng,
            );

            // Verify partial decryption
            assert!(DHPVSS::<G>::verify_dec(
                &pp,
                &distributor_keys.pk_d,
                &participant_keys[i].pk,
                &distribution.ciphertexts[i],
                &a_prime,
                &proof_dec,
            ));

            partial_decryptions.push((i, a_prime));
        }

        // Reconstruct secret
        let reconstructed = DHPVSS::<G>::reconstruct(&pp, &partial_decryptions);
        assert_eq!(reconstructed, secret);
    }
}
