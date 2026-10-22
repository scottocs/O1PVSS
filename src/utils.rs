use ark_ec::PrimeGroup;
use ark_ff::{FftField, PrimeField};
use ark_serialize::*;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use merlin::Transcript;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct DleqProof<G: PrimeGroup> {
    pub c_1: G,
    pub c_2: G,
    pub challenge: G::ScalarField,
    pub response: G::ScalarField,
}

/// DL Proof - Discrete Logarithm Proof
/// Proves knowledge of the discrete logarithm of a group element
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct DlProof<G: PrimeGroup> {
    pub commitment: G,
    pub challenge: G::ScalarField,
    pub response: G::ScalarField,
}

pub fn dleq_prove<G: ark_ec::CurveGroup, R: RngCore>(
    g_1: G,
    g_2: G,
    secret: G::ScalarField,
    powers: (G, G),
    rng: &mut R,
) -> DleqProof<G> {
    dleq_prove_with_context(g_1, g_2, secret, powers, b"", rng)
}

pub fn dleq_prove_with_context<G: ark_ec::CurveGroup, R: RngCore>(
    g_1: G,
    g_2: G,
    secret: G::ScalarField,
    powers: (G, G),
    context: &[u8],
    rng: &mut R,
) -> DleqProof<G> {
    let r = G::ScalarField::rand(rng);

    //commitment
    let c_1 = crate::arithmetic::fixed_base_mul(g_1, r);
    let c_2 = g_2 * r;

    let mut power0_bytes = Vec::new();
    powers.0.serialize_compressed(&mut power0_bytes).unwrap();
    let mut power1_bytes = Vec::new();
    powers.1.serialize_compressed(&mut power1_bytes).unwrap();
    let mut g1_bytes = Vec::new();
    g_1.serialize_compressed(&mut g1_bytes).unwrap();
    let mut g2_bytes = Vec::new();
    g_2.serialize_compressed(&mut g2_bytes).unwrap();

    let mut transcript = Transcript::new(b"dleq_proof");
    if !context.is_empty() {
        transcript.append_message(b"context", context);
    }

    transcript.append_message(b"base_1", &g1_bytes);
    transcript.append_message(b"base_2", &g2_bytes);
    transcript.append_message(b"power_1", &power0_bytes);
    transcript.append_message(b"power_2", &power1_bytes);

    let mut c1_bytes = Vec::new();
    c_1.serialize_compressed(&mut c1_bytes).unwrap();
    let mut c2_bytes = Vec::new();
    c_2.serialize_compressed(&mut c2_bytes).unwrap();

    transcript.append_message(b"commitment_1", &c1_bytes);
    transcript.append_message(b"commitment_2", &c2_bytes);

    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut buf);

    let challenge = G::ScalarField::from_be_bytes_mod_order(&mut buf);

    let response = r + challenge * secret;

    DleqProof {
        c_1,
        c_2,
        challenge,
        response,
    }
}

pub fn dleq_verify<G: ark_ec::CurveGroup>(
    g_1: G,
    g_2: G,
    powers: (G, G),
    proof: &DleqProof<G>,
) -> bool {
    dleq_verify_with_context(g_1, g_2, powers, proof, b"")
}

pub fn dleq_verify_with_context<G: ark_ec::CurveGroup>(
    g_1: G,
    g_2: G,
    powers: (G, G),
    proof: &DleqProof<G>,
    context: &[u8],
) -> bool {
    let c_1 = proof.c_1;
    let c_2 = proof.c_2;
    let challenge = proof.challenge;
    let response = proof.response;

    let mut power0_bytes = Vec::new();
    powers.0.serialize_compressed(&mut power0_bytes).unwrap();
    let mut power1_bytes = Vec::new();
    powers.1.serialize_compressed(&mut power1_bytes).unwrap();
    let mut g1_bytes = Vec::new();
    g_1.serialize_compressed(&mut g1_bytes).unwrap();
    let mut g2_bytes = Vec::new();
    g_2.serialize_compressed(&mut g2_bytes).unwrap();

    let mut transcript = Transcript::new(b"dleq_proof");
    if !context.is_empty() {
        transcript.append_message(b"context", context);
    }

    transcript.append_message(b"base_1", &g1_bytes);
    transcript.append_message(b"base_2", &g2_bytes);
    transcript.append_message(b"power_1", &power0_bytes);
    transcript.append_message(b"power_2", &power1_bytes);

    let mut c1_bytes = Vec::new();
    c_1.serialize_compressed(&mut c1_bytes).unwrap();
    let mut c2_bytes = Vec::new();
    c_2.serialize_compressed(&mut c2_bytes).unwrap();

    transcript.append_message(b"commitment_1", &c1_bytes);
    transcript.append_message(b"commitment_2", &c2_bytes);

    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut buf);

    let verifier_challenge = G::ScalarField::from_be_bytes_mod_order(&mut buf);

    verifier_challenge == challenge
        && crate::arithmetic::fixed_base_mul(g_1, response) == c_1 + powers.0 * challenge
        && g_2 * response == c_2 + powers.1 * challenge
}

/// DL Proof Generation
/// Proves knowledge of the discrete logarithm x such that y = g^x
///
/// # Arguments
/// * `generator` - The generator element g
/// * `public_key` - The public key y = g^x
/// * `secret` - The secret x
/// * `rng` - Random number generator
///
/// # Returns
/// A DL proof proving knowledge of the discrete logarithm
pub fn dl_prove<G: ark_ec::CurveGroup, R: RngCore>(
    generator: G,
    public_key: G,
    secret: G::ScalarField,
    rng: &mut R,
) -> DlProof<G> {
    // Generate random nonce
    let r = G::ScalarField::rand(rng);

    // Compute commitment: C = g^r
    let commitment = crate::arithmetic::fixed_base_mul(generator, r);

    // Create transcript for Fiat-Shamir transformation
    let mut transcript = Transcript::new(b"dl_proof");

    // Add public parameters to transcript
    let mut generator_bytes = Vec::new();
    generator
        .serialize_compressed(&mut generator_bytes)
        .unwrap();
    let mut public_key_bytes = Vec::new();
    public_key
        .serialize_compressed(&mut public_key_bytes)
        .unwrap();
    let mut commitment_bytes = Vec::new();
    commitment
        .serialize_compressed(&mut commitment_bytes)
        .unwrap();

    transcript.append_message(b"generator", &generator_bytes);
    transcript.append_message(b"public_key", &public_key_bytes);
    transcript.append_message(b"commitment", &commitment_bytes);

    // Generate challenge using Fiat-Shamir
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
    let challenge = G::ScalarField::from_be_bytes_mod_order(&challenge_bytes);

    // Compute response: s = r + c * x
    let response = r + challenge * secret;
    DlProof {
        commitment,
        challenge,
        response,
    }
}

/// DL Proof Verification
/// Verifies a DL proof of knowledge of discrete logarithm
///
/// # Arguments
/// * `generator` - The generator element g
/// * `public_key` - The public key y = g^x
/// * `proof` - The DL proof to verify
///
/// # Returns
/// true if the proof is valid, false otherwise
pub fn dl_verify<G: ark_ec::CurveGroup>(generator: G, public_key: G, proof: &DlProof<G>) -> bool {
    let DlProof {
        commitment,
        challenge,
        response,
    } = proof;

    // Recreate transcript for Fiat-Shamir transformation
    let mut transcript = Transcript::new(b"dl_proof");

    // Add public parameters to transcript
    let mut generator_bytes = Vec::new();
    generator
        .serialize_compressed(&mut generator_bytes)
        .unwrap();
    let mut public_key_bytes = Vec::new();
    public_key
        .serialize_compressed(&mut public_key_bytes)
        .unwrap();
    let mut commitment_bytes = Vec::new();
    commitment
        .serialize_compressed(&mut commitment_bytes)
        .unwrap();

    transcript.append_message(b"generator", &generator_bytes);
    transcript.append_message(b"public_key", &public_key_bytes);
    transcript.append_message(b"commitment", &commitment_bytes);

    // Generate challenge using Fiat-Shamir
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
    let verifier_challenge = G::ScalarField::from_be_bytes_mod_order(&challenge_bytes);

    // Verify: g^s = C + y^c
    let left_side = crate::arithmetic::fixed_base_mul(generator, *response);
    let right_side = *commitment + public_key * (*challenge);
    verifier_challenge == *challenge && left_side == right_side
}

/// Precompute Lagrange coefficients for all possible share combinations
/// This function computes the Lagrange coefficients used in secret sharing schemes
/// for efficient secret reconstruction.
///
/// # Arguments
/// * `share_amount` - The number of shares (n)
///
/// # Returns
/// A tuple containing:
/// * `root_powers` - Public evaluation points
/// * `lagrange_coeffs` - Precomputed Lagrange coefficients matrix
pub fn precompute_lagrange_coefficients<F: FftField + PrimeField>(
    share_amount: usize,
) -> (Vec<F>, Vec<Vec<F>>) {
    let cached = crate::cache::get_or_try_insert(
        "interpolation-matrix",
        crate::cache::binding(&(share_amount as u64)),
        || {
            let points = crate::cache::evaluation_points::<F>(share_amount, 1);
            let mut inverses: Vec<F> = points
                .iter()
                .enumerate()
                .flat_map(|(i, x)| {
                    points.iter().enumerate().map(
                        move |(j, y)| {
                            if i == j {
                                F::from(1u64)
                            } else {
                                *x - y
                            }
                        },
                    )
                })
                .collect();
            ark_ff::batch_inversion(&mut inverses);
            let rows = (0..share_amount)
                .map(|i| {
                    (0..share_amount)
                        .map(|j| {
                            if i == j {
                                F::from(1u64)
                            } else {
                                -points[j] * inverses[i * share_amount + j]
                            }
                        })
                        .collect()
                })
                .collect();
            Some((points.as_ref().clone(), rows))
        },
    )
    .unwrap();
    cached.as_ref().clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::pairing::Pairing;
    use ark_ff::{One, Zero};
    type E = ark_bls12_381::Bls12_381;
    type G1 = <E as Pairing>::G1;

    #[test]
    fn test_dleq_prove_verify_ok() {
        let mut rng = ark_std::test_rng();
        let g1 = G1::generator();
        let x = Fr::rand(&mut rng);
        let g2 = g1 + g1;
        let powers = (g1 * x, g2 * x);
        let proof = dleq_prove(g1, g2, x, powers, &mut rng);
        assert!(dleq_verify(g1, g2, powers, &proof));
    }

    #[test]
    fn test_dleq_prove_verify_fail_wrong_statement() {
        let mut rng = ark_std::test_rng();
        let g1 = G1::generator();
        let g2 = g1 + g1;
        let x = Fr::rand(&mut rng);
        let powers = (g1 * x, g2 * x);
        let proof = dleq_prove(g1, g2, x, powers, &mut rng);
        let g2_bad = g1 + g2; //
        assert!(!dleq_verify(g1, g2_bad, powers, &proof));
    }

    #[test]
    fn test_precompute_lagrange_coefficients() {
        let share_amount = 8;
        let (root_powers, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(share_amount);

        // Verify root_powers has correct length
        assert_eq!(root_powers.len(), share_amount);

        // Verify lagrange_coeffs has correct dimensions
        assert_eq!(lagrange_coeffs.len(), share_amount);
        for coeffs_for_i in &lagrange_coeffs {
            assert_eq!(coeffs_for_i.len(), share_amount);
        }

        // Verify diagonal elements are 1
        for i in 0..share_amount {
            assert_eq!(lagrange_coeffs[i][i], Fr::one());
        }

        // Verify some basic properties of Lagrange coefficients
        // For i != j, the coefficient should be non-zeroro
        for i in 0..share_amount {
            for j in 0..share_amount {
                if i != j {
                    assert_ne!(lagrange_coeffs[i][j], Fr::zero());
                }
            }
        }
    }

    #[test]
    fn test_dl_proof_basic() {
        use ark_bls12_381::G1Projective as G;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let generator = G::generator();
        let secret = <G as PrimeGroup>::ScalarField::rand(&mut rng);
        let public_key = generator * secret;

        // Generate DL proof
        let proof = dl_prove(generator, public_key, secret, &mut rng);

        // Verify DL proof
        assert!(dl_verify(generator, public_key, &proof));
    }

    #[test]
    fn test_dl_proof_wrong_secret() {
        use ark_bls12_381::G1Projective as G;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let generator = G::generator();
        let secret = <G as PrimeGroup>::ScalarField::rand(&mut rng);
        let public_key = generator * secret;

        // Generate DL proof with wrong secret
        let wrong_secret = <G as PrimeGroup>::ScalarField::rand(&mut rng);
        let proof = dl_prove(generator, public_key, wrong_secret, &mut rng);

        // Verification should fail because the proof was generated with wrong secret
        // but we're verifying against the correct public_key
        assert!(!dl_verify(generator, public_key, &proof));
    }

    #[test]
    fn test_dl_proof_wrong_public_key() {
        use ark_bls12_381::G1Projective as G;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let generator = G::generator();
        let secret = <G as PrimeGroup>::ScalarField::rand(&mut rng);
        let public_key = generator * secret;

        // Generate DL proof
        let proof = dl_prove(generator, public_key, secret, &mut rng);

        // Verify with wrong public key - this should fail because
        // the proof was generated for a different public key
        let wrong_public_key = generator * <G as PrimeGroup>::ScalarField::rand(&mut rng);
        assert!(!dl_verify(generator, wrong_public_key, &proof));
    }

    #[test]
    fn test_dl_proof_multiple_proofs() {
        use ark_bls12_381::G1Projective as G;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let generator = G::generator();

        // Test multiple DL proofs
        for _ in 0..5 {
            let secret = <G as PrimeGroup>::ScalarField::rand(&mut rng);
            let public_key = generator * secret;

            let proof = dl_prove(generator, public_key, secret, &mut rng);
            assert!(dl_verify(generator, public_key, &proof));
        }
    }
}
