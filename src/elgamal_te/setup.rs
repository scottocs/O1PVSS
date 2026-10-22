//DKG setup using Feldman VSS
use ark_ec::PrimeGroup;
use ark_ff::Field;
use ark_serialize::*;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use ark_std::{One, Zero};

#[cfg(test)]
use crate::utils::precompute_lagrange_coefficients;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct SecretKey<G: PrimeGroup> {
    pub id: usize,
    pub setup_digest: [u8; 32],
    pub sk_i: G::ScalarField,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct PublicKey<G: PrimeGroup> {
    pub id: usize,
    pub pk_i: G,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MasterSecretKey<G: PrimeGroup> {
    pub sk: G::ScalarField,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Default, Debug)]
pub struct MasterPublicKey<G: PrimeGroup> {
    pub pk: G,
}

//Feldman VSS
#[derive(Clone, Debug)]
pub struct VerifiableSecretSharing<G: PrimeGroup> {
    /// the threshold of shares to recover the secret.
    pub threshold: usize,
    /// the total number of shares to generate from the secret.
    pub share_amount: usize,
    /// Precomputed Lagrange coefficients for efficient secret recovery
    pub lagrange_coeffs: Vec<Vec<G::ScalarField>>,
    /// Public evaluation points.
    pub root_powers: Vec<G::ScalarField>,
}

impl<G: PrimeGroup> VerifiableSecretSharing<G> {
    pub fn new(
        threshold: usize,
        share_amount: usize,
        root_powers: Vec<G::ScalarField>,
        lagrange_coeffs: Vec<Vec<G::ScalarField>>,
    ) -> Self {
        Self {
            threshold,
            share_amount,
            lagrange_coeffs,
            root_powers,
        }
    }

    pub fn share_secret<R: Rng>(
        &self,
        secret: G::ScalarField,
        rng: &mut R,
    ) -> (Vec<G::ScalarField>, Vec<G>) {
        let mut coeffs = vec![secret];
        for _ in 1..self.threshold {
            coeffs.push(G::ScalarField::rand(rng));
        }
        let shares = self
            .root_powers
            .iter()
            .take(self.share_amount)
            .map(|point| {
                let mut power = G::ScalarField::one();
                let mut share = G::ScalarField::zero();
                for coeff in &coeffs {
                    share += *coeff * power;
                    power *= point;
                }
                share
            })
            .collect();
        let mut commitments = Vec::new();
        for i in 0..self.threshold {
            let commitment = G::generator() * coeffs[i];
            commitments.push(commitment);
        }
        (shares, commitments)
    }

    pub fn recover_secret(&self, shares: Vec<(u64, G::ScalarField)>) -> G::ScalarField {
        assert!(
            shares.len() >= self.threshold,
            "Not enough shares to recover the secret"
        );

        let mut secret = G::ScalarField::zero();

        // Use precomputed Lagrange coefficients for efficient recovery
        for (i, (idx_i, share_i)) in shares.iter().enumerate() {
            let mut lagrange_coeff = G::ScalarField::one();

            for (j, (idx_j, _)) in shares.iter().enumerate() {
                if i != j {
                    // Use precomputed coefficient
                    lagrange_coeff *= self.lagrange_coeffs[*idx_i as usize][*idx_j as usize];
                }
            }

            secret += *share_i * lagrange_coeff;
        }

        secret
    }

    pub fn verify_share(&self, i: usize, share: G::ScalarField, commitments: Vec<G>) -> bool {
        // Use precomputed root power
        let point = self.root_powers[i];
        let mut commitment_sum = G::zero();
        for j in 0..self.threshold {
            commitment_sum += commitments[j] * point.pow(&[j as u64]);
        }
        commitment_sum == G::generator() * share
    }
}

// ============================================================================
// Distributed Key Generation (DKG) Protocol
// ============================================================================

/// DKG participant with their secret and public information
#[derive(Clone, Debug)]
pub struct DKGParticipant<G: PrimeGroup> {
    /// Participant ID
    pub id: usize,
    /// Participant's secret key
    pub secret_key: SecretKey<G>,
    /// Participant's public key
    pub public_key: PublicKey<G>,
    /// Participant's Feldman VSS instance
    pub vss: VerifiableSecretSharing<G>,
}

/// DKG sharing message sent by each participant
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct DKGShareMessage<G: PrimeGroup> {
    /// Sender's participant ID
    pub sender_id: usize,
    /// Shares sent to other participants
    pub shares: Vec<G::ScalarField>,
    /// Commitments for verification
    pub commitments: Vec<G>,
}

/// DKG verification result
#[derive(Clone, Debug)]
pub struct DKGVerificationResult {
    /// Participant ID
    pub participant_id: usize,
    /// Whether verification passed
    pub is_valid: bool,
    /// Error message if verification failed
    pub error_msg: Option<String>,
}

/// DKG protocol result
#[derive(Clone, Debug)]
pub struct DKGResult<G: PrimeGroup> {
    /// Master secret key (sum of all participant secrets)
    pub master_sk: MasterSecretKey<G>,
    /// Master public key (sum of all participant public keys)
    pub master_pk: MasterPublicKey<G>,
    /// Individual participant information
    pub participants: Vec<DKGParticipant<G>>,
    /// Successful participants
    pub successful_participants: Vec<usize>,
}

/// Distributed Key Generation protocol implementation
pub struct DistributedKeyGeneration<G: PrimeGroup> {
    /// Number of participants
    pub n: usize,
    /// Threshold for secret recovery
    pub threshold: usize,
    /// Feldman VSS instance
    pub vss: VerifiableSecretSharing<G>,
}

impl<G: PrimeGroup> DistributedKeyGeneration<G> {
    /// Create a new DKG instance
    pub fn new(
        n: usize,
        threshold: usize,
        root_powers: Vec<G::ScalarField>,
        lagrange_coeffs: Vec<Vec<G::ScalarField>>,
    ) -> Self {
        let vss = VerifiableSecretSharing::new(threshold, n, root_powers, lagrange_coeffs);

        Self { n, threshold, vss }
    }

    /// Initialize a participant for DKG
    pub fn initialize_participant<R: Rng>(&self, id: usize, rng: &mut R) -> DKGParticipant<G> {
        let secret_key = SecretKey {
            id,
            setup_digest: [0; 32],
            sk_i: G::ScalarField::rand(rng),
        };

        let public_key = PublicKey {
            id,
            pk_i: G::generator() * secret_key.sk_i,
        };

        DKGParticipant {
            id,
            secret_key,
            public_key,
            vss: self.vss.clone(),
        }
    }

    /// Generate sharing message for a participant
    pub fn generate_sharing_message<R: Rng>(
        &self,
        participant: &DKGParticipant<G>,
        rng: &mut R,
    ) -> DKGShareMessage<G> {
        let (shares, commitments) = self.vss.share_secret(participant.secret_key.sk_i, rng);

        DKGShareMessage {
            sender_id: participant.id,
            shares,
            commitments,
        }
    }

    /// Verify a sharing message from another participant
    pub fn verify_sharing_message(
        &self,
        share_msg: &DKGShareMessage<G>,
        participant_id: usize,
    ) -> DKGVerificationResult {
        // Verify the share assigned to this participant
        let share = share_msg.shares[participant_id];
        let is_valid = self
            .vss
            .verify_share(participant_id, share, share_msg.commitments.clone());

        DKGVerificationResult {
            participant_id,
            is_valid,
            error_msg: if is_valid {
                None
            } else {
                Some(format!(
                    "Invalid share from participant {}",
                    share_msg.sender_id
                ))
            },
        }
    }

    /// Aggregate shares from successful participants to recover master secret
    pub fn aggregate_shares(
        &self,
        share_messages: &[DKGShareMessage<G>],
        successful_participants: &[usize],
        participant_id: usize,
    ) -> G::ScalarField {
        // Collect shares from successful participants
        let mut shares = Vec::new();
        for &pid in successful_participants {
            if let Some(share_msg) = share_messages.iter().find(|msg| msg.sender_id == pid) {
                shares.push((pid as u64, share_msg.shares[participant_id]));
            }
        }

        // Recover the master secret using Lagrange interpolation
        self.vss.recover_secret(shares)
    }

    /// Complete the DKG protocol
    pub fn complete_dkg(
        &self,
        participants: Vec<DKGParticipant<G>>,
        share_messages: Vec<DKGShareMessage<G>>,
    ) -> DKGResult<G> {
        let mut successful_participants = Vec::new();
        let mut verification_results = Vec::new();

        // Verify all sharing messages
        let mut participant_verification_results = std::collections::HashMap::new();

        for participant in &participants {
            for share_msg in &share_messages {
                if share_msg.sender_id != participant.id {
                    let result = self.verify_sharing_message(share_msg, participant.id);
                    verification_results.push(result.clone());

                    // Track verification results for each sender
                    participant_verification_results
                        .entry(share_msg.sender_id)
                        .or_insert_with(Vec::new)
                        .push(result.is_valid);
                }
            }
        }

        // Only add participants to successful list if ALL their verifications passed
        for (sender_id, verification_results_for_sender) in participant_verification_results {
            if verification_results_for_sender
                .iter()
                .all(|&is_valid| is_valid)
            {
                successful_participants.push(sender_id);
            }
        }

        // Ensure we have at least threshold successful participants
        if successful_participants.len() < self.threshold {
            panic!("Not enough successful participants for DKG completion");
        }

        // Calculate each participant's private key share: sk_j = sum of shares received from others
        let mut updated_participants = Vec::new();
        for participant in &participants {
            if successful_participants.contains(&participant.id) {
                // Calculate sk_j = sum of shares received from successful participants
                let mut private_key_share = G::ScalarField::zero();
                for share_msg in &share_messages {
                    if successful_participants.contains(&share_msg.sender_id) {
                        private_key_share += share_msg.shares[participant.id];
                    }
                }

                // Create updated participant with calculated private key share
                let updated_participant = DKGParticipant {
                    id: participant.id,
                    secret_key: SecretKey {
                        id: participant.id,
                        setup_digest: [0; 32],
                        sk_i: private_key_share,
                    },
                    public_key: PublicKey {
                        id: participant.id,
                        pk_i: G::generator() * private_key_share,
                    },
                    vss: participant.vss.clone(),
                };
                updated_participants.push(updated_participant);
            }
        }

        // Aggregate master secret and public key
        let mut master_sk_sum = G::ScalarField::zero();
        let mut master_pk_sum = G::zero();

        // Sum up all successful participants' secrets
        for participant in &participants {
            if successful_participants.contains(&participant.id) {
                master_sk_sum += participant.secret_key.sk_i;
            }
        }

        // Sum up all commitments from successful participants
        for share_msg in &share_messages {
            if successful_participants.contains(&share_msg.sender_id) {
                // Add the first commitment (which is G * secret) from each participant
                if !share_msg.commitments.is_empty() {
                    master_pk_sum += share_msg.commitments[0];
                }
            }
        }

        let master_sk = MasterSecretKey { sk: master_sk_sum };

        let master_pk = MasterPublicKey { pk: master_pk_sum };

        DKGResult {
            master_sk: master_sk,
            master_pk: master_pk,
            participants: updated_participants,
            successful_participants,
        }
    }

    /// Verify that the master public key matches the master secret
    pub fn verify_master_key(
        &self,
        master_sk: &MasterSecretKey<G>,
        master_pk: &MasterPublicKey<G>,
    ) -> bool {
        master_pk.pk == G::generator() * master_sk.sk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::pairing::Pairing;
    use ark_std::test_rng;

    type E = ark_bls12_381::Bls12_381;
    type G1 = <E as Pairing>::G1;

    #[test]
    fn test_feldman_vss_basic_functionality() {
        let mut rng = test_rng();
        let threshold = 4;
        let share_amount = 8;

        let (root_powers, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(share_amount);
        let vss = VerifiableSecretSharing::<G1>::new(
            threshold,
            share_amount,
            root_powers,
            lagrange_coeffs,
        );

        // Generate a random secret
        let secret = Fr::rand(&mut rng);

        // Share the secret
        let (shares, commitments) = vss.share_secret(secret, &mut rng);

        // Verify we got the right number of shares and commitments
        assert_eq!(shares.len(), share_amount);
        assert_eq!(commitments.len(), threshold);

        // Verify each share
        for (i, share) in shares.iter().enumerate() {
            assert!(vss.verify_share(i, *share, commitments.clone()));
        }
    }

    #[test]
    fn test_feldman_vss_secret_recovery() {
        let mut rng = test_rng();
        let threshold = 4;
        let share_amount = 8;
        let (root_powers, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(share_amount);
        let vss = VerifiableSecretSharing::<G1>::new(
            threshold,
            share_amount,
            root_powers,
            lagrange_coeffs,
        );

        // Generate a random secret
        let original_secret = Fr::rand(&mut rng);

        // Share the secret
        let (shares, _) = vss.share_secret(original_secret, &mut rng);

        // Test recovery with exactly threshold shares
        let recovery_shares: Vec<(u64, Fr)> = shares
            .iter()
            .enumerate()
            .take(threshold)
            .map(|(i, s)| (i as u64, *s))
            .collect();
        let recovered_secret = vss.recover_secret(recovery_shares);
        assert_eq!(original_secret, recovered_secret);
    }

    #[test]
    fn test_feldman_vss_share_verification() {
        let mut rng = test_rng();
        let threshold = 8;
        let share_amount = 16;
        let (root_powers, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(share_amount);
        let vss = VerifiableSecretSharing::<G1>::new(
            threshold,
            share_amount,
            root_powers,
            lagrange_coeffs,
        );

        let secret = Fr::rand(&mut rng);
        let (shares, commitments) = vss.share_secret(secret, &mut rng);

        // Test verification of valid shares
        for (i, share) in shares.iter().enumerate() {
            assert!(vss.verify_share(i, *share, commitments.clone()));
        }

        // Test verification of invalid shares
        let fake_share = Fr::rand(&mut rng);
        assert!(!vss.verify_share(0, fake_share, commitments.clone()));
    }

    // ============================================================================
    // DKG Tests
    // ============================================================================

    #[test]
    fn test_dkg_basic_functionality() {
        let mut rng = test_rng();
        let threshold = 3;
        let share_amount = 5;
        let n = share_amount;
        // Use the common precomputation function
        let (root_powers, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(share_amount);

        let dkg = DistributedKeyGeneration::<G1>::new(n, threshold, root_powers, lagrange_coeffs);

        // Initialize participants
        let mut participants = Vec::new();
        for i in 0..n {
            participants.push(dkg.initialize_participant(i, &mut rng));
        }

        // Generate sharing messages
        let mut share_messages = Vec::new();
        for participant in &participants {
            share_messages.push(dkg.generate_sharing_message(participant, &mut rng));
        }

        // Complete DKG
        let result = dkg.complete_dkg(participants, share_messages);

        // Verify results
        assert_eq!(result.successful_participants.len(), n);
        assert!(dkg.verify_master_key(&result.master_sk, &result.master_pk));
    }

    #[test]
    fn test_dkg_with_failed_participants() {
        let mut rng = test_rng();
        let threshold = 4;
        let share_amount = 6;
        let n = share_amount;
        // Use the common precomputation function
        let (root_powers, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(share_amount);

        let dkg = DistributedKeyGeneration::<G1>::new(n, threshold, root_powers, lagrange_coeffs);

        // Initialize participants
        let mut participants = Vec::new();
        for i in 0..n {
            participants.push(dkg.initialize_participant(i, &mut rng));
        }

        // Generate sharing messages
        let mut share_messages = Vec::new();
        for participant in &participants {
            share_messages.push(dkg.generate_sharing_message(participant, &mut rng));
        }

        // Corrupt one participant's shares to simulate failure
        share_messages[0].shares[1] = Fr::rand(&mut rng); // Corrupt share

        // Complete DKG
        let result = dkg.complete_dkg(participants, share_messages);

        // Should still succeed with remaining participants
        assert!(result.successful_participants.len() >= threshold);
        assert!(dkg.verify_master_key(&result.master_sk, &result.master_pk));
    }

    #[test]
    fn test_dkg_share_verification() {
        let mut rng = test_rng();
        let threshold = 3;
        let share_amount = 6;
        let n = share_amount;
        // Use the common precomputation function
        let (root_powers, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(share_amount);

        let dkg = DistributedKeyGeneration::<G1>::new(n, threshold, root_powers, lagrange_coeffs);

        // Initialize participants
        let participants: Vec<_> = (0..n)
            .map(|i| dkg.initialize_participant(i, &mut rng))
            .collect();

        // Generate sharing message
        let share_msg = dkg.generate_sharing_message(&participants[0], &mut rng);

        // Verify shares
        for i in 1..n {
            let result = dkg.verify_sharing_message(&share_msg, i);
            assert!(result.is_valid);
            assert!(result.error_msg.is_none());
        }
    }

    #[test]
    fn test_dkg_share_aggregation() {
        let mut rng = test_rng();
        let threshold = 3;
        let share_amount = 6;
        let n = share_amount;
        // Use the common precomputation function
        let (root_powers, lagrange_coeffs) = precompute_lagrange_coefficients::<Fr>(share_amount);

        let dkg = DistributedKeyGeneration::<G1>::new(n, threshold, root_powers, lagrange_coeffs);

        // Initialize participants
        let participants: Vec<_> = (0..n)
            .map(|i| dkg.initialize_participant(i, &mut rng))
            .collect();

        // Generate sharing messages
        let share_messages: Vec<_> = participants
            .iter()
            .map(|p| dkg.generate_sharing_message(p, &mut rng))
            .collect();

        // Test aggregation for participant 0
        let successful_participants = vec![0, 1, 2]; // Use first 3 participants
        let aggregated_secret = dkg.aggregate_shares(
            &share_messages,
            &successful_participants,
            0, // participant_id
        );

        // Verify aggregated secret is non-zero
        assert_ne!(aggregated_secret, Fr::zero());
    }
}
