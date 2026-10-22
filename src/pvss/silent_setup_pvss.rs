//! Instantiation II: sharing NIZK and a two-pairing share check with pi_i=bot.
use super::context;
use crate::arithmetic::fixed_base_mul;
use crate::silent_setup_te::{
    ceremony::{self, CeremonyRecord},
    decryption::{decrypt_cached, partial_decrypt},
    encryption::{encrypt_with_randomness, matrix_image, Ciphertext},
    kzg::PowersOfTau,
    setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey},
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{rand::RngCore, UniformRand, Zero};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct SilentSetupPVSSParams<E: Pairing> {
    pub security_param: usize,
    pub threshold: usize,
    /// Total domain slots, including dummy slot 0. Must be an exact radix-2 domain.
    pub n: usize,
    pub powers_of_tau: PowersOfTau<E>,
    pub ceremony_record: CeremonyRecord<E>,
    pub lagrange_params: LagrangePowers<E>,
    /// Full public registry, including records excluded by the audit.
    pub public_keys: Vec<PublicKey<E>>,
    pub key_indices: Vec<Option<usize>>,
    pub aggregate_key: AggregateKey<E>,
    pub generator_t1: PairingOutput<E>,
    pub epoch: u64,
    pub setup_digest: [u8; 32],
}

impl<E: Pairing> SilentSetupPVSSParams<E> {
    fn digest(&self) -> [u8; 32] {
        let mut public = self.clone();
        public.setup_digest = [0; 32];
        context::digest(b"pvss-instantiation-ii-setup", &public)
    }

    fn valid_shape(&self) -> bool {
        self.security_param > 0
            && self.n >= 2
            && self.n.is_power_of_two()
            && self.threshold > 0
            && self.threshold < self.n
            && self.public_keys.len() >= self.threshold
            && self.powers_of_tau.powers_of_g.len() == self.n
            && self.powers_of_tau.powers_of_h.len() == self.n + 1
            && self.key_indices.len() == self.n
            && self.aggregate_key.pk.len() >= self.threshold + 1
            && self.aggregate_key.pk.len() <= self.public_keys.len() + 1
            && !self.generator_t1.is_zero()
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Proof<E: Pairing> {
    pub commitment: Ciphertext<E>,
    pub challenge: E::ScalarField,
    pub response_gamma: E::ScalarField,
    pub response_v: [E::ScalarField; 5],
    pub response_s: E::ScalarField,
}

/// None denotes the manuscript's bot placeholder; Some(()) must be rejected.
pub type ReconstructionProof = Option<()>;

/// Immutable, lifetime-bound evidence that this sharing passed the full proof
/// and membership checks. No global memoization of dynamic inputs is used.
pub struct VerifiedSharing<'a, E: Pairing> {
    ct: &'a Ciphertext<E>,
    pp: &'a SilentSetupPVSSParams<E>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SilentSetupPVSSError {
    InvalidParameters,
    InvalidThreshold,
    InvalidParticipantCount,
    InvalidSecret,
    InvalidCiphertext,
    InvalidProof,
    InsufficientDecryptions,
    KZGError,
}

pub struct SilentSetupPVSS<E: Pairing> {
    _phantom: std::marker::PhantomData<E>,
}

impl<E: Pairing> SilentSetupPVSS<E> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Honest local ceremony simulator. Does not implement a distributed network or certify erasure.
    /// n is the total slot count; returns only n-1 real shareholder key pairs.
    pub fn setup<R: RngCore>(
        security_param: usize,
        threshold: usize,
        n: usize,
        rng: &mut R,
    ) -> Result<(SilentSetupPVSSParams<E>, Vec<(SecretKey<E>, PublicKey<E>)>), SilentSetupPVSSError>
    {
        Self::setup_with_capacity(security_param, threshold, n, n.saturating_sub(1), rng)
    }

    /// Keep the domain capacity explicit when fewer real parties occupy the available slots.
    pub fn setup_with_capacity<R: RngCore>(
        security_param: usize,
        threshold: usize,
        slots: usize,
        real_parties: usize,
        rng: &mut R,
    ) -> Result<(SilentSetupPVSSParams<E>, Vec<(SecretKey<E>, PublicKey<E>)>), SilentSetupPVSSError>
    {
        if security_param == 0 || slots < 2 || !slots.is_power_of_two() {
            return Err(SilentSetupPVSSError::InvalidParameters);
        }
        if threshold == 0 || threshold > real_parties || real_parties >= slots {
            return Err(SilentSetupPVSSError::InvalidThreshold);
        }
        let initial = ceremony::initial::<E>(slots);
        let beta = loop {
            let value = E::ScalarField::rand(rng);
            if !value.is_zero() && value.pow([slots as u64]) != E::ScalarField::from(1u64) {
                break value;
            }
        };
        let contribution =
            ceremony::contribute(&initial, beta, rng).ok_or(SilentSetupPVSSError::KZGError)?;
        let crs = contribution.crs.clone();
        let record = CeremonyRecord {
            initial,
            contributions: vec![contribution],
        };
        // Fast basis generation is confined to this local setup simulator.
        let basis = crate::cache::get_or_try_insert(
            "ste-public-lagrange-basis",
            crate::cache::binding(&crs),
            || Some(LagrangePowers::<E>::new(beta, slots)),
        )
        .ok_or(SilentSetupPVSSError::KZGError)?
        .as_ref()
        .clone();
        Self::finish_setup(
            security_param,
            threshold,
            crs,
            record,
            basis,
            real_parties,
            rng,
        )
    }

    /// Key generation using public CRS material only, after verifying a dedicated ceremony record.
    pub fn setup_from_crs<R: RngCore>(
        security_param: usize,
        threshold: usize,
        crs: PowersOfTau<E>,
        record: CeremonyRecord<E>,
        real_parties: usize,
        rng: &mut R,
    ) -> Result<(SilentSetupPVSSParams<E>, Vec<(SecretKey<E>, PublicKey<E>)>), SilentSetupPVSSError>
    {
        if security_param == 0
            || threshold == 0
            || threshold > real_parties
            || real_parties >= crs.powers_of_g.len()
            || !ceremony::verify_record(&crs, &record)
        {
            return Err(SilentSetupPVSSError::InvalidParameters);
        }
        let basis = crate::cache::get_or_try_insert(
            "ste-public-lagrange-basis",
            crate::cache::binding(&crs),
            || LagrangePowers::<E>::from_crs(&crs),
        )
        .ok_or(SilentSetupPVSSError::KZGError)?
        .as_ref()
        .clone();
        Self::finish_setup(
            security_param,
            threshold,
            crs,
            record,
            basis,
            real_parties,
            rng,
        )
    }

    fn finish_setup<R: RngCore>(
        security_param: usize,
        threshold: usize,
        crs: PowersOfTau<E>,
        record: CeremonyRecord<E>,
        basis: LagrangePowers<E>,
        real_parties: usize,
        rng: &mut R,
    ) -> Result<(SilentSetupPVSSParams<E>, Vec<(SecretKey<E>, PublicKey<E>)>), SilentSetupPVSSError>
    {
        let mut generator_t1 = PairingOutput::<E>::rand(rng);
        while generator_t1.is_zero() {
            generator_t1 = PairingOutput::<E>::rand(rng);
        }
        let mut keys: Vec<_> = (1..=real_parties)
            .map(|id| {
                let sk = SecretKey::new(id, rng);
                let pk = sk.get_pk(&basis);
                (sk, pk)
            })
            .collect();
        let public_keys: Vec<_> = keys.iter().map(|(_, pk)| pk.clone()).collect();
        let mut active_keys = vec![SecretKey::<E>::dummy().get_pk(&basis)];
        active_keys.extend(public_keys.clone());
        let aggregate_key = AggregateKey::new(active_keys, &crs, generator_t1);
        let mut key_indices = vec![None; crs.powers_of_g.len()];
        for (position, key) in public_keys.iter().enumerate() {
            key_indices[key.id] = Some(position);
        }
        let mut pp = SilentSetupPVSSParams {
            security_param,
            threshold,
            n: crs.powers_of_g.len(),
            powers_of_tau: crs,
            ceremony_record: record,
            lagrange_params: basis,
            public_keys,
            key_indices,
            aggregate_key,
            generator_t1,
            epoch: 0,
            setup_digest: [0; 32],
        };
        pp.setup_digest = pp.digest();
        for (sk, _) in &mut keys {
            sk.setup_digest = pp.setup_digest;
        }
        Ok((pp, keys))
    }

    /// Audit is a predicate. It checks cached public aggregates and never updates pp.
    pub fn verify_setup(pp: &SilentSetupPVSSParams<E>, public_keys: &[PublicKey<E>]) -> bool {
        if !pp.valid_shape()
            || pp.setup_digest != pp.digest()
            || !ceremony::verify_record(&pp.powers_of_tau, &pp.ceremony_record)
            || !same(public_keys, &pp.public_keys)
        {
            return false;
        }
        let Some(basis) = LagrangePowers::from_crs(&pp.powers_of_tau) else {
            return false;
        };
        if !same(&basis, &pp.lagrange_params) {
            return false;
        }
        let Some((active, indices)) = Self::accepted_registry(pp, public_keys, &basis) else {
            return false;
        };
        if indices != pp.key_indices {
            return false;
        }
        let recomputed = AggregateKey::new(active, &pp.powers_of_tau, pp.generator_t1);
        same(&recomputed, &pp.aggregate_key)
    }

    fn accepted_registry(
        pp: &SilentSetupPVSSParams<E>,
        registry: &[PublicKey<E>],
        basis: &LagrangePowers<E>,
    ) -> Option<(Vec<PublicKey<E>>, Vec<Option<usize>>)> {
        let mut seen = std::collections::HashSet::new();
        let mut active = vec![SecretKey::<E>::dummy().get_pk(basis)];
        let mut indices = vec![None; pp.n];
        for (position, key) in registry.iter().enumerate() {
            if key.id == 0 || key.id >= pp.n || !seen.insert(key.id) {
                return None;
            }
            if Self::verify_public_key(key, &pp.powers_of_tau, basis) {
                indices[key.id] = Some(position);
                active.push(key.clone());
            }
        }
        if active.len() - 1 < pp.threshold {
            return None;
        }
        active.sort_by_key(|key| key.id);
        Some((active, indices))
    }

    /// Recompute a new epoch within the same dedicated domain, retaining the full registry.
    /// This is public aggregation, not a claim of mobile-corruption security.
    /// Shareholders bind retained key records to the accepted new setup digest before use.
    pub fn reconfigure_epoch(
        pp: &SilentSetupPVSSParams<E>,
        registry: Vec<PublicKey<E>>,
        epoch: u64,
    ) -> Result<SilentSetupPVSSParams<E>, SilentSetupPVSSError> {
        if epoch <= pp.epoch || !Self::verify_setup(pp, &pp.public_keys) {
            return Err(SilentSetupPVSSError::InvalidParameters);
        }
        let (active, indices) = Self::accepted_registry(pp, &registry, &pp.lagrange_params)
            .ok_or(SilentSetupPVSSError::InvalidParticipantCount)?;
        let mut next = pp.clone();
        next.public_keys = registry;
        next.key_indices = indices;
        next.aggregate_key = AggregateKey::new(active, &next.powers_of_tau, next.generator_t1);
        next.epoch = epoch;
        next.setup_digest = next.digest();
        Ok(next)
    }

    fn verify_public_key(
        pk: &PublicKey<E>,
        params: &PowersOfTau<E>,
        basis: &LagrangePowers<E>,
    ) -> bool {
        let n = params.powers_of_g.len();
        if pk.id >= n || pk.sk_li_lj_z.len() != n || pk.check().is_err() {
            return false;
        }
        let h = params.powers_of_h[0];
        let i = pk.id;
        E::pairing(pk.sk_li, h) == E::pairing(pk.bls_pk, basis.li_g2[i])
            && E::pairing(pk.sk_li_minus0, h) == E::pairing(pk.bls_pk, basis.li_minus0_g2[i])
            && E::pairing(pk.sk_li_x, h) == E::pairing(pk.bls_pk, basis.li_x_g2[i])
            && (0..n).all(|j| {
                E::pairing(pk.sk_li_lj_z[j], h) == E::pairing(pk.bls_pk, basis.li_lj_z_g2[i][j])
            })
    }

    fn sharing_challenge(
        pp: &SilentSetupPVSSParams<E>,
        ct: &Ciphertext<E>,
        commitment: &Ciphertext<E>,
    ) -> E::ScalarField {
        let mut transcript =
            context::transcript(b"pvss-instantiation-ii-sharing", &pp.setup_digest, pp.epoch);
        context::append(&mut transcript, b"ciphertext", ct);
        context::append(&mut transcript, b"commitment", commitment);
        context::challenge(&mut transcript)
    }

    pub fn share<R: RngCore>(
        secret: E::ScalarField,
        pp: &SilentSetupPVSSParams<E>,
        rng: &mut R,
    ) -> Result<(Ciphertext<E>, Proof<E>), SilentSetupPVSSError> {
        if !pp.valid_shape() {
            return Err(SilentSetupPVSSError::InvalidParameters);
        }
        let gamma = E::ScalarField::rand(rng);
        let v = std::array::from_fn(|_| E::ScalarField::rand(rng));
        let ct = encrypt_with_randomness(
            &pp.aggregate_key,
            pp.threshold,
            &pp.powers_of_tau,
            fixed_base_mul(pp.generator_t1, secret),
            gamma,
            &v,
        );
        let gamma_prime = E::ScalarField::rand(rng);
        let v_prime = std::array::from_fn(|_| E::ScalarField::rand(rng));
        let s_prime = E::ScalarField::rand(rng);
        // Commit with the same A(C[0]), not A(C'[0]).
        let (sa1, sa2, mask) = matrix_image(
            &pp.aggregate_key,
            pp.threshold,
            &pp.powers_of_tau,
            ct.gamma_g2,
            &v_prime,
        );
        let commitment = Ciphertext {
            gamma_g2: fixed_base_mul(pp.powers_of_tau.powers_of_h[0].into_group(), gamma_prime),
            sa1,
            sa2,
            c_3: fixed_base_mul(pp.generator_t1, s_prime) + mask,
        };
        let c = Self::sharing_challenge(pp, &ct, &commitment);
        Ok((
            ct,
            Proof {
                commitment,
                challenge: c,
                response_gamma: gamma_prime - c * gamma,
                response_v: std::array::from_fn(|i| v_prime[i] - c * v[i]),
                response_s: s_prime - c * secret,
            },
        ))
    }

    pub fn verify(ct: &Ciphertext<E>, proof: &Proof<E>, pp: &SilentSetupPVSSParams<E>) -> bool {
        if !pp.valid_shape() || ct.check().is_err() || proof.check().is_err() {
            return false;
        }
        let c = Self::sharing_challenge(pp, ct, &proof.commitment);
        let (sa1, sa2, mask) = matrix_image(
            &pp.aggregate_key,
            pp.threshold,
            &pp.powers_of_tau,
            ct.gamma_g2,
            &proof.response_v,
        );
        c == proof.challenge
            && proof.commitment.gamma_g2
                == ct.gamma_g2 * c
                    + fixed_base_mul(
                        pp.powers_of_tau.powers_of_h[0].into_group(),
                        proof.response_gamma,
                    )
            && (0..2).all(|i| proof.commitment.sa1[i] == ct.sa1[i] * c + sa1[i])
            && (0..6).all(|i| proof.commitment.sa2[i] == ct.sa2[i] * c + sa2[i])
            && proof.commitment.c_3
                == ct.c_3 * c + mask + fixed_base_mul(pp.generator_t1, proof.response_s)
    }

    pub fn verify_sharing<'a>(
        ct: &'a Ciphertext<E>,
        proof: &Proof<E>,
        pp: &'a SilentSetupPVSSParams<E>,
    ) -> Result<VerifiedSharing<'a, E>, SilentSetupPVSSError> {
        if !Self::verify(ct, proof, pp) {
            return Err(SilentSetupPVSSError::InvalidProof);
        }
        Ok(VerifiedSharing { ct, pp })
    }

    /// Requires a previously verified sharing. pi_s is retained as an unused interface input.
    pub fn pre_recon<R: RngCore>(
        ct: &Ciphertext<E>,
        _sharing_proof: &Proof<E>,
        sk: &SecretKey<E>,
        pp: &SilentSetupPVSSParams<E>,
        _rng: &mut R,
    ) -> Result<(E::G2, ReconstructionProof), SilentSetupPVSSError> {
        if ct.check().is_err() {
            return Err(SilentSetupPVSSError::InvalidCiphertext);
        }
        Self::pre_recon_validated(ct, sk, pp)
    }

    fn pre_recon_validated(
        ct: &Ciphertext<E>,
        sk: &SecretKey<E>,
        pp: &SilentSetupPVSSParams<E>,
    ) -> Result<(E::G2, ReconstructionProof), SilentSetupPVSSError> {
        if !pp.valid_shape() || sk.setup_digest != pp.setup_digest {
            return Err(SilentSetupPVSSError::InvalidParameters);
        }
        if sk.id == 0 || pp.key_indices.get(sk.id).and_then(|value| *value).is_none() {
            return Err(SilentSetupPVSSError::InvalidParticipantCount);
        }
        Ok((partial_decrypt(ct, sk), None))
    }

    pub fn dec_vrf(
        d: E::G2,
        proof: &ReconstructionProof,
        pk: &PublicKey<E>,
        ct: &Ciphertext<E>,
        pp: &SilentSetupPVSSParams<E>,
    ) -> bool {
        ct.check().is_ok() && Self::dec_vrf_validated(d, proof, pk, ct, pp)
    }

    fn dec_vrf_validated(
        d: E::G2,
        proof: &ReconstructionProof,
        pk: &PublicKey<E>,
        ct: &Ciphertext<E>,
        pp: &SilentSetupPVSSParams<E>,
    ) -> bool {
        if !pp.valid_shape() {
            return false;
        }
        let Some(position) = pp.key_indices.get(pk.id).and_then(|value| *value) else {
            return false;
        };
        let Some(expected) = pp.public_keys.get(position) else {
            return false;
        };
        proof.is_none()
            && pk.id != 0
            && expected.id == pk.id
            && pk.bls_pk == expected.bls_pk
            && crate::silent_setup_te::decryption::verify_partial_decryption_validated::<E>(
                ct,
                d,
                pk.bls_pk,
                pp.powers_of_tau.powers_of_g[0],
            )
    }

    /// Combines previously verified shares; no sharing or share verification is repeated here.
    pub fn reconstruct<R: RngCore>(
        ct: &Ciphertext<E>,
        shares: &[(usize, E::G2)],
        pp: &SilentSetupPVSSParams<E>,
        _rng: &mut R,
    ) -> Result<PairingOutput<E>, SilentSetupPVSSError> {
        if ct.check().is_err() {
            return Err(SilentSetupPVSSError::InvalidCiphertext);
        }
        Self::reconstruct_validated(ct, shares, pp)
    }

    fn reconstruct_validated(
        ct: &Ciphertext<E>,
        shares: &[(usize, E::G2)],
        pp: &SilentSetupPVSSParams<E>,
    ) -> Result<PairingOutput<E>, SilentSetupPVSSError> {
        if !pp.valid_shape() {
            return Err(SilentSetupPVSSError::InvalidParameters);
        }
        if shares.len() < pp.threshold {
            return Err(SilentSetupPVSSError::InsufficientDecryptions);
        }
        if shares.iter().any(|(_, d)| d.check().is_err()) {
            return Err(SilentSetupPVSSError::InvalidCiphertext);
        }
        decrypt_cached(
            ct,
            shares,
            pp.threshold,
            &pp.aggregate_key,
            &pp.powers_of_tau,
            &pp.setup_digest,
        )
        .ok_or(SilentSetupPVSSError::InvalidParticipantCount)
    }
}

impl<E: Pairing> VerifiedSharing<'_, E> {
    pub fn pre_recon<R: RngCore>(
        &self,
        sk: &SecretKey<E>,
        _rng: &mut R,
    ) -> Result<(E::G2, ReconstructionProof), SilentSetupPVSSError> {
        SilentSetupPVSS::<E>::pre_recon_validated(self.ct, sk, self.pp)
    }

    pub fn dec_vrf(&self, d: E::G2, proof: &ReconstructionProof, pk: &PublicKey<E>) -> bool {
        SilentSetupPVSS::<E>::dec_vrf_validated(d, proof, pk, self.ct, self.pp)
    }

    /// Shares still require DecVrf before combination, as in the raw interface.
    pub fn reconstruct(
        &self,
        shares: &[(usize, E::G2)],
    ) -> Result<PairingOutput<E>, SilentSetupPVSSError> {
        SilentSetupPVSS::<E>::reconstruct_validated(self.ct, shares, self.pp)
    }
}

fn same<T: CanonicalSerialize + ?Sized>(a: &T, b: &T) -> bool {
    let mut left = Vec::new();
    let mut right = Vec::new();
    a.serialize_compressed(&mut left)
        .expect("serialization to Vec");
    b.serialize_compressed(&mut right)
        .expect("serialization to Vec");
    left == right
}
