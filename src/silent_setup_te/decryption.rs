//! Proof-free STE decryption. The public dummy slot never counts toward the threshold.
use super::{
    encryption::Ciphertext,
    kzg::{PowersOfTau, KZG10},
    setup::{AggregateKey, SecretKey},
    utils::interp_mostly_zero,
};
use crate::arithmetic::public_msm;
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr,
};
use ark_ff::Field;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_serialize::Valid;
use ark_std::{One, Zero};

pub fn partial_decrypt<E: Pairing>(ct: &Ciphertext<E>, sk: &SecretKey<E>) -> E::G2 {
    ct.gamma_g2 * sk.scalar()
}

/// Algebraic share-verification kernel. The PVSS caller separately checks
/// eligibility, the registered public key and the absence of a share proof.
pub fn verify_partial_decryption<E: Pairing>(
    ct: &Ciphertext<E>,
    d: E::G2,
    pk: E::G1,
    generator: E::G1Affine,
) -> bool {
    ct.check().is_ok() && verify_partial_decryption_validated::<E>(ct, d, pk, generator)
}

/// Internal kernel for a ciphertext borrowed through a verified PVSS receipt.
/// Incoming share and public key checks remain mandatory.
pub(crate) fn verify_partial_decryption_validated<E: Pairing>(
    ct: &Ciphertext<E>,
    d: E::G2,
    pk: E::G1,
    generator: E::G1Affine,
) -> bool {
    pk.check().is_ok()
        && d.check().is_ok()
        && E::multi_pairing([pk, -generator.into_group()], [ct.gamma_g2, d]).is_zero()
}

/// Ciphertext-independent public reconstruction material for one audited setup
/// and exact ordered real-party subset. No partial decryption is retained.
pub struct ReconstructionPlan<E: Pairing> {
    ids: Vec<usize>,
    weights: Vec<E::ScalarField>,
    n_inv: E::ScalarField,
    prepared_g1: [E::G1Prepared; 6],
    prepared_b_g2: E::G2Prepared,
}

fn valid_indices<E: Pairing>(
    ids: &[usize],
    t: usize,
    agg_key: &AggregateKey<E>,
    params: &PowersOfTau<E>,
) -> bool {
    let n = params.powers_of_g.len();
    if n < 2 || t == 0 || t >= n || params.powers_of_h.len() != n + 1 || ids.len() < t {
        return false;
    }
    let mut selected = std::collections::HashSet::new();
    ids.iter().all(|id| {
        *id > 0
            && *id < n
            && selected.insert(*id)
            && agg_key.key_indices.get(*id).and_then(|p| *p).is_some()
    })
}

fn build_plan<E: Pairing>(
    ids: &[usize],
    t: usize,
    agg_key: &AggregateKey<E>,
    params: &PowersOfTau<E>,
) -> Option<ReconstructionPlan<E>> {
    if !valid_indices(ids, t, agg_key, params) {
        return None;
    }
    let n = params.powers_of_g.len();
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n)?;
    if domain.size() != n {
        return None;
    }
    let mut selected = vec![false; n];
    for id in ids {
        selected[*id] = true;
    }
    let elements: Vec<_> = domain.elements().collect();
    let mut points = vec![elements[0]];
    for id in 1..n {
        if !selected[id] {
            points.push(elements[id]);
        }
    }
    let b = interp_mostly_zero(E::ScalarField::one(), &points);
    if b.degree() > n - 1 - t {
        return None;
    }
    let b_evals = domain.fft(&b.coeffs);
    let b_g2: E::G2 = KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g2(params, &b)
        .ok()?
        .into();
    let mut b_minus_one = b.clone();
    b_minus_one.coeffs[0] -= E::ScalarField::one();
    let divisor =
        DensePolynomial::from_coefficients_vec(vec![-E::ScalarField::one(), E::ScalarField::one()]);
    let q0 = &b_minus_one / &divisor;
    let q0_g1: E::G1 = KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g1(params, &q0)
        .ok()?
        .into();
    let mut bhat_coefficients = vec![E::ScalarField::zero(); t];
    bhat_coefficients.extend_from_slice(&b.coeffs);
    let bhat = DensePolynomial::from_coefficients_vec(bhat_coefficients);
    let bhat_g1: E::G1 = KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g1(params, &bhat)
        .ok()?
        .into();
    let n_inv = E::ScalarField::from(n as u64).inverse()?;
    let mut apk = params.powers_of_g[0].into_group();
    for id in ids {
        let pk = agg_key.pk.get(*agg_key.key_indices.get(*id)?.as_ref()?)?;
        apk += pk.bls_pk * b_evals[*id];
    }
    apk *= n_inv;
    let (mut qx, mut qhatx, mut qz) = (E::G1::zero(), E::G1::zero(), E::G1::zero());
    for pk in &agg_key.pk {
        qx += pk.sk_li_x * b_evals[pk.id];
        qhatx += pk.sk_li_minus0 * b_evals[pk.id];
        qz += *agg_key.agg_sk_li_lj_z.get(pk.id)? * b_evals[pk.id];
    }
    let prepared_g1 = [-apk, -qz, -qx, qhatx, -bhat_g1, -q0_g1].map(E::G1Prepared::from);
    let prepared_b_g2 = E::G2Prepared::from(b_g2);
    Some(ReconstructionPlan {
        ids: ids.to_vec(),
        weights: ids.iter().map(|id| b_evals[*id]).collect(),
        n_inv,
        prepared_g1,
        prepared_b_g2,
    })
}

/// `setup_digest` must bind the complete audited public parameters and epoch.
/// Index eligibility is checked on every lookup, including a cache hit.
pub fn prepare_reconstruction<E: Pairing>(
    ids: &[usize],
    t: usize,
    agg_key: &AggregateKey<E>,
    params: &PowersOfTau<E>,
    setup_digest: &[u8; 32],
) -> Option<std::sync::Arc<ReconstructionPlan<E>>> {
    if !valid_indices(ids, t, agg_key, params) {
        return None;
    }
    crate::cache::get_or_try_insert(
        "ste-reconstruction",
        crate::cache::binding(&(
            *setup_digest,
            params.powers_of_g.len() as u64,
            t as u64,
            ids.to_vec(),
        )),
        || build_plan(ids, t, agg_key, params),
    )
}

impl<E: Pairing> ReconstructionPlan<E> {
    fn mask(&self, ct: &Ciphertext<E>, shares: &[(usize, E::G2)]) -> Option<PairingOutput<E>> {
        if shares.len() != self.ids.len()
            || shares
                .iter()
                .zip(&self.ids)
                .any(|((id, _), expected)| id != expected)
        {
            return None;
        }
        let bases: Vec<_> = shares.iter().map(|(_, d)| *d).collect();
        let mut sigma = ct.gamma_g2 + public_msm(&bases, &self.weights);
        sigma *= self.n_inv;
        Some(E::multi_pairing(
            [
                self.prepared_g1[0].clone(),
                self.prepared_g1[1].clone(),
                self.prepared_g1[2].clone(),
                self.prepared_g1[3].clone(),
                self.prepared_g1[4].clone(),
                self.prepared_g1[5].clone(),
                E::G1Prepared::from(ct.sa1[0]),
                E::G1Prepared::from(ct.sa1[1]),
            ],
            [
                E::G2Prepared::from(ct.sa2[0]),
                E::G2Prepared::from(ct.sa2[1]),
                E::G2Prepared::from(ct.sa2[2]),
                E::G2Prepared::from(ct.sa2[3]),
                E::G2Prepared::from(ct.sa2[4]),
                E::G2Prepared::from(ct.sa2[5]),
                self.prepared_b_g2.clone(),
                E::G2Prepared::from(sigma),
            ],
        ))
    }
}

/// Uncached reference path, also available to TE callers without a bound setup digest.
pub fn agg_dec<E: Pairing>(
    shares: &[(usize, E::G2)],
    ct: &Ciphertext<E>,
    t: usize,
    agg_key: &AggregateKey<E>,
    params: &PowersOfTau<E>,
) -> Option<PairingOutput<E>> {
    let ids: Vec<_> = shares.iter().map(|(id, _)| *id).collect();
    build_plan(&ids, t, agg_key, params)?.mask(ct, shares)
}
pub fn decrypt<E: Pairing>(
    ct: &Ciphertext<E>,
    shares: &[(usize, E::G2)],
    t: usize,
    agg_key: &AggregateKey<E>,
    params: &PowersOfTau<E>,
) -> Option<PairingOutput<E>> {
    Some(ct.c_3 - agg_dec(shares, ct, t, agg_key, params)?)
}
pub fn decrypt_cached<E: Pairing>(
    ct: &Ciphertext<E>,
    shares: &[(usize, E::G2)],
    t: usize,
    agg_key: &AggregateKey<E>,
    params: &PowersOfTau<E>,
    setup_digest: &[u8; 32],
) -> Option<PairingOutput<E>> {
    let ids: Vec<_> = shares.iter().map(|(id, _)| *id).collect();
    let plan = prepare_reconstruction(&ids, t, agg_key, params, setup_digest)?;
    Some(ct.c_3 - plan.mask(ct, shares)?)
}
