//! A local dedicated Power-of-Tau ceremony model and public update checks.
//! Verification cannot certify honest entropy or secure erasure by contributors.
use super::kzg::PowersOfTau;
use crate::{
    pvss::context,
    utils::{dleq_prove_with_context, dleq_verify_with_context, DleqProof},
};
use ark_ec::{pairing::Pairing, AffineRepr, PrimeGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{rand::RngCore, One, Zero};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct Contribution<E: Pairing> {
    pub crs: PowersOfTau<E>,
    pub beta_g1: E::G1,
    pub beta_g2: E::G2,
    pub proof: DleqProof<E::G1>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct CeremonyRecord<E: Pairing> {
    pub initial: PowersOfTau<E>,
    pub contributions: Vec<Contribution<E>>,
}

fn update_context<E: Pairing>(old: &PowersOfTau<E>, new: &PowersOfTau<E>) -> Vec<u8> {
    let mut transcript = merlin::Transcript::new(b"pvss-dedicated-power-of-tau-update");
    context::append(&mut transcript, b"old-crs", old);
    context::append(&mut transcript, b"new-crs", new);
    let mut bytes = vec![0; 32];
    transcript.challenge_bytes(b"update-context", &mut bytes);
    bytes
}

pub fn initial<E: Pairing>(n: usize) -> PowersOfTau<E> {
    PowersOfTau {
        powers_of_g: vec![E::G1::generator().into(); n],
        powers_of_h: vec![E::G2::generator().into(); n + 1],
    }
}

pub fn contribute<E: Pairing, R: RngCore>(
    old: &PowersOfTau<E>,
    beta: E::ScalarField,
    rng: &mut R,
) -> Option<Contribution<E>> {
    let n = old.powers_of_g.len();
    if n < 2 || old.powers_of_h.len() != n + 1 || beta.is_zero() {
        return None;
    }
    let mut power = E::ScalarField::one();
    let mut powers_of_g = Vec::with_capacity(n);
    let mut powers_of_h = Vec::with_capacity(n + 1);
    for i in 0..=n {
        if i < n {
            powers_of_g.push((old.powers_of_g[i] * power).into());
        }
        powers_of_h.push((old.powers_of_h[i] * power).into());
        power *= beta;
    }
    let crs = PowersOfTau {
        powers_of_g,
        powers_of_h,
    };
    let g = old.powers_of_g[0].into_group();
    let beta_g1 = g * beta;
    let beta_g2 = old.powers_of_h[0] * beta;
    let proof = dleq_prove_with_context(
        g,
        g,
        beta,
        (beta_g1, beta_g1),
        &update_context(old, &crs),
        rng,
    );
    Some(Contribution {
        crs,
        beta_g1,
        beta_g2,
        proof,
    })
}

pub fn verify_final<E: Pairing>(crs: &PowersOfTau<E>) -> bool {
    let n = crs.powers_of_g.len();
    if n < 2 || !n.is_power_of_two() || crs.powers_of_h.len() != n + 1 || crs.check().is_err() {
        return false;
    }
    let u = &crs.powers_of_g;
    let v = &crs.powers_of_h;
    if u[0].is_zero() || v[0].is_zero() || v[1].is_zero() || v[n] == v[0] {
        return false;
    }
    (0..n).all(|i| E::pairing(u[i], v[0]) == E::pairing(u[0], v[i]))
        && (1..=n).all(|i| E::pairing(u[1], v[i - 1]) == E::pairing(u[0], v[i]))
}

pub fn verify_record<E: Pairing>(crs: &PowersOfTau<E>, record: &CeremonyRecord<E>) -> bool {
    if !verify_final(crs) || record.contributions.is_empty() {
        return false;
    }
    let n = crs.powers_of_g.len();
    let expected = initial::<E>(n);
    if record.initial.powers_of_g != expected.powers_of_g
        || record.initial.powers_of_h != expected.powers_of_h
    {
        return false;
    }
    let mut old = &record.initial;
    for contribution in &record.contributions {
        let new = &contribution.crs;
        if new.powers_of_g.len() != n
            || new.powers_of_h.len() != n + 1
            || !verify_final(new)
            || new.powers_of_g[0] != old.powers_of_g[0]
            || new.powers_of_h[0] != old.powers_of_h[0]
            || contribution.beta_g1.is_zero()
            || contribution.beta_g2.is_zero()
            || contribution.proof.check().is_err()
            || contribution.beta_g1.check().is_err()
            || contribution.beta_g2.check().is_err()
        {
            return false;
        }
        let g = old.powers_of_g[0].into_group();
        if !dleq_verify_with_context(
            g,
            g,
            (contribution.beta_g1, contribution.beta_g1),
            &contribution.proof,
            &update_context(old, new),
        ) || E::pairing(contribution.beta_g1, old.powers_of_h[0])
            != E::pairing(old.powers_of_g[0], contribution.beta_g2)
            || E::pairing(new.powers_of_g[1], old.powers_of_h[0])
                != E::pairing(old.powers_of_g[1], contribution.beta_g2)
        {
            return false;
        }
        old = new;
    }
    old.powers_of_g == crs.powers_of_g && old.powers_of_h == crs.powers_of_h
}
