//! Silent setup public key hints are exclusively in G1.
use super::{
    kzg::{PowersOfTau, KZG10},
    utils::lagrange_poly,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    scalar_mul::ScalarMul,
    AffineRepr, PrimeGroup,
};
use ark_ff::Field;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, One, UniformRand, Zero};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct LagrangePowers<E: Pairing> {
    pub li: Vec<E::G1>,
    pub li_minus0: Vec<E::G1>,
    pub li_x: Vec<E::G1>,
    pub li_lj_z: Vec<Vec<E::G1>>,
    pub li_g2: Vec<E::G2>,
    pub li_minus0_g2: Vec<E::G2>,
    pub li_x_g2: Vec<E::G2>,
    pub li_lj_z_g2: Vec<Vec<E::G2>>,
}

impl<E: Pairing> LagrangePowers<E> {
    pub(crate) fn new(tau: E::ScalarField, n: usize) -> Self {
        assert!(n >= 2 && n.is_power_of_two());
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n).unwrap();
        let li_evals = domain.evaluate_all_lagrange_coefficients(tau);
        let n_inv = E::ScalarField::from(n as u64).inverse().unwrap();
        let tau_inv = tau.inverse().unwrap();
        let z_inv = domain.evaluate_vanishing_polynomial(tau).inverse().unwrap();
        // These are the same polynomial evaluations as the public-CRS path.
        // Fixed-base batches speed up only the local setup fixture; no online
        // algorithm or public-only setup path receives the trapdoor.
        let mut scalars = Vec::with_capacity(3 * n + n * n);
        scalars.extend_from_slice(&li_evals);
        scalars.extend(li_evals.iter().map(|v| *v - n_inv));
        scalars.extend(li_evals.iter().map(|v| (*v - n_inv) * tau_inv));
        for i in 0..n {
            for j in 0..n {
                let numerator = li_evals[i] * li_evals[j]
                    - if i == j {
                        li_evals[i]
                    } else {
                        E::ScalarField::zero()
                    };
                scalars.push(numerator * z_inv);
            }
        }
        let g1: Vec<E::G1> = E::G1::generator()
            .batch_mul(&scalars)
            .into_iter()
            .map(Into::into)
            .collect();
        let g2: Vec<E::G2> = E::G2::generator()
            .batch_mul(&scalars)
            .into_iter()
            .map(Into::into)
            .collect();
        LagrangePowers {
            li: g1[..n].to_vec(),
            li_minus0: g1[n..2 * n].to_vec(),
            li_x: g1[2 * n..3 * n].to_vec(),
            li_lj_z: g1[3 * n..]
                .chunks_exact(n)
                .map(|row| row.to_vec())
                .collect(),
            li_g2: g2[..n].to_vec(),
            li_minus0_g2: g2[n..2 * n].to_vec(),
            li_x_g2: g2[2 * n..3 * n].to_vec(),
            li_lj_z_g2: g2[3 * n..]
                .chunks_exact(n)
                .map(|row| row.to_vec())
                .collect(),
        }
    }
}

impl<E: Pairing> LagrangePowers<E> {
    /// Derive the verification bases solely from the degree-capped public CRS.
    pub fn from_crs(params: &PowersOfTau<E>) -> Option<Self> {
        let n = params.powers_of_g.len();
        if n < 2 || !n.is_power_of_two() || params.powers_of_h.len() != n + 1 {
            return None;
        }
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n)?;
        let mut result = Self {
            li: vec![],
            li_minus0: vec![],
            li_x: vec![],
            li_lj_z: vec![],
            li_g2: vec![],
            li_minus0_g2: vec![],
            li_x_g2: vec![],
            li_lj_z_g2: vec![],
        };
        let polys: Vec<_> = (0..n)
            .map(|i| lagrange_poly::<E::ScalarField>(n, i))
            .collect();
        for i in 0..n {
            let li = &polys[i];
            let mut minus0 = li.clone();
            minus0.coeffs[0] = E::ScalarField::zero();
            let quotient_x = DensePolynomial::from_coefficients_vec(li.coeffs[1..].to_vec());
            result.li.push(
                KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g1(params, li)
                    .ok()?
                    .into(),
            );
            result.li_g2.push(
                KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g2(params, li)
                    .ok()?
                    .into(),
            );
            result.li_minus0.push(
                KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g1(params, &minus0)
                    .ok()?
                    .into(),
            );
            result.li_minus0_g2.push(
                KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g2(params, &minus0)
                    .ok()?
                    .into(),
            );
            result.li_x.push(
                KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g1(params, &quotient_x)
                    .ok()?
                    .into(),
            );
            result.li_x_g2.push(
                KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g2(params, &quotient_x)
                    .ok()?
                    .into(),
            );
            let mut row_g1 = vec![];
            let mut row_g2 = vec![];
            for j in 0..n {
                let mut numerator = li * &polys[j];
                if i == j {
                    numerator = &numerator - li;
                }
                let (quotient, remainder) = numerator.divide_by_vanishing_poly(domain);
                if !remainder.is_zero() {
                    return None;
                }
                row_g1.push(
                    KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g1(params, &quotient)
                        .ok()?
                        .into(),
                );
                row_g2.push(
                    KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g2(params, &quotient)
                        .ok()?
                        .into(),
                );
            }
            result.li_lj_z.push(row_g1);
            result.li_lj_z_g2.push(row_g2);
        }
        Some(result)
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct SecretKey<E: Pairing> {
    pub id: usize,
    pub setup_digest: [u8; 32],
    sk: E::ScalarField,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    pub id: usize,
    pub bls_pk: E::G1,
    pub sk_li: E::G1,
    pub sk_li_minus0: E::G1,
    /// Entry id is h_{i,3}; other entries are h_{i,5,j}.
    pub sk_li_lj_z: Vec<E::G1>,
    pub sk_li_x: E::G1,
}

impl<E: Pairing> SecretKey<E> {
    pub fn new<R: RngCore>(id: usize, rng: &mut R) -> Self {
        Self {
            id,
            setup_digest: [0; 32],
            sk: E::ScalarField::rand(rng),
        }
    }
    pub(crate) fn dummy() -> Self {
        Self {
            id: 0,
            setup_digest: [0; 32],
            sk: E::ScalarField::one(),
        }
    }
    pub(crate) fn scalar(&self) -> E::ScalarField {
        self.sk
    }

    pub fn get_pk(&self, params: &LagrangePowers<E>) -> PublicKey<E> {
        PublicKey {
            id: self.id,
            bls_pk: E::G1::generator() * self.sk,
            sk_li: params.li[self.id] * self.sk,
            sk_li_minus0: params.li_minus0[self.id] * self.sk,
            sk_li_x: params.li_x[self.id] * self.sk,
            sk_li_lj_z: params.li_lj_z[self.id]
                .iter()
                .map(|value| *value * self.sk)
                .collect(),
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct AggregateKey<E: Pairing> {
    /// Active real keys and deterministic dummy, ordered by slot index.
    pub pk: Vec<PublicKey<E>>,
    pub key_indices: Vec<Option<usize>>,
    /// h_{i,3}+A_i, stored at domain index i; all sums are in G1.
    pub agg_sk_li_lj_z: Vec<E::G1>,
    pub ask: E::G1,
    pub z_g2: E::G2,
    pub h_minus1: E::G2,
    pub e_gh: PairingOutput<E>,
    pub generator_t1: PairingOutput<E>,
}

impl<E: Pairing> AggregateKey<E> {
    pub fn new(
        pk: Vec<PublicKey<E>>,
        params: &PowersOfTau<E>,
        generator_t1: PairingOutput<E>,
    ) -> Self {
        let n = params.powers_of_g.len();
        let h_minus1 = -params.powers_of_h[0].into_group();
        let mut ask = E::G1::zero();
        let mut aggregate = vec![E::G1::zero(); n];
        for key in &pk {
            ask += key.sk_li;
            for (sum, value) in aggregate.iter_mut().zip(&key.sk_li_lj_z) {
                *sum += value;
            }
        }
        let mut key_indices = vec![None; n];
        for (position, key) in pk.iter().enumerate() {
            key_indices[key.id] = Some(position);
        }
        Self {
            pk,
            key_indices,
            agg_sk_li_lj_z: aggregate,
            ask,
            z_g2: params.powers_of_h[n] + h_minus1,
            h_minus1,
            e_gh: E::pairing(params.powers_of_g[0], params.powers_of_h[0]),
            generator_t1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    fn local_batched_basis_matches_public_crs_derivation() {
        let mut rng = test_rng();
        for n in [2, 4, 8, 16] {
            let tau = loop {
                let x = Fr::rand(&mut rng);
                if !x.is_zero() && x.pow([n as u64]) != Fr::one() {
                    break x;
                }
            };
            let local = LagrangePowers::<Bls12_381>::new(tau, n);
            let mut crs = KZG10::<Bls12_381, DensePolynomial<Fr>>::setup(n, tau).unwrap();
            crs.powers_of_g.truncate(n);
            let public = LagrangePowers::<Bls12_381>::from_crs(&crs).unwrap();
            let mut local_bytes = Vec::new();
            let mut public_bytes = Vec::new();
            local.serialize_compressed(&mut local_bytes).unwrap();
            public.serialize_compressed(&mut public_bytes).unwrap();
            assert_eq!(local_bytes, public_bytes, "domain size {n}");
        }
    }
}
