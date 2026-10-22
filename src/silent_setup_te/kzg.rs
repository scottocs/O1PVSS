//adapted from https://github.com/arkworks-rs/poly-commit/blob/master/src/kzg10/mod.rs
use ark_ec::{pairing::Pairing, CurveGroup, PrimeGroup};
use ark_ec::{scalar_mul::ScalarMul, VariableBaseMSM};
use ark_ff::{One, PrimeField};
use ark_poly::DenseUVPolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::marker::PhantomData;

pub struct KZG10<E: Pairing, P: DenseUVPolynomial<E::ScalarField>> {
    _engine: PhantomData<E>,
    _poly: PhantomData<P>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PowersOfTau<E: Pairing> {
    /// Group elements of the form `{ \tau^i G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_g: Vec<E::G1Affine>,
    /// Group elements of the form `{ \tau^i H }`, where `i` ranges from 0 to `degree`.
    pub powers_of_h: Vec<E::G2Affine>,
}

#[derive(Debug)]
pub enum Error {
    /// The degree provided in setup was too small; degree 0 polynomials
    /// are not supported.
    DegreeIsZero,

    /// The commitment polynomial exceeds the available CRS powers.
    TooManyCoefficients {
        /// The number of coefficients in the polynomial.
        num_coefficients: usize,
        /// The maximum number of powers provided in `Powers`.
        num_powers: usize,
    },
}

impl<E, P> KZG10<E, P>
where
    E: Pairing,
    P: DenseUVPolynomial<E::ScalarField, Point = E::ScalarField>,
{
    pub fn setup(max_degree: usize, tau: E::ScalarField) -> Result<PowersOfTau<E>, Error> {
        if max_degree < 1 {
            return Err(Error::DegreeIsZero);
        }

        let g = E::G1::generator();
        let h = E::G2::generator();

        let mut powers_of_tau = vec![E::ScalarField::one()];

        let mut cur = tau;
        for _ in 0..max_degree {
            powers_of_tau.push(cur);
            cur *= &tau;
        }

        let powers_of_g = g.batch_mul(&powers_of_tau[0..max_degree + 1]);
        let powers_of_h = h.batch_mul(&powers_of_tau[0..max_degree + 1]);

        let pp = PowersOfTau {
            powers_of_g,
            powers_of_h,
        };

        Ok(pp)
    }

    pub fn commit_g1(params: &PowersOfTau<E>, polynomial: &P) -> Result<E::G1Affine, Error> {
        let d = polynomial.degree();
        check_degree_is_too_large(d, params.powers_of_g.len())?;

        let plain_coeffs = convert_to_bigints(polynomial.coeffs());

        let commitment =
            <E::G1 as VariableBaseMSM>::msm_bigint(&params.powers_of_g[..=d], &plain_coeffs);
        Ok(commitment.into_affine())
    }

    pub fn commit_g2(params: &PowersOfTau<E>, polynomial: &P) -> Result<E::G2Affine, Error> {
        let d = polynomial.degree();
        check_degree_is_too_large(d, params.powers_of_h.len())?;

        let plain_coeffs = convert_to_bigints(polynomial.coeffs());

        let commitment =
            <E::G2 as VariableBaseMSM>::msm_bigint(&params.powers_of_h[..=d], &plain_coeffs);

        Ok(commitment.into_affine())
    }
}

fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    p.iter().map(|s| s.into_bigint()).collect::<Vec<_>>()
}

fn check_degree_is_too_large(degree: usize, num_powers: usize) -> Result<(), Error> {
    let num_coefficients = degree + 1;
    if num_coefficients > num_powers {
        Err(Error::TooManyCoefficients {
            num_coefficients,
            num_powers,
        })
    } else {
        Ok(())
    }
}
