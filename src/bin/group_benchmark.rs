//! Physical BLS12-381 operation costs; preprocessing and validation excluded.
use ark_bls12_381::{Bls12_381 as E, Fr, G1Projective, G2Projective};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    scalar_mul::{BatchMulPreprocessing, ScalarMul},
};
use ark_std::{test_rng, UniformRand};
use std::{hint::black_box, time::Instant};

fn measure<T>(name: &str, mut run: impl FnMut(usize) -> T) {
    for i in 0..32 {
        black_box(run(i));
    }
    let mut means = Vec::new();
    for batch in 0..10 {
        let start = Instant::now();
        for i in 0..256 {
            black_box(run(i));
        }
        let ms = start.elapsed().as_secs_f64() * 1000.0 / 256.0;
        eprintln!("{name},{batch},{ms:.9}");
        means.push(ms);
    }
    println!(
        "{name},{:.9}",
        means.iter().sum::<f64>() / means.len() as f64
    );
}
fn exponents<G: ScalarMul>(name: &str, bases: &[G], scalars: &[G::ScalarField]) {
    measure(&format!("{name}_variable"), |i| {
        black_box(bases[i]) * black_box(scalars[i])
    });
    let table = BatchMulPreprocessing::new(bases[0], 128);
    measure(&format!("{name}_fixed"), |i| {
        G::from(table.batch_mul(&[black_box(scalars[i])])[0])
    });
}
fn main() {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn pthread_set_qos_class_self_np(class: u32, relative: i32) -> i32;
        }
        assert_eq!(unsafe { pthread_set_qos_class_self_np(0x19, 0) }, 0);
    }
    let mut rng = test_rng();
    let g1: Vec<_> = (0..256).map(|_| G1Projective::rand(&mut rng)).collect();
    let g2: Vec<_> = (0..256).map(|_| G2Projective::rand(&mut rng)).collect();
    let gt: Vec<_> = (0..256)
        .map(|_| PairingOutput::<E>::rand(&mut rng))
        .collect();
    let s: Vec<_> = (0..256).map(|_| Fr::rand(&mut rng)).collect();
    println!("operation,mean_ms");
    exponents("E1", &g1, &s);
    exponents("E2", &g2, &s);
    exponents("ET", &gt, &s);
    measure("P", |i| E::pairing(black_box(g1[i]), black_box(g2[i])));
    let a: Vec<_> = g1
        .iter()
        .map(|p| <E as Pairing>::G1Prepared::from(*p))
        .collect();
    let b: Vec<_> = g2
        .iter()
        .map(|p| <E as Pairing>::G2Prepared::from(*p))
        .collect();
    measure("P_prepared", |i| {
        E::pairing(black_box(a[i].clone()), black_box(b[i].clone()))
    });
}
