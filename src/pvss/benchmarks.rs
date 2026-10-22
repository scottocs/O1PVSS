//! Benchmarks for the current construction. Each PreRecon timer excludes DecVrf.
use crate::{
    pvss::{
        albatross::Albatross, dhpvss::DHPVSS, elgamal_pvss::ElGamalPVSS,
        preconstructed_pvss::PreconstructedPVSS, silent_setup_pvss::SilentSetupPVSS,
    },
    utils::precompute_lagrange_coefficients,
};
use ark_bls12_381::{Fr, G1Projective};
use ark_std::{test_rng, UniformRand};
use std::{hint::black_box, time::Instant};

type E = crate::transposed_pairing::OnlineBls12_381;
type G = G1Projective;
const DKG_COMMITTEE_SIZE: usize = 64;
const BENCH_REPETITIONS: usize = 10;
pub const BENCH_SIZES: [usize; 8] = [4, 8, 16, 32, 64, 128, 256, 512];

/// Bacho--Chen--Loss 2026, Illusi (pairing-free DDH), source Section 4.2.
pub fn benchmark_illusi(n: usize, threshold: usize) -> PVSSBenchmarkResults {
    use crate::pvss::illusi::Illusi;
    let mut rng = test_rng();
    let mut r = PVSSBenchmarkResults::new("Illusi".into(), n, threshold);
    let start = Instant::now();
    let (pp, keys) = Illusi::setup::<G, _>(n, threshold, &mut rng).unwrap();
    r.setup_ms = elapsed_ms(start);
    let secret = Fr::rand(&mut rng);
    let (sharing, ms) = measure(
        "Share",
        1,
        || Illusi::share(black_box(secret), &pp, &mut rng),
        |_| {},
    );
    r.share_ms = ms;
    let (verified, ms) = measure(
        "Verify",
        1,
        || Illusi::verify(black_box(&sharing), &pp, &mut rng).unwrap(),
        |_| {},
    );
    r.verify_ms = ms;
    let (shares, ms) = measure(
        "PreRecon",
        threshold,
        || {
            keys.iter()
                .take(threshold)
                .map(|key| verified.pre_recon(key, &mut rng).unwrap())
                .collect::<Vec<_>>()
        },
        |_| {},
    );
    r.pre_recon_ms = ms;
    let (_, ms) = measure(
        "DecVrf",
        threshold,
        || shares.iter().all(|s| verified.dec_vrf(black_box(s))),
        |ok| assert!(*ok),
    );
    r.dec_vrf_ms = ms;
    let values: Vec<_> = shares.iter().map(|s| (s.id, s.value)).collect();
    let start = Instant::now();
    let plan = pp
        .prepare_reconstruction(&values.iter().map(|s| s.0).collect::<Vec<_>>())
        .unwrap();
    r.lagrange_precompute_ms = elapsed_ms(start);
    let expected = pp.encode(secret);
    let (_, ms) = measure(
        "Recon",
        1,
        || verified.reconstruct(black_box(&values), &plan).unwrap(),
        |out| assert_eq!(*out, expected),
    );
    r.recon_ms = ms;
    r.calculate_total();
    r
}

#[derive(Debug, Clone)]
pub struct PVSSBenchmarkResults {
    pub scheme_name: String,
    /// Number of real shareholders, consistently across the full schemes.
    pub n: usize,
    /// Silent setup domain capacity including dummy; n for the other schemes.
    pub domain_slots: usize,
    pub threshold: usize,
    pub batch_secrets: usize,
    pub privacy_threshold: usize,
    /// PPVSS dealer opening, including validation and encoding; not in total_ms.
    pub optimistic_open_ms: Option<f64>,
    pub setup_ms: f64,
    pub lagrange_precompute_ms: f64,
    /// None means setup audit was not benchmarked.
    pub verify_setup_ms: Option<f64>,
    pub share_ms: f64,
    pub verify_ms: f64,
    pub pre_recon_ms: f64,
    pub dec_vrf_ms: f64,
    pub recon_ms: f64,
    /// Online cost of one sharing and reconstruction with t shareholders.
    pub total_ms: f64,
}
impl PVSSBenchmarkResults {
    pub fn new(scheme_name: String, n: usize, threshold: usize) -> Self {
        CASE.with(|case| *case.borrow_mut() = (scheme_name.clone(), n));
        Self {
            scheme_name,
            n,
            domain_slots: n,
            threshold,
            batch_secrets: 1,
            privacy_threshold: threshold.saturating_sub(1),
            optimistic_open_ms: None,
            setup_ms: 0.0,
            lagrange_precompute_ms: 0.0,
            verify_setup_ms: None,
            share_ms: 0.0,
            verify_ms: 0.0,
            pre_recon_ms: 0.0,
            dec_vrf_ms: 0.0,
            recon_ms: 0.0,
            total_ms: 0.0,
        }
    }
    pub fn calculate_total(&mut self) {
        self.total_ms = self.share_ms
            + self.verify_ms
            + self.threshold as f64 * (self.pre_recon_ms + self.dec_vrf_ms)
            + self.recon_ms;
    }
}
fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

// All schemes share the same warm-cache timing policy. Every batch includes
// fresh algorithm invocations; only deterministic public preprocessing is reused.
fn measure<T>(
    operation: &str,
    parties_per_call: usize,
    mut run: impl FnMut() -> T,
    mut check: impl FnMut(&T),
) -> (T, f64) {
    let mut last = None;
    let mut estimate = 0.0_f64;
    for _ in 0..3 {
        let start = Instant::now();
        let value = black_box(run());
        estimate = elapsed_ms(start);
        check(&value);
        last = Some(value);
    }
    let minimum = if parties_per_call > 1 { 1 } else { 5 };
    let target = if cfg!(test) { 0.0 } else { 20.0 };
    let calls = ((target / estimate.max(0.001)).ceil() as usize).clamp(minimum, 128);
    let mut means = Vec::with_capacity(BENCH_REPETITIONS);
    for batch in 0..BENCH_REPETITIONS {
        let mut sum = 0.0;
        for _ in 0..calls {
            let start = Instant::now();
            let value = black_box(run());
            sum += elapsed_ms(start);
            check(&value);
            last = Some(value);
        }
        let mean = sum / (calls * parties_per_call) as f64;
        means.push(mean);
        record_batch(operation, batch, calls, parties_per_call, mean);
    }
    (
        last.unwrap(),
        means.iter().sum::<f64>() / means.len() as f64,
    )
}
thread_local! {
    static CASE: std::cell::RefCell<(String,usize)> = const { std::cell::RefCell::new((String::new(),0)) };
}
fn record_batch(operation: &str, batch: usize, calls: usize, parties: usize, mean: f64) {
    let Ok(path) = std::env::var("PVSS_BENCH_SAMPLES") else {
        return;
    };
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("raw batch log");
    CASE.with(|case| {
        let (scheme, n) = case.borrow().clone();
        writeln!(
            file,
            "{scheme},{n},{operation},{batch},{calls},{parties},{mean:.9}"
        )
        .unwrap();
    });
}
fn prepare_integer_interpolation(n: usize, ids: &[usize]) -> f64 {
    let points = crate::cache::evaluation_points::<Fr>(n, 1);
    let xs: Vec<_> = ids.iter().map(|id| points[*id]).collect();
    let start = Instant::now();
    crate::cache::interpolation_weights(&xs, &[Fr::from(0u64)]).unwrap();
    elapsed_ms(start)
}

/// `threshold` shares recover the whole batch; privacy bound is threshold-ell.
pub fn benchmark_albatross(
    n: usize,
    threshold: usize,
    batch_secrets: usize,
) -> PVSSBenchmarkResults {
    benchmark_polynomial_pvss(n, threshold, batch_secrets, false)
}
pub fn benchmark_preconstructed_pvss(n: usize, threshold: usize) -> PVSSBenchmarkResults {
    benchmark_polynomial_pvss(n, threshold, 1, true)
}
fn benchmark_polynomial_pvss(
    n: usize,
    threshold: usize,
    batch_secrets: usize,
    ppvss: bool,
) -> PVSSBenchmarkResults {
    let mut rng = test_rng();
    let name = if ppvss {
        "PPVSS RO".to_owned()
    } else {
        format!("ALBATROSS ell={batch_secrets}")
    };
    let mut r = PVSSBenchmarkResults::new(name, n, threshold);
    r.batch_secrets = batch_secrets;
    r.privacy_threshold = threshold - batch_secrets;
    let start = Instant::now();
    let (pp, keys) = if ppvss {
        PreconstructedPVSS::setup::<G, _>(n, threshold, 0, &mut rng).unwrap()
    } else {
        Albatross::setup::<G, _>(n, threshold, batch_secrets, 0, &mut rng).unwrap()
    };
    r.setup_ms = elapsed_ms(start);
    let secrets: Vec<_> = (0..batch_secrets).map(|_| Fr::rand(&mut rng)).collect();
    let anchor = if ppvss {
        Some(PreconstructedPVSS::preconstruct(secrets[0], &pp).unwrap())
    } else {
        None
    };
    let (sharing, ms) = measure(
        "Share",
        1,
        || {
            if let Some(anchor) = anchor {
                PreconstructedPVSS::share(black_box(secrets[0]), anchor, &pp, &mut rng).unwrap()
            } else {
                Albatross::share(black_box(&secrets), &pp, &mut rng).unwrap()
            }
        },
        |_| {},
    );
    r.share_ms = ms;
    let (verified, ms) = measure(
        "Verify",
        1,
        || {
            if let Some(anchor) = anchor {
                PreconstructedPVSS::verify(black_box(&sharing), anchor, &pp).unwrap()
            } else {
                Albatross::verify(black_box(&sharing), &pp).unwrap()
            }
        },
        |_| {},
    );
    r.verify_ms = ms;
    let (shares, ms) = measure(
        "PreRecon",
        threshold,
        || {
            keys.iter()
                .take(threshold)
                .map(|key| verified.pre_recon(key, &mut rng).unwrap())
                .collect::<Vec<_>>()
        },
        |_| {},
    );
    r.pre_recon_ms = ms;
    let (_, ms) = measure(
        "DecVrf",
        threshold,
        || {
            shares
                .iter()
                .all(|share| verified.dec_vrf(black_box(share)))
        },
        |ok| assert!(*ok),
    );
    r.dec_vrf_ms = ms;
    let values: Vec<_> = shares.iter().map(|share| (share.id, share.value)).collect();
    let start = Instant::now();
    let plan = pp
        .prepare_reconstruction(&values.iter().map(|s| s.0).collect::<Vec<_>>())
        .unwrap();
    r.lagrange_precompute_ms = elapsed_ms(start);
    let expected: Vec<_> = secrets.iter().map(|s| pp.generator() * s).collect();
    let (_, ms) = measure(
        "Recon",
        1,
        || verified.reconstruct(black_box(&values), &plan).unwrap(),
        |out| assert_eq!(*out, expected),
    );
    r.recon_ms = ms;
    if let Some(anchor) = anchor {
        let (_, ms) = measure(
            "OptimisticOpen",
            1,
            || PreconstructedPVSS::optimistic_open(black_box(secrets[0]), anchor, &pp).unwrap(),
            |out| assert_eq!(*out, expected[0]),
        );
        r.optimistic_open_ms = Some(ms);
    }
    r.calculate_total();
    r
}

pub fn benchmark_elgamal_pvss(n: usize, threshold: usize) -> PVSSBenchmarkResults {
    let mut rng = test_rng();
    let mut r = PVSSBenchmarkResults::new("ElGamal PVSS".into(), n, threshold);
    let start = Instant::now();
    let (points, coefficients) = precompute_lagrange_coefficients::<Fr>(n);
    r.lagrange_precompute_ms = elapsed_ms(start);
    let start = Instant::now();
    let (pp, keys) = ElGamalPVSS::<G>::setup_with_committee_size(
        128,
        threshold,
        n,
        DKG_COMMITTEE_SIZE,
        points,
        coefficients,
        &mut rng,
    )
    .unwrap();
    r.setup_ms = elapsed_ms(start);
    let secret = Fr::rand(&mut rng);
    let ((ct, proof), ms) = measure(
        "Share",
        1,
        || ElGamalPVSS::<G>::share(black_box(secret), &pp, &mut rng).unwrap(),
        |_| {},
    );
    r.share_ms = ms;
    let (verified, ms) = measure(
        "Verify",
        1,
        || ElGamalPVSS::<G>::verify_sharing(black_box(&ct), &proof, &pp).unwrap(),
        |_| {},
    );
    r.verify_ms = ms;
    let (shares, ms) = measure(
        "PreRecon",
        threshold,
        || {
            keys.iter()
                .take(threshold)
                .map(|(sk, _)| {
                    let (d, pi) = verified.pre_recon(sk, &mut rng).unwrap();
                    (sk.id, d, pi)
                })
                .collect::<Vec<_>>()
        },
        |_| {},
    );
    r.pre_recon_ms = ms;
    let (_, ms) = measure(
        "DecVrf",
        threshold,
        || {
            shares
                .iter()
                .zip(&keys)
                .all(|((_, d, pi), (_, pk))| verified.dec_vrf(*d, pi, pk))
        },
        |ok| assert!(*ok),
    );
    r.dec_vrf_ms = ms;
    let values: Vec<_> = shares.iter().map(|(id, d, _)| (*id, *d)).collect();
    r.lagrange_precompute_ms +=
        prepare_integer_interpolation(n, &values.iter().map(|s| s.0).collect::<Vec<_>>());
    let (_, ms) = measure(
        "Recon",
        1,
        || verified.reconstruct(black_box(&values)).unwrap(),
        |out| assert_eq!(*out, pp.generator * secret),
    );
    r.recon_ms = ms;
    r.calculate_total();
    r
}

pub fn benchmark_silent_setup_pvss(n: usize, threshold: usize) -> PVSSBenchmarkResults {
    let mut rng = test_rng();
    let mut r = PVSSBenchmarkResults::new("Silent Setup PVSS".into(), n, threshold);
    let slots = (n + 1).next_power_of_two();
    r.domain_slots = slots;
    let start = Instant::now();
    let (pp, keys) =
        SilentSetupPVSS::<E>::setup_with_capacity(128, threshold, slots, n, &mut rng).unwrap();
    r.setup_ms = elapsed_ms(start);
    let secret = Fr::rand(&mut rng);
    let ((ct, proof), ms) = measure(
        "Share",
        1,
        || SilentSetupPVSS::<E>::share(black_box(secret), &pp, &mut rng).unwrap(),
        |_| {},
    );
    r.share_ms = ms;
    let (verified, ms) = measure(
        "Verify",
        1,
        || SilentSetupPVSS::<E>::verify_sharing(black_box(&ct), &proof, &pp).unwrap(),
        |_| {},
    );
    r.verify_ms = ms;
    let (shares, ms) = measure(
        "PreRecon",
        threshold,
        || {
            keys.iter()
                .take(threshold)
                .map(|(sk, _)| {
                    let (d, pi) = verified.pre_recon(sk, &mut rng).unwrap();
                    (sk.id, d, pi)
                })
                .collect::<Vec<_>>()
        },
        |_| {},
    );
    r.pre_recon_ms = ms;
    let (_, ms) = measure(
        "DecVrf",
        threshold,
        || {
            shares
                .iter()
                .zip(&keys)
                .all(|((_, d, pi), (_, pk))| verified.dec_vrf(*d, pi, pk))
        },
        |ok| assert!(*ok),
    );
    r.dec_vrf_ms = ms;
    let values: Vec<_> = shares.iter().map(|(id, d, _)| (*id, *d)).collect();
    let start = Instant::now();
    crate::silent_setup_te::decryption::prepare_reconstruction(
        &values.iter().map(|s| s.0).collect::<Vec<_>>(),
        threshold,
        &pp.aggregate_key,
        &pp.powers_of_tau,
        &pp.setup_digest,
    )
    .unwrap();
    r.lagrange_precompute_ms = elapsed_ms(start);
    let (_, ms) = measure(
        "Recon",
        1,
        || verified.reconstruct(black_box(&values)).unwrap(),
        |out| assert_eq!(*out, pp.generator_t1 * secret),
    );
    r.recon_ms = ms;
    r.calculate_total();
    r
}

pub fn benchmark_dhpvss(n: usize, threshold: usize) -> PVSSBenchmarkResults {
    let mut rng = test_rng();
    let mut r = PVSSBenchmarkResults::new("DHPVSS".into(), n, threshold);
    let start = Instant::now();
    let (_, coefficients) = precompute_lagrange_coefficients::<Fr>(n);
    r.lagrange_precompute_ms = elapsed_ms(start);
    let start = Instant::now();
    let pp = DHPVSS::<G>::setup(128, threshold - 1, n, coefficients, &mut rng).unwrap();
    r.setup_ms = elapsed_ms(start);
    let distributor = DHPVSS::<G>::d_key_gen(&pp, &mut rng);
    let keys: Vec<_> = (0..n)
        .map(|i| DHPVSS::<G>::key_gen(&pp, i, &mut rng))
        .collect();
    let start = Instant::now();
    for (i, key) in keys.iter().enumerate() {
        assert!(DHPVSS::<G>::verify_key(&pp, i, &key.pk));
    }
    r.verify_setup_ms = Some(elapsed_ms(start));
    let secret = pp.generator * Fr::rand(&mut rng);
    let (sharing, ms) = measure(
        "Share",
        1,
        || {
            DHPVSS::<G>::dist(
                &pp,
                &distributor.pk_d,
                &distributor.sk_d,
                &keys,
                black_box(secret),
                &mut rng,
            )
            .unwrap()
        },
        |_| {},
    );
    r.share_ms = ms;
    let (verified, ms) = measure(
        "Verify",
        1,
        || DHPVSS::<G>::verify_sharing(&pp, &distributor.pk_d, &keys, black_box(&sharing)).unwrap(),
        |_| {},
    );
    r.verify_ms = ms;
    let (shares, ms) = measure(
        "PreRecon",
        threshold,
        || {
            (0..threshold)
                .map(|i| {
                    let (d, pi) = verified.pre_recon(i, &keys[i], &mut rng).unwrap();
                    (i, d, pi)
                })
                .collect::<Vec<_>>()
        },
        |_| {},
    );
    r.pre_recon_ms = ms;
    let (_, ms) = measure(
        "DecVrf",
        threshold,
        || {
            shares
                .iter()
                .all(|(id, d, pi)| verified.dec_vrf(*id, d, pi))
        },
        |ok| assert!(*ok),
    );
    r.dec_vrf_ms = ms;
    let values: Vec<_> = shares.iter().map(|(id, d, _)| (*id, *d)).collect();
    r.lagrange_precompute_ms +=
        prepare_integer_interpolation(n, &values.iter().map(|s| s.0).collect::<Vec<_>>());
    let (_, ms) = measure(
        "Recon",
        1,
        || DHPVSS::<G>::reconstruct(&pp, black_box(&values)),
        |out| assert_eq!(*out, secret),
    );
    r.recon_ms = ms;
    r.calculate_total();
    r
}

pub fn benchmark_results_csv(results: &[PVSSBenchmarkResults]) -> String {
    use std::fmt::Write;
    let mut output = String::from("scheme,real_parties,domain_slots,t,privacy_threshold,batch_secrets,Share_ms,Verify_ms,PreRecon_ms,DecVrf_ms,Recon_ms,online_total_ms,amortized_online_ms,optimistic_open_ms,setup_fixture_ms,interpolation_precompute_ms\n");
    for r in results {
        writeln!(
            output,
            "{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{:.6},{:.6}",
            r.scheme_name,
            r.n,
            r.domain_slots,
            r.threshold,
            r.privacy_threshold,
            r.batch_secrets,
            r.share_ms,
            r.verify_ms,
            r.pre_recon_ms,
            r.dec_vrf_ms,
            r.recon_ms,
            r.total_ms,
            r.total_ms / r.batch_secrets as f64,
            r.optimistic_open_ms
                .map(|v| format!("{v:.6}"))
                .unwrap_or_default(),
            r.setup_ms,
            r.lagrange_precompute_ms
        )
        .unwrap();
    }
    output
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_benchmark_small_scale() {
        let results = [
            benchmark_elgamal_pvss(8, 4),
            benchmark_silent_setup_pvss(8, 4),
            benchmark_dhpvss(8, 4),
            benchmark_albatross(8, 4, 1),
            benchmark_preconstructed_pvss(8, 4),
            benchmark_albatross(8, 6, 3),
            benchmark_illusi(8, 4),
        ];
        assert_eq!(results[1].n, 8);
        assert_eq!(results[1].domain_slots, 16);
        for r in &results {
            assert!(r.total_ms > 0.0);
        }
    }
}
