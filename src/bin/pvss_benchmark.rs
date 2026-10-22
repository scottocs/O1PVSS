use o1pvss::pvss::benchmarks::{
    benchmark_albatross, benchmark_dhpvss, benchmark_elgamal_pvss, benchmark_illusi,
    benchmark_preconstructed_pvss, benchmark_results_csv, benchmark_silent_setup_pvss, BENCH_SIZES,
};

fn main() {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn pthread_set_qos_class_self_np(class: u32, relative: i32) -> i32;
        }
        assert_eq!(
            unsafe { pthread_set_qos_class_self_np(0x19, 0) },
            0,
            "benchmark QoS"
        );
    }
    let mut sizes = Vec::new();
    let mut schemes = String::from("elgamal,silent,dhpvss,illusi");
    let mut csv: Option<String> = None;
    let mut samples = None;
    let mut packed = 8usize;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--full" => sizes = BENCH_SIZES.to_vec(),
            "--comparison" => schemes = "elgamal,dhpvss,illusi".into(),
            "--schemes" => {
                schemes = args
                    .next()
                    .expect("--schemes requires a comma-separated list")
            }
            "--csv" => csv = Some(args.next().expect("--csv requires a path")),
            "--samples" => samples = Some(args.next().expect("--samples requires a path")),
            "--batch-secrets" => {
                packed = args
                    .next()
                    .expect("batch size")
                    .parse()
                    .expect("positive batch size")
            }
            "--help" | "-h" => {
                println!(
                    "Usage: pvss_benchmark [n ... | --full] [OPTIONS]\n\n\
                     --schemes LIST     elgamal,silent,dhpvss,illusi (default); also albatross,ppvss,albatross-packed\n\
                     --comparison       Run elgamal,dhpvss,illusi\n\
                     --batch-secrets N  Packed ALBATROSS batch size (default: 8)\n\
                     --csv PATH         Save results and checkpoint completed cases\n\
                     --samples PATH     Save per-batch measurements (default: CSV path with .samples.csv extension)\n\n\
                     Default shareholder count: 8. --full uses 4,8,16,32,64,128,256,512.\n\
                     Online means use 10 warm-cache batches after three warm-up calls.\n\
                     Packed ALBATROSS preserves the privacy bound by increasing the recovery threshold."
                );
                return;
            }
            _ => sizes.push(
                arg.parse::<usize>()
                    .expect("unknown option/invalid real-party count; see --help"),
            ),
        }
    }
    if samples.is_none() {
        samples = csv.as_ref().map(|path| {
            std::path::Path::new(path)
                .with_extension("samples.csv")
                .to_string_lossy()
                .into_owned()
        });
    }
    if let Some(path) = samples {
        std::fs::write(
            &path,
            "scheme,real_parties,operation,batch,calls,parties_per_call,mean_ms\n",
        )
        .expect("sample log header");
        std::env::set_var("PVSS_BENCH_SAMPLES", path);
    }
    if sizes.is_empty() {
        sizes.push(8);
    }
    let mut results = Vec::new();
    for n in sizes {
        assert!(n >= 3, "at least three real parties required");
        let t = n / 2 + 1;
        for scheme in schemes.split(',') {
            eprintln!("benchmark: n={n}, scheme={scheme}");
            let row = match scheme {
                "elgamal" => benchmark_elgamal_pvss(n, t),
                "silent" => benchmark_silent_setup_pvss(n, t),
                "dhpvss" => benchmark_dhpvss(n, t),
                "albatross" => benchmark_albatross(n, t, 1),
                "illusi" => benchmark_illusi(n, t),
                "ppvss" => benchmark_preconstructed_pvss(n, t),
                "albatross-packed" => {
                    assert!(
                        packed > 0 && packed <= n - t + 1,
                        "batch must fit while preserving privacy bound"
                    );
                    benchmark_albatross(n, t + packed - 1, packed)
                }
                _ => panic!("unknown scheme: {scheme}"),
            };
            eprintln!(
                "completed: n={n}, scheme={scheme}, public_cache={:?}",
                o1pvss::cache::public_cache_stats()
            );
            results.push(row);
            // Checkpoint only completed measurements, even on interrupted runs.
            if let Some(path) = &csv {
                std::fs::write(path, benchmark_results_csv(&results)).expect("write CSV");
            }
        }
    }
    print!("{}", benchmark_results_csv(&results));
}
