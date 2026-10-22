# Benchmarks

Run from the repository root:

```sh
cargo run --release --bin pvss_benchmark -- 8 16 --csv /tmp/o1pvss.csv
cargo run --release --bin pvss_benchmark -- --full --schemes elgamal,silent,dhpvss,illusi,albatross,ppvss --csv /tmp/o1pvss-full.csv
cargo run --release --bin group_benchmark > /tmp/o1pvss-groups.csv 2> /tmp/o1pvss-groups.samples.csv
python3 benchmarks/validate.py
```

Use `pvss_benchmark --help` for scheme selection, packed ALBATROSS and output
options. Fresh benchmark output should be written separately from `results/`.
The group benchmark's sample stream has columns `operation,batch,mean_ms`
without a header; the supplied `results/group-costs.samples.csv` includes one.

## Measurement policy

- BLS12-381, single-threaded release mode; macOS runs request user-initiated QoS.
- Real-party counts: 4 through 512 in powers of two; threshold: `floor(n/2) + 1`.
  The ElGamal setup uses 64 contributors. Silent setup uses a power-of-two
  capacity exceeding the real-party count and the transposed pairing engine
  (`OnlineBls12_381`), with logical G1/G2 mapped to physical G2/G1.
- Each PVSS operation uses three warm-up calls and ten calibrated batches.
  Calibration targets 20 ms per batch, with 5–128 calls for ordinary operations
  and 1–128 calls for threshold workloads. PreRecon and DecVrf are per shareholder.
- Online timings exclude setup, setup auditing and deterministic public
  preprocessing. Only public evaluation grids, interpolation plans, CRS bases
  and arithmetic tables are cached. Fresh ciphertexts, proofs and shares are
  processed online; reconstruction outputs are checked.
- Online total is Share + Verify + t × (PreRecon + DecVrf) + Recon.
  PPVSS optimistic opening is reported separately. Packed ALBATROSS increases
  the threshold by `ell - 1` to preserve the single-secret privacy bound;
  amortized cost divides the full online total by `ell`.
- Group-operation timings use 32 warm-ups and ten batches of 256 calls.
  Scalar sampling, fixed-base tables and prepared pairing inputs are outside
  the corresponding timed operations. Pairing timings include final exponentiation.

## Supplied data

| File under `results/` | Contents |
| --- | --- |
| `comparison.csv`, `comparison.samples.csv` | Four manuscript schemes: 32 cases, 1,600 batch means |
| `supplementary.csv`, `supplementary.samples.csv` | Single-secret ALBATROSS and PPVSS: 16 cases, 880 batch means |
| `group-costs.csv`, `group-costs.samples.csv` | Eight physical group operations and 80 batch means |
| `payloads.csv` | Sharing and per-party reconstruction payloads in bytes |
| `metadata.json` | Measurement environment, policy and dataset checksums |

`validate.py` checks dataset integrity, thresholds and capacities, complete
batch coverage, reported averages, online totals and communication formulas.
Timing data is preserved without filtering, fitting or interpolation. It does
not require the manuscript or LaTeX.
