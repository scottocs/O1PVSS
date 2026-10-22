# O1PVSS

Rust implementations and benchmarks for *Constant-Online PVSS from Threshold
Encryption: A Generic Framework*.

## Implementations

| Module under `src/pvss/` | Construction |
| --- | --- |
| `elgamal_pvss` | Instantiation I: pairing-free threshold ElGamal |
| `silent_setup_pvss` | Instantiation II: threshold encryption with silent setup |
| `adaptive_elgamal_pvss` | Split-key adaptive variant under ideal setup |
| `dhpvss`, `illusi` | Main comparison baselines |
| `albatross`, `preconstructed_pvss` | Additional comparison baselines |

The crate is imported as `o1pvss`. Baseline sources and implementation scope are
listed in [BASELINES.md](src/pvss/BASELINES.md).

## Build and test

Use a stable Rust toolchain:

```sh
cargo build --release --bins
cargo test --release
```

## Benchmarks

```sh
# Four manuscript schemes with 8 and 16 real shareholders.
cargo run --release --bin pvss_benchmark -- 8 16 --csv results.csv

# Full experiment: 4, 8, 16, 32, 64, 128, 256 and 512 real shareholders.
cargo run --release --bin pvss_benchmark -- --full --csv results.csv

# Select comparison schemes.
cargo run --release --bin pvss_benchmark -- 8 --schemes albatross,ppvss

# Physical BLS12-381 operation costs.
cargo run --release --bin group_benchmark
```

`--csv` also saves per-batch measurements. Setup and reusable public preprocessing
are excluded from online timers. See [benchmarks](benchmarks/README.md) for the
measurement policy, supplied datasets and validation commands. The full
silent-setup experiment requires substantially more setup work than small runs.

## API and security assumptions

For the two main constructions, accept `verify_setup` before using public
parameters, accept each sharing with `verify`, generate reconstruction shares
with `pre_recon`, verify each share with `dec_vrf`, and then call `reconstruct`.
`pre_recon` does not repeat sharing verification. Supply a cryptographically
secure RNG; deterministic test RNGs are used only in tests and benchmarks.

Instantiation I uses party IDs `0..n`. Instantiation II uses real slots `1..slots`
with slot `0` reserved for a public dummy; the dummy does not count toward the
threshold. Its domain capacity must be a power of two. Use
`setup_with_capacity` to specify capacity separately from the real-party count.
Its dedicated CRS has `slots` G1 powers and `slots + 1` G2 powers; a prefix of a
larger CRS under the same trapdoor is outside the setup model.

The main constructions provide post-setup static privacy under their stated
setup and cryptographic assumptions. Setup routines are local simulators;
authenticated delivery, complaint resolution and secure erasure require a
distributed implementation. The adaptive variant assumes ideal setup. Epoch
reconfiguration requires new setup audits and does not establish security
against mobile corruption. This repository is research software.
