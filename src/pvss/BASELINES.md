# Comparison baselines

These modules independently implement the cited algorithms using arkworks and
Merlin transcripts. Group arithmetic uses physical BLS12-381 G1. They implement
PVSS algorithms, without bulletin-board networking or PKI.

| Module | Source | Scope |
| --- | --- | --- |
| `dhpvss.rs` | Cascudo et al., *YOLO YOSO*, ASIACRYPT 2022, [ePrint 2022/242](https://eprint.iacr.org/2022/242) | DHPVSS distribution and reconstruction |
| `illusi.rs` | Bacho, Chen and Loss, *Adaptively Secure (Aggregatable) PVSS from Standard Assumptions*, CRYPTO 2026, [DOI](https://doi.org/10.1007/978-3-032-35374-0_6) | Pairing-free DDH construction, Section 4.2, equations (1) and (2) |
| `albatross.rs` | Cascudo and David, *ALBATROSS*, ASIACRYPT 2020, [ePrint 2020/644](https://eprint.iacr.org/2020/644) | Packed PVSS core, LDEI and LocalLDEI checks, DLEQ decryption proofs |
| `preconstructed_pvss.rs` | Baghery et al., *Pre-constructed Publicly Verifiable Secret Sharing and Applications*, ACNS 2025, [ePrint 2025/576](https://eprint.iacr.org/2025/576) | Random-oracle construction, Fig. 3; optimistic opening and threshold recovery |

All `threshold` values denote the actual number of shares required for recovery.
Illusi normalizes its source threshold `t + 1` to this convention and recovers
`h^s`. ALBATROSS with batch size `ell` has privacy bound `threshold - ell`;
recovering a batch releases every encoded secret. Its beacon coordination,
randomness extraction and cross-instance proof amortization are outside this
implementation. PPVSS requires the expected preconstruction as a separate
verification input; its pairing-based plain-model variant is not implemented.

`verify` returns a borrowed `VerifiedSharing` receipt. Use it to generate and
verify decrypted shares, then reconstruct previously verified values. Public
interpolation plans bind the ordered qualified subset. Every incoming sharing
and decrypted share is checked; only deterministic public preprocessing is
cached. No secret, nonce, ciphertext, proof outcome or decrypted share is cached.

ALBATROSS and PPVSS share polynomial arithmetic in `ldeipoly.rs`. Benchmark
results measure these implementations and do not establish the cited schemes'
security theorems. [Benchmark documentation](../../benchmarks/README.md) defines
the common timing and preprocessing policy.
