"""Validate the supplied PVSS measurements without manuscript dependencies."""

import csv
import hashlib
import json
import math
import statistics
from pathlib import Path


RESULTS = Path(__file__).resolve().parent / "results"
SIZES = [4, 8, 16, 32, 64, 128, 256, 512]
MAIN = {"ElGamal PVSS", "Silent Setup PVSS", "DHPVSS", "Illusi"}
SUPPLEMENTARY = {"ALBATROSS ell=1", "PPVSS RO"}
OPERATIONS = ["Share", "Verify", "PreRecon", "DecVrf", "Recon"]


def read_csv(name):
    with (RESULTS / name).open(newline="") as stream:
        return list(csv.DictReader(stream))


def validate_pvss(prefix, schemes, expected_batches):
    rows = read_csv(prefix + ".csv")
    samples = read_csv(prefix + ".samples.csv")
    assert len(rows) == len(schemes) * len(SIZES)
    assert len(samples) == expected_batches
    assert {row["scheme"] for row in rows} == schemes
    assert {row["scheme"] for row in samples} == schemes
    expected_keys = {
        (scheme, n, operation, batch)
        for scheme in schemes
        for n in SIZES
        for operation in OPERATIONS + (["OptimisticOpen"] if scheme == "PPVSS RO" else [])
        for batch in range(10)
    }
    actual_keys = {
        (row["scheme"], int(row["real_parties"]), row["operation"], int(row["batch"]))
        for row in samples
    }
    assert actual_keys == expected_keys and len(actual_keys) == len(samples)
    for scheme in schemes:
        cases = [row for row in rows if row["scheme"] == scheme]
        assert [int(row["real_parties"]) for row in cases] == SIZES
        for row in cases:
            n, threshold = int(row["real_parties"]), int(row["t"])
            assert threshold == n // 2 + 1
            assert int(row["privacy_threshold"]) == threshold - 1
            assert int(row["batch_secrets"]) == 1
            capacity = 1 << n.bit_length() if scheme == "Silent Setup PVSS" else n
            assert int(row["domain_slots"]) == capacity
            operations = OPERATIONS + (["OptimisticOpen"] if scheme == "PPVSS RO" else [])
            assert bool(row["optimistic_open_ms"]) == (scheme == "PPVSS RO")
            for operation in operations:
                batch = [
                    sample for sample in samples
                    if sample["scheme"] == scheme
                    and int(sample["real_parties"]) == n
                    and sample["operation"] == operation
                ]
                assert [int(sample["batch"]) for sample in batch] == list(range(10))
                parties = threshold if operation in {"PreRecon", "DecVrf"} else 1
                assert all(int(sample["parties_per_call"]) == parties for sample in batch)
                calls = {int(sample["calls"]) for sample in batch}
                assert len(calls) == 1
                assert (1 if parties > 1 else 5) <= next(iter(calls)) <= 128
                values = [float(sample["mean_ms"]) for sample in batch]
                assert all(math.isfinite(value) and value > 0 for value in values)
                column = "optimistic_open_ms" if operation == "OptimisticOpen" else operation + "_ms"
                assert abs(statistics.mean(values) - float(row[column])) < 0.000000502
            total = (
                float(row["Share_ms"]) + float(row["Verify_ms"]) + float(row["Recon_ms"])
                + threshold * (float(row["PreRecon_ms"]) + float(row["DecVrf_ms"]))
            )
            assert abs(total - float(row["online_total_ms"])) < (threshold + 3) * 0.0000011
            assert row["online_total_ms"] == row["amortized_online_ms"]


def validate_groups():
    rows = read_csv("group-costs.csv")
    samples = read_csv("group-costs.samples.csv")
    names = ["E1_variable", "E1_fixed", "E2_variable", "E2_fixed",
             "ET_variable", "ET_fixed", "P", "P_prepared"]
    assert [row["operation"] for row in rows] == names
    assert len(samples) == 80 and {row["operation"] for row in samples} == set(names)
    for row in rows:
        batch = [sample for sample in samples if sample["operation"] == row["operation"]]
        assert [int(sample["batch"]) for sample in batch] == list(range(10))
        values = [float(sample["mean_ms"]) for sample in batch]
        assert all(math.isfinite(value) and value > 0 for value in values)
        assert abs(statistics.mean(values) - float(row["mean_ms"])) < 1.01e-9


def validate_payloads():
    rows = read_csv("payloads.csv")
    assert len(rows) == 32 and {row["scheme"] for row in rows} == MAIN
    for scheme in MAIN:
        cases = [row for row in rows if row["scheme"] == scheme]
        assert [int(row["n"]) for row in cases] == SIZES
        for row in cases:
            n = int(row["n"])
            sharing = {"ElGamal PVSS": 288, "Silent Setup PVSS": 2464,
                       "DHPVSS": 48 * n + 160, "Illusi": 288 * n + 48}[scheme]
            partial = {"ElGamal PVSS": 208, "Silent Setup PVSS": 48,
                       "DHPVSS": 208, "Illusi": 144}[scheme]
            assert int(row["Share_bytes"]) == sharing
            assert float(row["Share_KiB"]) == sharing / 1024
            assert int(row["PreRecon_bytes"]) == partial


def main():
    metadata = json.loads((RESULTS / "metadata.json").read_text())
    assert set(metadata["sha256"]) == {path.name for path in RESULTS.glob("*.csv")}
    for name, digest in metadata["sha256"].items():
        assert hashlib.sha256((RESULTS / name).read_bytes()).hexdigest() == digest, name
    validate_pvss("comparison", MAIN, 1600)
    validate_pvss("supplementary", SUPPLEMENTARY, 880)
    validate_groups()
    validate_payloads()
    print("Validated dataset checksums, 48 PVSS cases, 2,480 PVSS batches, "
          "80 group-operation batches and 32 payload cases.")


if __name__ == "__main__":
    main()
