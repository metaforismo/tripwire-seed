#!/usr/bin/env python3
"""Standard-library tests for the independent reproduction verifier."""

from __future__ import annotations

import datetime as dt
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from verify_independent_reproduction import (
    CANDIDATE_METADATA_SCHEMA,
    ReproductionVerificationError,
    sha256_bytes,
    verify_reproduction,
)

COMMIT = "016e53f4cc2963ee225230055c1a86b2099f1583"
TARGET = "x86_64-unknown-linux-gnu"
VERSION = "0.1.0"
EPOCH = 1_786_971_800
PREFIX = f"tripwire-seed-v{VERSION}-{TARGET}"
ARCHIVE_NAME = f"{PREFIX}.zip"
BINARY = b"synthetic-tripwire-seed-binary\x00"
SELF_TEST_SCHEMA = "tripwire-seed/self-test/v1"


def zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    instant = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    second = instant.second - (instant.second % 2)
    return (instant.year, instant.month, instant.day, instant.hour, instant.minute, second)


def write_member(
    archive: zipfile.ZipFile,
    name: str,
    data: bytes,
    mode: int,
) -> None:
    info = zipfile.ZipInfo(name, date_time=zip_datetime(EPOCH))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | mode) << 16
    archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def metadata(binary: bytes, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": CANDIDATE_METADATA_SCHEMA,
        "package": "tripwire-seed",
        "version": VERSION,
        "commit": COMMIT,
        "target": TARGET,
        "source_date_epoch": EPOCH,
        "binary_sha256": sha256_bytes(binary),
        "same_runner_double_build": True,
        "rustc": "rustc 1.97.1 synthetic",
        "cargo": "cargo 1.97.1 synthetic",
        "linker_reproducibility_flags": [],
        "self_test_schema": SELF_TEST_SCHEMA,
        "self_test_passed": True,
        "public_vectors_only": True,
    }
    value.update(overrides)
    return value


def candidate_bytes(
    *,
    binary: bytes = BINARY,
    metadata_overrides: dict[str, object] | None = None,
    name_overrides: dict[str, str] | None = None,
    duplicate_readme: bool = False,
    omit_apache: bool = False,
) -> bytes:
    names = {
        "binary": f"{PREFIX}/tripwire-seed",
        "metadata": f"{PREFIX}/BUILD-METADATA.json",
        "readme": f"{PREFIX}/README.md",
        "mit": f"{PREFIX}/LICENSE-MIT",
        "apache": f"{PREFIX}/LICENSE-APACHE",
    }
    if name_overrides:
        names.update(name_overrides)
    candidate_metadata = metadata(binary, **(metadata_overrides or {}))
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w") as archive:
        write_member(archive, names["binary"], binary, 0o755)
        write_member(
            archive,
            names["metadata"],
            (json.dumps(candidate_metadata, sort_keys=True, indent=2) + "\n").encode(),
            0o644,
        )
        write_member(archive, names["readme"], b"README\n", 0o644)
        write_member(archive, names["mit"], b"MIT\n", 0o644)
        if not omit_apache:
            write_member(archive, names["apache"], b"APACHE\n", 0o644)
        if duplicate_readme:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                write_member(archive, names["readme"], b"duplicate\n", 0o644)
    return output.getvalue()


def sidecar(archive_data: bytes, digest: str | None = None) -> bytes:
    value = digest or sha256_bytes(archive_data)
    return f"{value}  {ARCHIVE_NAME}\n".encode("ascii")


def reference_artifact(
    candidate_data: bytes,
    *,
    sidecar_data: bytes | None = None,
    extra_member: bool = False,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w") as archive:
        write_member(archive, ARCHIVE_NAME, candidate_data, 0o644)
        write_member(
            archive,
            f"{ARCHIVE_NAME}.sha256",
            sidecar_data or sidecar(candidate_data),
            0o644,
        )
        if extra_member:
            write_member(archive, "extra.txt", b"extra\n", 0o644)
    return output.getvalue()


class ReproductionVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.reference_candidate = candidate_bytes()
        self.artifact_data = reference_artifact(self.reference_candidate)
        self.artifact = self.root / "github-artifact.zip"
        self.artifact.write_bytes(self.artifact_data)
        self.reproduced = self.root / ARCHIVE_NAME
        self.reproduced.write_bytes(self.reference_candidate)
        self.reproduced_sidecar = self.root / f"{ARCHIVE_NAME}.sha256"
        self.reproduced_sidecar.write_bytes(sidecar(self.reference_candidate))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def verify(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "reference_artifact": self.artifact,
            "reference_artifact_sha256": sha256_bytes(self.artifact_data),
            "reproduced_archive": self.reproduced,
            "reproduced_sidecar": self.reproduced_sidecar,
            "expected_commit": COMMIT,
            "expected_target": TARGET,
        }
        arguments.update(overrides)
        return verify_reproduction(**arguments)  # type: ignore[arg-type]

    def test_matching_archives_pass_without_execution(self) -> None:
        with mock.patch("verify_independent_reproduction.subprocess.run") as runner:
            report = self.verify()
        runner.assert_not_called()
        self.assertTrue(report["inspection_only"])
        comparison = report["comparison"]
        self.assertTrue(comparison["binary_bytes_equal"])
        self.assertFalse(comparison["self_test_executed"])

    def test_optional_self_test_executes_only_reproduced_binary(self) -> None:
        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            executable = Path(command[0])
            self.assertEqual(command[1:], ["self-test", "--json"])
            self.assertEqual(executable.read_bytes(), BINARY)
            payload = {
                "schema": SELF_TEST_SCHEMA,
                "public_vectors_only": True,
                "passed": True,
                "checks": [{"name": "synthetic", "passed": True}],
            }
            return subprocess.CompletedProcess(
                command, 0, stdout=json.dumps(payload).encode(), stderr=b""
            )

        with mock.patch(
            "verify_independent_reproduction.subprocess.run", side_effect=fake_run
        ) as runner:
            report = self.verify(execute_reproduced_self_test=True)
        self.assertEqual(runner.call_count, 1)
        self.assertFalse(report["inspection_only"])
        self.assertTrue(report["comparison"]["self_test"]["passed"])

    def test_reference_artifact_digest_mismatch_fails(self) -> None:
        with self.assertRaises(ReproductionVerificationError):
            self.verify(reference_artifact_sha256="00" * 32)

    def test_reference_sidecar_mismatch_fails(self) -> None:
        self.artifact_data = reference_artifact(
            self.reference_candidate,
            sidecar_data=sidecar(self.reference_candidate, "00" * 32),
        )
        self.artifact.write_bytes(self.artifact_data)
        with self.assertRaises(ReproductionVerificationError):
            self.verify()

    def test_reference_artifact_requires_exactly_two_members(self) -> None:
        self.artifact_data = reference_artifact(
            self.reference_candidate, extra_member=True
        )
        self.artifact.write_bytes(self.artifact_data)
        with self.assertRaises(ReproductionVerificationError):
            self.verify()

    def test_path_traversal_rejected_with_exactly_five_members(self) -> None:
        malicious = candidate_bytes(
            name_overrides={"readme": f"{PREFIX}/../README.md"}
        )
        self.reproduced.write_bytes(malicious)
        self.reproduced_sidecar.write_bytes(sidecar(malicious))
        with self.assertRaises(ReproductionVerificationError):
            self.verify()

    def test_duplicate_candidate_member_is_rejected(self) -> None:
        duplicate = candidate_bytes(duplicate_readme=True, omit_apache=True)
        self.reproduced.write_bytes(duplicate)
        self.reproduced_sidecar.write_bytes(sidecar(duplicate))
        with self.assertRaises(ReproductionVerificationError):
            self.verify()

    def test_metadata_binary_digest_mismatch_is_rejected(self) -> None:
        inconsistent = candidate_bytes(
            metadata_overrides={"binary_sha256": "00" * 32}
        )
        self.reproduced.write_bytes(inconsistent)
        self.reproduced_sidecar.write_bytes(sidecar(inconsistent))
        with self.assertRaises(ReproductionVerificationError):
            self.verify()

    def test_reproduced_binary_mismatch_is_rejected(self) -> None:
        different = candidate_bytes(binary=b"different-but-internally-valid-binary")
        self.reproduced.write_bytes(different)
        self.reproduced_sidecar.write_bytes(sidecar(different))
        with self.assertRaises(ReproductionVerificationError):
            self.verify()

    def test_toolchain_metadata_difference_is_reported(self) -> None:
        different = candidate_bytes(
            metadata_overrides={
                "cargo": "cargo 1.97.1 same compiler, different host metadata"
            }
        )
        self.reproduced.write_bytes(different)
        self.reproduced_sidecar.write_bytes(sidecar(different))
        report = self.verify()
        self.assertTrue(report["comparison"]["binary_bytes_equal"])
        self.assertFalse(report["comparison"]["toolchain_metadata_equal"])

    def test_out_of_range_source_epoch_is_rejected_cleanly(self) -> None:
        invalid = candidate_bytes(
            metadata_overrides={"source_date_epoch": 9_999_999_999_999}
        )
        self.reproduced.write_bytes(invalid)
        self.reproduced_sidecar.write_bytes(sidecar(invalid))
        with self.assertRaises(ReproductionVerificationError):
            self.verify()


if __name__ == "__main__":
    unittest.main(verbosity=2)
