#!/usr/bin/env python3
"""Safely compare a Tripwire Seed release candidate with an independent build.

The verifier treats the GitHub artifact and both candidate archives as untrusted
input. It validates archive structure, paths, metadata, checksum sidecars, and
raw executable bytes without extracting or executing the reference binary.
Executing the independently reproduced binary's public-vector self-test requires
an explicit flag.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping
import zipfile

PACKAGE_NAME = "tripwire-seed"
CANDIDATE_METADATA_SCHEMA = "tripwire-seed/release-candidate/v1"
REPORT_SCHEMA = "tripwire-seed/independent-reproduction-report/v1"
SUPPORTED_TARGETS = frozenset(
    {
        "x86_64-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    }
)
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$")
EXPECTED_METADATA_KEYS = frozenset(
    {
        "schema",
        "package",
        "version",
        "commit",
        "target",
        "source_date_epoch",
        "binary_sha256",
        "same_runner_double_build",
        "rustc",
        "cargo",
        "linker_reproducibility_flags",
        "self_test_schema",
        "self_test_passed",
        "public_vectors_only",
    }
)
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_SIDECAR_BYTES = 1024
SELF_TEST_TIMEOUT_SECONDS = 30
MAX_SOURCE_DATE_EPOCH = 4_354_819_198


class ReproductionVerificationError(RuntimeError):
    """Raised when a reproduction-verification invariant is not satisfied."""


@dataclass(frozen=True)
class CandidateArchive:
    """Validated, in-memory public contents of one native candidate archive."""

    archive_name: str
    archive_sha256: str
    prefix: str
    binary_name: str
    binary_bytes: bytes
    binary_sha256: str
    metadata: Mapping[str, Any]
    documents: Mapping[str, bytes]


def sha256_bytes(data: bytes) -> str:
    """Return a lower-case SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def _validate_hex(value: str, pattern: re.Pattern[str], label: str) -> str:
    if value != value.strip() or pattern.fullmatch(value) is None:
        raise ReproductionVerificationError(
            f"{label} must be canonical lower-case hexadecimal"
        )
    return value


def _read_regular_file(path: Path, *, label: str, limit: int) -> bytes:
    """Open one regular file without following a final symlink where supported."""

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise ReproductionVerificationError(f"{label} does not exist") from error
    except OSError as error:
        raise ReproductionVerificationError(
            f"{label} must be an accessible non-symlink regular file"
        ) from error
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ReproductionVerificationError(f"{label} must be a regular file")
        if file_stat.st_size > limit:
            raise ReproductionVerificationError(f"{label} exceeds the {limit}-byte limit")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            raise ReproductionVerificationError(f"{label} exceeds the {limit}-byte limit")
        return data
    finally:
        os.close(descriptor)


def _validate_zip_member_name(name: str, *, label: str) -> PurePosixPath:
    """Reject absolute, ambiguous, platform-dependent, or traversing ZIP paths."""

    if not name or "\x00" in name or "\\" in name:
        raise ReproductionVerificationError(f"{label} contains an invalid member path")
    raw_parts = name.split("/")
    if name.startswith("/"):
        raise ReproductionVerificationError(f"{label} contains an absolute member path")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ReproductionVerificationError(f"{label} contains an ambiguous member path")
    if ":" in raw_parts[0]:
        raise ReproductionVerificationError(f"{label} contains a drive-qualified path")
    return PurePosixPath(*raw_parts)


def _read_zip_entries(
    data: bytes,
    *,
    label: str,
    max_members: int,
) -> dict[str, tuple[bytes, zipfile.ZipInfo]]:
    """Read bounded regular-file members without extracting them to disk."""

    try:
        archive = zipfile.ZipFile(io.BytesIO(data), mode="r")
    except (zipfile.BadZipFile, OSError) as error:
        raise ReproductionVerificationError(f"{label} is not a valid ZIP archive") from error

    with archive:
        infos = archive.infolist()
        if len(infos) > max_members:
            raise ReproductionVerificationError(
                f"{label} contains more than {max_members} members"
            )
        entries: dict[str, tuple[bytes, zipfile.ZipInfo]] = {}
        total_size = 0
        for info in infos:
            _validate_zip_member_name(info.filename, label=label)
            if info.filename in entries:
                raise ReproductionVerificationError(
                    f"{label} contains a duplicate member name"
                )
            if info.is_dir():
                raise ReproductionVerificationError(f"{label} must not contain directories")
            if info.flag_bits & 0x1:
                raise ReproductionVerificationError(
                    f"{label} must not contain encrypted members"
                )
            raw_mode = info.external_attr >> 16
            file_type = stat.S_IFMT(raw_mode)
            if file_type not in {0, stat.S_IFREG}:
                raise ReproductionVerificationError(
                    f"{label} contains a non-regular member"
                )
            if info.file_size > MAX_MEMBER_BYTES:
                raise ReproductionVerificationError(
                    f"{label} contains an oversized member"
                )
            total_size += info.file_size
            if total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ReproductionVerificationError(
                    f"{label} exceeds the uncompressed-size limit"
                )
            try:
                member_data = archive.read(info)
            except (zipfile.BadZipFile, RuntimeError, OSError) as error:
                raise ReproductionVerificationError(
                    f"{label} contains an unreadable member"
                ) from error
            if len(member_data) != info.file_size:
                raise ReproductionVerificationError(
                    f"{label} member size does not match its ZIP metadata"
                )
            entries[info.filename] = (member_data, info)
        return entries


def _parse_sidecar(data: bytes, *, archive_name: str, label: str) -> str:
    if len(data) > MAX_SIDECAR_BYTES:
        raise ReproductionVerificationError(f"{label} is oversized")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReproductionVerificationError(f"{label} must be ASCII") from error
    lines = text.splitlines()
    if len(lines) != 1 or not text.endswith("\n"):
        raise ReproductionVerificationError(f"{label} must contain one final-newline line")
    fields = lines[0].split()
    if len(fields) != 2 or fields[1] != archive_name:
        raise ReproductionVerificationError(f"{label} has an invalid archive filename")
    return _validate_hex(fields[0], HEX_64, f"{label} digest")


def _expected_zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    try:
        instant = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    except (OverflowError, OSError, ValueError) as error:
        raise ReproductionVerificationError(
            "candidate source timestamp is out of range"
        ) from error
    if instant.year > 2107:
        raise ReproductionVerificationError(
            "candidate source timestamp exceeds the ZIP range"
        )
    if instant.year < 1980:
        instant = instant.replace(
            year=1980,
            month=1,
            day=1,
            hour=0,
            minute=0,
            second=0,
        )
    second = instant.second - (instant.second % 2)
    return (instant.year, instant.month, instant.day, instant.hour, instant.minute, second)


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReproductionVerificationError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _expect_string(metadata: Mapping[str, Any], key: str) -> str:
    value = metadata.get(key)
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ReproductionVerificationError(f"candidate metadata field {key} is invalid")
    return value


def _validate_candidate_metadata(
    metadata: Mapping[str, Any],
    *,
    expected_commit: str,
    expected_target: str,
) -> tuple[str, int]:
    if set(metadata) != EXPECTED_METADATA_KEYS:
        raise ReproductionVerificationError("candidate metadata field set is unexpected")
    if _expect_string(metadata, "schema") != CANDIDATE_METADATA_SCHEMA:
        raise ReproductionVerificationError("candidate metadata schema is unsupported")
    if _expect_string(metadata, "package") != PACKAGE_NAME:
        raise ReproductionVerificationError("candidate package identity is unexpected")
    version = _expect_string(metadata, "version")
    if SAFE_VERSION.fullmatch(version) is None:
        raise ReproductionVerificationError("candidate version is not path-safe")
    commit = _validate_hex(_expect_string(metadata, "commit"), HEX_40, "candidate commit")
    if commit != expected_commit:
        raise ReproductionVerificationError("candidate commit does not match the frozen target")
    target = _expect_string(metadata, "target")
    if target != expected_target:
        raise ReproductionVerificationError("candidate target does not match the requested target")
    epoch = metadata.get("source_date_epoch")
    if (
        not isinstance(epoch, int)
        or isinstance(epoch, bool)
        or epoch < 0
        or epoch > MAX_SOURCE_DATE_EPOCH
    ):
        raise ReproductionVerificationError("candidate source_date_epoch is invalid")
    binary_digest = _validate_hex(
        _expect_string(metadata, "binary_sha256"), HEX_64, "candidate binary SHA-256"
    )
    if metadata.get("same_runner_double_build") is not True:
        raise ReproductionVerificationError("candidate lacks successful double-build metadata")
    if metadata.get("self_test_passed") is not True:
        raise ReproductionVerificationError("candidate self-test metadata is not successful")
    if metadata.get("public_vectors_only") is not True:
        raise ReproductionVerificationError("candidate self-test was not public-vector-only")
    _expect_string(metadata, "rustc")
    _expect_string(metadata, "cargo")
    _expect_string(metadata, "self_test_schema")
    flags = metadata.get("linker_reproducibility_flags")
    expected_flags = ["/Brepro"] if expected_target.endswith("-windows-msvc") else []
    if flags != expected_flags:
        raise ReproductionVerificationError(
            "candidate linker reproducibility metadata is unexpected"
        )
    return binary_digest, epoch


def _validate_member_mode(info: zipfile.ZipInfo, expected: int, *, label: str) -> None:
    if info.create_system != 3:
        raise ReproductionVerificationError(f"{label} lacks Unix permission metadata")
    raw_mode = info.external_attr >> 16
    if stat.S_IFMT(raw_mode) != stat.S_IFREG or stat.S_IMODE(raw_mode) != expected:
        raise ReproductionVerificationError(f"{label} has unexpected file permissions")


def _parse_candidate_archive(
    data: bytes,
    *,
    archive_name: str,
    expected_commit: str,
    expected_target: str,
    label: str,
) -> CandidateArchive:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ReproductionVerificationError(f"{label} exceeds the archive-size limit")
    entries = _read_zip_entries(data, label=label, max_members=5)
    if len(entries) != 5:
        raise ReproductionVerificationError(f"{label} must contain exactly five members")

    metadata_names = [
        name for name in entries if name.endswith("/BUILD-METADATA.json")
    ]
    if len(metadata_names) != 1:
        raise ReproductionVerificationError(f"{label} lacks one unambiguous metadata file")
    metadata_name = metadata_names[0]
    prefix = metadata_name.rsplit("/", 1)[0]
    metadata_bytes, metadata_info = entries[metadata_name]
    if len(metadata_bytes) > MAX_METADATA_BYTES:
        raise ReproductionVerificationError(f"{label} metadata is oversized")
    try:
        metadata_value = json.loads(
            metadata_bytes.decode("utf-8"), object_pairs_hook=_strict_json_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReproductionVerificationError(f"{label} metadata is not valid UTF-8 JSON") from error
    if not isinstance(metadata_value, dict):
        raise ReproductionVerificationError(f"{label} metadata root must be an object")

    metadata: dict[str, Any] = metadata_value
    declared_binary_digest, epoch = _validate_candidate_metadata(
        metadata,
        expected_commit=expected_commit,
        expected_target=expected_target,
    )
    version = metadata["version"]
    expected_prefix = f"{PACKAGE_NAME}-v{version}-{expected_target}"
    if prefix != expected_prefix:
        raise ReproductionVerificationError(f"{label} top-level prefix is unexpected")
    expected_archive_name = f"{expected_prefix}.zip"
    if archive_name != expected_archive_name:
        raise ReproductionVerificationError(f"{label} filename is inconsistent with metadata")

    binary_name = f"{PACKAGE_NAME}.exe" if "windows" in expected_target else PACKAGE_NAME
    expected_members = {
        f"{prefix}/{binary_name}",
        f"{prefix}/BUILD-METADATA.json",
        f"{prefix}/README.md",
        f"{prefix}/LICENSE-MIT",
        f"{prefix}/LICENSE-APACHE",
    }
    if set(entries) != expected_members:
        raise ReproductionVerificationError(f"{label} member set is unexpected")

    expected_timestamp = _expected_zip_datetime(epoch)
    for member_name, (_, info) in entries.items():
        if info.date_time != expected_timestamp:
            raise ReproductionVerificationError(
                f"{label} contains a non-normalized member timestamp"
            )
        expected_mode = 0o755 if member_name.endswith(f"/{binary_name}") else 0o644
        _validate_member_mode(info, expected_mode, label=label)

    binary_bytes = entries[f"{prefix}/{binary_name}"][0]
    actual_binary_digest = sha256_bytes(binary_bytes)
    if actual_binary_digest != declared_binary_digest:
        raise ReproductionVerificationError(
            f"{label} binary does not match BUILD-METADATA.json"
        )
    _validate_member_mode(metadata_info, 0o644, label=label)
    documents = {
        document: entries[f"{prefix}/{document}"][0]
        for document in ("README.md", "LICENSE-MIT", "LICENSE-APACHE")
    }
    return CandidateArchive(
        archive_name=archive_name,
        archive_sha256=sha256_bytes(data),
        prefix=prefix,
        binary_name=binary_name,
        binary_bytes=binary_bytes,
        binary_sha256=actual_binary_digest,
        metadata=metadata,
        documents=documents,
    )


def _load_reference_candidate(
    path: Path,
    *,
    expected_artifact_sha256: str,
    expected_commit: str,
    expected_target: str,
) -> tuple[CandidateArchive, str]:
    artifact_data = _read_regular_file(
        path, label="reference artifact", limit=MAX_ARTIFACT_BYTES
    )
    artifact_digest = sha256_bytes(artifact_data)
    if artifact_digest != expected_artifact_sha256:
        raise ReproductionVerificationError(
            "reference artifact does not match the separately supplied SHA-256"
        )
    entries = _read_zip_entries(
        artifact_data, label="reference artifact", max_members=2
    )
    if len(entries) != 2:
        raise ReproductionVerificationError(
            "reference artifact must contain exactly one candidate and one sidecar"
        )
    for name in entries:
        if PurePosixPath(name).name != name:
            raise ReproductionVerificationError(
                "reference artifact members must be at the archive root"
            )
    candidate_names = [name for name in entries if name.endswith(".zip")]
    if len(candidate_names) != 1:
        raise ReproductionVerificationError(
            "reference artifact must contain exactly one candidate ZIP"
        )
    candidate_name = candidate_names[0]
    sidecar_name = f"{candidate_name}.sha256"
    if set(entries) != {candidate_name, sidecar_name}:
        raise ReproductionVerificationError(
            "reference artifact sidecar filename is inconsistent"
        )
    candidate_data = entries[candidate_name][0]
    declared_digest = _parse_sidecar(
        entries[sidecar_name][0],
        archive_name=candidate_name,
        label="reference checksum sidecar",
    )
    if sha256_bytes(candidate_data) != declared_digest:
        raise ReproductionVerificationError(
            "reference candidate does not match its checksum sidecar"
        )
    candidate = _parse_candidate_archive(
        candidate_data,
        archive_name=candidate_name,
        expected_commit=expected_commit,
        expected_target=expected_target,
        label="reference candidate",
    )
    return candidate, artifact_digest


def _load_reproduced_candidate(
    archive_path: Path,
    sidecar_path: Path,
    *,
    expected_commit: str,
    expected_target: str,
) -> CandidateArchive:
    archive_data = _read_regular_file(
        archive_path, label="reproduced archive", limit=MAX_ARCHIVE_BYTES
    )
    sidecar_data = _read_regular_file(
        sidecar_path, label="reproduced sidecar", limit=MAX_SIDECAR_BYTES
    )
    declared_digest = _parse_sidecar(
        sidecar_data,
        archive_name=archive_path.name,
        label="reproduced checksum sidecar",
    )
    if sha256_bytes(archive_data) != declared_digest:
        raise ReproductionVerificationError(
            "reproduced archive does not match its checksum sidecar"
        )
    return _parse_candidate_archive(
        archive_data,
        archive_name=archive_path.name,
        expected_commit=expected_commit,
        expected_target=expected_target,
        label="reproduced candidate",
    )


def _run_reproduced_self_test(candidate: CandidateArchive) -> dict[str, Any]:
    """Execute only the reproduced binary after explicit caller opt-in."""

    with tempfile.TemporaryDirectory(prefix="tripwire-reproduction-self-test-") as name:
        directory = Path(name)
        try:
            directory.chmod(0o700)
        except OSError:
            pass
        binary = directory / candidate.binary_name
        with binary.open("xb") as output:
            output.write(candidate.binary_bytes)
            output.flush()
            os.fsync(output.fileno())
        try:
            binary.chmod(0o700)
        except OSError:
            pass
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR"}
        }
        environment.update({"LANG": "C", "LC_ALL": "C"})
        try:
            result = subprocess.run(
                [os.fspath(binary), "self-test", "--json"],
                cwd=directory,
                env=environment,
                check=False,
                capture_output=True,
                timeout=SELF_TEST_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReproductionVerificationError(
                "reproduced binary self-test could not complete"
            ) from error
        if result.returncode != 0:
            raise ReproductionVerificationError(
                "reproduced binary self-test exited unsuccessfully"
            )
        if result.stderr:
            raise ReproductionVerificationError(
                "reproduced binary self-test wrote to stderr"
            )
        try:
            report = json.loads(
                result.stdout.decode("utf-8"), object_pairs_hook=_strict_json_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReproductionVerificationError(
                "reproduced binary self-test did not emit valid JSON"
            ) from error
        if not isinstance(report, dict):
            raise ReproductionVerificationError(
                "reproduced binary self-test JSON root must be an object"
            )
        if report.get("schema") != candidate.metadata["self_test_schema"]:
            raise ReproductionVerificationError(
                "reproduced binary self-test schema differs from candidate metadata"
            )
        checks = report.get("checks")
        if (
            report.get("public_vectors_only") is not True
            or report.get("passed") is not True
            or not isinstance(checks, list)
            or not checks
        ):
            raise ReproductionVerificationError(
                "reproduced binary public-vector self-test did not pass"
            )
        return {"schema": report["schema"], "checks": len(checks), "passed": True}


def verify_reproduction(
    *,
    reference_artifact: Path,
    reference_artifact_sha256: str,
    reproduced_archive: Path,
    reproduced_sidecar: Path,
    expected_commit: str,
    expected_target: str,
    execute_reproduced_self_test: bool = False,
) -> dict[str, Any]:
    """Validate inputs and return a privacy-safe reproduction report."""

    expected_commit = _validate_hex(expected_commit, HEX_40, "expected commit")
    expected_artifact_digest = _validate_hex(
        reference_artifact_sha256, HEX_64, "reference artifact SHA-256"
    )
    if expected_target not in SUPPORTED_TARGETS:
        raise ReproductionVerificationError("expected target is unsupported")

    reference, artifact_digest = _load_reference_candidate(
        reference_artifact,
        expected_artifact_sha256=expected_artifact_digest,
        expected_commit=expected_commit,
        expected_target=expected_target,
    )
    reproduced = _load_reproduced_candidate(
        reproduced_archive,
        reproduced_sidecar,
        expected_commit=expected_commit,
        expected_target=expected_target,
    )

    identity_fields = (
        "schema",
        "package",
        "version",
        "commit",
        "target",
        "source_date_epoch",
        "same_runner_double_build",
        "linker_reproducibility_flags",
        "self_test_schema",
        "self_test_passed",
        "public_vectors_only",
    )
    if any(reference.metadata[field] != reproduced.metadata[field] for field in identity_fields):
        raise ReproductionVerificationError(
            "reproduced candidate identity metadata differs"
        )
    toolchain_metadata_equal = (
        reference.metadata["rustc"] == reproduced.metadata["rustc"]
        and reference.metadata["cargo"] == reproduced.metadata["cargo"]
    )
    if reference.documents != reproduced.documents:
        raise ReproductionVerificationError(
            "reproduced candidate public package documents differ"
        )
    if reference.binary_bytes != reproduced.binary_bytes:
        raise ReproductionVerificationError(
            "reproduced executable bytes differ from the reference candidate"
        )

    self_test = (
        _run_reproduced_self_test(reproduced)
        if execute_reproduced_self_test
        else None
    )
    return {
        "schema": REPORT_SCHEMA,
        "inspection_only": not execute_reproduced_self_test,
        "expected": {"commit": expected_commit, "target": expected_target},
        "reference": {
            "artifact": reference_artifact.name,
            "artifact_sha256": artifact_digest,
            "candidate_archive": reference.archive_name,
            "candidate_archive_sha256": reference.archive_sha256,
            "binary_sha256": reference.binary_sha256,
        },
        "reproduced": {
            "candidate_archive": reproduced.archive_name,
            "candidate_archive_sha256": reproduced.archive_sha256,
            "binary_sha256": reproduced.binary_sha256,
        },
        "comparison": {
            "binary_bytes_equal": True,
            "binary_sha256_equal": True,
            "public_documents_equal": True,
            "identity_metadata_equal": True,
            "toolchain_metadata_equal": toolchain_metadata_equal,
            "toolchain_metadata_sha256": {
                "reference": {
                    "rustc": sha256_bytes(reference.metadata["rustc"].encode("utf-8")),
                    "cargo": sha256_bytes(reference.metadata["cargo"].encode("utf-8")),
                },
                "reproduced": {
                    "rustc": sha256_bytes(reproduced.metadata["rustc"].encode("utf-8")),
                    "cargo": sha256_bytes(reproduced.metadata["cargo"].encode("utf-8")),
                },
            },
            "self_test_executed": execute_reproduced_self_test,
            "self_test": self_test,
        },
        "verifier_environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "limitations": [
            "This report does not authenticate the source checkout or build host.",
            "The reference binary was inspected in memory and was never executed.",
            "Matching bytes do not prove either compiler or operating system was uncompromised.",
            "Toolchain metadata differences must be explained even when executable bytes match.",
            "Administrative independence and reviewer sign-off must be established outside this tool.",
            "This report does not replace recovery drills or an independent security review.",
        ],
    }


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ReproductionVerificationError("report path already exists")
    if not path.parent.is_dir():
        raise ReproductionVerificationError("report parent directory does not exist")
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        raise ReproductionVerificationError("report path already exists") from error


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-artifact", required=True, type=Path)
    parser.add_argument("--reference-artifact-sha256", required=True)
    parser.add_argument("--reproduced-archive", required=True, type=Path)
    parser.add_argument(
        "--reproduced-sidecar",
        type=Path,
        help="default: <reproduced-archive>.sha256",
    )
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument(
        "--expected-target", required=True, choices=sorted(SUPPORTED_TARGETS)
    )
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--execute-reproduced-self-test",
        action="store_true",
        help="explicitly execute only the independently reproduced binary",
    )
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    options = parse_arguments(arguments)
    sidecar = options.reproduced_sidecar or options.reproduced_archive.with_name(
        f"{options.reproduced_archive.name}.sha256"
    )
    try:
        report = verify_reproduction(
            reference_artifact=options.reference_artifact,
            reference_artifact_sha256=options.reference_artifact_sha256,
            reproduced_archive=options.reproduced_archive,
            reproduced_sidecar=sidecar,
            expected_commit=options.expected_commit,
            expected_target=options.expected_target,
            execute_reproduced_self_test=options.execute_reproduced_self_test,
        )
        if options.report is not None:
            _write_report(options.report, report)
        print(json.dumps(report, sort_keys=True, indent=2), flush=True)
    except (ReproductionVerificationError, OSError) as error:
        print(f"reproduction verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
