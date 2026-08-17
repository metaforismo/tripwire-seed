#!/usr/bin/env python3
"""Shared types and constants for reproduction comparison tooling."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import BinaryIO, Mapping, Any

PACKAGE_NAME = "tripwire-seed"
CANDIDATE_SCHEMA = "tripwire-seed/release-candidate/v1"
SELF_TEST_SCHEMA = "tripwire-seed/self-test/v1"
SUPPORTED_TARGETS = {
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
}
EXPECTED_DOCUMENTS = ("README.md", "LICENSE-MIT", "LICENSE-APACHE")
EXPECTED_METADATA_KEYS = {
    "schema", "package", "version", "commit", "target",
    "source_date_epoch", "binary_sha256", "same_runner_double_build",
    "rustc", "cargo", "linker_reproducibility_flags", "self_test_schema",
    "self_test_passed", "public_vectors_only",
}
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_SIDECAR_BYTES = 4 * 1024
MAX_TOOL_OUTPUT_CHARS = 16 * 1024


class ReproductionError(RuntimeError):
    """Raised when candidate or evidence validation fails."""


@dataclass(frozen=True)
class Candidate:
    archive_name: str
    archive_sha256: str
    prefix: str
    metadata: Mapping[str, Any]
    binary_name: str
    binary_sha256: str
    binary_bytes: bytes
    document_sha256: Mapping[str, str]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_stream(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()
