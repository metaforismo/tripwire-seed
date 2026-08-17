#!/usr/bin/env python3
"""Candidate summaries and byte-level comparison."""

from typing import Any
from reproduction_support import Candidate


def candidate_summary(candidate: Candidate, sidecar_verified: bool) -> dict[str, Any]:
    return {
        "archive": candidate.archive_name,
        "archive_sha256": candidate.archive_sha256,
        "binary_sha256": candidate.binary_sha256,
        "sidecar_verified": sidecar_verified,
        "metadata": {
            "schema": candidate.metadata["schema"],
            "package": candidate.metadata["package"],
            "version": candidate.metadata["version"],
            "commit": candidate.metadata["commit"],
            "target": candidate.metadata["target"],
            "source_date_epoch": candidate.metadata["source_date_epoch"],
            "rustc": candidate.metadata["rustc"],
            "cargo": candidate.metadata["cargo"],
            "linker_reproducibility_flags": candidate.metadata[
                "linker_reproducibility_flags"
            ],
            "self_test_schema": candidate.metadata["self_test_schema"],
            "self_test_passed": candidate.metadata["self_test_passed"],
            "public_vectors_only": candidate.metadata["public_vectors_only"],
        },
        "document_sha256": dict(candidate.document_sha256),
    }


def compare_candidates(reference: Candidate, reproduction: Candidate) -> dict[str, bool]:
    identity_fields = ("schema", "package", "version", "commit", "target")
    identity_match = all(
        reference.metadata[field] == reproduction.metadata[field]
        for field in identity_fields
    )
    return {
        "identity_match": identity_match,
        "binary_match": reference.binary_sha256 == reproduction.binary_sha256,
        "package_documents_match": (
            reference.document_sha256 == reproduction.document_sha256
        ),
        "archive_match": reference.archive_sha256 == reproduction.archive_sha256,
        "toolchain_metadata_match": (
            reference.metadata["rustc"] == reproduction.metadata["rustc"]
            and reference.metadata["cargo"] == reproduction.metadata["cargo"]
        ),
        "build_contract_match": (
            reference.metadata["source_date_epoch"]
            == reproduction.metadata["source_date_epoch"]
            and reference.metadata["linker_reproducibility_flags"]
            == reproduction.metadata["linker_reproducibility_flags"]
        ),
    }
