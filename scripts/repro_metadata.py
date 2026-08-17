#!/usr/bin/env python3
"""Strict release-candidate metadata validation."""

from __future__ import annotations

import re
from typing import Any

from repro_io import validate_public_text
from repro_types import (
    CANDIDATE_SCHEMA, EXPECTED_METADATA_KEYS, PACKAGE_NAME, ReproductionError,
    SELF_TEST_SCHEMA, SUPPORTED_TARGETS,
)

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$")


def require_string(value: Any, field: str, *, limit: int = 16_384) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ReproductionError(f"candidate metadata field {field!r} is invalid")
    return value


def require_bool_true(value: Any, field: str) -> None:
    if value is not True:
        raise ReproductionError(f"candidate metadata field {field!r} must be true")


def validate_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReproductionError("candidate metadata root must be an object")
    keys = set(value)
    if keys != EXPECTED_METADATA_KEYS:
        missing = sorted(EXPECTED_METADATA_KEYS - keys)
        unknown = sorted(keys - EXPECTED_METADATA_KEYS)
        raise ReproductionError(
            f"candidate metadata keys differ: missing={missing} unknown={unknown}"
        )

    schema = require_string(value["schema"], "schema", limit=128)
    package = require_string(value["package"], "package", limit=128)
    version = require_string(value["version"], "version", limit=64)
    commit = require_string(value["commit"], "commit", limit=40)
    target = require_string(value["target"], "target", limit=128)
    binary_sha256 = require_string(
        value["binary_sha256"], "binary_sha256", limit=64
    )
    self_test_schema = require_string(
        value["self_test_schema"], "self_test_schema", limit=128
    )
    rustc = validate_public_text(
        require_string(value["rustc"], "rustc"), "rustc"
    )
    cargo = validate_public_text(
        require_string(value["cargo"], "cargo"), "cargo"
    )

    if schema != CANDIDATE_SCHEMA:
        raise ReproductionError(f"unsupported candidate metadata schema: {schema}")
    if package != PACKAGE_NAME:
        raise ReproductionError(f"unexpected package identity: {package}")
    if not VERSION.fullmatch(version):
        raise ReproductionError("candidate version has an invalid shape")
    if not HEX_40.fullmatch(commit):
        raise ReproductionError(
            "candidate commit must be a lower-case 40-character SHA"
        )
    if target not in SUPPORTED_TARGETS:
        raise ReproductionError(f"unsupported target: {target}")
    if not HEX_64.fullmatch(binary_sha256):
        raise ReproductionError("candidate binary SHA-256 is invalid")
    if self_test_schema != SELF_TEST_SCHEMA:
        raise ReproductionError(
            f"unsupported self-test schema: {self_test_schema}"
        )

    epoch = value["source_date_epoch"]
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise ReproductionError("candidate source_date_epoch is invalid")

    flags = value["linker_reproducibility_flags"]
    if not isinstance(flags, list) or any(
        not isinstance(flag, str) or not flag or len(flag) > 256 for flag in flags
    ):
        raise ReproductionError("candidate linker flags are invalid")

    require_bool_true(value["same_runner_double_build"], "same_runner_double_build")
    require_bool_true(value["self_test_passed"], "self_test_passed")
    require_bool_true(value["public_vectors_only"], "public_vectors_only")

    return {
        **value,
        "rustc": rustc,
        "cargo": cargo,
    }
