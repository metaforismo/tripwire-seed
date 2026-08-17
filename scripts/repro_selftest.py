#!/usr/bin/env python3
"""Explicit execution of the reproduced public-vector self-test."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any

from reproduction_support import Candidate, ReproductionError, SELF_TEST_SCHEMA

MAX_OUTPUT = 1024 * 1024
NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
ROOT_KEYS = {"schema", "crate_version", "public_vectors_only", "passed", "checks"}
CHECK_KEYS = {"name", "passed"}


def self_test_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C",
        "LC_ALL": "C",
    }
    if os.name == "nt":
        for key in ("SystemRoot", "WINDIR", "PATHEXT"):
            if key in os.environ:
                environment[key] = os.environ[key]
    return environment


def run_reproduced_self_test(candidate: Candidate) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="tripwire-reproduction-") as directory:
        binary = Path(directory) / candidate.binary_name
        binary.write_bytes(candidate.binary_bytes)
        if os.name != "nt":
            binary.chmod(0o700)
        try:
            result = subprocess.run(
                [os.fspath(binary), "self-test", "--json"],
                check=False,
                text=True,
                capture_output=True,
                timeout=60,
                env=self_test_environment(),
                cwd=directory,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReproductionError("reproduced binary self-test could not run") from error
    if result.returncode != 0:
        raise ReproductionError(
            f"reproduced binary self-test exited with code {result.returncode}"
        )
    if result.stderr:
        raise ReproductionError("reproduced binary self-test wrote to stderr")
    if len(result.stdout) > MAX_OUTPUT:
        raise ReproductionError("reproduced binary self-test output is oversized")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ReproductionError("reproduced binary self-test did not emit JSON") from error
    if not isinstance(report, dict):
        raise ReproductionError("reproduced self-test JSON root must be an object")
    if set(report) != ROOT_KEYS:
        raise ReproductionError("reproduced self-test JSON keys are not canonical")
    if report.get("schema") != SELF_TEST_SCHEMA:
        raise ReproductionError("reproduced self-test schema is unsupported")
    if report.get("crate_version") != candidate.metadata["version"]:
        raise ReproductionError("reproduced self-test version disagrees with metadata")
    if report.get("public_vectors_only") is not True or report.get("passed") is not True:
        raise ReproductionError("reproduced binary public-vector self-test failed")
    checks = report.get("checks")
    if not isinstance(checks, list) or not checks or len(checks) > 256:
        raise ReproductionError("reproduced self-test report has no checks")
    if any(
        not isinstance(check, dict)
        or set(check) != CHECK_KEYS
        or not isinstance(check.get("name"), str)
        or not NAME.fullmatch(check["name"])
        or check.get("passed") is not True
        for check in checks
    ):
        raise ReproductionError("reproduced self-test contains an invalid or failed check")
    check_names = [check["name"] for check in checks]
    if len(set(check_names)) != len(check_names):
        raise ReproductionError("reproduced self-test contains duplicate check names")
    return {
        "schema": report["schema"],
        "crate_version": report["crate_version"],
        "passed": True,
        "public_vectors_only": True,
        "checks": check_names,
    }
