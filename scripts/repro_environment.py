#!/usr/bin/env python3
"""Privacy-safe build environment evidence."""

from __future__ import annotations

import platform
import subprocess
from typing import Any, Sequence

from reproduction_support import Candidate, sanitize_public_text
from repro_selftest import self_test_environment


def command_output(command: Sequence[str]) -> str | None:
    try:
        result = subprocess.run(
            list(command),
            check=False,
            text=True,
            capture_output=True,
            timeout=15,
            env=self_test_environment(),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return sanitize_public_text(result.stdout)


def platform_value(value: str) -> str | None:
    return sanitize_public_text(value)


def environment_evidence(reproduction: Candidate) -> dict[str, Any]:
    local_rustc = command_output(["rustc", "--version", "--verbose"])
    local_cargo = command_output(["cargo", "--version", "--verbose"])
    return {
        "os": {
            "system": platform_value(platform.system()),
            "release": platform_value(platform.release()),
            "machine": platform_value(platform.machine()),
        },
        "python": {
            "implementation": platform_value(platform.python_implementation()),
            "version": platform_value(platform.python_version()),
        },
        "rustc": local_rustc,
        "cargo": local_cargo,
        "cc": command_output(["cc", "--version"]),
        "ld": command_output(["ld", "--version"]),
        "metadata_matches_current_tools": {
            "rustc": local_rustc == reproduction.metadata["rustc"],
            "cargo": local_cargo == reproduction.metadata["cargo"],
        },
        "build_contract": {
            "source_date_epoch": reproduction.metadata["source_date_epoch"],
            "cargo_incremental": "0",
            "linker_reproducibility_flags": reproduction.metadata[
                "linker_reproducibility_flags"
            ],
        },
    }
