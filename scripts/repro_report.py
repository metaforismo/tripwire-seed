#!/usr/bin/env python3
"""Privacy-safe reproduction report construction."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any, Mapping

from repro_compare import candidate_summary, compare_candidates
from repro_environment import environment_evidence
from reproduction_support import Candidate, ReproductionError

REPORT_SCHEMA = "tripwire-seed/independent-reproduction/v1"


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(report, output, sort_keys=True, indent=2, ensure_ascii=True)
            output.write("\n")
    except FileExistsError as error:
        raise ReproductionError(f"report path already exists: {path.name}") from error


def build_report(
    *,
    reference: Candidate,
    reproduction: Candidate,
    reference_sidecar_verified: bool,
    reproduction_sidecar_verified: bool,
    self_test: Mapping[str, Any] | None,
    inspection_only: bool,
) -> dict[str, Any]:
    comparison = compare_candidates(reference, reproduction)
    technical_complete = (
        reference_sidecar_verified
        and reproduction_sidecar_verified
        and not inspection_only
        and self_test is not None
        and comparison["identity_match"]
        and comparison["binary_match"]
        and comparison["package_documents_match"]
        and comparison["build_contract_match"]
    )
    return {
        "schema": REPORT_SCHEMA,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "repository": "https://github.com/metaforismo/tripwire-seed",
        "comparison_scope": {
            "reference_commit": reference.metadata["commit"],
            "reproduction_commit": reproduction.metadata["commit"],
            "reference_target": reference.metadata["target"],
            "reproduction_target": reproduction.metadata["target"],
        },
        "reference": candidate_summary(reference, reference_sidecar_verified),
        "reproduction": candidate_summary(
            reproduction, reproduction_sidecar_verified
        ),
        "comparison": comparison,
        "reproduced_self_test": self_test,
        "environment": environment_evidence(reproduction),
        "inspection_only": inspection_only,
        "technical_comparison_complete": technical_complete,
        "execution": {
            "reference_binary_executed": False,
            "reproduced_binary_executed": not inspection_only,
        },
        "administrative_independence_verified": False,
        "all_supported_targets_complete": False,
        "stable_release_gate_satisfied": False,
        "operator_independence_review_required": True,
        "privacy": {
            "wallet_material_recorded": False,
            "absolute_paths_recorded": False,
            "hostnames_recorded": False,
            "usernames_recorded": False,
        },
        "boundary": (
            "This report validates bytes and declared metadata. It does not prove "
            "that the source, compiler, dependencies, or two build environments "
            "were independently administered or uncompromised."
        ),
    }
