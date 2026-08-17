#!/usr/bin/env python3
"""Compare a separately built candidate without executing the reference binary."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Iterable

from repro_report import build_report, write_report
from repro_runtime import run_reproduced_self_test
from reproduction_support import (
    CANDIDATE_SCHEMA, PACKAGE_NAME, SELF_TEST_SCHEMA, ReproductionError,
    inspect_candidate, normalized_zip_datetime, read_sidecar, sha256_file,
)


def parse_arguments(arguments: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-candidate", required=True, type=Path)
    parser.add_argument("--reference-checksum", required=True, type=Path)
    parser.add_argument("--reproduced-candidate", required=True, type=Path)
    parser.add_argument("--reproduced-checksum", required=True, type=Path)
    parser.add_argument("--report-out", required=True, type=Path)
    parser.add_argument(
        "--execute-reproduced-self-test",
        action="store_true",
        help=(
            "explicitly execute the reproducer's local candidate self-test; "
            "without this flag the helper performs inspection only"
        ),
    )
    return parser.parse_args(arguments)


def main(arguments: Iterable[str] | None = None) -> int:
    options = parse_arguments(arguments)
    try:
        reference_sidecar_digest = read_sidecar(
            options.reference_checksum, options.reference_candidate.name
        )
        reproduction_sidecar_digest = read_sidecar(
            options.reproduced_checksum, options.reproduced_candidate.name
        )
        reference = inspect_candidate(options.reference_candidate)
        reproduction = inspect_candidate(options.reproduced_candidate)
        if reference_sidecar_digest != reference.archive_sha256:
            raise ReproductionError(
                "reference checksum sidecar does not match candidate archive"
            )
        if reproduction_sidecar_digest != reproduction.archive_sha256:
            raise ReproductionError(
                "reproduced checksum sidecar does not match candidate archive"
            )
        self_test = None
        if options.execute_reproduced_self_test:
            self_test = run_reproduced_self_test(reproduction)
        inspection_only = not options.execute_reproduced_self_test
        report = build_report(
            reference=reference,
            reproduction=reproduction,
            reference_sidecar_verified=True,
            reproduction_sidecar_verified=True,
            self_test=self_test,
            inspection_only=inspection_only,
        )
        write_report(options.report_out, report)
    except ReproductionError as error:
        print(f"reproduction error: {error}", file=sys.stderr)
        return 1

    if report["technical_comparison_complete"]:
        print(
            "candidate reproduction comparison: MATCH "
            "(administrative independence remains unverified)"
        )
        return 0
    if not options.execute_reproduced_self_test:
        print("candidate reproduction comparison: INSPECTION ONLY")
        return 3
    print("candidate reproduction comparison: MISMATCH")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
