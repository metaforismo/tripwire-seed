#!/usr/bin/env python3
"""Core success and execution-boundary tests for reproduction comparison."""

import json
from pathlib import Path
import tempfile
import unittest

from repro_report import build_report
from reproduction_test_fixtures import MODULE, create_candidate, executable


class ReproductionCoreTests(unittest.TestCase):
    def run_case(self, ref, refsum, rep, repsum, report, execute=True):
        arguments = [
            "--reference-candidate", str(ref),
            "--reference-checksum", str(refsum),
            "--reproduced-candidate", str(rep),
            "--reproduced-checksum", str(repsum),
            "--report-out", str(report),
        ]
        if execute:
            arguments.append("--execute-reproduced-self-test")
        return MODULE.main(arguments)

    def test_match_and_safe_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = executable()
            reference, reference_sum = create_candidate(root / "reference", binary)
            reproduced, reproduced_sum = create_candidate(root / "reproduced", binary)
            full_path = root / "full.json"
            self.assertEqual(
                self.run_case(
                    reference, reference_sum, reproduced, reproduced_sum, full_path
                ),
                0,
            )
            full = json.loads(full_path.read_text())
            self.assertTrue(full["technical_comparison_complete"])
            self.assertFalse(full["administrative_independence_verified"])

            marker = root / "inspection-marker"
            inspected_candidate, inspected_sum = create_candidate(
                root / "inspection", executable(marker=marker)
            )
            inspect_path = root / "inspect.json"
            self.assertEqual(
                self.run_case(
                    inspected_candidate,
                    inspected_sum,
                    inspected_candidate,
                    inspected_sum,
                    inspect_path,
                    False,
                ),
                3,
            )
            inspected = json.loads(inspect_path.read_text())
            self.assertFalse(inspected["execution"]["reference_binary_executed"])
            self.assertFalse(inspected["execution"]["reproduced_binary_executed"])
            self.assertFalse(marker.exists())

    def test_reference_never_executes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "marker"
            reference, reference_sum = create_candidate(
                root / "reference", executable(marker=marker)
            )
            reproduced, reproduced_sum = create_candidate(
                root / "reproduced", executable()
            )
            self.assertEqual(
                self.run_case(
                    reference,
                    reference_sum,
                    reproduced,
                    reproduced_sum,
                    root / "out.json",
                ),
                2,
            )
            self.assertFalse(marker.exists())

    def test_unverified_sidecar_cannot_complete_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, _ = create_candidate(root / "candidate", executable())
            candidate = MODULE.inspect_candidate(archive)
            report = build_report(
                reference=candidate,
                reproduction=candidate,
                reference_sidecar_verified=False,
                reproduction_sidecar_verified=True,
                self_test={"passed": True},
                inspection_only=False,
            )
            self.assertFalse(report["technical_comparison_complete"])


if __name__ == "__main__":
    unittest.main()
