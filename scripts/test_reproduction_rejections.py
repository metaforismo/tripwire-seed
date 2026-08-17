#!/usr/bin/env python3
"""Malformed candidate rejection tests for reproduction comparison."""

from pathlib import Path
import tempfile
import unittest

from reproduction_test_fixtures import MODULE, create_candidate, executable


class ReproductionRejectionTests(unittest.TestCase):
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

    def test_mismatch_and_rejections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference, reference_sum = create_candidate(
                root / "reference", executable()
            )
            reproduced, reproduced_sum = create_candidate(
                root / "reproduced", executable() + b"#"
            )
            self.assertEqual(
                self.run_case(
                    reference,
                    reference_sum,
                    reproduced,
                    reproduced_sum,
                    root / "mismatch.json",
                ),
                2,
            )
            cases = [
                create_candidate(root / "bad", executable(), bad_hash=True),
                create_candidate(root / "extra", executable(), extra="extra"),
                create_candidate(root / "meta", executable(), extra_meta=True),
            ]
            for index, (candidate, sidecar) in enumerate(cases):
                with self.subTest(index=index):
                    self.assertEqual(
                        self.run_case(
                            reference,
                            reference_sum,
                            candidate,
                            sidecar,
                            root / f"rejected-{index}.json",
                        ),
                        1,
                    )


if __name__ == "__main__":
    unittest.main()
