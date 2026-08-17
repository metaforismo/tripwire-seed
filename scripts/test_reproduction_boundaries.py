#!/usr/bin/env python3
"""Boundary and evidence-file tests for reproduction comparison."""

from pathlib import Path, PurePosixPath
import tempfile
import unittest
import zipfile

from reproduction_test_fixtures import MODULE, create_candidate, executable


class ReproductionBoundaryTests(unittest.TestCase):
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

    def test_sidecar_version_no_overwrite_and_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference, reference_sum = create_candidate(
                root / "reference", executable()
            )
            versioned, versioned_sum = create_candidate(
                root / "versioned", executable("9.9.9")
            )
            self.assertEqual(
                self.run_case(
                    reference,
                    reference_sum,
                    versioned,
                    versioned_sum,
                    root / "version.json",
                ),
                1,
            )
            reference_sum.write_text(
                "0" * 64 + f"  {reference.name}\n", encoding="ascii"
            )
            self.assertEqual(
                self.run_case(
                    reference,
                    reference_sum,
                    versioned,
                    versioned_sum,
                    root / "sidecar.json",
                ),
                1,
            )
            reference, reference_sum = create_candidate(
                root / "reference2", executable()
            )
            report = root / "exists.json"
            report.write_text("keep")
            self.assertEqual(
                self.run_case(
                    reference,
                    reference_sum,
                    reference,
                    reference_sum,
                    report,
                ),
                1,
            )
            self.assertEqual(report.read_text(), "keep")

            source, _ = create_candidate(root / "path", executable())
            rewritten = root / "path" / source.name
            replacement = root / "replacement.zip"
            with zipfile.ZipFile(source) as old, zipfile.ZipFile(
                replacement, "w"
            ) as new:
                for index, info in enumerate(old.infolist()):
                    data = old.read(info)
                    if index == 0:
                        basename = PurePosixPath(info.filename).name
                        info.filename = f"../{basename}"
                    new.writestr(info, data)
            replacement.replace(rewritten)
            with self.assertRaises(MODULE.ReproductionError):
                MODULE.inspect_candidate(rewritten)


if __name__ == "__main__":
    unittest.main()
