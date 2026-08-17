#!/usr/bin/env python3
"""Unit tests for deterministic release-candidate packaging."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from reproducible_release import (
    METADATA_SCHEMA,
    create_archive,
    normalized_zip_datetime,
    sha256_file,
    write_checksum_sidecar,
)


class ReproducibleReleaseTests(unittest.TestCase):
    def test_zip_timestamp_is_utc_and_rounded_to_two_seconds(self) -> None:
        # 2024-01-02 03:24:05 UTC becomes the ZIP-representable even second.
        self.assertEqual(
            normalized_zip_datetime(1_704_165_845),
            (2024, 1, 2, 3, 24, 4),
        )

    def test_archive_is_byte_for_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in {
                "README.md": "readme\n",
                "LICENSE-MIT": "mit\n",
                "LICENSE-APACHE": "apache\n",
            }.items():
                (root / name).write_text(content, encoding="utf-8", newline="\n")

            metadata = {
                "schema": METADATA_SCHEMA,
                "commit": "11" * 20,
                "target": "x86_64-unknown-linux-gnu",
                "same_runner_double_build": True,
            }
            first = root / "first.zip"
            second = root / "second.zip"
            arguments = {
                "root": root,
                "binary_data": b"synthetic-public-test-binary\n",
                "binary_name": "tripwire-seed",
                "target": "x86_64-unknown-linux-gnu",
                "version": "0.1.0",
                "epoch": 1_704_165_845,
                "metadata": metadata,
            }
            create_archive(output_path=first, **arguments)
            create_archive(output_path=second, **arguments)
            self.assertEqual(first.read_bytes(), second.read_bytes())

            with zipfile.ZipFile(first) as archive:
                names = archive.namelist()
                self.assertEqual(names, sorted(names))
                metadata_name = next(
                    name for name in names if name.endswith("BUILD-METADATA.json")
                )
                parsed = json.loads(archive.read(metadata_name))
                self.assertEqual(parsed["schema"], METADATA_SCHEMA)
                executable = next(
                    name for name in names if name.endswith("/tripwire-seed")
                )
                mode = archive.getinfo(executable).external_attr >> 16
                self.assertEqual(mode & 0o777, 0o755)

    def test_checksum_sidecar_matches_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "candidate.zip"
            archive.write_bytes(b"candidate")
            sidecar = write_checksum_sidecar(archive)
            expected = f"{sha256_file(archive)}  {archive.name}\n"
            self.assertEqual(sidecar.read_text(encoding="ascii"), expected)


if __name__ == "__main__":
    unittest.main()
