#!/usr/bin/env python3
"""Inspect candidate bytes after canonical ZIP validation."""

from __future__ import annotations

from pathlib import Path
import zipfile

from repro_io import bounded_regular_file
from repro_types import (
    Candidate, EXPECTED_DOCUMENTS, MAX_ARCHIVE_BYTES, MAX_UNCOMPRESSED_BYTES,
    ReproductionError, sha256_bytes, sha256_stream,
)
from repro_zip import validate_layout


def inspect_candidate(path: Path) -> Candidate:
    try:
        with bounded_regular_file(path, MAX_ARCHIVE_BYTES, "candidate archive") as source:
            archive_sha256 = sha256_stream(source)
            source.seek(0)
            with zipfile.ZipFile(source, "r") as archive:
                infos = archive.infolist()
                if sum(info.file_size for info in infos) > MAX_UNCOMPRESSED_BYTES:
                    raise ReproductionError("candidate ZIP uncompressed size exceeds limit")
                prefix, metadata, files, binary_name = validate_layout(archive, path)
                binary_bytes = archive.read(files[binary_name])
                binary_sha256 = sha256_bytes(binary_bytes)
                if binary_sha256 != metadata["binary_sha256"]:
                    raise ReproductionError("candidate binary does not match metadata SHA-256")
                documents = {
                    name: sha256_bytes(archive.read(files[name]))
                    for name in EXPECTED_DOCUMENTS
                }
    except zipfile.BadZipFile as error:
        raise ReproductionError(f"candidate archive is not a valid ZIP: {path.name}") from error
    return Candidate(
        path.name, archive_sha256, prefix, metadata, binary_name,
        binary_sha256, binary_bytes, documents,
    )
