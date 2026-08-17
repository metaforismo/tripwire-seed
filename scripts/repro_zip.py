#!/usr/bin/env python3
"""Canonical ZIP layout validation for release candidates."""

from pathlib import Path
import stat
import zipfile

from repro_metadata import validate_metadata
from repro_types import (
    EXPECTED_DOCUMENTS, MAX_METADATA_BYTES, PACKAGE_NAME, ReproductionError,
)
from repro_zip_member import normalized_zip_datetime, safe_member


def validate_layout(archive: zipfile.ZipFile, path: Path):
    if archive.comment:
        raise ReproductionError("candidate ZIP has an unexpected archive comment")
    infos = archive.infolist()
    if len(infos) != 5:
        raise ReproductionError("candidate ZIP must contain exactly five files")
    names = [info.filename for info in infos]
    if names != sorted(names) or len(set(names)) != len(names):
        raise ReproductionError("candidate ZIP member names are not canonical")
    parsed = [safe_member(info) for info in infos]
    if archive.testzip() is not None:
        raise ReproductionError("candidate ZIP failed CRC validation")
    prefixes = {prefix for prefix, _ in parsed}
    if len(prefixes) != 1:
        raise ReproductionError("candidate ZIP has multiple top-level prefixes")
    prefix = next(iter(prefixes))
    files = {base: info for (_, base), info in zip(parsed, infos)}
    meta_info = files.get("BUILD-METADATA.json")
    if meta_info is None or meta_info.file_size > MAX_METADATA_BYTES:
        raise ReproductionError("candidate metadata is missing or oversized")
    try:
        import json
        metadata = validate_metadata(json.loads(archive.read(meta_info).decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReproductionError("candidate metadata is not valid UTF-8 JSON") from error
    target, version = metadata["target"], metadata["version"]
    expected_prefix = f"{PACKAGE_NAME}-v{version}-{target}"
    if prefix != expected_prefix or path.name != f"{expected_prefix}.zip":
        raise ReproductionError("candidate archive identity is not canonical")
    binary = f"{PACKAGE_NAME}.exe" if "windows" in target else PACKAGE_NAME
    if set(files) != {binary, "BUILD-METADATA.json", *EXPECTED_DOCUMENTS}:
        raise ReproductionError("candidate ZIP file set is not canonical")
    timestamp = normalized_zip_datetime(metadata["source_date_epoch"])
    for name, info in files.items():
        permission = 0o755 if name == binary else 0o644
        if stat.S_IMODE(info.external_attr >> 16) != permission:
            raise ReproductionError(f"candidate ZIP permissions are not canonical: {name}")
        if info.date_time != timestamp:
            raise ReproductionError(f"candidate ZIP timestamp is not canonical: {name}")
    return prefix, metadata, files, binary
