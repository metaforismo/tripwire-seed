#!/usr/bin/env python3
"""Canonical ZIP member validation."""

from __future__ import annotations

import datetime as dt
from pathlib import PurePosixPath
import stat
import zipfile

from repro_types import MAX_MEMBER_BYTES, ReproductionError


def safe_member(info: zipfile.ZipInfo) -> tuple[str, str]:
    name = info.filename
    if "\x00" in name or "//" in name:
        raise ReproductionError("candidate ZIP member path is not canonical")
    if "\\" in name:
        raise ReproductionError("candidate ZIP uses a backslash path")
    path = PurePosixPath(name)
    if path.is_absolute() or len(path.parts) != 2:
        raise ReproductionError(f"candidate ZIP member path is invalid: {name}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ReproductionError(f"candidate ZIP member path is unsafe: {name}")
    if info.is_dir():
        raise ReproductionError(f"candidate ZIP contains a directory entry: {name}")
    if info.flag_bits & 0x1:
        raise ReproductionError(f"candidate ZIP contains an encrypted entry: {name}")
    if info.file_size > MAX_MEMBER_BYTES:
        raise ReproductionError(f"candidate ZIP member is oversized: {name}")
    if info.create_system != 3:
        raise ReproductionError(f"candidate ZIP member lacks Unix metadata: {name}")
    mode = info.external_attr >> 16
    if not stat.S_ISREG(mode):
        raise ReproductionError(f"candidate ZIP contains a non-regular file: {name}")
    if info.compress_type != zipfile.ZIP_DEFLATED:
        raise ReproductionError(f"candidate ZIP member is not deflated: {name}")
    if info.extra or info.comment:
        raise ReproductionError(
            f"candidate ZIP member has unexpected metadata: {name}"
        )
    return path.parts[0], path.parts[1]


def normalized_zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    instant = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    if instant.year < 1980:
        instant = instant.replace(
            year=1980, month=1, day=1, hour=0, minute=0, second=0
        )
    second = instant.second - (instant.second % 2)
    return (
        instant.year,
        instant.month,
        instant.day,
        instant.hour,
        instant.minute,
        second,
    )
