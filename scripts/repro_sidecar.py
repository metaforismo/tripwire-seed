#!/usr/bin/env python3
"""Strict checksum-sidecar validation."""

from pathlib import Path
import re

from repro_io import bounded_regular_file
from repro_types import MAX_SIDECAR_BYTES, ReproductionError


def read_sidecar(sidecar: Path, candidate_name: str) -> str:
    if sidecar.name != f"{candidate_name}.sha256":
        raise ReproductionError("checksum sidecar filename is not canonical")
    with bounded_regular_file(sidecar, MAX_SIDECAR_BYTES, "checksum sidecar") as source:
        try:
            text = source.read().decode("ascii")
        except UnicodeDecodeError as error:
            raise ReproductionError("checksum sidecar is not ASCII") from error
    if "\r" in text or not text.endswith("\n") or len(text.splitlines()) != 1:
        raise ReproductionError("checksum sidecar is not canonically terminated")
    match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\\r\n]+)", text.rstrip("\n"))
    if match is None or match.group(2) != candidate_name:
        raise ReproductionError("checksum sidecar has an invalid shape")
    return match.group(1)
