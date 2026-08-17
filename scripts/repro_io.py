#!/usr/bin/env python3
"""Bounded file and privacy-safe text helpers."""

from __future__ import annotations

from contextlib import contextmanager
import getpass
import os
from pathlib import Path
import platform
import re
import stat
from typing import BinaryIO, Iterator

from repro_types import MAX_TOOL_OUTPUT_CHARS, ReproductionError


@contextmanager
def bounded_regular_file(
    path: Path, limit: int, label: str
) -> Iterator[BinaryIO]:
    try:
        if path.is_symlink():
            raise ReproductionError(
                f"{label} must not be a symbolic link: {path.name}"
            )
        source = path.open("rb")
    except FileNotFoundError as error:
        raise ReproductionError(f"{label} does not exist: {path.name}") from error
    except OSError as error:
        raise ReproductionError(
            f"{label} could not be opened: {path.name}"
        ) from error

    try:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ReproductionError(f"{label} is not a regular file: {path.name}")
        if metadata.st_size > limit:
            raise ReproductionError(f"{label} exceeds {limit} bytes: {path.name}")
        yield source
    finally:
        source.close()


def private_evidence_tokens() -> tuple[str, ...]:
    try:
        current_user = getpass.getuser()
    except OSError:
        current_user = ""
    values = {
        os.environ.get("HOME", ""),
        os.environ.get("USER", ""),
        os.environ.get("USERNAME", ""),
        os.fspath(Path.home()),
        platform.node(),
        current_user,
    }
    retained = (value for value in values if len(value) >= 3)
    return tuple(sorted(retained, key=len, reverse=True))


def contains_absolute_path(value: str) -> bool:
    return bool(
        re.search(r"(?:^|[\s=])/\S+", value)
        or re.search(r"(?:^|[\s=])[A-Za-z]:[\\/][^\s]+", value)
        or re.search(r"(?:^|[\s=])\\\\[^\s]+", value)
    )


def validate_public_text(value: str, field: str) -> str:
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise ReproductionError(f"{field} contains a control character")
    if any(token in value for token in private_evidence_tokens()):
        raise ReproductionError(f"{field} contains host-specific private data")
    if contains_absolute_path(value):
        raise ReproductionError(f"{field} contains an absolute path")
    return value


def sanitize_public_text(value: str) -> str | None:
    value = value.strip()
    if not value or len(value) > MAX_TOOL_OUTPUT_CHARS:
        return None
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        return None
    for token in private_evidence_tokens():
        value = value.replace(token, "<redacted>")
    value = re.sub(r"(^|[\s=])/\S+", r"\1<path>", value)
    value = re.sub(
        r"(^|[\s=])[A-Za-z]:[\\/][^\s]+", r"\1<path>", value
    )
    value = re.sub(r"(^|[\s=])\\\\[^\s]+", r"\1<path>", value)
    return value
