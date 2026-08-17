#!/usr/bin/env python3
"""Fixtures for reproduction helper tests."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import stat
import sys
import zipfile

SCRIPT = Path(__file__).with_name("compare_reproduction.py")
SPEC = importlib.util.spec_from_file_location("compare_reproduction", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
TARGET = "x86_64-unknown-linux-gnu"
COMMIT = "1" * 40
VERSION = "0.1.0"


def executable(version=VERSION, marker=None):
    report = json.dumps(
        {
            "schema": MODULE.SELF_TEST_SCHEMA,
            "crate_version": version,
            "public_vectors_only": True,
            "passed": True,
            "checks": [{"name": "fixture", "passed": True}],
        },
        separators=(",", ":"),
    )
    touch = f"touch {shlex.quote(str(marker))}\n" if marker else ""
    return (
        "#!/bin/sh\n"
        + touch
        + 'if [ "$1" = "self-test" ] && [ "$2" = "--json" ]; then\n'
        + f"  printf '%s' '{report}'\nelse\n  exit 64\nfi\n"
    ).encode()


def create_candidate(
    directory, binary, *, extra=None, bad_hash=False, extra_meta=False
):
    directory.mkdir(parents=True, exist_ok=True)
    prefix = f"tripwire-seed-v{VERSION}-{TARGET}"
    archive = directory / f"{prefix}.zip"
    metadata = {
        "schema": MODULE.CANDIDATE_SCHEMA,
        "package": MODULE.PACKAGE_NAME,
        "version": VERSION,
        "commit": COMMIT,
        "target": TARGET,
        "source_date_epoch": 1_700_000_000,
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "same_runner_double_build": True,
        "rustc": "rustc fixture",
        "cargo": "cargo fixture",
        "linker_reproducibility_flags": [],
        "self_test_schema": MODULE.SELF_TEST_SCHEMA,
        "self_test_passed": True,
        "public_vectors_only": True,
    }
    if bad_hash:
        metadata["binary_sha256"] = "0" * 64
    if extra_meta:
        metadata["unexpected"] = True
    files = {
        "tripwire-seed": binary,
        "BUILD-METADATA.json": (
            json.dumps(metadata, sort_keys=True) + "\n"
        ).encode(),
        "README.md": b"readme\n",
        "LICENSE-MIT": b"mit\n",
        "LICENSE-APACHE": b"apache\n",
    }
    if extra:
        files[extra] = b"extra\n"
    stamp = MODULE.normalized_zip_datetime(1_700_000_000)
    with zipfile.ZipFile(archive, "w") as output:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(f"{prefix}/{name}", date_time=stamp)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            permission = 0o755 if name == "tripwire-seed" else 0o644
            info.external_attr = (stat.S_IFREG | permission) << 16
            output.writestr(
                info,
                data,
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
    sidecar = Path(f"{archive}.sha256")
    sidecar.write_text(
        f"{MODULE.sha256_file(archive)}  {archive.name}\n",
        encoding="ascii",
    )
    return archive, sidecar
