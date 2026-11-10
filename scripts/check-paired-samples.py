#!/usr/bin/env python3
"""Check extractors against a corpus that pairs artifacts with extracted hashes.

The corpus is the hashcat repository's `tools/2hashcat_tests` directory. Its
KeePass entries carry both hashcat (`*.hash`) and John (`*.keepass2john`)
serializations, and the GPG OCB-AES entries carry hashcat serializations. The
artifacts are cloned at run time and are not part of this repository.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "tmp" / "paired-samples"
REPO = WORK / "hashcat"
SAMPLES = REPO / "tools" / "2hashcat_tests"
REF = os.environ.get("OMNIEX_PAIRED_SAMPLES_REF", "master")


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, **kwargs)


def clone() -> None:
    if (REPO / ".git").is_dir():
        result = run(["git", "-C", str(REPO), "fetch", "--depth", "1", "origin", REF])
        if result.returncode != 0:
            raise SystemExit(f"fetch failed: {result.stderr}")
        result = run(["git", "-C", str(REPO), "checkout", "--detach", "FETCH_HEAD"])
        if result.returncode != 0:
            raise SystemExit(f"checkout failed: {result.stderr}")
        return
    WORK.mkdir(parents=True, exist_ok=True)
    result = run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            "--sparse",
            "--branch",
            REF,
            "https://github.com/hashcat/hashcat.git",
            str(REPO),
        ]
    )
    if result.returncode != 0:
        raise SystemExit(f"clone failed: {result.stderr}")
    result = run(["git", "-C", str(REPO), "sparse-checkout", "set", "tools/2hashcat_tests"])
    if result.returncode != 0:
        raise SystemExit(f"sparse checkout failed: {result.stderr}")


def binary() -> str:
    if path := os.environ.get("OMNIEX_BIN"):
        return path
    candidate = ROOT / "target" / "debug" / "omniex"
    if candidate.is_file():
        return str(candidate)
    found = shutil.which("omniex")
    if found:
        return found
    raise SystemExit("build omniex or set OMNIEX_BIN")


def render(binary_path: str, slug: str, artifact: Path, tool: str) -> list[str]:
    result = run(
        [
            binary_path,
            "extract",
            "--type",
            slug,
            "--format",
            tool,
            "--json",
            str(artifact),
        ]
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return [entry["hash"] for entry in json.loads(result.stdout)]


def expected(path: Path) -> list[str]:
    text = path.read_text()
    hashes = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line == "-":
            continue
        start = line.find("$")
        hashes.append(line[start:] if start >= 0 else line)
    return hashes


def compare(name: str, got: list[str], want: list[str], failures: list[str]) -> None:
    if got == want:
        print(f"ok   {name}")
        return
    failures.append(name)
    print(f"FAIL {name}")
    print(f"  expected: {want}")
    print(f"  actual:   {got}")


def check_keepass(binary_path: str, failures: list[str]) -> int:
    checked = 0
    for artifact in sorted((SAMPLES / "keepass").glob("*.kdbx")):
        hashcat_expected = artifact.with_suffix(".hash")
        john_expected = artifact.with_suffix(".keepass2john")
        if not hashcat_expected.is_file() or not john_expected.is_file():
            failures.append(f"missing expected output for {artifact.name}")
            continue
        try:
            compare(
                f"keepass/hashcat/{artifact.name}",
                render(binary_path, "keepass4", artifact, "hashcat"),
                expected(hashcat_expected),
                failures,
            )
            compare(
                f"keepass/john/{artifact.name}",
                render(binary_path, "keepass4", artifact, "john"),
                expected(john_expected),
                failures,
            )
            checked += 1
        except RuntimeError as error:
            failures.append(f"{artifact.name}: {error}")
            print(f"FAIL keepass/{artifact.name}: {error}")
    return checked


def check_gpg(binary_path: str, failures: list[str]) -> int:
    checked = 0
    directory = SAMPLES / "gpg-ocb-aes" / "private-keys-v1.d"
    for artifact in sorted(directory.glob("*.key")):
        hashcat_expected = artifact.with_suffix(artifact.suffix + ".hash")
        if not hashcat_expected.is_file():
            failures.append(f"missing expected output for {artifact.name}")
            continue
        try:
            compare(
                f"gpg/{artifact.name}",
                render(binary_path, "gpg", artifact, "hashcat"),
                expected(hashcat_expected),
                failures,
            )
            checked += 1
        except RuntimeError as error:
            failures.append(f"{artifact.name}: {error}")
            print(f"FAIL gpg/{artifact.name}: {error}")
    return checked


def main() -> int:
    clone()
    if not SAMPLES.is_dir():
        raise SystemExit(f"paired sample directory is missing: {SAMPLES}")
    binary_path = binary()
    failures: list[str] = []
    checked = check_keepass(binary_path, failures) + check_gpg(binary_path, failures)
    skipped = len(list((SAMPLES / "metamask").glob("*.json")))
    print()
    print(f"checked {checked} artifact(s), skipped {skipped} metamask input(s) without paired hashes")
    if failures:
        print(f"{len(failures)} failure(s)")
        return 1
    print("all paired samples matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
