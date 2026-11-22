#!/usr/bin/env python3
"""Run encrypted-artifact extraction tests against external sample repositories.

Manifests live under ``repos/<id>/manifest.toml``. Artifacts are fetched on
demand from a pinned commit or read from a local checkout supplied with
``--source <id>=<path>``. The cache lives under ``tmp/external-samples``.

The default oracle is a reference extractor command (John ``*2john`` or a
hashcat ``*2hashcat`` script). Both the reference output and the omniex output
are parsed into fields with ``omniex parse`` and compared field by field.
"""

from __future__ import annotations

import argparse
import binascii
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "scripts" / "external-samples"
REPOS = BASE / "repos"
LOCKS = BASE / "locks"
CACHE = ROOT / "tmp" / "external-samples"
WORK = CACHE / "work"

ALLOWED_MANIFEST = {"id", "repo", "commit", "notes", "fetch", "case"}
ALLOWED_CASE = {
    "name",
    "path",
    "glob",
    "slug",
    "reference",
    "format",
    "args",
    "omniex_args",
    "ignore_fields",
    "ordered",
    "fetch",
    "reference_path",
    "reference_format",
    "subset",
    "requires",
    "companions",
    "decode",
    "filter",
    "exclude",
    "normalize",
    "reference_subset",
    "env",
}
ALLOWED_FETCH = {"mode"}


@dataclass
class Case:
    repo: str
    name: str
    path: str
    slug: str
    reference: str
    format: str
    args: list[str] = field(default_factory=list)
    omniex_args: list[str] = field(default_factory=list)
    ignore_fields: list[str] = field(default_factory=list)
    ordered: bool = False
    fetch: str = "file"
    reference_path: str = ""
    reference_format: str = ""
    subset: bool = False
    reference_subset: bool = False
    requires: list[str] = field(default_factory=list)
    companions: list[str] = field(default_factory=list)
    decode: str = ""
    normalize: str = ""
    exclude: list[str] = field(default_factory=list)
    filter: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class Manifest:
    ident: str
    repo: str
    commit: str
    cases: list[dict]
    mode: str = "file"
    notes: str = ""


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def require(data: dict, key: str, where: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        fail(f"{where}: missing string `{key}`")
    return value


def load_manifests(only: list[str]) -> list[Manifest]:
    manifests = []
    if not REPOS.is_dir():
        fail(f"missing manifest directory: {REPOS}")
    for path in sorted(REPOS.glob("*/manifest.toml")):
        with path.open("rb") as handle:
            data = tomllib.load(handle)
        unknown = set(data) - ALLOWED_MANIFEST
        if unknown:
            fail(f"{path}: unknown manifest keys: {sorted(unknown)}")
        fetch = data.get("fetch", {})
        if not isinstance(fetch, dict):
            fail(f"{path}: `fetch` must be a table")
        unknown_fetch = set(fetch) - ALLOWED_FETCH
        if unknown_fetch:
            fail(f"{path}: unknown fetch keys: {sorted(unknown_fetch)}")
        manifest = Manifest(
            ident=require(data, "id", path),
            repo=require(data, "repo", path),
            commit=require(data, "commit", path),
            cases=data.get("case", []),
            mode=fetch.get("mode", "file"),
            notes=str(data.get("notes", "")),
        )
        if not isinstance(manifest.cases, list):
            fail(f"{path}: `case` must be an array of tables")
        if only and manifest.ident not in only:
            continue
        for case in manifest.cases:
            if not isinstance(case, dict):
                fail(f"{path}: each case must be a table")
            unknown_case_keys = set(case) - ALLOWED_CASE
            if unknown_case_keys:
                fail(f"{path}: unknown case keys: {sorted(unknown_case_keys)}")
        manifests.append(manifest)
    if only:
        found = {manifest.ident for manifest in manifests}
        missing = sorted(set(only) - found)
        if missing:
            fail(f"unknown repo(s): {', '.join(missing)}")
    return manifests


def source_from_environment(ident: str) -> Path | None:
    env_key = "OMNIEX_SOURCE_" + "".join(
        character if character.isalnum() else "_" for character in ident.upper()
    )
    value = os.environ.get(env_key)
    return Path(value).resolve() if value else None


def parse_sources(values: list[str]) -> dict[str, Path]:
    sources = {}
    for value in values:
        if "=" not in value:
            fail(f"--source expects ID=PATH, got `{value}`")
        ident, path = value.split("=", 1)
        root = Path(path).expanduser().resolve()
        if not root.is_dir():
            fail(f"source for `{ident}` is not a directory: {root}")
        sources[ident] = root
    return sources


def git_output(checkout: Path, *args: str) -> str:
    result = timed_run(
        ["git", "-C", str(checkout), *args],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        fail(f"git {' '.join(args)} failed in {checkout}: {result.stderr.strip()}")
    return result.stdout.strip()


def local_head(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    try:
        return git_output(root, "rev-parse", "HEAD")
    except SystemExit:
        return None


def checkout_for(manifest: Manifest, paths: list[str]) -> Path:
    dest = CACHE / "checkouts" / manifest.ident / manifest.commit
    if (dest / ".git").is_dir():
        head = git_subprocess(dest, ["rev-parse", "HEAD"])
        if head == manifest.commit:
            sparse = sorted({path.strip("/") for path in paths if path.strip("/")})
            if sparse:
                timed_run(
                    ["git", "-C", str(dest), "sparse-checkout", "add", *sparse],
                    check=True,
                    capture_output=True,
                )
            return dest
        # A stale checkout at a different commit is rebuilt below.
        shutil.rmtree(dest, ignore_errors=True)

    if not dest.parent.is_dir():
        dest.parent.mkdir(parents=True, exist_ok=True)
    timed_run(["git", "init", "-q", str(dest)], check=True)
    timed_run(
        ["git", "-C", str(dest), "remote", "add", "origin", manifest.repo],
        check=True,
    )
    fetch = timed_run(
        ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", manifest.commit],
        text=True,
        capture_output=True,
    )
    if fetch.returncode != 0:
        fail(
            f"cannot fetch {manifest.repo} at {manifest.commit}: "
            f"{fetch.stderr.strip()}"
        )
    timed_run(
        ["git", "-C", str(dest), "sparse-checkout", "init", "--cone"],
        check=True,
        capture_output=True,
    )
    sparse = sorted({path.strip("/") for path in paths if path.strip("/")})
    if sparse:
        timed_run(
            ["git", "-C", str(dest), "sparse-checkout", "set", *sparse],
            check=True,
            capture_output=True,
        )
    timed_run(
        ["git", "-C", str(dest), "checkout", "-q", "--detach", "FETCH_HEAD"],
        check=True,
        capture_output=True,
    )
    return dest


def git_subprocess(checkout: Path, args: list[str]) -> str | None:
    result = timed_run(
        ["git", "-C", str(checkout), *args],
        text=True,
        capture_output=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def github_raw_url(manifest: Manifest, path: str) -> str:
    repo = manifest.repo.rstrip("/")
    if repo.startswith("https://github.com/"):
        owner_repo = repo[len("https://github.com/") :]
        return (
            f"https://raw.githubusercontent.com/{owner_repo}/"
            f"{manifest.commit}/{urllib.parse.quote(path)}"
        )
    fail(f"unsupported repository URL for direct fetch: {manifest.repo}")


def github_media_url(manifest: Manifest, path: str) -> str:
    repo = manifest.repo.rstrip("/")
    if repo.startswith("https://github.com/"):
        owner_repo = repo.removeprefix("https://github.com/")
        return (
            "https://media.githubusercontent.com/media/"
            f"{owner_repo}/{commit_path(manifest, path)}"
        )
    fail(f"unsupported repository URL for LFS fetch: {manifest.repo}")


def commit_path(manifest: Manifest, path: str) -> str:
    return f"{manifest.commit}/{urllib.parse.quote(path)}"


def timed_run(command: list[str], **kwargs):
    start = time.monotonic()
    result = subprocess.run(command, **kwargs)
    elapsed = time.monotonic() - start
    print(f"[time] {elapsed:8.3f}s {' '.join(str(part) for part in command)}", file=sys.stderr, flush=True)
    return result


def timed_fetch(label: str, fetch):
    start = time.monotonic()
    try:
        return fetch()
    finally:
        elapsed = time.monotonic() - start
        print(f"[time] {elapsed:8.3f}s {label}", file=sys.stderr, flush=True)


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "omniex-samples"})

    def fetch() -> bytes:
        with urllib.request.urlopen(request, timeout=60) as response:
            return request_read(response)

    try:
        return timed_fetch(f"download {url}", fetch)
    except urllib.error.HTTPError as error:
        fail(f"download failed ({url}): HTTP {error.code}")
    except urllib.error.URLError as error:
        fail(f"download failed ({url}): {error.reason}")


def request_path(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "omniex-samples"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return request_read(response).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        fail(f"download failed ({url}): HTTP {error.code}")
    except urllib.error.URLError as error:
        fail(f"download failed ({url}): {error.reason}")


def request_read(response) -> bytes:
    chunks = []
    while True:
        chunk = response.read(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def is_lfs_pointer(data: bytes) -> bool:
    return data.startswith(b"version https://git-lfs.github.com/spec/v1")


def load_lock(manifest: Manifest) -> dict[str, str]:
    path = LOCKS / f"{manifest.ident}.toml"
    if not path.is_file():
        return {}
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return {entry["path"]: entry["sha256"] for entry in data.get("file", [])}


def verify_lock(manifest: Manifest, path: str, artifact: Path) -> None:
    expected = LOCKS_BY_REPO.get(manifest.ident, {}).get(path)
    if expected is None:
        return
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual != expected:
        fail(
            f"{manifest.ident}: artifact hash mismatch for {path}\n"
            f"  expected {expected}\n  actual   {actual}"
        )


def make_readable(path: Path) -> None:
    path.chmod(0o644)
    for directory in path.parents:
        directory.chmod(0o755)
        if directory == CACHE:
            break


def fetch_file(manifest: Manifest, path: str, offline: bool) -> Path:
    dest = CACHE / "files" / manifest.ident / manifest.commit / path
    if dest.is_file():
        make_readable(dest)
        verify_lock(manifest, path, dest)
        return dest
    if offline:
        fail(f"offline mode: missing cached artifact {dest}")
    data = download(github_raw_url(manifest, path))
    if is_lfs_pointer(data):
        data = download(github_media_url(manifest, path))
    dest.parent.mkdir(parents=True, exist_ok=True)
    temporary = dest.with_suffix(dest.suffix + ".part")
    temporary.write_bytes(data)
    temporary.replace(dest)
    make_readable(dest)
    verify_lock(manifest, path, dest)
    return dest


def artifact_path(
    manifest: Manifest,
    case: Case,
    sources: dict[str, Path],
    offline: bool,
) -> Path:
    if manifest.ident in sources:
        primary = sources[manifest.ident] / case.path
    else:
        if manifest.repo == "local":
            fail(f"{manifest.ident}: a local source is required (--source {manifest.ident}=PATH)")
        if case.fetch == "tree":
            checkout = checkout_for(manifest, [case.path.rstrip("/")])
            primary = checkout / case.path
        else:
            primary = fetch_file(manifest, case.path, offline)

    for companion in case.companions:
        companion = render_template(companion, case.path)
        try:
            fetch_file(manifest, companion, offline)
        except SystemExit:
            if not case.companions:
                raise

    return decoded_path(manifest, case, primary)


def decoded_path(manifest: Manifest, case: Case, primary: Path) -> Path:
    if not case.decode:
        return primary

    dest = WORK / "decoded" / manifest.ident / f"{case.name}{primary.suffix}.decoded"
    dest.parent.mkdir(parents=True, exist_ok=True)

    if case.decode == "uu":
        decode_uu(primary, dest)
    else:
        fail(f"{manifest.ident}/{case.name}: unknown decode value `{case.decode}`")

    return dest


def decode_uu(source: Path, dest: Path) -> None:
    output = bytearray()
    started = False
    ended = False

    for line in source.read_bytes().splitlines():
        if not started:
            if line.startswith(b"begin "):
                started = True
            continue
        if line.strip() == b"end":
            ended = True
            break
        try:
            output.extend(binascii.a2b_uu(line))
        except binascii.Error as error:
            fail(f"{source}: invalid uuencode data: {error}")

    if not started:
        fail(f"{source}: missing uuencode `begin` line")
    if not ended:
        fail(f"{source}: missing uuencode `end` line")

    dest.write_bytes(output)
    make_readable(dest)


def glob_prefix(pattern: str) -> str:
    parts = Path(pattern).parts
    prefix = []
    for part in parts:
        if any(character in part for character in "*?["):
            break
        prefix.append(part)
    return str(Path(*prefix)) if prefix else ""


def expand_cases(
    manifest: Manifest,
    sources: dict[str, Path],
    offline: bool,
) -> list[Case]:
    expanded: list[Case] = []
    local_root = sources.get(manifest.ident)
    for raw in manifest.cases:
        slug = raw.get("slug")
        if not isinstance(slug, str) or not slug:
            fail(f"{manifest.ident}: case is missing `slug`")
        reference = raw.get("reference")
        if not isinstance(reference, str) or not reference:
            fail(f"{manifest.ident}: case `{raw.get('name', slug)}` is missing `reference`")
        base = Case(
            repo=manifest.ident,
            name=str(raw.get("name", "")),
            path=str(raw.get("path", "")),
            slug=slug,
            reference=reference,
            format=str(raw.get("format", "")),
            args=list(raw.get("args", [])),
            omniex_args=list(raw.get("omniex_args", [])),
            ignore_fields=list(raw.get("ignore_fields", [])),
            ordered=bool(raw.get("ordered", False)),
            fetch=str(raw.get("fetch", manifest.mode)),
            reference_path=str(raw.get("reference_path", "")),
            reference_format=str(raw.get("reference_format", "")),
            subset=bool(raw.get("subset", False)),
            reference_subset=bool(raw.get("reference_subset", False)),
            requires=list(raw.get("requires", [])),
            companions=list(raw.get("companions", [])),
            decode=str(raw.get("decode", "")),
            normalize=str(raw.get("normalize", "")),
            filter=list(raw.get("filter", [])),
            exclude=list(raw.get("exclude", [])),
            env={str(key): str(value) for key, value in raw.get("env", {}).items()},
        )
        pattern = raw.get("glob")
        if pattern is not None:
            if not isinstance(pattern, str) or not pattern:
                fail(f"{manifest.ident}: `glob` must be a non-empty string")
            root = local_root
            if root is None:
                prefix = glob_prefix(pattern)
                if prefix == pattern:
                    prefix = str(Path(prefix).parent)
                checkout = checkout_for(manifest, [prefix] if prefix else [""])
                root = checkout
            matches = sorted(
                path
                for path in root.glob(pattern)
                if path.is_file()
                and not any(
                    fnmatch.fnmatch(path.relative_to(root).as_posix(), excluded)
                    for excluded in base.exclude
                )
            )
            if not matches:
                fail(f"{manifest.ident}: glob matched nothing: {pattern}")
            for match in matches:
                relative = match.relative_to(root).as_posix()
                case = Case(**vars(base))
                case.path = relative
                case.name = render_template(base.name or "{stem}", relative)
                expanded.append(case)
        else:
            if not base.path:
                fail(f"{manifest.ident}: case `{base.name or slug}` is missing `path` or `glob`")
            if base.path.endswith("/"):
                base.fetch = "tree"
            base.name = render_template(base.name or "{base}", base.path)
            expanded.append(base)
    return expanded


def render_template(template: str, path: str, extra: dict[str, str] | None = None) -> str:
    path_object = Path(path)
    values = {
        "path": path,
        "dir": path_object.parent.as_posix(),
        "name": path_object.name,
        "stem": str(path_object.with_suffix("")),
        "basename": path_object.stem,
        "base": path_object.stem,
        "root": str(ROOT),
    }
    if extra:
        values.update(extra)
    return template.format_map(values)


def resolve_reference(manifest: Manifest, case: Case, artifact: Path) -> tuple[str, str, Path | None]:
    kind, _, value = case.reference.partition(":")
    if kind not in {"john", "hashcat", "paired", "expected", "structural"}:
        fail(f"{manifest.ident}/{case.name}: unknown reference kind `{kind}`")
    if kind == "structural":
        return kind, value, None
    if kind in {"paired", "expected"}:
        if manifest.ident in SOURCES:
            root = SOURCES[manifest.ident]
        elif manifest.repo == "local":
            fail(f"{manifest.ident}: a local source is required (--source {manifest.ident}=PATH)")
        else:
            root = CACHE / "checkouts" / manifest.ident / manifest.commit
            if not root.is_dir():
                root = checkout_for(manifest, [""])
        rendered = render_template(value, case.path)
        return kind, value, root / rendered
    reference_format = "john" if kind == "john" else "hashcat"
    return kind, value, None


def reference_command(kind: str, script: str, artifact: Path, args: list[str]) -> list[str]:
    if kind == "john":
        run_dir = john_run()
        if run_dir is None:
            fail("OMNIEX_JOHN_RUN or OMNIEX_JOHN is required for John references")
        path = run_dir / script
        if not path.exists():
            fail(f"John reference script is missing: {path}")
        return interpreter_command(path) + [*args, str(artifact)]
    if kind == "hashcat":
        tools = hashcat_tools()
        if tools is None:
            fail("OMNIEX_HASHCAT_TOOLS or OMNIEX_HASHCAT is required for hashcat references")
        path = tools / script
        if not path.exists():
            fail(f"hashcat reference script is missing: {path}")
        return interpreter_command(path) + [*args, str(artifact)]
    fail(f"unsupported reference kind: {kind}")


def interpreter_command(path: Path) -> list[str]:
    if path.suffix == ".py":
        return [sys.executable, str(path)]
    if path.suffix == ".pl":
        return ["perl", str(path)]
    return [str(path)]


def john_run() -> Path | None:
    if value := os.environ.get("OMNIEX_JOHN_RUN"):
        return Path(value)
    if value := os.environ.get("OMNIEX_JOHN"):
        return Path(value).parent
    return None


def hashcat_tools() -> Path | None:
    if value := os.environ.get("OMNIEX_HASHCAT_TOOLS"):
        return Path(value)
    binary = os.environ.get("OMNIEX_HASHCAT")
    if binary:
        tools = Path(binary).parent / "tools"
        return tools if tools.is_dir() else None
    return None


def omniex_binary() -> Path:
    if value := os.environ.get("OMNIEX_BIN"):
        return Path(value)
    release = ROOT / "target" / "debug" / "omniex"
    if release.is_file():
        return release
    found = shutil.which("omniex")
    if found:
        return Path(found)
    fail("build omniex or set OMNIEX_BIN")


def run_command(
    command: list[str],
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> str:
    env = {**os.environ, **extra_env} if extra_env else None
    result = timed_run(command, cwd=cwd, env=env, text=True, capture_output=True)
    if result.returncode != 0:
        fail(
            f"command failed ({' '.join(command)}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def normalize_reference(text: str, mode: str) -> list[str]:
    lines = [line.strip() for line in text.splitlines()]
    lines = [line for line in lines if line and line != "-"]
    if mode == "raw":
        return [line.rsplit(":", 1)[-1] for line in lines]
    if mode in {"hash", "bks"}:
        normalized = []
        for line in lines:
            index = line.find("$")
            if index < 0:
                continue
            else:
                value = line[index:]
                last = value.rfind("$")
                if last >= 0 and ":" in value[last + 1 :]:
                    value = value[: last + 1 + value[last + 1 :].find(":")]
            if mode == "bks":
                value = "$".join(
                    field[2:-1]
                    if field.startswith("b'") and field.endswith("'")
                    else field
                    for field in value.split("$")
                )
            normalized.append(value)
        return normalized
    return lines


def fields_for_hash(binary: Path, slug: str, format_name: str, hash_text: str) -> list[dict]:
    WORK.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", dir=WORK, suffix=".hash", delete=False, encoding="utf-8"
    )
    try:
        handle.write(hash_text)
        handle.write("\n")
        handle.close()
        output = run_command(
            [
                str(binary),
                "parse",
                "--type",
                slug,
                "--format",
                "json",
                "--tool",
                "json",
                "--file",
                handle.name,
            ]
        )
    finally:
        Path(handle.name).unlink(missing_ok=True)
    document = json.loads(output)
    entries = document["results"]
    if entries:
        return [
            {"name": name, **data}
            for name, data in entries[0]["hash"]["fields"].items()
        ]
    return []


def extract(binary: Path, slug: str, format_name: str, artifact: Path, args: list[str]) -> list[dict]:
    output = run_command(
        [
            str(binary),
            "extract",
            "--type",
            slug,
            "--format",
            "json",
            "--tool",
            "json",
            *args,
            str(artifact),
        ]
    )
    return json.loads(output)["results"]


def comparable(hashes: list[list[dict]], ignore: list[str]) -> list[tuple[tuple[str, str], ...]]:
    return [
        tuple(
            sorted(
                (entry["name"], str(entry.get("value", "")))
                for entry in fields
                if entry["name"] not in ignore
            )
        )
        for fields in hashes
    ]


def compare(
    name: str,
    got: list[list[dict]],
    want: list[list[dict]],
    ignore: list[str],
    ordered: bool,
    subset: bool = False,
    reference_subset: bool = False,
) -> None:
    got_fields = comparable(got, ignore)
    want_fields = comparable(want, ignore)
    if reference_subset:
        missing = [entry for entry in got_fields if entry not in want_fields]
        if not missing:
            print(f"ok   {name}")
            return
    if subset:
        missing = [entry for entry in want_fields if entry not in got_fields]
        if not missing:
            print(f"ok   {name}")
            return
    if not ordered:
        got_fields = sorted(got_fields)
        want_fields = sorted(want_fields)
    if got_fields == want_fields:
        print(f"ok   {name}")
        return
    print(f"FAIL {name}")
    print(f"  expected fields: {want_fields}")
    print(f"  actual fields:   {got_fields}")
    raise SystemExit(1)


def run_case(manifest: Manifest, case: Case, sources: dict[str, Path], offline: bool) -> bool:
    for requirement in case.requires:
        kind, _, name = requirement.partition(":")
        if kind == "perl":
            result = timed_run(
                ["perl", f"-M{name}", "-e", "1"],
                capture_output=True,
            )
            if result.returncode != 0:
                print(f"skip {manifest.ident}/{case.name}: Perl module `{name}` is missing")
                return True
        elif kind == "python":
            result = timed_run(
                [sys.executable, "-c", f"import {name}"],
                capture_output=True,
            )
            if result.returncode != 0:
                print(f"skip {manifest.ident}/{case.name}: Python module `{name}` is missing")
                return True
        elif kind == "tool":
            if shutil.which(name) is None:
                print(f"skip {manifest.ident}/{case.name}: tool `{name}` is missing")
                return True
        else:
            fail(f"{manifest.ident}/{case.name}: unknown requirement `{requirement}`")
    artifact = artifact_path(manifest, case, sources, offline)
    if not artifact.exists():
        fail(f"{manifest.ident}/{case.name}: artifact is missing: {artifact}")
    format_name = case.format or ("john" if case.reference.startswith("john:") else "hashcat")
    binary = omniex_binary()
    wanted = extract(
        binary,
        case.slug,
        format_name,
        artifact,
        [
            render_template(arg, case.path, {"artifact_dir": str(artifact.parent)})
            for arg in case.omniex_args
        ],
    )
    if not wanted:
        fail(f"{manifest.ident}/{case.name}: omniex extracted no `{case.slug}` hash")

    reference_artifact = artifact
    if case.reference_path:
        reference_case = Case(**{**vars(case), "path": render_template(case.reference_path, case.path)})
        if reference_case.path.endswith("/"):
            reference_case.fetch = "tree"
        reference_artifact = artifact_path(manifest, reference_case, sources, offline)
    if case.filter:
        command = [
            render_template(
                arg,
                str(reference_artifact),
                {
                    "artifact": str(reference_artifact),
                    "artifact_dir": str(reference_artifact.parent),
                },
            )
            for arg in case.filter
        ]
        output = run_command(command)
        WORK.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(case.name.encode("utf-8")).hexdigest()[:16]
        prepared = WORK / f"{manifest.ident}-{digest}.filtered"
        prepared.write_text(output, encoding="utf-8")
        reference_artifact = prepared
    kind, value, reference_path = resolve_reference(manifest, case, reference_artifact)
    if kind == "structural":
        print(f"ok   {manifest.ident}/{case.name} (structural, {len(wanted)} hash(es))")
        return

    if kind in {"paired", "expected"}:
        if reference_path is None or not reference_path.is_file():
            fail(f"{manifest.ident}/{case.name}: reference file is missing: {reference_path}")
        reference_text = reference_path.read_text(encoding="utf-8")
        normalize = "hash"
    else:
        reference_args = [
            render_template(arg, case.path, {"artifact_dir": str(reference_artifact.parent)})
            for arg in case.args
        ]
        command = reference_command(kind, value, reference_artifact, reference_args)
        reference_text = run_command(
            command,
            cwd=john_run() if kind == "john" else None,
            extra_env=case.env,
        )
        normalize = case.normalize or (
            "bks" if case.slug in {"bks", "vmx-keysafe", "sappse"} else "hash"
        )

    reference_lines = normalize_reference(reference_text, normalize)
    if not reference_lines:
        fail(f"{manifest.ident}/{case.name}: reference produced no hashes")
    reference_format = case.reference_format or format_name
    reference_fields = [
        fields_for_hash(binary, case.slug, reference_format, line)
        for line in reference_lines
    ]
    reference_fields = [fields for fields in reference_fields if fields]
    if not reference_fields:
        fail(f"{manifest.ident}/{case.name}: no reference hash could be parsed")

    got = [
        [{"name": name, **data} for name, data in entry["hash"]["fields"].items()]
        for entry in wanted
    ]
    compare(
        f"{manifest.ident}/{case.name}",
        got,
        reference_fields,
        case.ignore_fields,
        case.ordered,
        case.subset,
        case.reference_subset,
    )
    return False


def command_list(args: argparse.Namespace) -> None:
    for manifest in load_manifests(args.repo):
        for case in expand_cases(manifest, SOURCES, args.offline):
            print(f"{manifest.ident}\t{case.name}\t{case.path}\t{case.slug}\t{case.reference}")


def command_fetch(args: argparse.Namespace) -> None:
    for manifest in load_manifests(args.repo):
        for case in expand_cases(manifest, SOURCES, args.offline):
            if case.fetch == "tree":
                checkout_for(manifest, [case.path.rstrip("/")])
            else:
                fetch_file(manifest, case.path, args.offline)
            print(f"fetched {manifest.ident}/{case.name}")


def command_lock(args: argparse.Namespace) -> None:
    LOCKS.mkdir(parents=True, exist_ok=True)
    for manifest in load_manifests(args.repo):
        lines = [f'commit = "{manifest.commit}"', ""]
        for case in expand_cases(manifest, SOURCES, args.offline):
            if case.fetch == "tree":
                checkout = checkout_for(manifest, [case.path.rstrip("/")])
                tree_oid = git_subprocess(checkout, ["rev-parse", f"HEAD:{case.path.rstrip('/')}"])
                if tree_oid is None:
                    fail(f"{manifest.ident}/{case.name}: cannot read tree object")
                lines.extend(
                    [
                        "[[tree]]",
                        f'path = "{case.path}"',
                        f'tree_oid = "{tree_oid}"',
                        "",
                    ]
                )
            else:
                artifact = fetch_file(manifest, case.path, args.offline)
                digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
                lines.extend(
                    [
                        "[[file]]",
                        f'path = "{case.path}"',
                        f'sha256 = "{digest}"',
                        "",
                    ]
                )
        (LOCKS / f"{manifest.ident}.toml").write_text("\n".join(lines), encoding="utf-8")
        print(f"wrote {LOCKS / (manifest.ident + '.toml')}")


SOURCES: dict[str, Path] = {}
LOCKS_BY_REPO: dict[str, dict[str, str]] = {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("list", "fetch", "lock", "run"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--repo", action="append", default=[], help="repo id")
        sub.add_argument("--case", action="append", default=[], help="case name glob")
        sub.add_argument("--offline", action="store_true")
        if name in {"run", "list", "fetch", "lock"}:
            sub.add_argument(
                "--source",
                action="append",
                default=[],
                metavar="ID=PATH",
                help="local checkout for a repository",
            )
        if name == "run":
            sub.add_argument(
                "--structural",
                action="store_true",
                help="skip reference extraction and only require omniex output",
            )
            sub.add_argument(
                "--fail-on-skip",
                action="store_true",
                help="fail when a case is skipped because a requirement is missing",
            )

    args = parser.parse_args()
    global SOURCES, LOCKS_BY_REPO
    SOURCES = parse_sources(args.source)
    LOCKS_BY_REPO = {
        manifest.ident: load_lock(manifest) for manifest in load_manifests(args.repo)
    }

    if args.command == "list":
        command_list(args)
        return 0
    if args.command == "fetch":
        command_fetch(args)
        return 0
    if args.command == "lock":
        command_lock(args)
        return 0

    manifests = load_manifests(args.repo)
    failures = []
    skipped = 0
    for manifest in manifests:
        local_root = SOURCES.get(manifest.ident)
        if local_root is None:
            local_root = source_from_environment(manifest.ident)
            if local_root is not None:
                SOURCES[manifest.ident] = local_root
        if local_root is not None:
            head = local_head(local_root)
            if head and manifest.commit != "local" and head != manifest.commit:
                print(
                    f"warning: {manifest.ident} source HEAD {head[:12]} "
                    f"differs from pinned {manifest.commit[:12]}",
                    file=sys.stderr,
                )
        cases = expand_cases(manifest, SOURCES, args.offline)
        selected = [
            case
            for case in cases
            if not args.case
            or any(fnmatch.fnmatch(case.name, pattern) for pattern in args.case)
        ]
        for case in selected:
            if args.structural:
                case.reference = "structural"
            try:
                if run_case(manifest, case, SOURCES, args.offline):
                    skipped += 1
            except SystemExit as error:
                failures.append((manifest.ident, case.name, str(error)))
        print(f"{manifest.ident}: {len(selected)} case(s) checked")
    if failures:
        print(f"\n{len(failures)} failure(s):")
        for repo, name, message in failures:
            print(f"  {repo}/{case_name(name)}: {message}")
        return 1
    if skipped:
        print(f"\n{skipped} case(s) skipped")
        return 1 if args.fail_on_skip else 0
    return 0


def case_name(name: str) -> str:
    return name or "<unnamed>"


if __name__ == "__main__":
    sys.exit(main())
