#!/usr/bin/env python3
"""Verify sing-box's patch authority and standard Go vendor projection."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "deps/vendor-lock.json"
VENDOR = ROOT / "vendor"
METADATA_PATHS = {"MANIFEST.json", "README.md"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REPOSITORY_METADATA_NAMES = {".gitattributes", ".gitignore", ".gitmodules"}

EXPECTED_COMPONENTS = {
    "dae-ebpfinbound": {
        "module": "github.com/daeuniverse/dae/ebpfinbound",
        "source": "third_party/dae",
        "replacement": "./.vendor-work/dae/ebpfinbound",
    },
    "tailscale": {
        "module": "github.com/sagernet/tailscale",
        "source": "third_party/tailscale",
        "replacement": "./.vendor-work/tailscale",
    },
}


def run(
    *args: str,
    cwd: Path | None = None,
    go_mod_mode: bool = False,
) -> str:
    environment = {**os.environ, "LC_ALL": "C", "TZ": "UTC"}
    if go_mod_mode:
        environment["GOFLAGS"] = "-mod=mod"
    result = subprocess.run(
        args,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=environment,
    )
    if result.returncode:
        detail = (result.stderr.strip() or result.stdout.strip())[:6000]
        raise RuntimeError(f"{' '.join(args)} failed: {detail}")
    return result.stdout


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: Path, *, excluded: Iterable[str] = ()) -> tuple[str, int]:
    excluded_set = set(excluded)
    digest = hashlib.sha256()
    entries = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in excluded_set:
            continue
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if path.is_symlink():
            mode = 0o777
            kind = "symlink"
            target = os.readlink(path)
            encoded_target = target.encode("utf-8")
            item_sha = hashlib.sha256(encoded_target).hexdigest()
            size = len(encoded_target)
        elif path.is_dir():
            kind = "directory"
            item_sha = None
            size = 0
        elif path.is_file():
            kind = "file"
            item_sha = file_sha256(path)
            size = info.st_size
        else:
            raise RuntimeError(f"unsupported vendor entry: {path}")
        record: dict[str, Any] = {
            "path": relative,
            "kind": kind,
            "mode": f"{mode:04o}",
            "size": size,
            "sha256": item_sha,
        }
        digest.update(json.dumps(record, sort_keys=True, separators=(",", ":")).encode())
        digest.update(b"\n")
        entries += 1
    return digest.hexdigest(), entries


def safe_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError("metadata receipt path must be a non-empty string")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or path.as_posix() != value:
        raise RuntimeError(f"unsafe metadata receipt path: {value!r}")
    return value


def validate_excluded_repository_metadata(projection: dict[str, Any]) -> None:
    receipt = projection.get("excluded_repository_metadata")
    if not isinstance(receipt, list):
        raise RuntimeError("excluded repository metadata receipt is missing")
    observed: set[str] = set()
    for item in receipt:
        if not isinstance(item, dict) or set(item) != {"path", "kind", "size", "sha256"}:
            raise RuntimeError("invalid excluded repository metadata record")
        path = safe_relative_path(item["path"])
        if PurePosixPath(path).name not in REPOSITORY_METADATA_NAMES:
            raise RuntimeError(f"unsupported excluded repository metadata: {path}")
        if path in observed:
            raise RuntimeError(f"duplicate excluded repository metadata: {path}")
        observed.add(path)
        if item["kind"] != "file":
            raise RuntimeError(f"excluded repository metadata must be a regular file: {path}")
        if not isinstance(item["size"], int) or item["size"] < 0:
            raise RuntimeError(f"invalid excluded repository metadata size: {path}")
        if not isinstance(item["sha256"], str) or not SHA256.fullmatch(item["sha256"]):
            raise RuntimeError(f"invalid excluded repository metadata digest: {path}")


def source_initialized(path: Path) -> bool:
    return (path / ".git").exists()


def verify_projection(value: dict[str, Any]) -> None:
    if not (VENDOR / "modules.txt").is_file():
        raise RuntimeError("vendor/modules.txt is missing")
    for nested in VENDOR.rglob(".git"):
        raise RuntimeError(f"nested Git metadata below vendor: {nested}")
    for name in REPOSITORY_METADATA_NAMES:
        if any(True for _ in VENDOR.rglob(name)):
            raise RuntimeError(f"vendor contains {name}")

    projection = value.get("projection")
    if not isinstance(projection, dict):
        raise RuntimeError("vendor lock projection is missing")
    if projection.get("path") != "vendor" or projection.get("format") != "go-mod-vendor":
        raise RuntimeError("vendor lock does not describe the standard Go projection")
    validate_excluded_repository_metadata(projection)
    actual_sha256, actual_entries = tree_sha256(VENDOR, excluded=METADATA_PATHS)
    if actual_sha256 != projection.get("tree_sha256"):
        raise RuntimeError("Go vendor projection tree mismatch")
    if actual_entries != projection.get("entries"):
        raise RuntimeError("Go vendor projection entry count mismatch")
    if file_sha256(VENDOR / "modules.txt") != projection.get("modules_txt_sha256"):
        raise RuntimeError("vendor/modules.txt digest mismatch")

    manifest = json.loads((VENDOR / "MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "sing-box-vendor-manifest/v2":
        raise RuntimeError("unsupported vendor manifest")
    if manifest.get("projection") != projection:
        raise RuntimeError("vendor manifest projection does not match the lock")


def verify_go_contract() -> None:
    module = json.loads(run("go", "mod", "edit", "-json", cwd=ROOT, go_mod_mode=True))
    replace_map = {item["Old"]["Path"]: item["New"]["Path"] for item in module.get("Replace", [])}
    for component in EXPECTED_COMPONENTS.values():
        module_path = component["module"]
        expected = component["replacement"]
        if replace_map.get(module_path) != expected:
            raise RuntimeError(f"incorrect replacement for {module_path}: {replace_map.get(module_path)!r}")

    modules_text = (VENDOR / "modules.txt").read_text(encoding="utf-8")
    for component in EXPECTED_COMPONENTS.values():
        expected_header = f"# {component['module']} "
        expected_replacement = f"=> {component['replacement']}"
        if not any(
            line.startswith(expected_header) and expected_replacement in line
            for line in modules_text.splitlines()
        ):
            raise RuntimeError(f"vendor/modules.txt does not bind {component['module']}")
    run("go", "list", "-mod=vendor", "./cmd/sing-box", cwd=ROOT)


def verify_sources(value: dict[str, Any], *, require_source: bool) -> bool:
    components = value.get("components")
    if not isinstance(components, list) or len(components) != len(EXPECTED_COMPONENTS):
        raise RuntimeError("vendor lock must contain exactly DAE and Tailscale")

    available = all(
        source_initialized(ROOT / expected["source"])
        for expected in EXPECTED_COMPONENTS.values()
    )
    if not available:
        if require_source:
            raise RuntimeError("pristine third_party source checkouts are required")
        return False

    observed_names: set[str] = set()
    for component in components:
        name = component.get("name")
        expected = EXPECTED_COMPONENTS.get(name)
        if expected is None or name in observed_names:
            raise RuntimeError(f"unexpected vendor component: {name!r}")
        observed_names.add(name)
        if component.get("module") != expected["module"]:
            raise RuntimeError(f"module mismatch for {name}")
        source = ROOT / component["source"]["path"]
        if source.relative_to(ROOT).as_posix() != expected["source"]:
            raise RuntimeError(f"source path mismatch for {name}")
        if run("git", "rev-parse", "HEAD", cwd=source).strip() != component["source"]["commit"]:
            raise RuntimeError(f"source pin mismatch for {name}")
        if run("git", "status", "--porcelain", cwd=source).strip():
            raise RuntimeError(f"dirty source submodule: {source.relative_to(ROOT)}")
        patches = component.get("patches")
        if not isinstance(patches, list) or not patches:
            raise RuntimeError(f"patch inventory missing for {name}")
        for expected_order, patch in enumerate(patches, 1):
            if patch.get("order") != expected_order:
                raise RuntimeError(f"non-contiguous patch order for {name}")
            patch_path = ROOT / patch["path"]
            if file_sha256(patch_path) != patch["sha256"]:
                raise RuntimeError(f"patch digest mismatch: {patch['path']}")

    run(
        sys.executable,
        str(ROOT / "tools/vendor/materialize.py"),
        "--check",
        cwd=ROOT,
        go_mod_mode=True,
    )
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-source",
        action="store_true",
        help="require initialized pristine source gitlinks and deterministic regeneration",
    )
    options = parser.parse_args()

    value = json.loads(LOCK.read_text(encoding="utf-8"))
    if value.get("schema_version") != "sing-box-vendor-lock/v2":
        raise RuntimeError("unsupported vendor lock")
    if value.get("authority") != "wignerStan/sing-box":
        raise RuntimeError("unexpected vendor authority")

    verify_projection(value)
    verify_go_contract()
    source_verified = verify_sources(value, require_source=options.require_source)
    scope = "source, patches, and Go vendor projection" if source_verified else "offline Go vendor projection"
    print(f"{scope} verified")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"vendor verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
