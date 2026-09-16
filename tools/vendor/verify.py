#!/usr/bin/env python3
"""Verify sing-box's parent-owned vendor materializations and local module wiring."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "deps/vendor-lock.json"


def run(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
        env={**os.environ, "LC_ALL": "C", "TZ": "UTC", "GOFLAGS": "-mod=mod"},
    )
    if result.returncode:
        detail = (result.stderr.strip() or result.stdout.strip())[:4000]
        raise RuntimeError(f"{' '.join(args)} failed: {detail}")
    return result.stdout


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if path.is_symlink():
            # POSIX exposes platform-specific permission bits for symlinks.
            # Git records symlinks by target, not by those filesystem bits.
            mode = 0o777
            kind = "symlink"
            target = os.readlink(path)
            item_sha = hashlib.sha256(target.encode("utf-8")).hexdigest()
            size = len(target.encode("utf-8"))
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
    return digest.hexdigest()


def main() -> None:
    value = json.loads(LOCK.read_text(encoding="utf-8"))
    if value.get("schema_version") != "sing-box-vendor-lock/v1":
        raise RuntimeError("unsupported vendor lock")
    if value.get("authority") != "wignerStan/sing-box":
        raise RuntimeError("unexpected vendor authority")

    for nested in (ROOT / "vendor").rglob(".git"):
        raise RuntimeError(f"nested Git metadata below vendor: {nested}")
    if any(path.name == ".gitmodules" for path in (ROOT / "vendor").rglob(".gitmodules")):
        raise RuntimeError("vendor contains .gitmodules")

    replacements = run("go", "mod", "edit", "-json", cwd=ROOT)
    module = json.loads(replacements)
    replace_map = {item["Old"]["Path"]: item["New"]["Path"] for item in module.get("Replace", [])}
    expected_replacements = {
        "github.com/daeuniverse/dae/ebpfinbound": "./vendor/dae/ebpfinbound",
        "github.com/sagernet/tailscale": "./vendor/tailscale",
    }
    for old, new in expected_replacements.items():
        if replace_map.get(old) != new:
            raise RuntimeError(f"incorrect replacement for {old}: {replace_map.get(old)!r}")

    components = value.get("components")
    if not isinstance(components, list) or len(components) != 2:
        raise RuntimeError("vendor lock must contain exactly DAE and Tailscale")
    for component in components:
        source = ROOT / component["source"]["path"]
        if run("git", "rev-parse", "HEAD", cwd=source).strip() != component["source"]["commit"]:
            raise RuntimeError(f"source pin mismatch for {component['name']}")
        if run("git", "status", "--porcelain", cwd=source).strip():
            raise RuntimeError(f"dirty source submodule: {source.relative_to(ROOT)}")
        for expected_order, patch in enumerate(component["patches"], 1):
            if patch["order"] != expected_order:
                raise RuntimeError(f"non-contiguous patch order for {component['name']}")
            patch_path = ROOT / patch["path"]
            if file_sha256(patch_path) != patch["sha256"]:
                raise RuntimeError(f"patch digest mismatch: {patch['path']}")
        vendor = ROOT / component["materialization"]["path"]
        actual = tree_sha256(vendor)
        if actual != component["materialization"]["tree_sha256"]:
            raise RuntimeError(f"materialized tree mismatch: {vendor.relative_to(ROOT)}")

    run(sys.executable, str(ROOT / "tools/vendor/materialize.py"), "--check", cwd=ROOT)
    print("vendor source, patch, materialization, and Go replacement contracts verified")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"vendor verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
