#!/usr/bin/env python3
"""Materialize patched DAE and Tailscale source into parent-owned vendor trees."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

COMPONENTS: tuple[dict[str, Any], ...] = (
    {
        "name": "dae-ebpfinbound",
        "source": ROOT / "third_party/dae",
        "series": ROOT / "patches/dae/series",
        "vendor": ROOT / "vendor/dae/ebpfinbound",
        "copy_subpath": "ebpfinbound",
        "module": "github.com/daeuniverse/dae/ebpfinbound",
    },
    {
        "name": "tailscale",
        "source": ROOT / "third_party/tailscale",
        "series": ROOT / "patches/tailscale/series",
        "vendor": ROOT / "vendor/tailscale",
        "copy_subpath": ".",
        "module": "github.com/sagernet/tailscale",
    },
)

LOCK_PATH = ROOT / "deps/vendor-lock.json"
MANIFEST_PATH = ROOT / "vendor/MANIFEST.json"
README_PATH = ROOT / "vendor/README.md"


def run(*args: str | os.PathLike[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        [str(arg) for arg in args],
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
        raise RuntimeError(f"{' '.join(map(str, args))} failed: {detail}")
    return result.stdout


def exact_head(repo: Path) -> str:
    return run("git", "rev-parse", "HEAD", cwd=repo).strip()


def read_series(path: Path) -> list[Path]:
    if not path.is_file():
        raise RuntimeError(f"missing patch series: {path.relative_to(ROOT)}")
    entries: list[Path] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        name = raw.strip()
        if not name or name.startswith("#"):
            continue
        patch = path.parent / name
        if not patch.is_file():
            raise RuntimeError(f"missing patch: {patch.relative_to(ROOT)}")
        entries.append(patch)
    if not entries:
        raise RuntimeError(f"empty patch series: {path.relative_to(ROOT)}")
    return entries


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_source(source: Path, destination: Path) -> None:
    def ignored(directory: str, names: list[str]) -> set[str]:
        del directory
        blocked = {".git", ".gitmodules"}
        return {name for name in names if name in blocked}

    shutil.copytree(source, destination, symlinks=True, ignore=ignored)


def tree_digest(root: Path) -> tuple[str, list[dict[str, Any]]]:
    digest = hashlib.sha256()
    entries: list[dict[str, Any]] = []
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
            content_sha256 = hashlib.sha256(target.encode("utf-8")).hexdigest()
            size = len(target.encode("utf-8"))
        elif path.is_dir():
            kind = "directory"
            content_sha256 = None
            size = 0
        elif path.is_file():
            kind = "file"
            content_sha256 = sha256_file(path)
            size = info.st_size
        else:
            raise RuntimeError(f"unsupported vendor entry: {path}")
        record = {
            "path": relative,
            "kind": kind,
            "mode": f"{mode:04o}",
            "size": size,
            "sha256": content_sha256,
        }
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest.update(canonical)
        digest.update(b"\n")
        entries.append(record)
    return digest.hexdigest(), entries


def ensure_pristine_source(repo: Path) -> None:
    if not (repo / ".git").exists():
        raise RuntimeError(f"source checkout is not initialized: {repo.relative_to(ROOT)}")
    if run("git", "status", "--porcelain", cwd=repo).strip():
        raise RuntimeError(f"source checkout is dirty: {repo.relative_to(ROOT)}")


def materialize_component(component: dict[str, Any], temporary_root: Path) -> dict[str, Any]:
    source: Path = component["source"]
    ensure_pristine_source(source)
    base_commit = exact_head(source)
    patches = read_series(component["series"])

    work = temporary_root / component["name"]
    run("git", "clone", "--quiet", "--no-hardlinks", str(source), str(work))
    run("git", "checkout", "--quiet", "--detach", base_commit, cwd=work)

    patch_records: list[dict[str, Any]] = []
    for order, patch in enumerate(patches, 1):
        run("git", "apply", "--index", "--binary", str(patch), cwd=work)
        patch_records.append(
            {
                "order": order,
                "path": patch.relative_to(ROOT).as_posix(),
                "sha256": sha256_file(patch),
            }
        )

    result_tree = run("git", "write-tree", cwd=work).strip()
    source_path = work / component["copy_subpath"]
    if not source_path.exists():
        raise RuntimeError(f"materialized subpath is absent: {component['copy_subpath']}")

    vendor: Path = component["vendor"]
    if vendor.exists() or vendor.is_symlink():
        if vendor.is_dir() and not vendor.is_symlink():
            shutil.rmtree(vendor)
        else:
            vendor.unlink()
    vendor.parent.mkdir(parents=True, exist_ok=True)
    copy_source(source_path, vendor)
    if any(vendor.rglob(".git")):
        raise RuntimeError(f"nested Git metadata in {vendor.relative_to(ROOT)}")
    if any(vendor.rglob(".gitmodules")):
        raise RuntimeError(f"nested .gitmodules in {vendor.relative_to(ROOT)}")
    vendor_sha256, entries = tree_digest(vendor)

    return {
        "name": component["name"],
        "module": component["module"],
        "source": {
            "path": source.relative_to(ROOT).as_posix(),
            "commit": base_commit,
        },
        "patches": patch_records,
        "result_tree": result_tree,
        "materialization": {
            "path": vendor.relative_to(ROOT).as_posix(),
            "source_subpath": component["copy_subpath"],
            "tree_sha256": vendor_sha256,
            "entries": len(entries),
        },
    }


def write_metadata(components: list[dict[str, Any]]) -> None:
    lock = {
        "schema_version": "sing-box-vendor-lock/v1",
        "authority": "wignerStan/sing-box",
        "components": components,
    }
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCK_PATH.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest = {
        "schema_version": "sing-box-vendor-manifest/v1",
        "generated_by": "tools/vendor/materialize.py",
        "lock": LOCK_PATH.relative_to(ROOT).as_posix(),
        "components": [
            {
                "name": component["name"],
                "module": component["module"],
                "path": component["materialization"]["path"],
                "tree_sha256": component["materialization"]["tree_sha256"],
            }
            for component in components
        ],
    }
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    README_PATH.write_text(
        """# Generated vendor materializations

`vendor/` contains parent-owned ordinary files generated from exact
`third_party/` source pins plus the ordered patch stacks in `patches/`.

Do not edit these files directly. Run:

```sh
python3 tools/vendor/materialize.py
python3 tools/vendor/verify.py
```

The source relationship, patch digests, patched Git tree, and materialized tree
digest are recorded in `deps/vendor-lock.json`. No Git metadata, gitlink,
submodule, or nested repository is permitted below `vendor/`.
""",
        encoding="utf-8",
    )


def main_materialize() -> None:
    vendor_root = ROOT / "vendor"
    if vendor_root.exists():
        for nested in vendor_root.rglob(".git"):
            raise RuntimeError(f"nested Git metadata found before generation: {nested}")
    with tempfile.TemporaryDirectory(prefix="sing-box-vendor-") as temporary:
        components = [
            materialize_component(component, Path(temporary)) for component in COMPONENTS
        ]
    write_metadata(components)
    run(
        "go",
        "mod",
        "edit",
        "-replace=github.com/daeuniverse/dae/ebpfinbound=./vendor/dae/ebpfinbound",
        cwd=ROOT,
    )
    run(
        "go",
        "mod",
        "edit",
        "-replace=github.com/sagernet/tailscale=./vendor/tailscale",
        cwd=ROOT,
    )
    run("go", "mod", "tidy", cwd=ROOT)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate and fail if checked-in output changes",
    )
    options = parser.parse_args()

    if options.check:
        tracked = [LOCK_PATH, MANIFEST_PATH, README_PATH, ROOT / "go.mod", ROOT / "go.sum"]
        for component in COMPONENTS:
            tracked.append(component["vendor"])
        with tempfile.TemporaryDirectory(prefix="sing-box-vendor-check-") as temporary:
            snapshot = Path(temporary) / "snapshot"
            for path in tracked:
                if path.is_dir():
                    shutil.copytree(path, snapshot / path.relative_to(ROOT), symlinks=True)
                elif path.exists():
                    target = snapshot / path.relative_to(ROOT)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, target)
            main_materialize()
            for path in tracked:
                expected = snapshot / path.relative_to(ROOT)
                if path.is_dir():
                    current_digest, _ = tree_digest(path)
                    if not expected.is_dir():
                        raise SystemExit(f"missing checked-in output: {path.relative_to(ROOT)}")
                    expected_digest, _ = tree_digest(expected)
                    if current_digest != expected_digest:
                        raise SystemExit(f"vendor drift: {path.relative_to(ROOT)}")
                else:
                    if not expected.is_file() or path.read_bytes() != expected.read_bytes():
                        raise SystemExit(f"generated metadata drift: {path.relative_to(ROOT)}")
        return

    main_materialize()


if __name__ == "__main__":
    main()
