#!/usr/bin/env python3
"""Generate the standard Go vendor projection from pristine sources and patches."""

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
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
WORK_ROOT = ROOT / ".vendor-work"
VENDOR_ROOT = ROOT / "vendor"
LOCK_PATH = ROOT / "deps/vendor-lock.json"
MANIFEST_PATH = VENDOR_ROOT / "MANIFEST.json"
README_PATH = VENDOR_ROOT / "README.md"
METADATA_PATHS = {"MANIFEST.json", "README.md"}
REPOSITORY_METADATA_NAMES = {".gitattributes", ".gitignore", ".gitmodules"}

COMPONENTS: tuple[dict[str, Any], ...] = (
    {
        "name": "dae-ebpfinbound",
        "module": "github.com/daeuniverse/dae/ebpfinbound",
        "source": ROOT / "third_party/dae",
        "series": ROOT / "patches/dae/series",
        "work": WORK_ROOT / "dae",
        "module_subpath": "ebpfinbound",
    },
    {
        "name": "tailscale",
        "module": "github.com/sagernet/tailscale",
        "source": ROOT / "third_party/tailscale",
        "series": ROOT / "patches/tailscale/series",
        "work": WORK_ROOT / "tailscale",
        "module_subpath": ".",
    },
)


def run(
    *args: str | os.PathLike[str],
    cwd: Path | None = None,
    go_mod_mode: bool = False,
) -> str:
    environment = {**os.environ, "LC_ALL": "C", "TZ": "UTC"}
    if go_mod_mode:
        environment["GOFLAGS"] = "-mod=mod"
    result = subprocess.run(
        [str(arg) for arg in args],
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
        raise RuntimeError(f"{' '.join(map(str, args))} failed: {detail}")
    return result.stdout


def exact_head(repo: Path) -> str:
    return run("git", "rev-parse", "HEAD", cwd=repo).strip()


def read_series(path: Path) -> list[Path]:
    if not path.is_file():
        raise RuntimeError(f"missing patch series: {path.relative_to(ROOT)}")
    patches: list[Path] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        name = raw.strip()
        if not name or name.startswith("#"):
            continue
        patch = path.parent / name
        if not patch.is_file():
            raise RuntimeError(f"missing patch: {patch.relative_to(ROOT)}")
        patches.append(patch)
    if not patches:
        raise RuntimeError(f"empty patch series: {path.relative_to(ROOT)}")
    return patches


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(
    root: Path,
    *,
    excluded: Iterable[str] = (),
) -> tuple[str, list[dict[str, Any]]]:
    excluded_set = set(excluded)
    digest = hashlib.sha256()
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in excluded_set:
            continue
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if path.is_symlink():
            # Git records symlinks by target; filesystem permission bits vary.
            mode = 0o777
            kind = "symlink"
            target = os.readlink(path)
            encoded_target = target.encode("utf-8")
            content_sha256 = hashlib.sha256(encoded_target).hexdigest()
            size = len(encoded_target)
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


def strip_repository_metadata(root: Path) -> list[dict[str, Any]]:
    """Remove projected repository-control files and return a closed receipt."""
    records: list[dict[str, Any]] = []
    candidates = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    for path in candidates:
        if path.name not in REPOSITORY_METADATA_NAMES:
            continue
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"projected repository metadata is not a regular file: {path}")
        relative = path.relative_to(root).as_posix()
        records.append(
            {
                "path": relative,
                "kind": "file",
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
        path.unlink()
    return records


def ensure_pristine_source(repo: Path) -> None:
    if not (repo / ".git").exists():
        raise RuntimeError(f"source checkout is not initialized: {repo.relative_to(ROOT)}")
    if run("git", "status", "--porcelain", cwd=repo).strip():
        raise RuntimeError(f"source checkout is dirty: {repo.relative_to(ROOT)}")


def remove_path(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def materialize_component(component: dict[str, Any]) -> dict[str, Any]:
    source: Path = component["source"]
    work: Path = component["work"]
    ensure_pristine_source(source)
    base_commit = exact_head(source)
    patches = read_series(component["series"])

    remove_path(work)
    work.parent.mkdir(parents=True, exist_ok=True)
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
    module_root = (work / component["module_subpath"]).resolve()
    if not (module_root / "go.mod").is_file():
        raise RuntimeError(f"materialized module is absent: {module_root}")

    return {
        "name": component["name"],
        "module": component["module"],
        "source": {
            "path": source.relative_to(ROOT).as_posix(),
            "commit": base_commit,
        },
        "patches": patch_records,
        "result_tree": result_tree,
        "generation_input": {
            "path": module_root.relative_to(ROOT).as_posix(),
            "tracked": False,
        },
    }


def enforce_replacements() -> None:
    for component in COMPONENTS:
        module_root = component["work"] / component["module_subpath"]
        replacement = "./" + module_root.relative_to(ROOT).as_posix()
        run(
            "go",
            "mod",
            "edit",
            f"-replace={component['module']}={replacement}",
            cwd=ROOT,
            go_mod_mode=True,
        )


def write_projection_metadata(
    components: list[dict[str, Any]],
    vendor_root: Path,
    excluded_repository_metadata: list[dict[str, Any]],
) -> dict[str, Any]:
    payload_sha256, entries = tree_digest(vendor_root)
    modules_path = vendor_root / "modules.txt"
    if not modules_path.is_file():
        raise RuntimeError("go mod vendor did not create vendor/modules.txt")

    projection = {
        "path": vendor_root.relative_to(ROOT).as_posix(),
        "format": "go-mod-vendor",
        "tree_sha256": payload_sha256,
        "entries": len(entries),
        "modules_txt_sha256": sha256_file(modules_path),
        "excluded_repository_metadata": excluded_repository_metadata,
    }
    lock = {
        "schema_version": "sing-box-vendor-lock/v2",
        "authority": "wignerStan/sing-box",
        "components": components,
        "projection": projection,
    }
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCK_PATH.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest = {
        "schema_version": "sing-box-vendor-manifest/v2",
        "generated_by": "tools/vendor/materialize.py",
        "lock": LOCK_PATH.relative_to(ROOT).as_posix(),
        "projection": projection,
        "components": [
            {
                "name": component["name"],
                "module": component["module"],
                "source_commit": component["source"]["commit"],
                "result_tree": component["result_tree"],
            }
            for component in components
        ],
    }
    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    README_PATH.write_text(
        """# Generated Go vendor projection

`vendor/` is a standard Go vendor projection generated from the main module
graph. DAE and Tailscale packages come from pristine `third_party/` pins after
the ordered parent-owned patch stacks under `patches/` are applied in the
ignored `.vendor-work/` generation area.

Do not edit files below `vendor/` directly. Regenerate and verify with:

```sh
python3 tools/vendor/materialize.py
python3 tools/vendor/verify.py --require-source
```

`vendor/modules.txt` is authoritative for Go's vendor-mode package mapping.
`deps/vendor-lock.json` records source commits, patch digests, patched Git tree
identities, the generated projection digest, and any repository-control files
that Go's projection copied and the materializer removed. No Git metadata,
gitlink, submodule, or nested repository is permitted below `vendor/`.
""",
        encoding="utf-8",
    )
    return projection


def main_materialize(*, keep_work: bool) -> None:
    remove_path(WORK_ROOT)
    components = [materialize_component(component) for component in COMPONENTS]
    enforce_replacements()
    run("go", "mod", "tidy", cwd=ROOT, go_mod_mode=True)

    generated = ROOT / ".vendor-generated"
    remove_path(generated)
    run("go", "mod", "vendor", "-o", generated, cwd=ROOT, go_mod_mode=True)
    excluded_repository_metadata = strip_repository_metadata(generated)

    remove_path(VENDOR_ROOT)
    generated.rename(VENDOR_ROOT)
    write_projection_metadata(components, VENDOR_ROOT, excluded_repository_metadata)

    if not keep_work:
        remove_path(WORK_ROOT)


def snapshot_path(source: Path, destination: Path) -> None:
    if source.is_dir() and not source.is_symlink():
        shutil.copytree(source, destination, symlinks=True)
    elif source.exists() or source.is_symlink():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=False)


def restore_path(snapshot: Path, destination: Path) -> None:
    remove_path(destination)
    if snapshot.is_dir() and not snapshot.is_symlink():
        shutil.copytree(snapshot, destination, symlinks=True)
    elif snapshot.exists() or snapshot.is_symlink():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(snapshot, destination, follow_symlinks=False)


def check_generated_output() -> None:
    tracked = [VENDOR_ROOT, LOCK_PATH, ROOT / "go.mod", ROOT / "go.sum"]
    with tempfile.TemporaryDirectory(prefix="sing-box-vendor-check-") as temporary:
        snapshot_root = Path(temporary) / "snapshot"
        for path in tracked:
            snapshot_path(path, snapshot_root / path.relative_to(ROOT))

        failure: str | None = None
        try:
            main_materialize(keep_work=False)
            for path in tracked:
                expected = snapshot_root / path.relative_to(ROOT)
                if path.is_dir():
                    if not expected.is_dir():
                        failure = f"missing checked-in output: {path.relative_to(ROOT)}"
                        break
                    current_digest, _ = tree_digest(path)
                    expected_digest, _ = tree_digest(expected)
                    if current_digest != expected_digest:
                        failure = f"generated tree drift: {path.relative_to(ROOT)}"
                        break
                elif not expected.is_file() or path.read_bytes() != expected.read_bytes():
                    failure = f"generated metadata drift: {path.relative_to(ROOT)}"
                    break
        finally:
            for path in tracked:
                restore_path(snapshot_root / path.relative_to(ROOT), path)
            remove_path(WORK_ROOT)
            remove_path(ROOT / ".vendor-generated")
        if failure:
            raise SystemExit(failure)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate and fail if checked-in output changes",
    )
    parser.add_argument(
        "--keep-work",
        action="store_true",
        help="retain ignored patched source inputs for dependency-level tests",
    )
    options = parser.parse_args()

    if options.check:
        if options.keep_work:
            parser.error("--check and --keep-work are mutually exclusive")
        check_generated_output()
        return
    main_materialize(keep_work=options.keep_work)


if __name__ == "__main__":
    main()
