#!/usr/bin/env python3
"""Materialize the standalone Tailscale 1.94.2 peer backport in a disposable path."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "third_party/tailscale-1.94.2"
SERIES = ROOT / "patches/tailscale-1.94.2/series"


def run(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
        env={**os.environ, "LC_ALL": "C", "TZ": "UTC"},
    )
    if result.returncode:
        detail = (result.stderr.strip() or result.stdout.strip())[:4000]
        raise RuntimeError(f"{' '.join(args)} failed: {detail}")
    return result.stdout


def patches() -> list[Path]:
    result: list[Path] = []
    for raw in SERIES.read_text(encoding="utf-8").splitlines():
        name = raw.strip()
        if not name or name.startswith("#"):
            continue
        path = SERIES.parent / name
        if not path.is_file():
            raise RuntimeError(f"missing patch: {path.relative_to(ROOT)}")
        result.append(path)
    if not result:
        raise RuntimeError("empty 1.94.2 patch series")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    output = Path(args.output).resolve()
    if output.exists():
        if not args.force:
            raise RuntimeError(f"output exists: {output}")
        shutil.rmtree(output)
    if not (SOURCE / ".git").exists():
        raise RuntimeError("third_party/tailscale-1.94.2 is not initialized")
    if run("git", "status", "--porcelain", cwd=SOURCE).strip():
        raise RuntimeError("third_party/tailscale-1.94.2 is dirty")

    run("git", "clone", "--quiet", "--no-hardlinks", str(SOURCE), str(output))
    commit = run("git", "rev-parse", "HEAD", cwd=SOURCE).strip()
    run("git", "checkout", "--quiet", "--detach", commit, cwd=output)
    for patch in patches():
        run("git", "apply", "--index", "--binary", str(patch), cwd=output)
    result_tree = run("git", "write-tree", cwd=output).strip()
    (output / ".sing-box-backport-tree").write_text(result_tree + "\n", encoding="utf-8")
    print(result_tree)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"backport materialization failed: {error}", file=sys.stderr)
        raise SystemExit(1)
