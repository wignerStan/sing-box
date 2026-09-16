#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

module = Path(__file__).resolve().parents[1]
repository = module.parent
source = repository / "control" / "kern"
if not (source / "tproxy.c").is_file():
    raise SystemExit(f"dae BPF source not found at {source / 'tproxy.c'}")
if not (source / "headers").is_dir():
    raise SystemExit("dae BPF headers submodule is missing; run git submodule update --init --recursive")

with tempfile.TemporaryDirectory(prefix="dae-ebpfinbound-generate-") as temporary:
    temporary_path = Path(temporary).resolve()
    kern = temporary_path / "kern"
    shutil.copytree(source, kern, symlinks=True)
    tproxy = kern / "tproxy.c"
    text = tproxy.read_text()
    if "Routing policy is owned by the embedding userspace engine." not in text:
        raise SystemExit("capture-only route seam missing from canonical dae BPF source")
    if "DAE_CAPTURE_ONLY" not in text or "wan_outbound_is_alive" not in text:
        raise SystemExit("capture-only connectivity seam missing from canonical dae BPF source")

    cflags = " ".join([
        "-DMAX_MATCH_SET_LEN=1024",
        "-DDAE_CAPTURE_ONLY=1",
        "-O2",
        "-Wall",
        "-Werror",
        "-fdebug-compilation-dir=.",
        f"-ffile-prefix-map={temporary_path}=.",
        f"-fdebug-prefix-map={temporary_path}=.",
    ])
    command = [
        "go", "run", "-mod=mod", "github.com/cilium/ebpf/cmd/bpf2go@v0.20.0",
        "-cc", os.environ.get("BPF_CLANG", "clang"),
        "-no-strip",
        "-no-global-types",
        "-cflags", cflags,
        "-output-dir", str(module),
        "-target", "bpfel,bpfeb",
        "-type", "dae_param",
        "-type", "tuples_key",
        "-type", "conn_state",
        "-type", "routing_handoff_entry",
        "bpf", "tproxy.c", "--", "-Iheaders",
    ]
    environment = os.environ.copy()
    environment["GOPACKAGE"] = "ebpfinbound"
    environment["LC_ALL"] = "C"
    environment["SOURCE_DATE_EPOCH"] = "0"
    environment["TZ"] = "UTC"
    subprocess.run(command, cwd=kern, env=environment, check=True)

for name in ("bpf_bpfel.go", "bpf_bpfeb.go"):
    path = module / name
    lines = path.read_text().splitlines()
    for index, line in enumerate(lines):
        if line.startswith("//go:build "):
            expression = line.removeprefix("//go:build ")
            lines[index] = f"//go:build linux && !dae_stub_ebpf && ({expression})"
            break
    else:
        raise SystemExit(f"generated build constraint missing from {name}")
    path.write_text("\n".join(lines) + "\n")
