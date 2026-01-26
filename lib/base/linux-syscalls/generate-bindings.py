#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Sequence

_TABLES = {
    "x86": ("x86", frozenset(["i386"])),
    "x86_64": ("x86_64", frozenset(["common", "64"])),
    "arm": ("arm", frozenset(["common", "oabi", "eabi"])),
    "arm64": ("arm64", frozenset(["common", "64"])),
    "mips": ("mips-o32", None),
    "mips64": ("mips-n64", None),
    "s390x": ("s390", None),
}
_TABLES["armbe"] = _TABLES["arm"]
_TABLES["armbe8"] = _TABLES["arm"]
_TABLES["armhf"] = _TABLES["arm"]
_TABLES["armv6kz"] = _TABLES["arm"]
_TABLES["arm64be"] = _TABLES["arm64"]
_TABLES["arm64beilp32"] = _TABLES["arm64"]
_TABLES["mipsel"] = _TABLES["mips"]
_TABLES["mips64el"] = _TABLES["mips64"]

_WS_SPLIT = re.compile(r"\s+")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--abi", required=True, help="ABI to target")
    parser.add_argument("--out-vala", help="Output .vala file path (optional)")
    parser.add_argument("--out-c-header", help="Output C header path (optional)")
    args = parser.parse_args()

    if args.out_vala is None and args.out_c_header is None:
        raise SystemExit("At least one of --out-vala or --out-c-header is required")

    tbl_name, capabilities = _TABLES[args.abi]
    tbl_path = Path(__file__).parent / (tbl_name + ".tbl")

    syscalls = parse_tbl(tbl_path, capabilities)

    if args.out_vala is not None:
        out_vala = Path(args.out_vala)
        out_vala.parent.mkdir(parents=True, exist_ok=True)
        out_vala.write_text(render_vala(syscalls), encoding="utf-8")

    if args.out_c_header is not None:
        out_h = Path(args.out_c_header)
        out_h.parent.mkdir(parents=True, exist_ok=True)
        out_h.write_text(render_c_header(syscalls), encoding="utf-8")

    return 0


def parse_tbl(path: Path, capabilities: Optional[FrozenSet[str]]) -> Dict[int, str]:
    out: Dict[int, str] = {}
    text = path.read_text(encoding="utf-8")

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        line = line.split("#", 1)[0].strip()
        if not line:
            continue

        cols = _WS_SPLIT.split(line)
        if len(cols) < 3:
            raise ValueError(f"Unexpected tbl row (too few columns): {raw!r}")

        nr_s, tag, name = cols[0], cols[1], cols[2]
        if not nr_s.isdigit():
            raise ValueError(f"Unexpected syscall number token: {nr_s!r}")

        if capabilities is not None and tag not in capabilities:
            continue

        nr = int(nr_s, 10)
        if nr in out:
            raise ValueError(
                f"Duplicate syscall number {nr} after filtering in {path} "
                f"(tag={tag!r}, name={name!r})"
            )

        out[nr] = name

    if not out:
        raise ValueError(f"Parsed 0 syscalls from {path}")

    return out


def render_vala(syscalls: Dict[int, str]) -> str:
    lines: list[str] = []

    lines.append("// AUTO-GENERATED FILE. DO NOT EDIT.\n\n")
    lines.append("public enum Frida.LinuxSyscall {\n")

    for nr, name in sorted(syscalls.items(), key=lambda kv: kv[0]):
        lines.append(f"\t{name.upper()} = {nr},\n")

    lines.append("}\n")

    return "".join(lines)


def render_c_header(syscalls: Dict[int, str]) -> str:
    lines: list[str] = []

    lines.append("#ifndef __FRIDA_LINUX_SYSCALLS_H__\n")
    lines.append("#define __FRIDA_LINUX_SYSCALLS_H__\n\n")

    lines.append("enum _FridaLinuxSyscall\n{\n")
    for nr, name in sorted(syscalls.items(), key=lambda kv: kv[0]):
        lines.append(f"  FRIDA_LINUX_SYSCALL_{name.upper()} = {nr},\n")
    lines.append("};\n\n")

    lines.append("#endif\n")
    return "".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
