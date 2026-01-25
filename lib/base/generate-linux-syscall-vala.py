#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Dict, FrozenSet, Optional


_WS_SPLIT = re.compile(r"\s+")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tbl", required=True, help="Path to input .tbl file")
    parser.add_argument(
        "--capabilities",
        help=(
            "Comma-separated set of ABI/capability tags to include (e.g. common,64). "
            "If omitted, all rows are included."
        ),
    )
    parser.add_argument("--out", required=True, help="Output .vala file path")
    args = parser.parse_args()

    tbl_path = Path(args.tbl)
    out_path = Path(args.out)

    if not tbl_path.is_file():
        raise FileNotFoundError(tbl_path)

    capabilities = parse_capabilities(args.capabilities)
    syscalls = parse_tbl(tbl_path, capabilities)
    vala = render_vala(syscalls)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(vala, encoding="utf-8")

    return 0


def parse_capabilities(value: Optional[str]) -> Optional[FrozenSet[str]]:
    if value is None:
        return None

    caps = tuple(item.strip() for item in value.split(",") if item.strip())
    return frozenset(caps)


def parse_tbl(
    path: Path,
    capabilities: Optional[FrozenSet[str]],
) -> Dict[int, str]:
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
    lines = []

    lines.append("// AUTO-GENERATED FILE. DO NOT EDIT.\n\n")
    lines.append("public enum Frida.LinuxSyscall {\n")

    for nr, name in sorted(syscalls.items(), key=lambda kv: kv[0]):
        lines.append(f"\t{name.upper()} = {nr},\n")

    lines.append("}\n")

    return "".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
