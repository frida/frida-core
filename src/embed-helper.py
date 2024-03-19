#!/usr/bin/env python

from pathlib import Path
import shutil
import subprocess
import sys


def main(argv):
    args = argv[1:]
    host_os = args.pop(0)
    host_arch = args.pop(0)
    host_toolchain = args.pop(0)
    resource_compiler = args.pop(0)
    lipo = pop_cmd_array_arg(args)
    output_dir = Path(args.pop(0))
    resource_config = args.pop(0)
    helper_modern, helper_legacy = [Path(p) if p else None for p in args[:2]]

    priv_dir = output_dir / "frida-helper@emb"
    priv_dir.mkdir(exist_ok=True)

    embedded_assets = []
    if host_os in {"macos", "ios", "watchos", "tvos"}:
        embedded_helper = priv_dir / "frida-helper"

        if helper_modern is not None and helper_legacy is not None:
            subprocess.run(lipo + [helper_modern, helper_legacy, "-create", "-output", embedded_helper],
                           check=True)
        elif helper_modern is not None:
            shutil.copy(helper_modern, embedded_helper)
        elif helper_legacy is not None:
            shutil.copy(helper_legacy, embedded_helper)
        else:
            embedded_helper.write_bytes(b"")

        embedded_assets += [embedded_helper]
    else:
        exe_suffix = ".exe" if host_os == "windows" else ""

        embedded_helper_modern = priv_dir / f"frida-helper-64{exe_suffix}"
        embedded_helper_legacy = priv_dir / f"frida-helper-32{exe_suffix}"

        if helper_modern is not None:
            shutil.copy(helper_modern, embedded_helper_modern)
        else:
            embedded_helper_modern.write_bytes(b"")

        if helper_legacy is not None:
            shutil.copy(helper_legacy, embedded_helper_legacy)
        else:
            embedded_helper_legacy.write_bytes(b"")

        embedded_assets += [embedded_helper_modern, embedded_helper_legacy]

    subprocess.run([
        resource_compiler,
        f"--toolchain={host_toolchain}",
        f"--machine={host_arch}",
        "--config-filename", resource_config,
        "--output-basename", output_dir / "frida-data-helper-process",
    ] + embedded_assets, check=True)


def pop_cmd_array_arg(args):
    result = []
    first = args.pop(0)
    assert first == ">>>"
    while True:
        cur = args.pop(0)
        if cur == "<<<":
            break
        result.append(cur)
    if len(result) == 1 and not result[0]:
        return None
    return result


if __name__ == "__main__":
    main(sys.argv)
