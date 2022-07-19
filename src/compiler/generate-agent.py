#!/usr/bin/env python3

from glob import glob
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


DEPS = {
    "frida-compile": "11.1.0",
}


def generate_agent(input_dir, output_dir):
    npm = os.environ.get("NPM", make_script_filename("npm"))

    output_dir.mkdir(parents=True, exist_ok=True)
    for name in ["agent.ts", "package.json", "package-lock.json", "tsconfig.json"]:
        shutil.copyfile(input_dir / name, output_dir / name)

    dist_dir = output_dir / "dist"

    if dist_dir.exists():
        shutil.rmtree(dist_dir)

    try:
        subprocess.run([npm, "install"], capture_output=True, cwd=output_dir, check=True)
        #subprocess.run([npm, "link", "/home/oleavr/src/frida-compile"], capture_output=True, cwd=output_dir, check=True)
    except Exception as e:
        message = "\n".join([
            "",
            "***",
            "Failed to bootstrap the compiler agent:",
            "\t" + str(e),
            "It appears Node.js is not installed.",
            "We need it for processing JavaScript code at build-time.",
            "Check PATH or set NPM to the absolute path of your npm binary.",
            "***\n",
        ])
        raise EnvironmentError(message)

    subprocess.run([npm, "run", "build"], cwd=output_dir, check=True)

    assets = []

    compiler_dir = output_dir / "node_modules" / "frida-compile"
    using_linked_compiler = (compiler_dir / "node_modules").is_dir()
    if using_linked_compiler:
        asset_parent_dir = compiler_dir
    else:
        asset_parent_dir = output_dir
    asset_modules_dir = asset_parent_dir / "node_modules"

    shim_dirs = [
        asset_modules_dir / "@frida" / "**",
        asset_modules_dir / "frida-fs" / "**",
    ]
    for shim_dir in shim_dirs:
        assets += glob(str(shim_dir / "package.json"), recursive=True)
        assets += glob(str(shim_dir / "*.js"), recursive=True)

    types_dir = asset_modules_dir / "@types" / "**"
    assets += glob(str(types_dir / "package.json"), recursive=True)
    assets += glob(str(types_dir / "*.d.ts"), recursive=True)

    assets += glob(str(compiler_dir / "ext" / "lib.es*.d.ts"))

    ignored_asset_files = set([
        "@frida/process/browser.js",
    ])

    for asset_path in assets:
        asset_relpath = Path(asset_path).relative_to(asset_parent_dir)
        if using_linked_compiler and asset_relpath.parts[0] == "ext":
            asset_relpath = Path("node_modules") / "frida-compile" / asset_relpath

        identifier = "/".join(asset_relpath.parts[-3:])
        if identifier in ignored_asset_files:
            continue

        destination = dist_dir / asset_relpath
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(asset_path, destination)

    shutil.make_archive(output_dir / "agent", "zip", dist_dir)


def make_script_filename(name):
    build_os = platform.system().lower()
    extension = ".cmd" if build_os == "windows" else ""
    return name + extension


if __name__ == "__main__":
    input_dir, output_dir = [Path(d).resolve() for d in sys.argv[1:3]]

    try:
        generate_agent(input_dir, output_dir)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)
