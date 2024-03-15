#!/usr/bin/env python3

import os
from pathlib import Path
import platform
import shutil
from subprocess import PIPE, STDOUT, CalledProcessError
import subprocess
import sys


def generate_runtime(input_dir, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)

    runtime_reldir = Path("frida-cshell")
    runtime_srcdir = input_dir / runtime_reldir
    runtime_intdir = output_dir / runtime_reldir
    if runtime_intdir.exists():
        shutil.rmtree(runtime_intdir)
    shutil.copytree(runtime_srcdir, runtime_intdir)

    npm = os.environ.get("NPM", make_script_filename("npm"))
    try:
        subprocess.run([npm, "install"], stdout=PIPE, stderr=STDOUT, cwd=runtime_intdir, check=True)
        shutil.copy(runtime_intdir / "frida-cshell.js", output_dir)
    except CalledProcessError as e:
        message = "\n".join([
            "",
            "***",
            "Failed to bootstrap the CShell backend script runtime:",
            "\t" + str(e),
            "It appears Node.js is not installed.",
            "We need it for processing JavaScript code at build-time.",
            "Check PATH or set NPM to the absolute path of your npm binary.",
            "***\n",
            e.stdout.decode("utf-8")
        ])
        raise EnvironmentError(message)


def make_script_filename(name):
    build_os = platform.system().lower()
    extension = ".cmd" if build_os == "windows" else ""
    return name + extension


if __name__ == "__main__":
    input_dir, output_dir = [Path(d).resolve() for d in sys.argv[1:3]]

    try:
        generate_runtime(input_dir, output_dir)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)
