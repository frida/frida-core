import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List


def main(argv):
    host_os, host_arch = argv[1:3]
    output_dir, priv_dir, go, npm, *inputs = [Path(d).resolve() for d in argv[3:]]

    try:
        build_backend(host_os, host_arch, inputs, output_dir, priv_dir, go, npm)
    except subprocess.CalledProcessError as e:
        print(e, file=sys.stderr)
        print(
            "Output:\n\t| " + "\n\t| ".join(e.output.strip().split("\n")),
            file=sys.stderr,
        )
        sys.exit(2)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


def build_backend(
    host_os: str,
    host_arch: str,
    inputs: List[Path],
    output_dir: Path,
    priv_dir: Path,
    go: Path,
    npm: Path,
):
    base_dir = min(inputs, key=lambda p: len(p.parts)).parent
    for f in inputs:
        dest = priv_dir / f.relative_to(base_dir)
        dest.parent.mkdir(exist_ok=True)
        shutil.copy(f, dest)

    go_sources = [str(f.relative_to(base_dir)) for f in inputs if f.suffix == ".go"]

    run_kwargs = {
        "cwd": priv_dir,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "encoding": "utf-8",
        "check": True,
    }

    subprocess.run([npm, "install"], **run_kwargs)
    # subprocess.run([npm, "link", "/Users/oleavr/src/frida-compile"], **run_kwargs)

    extra_args = []

    if host_os == "macos":
        extra_args.append("-ldflags=-extldflags=-mmacosx-version-min=11.0")

    subprocess.run(
        [
            go,
            "build",
            "-buildmode=c-archive",
            "-o",
            output_dir / "frida-compiler-backend.a",
            *extra_args,
            *go_sources,
        ],
        env={
            "MACOSX_DEPLOYMENT_TARGET": "11.0",
            **os.environ,
        },
        **run_kwargs
    )


if __name__ == "__main__":
    main(sys.argv)
