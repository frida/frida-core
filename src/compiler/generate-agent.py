#!/usr/bin/env python3

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


INPUTS = [
    "agent-entrypoint.js",
    "agent-core.ts",
    "agent-warmup.js",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "rollup.config.agent-core.ts",
    "rollup.config.typescript.ts",
]


def main(argv):
    input_dir, output_dir, priv_dir = [Path(d).resolve() for d in sys.argv[1:4]]
    host_os_family, host_arch, host_cpu_mode = sys.argv[4:7]
    v8_mksnapshot = sys.argv[7]
    if v8_mksnapshot != "":
        v8_mksnapshot = Path(v8_mksnapshot)
    else:
        v8_mksnapshot = None

    try:
        generate_agent(input_dir, output_dir, priv_dir, host_os_family, host_arch, host_cpu_mode, v8_mksnapshot)
    except subprocess.CalledProcessError as e:
        print(e, file=sys.stderr)
        print("Output:\n\t| " + "\n\t| ".join(e.output.strip().split("\n")), file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


def generate_agent(input_dir, output_dir, priv_dir, host_os_family, host_arch, host_cpu_mode, v8_mksnapshot):
    npm = os.environ.get("NPM", make_script_filename("npm"))

    entrypoint = input_dir / "agent-entrypoint.js"
    priv_dir.mkdir(exist_ok=True)
    for name in INPUTS:
        if name == "agent-entrypoint.js":
            continue
        shutil.copy(input_dir / name, priv_dir / name)

    run_kwargs = {
        "cwd": priv_dir,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "encoding": "utf-8",
        "check": True,
    }

    try:
        subprocess.run([npm, "install"], **run_kwargs)
        #subprocess.run([npm, "link", "/Users/oleavr/src/frida-compile"], **run_kwargs)
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

    components = ["typescript", "agent-core"]
    for component in components:
        subprocess.run([
                           npm, "run", "build:" + component,
                           "--",
                           "--environment", f"FRIDA_HOST_OS_FAMILY:{host_os_family},FRIDA_HOST_ARCH:{host_arch},FRIDA_HOST_CPU_MODE:{host_cpu_mode}",
                           "--silent",
                       ],
                       **run_kwargs)
    chunks = []
    for component in components:
        script = (priv_dir / f"{component}.js").read_text(encoding="utf-8")
        chunks.append(script)
    components_source = "\n".join(chunks)

    agent = output_dir / "agent.js"
    snapshot = output_dir / "snapshot.bin"

    if v8_mksnapshot is not None:
        shutil.copy(entrypoint, agent)
        (priv_dir / "embed.js").write_text(components_source, encoding="utf-8")
        subprocess.run([
                           v8_mksnapshot,
                           "--turbo-instruction-scheduling",
                           "--startup-blob=snapshot.bin",
                           "embed.js",
                           input_dir / "agent-warmup.js",
                       ],
                       **run_kwargs)
    else:
        agent.write_text("\n".join([
            components_source,
            entrypoint.read_text(encoding="utf-8"),
        ]), encoding="utf-8")
        snapshot.write_bytes(b"")


def make_script_filename(name):
    build_os = platform.system().lower()
    extension = ".cmd" if build_os == "windows" else ""
    return name + extension


if __name__ == "__main__":
    main(sys.argv)
