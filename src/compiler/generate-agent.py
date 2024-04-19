#!/usr/bin/env python3

from pathlib import Path
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
    output_dir, priv_dir, input_dir, npm, v8_mksnapshot = [Path(d).resolve() if d else None for d in argv[1:6]]
    host_os_family, host_arch, host_cpu_mode = argv[6:9]

    try:
        generate_agent(output_dir, priv_dir, input_dir, npm, v8_mksnapshot, host_os_family, host_arch, host_cpu_mode)
    except subprocess.CalledProcessError as e:
        print(e, file=sys.stderr)
        print("Output:\n\t| " + "\n\t| ".join(e.output.strip().split("\n")), file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


def generate_agent(output_dir, priv_dir, input_dir, npm, v8_mksnapshot, host_os_family, host_arch, host_cpu_mode):
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

    subprocess.run([npm, "install"], **run_kwargs)
    #subprocess.run([npm, "link", "/Users/oleavr/src/frida-compile"], **run_kwargs)

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


if __name__ == "__main__":
    main(sys.argv)
