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
    priv_dir = Path(args.pop(0))
    resource_config = args.pop(0)
    agent_modern, agent_legacy, \
            agent_emulated_modern, agent_emulated_legacy, \
            agent_dbghelp_prefix, agent_symsrv_prefix \
            = [Path(p) if p else None for p in args[:6]]

    if agent_modern is None and agent_legacy is None:
        print("At least one agent must be provided", file=sys.stderr)
        sys.exit(1)

    priv_dir.mkdir(exist_ok=True)

    embedded_assets = []
    if host_os == "windows":
        for agent, flavor in [(agent_modern, "64"),
                              (agent_legacy, "32")]:
            embedded_agent = priv_dir / f"frida-agent-{flavor}.dll"
            embedded_dbghelp = priv_dir / f"dbghelp-{flavor}.dll"
            embedded_symsrv = priv_dir / f"symsrv-{flavor}.dll"

            if agent is not None:
                shutil.copy(agent, embedded_agent)

                if agent_dbghelp_prefix is not None:
                    shutil.copy(agent_dbghelp_prefix / f"dbghelp-{flavor}.dll", embedded_dbghelp)
                else:
                    embedded_dbghelp.write_bytes(b"")

                if agent_symsrv_prefix is not None:
                    shutil.copy(agent_symsrv_prefix / f"symsrv-{flavor}.dll", embedded_symsrv)
                else:
                    embedded_symsrv.write_bytes(b"")
            else:
                for f in [embedded_agent, embedded_dbghelp, embedded_symsrv]:
                    f.write_bytes(b"")

            embedded_assets += [embedded_agent, embedded_dbghelp, embedded_symsrv]
    elif host_os in {"macos", "ios", "watchos", "tvos"}:
        embedded_agent = priv_dir / "frida-agent.dylib"
        if agent_modern is not None and agent_legacy is not None:
            subprocess.run(lipo + [agent_modern, agent_legacy, "-create", "-output", embedded_agent],
                           check=True)
        elif agent_modern is not None:
            shutil.copy(agent_modern, embedded_agent)
        else:
            shutil.copy(agent_legacy, embedded_agent)
        embedded_assets += [embedded_agent]
    elif host_os in {"linux", "android"}:
        for agent, flavor in [(agent_modern, "64"),
                              (agent_legacy, "32"),
                              (agent_emulated_modern, "arm64"),
                              (agent_emulated_legacy, "arm")]:
            embedded_agent = priv_dir / f"frida-agent-{flavor}.so"
            if agent is not None:
                shutil.copy(agent, embedded_agent)
            else:
                embedded_agent.write_bytes(b"")
            embedded_assets += [embedded_agent]
    elif host_os in {"freebsd", "qnx"}:
        embedded_agent = priv_dir / "frida-agent.so"
        agent = agent_modern if agent_modern is not None else agent_legacy
        shutil.copy(agent, embedded_agent)
        embedded_assets += [embedded_agent]
    else:
        print("Unsupported OS", file=sys.stderr)
        sys.exit(1)

    subprocess.run([
        resource_compiler,
        f"--toolchain={host_toolchain}",
        f"--machine={host_arch}",
        "--config-filename", resource_config,
        "--output-basename", output_dir / "frida-data-agent",
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
