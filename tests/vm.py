#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import urllib.request


def main():
    if len(sys.argv) >= 2 and sys.argv[1] in SUBCOMMANDS:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)

        subparsers.add_parser("check-x86",
                              help="verify that the x86 guest can be booted, fetching it if needed")

        boot_x86 = subparsers.add_parser("boot-x86",
                                         help="boot a minimal x86 guest with the GDB stub enabled")
        boot_x86.add_argument("--gdb-port", type=int, required=True)
        boot_x86.add_argument("--memory", type=int, default=256)

        args = parser.parse_args()
        SUBCOMMANDS[args.command](args)
        return

    arch = sys.argv[1]
    args = sys.argv[2:] if len(sys.argv) >= 3 else []
    run(arch, args)


def run(arch: str, args: [str]):
    import pexpect

    child = pexpect.spawn("arm_now", ["start", arch, "--sync"])

    child.expect("buildroot login: ")
    child.sendline("root")
    child.expect("# ")

    child.sendline(shlex.join(["/root/frida-tests"] + args))
    child.interact()


def check_x86(args):
    """
    Do everything boot-x86 needs except the boot itself, so that a caller can tell a missing
    prerequisite apart from a guest that failed to come up — and pay for the download here
    rather than inside its connect timeout.
    """
    require_qemu()
    fetch_kernel()
    print("ok")


def boot_x86(args):
    """
    Boot a stock 32-bit Linux kernel far enough to have its page tables up, and hand it to
    QEMU's GDB stub. There is no root filesystem, so the kernel panics once it goes looking
    for one; panic=0 then parks it forever with paging still enabled, which is exactly the
    quiescent state we want to inspect.

    QEMU discards every GDB packet except Ctrl-C while the guest is running, so the caller
    cannot attach and then wait for the boot — it has to wait first. Watch the serial console
    on its behalf and announce readiness once the kernel has parked itself.
    """
    qemu = require_qemu()
    kernel = fetch_kernel()

    process = subprocess.Popen([
        qemu,
        "-m", str(args.memory),
        "-kernel", str(kernel),
        "-append", "console=ttyS0 panic=0",
        "-display", "none",
        "-serial", "stdio",
        "-monitor", "none",
        "-no-reboot",
        "-gdb", f"tcp::{args.gdb_port}",
    ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    try:
        for raw_line in process.stdout:
            line = raw_line.decode(errors="replace").rstrip()
            print(line, file=sys.stderr)
            if BOOT_COMPLETE_MARKER in line:
                print("ready", flush=True)
                process.wait()
                return

        raise Unavailable("guest exited before it finished booting")
    finally:
        process.kill()


def require_qemu() -> str:
    qemu = shutil.which(QEMU_BINARY)
    if qemu is None:
        raise Unavailable(f"{QEMU_BINARY} is not installed")
    return qemu


def fetch_kernel() -> Path:
    kernel = cache_dir() / "vmlinuz-lts"
    if kernel.exists():
        return kernel

    kernel.parent.mkdir(parents=True, exist_ok=True)
    staging = kernel.with_suffix(".partial")
    try:
        with urllib.request.urlopen(KERNEL_URL, timeout=60) as response, staging.open("wb") as f:
            shutil.copyfileobj(response, f)
    except Exception as e:
        staging.unlink(missing_ok=True)
        raise Unavailable(f"unable to download {KERNEL_URL}: {e}")
    staging.replace(kernel)

    return kernel


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base is not None else Path.home() / ".cache"
    return root / "frida-tests" / "qemu-x86"


class Unavailable(Exception):
    pass


QEMU_BINARY = "qemu-system-i386"

# Paging comes up long before this, so the panic that follows the missing root filesystem is a
# safely late — and unmistakable — sign that the kernel has finished with its page tables.
BOOT_COMPLETE_MARKER = "Kernel panic"

# Alpine's netboot kernel is the smallest stock x86 kernel that is trivially fetchable. It is
# not versioned in-place, so treat whatever the mirror currently serves as the fixture; the
# test only cares that it is a Linux kernel that enables paging.
KERNEL_URL = "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86/netboot/vmlinuz-lts"

SUBCOMMANDS = {
    "check-x86": check_x86,
    "boot-x86": boot_x86,
}


if __name__ == "__main__":
    try:
        main()
    except Unavailable as e:
        print(f"unavailable: {e}", file=sys.stderr)
        sys.exit(2)
