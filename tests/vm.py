#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from typing import NamedTuple
import urllib.request


def main():
    if len(sys.argv) >= 2 and sys.argv[1].split("-", maxsplit=1)[0] in ("check", "boot"):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)

        for arch in GUESTS:
            subparsers.add_parser(f"check-{arch}",
                                  help=f"verify that the {arch} guest can be booted, fetching it if needed")

            boot = subparsers.add_parser(f"boot-{arch}",
                                         help=f"boot a minimal {arch} guest with the GDB stub enabled")
            boot.add_argument("--gdb-port", type=int, required=True)
            boot.add_argument("--memory", type=int, default=256)

        args = parser.parse_args()
        action, arch = args.command.split("-", maxsplit=1)
        if action == "check":
            check_guest(arch)
        else:
            boot_guest(arch, args)
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


def check_guest(arch: str):
    """
    Do everything booting needs except the boot itself, so that a caller can tell a missing
    prerequisite apart from a guest that failed to come up — and pay for the download here
    rather than inside its connect timeout.
    """
    guest = GUESTS[arch]
    require_qemu(guest)
    fetch_kernel(guest)
    print("ok")


def boot_guest(arch: str, args):
    """
    Boot a stock 32-bit Linux kernel far enough to have its page tables up, and hand it to
    QEMU's GDB stub. There is no root filesystem, so the kernel panics once it goes looking
    for one; panic=0 then parks it forever with paging still enabled, which is exactly the
    quiescent state we want to inspect.

    QEMU discards every GDB packet except Ctrl-C while the guest is running, so the caller
    cannot attach and then wait for the boot — it has to wait first. Watch the serial console
    on its behalf and announce readiness once the kernel has parked itself.
    """
    guest = GUESTS[arch]
    qemu = require_qemu(guest)
    kernel = fetch_kernel(guest)

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


def require_qemu(guest: "Guest") -> str:
    qemu = shutil.which(guest.qemu_binary)
    if qemu is None:
        raise Unavailable(f"{guest.qemu_binary} is not installed")
    return qemu


def fetch_kernel(guest: "Guest") -> Path:
    kernel = cache_dir(guest) / "vmlinuz-lts"
    if kernel.exists():
        return kernel

    kernel.parent.mkdir(parents=True, exist_ok=True)
    staging = kernel.with_suffix(".partial")
    try:
        with urllib.request.urlopen(guest.kernel_url, timeout=60) as response, staging.open("wb") as f:
            shutil.copyfileobj(response, f)
    except Exception as e:
        staging.unlink(missing_ok=True)
        raise Unavailable(f"unable to download {guest.kernel_url}: {e}")
    staging.replace(kernel)

    return kernel


def cache_dir(guest: "Guest") -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base is not None else Path.home() / ".cache"
    return root / "frida-tests" / f"qemu-{guest.arch}"


class Unavailable(Exception):
    pass


class Guest(NamedTuple):
    arch: str
    qemu_binary: str
    kernel_url: str

# Paging comes up long before this, so the panic that follows the missing root filesystem is a
# safely late — and unmistakable — sign that the kernel has finished with its page tables.
BOOT_COMPLETE_MARKER = "Kernel panic"

# Alpine's netboot kernels are the smallest stock ones that are trivially fetchable. They are
# not versioned in-place, so treat whatever the mirror currently serves as the fixture; the
# tests only care that it is a Linux kernel that enables paging.
ALPINE_NETBOOT_URL = "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/{0}/netboot/vmlinuz-lts"

GUESTS = {
    guest.arch: guest
    for guest in [
        Guest("x86", "qemu-system-i386", ALPINE_NETBOOT_URL.format("x86")),
        Guest("x86_64", "qemu-system-x86_64", ALPINE_NETBOOT_URL.format("x86_64")),
    ]
}


if __name__ == "__main__":
    try:
        main()
    except Unavailable as e:
        print(f"unavailable: {e}", file=sys.stderr)
        sys.exit(2)
