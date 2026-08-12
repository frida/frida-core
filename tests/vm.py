#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
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

        subparsers.add_parser("check-kmod",
                              help="verify that a kmod guest can be booted, fetching what it needs")

        boot_kmod = subparsers.add_parser("boot-kmod",
                                          help="boot the running kernel in a guest and load a module into it")
        boot_kmod.add_argument("--module", type=Path, required=True)
        boot_kmod.add_argument("--kernel", type=Path)
        boot_kmod.add_argument("--memory", type=int, default=512)
        boot_kmod.add_argument("--ibt", action=argparse.BooleanOptionalAction, default=True)

        args = parser.parse_args()
        action, target = args.command.split("-", maxsplit=1)
        if target == "kmod":
            if action == "check":
                check_kmod_guest()
            else:
                boot_kmod_guest(args)
        elif action == "check":
            check_guest(target)
        else:
            boot_guest(target, args)
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


def check_kmod_guest():
    guest = GUESTS[KMOD_GUEST_ARCH]
    require_qemu(guest)
    require_program("cpio")
    fetch_busybox(guest)

    kernel = host_kernel()
    if not os.access(kernel, os.R_OK):
        raise Unavailable(f"{kernel} is not readable")

    print("ok")


def boot_kmod_guest(args):
    guest = GUESTS[KMOD_GUEST_ARCH]
    qemu = require_qemu(guest)
    busybox = fetch_busybox(guest)
    kernel = args.kernel if args.kernel is not None else host_kernel()

    cmdline = ["console=ttyS0", "panic=-1"]
    if not args.ibt:
        cmdline.append("ibt=off")

    with tempfile.TemporaryDirectory() as staging_dir:
        initramfs = build_initramfs(Path(staging_dir), busybox, args.module)

        process = subprocess.Popen([
            qemu,
            "-m", str(args.memory),
            "-enable-kvm",
            "-cpu", "host",
            "-kernel", str(kernel),
            "-initrd", str(initramfs),
            "-append", " ".join(cmdline),
            "-display", "none",
            "-serial", "stdio",
            "-monitor", "none",
            "-no-reboot",
        ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        listening = False
        try:
            for raw_line in process.stdout:
                line = raw_line.decode(errors="replace").rstrip()
                print(line, file=sys.stderr)
                if MODULE_LOAD_FAILED_MARKER in line:
                    raise Unavailable("the module failed to load")
                if not listening and AGENT_READY_MARKER in line:
                    print("ready", flush=True)
                    listening = True

            if not listening:
                raise Unavailable("guest exited before the module was listening")
        finally:
            process.kill()


def require_qemu(guest: "Guest") -> str:
    qemu = shutil.which(guest.qemu_binary)
    if qemu is None:
        raise Unavailable(f"{guest.qemu_binary} is not installed")
    return qemu


def fetch_kernel(guest: "Guest") -> Path:
    return fetch_cached(guest, "vmlinuz-lts", guest.kernel_url)


def require_program(name: str) -> str:
    program = shutil.which(name)
    if program is None:
        raise Unavailable(f"{name} is not installed")
    return program


def fetch_busybox(guest: "Guest") -> Path:
    return fetch_cached(guest, "busybox", BUSYBOX_URL)


def host_kernel() -> Path:
    return Path("/boot") / ("vmlinuz-" + os.uname().release)


def build_initramfs(staging_dir: Path, busybox: Path, module: Path) -> Path:
    root = staging_dir / "root"
    (root / "bin").mkdir(parents=True)
    (root / "proc").mkdir()

    shutil.copy(busybox, root / "bin" / "busybox")
    (root / "bin" / "busybox").chmod(0o755)
    for applet in ("sh", "insmod", "dmesg", "mount", "poweroff", "cat"):
        (root / "bin" / applet).symlink_to("busybox")

    shutil.copy(module, root / module.name)

    init = root / "init"
    init.write_text("\n".join([
        "#!/bin/sh",
        "mount -t proc proc /proc",
        f"insmod /{module.name} || echo {MODULE_LOAD_FAILED_MARKER}",
        "cat /proc/self/maps > /dev/null",
        "dmesg",
        "exec sh",
        "",
    ]))
    init.chmod(0o755)

    initramfs = staging_dir / "initramfs.cpio"
    names = subprocess.run(["find", "."], cwd=root, check=True, capture_output=True)
    with initramfs.open("wb") as f:
        subprocess.run(["cpio", "--create", "--format=newc", "--quiet"],
                       cwd=root, input=names.stdout, stdout=f, check=True)

    return initramfs


def fetch_cached(guest: "Guest", name: str, url: str) -> Path:
    cached = cache_dir(guest) / name
    if cached.exists():
        return cached

    cached.parent.mkdir(parents=True, exist_ok=True)
    staging = cached.with_suffix(".partial")
    try:
        with urllib.request.urlopen(url, timeout=60) as response, staging.open("wb") as f:
            shutil.copyfileobj(response, f)
    except Exception as e:
        staging.unlink(missing_ok=True)
        raise Unavailable(f"unable to download {url}: {e}")
    staging.replace(cached)

    return cached


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

KMOD_GUEST_ARCH = "x86_64"

BUSYBOX_URL = "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"

AGENT_READY_MARKER = "frida: listening on /dev/"
MODULE_LOAD_FAILED_MARKER = "frida-kmod-load-failed"


if __name__ == "__main__":
    try:
        main()
    except Unavailable as e:
        print(f"unavailable: {e}", file=sys.stderr)
        sys.exit(2)
