use core::ffi::c_void;

pub fn bootstrap_offset() -> usize {
    (frida_linux_user_bootstrap as usize) - crate::own_range().0
}

// The first thing the copy does is say that it woke up where it was meant to, which is what
// the host is waiting to hear.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl frida_linux_user_bootstrap",
    "frida_linux_user_bootstrap:",
    "ldr w1, [x0, #4]",
    "str w1, [x0]",
    "mov x0, #0",
    "mov x8, #93",
    "svc #0",
);

unsafe extern "C" {
    fn frida_linux_user_bootstrap(arena: *mut c_void) -> !;
}
