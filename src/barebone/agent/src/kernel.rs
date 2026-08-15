// Facade over the host kernel the agent is running inside of. Both backends
// expose the same primitives, so the rest of the agent never names a specific
// kernel.
//
// XNU is reached from the outside: a remote stub injects the agent and patches
// the addresses it needs into .kernel_addrs. Linux is reached from the inside:
// the agent is a kernel module, so its glue is an ordinary C translation unit
// (linux/frida-kmod.c) compiled against the target kernel's headers by kbuild.

#[cfg(feature = "linux")]
pub use crate::linux::*;
#[cfg(feature = "win9x")]
pub use crate::win9x::*;
#[cfg(feature = "winnt")]
pub use crate::winnt::*;
#[cfg(feature = "xnu")]
pub use crate::xnu::*;

use core::ffi::c_void;

pub type ThreadEntry = unsafe extern "C" fn(parameter: *mut c_void, wait_result: i32);

// Some flavors run this image on both sides of the privilege boundary: one copy in the kernel
// and one in a target process. Primitives that are different use this, not the flavor. Do not
// keep the value, because both sides share the image.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Kernel,
    User,
}

pub struct ThreadInfo {
    pub id: u32,
    pub cpu_state: Option<CpuState>,
}

pub struct CpuState {
    pub eip: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
}
