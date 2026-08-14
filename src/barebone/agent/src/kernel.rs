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
#[cfg(feature = "xnu")]
pub use crate::xnu::*;

use core::ffi::c_void;

pub type ThreadEntry = unsafe extern "C" fn(parameter: *mut c_void, wait_result: i32);
