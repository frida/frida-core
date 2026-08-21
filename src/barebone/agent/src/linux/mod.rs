// Linux backend. The agent reaches the kernel in one of two ways, and the rest
// of the agent cannot tell which: loaded from the inside as a kernel module,
// where every primitive is a call into a shim kbuild compiled against the
// target's headers; or injected from the outside like XNU and Windows, where
// the host patches the addresses it needs into .kernel_addrs and the memory it
// cannot touch is reached over the hostlink.

use alloc::string::String;

#[cfg(feature = "linux")]
mod kmod;
#[cfg(feature = "linux-injected")]
mod native;
#[cfg(feature = "linux-injected")]
mod processes;

#[cfg(feature = "linux")]
pub use self::kmod::*;
#[cfg(feature = "linux-injected")]
pub use self::native::*;
#[cfg(feature = "linux-injected")]
pub use self::processes::*;

#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub version: String,
    pub base: u64,
    pub size: u64,
}
