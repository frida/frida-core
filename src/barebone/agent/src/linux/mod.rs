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
mod arena;
#[cfg(feature = "linux-injected")]
mod facade;
#[cfg(feature = "linux-injected")]
mod heap;
#[cfg(feature = "linux-injected")]
mod injection;
#[cfg(feature = "linux-injected")]
mod layout;
#[cfg(feature = "linux-injected")]
mod mapped;
#[cfg(feature = "linux-injected")]
mod native;
#[cfg(feature = "linux-injected")]
mod relay;
#[cfg(feature = "linux-injected")]
mod symbols;
#[cfg(feature = "linux-injected")]
mod threads;
#[cfg(feature = "linux-injected")]
mod user;
#[cfg(feature = "linux-injected")]
mod processes;

#[cfg(feature = "linux")]
pub use self::kmod::*;
#[cfg(feature = "linux-injected")]
pub use self::injection::*;
#[cfg(feature = "linux-injected")]
pub use self::relay::*;
#[cfg(feature = "linux-injected")]
pub use self::facade::*;
#[cfg(feature = "linux-injected")]
pub use self::native::{
    alloc_dma, free_dma, get_kernel_base, install_interrupt_handler, map_io, map_pages,
    pci_interrupt, run_when_ready, set_kernel_base, virt_to_phys,
};
#[cfg(feature = "linux-injected")]
pub use self::mapped::*;
#[cfg(feature = "linux-injected")]
pub use self::processes::*;
#[cfg(feature = "linux-injected")]
pub use self::symbols::*;
#[cfg(feature = "linux-injected")]
pub use self::threads::*;

#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub version: String,
    pub base: u64,
    pub size: u64,
}
