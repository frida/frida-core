// Win9x half of Gum's platform backend. The processors this kernel runs on have
// no execute permission to withhold and no supervisor write protection worth
// speaking of, so code is writable where it lies and none of the aliasing the
// other backends need arises.

use crate::{
    bindings::{
        _GumPageProtection_GUM_PAGE_EXECUTE, _GumRwxSupport_GUM_RWX_FULL, GumMemoryRange,
        GumModuleRegistry, GumPageProtection, GumRwxSupport, g_object_unref, gboolean, gpointer,
        gsize, guint, gum_barebone_register_module, gum_mprotect,
    },
    gum::{self, FoundExportCallback},
    kernel,
};
use core::ptr;

#[unsafe(no_mangle)]
pub extern "C" fn gum_query_rwx_support() -> GumRwxSupport {
    _GumRwxSupport_GUM_RWX_FULL
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_can_remap_writable() -> gboolean {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_try_remap_writable_pages(
    first_page: gpointer,
    _n_pages: guint,
) -> gpointer {
    first_page
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_dispose_writable_pages(_writable: gpointer, _n_pages: guint) {}

#[unsafe(no_mangle)]
pub extern "C" fn gum_try_mprotect(
    address: gpointer,
    size: gsize,
    prot: GumPageProtection,
) -> gboolean {
    if kernel::protect(address as u64, size as usize, prot as u32) {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_allocate(
    _address: gpointer,
    size: gsize,
    _alignment: gsize,
    prot: GumPageProtection,
) -> gpointer {
    let ptr = kernel::alloc_code(size as usize);
    if ptr.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        core::ptr::write_bytes(ptr, 0, size as usize);
        if (prot & _GumPageProtection_GUM_PAGE_EXECUTE) != 0 {
            gum::register_slab(ptr as u64, size as usize);
            gum_mprotect(ptr as gpointer, size, prot);
        }
    }

    ptr as gpointer
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_free(address: gpointer, size: gsize) -> gboolean {
    if gum::is_agent_slab(address as u64) {
        gum::unregister_slab(address as u64);
    }
    kernel::free_code(address as *mut u8, size as usize);
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_on_registry_activating(registry: *mut GumModuleRegistry) {
    let kernel_base = kernel::get_kernel_base();
    if kernel_base == 0 {
        return;
    }

    unsafe {
        let range = GumMemoryRange {
            base_address: kernel_base,
            size: 0,
        };
        let module = gum::gum_native_module_new("/VMM32.VXD", "", &range);
        gum_barebone_register_module(registry, module);
        g_object_unref(module as gpointer);
    }
}

// Nothing here has a symbol table to walk: the loader resolves VxD services
// through a dispatch table rather than by name.
pub(crate) unsafe fn enumerate_exports_in_range(
    _start: u64,
    _end: u64,
    _callback: &mut FoundExportCallback,
) {
}
