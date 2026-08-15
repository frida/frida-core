// The Windows part of Gum's platform backend, for Win9x and NT. Kernel code is writable on
// both, thus this backend needs no alias. Only the position of the modules is different.

use crate::{
    bindings::{
        _GumPageProtection_GUM_PAGE_EXECUTE, _GumRwxSupport_GUM_RWX_FULL, GumMemoryRange,
        GumCpuContext, GumModuleRegistry, GumPageProtection, GumRwxSupport, g_object_unref,
        gboolean, gpointer, gsize, guint, gum_barebone_register_module, gum_mprotect,
        GumFoundThreadFunc, GumThreadDetails, GumThreadFlags_GUM_THREAD_FLAGS_CPU_CONTEXT,
        GumThreadId,
    },
    gum::{self, FoundExportCallback},
    kernel,
};
use alloc::format;
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
    unsafe {
        let modules = &*core::ptr::addr_of!(crate::MODULE_INFO);

        for module_info in modules.iter() {
            let path = format!("{}{}", kernel::MODULE_DIRECTORY, module_info.name);
            let range = GumMemoryRange {
                base_address: module_info.offset as u64,
                size: module_info.size as gsize,
            };

            let module = gum::gum_native_module_new(&path, &module_info.version, &range);
            gum_barebone_register_module(registry, module);
            g_object_unref(module as gpointer);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_enumerate_threads(func: GumFoundThreadFunc, user_data: gpointer) {
    let Some(emit) = func else {
        return;
    };

    kernel::enumerate_threads(&mut |thread| {
        let mut details: GumThreadDetails = unsafe { core::mem::zeroed() };
        details.flags = 0;
        details.id = thread.id as GumThreadId;

        if let Some(state) = thread.cpu_state {
            details.flags = GumThreadFlags_GUM_THREAD_FLAGS_CPU_CONTEXT;
            details.cpu_context = GumCpuContext {
                eip: state.eip,
                edi: state.edi,
                esi: state.esi,
                ebp: state.ebp,
                esp: state.esp,
                ebx: state.ebx,
                edx: state.edx,
                ecx: state.ecx,
                eax: state.eax,
                xmm: ptr::null_mut(),
            };
        }

        unsafe { emit(&details, user_data) };
    });
}

pub(crate) unsafe fn enumerate_exports_in_range(
    start_address: u64,
    end_address: u64,
    callback: &mut FoundExportCallback,
) {
    unsafe {
        let symbol_table = &*core::ptr::addr_of!(crate::SYMBOL_TABLE);

        for symbol_ref in symbol_table.iter_symbols_in_range(start_address, end_address) {
            if !callback(symbol_ref.name_ptr(), symbol_ref.address()) {
                break;
            }
        }
    }
}
