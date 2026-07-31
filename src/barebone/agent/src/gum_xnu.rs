// XNU half of Gum's platform backend. Memory permissions and kernel-text writes
// go out over the hostlink, because the guest CPU cannot perform them itself:
// the host owns the page tables and the physical-memory bridge.

use crate::{
    FridaCommand,
    bindings::{
        _GumPageProtection_GUM_PAGE_EXECUTE, _GumPageProtection_GUM_PAGE_READ,
        _GumPageProtection_GUM_PAGE_WRITE, _GumRwxSupport_GUM_RWX_NONE, GArray,
        GumDebugSymbolDetails, GumMemoryRange, GumModuleRegistry, GumPageProtection, GumRwxSupport,
        g_array_append_vals, g_array_new, g_object_unref, g_strdup, g_variant_get_boolean,
        g_variant_get_uint64, g_variant_new, g_variant_new_fixed_array, g_variant_type_free,
        g_variant_type_new, g_variant_unref, gboolean, gchar, gconstpointer, gpointer, gsize, guint,
        gum_barebone_register_module,
        gum_barebone_try_remap_writable_pages as _gum_barebone_try_remap_writable_pages,
        gum_mprotect, gum_query_page_size,
    },
    gum::{self, FoundExportCallback},
    host_rpc, kernel, libc,
};
use alloc::format;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::mem::size_of;
use core::ptr;

const SHADOW_MAGIC: u64 = 0x4644_4f48_5341_4853;
const SHADOW_HEADER: usize = 24;
const SHADOW_MIN_ADDRESS: u64 = 0xffff_f000_0000_0000;

#[unsafe(no_mangle)]
pub extern "C" fn gum_query_rwx_support() -> GumRwxSupport {
    _GumRwxSupport_GUM_RWX_NONE
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_can_remap_writable() -> gboolean {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_try_remap_writable_pages(
    first_page: gpointer,
    n_pages: guint,
) -> gpointer {
    if gum::is_agent_slab(first_page as u64) {
        return remap_agent_pages(first_page, n_pages);
    }
    shadow_kernel_pages(first_page, n_pages)
}

fn remap_agent_pages(first_page: gpointer, n_pages: guint) -> gpointer {
    unsafe {
        let page_size = gum_query_page_size() as usize;
        let mut virtual_addrs = Vec::with_capacity(n_pages as usize);

        let mut current_page = first_page as u64;
        for _ in 0..n_pages {
            virtual_addrs.push(current_page as gpointer);
            current_page += page_size as u64;
        }

        _gum_barebone_try_remap_writable_pages(
            virtual_addrs.as_ptr() as *mut *const core::ffi::c_void,
            virtual_addrs.len() as guint,
        )
    }
}

fn shadow_kernel_pages(first_page: gpointer, n_pages: guint) -> gpointer {
    unsafe {
        let total = n_pages as usize * gum_query_page_size() as usize;
        let buffer = kernel::alloc(SHADOW_HEADER + total);
        *(buffer as *mut u64) = SHADOW_MAGIC;
        *(buffer.add(8) as *mut u64) = first_page as u64;
        *(buffer.add(16) as *mut u32) = n_pages;

        let body = buffer.add(SHADOW_HEADER);
        core::ptr::copy_nonoverlapping(first_page as *const u8, body, total);
        body as gpointer
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_dispose_writable_pages(writable: gpointer, _n_pages: guint) {
    if (writable as u64) < SHADOW_MIN_ADDRESS {
        return;
    }
    unsafe {
        let buffer = (writable as *mut u8).sub(SHADOW_HEADER);
        if *(buffer as *const u64) != SHADOW_MAGIC {
            return;
        }
        let first_page = *(buffer.add(8) as *const u64);
        let n_pages = *(buffer.add(16) as *const u32);
        let total = n_pages as usize * gum_query_page_size() as usize;

        commit_kernel_patch(first_page, writable as *const u8, total);
        libc::__clear_cache(first_page as *const u8, (first_page + total as u64) as *const u8);

        kernel::free(buffer, SHADOW_HEADER + total);
    }
}

unsafe fn commit_kernel_patch(address: u64, data: *const u8, len: usize) {
    unsafe {
        let element_type = g_variant_type_new(c"y".as_ptr());
        let bytes = g_variant_new_fixed_array(element_type, data as gconstpointer, len as gsize, 1);
        g_variant_type_free(element_type);

        let payload = g_variant_new(c"(t@ay)".as_ptr(), address, bytes);
        let reply = host_rpc(FridaCommand::PatchCode, payload);
        g_variant_unref(reply);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_try_remap_writable_pages(
    addrs: *const gpointer,
    n_addrs: guint,
) -> gpointer {
    if !crate::transport_is_up() {
        return ptr::null_mut();
    }
    unsafe {
        let element_type = g_variant_type_new(c"t".as_ptr());
        let payload = g_variant_new_fixed_array(
            element_type,
            addrs as gconstpointer,
            n_addrs as gsize,
            size_of::<u64>() as gsize,
        );
        g_variant_type_free(element_type);

        let reply = host_rpc(FridaCommand::RemapWritablePages, payload);
        let virtual_address = g_variant_get_uint64(reply);
        g_variant_unref(reply);

        virtual_address as gpointer
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_try_mprotect(
    address: gpointer,
    size: gsize,
    prot: GumPageProtection,
) -> gboolean {
    if !crate::transport_is_up() {
        return 1;
    }
    unsafe {
        let payload = g_variant_new(c"(ttu)".as_ptr(), address as u64, size as u64, prot as u32);

        let reply = host_rpc(FridaCommand::MemoryProtect, payload);
        let success = g_variant_get_boolean(reply);
        g_variant_unref(reply);

        if success != 0 {
            flush_tlb_range(address as u64, size as u64);
        }

        success
    }
}

// The host rewrites our page-table descriptors through the physical-memory
// bridge, which leaves this CPU's TLB holding the stale translation. Stalker
// flips a slab page RW then RX in place, so without this the freeze never takes
// effect and executing the page faults with a permission abort.
unsafe fn flush_tlb_range(address: u64, size: u64) {
    unsafe {
        let page_size = gum_query_page_size() as u64;
        let start = address & !(page_size - 1);
        let end = (address + size + page_size - 1) & !(page_size - 1);

        core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        let mut va = start;
        while va < end {
            core::arch::asm!("tlbi vaae1is, {operand}", operand = in(reg) va >> 12,
                options(nostack, preserves_flags));
            va += page_size;
        }
        core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
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
    // Executable slabs were flipped to RX in the page tables; restore RW before returning them to
    // the allocator, otherwise the reclaimed pages stay non-writable and the next consumer faults.
    if gum::is_agent_slab(address as u64) {
        unsafe {
            gum_mprotect(
                address,
                size,
                (_GumPageProtection_GUM_PAGE_READ | _GumPageProtection_GUM_PAGE_WRITE)
                    as GumPageProtection,
            );
        }
        gum::unregister_slab(address as u64);
    }
    kernel::free_code(address as *mut u8, size as usize);
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_on_registry_activating(registry: *mut GumModuleRegistry) {
    let kernel_base = kernel::get_kernel_base();

    unsafe {
        let module_infos = core::ptr::addr_of!(crate::MODULE_INFO);
        let module_infos = &*module_infos;

        let mut i = 0;
        for module_info in module_infos.iter() {
            let module_base = kernel_base + module_info.offset as u64;

            let module_path = if i == 0 {
                "/System/Library/Kernels/kernel"
            } else {
                &format!(
                    "/System/Library/Extensions/{}.kext/{}",
                    module_info.name, module_info.name
                )
            };
            let module_range = GumMemoryRange {
                base_address: module_base,
                size: module_info.size as u64,
            };

            let module = gum::gum_native_module_new(&module_path, &module_info.version, &module_range);
            gum_barebone_register_module(registry, module);
            g_object_unref(module as gpointer);

            i += 1;
        }
    }
}

pub(crate) unsafe fn enumerate_exports_in_range(
    start_address: u64,
    end_address: u64,
    callback: &mut FoundExportCallback<'_>,
) {
    unsafe {
        let symbol_table = core::ptr::addr_of!(crate::SYMBOL_TABLE);
        let symbol_table = &*symbol_table;

        const N_EXT: u8 = 0x01; // External symbol flag
        const N_TYPE: u8 = 0x0e; // Type mask
        const N_SECT: u8 = 0x0e; // Defined in section

        for symbol_ref in symbol_table.iter_symbols_in_range(start_address, end_address) {
            let is_external = (symbol_ref.symbol_type() & N_EXT) != 0;
            let is_defined = (symbol_ref.symbol_type() & N_TYPE) == N_SECT;
            if !is_external || !is_defined {
                continue;
            }

            if !callback(symbol_ref.name_ptr(), symbol_ref.address()) {
                break;
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_symbol_details_from_address(
    address: gpointer,
    details: *mut GumDebugSymbolDetails,
) -> gboolean {
    unsafe {
        let table = core::ptr::addr_of!(crate::SYMBOL_TABLE).read();
        if let Some(symbol) = table.find_symbol_by_address(address as u64) {
            let name_bytes = symbol.name().as_bytes();
            let copy_len = core::cmp::min(name_bytes.len(), 2048);
            core::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                (*details).symbol_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
            (*details).symbol_name[copy_len] = 0;

            (*details).address = symbol.address();

            (*details).module_name[0] = 0;
            (*details).file_name[0] = 0;
            (*details).line_number = 0;
            (*details).column = 0;

            return 1;
        }

        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_symbol_name_from_address(address: gpointer) -> *mut gchar {
    unsafe {
        let table = core::ptr::addr_of!(crate::SYMBOL_TABLE).read();
        let name_ptr = table.find_symbol_name_ptr_by_address(address as u64);
        g_strdup(name_ptr as *const gchar)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_find_function(name: *const gchar) -> gpointer {
    unsafe {
        let target_name = CStr::from_ptr(name).to_string_lossy();
        let table = core::ptr::addr_of!(crate::SYMBOL_TABLE).read();

        if let Some(symbol) = table.find_symbol_by_name(&target_name) {
            return symbol.address() as gpointer;
        }

        core::ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_find_functions_named(name: *const gchar) -> *mut GArray {
    unsafe {
        let array = g_array_new(0, 0, core::mem::size_of::<gpointer>() as guint);

        let target_name = CStr::from_ptr(name).to_string_lossy();
        let table = core::ptr::addr_of!(crate::SYMBOL_TABLE).read();

        let symbols = table.find_symbols_by_name(&target_name);
        for symbol in symbols {
            let addr = symbol.address() as gpointer;
            g_array_append_vals(array, &addr as *const gpointer as gconstpointer, 1);
        }

        array
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_find_functions_matching(pattern: *const gchar) -> *mut GArray {
    unsafe {
        let array = g_array_new(0, 0, core::mem::size_of::<gpointer>() as guint);

        let glob_pattern = CStr::from_ptr(pattern).to_string_lossy();
        let table = core::ptr::addr_of!(crate::SYMBOL_TABLE).read();

        let symbols = table.find_symbols_matching_glob(&glob_pattern);
        for symbol in symbols {
            let addr = symbol.address() as gpointer;
            g_array_append_vals(array, &addr as *const gpointer as gconstpointer, 1);
        }

        array
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_load_symbols(_path: *const gchar) -> gboolean {
    0
}
