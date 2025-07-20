use alloc::boxed::Box;
use core::ffi::CStr;
use crate::{bindings::{gboolean, gpointer, gsize, guint, GPrivate, GumPageProtection, GumThreadId, GumTlsKey, GumDebugSymbolDetails, GArray, g_array_new, g_array_append_vals, gchar, gconstpointer, g_strdup}, gthread, libc};
use core::arch::asm;

#[unsafe(no_mangle)]
pub extern "C" fn gum_process_get_current_thread_id() -> GumThreadId {
    unsafe { gthread::get_current_thread_id() }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_query_page_size() -> guint {
    unsafe {
        let tcr_el1: u64;
        core::arch::asm!("mrs {}, tcr_el1", out(reg) tcr_el1, options(nomem, nostack));

        let tg0 = (tcr_el1 >> 14) & 0x3;

        match tg0 {
            0b00 => 4096,
            0b01 => 65536,
            0b10 => 16384,
            _ => 4096,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_virtual_to_physical(virt_addr: gpointer) -> gpointer {
    let virt_addr = virt_addr as usize;
    let phys_addr: usize;
    unsafe {
        asm!(
            "at s1e1r, {virt}",
            "mrs {phys}, par_el1",
            virt = in(reg) virt_addr,
            phys = out(reg) phys_addr,
            options(nomem, nostack),
        );
    }

    if (phys_addr & 1) == 0 {
        let page_size = gum_barebone_query_page_size() as usize;
        let offset_mask = page_size - 1;

        let pa_bits = (phys_addr >> 12) & ((1usize << (48 - 12)) - 1);
        let offset = virt_addr & offset_mask;
        ((pa_bits << 12) | offset) as gpointer
    } else {
        virt_addr as gpointer
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_try_mprotect(
    _address: gpointer,
    _size: gsize,
    _prot: GumPageProtection,
) -> gboolean {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_allocate(
    _address: gpointer,
    size: gsize,
    _alignment: gsize,
    _prot: GumPageProtection,
) -> gpointer {
    let ptr = crate::xnu::kalloc(size as usize);
    if !ptr.is_null() {
        unsafe {
            core::ptr::write_bytes(ptr, 0, size as usize);
        }
    }
    ptr as gpointer
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_free(address: gpointer, size: gsize) -> gboolean {
    crate::xnu::free(address as *mut u8, size as usize);
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_clear_cache(address: gpointer, size: gsize) {
    unsafe {
        let start = address as *const u8;
        let end = start.add(size as usize);
        libc::__clear_cache(start, end);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_tls_key_new() -> GumTlsKey {
    Box::into_raw(Box::new(unsafe { core::mem::zeroed::<GPrivate>() })) as GumTlsKey
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_tls_key_free(key: GumTlsKey) {
    unsafe {
        let _ = Box::from_raw(key as *mut GPrivate);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_tls_key_get_value(key: GumTlsKey) -> gpointer {
    gthread::g_private_get(key as *mut GPrivate)
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_tls_key_set_value(key: GumTlsKey, value: gpointer) {
    gthread::g_private_set(key as *mut GPrivate, value)
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_symbol_details_from_address(
    address: gpointer,
    details: *mut GumDebugSymbolDetails,
) -> gboolean {
    unsafe {
        if let Some(symbol) = find_symbol_by_address(address as u64) {
            let name_bytes = symbol.name.as_bytes();
            let copy_len = core::cmp::min(name_bytes.len(), 2048);
            core::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                (*details).symbol_name.as_mut_ptr() as *mut u8,
                copy_len,
            );
            (*details).symbol_name[copy_len] = 0;

            (*details).address = symbol.address;

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
        if let Some(symbol) = find_symbol_by_address(address as u64) {
            let name_bytes = symbol.name.as_bytes();
            let name_ptr = crate::xnu::kalloc(name_bytes.len() + 1);
            if !name_ptr.is_null() {
                core::ptr::copy_nonoverlapping(
                    name_bytes.as_ptr(),
                    name_ptr as *mut u8,
                    name_bytes.len(),
                );
                *((name_ptr as *mut u8).add(name_bytes.len())) = 0;

                let result = g_strdup(name_ptr as *const gchar);
                crate::xnu::free(name_ptr as *mut u8, name_bytes.len() + 1);
                return result;
            }
        }

        core::ptr::null_mut()
    }
}

unsafe fn find_symbol_by_address(address: u64) -> Option<&'static crate::DarwinSymbolDetails> {
    unsafe {
        let symbols = &*core::ptr::addr_of!(crate::SYMBOL_TABLE);
        let mut best_match: Option<&crate::DarwinSymbolDetails> = None;
        let mut best_distance = u64::MAX;

        for symbol in symbols.iter() {
            if symbol.address <= address {
                let distance = address - symbol.address;
                if distance < best_distance {
                    best_distance = distance;
                    best_match = Some(symbol);
                }
            }
        }

        best_match
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_find_function(name: *const gchar) -> gpointer {
    unsafe {
        let target_name = CStr::from_ptr(name).to_string_lossy();

        let symbols = &*core::ptr::addr_of!(crate::SYMBOL_TABLE);
        let name_index = &*core::ptr::addr_of!(crate::SYMBOL_NAME_INDEX);

        if let Some(&index) = name_index.get(&*target_name) {
            if let Some(symbol) = symbols.get(index) {
                return symbol.address as gpointer;
            }
        }

        core::ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_find_functions_named(name: *const gchar) -> *mut GArray {
    unsafe {
        let array = g_array_new(0, 0, core::mem::size_of::<gpointer>() as guint);

        let target_name = CStr::from_ptr(name).to_string_lossy();

        let symbols = &*core::ptr::addr_of!(crate::SYMBOL_TABLE);
        let name_index = &*core::ptr::addr_of!(crate::SYMBOL_NAME_INDEX);

        if let Some(&index) = name_index.get(&*target_name) {
            if let Some(symbol) = symbols.get(index) {
                let addr = symbol.address as gpointer;
                g_array_append_vals(array, &addr as *const gpointer as gconstpointer, 1);
            }
        }

        array
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_find_functions_matching(pattern: *const gchar) -> *mut GArray {
    unsafe {
        let array = g_array_new(0, 0, core::mem::size_of::<gpointer>() as guint);

        let pattern_str = CStr::from_ptr(pattern).to_string_lossy();

        let symbols = &*core::ptr::addr_of!(crate::SYMBOL_TABLE);
        for symbol in symbols.iter() {
            if symbol.name.contains(&*pattern_str) {
                let addr = symbol.address as gpointer;
                g_array_append_vals(array, &addr as *const gpointer as gconstpointer, 1);
            }
        }

        array
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_load_symbols(_path: *const gchar) -> gboolean {
    0
}
