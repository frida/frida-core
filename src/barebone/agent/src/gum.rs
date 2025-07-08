use alloc::boxed::Box;
use crate::{bindings::{gboolean, gpointer, gsize, guint, GPrivate, GumPageProtection, GumThreadId, GumTlsKey}, gthread};

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
