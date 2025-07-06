use alloc::boxed::Box;
use crate::{bindings::{gboolean, gpointer, gsize, guint, GumPageProtection, GumTlsKey, GPrivate}, kprintln};

#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_query_page_size() -> guint {
    unsafe {
        let tcr_el1: u64;
        core::arch::asm!("mrs {}, tcr_el1", out(reg) tcr_el1, options(nomem, nostack));

        let tg0 = (tcr_el1 >> 14) & 0x3;

        let page_size = match tg0 {
            0b00 => 4096,
            0b01 => 65536,
            0b10 => 16384,
            _ => 4096,
        };

        kprintln!("gum_barebone_query_page_size() => {}", page_size);

        page_size
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_try_mprotect(
    address: gpointer,
    size: gsize,
    prot: GumPageProtection,
) -> gboolean {
    kprintln!("gum_try_mprotect: addr={:?} size={} prot={}", address, size, prot);
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

    kprintln!("gum_memory_allocate: size={} => {:?}", size, ptr);

    ptr as gpointer
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_free(address: gpointer, size: gsize) -> gboolean {
    kprintln!("gum_memory_free: address={:?} size={}", address, size);

    crate::xnu::free(address as *mut u8, size as usize);
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_tls_key_new() -> GumTlsKey {
    let private_key = Box::into_raw(Box::new(unsafe { core::mem::zeroed::<GPrivate>() }));
    let key = private_key as GumTlsKey;

    kprintln!("gum_tls_key_new() => {}", key);
    key
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_tls_key_free(key: GumTlsKey) {
    kprintln!("gum_tls_key_free({})", key);

    let private_key = key as *mut GPrivate;

    unsafe {
        let _ = Box::from_raw(private_key);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_tls_key_get_value(key: GumTlsKey) -> gpointer {
    let private_key = key as *mut GPrivate;
    let value = crate::gthread::g_private_get(private_key);
    kprintln!("gum_tls_key_get_value({}) => {:?}", key, value);
    value
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_tls_key_set_value(key: GumTlsKey, value: gpointer) {
    kprintln!("gum_tls_key_set_value({}, {:?})", key, value);

    let private_key = key as *mut GPrivate;
    crate::gthread::g_private_set(private_key, value);
}
