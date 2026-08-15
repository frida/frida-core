// Gum's platform backend, without the parts that depend on the kernel. Memory protection,
// symbols and the module registry are in gum_xnu.rs, gum_linux.rs and gum_windows.rs.

use crate::{
    bindings::{
        _GInterfaceInfo, _GTypeInfo, GObject, GObjectClass, GPrivate, GType, GumExportDetails,
        GumExportType_GUM_EXPORT_FUNCTION, GumFoundExportFunc, GumMemoryRange, GumModule,
        GumModuleInterface, GumThreadId, GumTlsKey, g_free, g_object_get_type, g_object_new,
        g_once_init_enter, g_once_init_leave, g_strdup, g_type_add_interface_static,
        g_type_class_peek_parent, g_type_register_static, gchar, gboolean, gpointer, gsize, guint,
    },
    gthread, kernel, libc,
};
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(feature = "linux")]
use crate::gum_linux::enumerate_exports_in_range;
#[cfg(any(feature = "win9x", feature = "winnt"))]
use crate::gum_windows::enumerate_exports_in_range;
#[cfg(feature = "xnu")]
use crate::gum_xnu::enumerate_exports_in_range;

#[unsafe(no_mangle)]
pub extern "C" fn gum_process_get_current_thread_id() -> GumThreadId {
    kernel::current_thread_id() as GumThreadId
}

#[cfg(feature = "win9x")]
#[unsafe(no_mangle)]
pub extern "C" fn gum_process_get_id() -> guint {
    kernel::current_process_id() as guint
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_query_page_size() -> guint {
    4096
}

#[cfg(target_arch = "aarch64")]
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

#[repr(C)]
pub struct GumNativeModule {
    parent: GObject,
    name: *mut gchar,
    version: *mut gchar,
    path: *mut gchar,
    range: GumMemoryRange,
}

#[repr(C)]
#[allow(dead_code)]
pub struct GumNativeModuleClass {
    parent_class: GObjectClass,
}

static mut GUM_NATIVE_MODULE_TYPE: gsize = 0;
static mut GUM_NATIVE_MODULE_PARENT_CLASS: *mut GObjectClass = core::ptr::null_mut();

fn gum_native_module_get_type() -> GType {
    unsafe {
        if g_once_init_enter(
            core::ptr::addr_of_mut!(GUM_NATIVE_MODULE_TYPE) as *mut ::core::ffi::c_void
        ) != 0
        {
            let type_name = c"GumNativeModule".as_ptr() as *const gchar;

            let type_info = _GTypeInfo {
                class_size: core::mem::size_of::<GObjectClass>() as u16,
                base_init: None,
                base_finalize: None,
                class_init: Some(gum_native_module_class_init),
                class_finalize: None,
                class_data: core::ptr::null(),
                instance_size: core::mem::size_of::<GumNativeModule>() as u16,
                n_preallocs: 0,
                instance_init: None,
                value_table: core::ptr::null(),
            };

            let new_type = g_type_register_static(g_object_get_type(), type_name, &type_info, 0);

            let interface_info = _GInterfaceInfo {
                interface_init: Some(gum_native_module_iface_init),
                interface_finalize: None,
                interface_data: core::ptr::null_mut(),
            };

            g_type_add_interface_static(new_type, crate::bindings::gum_module_get_type(), &interface_info);

            g_once_init_leave(
                core::ptr::addr_of_mut!(GUM_NATIVE_MODULE_TYPE) as *mut ::core::ffi::c_void,
                new_type as gsize,
            );
        }

        GUM_NATIVE_MODULE_TYPE as GType
    }
}

unsafe extern "C" fn gum_native_module_class_init(klass: gpointer, _class_data: gpointer) {
    unsafe {
        let object_class = klass as *mut GObjectClass;

        GUM_NATIVE_MODULE_PARENT_CLASS = g_type_class_peek_parent(klass) as *mut GObjectClass;

        (*object_class).finalize = Some(gum_native_module_finalize);
    }
}

extern "C" fn gum_native_module_iface_init(g_iface: gpointer, _iface_data: gpointer) {
    unsafe {
        let iface = g_iface as *mut GumModuleInterface;
        (*iface).get_name = Some(gum_native_module_get_name);
        (*iface).get_version = Some(gum_native_module_get_version);
        (*iface).get_path = Some(gum_native_module_get_path);
        (*iface).get_range = Some(gum_native_module_get_range);
        (*iface).enumerate_exports = Some(gum_native_module_enumerate_exports);
    }
}

unsafe extern "C" fn gum_native_module_finalize(object: *mut GObject) {
    unsafe {
        let module = object as *mut GumNativeModule;

        g_free((*module).path as gpointer);

        (*GUM_NATIVE_MODULE_PARENT_CLASS).finalize.unwrap()(object);
    }
}

pub(crate) fn gum_native_module_new(
    path: &str,
    version: &str,
    range: &GumMemoryRange,
) -> *mut GumModule {
    unsafe {
        let path_cstr = CString::new(path).unwrap();
        let version_cstr = CString::new(version).unwrap();

        let module =
            g_object_new(gum_native_module_get_type(), ptr::null()) as *mut GumNativeModule;
        (*module).path = g_strdup(path_cstr.as_ptr());
        (*module).name = (*module).path.add(path.rfind('/').unwrap() + 1);
        (*module).version = g_strdup(version_cstr.as_ptr());
        (*module).range = *range;

        module as *mut GumModule
    }
}

extern "C" fn gum_native_module_get_name(module: *mut GumModule) -> *const gchar {
    unsafe {
        let native_module = module as *mut GumNativeModule;
        (*native_module).name as *const gchar
    }
}

extern "C" fn gum_native_module_get_version(module: *mut GumModule) -> *const gchar {
    unsafe {
        let native_module = module as *mut GumNativeModule;
        (*native_module).version as *const gchar
    }
}

extern "C" fn gum_native_module_get_path(module: *mut GumModule) -> *const gchar {
    unsafe {
        let native_module = module as *mut GumNativeModule;
        (*native_module).path as *const gchar
    }
}

extern "C" fn gum_native_module_get_range(module: *mut GumModule) -> *const GumMemoryRange {
    unsafe {
        let native_module = module as *mut GumNativeModule;
        &(*native_module).range as *const GumMemoryRange
    }
}

unsafe extern "C" fn gum_native_module_enumerate_exports(
    self_: *mut GumModule,
    func: GumFoundExportFunc,
    user_data: gpointer,
) {
    unsafe {
        let module = self_ as *mut GumNativeModule;
        let range = (*module).range;

        let mut on_export = |name: *const gchar, address: u64| {
            let export_details = GumExportDetails {
                type_: GumExportType_GUM_EXPORT_FUNCTION,
                name: g_strdup(name),
                address,
                size: -1,
            };

            func.unwrap()(&export_details as *const GumExportDetails, user_data) != 0
        };

        enumerate_exports_in_range(
            range.base_address,
            range.base_address + range.size as u64,
            &mut on_export,
        );
    }
}

/// What the backends implement for `gum_native_module_enumerate_exports`: call
/// `callback` for every exported function in `[start, end)`, stopping early when
/// it returns false.
pub(crate) type FoundExportCallback<'a> = dyn FnMut(*const gchar, u64) -> bool + 'a;

// Code slabs the agent allocates are normal writable RAM, so Gum can keep a real writable alias to
// them across the slab's lifetime. Pre-existing kernel text is write-protected — CTRR-locked on
// Apple silicon, STRICT_KERNEL_RWX on Linux — and can only be modified through a separate path, so
// we treat it differently. We distinguish the two by tracking the executable ranges we hand out.
static SLAB_LOCK: AtomicU32 = AtomicU32::new(0);
static mut SLABS: Vec<(u64, u64)> = Vec::new();

fn slab_lock() {
    while SLAB_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        kernel::yield_now();
    }
}

fn slab_unlock() {
    SLAB_LOCK.store(0, Ordering::Release);
}

pub(crate) fn register_slab(start: u64, size: usize) {
    slab_lock();
    unsafe {
        (*core::ptr::addr_of_mut!(SLABS)).push((start, start + size as u64));
    }
    slab_unlock();
}

pub(crate) fn unregister_slab(start: u64) {
    slab_lock();
    unsafe {
        (*core::ptr::addr_of_mut!(SLABS)).retain(|&(begin, _)| begin != start);
    }
    slab_unlock();
}

// For callers that must not block, primarily a fault handler, which can interrupt the code
// that holds the lock. Report a busy registry and let the caller decide.
pub(crate) fn is_agent_slab_if_idle(address: u64) -> Option<bool> {
    if SLAB_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return None;
    }
    let found = unsafe {
        (*core::ptr::addr_of!(SLABS))
            .iter()
            .any(|&(begin, end)| address >= begin && address < end)
    };
    slab_unlock();
    Some(found)
}

pub(crate) fn is_agent_slab(address: u64) -> bool {
    slab_lock();
    let found = unsafe {
        (*core::ptr::addr_of!(SLABS))
            .iter()
            .any(|&(begin, end)| address >= begin && address < end)
    };
    slab_unlock();
    found
}

// The host gives the symbol table, thus this makes a name from an address.
#[cfg(feature = "blob")]
mod symbolication {
    use super::*;
    use crate::bindings::{
        GArray, GumAddress, GumDebugSymbolDetails, g_array_append_vals, g_array_new, gconstpointer,
    };
    use core::ffi::CStr;

    #[unsafe(no_mangle)]
    pub extern "C" fn gum_symbol_name_from_address(address: gpointer) -> *mut gchar {
        match closest_to(address) {
            Some(symbol) => unsafe { g_strdup(symbol.name_ptr()) },
            None => ptr::null_mut(),
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn gum_symbol_details_from_address(
        address: gpointer,
        details: *mut GumDebugSymbolDetails,
    ) -> gboolean {
        let Some(symbol) = closest_to(address) else {
            return 0;
        };

        let details = unsafe { &mut *details };
        *details = unsafe { core::mem::zeroed() };
        details.address = address as u64;
        put_text(symbol.name(), &mut details.symbol_name);
        if let Some(module) = module_containing(address as u64) {
            put_text(&module.name, &mut details.module_name);
        }

        1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn gum_module_find_global_export_by_name(name: *const gchar) -> GumAddress {
        let Some(name) = text_of(name) else {
            return 0;
        };
        let table = unsafe { &*ptr::addr_of!(crate::SYMBOL_TABLE) };

        match table.find_symbol_by_name(name) {
            Some(symbol) => symbol.address(),
            None => 0,
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn gum_find_function(name: *const gchar) -> gpointer {
        let Some(name) = text_of(name) else {
            return ptr::null_mut();
        };
        let table = unsafe { &*ptr::addr_of!(crate::SYMBOL_TABLE) };

        match table.find_symbol_by_name(name) {
            Some(symbol) => symbol.address() as gpointer,
            None => ptr::null_mut(),
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn gum_find_functions_named(name: *const gchar) -> *mut GArray {
        let table = unsafe { &*ptr::addr_of!(crate::SYMBOL_TABLE) };
        let found = text_of(name)
            .map(|name| table.find_symbols_by_name(name).map(|s| s.address()).collect())
            .unwrap_or_else(Vec::new);

        pointer_array_of(&found)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn gum_find_functions_matching(pattern: *const gchar) -> *mut GArray {
        let table = unsafe { &*ptr::addr_of!(crate::SYMBOL_TABLE) };
        let found = text_of(pattern)
            .map(|pattern| {
                table
                    .find_symbols_matching_glob(pattern)
                    .map(|s| s.address())
                    .collect()
            })
            .unwrap_or_else(Vec::new);

        pointer_array_of(&found)
    }

    fn closest_to(address: gpointer) -> Option<crate::symbols::SymbolRef<'static>> {
        let table = unsafe { &*ptr::addr_of!(crate::SYMBOL_TABLE) };
        table.find_closest_symbol_by_address(address as u64)
    }

    fn module_containing(address: u64) -> Option<&'static crate::ModuleInfo> {
        let modules = unsafe { &*ptr::addr_of!(crate::MODULE_INFO) };

        modules.iter().find(|m| {
            address >= m.offset as u64 && address < m.offset as u64 + m.size as u64
        })
    }

    fn pointer_array_of(addresses: &[u64]) -> *mut GArray {
        let pointers: Vec<gpointer> = addresses.iter().map(|a| *a as gpointer).collect();

        unsafe {
            let array = g_array_new(0, 0, core::mem::size_of::<gpointer>() as guint);
            g_array_append_vals(
                array,
                pointers.as_ptr() as gconstpointer,
                pointers.len() as guint,
            );
            array
        }
    }

    fn text_of(value: *const gchar) -> Option<&'static str> {
        if value.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(value) }.to_str().ok()
    }

    fn put_text(text: &str, out: &mut [gchar]) {
        let limit = out.len() - 1;
        for (i, byte) in text.bytes().take(limit).enumerate() {
            out[i] = byte as gchar;
        }
        out[text.len().min(limit)] = 0;
    }
}
