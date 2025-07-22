use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use core::ffi::CStr;
use core::ptr;
use crate::{
    bindings::{
        gboolean, gpointer, gsize, guint, GPrivate, GumPageProtection, GumThreadId, GumTlsKey,
        GumDebugSymbolDetails, GArray, g_array_new, g_array_append_vals, gchar, gconstpointer,
        g_strdup, GObject, GObjectClass, GType, GumModule,
        GumModuleInterface, GumMemoryRange, GumModuleRegistry, gum_barebone_register_module,
        g_object_new, g_free, _GTypeInfo, _GInterfaceInfo,
        g_once_init_enter, g_once_init_leave,
        g_type_register_static, g_object_get_type, g_type_add_interface_static,
        gum_module_get_type, g_type_class_peek_parent
    },
    gthread, libc
};
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
pub extern "C" fn gum_barebone_on_registry_activating(registry: *mut GumModuleRegistry) {
    register_kernel_extensions(registry);
}

fn register_kernel_extensions(registry: *mut GumModuleRegistry) {
    let table = unsafe { core::ptr::addr_of!(crate::SYMBOL_TABLE).read() };

    if table.is_empty() {
        return;
    }

    let kernel_base = crate::xnu::get_kernel_base();
    let kernel_range = GumMemoryRange {
        base_address: kernel_base,
        size: 0x1000000,
    };
    let kernel_module = gum_native_module_new(
        "/System/Library/Kernels/kernel",
        &kernel_range,
    );

    unsafe {
        gum_barebone_register_module(registry, kernel_module);
    }

    register_modules_from_symbols(registry, &table);
}

fn register_modules_from_symbols(registry: *mut GumModuleRegistry, table: &crate::symbols::SymbolTable) {
    let mut seen_kexts = alloc::collections::BTreeSet::new();

    let kext_patterns = [
        "_com_apple_*",
        "*IOKit*",
    ];

    for pattern in &kext_patterns {
        let symbols = table.find_symbols_matching_glob(pattern);
        for symbol in symbols {
            if let Some(kext_name) = extract_kext_name(&symbol.name) {
                if !seen_kexts.contains(kext_name) {
                    seen_kexts.insert(String::from(kext_name));

                    let module_path = alloc::format!("/System/Library/Extensions/{}.kext", kext_name);
                    let kext_range = GumMemoryRange {
                        base_address: symbol.address,
                        size: 0x100000,
                    };

                    let kext_module = gum_native_module_new(
                        &module_path,
                        &kext_range,
                    );

                    unsafe {
                        gum_barebone_register_module(registry, kext_module);
                    }
                }
            }
        }
    }
}

fn extract_kext_name(symbol_name: &str) -> Option<&str> {
    if symbol_name.starts_with("_com_apple_") {
        if let Some(end) = symbol_name[11..].find('_') {
            return Some(&symbol_name[1..11 + end]);
        }
    }

    if symbol_name.contains("IOKit") || symbol_name.contains("Driver") {
        return Some("IOKit");
    }

    None
}

#[repr(C)]
pub struct GumNativeModule {
    parent: GObject,
    name: *mut gchar,
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
        if g_once_init_enter(core::ptr::addr_of_mut!(GUM_NATIVE_MODULE_TYPE) as *mut ::core::ffi::c_void) != 0 {
            let type_name = b"GumNativeModule\0".as_ptr() as *const gchar;

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

            let new_type = g_type_register_static(
                g_object_get_type(),
                type_name,
                &type_info,
                0,
            );

            let interface_info = _GInterfaceInfo {
                interface_init: Some(gum_native_module_iface_init),
                interface_finalize: None,
                interface_data: core::ptr::null_mut(),
            };

            g_type_add_interface_static(
                new_type,
                gum_module_get_type(),
                &interface_info,
            );

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
        (*iface).get_path = Some(gum_native_module_get_path);
        (*iface).get_range = Some(gum_native_module_get_range);
    }
}

unsafe extern "C" fn gum_native_module_finalize(object: *mut GObject) {
    unsafe {
        let module = object as *mut GumNativeModule;

        g_free((*module).path as gpointer);

        (*GUM_NATIVE_MODULE_PARENT_CLASS).finalize.unwrap()(object);
    }
}

fn gum_native_module_new(path: &str, range: &GumMemoryRange) -> *mut GumModule {
    unsafe {
        let path_cstr = CString::new(path).unwrap();

        let module = g_object_new(gum_native_module_get_type(), ptr::null()) as *mut GumNativeModule;

        (*module).path = g_strdup(path_cstr.as_ptr());

        let path_str = (*module).path;
        if let Some(sep_pos) = path.rfind('/').or_else(|| path.rfind('\\')) {
            (*module).name = path_str.add(sep_pos + 1);
        } else {
            (*module).name = path_str;
        }

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

#[unsafe(no_mangle)]
pub extern "C" fn gum_symbol_details_from_address(
    address: gpointer,
    details: *mut GumDebugSymbolDetails,
) -> gboolean {
    unsafe {
        let table = core::ptr::addr_of!(crate::SYMBOL_TABLE).read();
        if let Some(symbol) = table.find_symbol_by_address(address as u64) {
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
            return symbol.address as gpointer;
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
            let addr = symbol.address as gpointer;
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
            let addr = symbol.address as gpointer;
            g_array_append_vals(array, &addr as *const gpointer as gconstpointer, 1);
        }

        array
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_load_symbols(_path: *const gchar) -> gboolean {
    0
}
