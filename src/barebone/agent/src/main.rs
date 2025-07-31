#![no_main]
#![no_std]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{CStr, c_void};
use core::ptr;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};

use bindings::{
    g_error_free, g_free, g_main_context_default, g_main_context_iteration, g_memdup2, g_object_unref, g_variant_check_format_string, g_variant_get, g_variant_get_child_value, g_variant_get_data, g_variant_get_size, g_variant_get_string, g_variant_get_uint32, g_variant_get_uint64, g_variant_iter_init, g_variant_iter_next, g_variant_new, g_variant_new_from_data, g_variant_new_string, g_variant_new_tuple, g_variant_new_uint32, g_variant_type_free, g_variant_type_new, g_variant_unref, gchar, gpointer, gsize, gum_script_backend_create_sync, gum_script_backend_obtain_qjs, gum_script_load_sync, gum_script_post, gum_script_set_message_handler, gum_script_unload_sync, GBytes, GCancellable, GError, GVariant, GVariantIter, GumScript
};
use hostlink_virtio::Hostlink;
use symbols::SymbolTable;

mod glib;
mod gthread;
mod gum;
mod hostlink_virtio;

mod libc;
mod pac;
mod symbols;
mod xnu;

mod bindings {
    #![allow(
        dead_code,
        improper_ctypes,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        unused_imports
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[repr(u8)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum FridaCommand {
    CreateScript = 1,
    LoadScript = 2,
    DestroyScript = 3,
    PostScriptMessage = 4,

    Reply = 128,
    ScriptMessage = 129,
}

impl core::fmt::Display for FridaCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FridaCommand::CreateScript => write!(f, "CreateScript"),
            FridaCommand::LoadScript => write!(f, "LoadScript"),
            FridaCommand::DestroyScript => write!(f, "DestroyScript"),
            FridaCommand::PostScriptMessage => write!(f, "PostScriptMessage"),
            FridaCommand::Reply => write!(f, "Reply"),
            FridaCommand::ScriptMessage => write!(f, "ScriptMessage"),
        }
    }
}

#[derive(Debug)]
struct HandlerResponse {
    variant: *mut GVariant,
}

impl HandlerResponse {
    fn success(variant: *mut GVariant) -> Self {
        Self { variant }
    }

    fn success_empty() -> Self {
        let variant = unsafe { g_variant_new_tuple(ptr::null(), 0) };
        Self { variant }
    }

    fn error(message: &str) -> Self {
        let mut c_message = String::from(message);
        c_message.push('\0');
        let error_variant = unsafe { g_variant_new_string(c_message.as_ptr()) };

        Self {
            variant: error_variant,
        }
    }
}

static mut CONFIG_DATA: &'static [u8] = &[];
pub static mut MODULE_INFOS: Vec<ModuleInfo> = Vec::new();
pub static mut SYMBOL_TABLE: SymbolTable = SymbolTable::empty();

static mut TRANSPORT_DRIVER: *mut Hostlink = core::ptr::null_mut();

#[inline(always)]
fn transport_set(driver: Hostlink) {
    unsafe {
        let boxed = Box::into_raw(Box::new(driver));
        TRANSPORT_DRIVER = boxed;
    }
}

#[inline(always)]
fn transport_get_unchecked() -> &'static Hostlink {
    unsafe {
        debug_assert!(!TRANSPORT_DRIVER.is_null());
        &*TRANSPORT_DRIVER
    }
}

static mut SCRIPTS: BTreeMap<u32, *mut GumScript> = BTreeMap::new();
static NEXT_SCRIPT_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub version: String,
    pub offset: u32,
    pub size: u32,
    pub start_func_offset: u32,
    pub stop_func_offset: u32,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start(config_data: *const u8, config_size: usize) {
    unsafe {
        CONFIG_DATA = core::slice::from_raw_parts(config_data, config_size);

        xnu::kernel_thread_start(frida_agent_worker, 12345usize as *mut core::ffi::c_void);
    }
}

unsafe extern "C" fn frida_agent_worker(_parameter: *mut core::ffi::c_void, _wait_result: i32) {
    unsafe {
        bindings::g_set_panic_handler(Some(frida_panic_handler), ptr::null_mut());
        bindings::gum_init_embedded();
        bindings::g_log_set_default_handler(Some(frida_log_handler), ptr::null_mut());

        parse_config(core::ptr::addr_of!(CONFIG_DATA).read());

        transport_set(Hostlink::init(Some(on_frame_from_host), ptr::addr_of_mut!(glib::WAKEUP_TOKEN) as *const u8).unwrap());

        let main_context = g_main_context_default();

        loop {
            transport_get_unchecked().process();
            g_main_context_iteration(main_context, 1);
        }
    }
}

fn on_frame_from_host(frame: &[u8]) {
    if let Some(variant) = deserialize_message(&frame) {
        process_incoming_message(variant);
        unsafe { g_variant_unref(variant); }
    }
}

unsafe fn parse_config(config: &[u8]) {
    unsafe {
        let type_string = c"(ta(ssuuuu)ay)".as_ptr() as *const gchar;
        let variant_type = g_variant_type_new(type_string);

        let root_variant = g_variant_new_from_data(
            variant_type,
            config.as_ptr() as *const core::ffi::c_void,
            config.len() as gsize,
            1,
            None,
            ptr::null_mut(),
        );

        let kernel_base_variant = g_variant_get_child_value(root_variant, 0);
        let kernel_base = g_variant_get_uint64(kernel_base_variant);
        xnu::set_kernel_base(kernel_base);

        let module_info_variant = g_variant_get_child_value(root_variant, 1);
        let mut iter: GVariantIter = core::mem::zeroed();
        g_variant_iter_init(&mut iter as *mut GVariantIter, module_info_variant);

        let module_infos = core::ptr::addr_of_mut!(MODULE_INFOS);
        let raw_name: *mut gchar = null_mut();
        let raw_version: *mut gchar = null_mut();
        let offset: u32 = 0;
        let size: u32 = 0;
        let start_func_offset: u32 = 0;
        let stop_func_offset: u32 = 0;
        while g_variant_iter_next(
            &mut iter as *mut GVariantIter,
            c"(&s&suuuu)".as_ptr(),
            &raw_name,
            &raw_version,
            &offset,
            &size,
            &start_func_offset,
            &stop_func_offset,
        ) != 0
        {
            (*module_infos).push(ModuleInfo {
                name: String::from(CStr::from_ptr(raw_name).to_str().unwrap()),
                version: String::from(CStr::from_ptr(raw_version).to_str().unwrap()),
                offset,
                size,
                start_func_offset,
                stop_func_offset,
            });
        }

        let symbol_array_variant = g_variant_get_child_value(root_variant, 2);
        let symbol_data_ptr = g_variant_get_data(symbol_array_variant) as *const u8;
        let symbol_data_size = g_variant_get_size(symbol_array_variant) as usize;
        SYMBOL_TABLE = SymbolTable::new(core::slice::from_raw_parts(
            symbol_data_ptr,
            symbol_data_size,
        ));

        g_variant_unref(symbol_array_variant);
        g_variant_unref(module_info_variant);
        g_variant_unref(kernel_base_variant);
        g_variant_unref(root_variant);
        g_variant_type_free(variant_type);
    }
}

unsafe fn serialize_message(variant: *mut GVariant) -> Option<Vec<u8>> {
    unsafe {
        let size = g_variant_get_size(variant) as usize;
        if size == 0 {
            return None;
        }

        let data_ptr = g_variant_get_data(variant) as *const u8;
        let mut result = Vec::with_capacity(size);
        result.resize(size, 0);
        core::ptr::copy_nonoverlapping(data_ptr, result.as_mut_ptr(), size);

        Some(result)
    }
}

fn deserialize_message(data: &[u8]) -> Option<*mut GVariant> {
    unsafe {
        if data.is_empty() {
            return None;
        }

        let variant_type = g_variant_type_new(c"(yqv)".as_ptr());
        let data_copy = g_memdup2(data.as_ptr() as *const c_void, data.len() as u64);
        let variant = g_variant_new_from_data(
            variant_type,
            data_copy,
            data.len() as u64,
            0,
            Some(g_free),
            data_copy,
        );
        g_variant_type_free(variant_type);

        if variant.is_null() {
            None
        } else {
            Some(variant)
        }
    }
}

fn process_incoming_message(variant: *mut GVariant) {
    {
        let mut cmd_value: u8 = 0;
        let mut request_id: u16 = 0;
        let mut payload_variant: *mut GVariant = ptr::null_mut();

        let cmd = unsafe {
            g_variant_get(
                variant,
                c"(yqv)".as_ptr(),
                &mut cmd_value,
                &mut request_id,
                &mut payload_variant,
            );

            core::mem::transmute::<u8, FridaCommand>(cmd_value)
        };

        let response = match cmd {
            FridaCommand::CreateScript => handle_create_script(payload_variant),
            FridaCommand::LoadScript => handle_load_script(payload_variant),
            FridaCommand::DestroyScript => handle_destroy_script(payload_variant),
            FridaCommand::PostScriptMessage => handle_post_script_message(payload_variant),
            _ => HandlerResponse::error("Unknown command"),
        };

        send_command_reply(request_id, response);

        unsafe { g_variant_unref(payload_variant) };
    }
}

fn send_command_reply(request_id: u16, response: HandlerResponse) {
    unsafe {
        let message = g_variant_new(
            c"(yqv)".as_ptr(),
            FridaCommand::Reply as u8 as u32,
            request_id as u32,
            response.variant,
        );

        if let Some(serialized) = serialize_message(message) {
            transport_get_unchecked().send(&serialized);
        }

        g_variant_unref(message);
    }
}

fn handle_create_script(payload_variant: *mut GVariant) -> HandlerResponse {
    unsafe {
        if g_variant_check_format_string(payload_variant, c"s".as_ptr(), 0) == 0 {
            return HandlerResponse::error("Invalid payload format: expected string");
        }
        let source = g_variant_get_string(payload_variant, core::ptr::null_mut());

        let backend = gum_script_backend_obtain_qjs();
        let cancellable: *mut GCancellable = ptr::null_mut();
        let mut error: *mut GError = ptr::null_mut();

        let script = gum_script_backend_create_sync(
            backend,
            c"agent.js".as_ptr(),
            source,
            ptr::null_mut(),
            cancellable,
            &mut error,
        );

        if !error.is_null() {
            let error_msg = CStr::from_ptr((*error).message).to_str().unwrap();
            let error_string = String::from(error_msg);
            g_error_free(error);
            return HandlerResponse::error(&error_string);
        }

        let script_id = NEXT_SCRIPT_ID.fetch_add(1, Ordering::Relaxed);

        let script_id_ptr = Box::into_raw(Box::new(script_id));
        gum_script_set_message_handler(
            script,
            Some(frida_message_handler),
            script_id_ptr as *mut c_void,
            None,
        );

        core::ptr::addr_of_mut!(SCRIPTS)
            .as_mut()
            .unwrap()
            .insert(script_id, script);

        HandlerResponse::success(g_variant_new_uint32(script_id))
    }
}

unsafe extern "C" fn frida_message_handler(
    message: *const gchar,
    _data: *mut GBytes,
    user_data: gpointer,
) {
    unsafe {
        let script_id = *(user_data as *const u32);

        let message_variant = g_variant_new(
            c"(yqv)".as_ptr(),
            FridaCommand::ScriptMessage as u8 as u32,
            0u32,
            g_variant_new(c"(us)".as_ptr(), script_id, message),
        );

        if let Some(serialized) = serialize_message(message_variant) {
            transport_get_unchecked().send(&serialized);
        }

        g_variant_unref(message_variant);
    }
}

fn handle_load_script(payload_variant: *mut GVariant) -> HandlerResponse {
    unsafe {
        if g_variant_check_format_string(payload_variant, c"u".as_ptr(), 0) == 0 {
            return HandlerResponse::error("Invalid payload format: expected uint32");
        }
        let script_id = g_variant_get_uint32(payload_variant);

        let Some(script) = get_script_by_id(script_id) else {
            return HandlerResponse::error(&format!("Script with ID {} not found", script_id));
        };

        gum_script_load_sync(script, ptr::null_mut());

        HandlerResponse::success_empty()
    }
}

fn handle_destroy_script(payload_variant: *mut GVariant) -> HandlerResponse {
    unsafe {
        if g_variant_check_format_string(payload_variant, c"u".as_ptr(), 0) == 0 {
            return HandlerResponse::error("Invalid payload format: expected uint32");
        }
        let script_id = g_variant_get_uint32(payload_variant);

        let scripts = core::ptr::addr_of_mut!(SCRIPTS).as_mut().unwrap();
        let Some(script) = scripts.remove(&script_id) else {
            return HandlerResponse::error(&format!("Script with ID {} not found", script_id));
        };

        gum_script_unload_sync(script, ptr::null_mut());
        g_object_unref(script as *mut c_void);

        HandlerResponse::success_empty()
    }
}

fn handle_post_script_message(payload_variant: *mut GVariant) -> HandlerResponse {
    unsafe {
        if g_variant_check_format_string(payload_variant, c"(us)".as_ptr(), 0) == 0 {
            return HandlerResponse::error("Invalid payload format: expected (uint32, string)");
        }
        let mut script_id: u32 = 0;
        let mut message: *const gchar = ptr::null();
        g_variant_get(
            payload_variant,
            c"(u&s)".as_ptr(),
            &mut script_id,
            &mut message,
        );

        let Some(script) = get_script_by_id(script_id) else {
            return HandlerResponse::error(&format!("Script with ID {} not found", script_id));
        };

        gum_script_post(script, message, ptr::null_mut());

        HandlerResponse::success_empty()
    }
}

unsafe fn get_script_by_id(script_id: u32) -> Option<*mut GumScript> {
    unsafe {
        let scripts = core::ptr::addr_of_mut!(SCRIPTS).as_mut().unwrap();
        scripts.get(&script_id).copied()
    }
}

unsafe extern "C" fn frida_panic_handler(message: *const u8, _user_data: *mut core::ffi::c_void) {
    let msg = unsafe { core::ffi::CStr::from_ptr(message).to_str().unwrap() };
    panic!("[Frida] {}", msg);
}

unsafe extern "C" fn frida_log_handler(
    _log_domain: *const core::ffi::c_char,
    _log_level: i32,
    message: *const core::ffi::c_char,
    _user_data: *mut core::ffi::c_void,
) {
    let msg = unsafe { core::ffi::CStr::from_ptr(message).to_str().unwrap() };
    kprintln!("[Frida] {}", msg);
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut s = format!("{}", info);
    s.push('\0');
    xnu::panic(s.as_str());
    loop {}
}

pub struct XnuAllocator;

unsafe impl GlobalAlloc for XnuAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        xnu::kalloc(layout.size())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        xnu::free(ptr, layout.size());
    }
}

#[global_allocator]
static GLOBAL: XnuAllocator = XnuAllocator;
extern crate alloc;

#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut buf = alloc::string::String::new();
        write!(&mut buf, $($arg)*).unwrap();
        buf.push('\n');
        buf.push('\0');
        crate::xnu::io_log(&buf)
    }};
}
