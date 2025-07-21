#![no_main]
#![no_std]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{CStr, c_void};
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use core::ptr;

use crate::bindings::g_variant_get_uint64;
use crate::bindings::{
    GBytes, GCancellable, g_main_loop_run, g_object_unref, gboolean, gchar, gpointer,
    gum_script_load_sync, gum_script_post, gum_script_set_message_handler, gum_script_unload_sync,
};

mod glib;
mod gthread;
mod gum;
mod libc;
mod pac;
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

#[derive(Debug, Clone)]
pub struct DarwinSymbolDetails {
    pub name: String,
    pub address: u64,
    pub symbol_type: u8,
    pub section: u8,
    pub description: u16,
}

static mut CONFIG_DATA: *const u8 = core::ptr::null();
static mut CONFIG_SIZE: usize = 0;
static mut SYMBOL_DATA: *const u8 = core::ptr::null();
static mut SYMBOL_DATA_SIZE: usize = 0;

#[repr(C)]
pub struct SharedBuffer {
    pub magic: u32,
    pub command: AtomicU8,
    pub status: AtomicU8,
    pub data_size: u32,
    pub result_code: u32,
    pub result_size: u32,
    pub data: [u8; 4096],
}

#[unsafe(no_mangle)]
pub static mut FRIDA_SHARED_BUFFER: SharedBuffer = SharedBuffer {
    magic: 0x44495246,
    command: AtomicU8::new(FridaCommand::Idle as u8),
    status: AtomicU8::new(FridaStatus::Idle as u8),
    data_size: 0,
    result_code: 0,
    result_size: 0,
    data: [0u8; 4096],
};

static mut SCRIPTS: BTreeMap<u32, *mut bindings::GumScript> = BTreeMap::new();
static mut MESSAGE_QUEUE: VecDeque<(u32, String)> = VecDeque::new();
static NEXT_SCRIPT_ID: AtomicU32 = AtomicU32::new(1);

#[repr(u8)]
#[derive(PartialEq, Eq)]
pub enum FridaCommand {
    Idle = 0,
    CreateScript = 1,
    LoadScript = 2,
    DestroyScript = 3,
    PostScriptMessage = 4,
    FetchScriptMessage = 5,
}

impl core::fmt::Display for FridaCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FridaCommand::Idle => write!(f, "Idle"),
            FridaCommand::CreateScript => write!(f, "CreateScript"),
            FridaCommand::LoadScript => write!(f, "LoadScript"),
            FridaCommand::DestroyScript => write!(f, "DestroyScript"),
            FridaCommand::PostScriptMessage => write!(f, "PostScriptMessage"),
            FridaCommand::FetchScriptMessage => write!(f, "FetchScriptMessage"),
        }
    }
}

#[repr(u8)]
pub enum FridaStatus {
    Idle = 0,
    Busy = 1,
    DataReady = 2,
    Error = 3,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start(config_data: *const u8, config_size: usize) -> usize {
    unsafe {
        CONFIG_DATA = config_data;
        CONFIG_SIZE = config_size;

        let buffer = core::ptr::addr_of_mut!(FRIDA_SHARED_BUFFER);
        (*buffer).magic = 0x44495246;
        (*buffer)
            .command
            .store(FridaCommand::Idle as u8, Ordering::Release);
        (*buffer)
            .status
            .store(FridaStatus::Idle as u8, Ordering::Release);
        (*buffer).data_size = 0;
        (*buffer).result_code = 0;
        (*buffer).result_size = 0;

        xnu::kernel_thread_start(frida_agent_worker, 12345usize as *mut core::ffi::c_void);

        gum::gum_barebone_virtual_to_physical(buffer as gpointer) as usize
    }
}

unsafe extern "C" fn frida_agent_worker(_parameter: *mut core::ffi::c_void, _wait_result: i32) {
    unsafe {
        kprintln!("Frida agent worker initializing");

        bindings::g_set_panic_handler(Some(frida_panic_handler), ptr::null_mut());
        bindings::gum_init_embedded();
        bindings::g_log_set_default_handler(Some(frida_log_handler), ptr::null_mut());

        kprintln!("Frida agent worker parsing config");

        if *core::ptr::addr_of!(CONFIG_SIZE) > 0 {
            parse_symbol_config(*core::ptr::addr_of!(CONFIG_DATA), *core::ptr::addr_of!(CONFIG_SIZE));
        }

        let symbol_count = get_symbol_count();
        kprintln!("Frida agent starting with symbols count: {}", symbol_count);

        bindings::g_timeout_add(10, Some(process_shared_buffer), ptr::null_mut());

        let main_loop = bindings::g_main_loop_new(ptr::null_mut(), 0);
        g_main_loop_run(main_loop);
    }
}

unsafe fn parse_symbol_config(config_data: *const u8, config_size: usize) {
    use crate::bindings::{
        g_variant_new_from_data, g_variant_get_child_value, g_variant_unref,
        g_variant_get_data, g_variant_get_size, gsize, g_variant_type_new,
    };

    unsafe {
        let type_string = b"(tay)\0".as_ptr() as *const gchar;
        let variant_type = g_variant_type_new(type_string);

        let root_variant = g_variant_new_from_data(
            variant_type,
            config_data as *const core::ffi::c_void,
            config_size as gsize,
            1,
            None,
            ptr::null_mut(),
        );

        let kernel_base_variant = g_variant_get_child_value(root_variant, 0);

        let kernel_base = g_variant_get_uint64(kernel_base_variant);
        xnu::set_kernel_base(kernel_base);
        kprintln!("Set kernel base to 0x{:x}", kernel_base);

        let symbol_array_variant = g_variant_get_child_value(root_variant, 1);

        SYMBOL_DATA = g_variant_get_data(symbol_array_variant) as *const u8;
        SYMBOL_DATA_SIZE = g_variant_get_size(symbol_array_variant) as usize;

        let symbol_data_size = core::ptr::addr_of!(SYMBOL_DATA_SIZE);
        kprintln!("Loaded symbol data with {} bytes", *symbol_data_size);

        let symbol_count = get_symbol_count();
        kprintln!("Loaded {} symbols in raw format", symbol_count);

        g_variant_unref(symbol_array_variant);
        g_variant_unref(kernel_base_variant);
        g_variant_unref(root_variant);
    }
}

unsafe extern "C" fn process_shared_buffer(_user_data: gpointer) -> gboolean {
    unsafe {
        let buffer = core::ptr::addr_of_mut!(FRIDA_SHARED_BUFFER);

        let cmd =
            core::mem::transmute::<u8, FridaCommand>((*buffer).command.load(Ordering::Acquire));
        if cmd != FridaCommand::Idle {
            (*buffer)
                .status
                .store(FridaStatus::Busy as u8, Ordering::Release);

            let new_status = match cmd {
                FridaCommand::CreateScript => {
                    handle_create_script_request(buffer);
                    FridaStatus::DataReady
                }
                FridaCommand::LoadScript => {
                    handle_load_script_request(buffer);
                    FridaStatus::DataReady
                }
                FridaCommand::DestroyScript => {
                    handle_destroy_script_request(buffer);
                    FridaStatus::DataReady
                }
                FridaCommand::PostScriptMessage => {
                    handle_post_script_message_request(buffer);
                    FridaStatus::DataReady
                }
                FridaCommand::FetchScriptMessage => {
                    handle_fetch_script_message_request(buffer);
                    FridaStatus::DataReady
                }
                _ => {
                    write_error_to_buffer(buffer, 1, "Unknown command");
                    FridaStatus::Error
                }
            };
            (*buffer).status.store(new_status as u8, Ordering::Release);

            (*buffer)
                .command
                .store(FridaCommand::Idle as u8, Ordering::Release);
        }
    }

    1
}

unsafe fn handle_create_script_request(buffer: *mut SharedBuffer) {
    unsafe {
        let data_size = (*buffer).data_size as usize;
        if data_size == 0 || data_size > 4096 {
            panic!("Protocol error");
        }

        let backend = bindings::gum_script_backend_obtain_qjs();
        let cancellable: *mut GCancellable = ptr::null_mut();
        let mut error: *mut bindings::GError = ptr::null_mut();

        let c_name = core::ffi::CStr::from_bytes_with_nul_unchecked("agent.js\0".as_bytes());

        let data_ptr = (*buffer).data.as_ptr();
        let data_slice = core::slice::from_raw_parts(data_ptr, data_size);
        let source = CStr::from_bytes_with_nul(data_slice).unwrap();

        let script = bindings::gum_script_backend_create_sync(
            backend,
            c_name.as_ptr(),
            source.as_ptr(),
            ptr::null_mut(),
            cancellable,
            &mut error,
        );
        if error != ptr::null_mut() {
            let error_msg = core::ffi::CStr::from_ptr((*error).message)
                .to_str()
                .unwrap();
            write_error_to_buffer(buffer, 1, error_msg);
            bindings::g_error_free(error);
            return;
        }
        let script_id = NEXT_SCRIPT_ID.fetch_add(1, Ordering::Relaxed);

        let script_id_ptr = Box::into_raw(Box::new(script_id));
        gum_script_set_message_handler(
            script,
            Some(frida_message_handler),
            script_id_ptr as *mut c_void,
            None,
        );
        gum_script_load_sync(script, cancellable);

        core::ptr::addr_of_mut!(SCRIPTS)
            .as_mut()
            .unwrap()
            .insert(script_id, script);

        write_uint32_result_to_buffer(buffer, script_id);
    }
}

unsafe fn handle_load_script_request(buffer: *mut SharedBuffer) {
    unsafe {
        let script_id = match parse_script_id_from_buffer(buffer) {
            Ok(id) => id,
            Err(msg) => {
                write_error_to_buffer(buffer, 1, msg);
                return;
            }
        };

        if let Some(script) = get_script_by_id(script_id) {
            bindings::gum_script_load_sync(script, ptr::null_mut());

            write_string_result_to_buffer(buffer, "Script loaded successfully");
        } else {
            write_error_to_buffer(buffer, 3, "Script not found");
        }
    }
}

unsafe fn handle_destroy_script_request(buffer: *mut SharedBuffer) {
    unsafe {
        let script_id = match parse_script_id_from_buffer(buffer) {
            Ok(id) => id,
            Err(msg) => {
                write_error_to_buffer(buffer, 1, msg);
                return;
            }
        };

        let scripts = core::ptr::addr_of_mut!(SCRIPTS).as_mut().unwrap();
        if let Some(script) = scripts.remove(&script_id) {
            gum_script_unload_sync(script, ptr::null_mut());
            g_object_unref(script as *mut c_void);

            write_string_result_to_buffer(buffer, "Script destroyed successfully");
        } else {
            write_error_to_buffer(buffer, 3, "Script not found");
        }
    }
}

unsafe fn handle_post_script_message_request(buffer: *mut SharedBuffer) {
    unsafe {
        let script_id = match parse_script_id_from_buffer(buffer) {
            Ok(id) => id,
            Err(msg) => {
                write_error_to_buffer(buffer, 1, msg);
                return;
            }
        };

        let _message_size = (*buffer).data_size as usize - 4;
        let message_ptr = (*buffer).data.as_ptr().add(4);

        if let Some(script) = get_script_by_id(script_id) {
            gum_script_post(script, message_ptr, ptr::null_mut());
            write_string_result_to_buffer(buffer, "Message posted successfully");
        } else {
            write_error_to_buffer(buffer, 3, "Script not found");
        }
    }
}

unsafe fn handle_fetch_script_message_request(buffer: *mut SharedBuffer) {
    unsafe {
        let message_queue = core::ptr::addr_of_mut!(MESSAGE_QUEUE).as_mut().unwrap();

        if let Some((script_id, message)) = message_queue.pop_front() {
            let script_id_bytes = script_id.to_le_bytes();
            core::ptr::copy_nonoverlapping(
                script_id_bytes.as_ptr(),
                (*buffer).data.as_mut_ptr(),
                4,
            );

            let message_bytes = message.as_bytes();
            let message_copy_size = core::cmp::min(message_bytes.len(), 4096 - 4 - 1);
            core::ptr::copy_nonoverlapping(
                message_bytes.as_ptr(),
                (*buffer).data.as_mut_ptr().add(4),
                message_copy_size,
            );
            *(*buffer).data.as_mut_ptr().add(4 + message_copy_size) = 0;

            (*buffer).result_code = 0;
            (*buffer).result_size = 4 + message_copy_size as u32 + 1;
        } else {
            (*buffer).result_code = 0;
            (*buffer).result_size = 0;
        }
    }
}

unsafe fn parse_script_id_from_buffer(buffer: *mut SharedBuffer) -> Result<u32, &'static str> {
    unsafe {
        if (*buffer).data_size < 4 {
            return Err("Expected at least 4 bytes for script ID");
        }

        let script_id = u32::from_le_bytes([
            (*buffer).data[0],
            (*buffer).data[1],
            (*buffer).data[2],
            (*buffer).data[3],
        ]);

        Ok(script_id)
    }
}

unsafe fn get_script_by_id(script_id: u32) -> Option<*mut bindings::GumScript> {
    unsafe {
        let scripts = core::ptr::addr_of_mut!(SCRIPTS).as_mut().unwrap();
        scripts.get(&script_id).copied()
    }
}

unsafe fn write_string_result_to_buffer(buffer: *mut SharedBuffer, text: &str) {
    unsafe {
        let text_bytes = text.as_bytes();
        let copy_size = core::cmp::min(text_bytes.len(), 4096);
        core::ptr::copy_nonoverlapping(text_bytes.as_ptr(), (*buffer).data.as_mut_ptr(), copy_size);

        (*buffer).result_code = 0;
        (*buffer).result_size = copy_size as u32;
    }
}

unsafe fn write_uint32_result_to_buffer(buffer: *mut SharedBuffer, value: u32) {
    unsafe {
        let value_bytes = value.to_le_bytes();
        core::ptr::copy_nonoverlapping(value_bytes.as_ptr(), (*buffer).data.as_mut_ptr(), 4);

        (*buffer).result_code = 0;
        (*buffer).result_size = 4;
    }
}

unsafe fn write_error_to_buffer(buffer: *mut SharedBuffer, error_code: u32, error_msg: &str) {
    unsafe {
        let error_bytes = error_msg.as_bytes();
        let copy_size = core::cmp::min(error_bytes.len(), 4096);
        core::ptr::copy_nonoverlapping(
            error_bytes.as_ptr(),
            (*buffer).data.as_mut_ptr(),
            copy_size,
        );

        (*buffer).result_code = error_code;
        (*buffer).result_size = copy_size as u32;
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

unsafe extern "C" fn frida_message_handler(
    message: *const gchar,
    _data: *mut GBytes,
    user_data: gpointer,
) {
    let msg = unsafe { core::ffi::CStr::from_ptr(message).to_str().unwrap() };

    if !user_data.is_null() {
        let script_id = unsafe { *(user_data as *const u32) };

        let message_queue = unsafe { core::ptr::addr_of_mut!(MESSAGE_QUEUE).as_mut().unwrap() };
        message_queue.push_back((script_id, String::from(msg)));
    }
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

fn get_symbol_count() -> u32 {
    unsafe {
        let data = core::slice::from_raw_parts(SYMBOL_DATA, SYMBOL_DATA_SIZE);
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    }
}

fn parse_symbol_at_offset(data: &[u8], offset: usize) -> (String, u32, u8, u8, u16) {
    let name_len = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;

    let name = unsafe {
        core::str::from_utf8_unchecked(&data[offset+2..offset+2+name_len]).to_string()
    };

    let meta_start = offset + 2 + name_len;
    let symbol_offset = u32::from_le_bytes([
        data[meta_start], data[meta_start+1], data[meta_start+2], data[meta_start+3]
    ]);
    let symbol_type = data[meta_start + 4];
    let section = data[meta_start + 5];
    let description = u16::from_le_bytes([data[meta_start+6], data[meta_start+7]]);

    (name, symbol_offset, symbol_type, section, description)
}

fn search_symbol_by_name(name: &str) -> Option<DarwinSymbolDetails> {
    unsafe {
        let data = core::slice::from_raw_parts(SYMBOL_DATA, SYMBOL_DATA_SIZE);
        let symbol_count = get_symbol_count() as usize;
        let kernel_base = crate::xnu::get_kernel_base();

        let mut left = 0;
        let mut right = symbol_count;

        while left < right {
            let mid = left + (right - left) / 2;

            let index_offset = 4 + mid * 4;
            let symbol_offset = u32::from_le_bytes([
                data[index_offset], data[index_offset+1],
                data[index_offset+2], data[index_offset+3]
            ]) as usize;

            let (symbol_name, symbol_addr_offset, symbol_type, section, description) =
                parse_symbol_at_offset(data, symbol_offset);

            match symbol_name.as_str().cmp(name) {
                core::cmp::Ordering::Equal => {
                    return Some(DarwinSymbolDetails {
                        name: symbol_name,
                        address: kernel_base + symbol_addr_offset as u64,
                        symbol_type,
                        section,
                        description,
                    });
                }
                core::cmp::Ordering::Less => {
                    left = mid + 1;
                }
                core::cmp::Ordering::Greater => {
                    right = mid;
                }
            }
        }

        None
    }
}

fn search_symbols_by_name(name: &str) -> Vec<DarwinSymbolDetails> {
    if let Some(symbol) = search_symbol_by_name(name) {
        alloc::vec![symbol]
    } else {
        Vec::new()
    }
}

pub unsafe fn find_symbol_by_address(address: u64) -> Option<DarwinSymbolDetails> {
    unsafe {
        let data = core::slice::from_raw_parts(SYMBOL_DATA, SYMBOL_DATA_SIZE);
        let symbol_count = get_symbol_count() as usize;
        let kernel_base = crate::xnu::get_kernel_base();
        let target_offset = (address - kernel_base) as u32;

        for i in 0..symbol_count {
            let index_offset = 4 + i * 4;
            let symbol_offset = u32::from_le_bytes([
                data[index_offset], data[index_offset+1],
                data[index_offset+2], data[index_offset+3]
            ]) as usize;

            let (symbol_name, symbol_addr_offset, symbol_type, section, description) =
                parse_symbol_at_offset(data, symbol_offset);

            if symbol_addr_offset == target_offset {
                return Some(DarwinSymbolDetails {
                    name: symbol_name,
                    address: address,
                    symbol_type,
                    section,
                    description,
                });
            }
        }

        None
    }
}
