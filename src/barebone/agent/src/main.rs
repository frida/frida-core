#![no_main]
#![no_std]

use alloc::format;
use alloc::collections::BTreeMap;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::CStr;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use core::{arch::asm, ptr};

use crate::bindings::{g_main_loop_run, gboolean, gchar, gpointer, gum_script_set_message_handler, gum_script_load_sync, GBytes, GCancellable};

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

#[repr(C)]
pub struct SharedBuffer {
    pub magic: AtomicU32,
    pub status: AtomicU8,
    pub command: AtomicU8,
    pub data_size: AtomicU32,
    pub result_code: AtomicU32,
    pub result_size: AtomicU32,
    pub data: [u8; 4096],
}

#[unsafe(no_mangle)]
pub static mut FRIDA_SHARED_BUFFER: SharedBuffer = SharedBuffer {
    magic: AtomicU32::new(0x44495246),
    status: AtomicU8::new(0),
    command: AtomicU8::new(0),
    data_size: AtomicU32::new(0),
    result_code: AtomicU32::new(0),
    result_size: AtomicU32::new(0),
    data: [0u8; 4096],
};

// Script storage
static mut SCRIPTS: BTreeMap<u32, *mut bindings::GumScript> = BTreeMap::new();
static NEXT_SCRIPT_ID: AtomicU32 = AtomicU32::new(1);

pub const CMD_IDLE: u8 = 0;
pub const CMD_CREATE_SCRIPT: u8 = 1;
pub const CMD_EXEC_JS: u8 = 2;
pub const CMD_SHUTDOWN: u8 = 3;

pub const STATUS_IDLE: u8 = 0;
pub const STATUS_BUSY: u8 = 1;
pub const STATUS_DATA_READY: u8 = 2;
pub const STATUS_ERROR: u8 = 3;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> usize {
    unsafe {
        let buffer = core::ptr::addr_of_mut!(FRIDA_SHARED_BUFFER);
        (*buffer).magic.store(0x44495246, Ordering::Release);
        (*buffer).status.store(STATUS_IDLE, Ordering::Release);
        (*buffer).command.store(CMD_IDLE, Ordering::Release);
        (*buffer).data_size.store(0, Ordering::Release);
        (*buffer).result_code.store(0, Ordering::Release);
        (*buffer).result_size.store(0, Ordering::Release);

        xnu::kernel_thread_start(frida_agent_worker, 12345usize as *mut core::ffi::c_void);

        virt_to_phys(buffer as usize)
    }
}

unsafe extern "C" fn frida_agent_worker(_parameter: *mut core::ffi::c_void, _wait_result: i32) {
    unsafe {
        bindings::g_set_panic_handler(Some(frida_panic_handler), ptr::null_mut());
        bindings::gum_init_embedded();
        bindings::g_log_set_default_handler(Some(frida_log_handler), ptr::null_mut());

        bindings::g_timeout_add(1000, Some(process_shared_buffer), ptr::null_mut());

        let main_loop = bindings::g_main_loop_new(ptr::null_mut(), 0);
        g_main_loop_run(main_loop);
    }
}

unsafe extern "C" fn process_shared_buffer(_user_data: gpointer) -> gboolean {
    unsafe {
        let buffer = core::ptr::addr_of_mut!(FRIDA_SHARED_BUFFER);

        let cmd = (*buffer).command.load(Ordering::Acquire);
        if cmd != CMD_IDLE {
            kprintln!("[Frida] Processing command: {}", cmd);

            (*buffer).status.store(STATUS_BUSY, Ordering::Release);

            match cmd {
                CMD_CREATE_SCRIPT => {
                    handle_create_script_request(buffer);
                    (*buffer).status.store(STATUS_DATA_READY, Ordering::Release);
                }
                CMD_EXEC_JS => {
                    write_string_result_to_buffer(buffer, "TODO");
                    (*buffer).status.store(STATUS_DATA_READY, Ordering::Release);
                }
                CMD_SHUTDOWN => {
                    write_string_result_to_buffer(buffer, "Worker shutting down");
                    (*buffer).status.store(STATUS_DATA_READY, Ordering::Release);
                }
                _ => {
                    write_error_to_buffer(buffer, 1, "Unknown command");
                    (*buffer).status.store(STATUS_ERROR, Ordering::Release);
                }
            }

            kprintln!("[Frida] Processed command: {}", cmd);

            (*buffer).command.store(CMD_IDLE, Ordering::Release);
        } else {
            kprintln!("[Frida] Nothing to do!");
        }
    }

    1
}

unsafe fn handle_create_script_request(buffer: *mut SharedBuffer) {
    unsafe {
        let data_size = (*buffer).data_size.load(Ordering::Acquire) as usize;
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
        gum_script_set_message_handler(script, Some(frida_message_handler), ptr::null_mut(), None);
        gum_script_load_sync(script, cancellable);
        /*
        gum_script_post(
            script,
            b"{\"type\":\"hello\",\"text\":\"How do you do?\"}\0".as_ptr() as *const u8,
            ptr::null_mut(),
        );
        */

        let script_id = NEXT_SCRIPT_ID.fetch_add(1, Ordering::Relaxed);
        core::ptr::addr_of_mut!(SCRIPTS).as_mut().unwrap().insert(script_id, script);

        write_uint32_result_to_buffer(buffer, script_id);
    }
}

unsafe fn write_string_result_to_buffer(buffer: *mut SharedBuffer, text: &str) {
    unsafe {
        let text_bytes = text.as_bytes();
        let copy_size = core::cmp::min(text_bytes.len(), 4096);
        core::ptr::copy_nonoverlapping(text_bytes.as_ptr(), (*buffer).data.as_mut_ptr(), copy_size);

        (*buffer).result_code.store(0, Ordering::Release);
        (*buffer)
            .result_size
            .store(copy_size as u32, Ordering::Release);
    }
}

unsafe fn write_uint32_result_to_buffer(buffer: *mut SharedBuffer, value: u32) {
    unsafe {
        let value_bytes = value.to_le_bytes();
        core::ptr::copy_nonoverlapping(value_bytes.as_ptr(), (*buffer).data.as_mut_ptr(), 4);

        (*buffer).result_code.store(0, Ordering::Release);
        (*buffer).result_size.store(4, Ordering::Release);
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

        (*buffer).result_code.store(error_code, Ordering::Release);
        (*buffer)
            .result_size
            .store(copy_size as u32, Ordering::Release);
    }
}

unsafe fn virt_to_phys(virt_addr: usize) -> usize {
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
        // Extract physical address from PAR_EL1 [47:12] and combine with offset [11:0]
        let pa_bits = (phys_addr >> 12) & 0xFFFFFFFFF; // Extract PA[47:12]
        let offset = virt_addr & 0xFFF; // Extract offset [11:0]
        (pa_bits << 12) | offset
    } else {
        virt_addr
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

unsafe extern "C" fn frida_message_handler(message: *const gchar, _data: *mut GBytes, _user_data: gpointer) {
    kprintln!("[Frida] Message from script: {}", unsafe { core::ffi::CStr::from_ptr(message).to_str().unwrap() });
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
