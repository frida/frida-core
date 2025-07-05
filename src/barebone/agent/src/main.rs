#![no_main]
#![no_std]

mod bindings {
    #![allow(dead_code,improper_ctypes,non_camel_case_types,non_snake_case,non_upper_case_globals,unused_imports)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

mod syscalls;

use core::{arch::asm, mem::transmute, ptr};
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use crate::bindings::GCancellable;

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
    magic: AtomicU32::new(0x46524944), // "FRID" in hex
    status: AtomicU8::new(0),
    command: AtomicU8::new(0),
    data_size: AtomicU32::new(0),
    result_code: AtomicU32::new(0),
    result_size: AtomicU32::new(0),
    data: [0u8; 4096],
};

pub const CMD_IDLE: u8 = 0;
pub const CMD_PING: u8 = 1;
pub const CMD_EXEC_JS: u8 = 2;
pub const CMD_SHUTDOWN: u8 = 3;

pub const STATUS_IDLE: u8 = 0;
pub const STATUS_BUSY: u8 = 1;
pub const STATUS_DATA_READY: u8 = 2;
pub const STATUS_ERROR: u8 = 3;

type KernelThreadStartFn = unsafe extern "C" fn(
    continuation: *const (),
    parameter: *mut core::ffi::c_void,
    new_thread: *mut *mut core::ffi::c_void
) -> i32;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> usize {
    const KERNEL_THREAD_START_ADDR: usize = 0xfffffff007a74674;
    let kernel_thread_start: KernelThreadStartFn = unsafe {
        core::mem::transmute(KERNEL_THREAD_START_ADDR as *const ())
    };

    unsafe {
        let buffer = core::ptr::addr_of_mut!(FRIDA_SHARED_BUFFER);
        (*buffer).magic.store(0x46524944, Ordering::Release); // "FRID"
        (*buffer).status.store(STATUS_IDLE, Ordering::Release);
        (*buffer).command.store(CMD_IDLE, Ordering::Release);
        (*buffer).data_size.store(0, Ordering::Release);
        (*buffer).result_code.store(0, Ordering::Release);
        (*buffer).result_size.store(0, Ordering::Release);

        let mut new_thread: *mut core::ffi::c_void = core::ptr::null_mut();
        let thread_parameter = 12345usize as *mut core::ffi::c_void;

        let _result = kernel_thread_start(
            transmute(ptrauth_sign(frida_agent_worker as *const u8, 0xd507)),
            thread_parameter,
            &mut new_thread as *mut *mut core::ffi::c_void
        );

        virt_to_phys(buffer as usize)
    }
}

unsafe extern "C" fn frida_agent_worker(_parameter: *mut core::ffi::c_void, _wait_result: i32) {
    loop {
        unsafe {
            bindings::gum_init_embedded();

            let backend = bindings::gum_script_backend_obtain_qjs();

            let cancellable: *mut GCancellable = ptr::null_mut();
            let mut error: *mut bindings::GError = ptr::null_mut();

            let c_name = core::ffi::CStr::from_bytes_with_nul_unchecked("explore.js".as_bytes());
            let c_source = core::ffi::CStr::from_bytes_with_nul_unchecked("console.log('Hello from Frida!');".as_bytes());

            let _script = bindings::gum_script_backend_create_sync(
                backend,
                c_name.as_ptr(),
                c_source.as_ptr(),
                ptr::null_mut(),
                cancellable,
                &mut error);

            let buffer = core::ptr::addr_of_mut!(FRIDA_SHARED_BUFFER);

            let cmd = (*buffer).command.load(Ordering::Acquire);
            if cmd != CMD_IDLE {
                (*buffer).status.store(STATUS_BUSY, Ordering::Release);

                match cmd {
                    CMD_PING => {
                        write_string_result_to_buffer(buffer, "PONG from worker thread!");
                        (*buffer).status.store(STATUS_DATA_READY, Ordering::Release);
                    }
                    CMD_EXEC_JS => {
                        write_string_result_to_buffer(buffer, "TODO");
                        (*buffer).status.store(STATUS_DATA_READY, Ordering::Release);
                    }
                    CMD_SHUTDOWN => {
                        write_string_result_to_buffer(buffer, "Worker shutting down");
                        (*buffer).status.store(STATUS_DATA_READY, Ordering::Release);
                        break;
                    }
                    _ => {
                        write_error_to_buffer(buffer, 1, "Unknown command");
                        (*buffer).status.store(STATUS_ERROR, Ordering::Release);
                    }
                }

                (*buffer).command.store(CMD_IDLE, Ordering::Release);
            }
        }

        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

unsafe fn write_string_result_to_buffer(buffer: *mut SharedBuffer, text: &str) {
    unsafe {
        let text_bytes = text.as_bytes();
        let copy_size = core::cmp::min(text_bytes.len(), 4096);
        core::ptr::copy_nonoverlapping(
            text_bytes.as_ptr(),
            (*buffer).data.as_mut_ptr(),
            copy_size
        );

        (*buffer).result_code.store(0, Ordering::Release);
        (*buffer).result_size.store(copy_size as u32, Ordering::Release);
    }
}

unsafe fn write_error_to_buffer(buffer: *mut SharedBuffer, error_code: u32, error_msg: &str) {
    unsafe {
        let error_bytes = error_msg.as_bytes();
        let copy_size = core::cmp::min(error_bytes.len(), 4096);
        core::ptr::copy_nonoverlapping(
            error_bytes.as_ptr(),
            (*buffer).data.as_mut_ptr(),
            copy_size
        );

        (*buffer).result_code.store(error_code, Ordering::Release);
        (*buffer).result_size.store(copy_size as u32, Ordering::Release);
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

unsafe fn ptrauth_sign(ptr: *const u8, discriminator: usize) -> *const u8 {
    let signed: usize;
    unsafe {
        asm!(
            ".inst 0xdac10020",       // pacia x0, x1
            in("x0") ptr as usize,
            in("x1") discriminator,
            lateout("x0") signed,
            options(nomem, nostack),
        );
    }
    signed as *const u8
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
