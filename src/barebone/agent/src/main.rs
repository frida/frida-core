#![no_main]
#![no_std]

mod quickjs;
mod syscalls;

use core::{arch::asm, ffi::CStr, mem::transmute};
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

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
    let rt = quickjs::JSRuntime::new();
    let ctx = rt.create_context();

    loop {
        unsafe {
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
                        on_exec_js(buffer, &ctx);
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

unsafe fn on_exec_js(buffer: *mut SharedBuffer, ctx: &quickjs::JSContext) {
    unsafe {
        let data_size = (*buffer).data_size.load(Ordering::Acquire) as usize;
        if data_size == 0 || data_size > 4096 {
            panic!("Protocol error");
        }

        let mut code_bytes = [0u8; 4097];
        let code_size = core::cmp::min(data_size, 4096);
        core::ptr::copy_nonoverlapping(
            (*buffer).data.as_ptr(),
            code_bytes.as_mut_ptr(),
            code_size
        );
        code_bytes[code_size] = 0;

        let code = CStr::from_bytes_with_nul_unchecked(&code_bytes[..code_size + 1]).to_str().unwrap();

        let result_val = ctx.eval("worker.js", code);
        if result_val.is_exception() {
            let exception = ctx.steal_exception().unwrap();
            let exception_str = exception.to_cstring();
            write_error_to_buffer(buffer, 1, exception_str.as_str_unchecked());
        } else {
            write_string_result_to_buffer(buffer, result_val.to_cstring().as_str_unchecked());
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
