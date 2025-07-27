use core::ptr;
use core::ffi::c_void;

use crate::bindings::{g_wait_is_set, gint64, gpointer};
use crate::{kprintln, xnu};

const G_WAIT_INFINITE: gint64 = -1;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".data")]
static mut PENDING_EVENT: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn g_get_monotonic_time() -> gint64 {
    let abstime = xnu::mach_absolute_time();
    let time = xnu::absolutetime_to_nanoseconds(abstime);
    (time / 1000) as gint64
}

#[unsafe(no_mangle)]
pub extern "C" fn g_wait_sleep(token: gpointer, timeout_us: gint64) {
    let wait_event = ptr::addr_of_mut!(PENDING_EVENT) as *const u8;
    kprintln!("[FRIDA] g_wait_sleep() token={:?} timeout_us={}", token, timeout_us);

    let wait_result = if timeout_us == G_WAIT_INFINITE {
        kprintln!("[FRIDA] A");
        xnu::assert_wait(wait_event, xnu::THREAD_INTERRUPTIBLE)
    } else {
        kprintln!("[FRIDA] B");
        xnu::assert_wait_timeout(
            wait_event,
            xnu::THREAD_INTERRUPTIBLE,
            (timeout_us * 1000) as u32,
            1, // TODO
        )
    };
    kprintln!("[FRIDA] C");
    if wait_result != xnu::THREAD_WAITING {
        panic!("assert_wait_timeout failed: {}", wait_result);
    }

    if unsafe { g_wait_is_set(token) != 0 } {
        kprintln!("[FRIDA] g_wait_sleep() bailing early");
        xnu::thread_wakeup(wait_event);
        return;
    }

    kprintln!(
        "[FRIDA] Waiting for event {:#x} with timeout {} us",
        wait_event as usize,
        timeout_us
    );
    xnu::thread_block(None);
    kprintln!("[FRIDA] Woke up");
}

#[unsafe(no_mangle)]
pub extern "C" fn g_wait_wake(_token: gpointer) {
    kprintln!("[FRIDA] g_wait_wake()");
    xnu::thread_wakeup(ptr::addr_of_mut!(PENDING_EVENT) as *const u8);
}

const DOORBELL_PADDR: u64 = 0x200100000;
const DOORBELL_SIZE: u64 = 0x4000;

const REG_TOKEN: usize = 0x0; // W 64‑bit
const REG_IRQ: usize = 0x8; // R 32‑bit

pub fn init_host_doorbell() {
    unsafe {
        let doorbell_va = xnu::ml_io_map(DOORBELL_PADDR, DOORBELL_SIZE);

        kprintln!(
            "[FRIDA] Host doorbell PA={:#x} VA={:#x}, ",
            DOORBELL_PADDR,
            doorbell_va as u64
        );

        let token_pa = xnu::ml_vtophys(PENDING_EVENT);
        ptr::write_volatile(
            (doorbell_va as u64 + REG_TOKEN as u64) as *mut u64,
            token_pa,
        );

        let irq: i32 = ptr::read_volatile((doorbell_va as u64 + REG_IRQ as u64) as *const i32);
        kprintln!("[FRIDA] Host doorbell irq={}", irq);

        xnu::ml_install_interrupt_handler(
            core::ptr::null_mut(),
            irq,
            ptr::addr_of!(PENDING_EVENT) as *mut c_void,
            host_doorbell_isr,
            core::ptr::null_mut(),
        );
    }
}

unsafe extern "C" fn host_doorbell_isr(
    target: *mut c_void,
    _refcon: *mut c_void,
    _nub: *mut c_void,
    source: i32,
) {
    kprintln!("[FRIDA] host_doorbell_isr() source={}", source);
    xnu::thread_wakeup(target as *const u8);
}
