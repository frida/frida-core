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

    let wait_result = if timeout_us == G_WAIT_INFINITE {
        xnu::assert_wait(wait_event, xnu::THREAD_INTERRUPTIBLE)
    } else {
        xnu::assert_wait_timeout(
            wait_event,
            xnu::THREAD_INTERRUPTIBLE,
            (timeout_us * 1000) as u32,
            1, // TODO
        )
    };
    if wait_result != xnu::THREAD_WAITING {
        panic!("assert_wait_timeout failed: {}", wait_result);
    }

    if unsafe { g_wait_is_set(token) != 0 } {
        xnu::thread_wakeup(wait_event);
        return;
    }

    xnu::thread_block(None);
}

#[unsafe(no_mangle)]
pub extern "C" fn g_wait_wake(_token: gpointer) {
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

        xnu::install_interrupt_handler(
            irq,
            ptr::addr_of_mut!(PENDING_EVENT) as *mut c_void,
            on_doorbell_interrupt,
            core::ptr::null_mut(),
        );
    }
}

extern "C" fn on_doorbell_interrupt(
    target: *mut c_void,
    _refcon: *mut c_void,
    _nub: *mut c_void,
    _source: i32,
) {
    xnu::thread_wakeup(target as *const u8);
}
