use core::arch::asm;
use core::ptr;

use crate::bindings::{g_wait_is_set, gint64, gpointer};
use crate::xnu;

const G_WAIT_INFINITE: gint64 = -1;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".data")]
static mut HOST_EVENT: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn g_get_monotonic_time() -> gint64 {
    let abstime = xnu::mach_absolute_time();
    let time = xnu::absolutetime_to_nanoseconds(abstime);
    (time / 1000) as gint64
}

#[unsafe(no_mangle)]
pub extern "C" fn g_wait_sleep(token: gpointer, timeout_us: gint64) {
    let wait_event = token as *const u8;

    xnu::assert_wait(
        ptr::addr_of_mut!(HOST_EVENT) as *const u8,
        xnu::THREAD_INTERRUPTIBLE,
    );

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
        xnu::thread_wakeup(ptr::addr_of!(HOST_EVENT) as *const u8);
        return;
    }

    xnu::thread_block(None);
}

#[unsafe(no_mangle)]
pub extern "C" fn g_wait_wake(token: gpointer) {
    xnu::thread_wakeup(token as *const u8);
}

pub const DOORBELL_IRQ: i32 = 32;

pub fn init_host_doorbell() {
    unsafe {
        let pa = xnu::ml_vtophys(ptr::addr_of!(HOST_EVENT) as u64);
        asm!("mov x0, {0}", "hvc #0xab", in(reg) pa);

        xnu::ml_install_interrupt_handler(
            core::ptr::null_mut(),
            DOORBELL_IRQ,
            ptr::addr_of!(HOST_EVENT) as *mut core::ffi::c_void,
            host_doorbell_isr,
            core::ptr::null_mut(),
        );
    }
}

unsafe extern "C" fn host_doorbell_isr(
    refcon: *mut core::ffi::c_void,
    _nub: *mut core::ffi::c_void,
    _source: i32,
) {
    xnu::thread_wakeup(refcon as *const u8);
}
