use core::ptr;

use crate::bindings::{g_wait_is_set, gint64, gpointer};
use crate::xnu;

const G_WAIT_INFINITE: gint64 = -1;

pub static mut WAKEUP_TOKEN: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn g_get_monotonic_time() -> gint64 {
    let abstime = xnu::mach_absolute_time();
    let time = xnu::absolutetime_to_nanoseconds(abstime);
    (time / 1000) as gint64
}

#[unsafe(no_mangle)]
pub extern "C" fn g_wait_sleep(token: gpointer, timeout_us: gint64) {
    let wait_event = ptr::addr_of_mut!(WAKEUP_TOKEN) as *const u8;

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
    xnu::thread_wakeup(ptr::addr_of_mut!(WAKEUP_TOKEN) as *const u8);
}
