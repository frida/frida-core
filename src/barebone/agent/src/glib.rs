use core::ptr;

use crate::bindings::{g_wait_is_set, gint64, gpointer};
use crate::kernel;

const G_WAIT_INFINITE: gint64 = -1;

pub static mut WAKEUP_TOKEN: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn g_get_monotonic_time() -> gint64 {
    kernel::monotonic_micros()
}

#[unsafe(no_mangle)]
pub extern "C" fn g_wait_sleep(token: gpointer, timeout_us: gint64) {
    let wait_event = ptr::addr_of_mut!(WAKEUP_TOKEN) as *const u8;

    let timeout = if timeout_us == G_WAIT_INFINITE {
        None
    } else {
        Some(timeout_us as u64)
    };

    kernel::wait(wait_event, timeout, &mut || unsafe {
        g_wait_is_set(token) != 0
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn g_wait_wake(_token: gpointer) {
    kernel::wake(ptr::addr_of_mut!(WAKEUP_TOKEN) as *const u8);
}

#[unsafe(no_mangle)]
pub extern "C" fn g_io_channel_unix_new(_fd: i32) -> gpointer {
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn g_spawn_async_with_pipes() -> i32 {
    0
}
