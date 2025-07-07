use core::ptr;

use crate::bindings::{gint64, gpointer};
use crate::kprintln;

const G_WAIT_INFINITE: gint64 = -1;

/// Sleep on a token until timeout or wakeup
///
/// Blocks the current thread until either:
/// - timeout_us expires, or
/// - g_wait_wake(token) fires on the same token
///
/// The token is opaque and must not be dereferenced.
///
/// # Arguments
/// * `token` - Opaque token to sleep on (used as XNU wait event)
/// * `timeout_us` - Timeout in microseconds
#[unsafe(no_mangle)]
pub extern "C" fn g_wait_sleep(token: gpointer, timeout_us: gint64) {
    kprintln!("g_wait_sleep: token={:?} timeout_us={}", token, timeout_us);

    let wait_event = token as *const u8;

    let timeout_ns = if timeout_us == G_WAIT_INFINITE {
        1_000_000_000 //u32::MAX
    } else {
        (timeout_us * 1000) as u32
    };

    kprintln!("g_wait_sleep: setting timeout to {} ns", timeout_ns);

    let wait_result = crate::xnu::assert_wait_timeout(
        wait_event,
        crate::xnu::THREAD_UNINT,
        timeout_ns,
        1 // TODO
    );

    if wait_result != 0 {
        kprintln!("g_wait_sleep: assert_wait_timeout failed: {}", wait_result);
        return;
    }

    let block_result = crate::xnu::thread_block(None);
    kprintln!("g_wait_sleep: thread_block returned {}", block_result);

    match block_result {
        r if r == crate::xnu::THREAD_AWAKENED => {
            kprintln!("g_wait_sleep: woken up by g_wait_wake");
        }
        r if r == crate::xnu::THREAD_TIMED_OUT => {
            kprintln!("g_wait_sleep: timeout expired");
        }
        r if r == crate::xnu::THREAD_INTERRUPTED => {
            kprintln!("g_wait_sleep: interrupted by system");
        }
        _ => {
            kprintln!("g_wait_sleep: unknown result: {}", block_result);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_wait_wake(token: gpointer) {
    kprintln!("g_wait_wake: waking up token={:?}", token);

    let wait_event = token as *const u8;

    let wake_result = crate::xnu::thread_wakeup(wait_event);
    kprintln!("g_wait_wake: thread_wakeup returned {}", wake_result);

    // Note: XNU thread_wakeup returns the number of threads woken up,
    // or a negative error code. We don't need to return anything since
    // the function is void.
}
