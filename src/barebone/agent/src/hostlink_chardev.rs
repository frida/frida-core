// Linux transport: /dev/frida, framed the same way as the XNU hostlinks (4-byte
// little-endian length prefix) so the host-side (yqv) protocol is identical across
// every transport.
//
// The character device itself lives in linux/frida-kmod.c and hands us a byte
// stream; whoever opens the device decides how it reaches the host.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use core::ffi::{c_int, c_void};

use alloc::vec::Vec;

struct Inner {
    rx_lenbuf: [u8; 4],
    rx_lenhave: usize,
    rx_buf: Vec<u8>,
    rx_have: usize,
    rx_need: usize,
}

pub struct Hostlink {
    state: UnsafeCell<Inner>,
    on_rx: Option<fn(&[u8])>,
}

unsafe impl Send for Hostlink {}

impl Hostlink {
    pub fn init(on_rx: Option<fn(&[u8])>) -> Result<Self, ()> {
        if unsafe { frida_kmod_link_open() } != 0 {
            return Err(());
        }
        LINK_OPEN.store(true, Ordering::Release);

        Ok(Hostlink {
            state: UnsafeCell::new(Inner {
                rx_lenbuf: [0; 4],
                rx_lenhave: 0,
                rx_buf: Vec::new(),
                rx_have: 0,
                rx_need: 0,
            }),
            on_rx,
        })
    }

    pub fn send(&self, payload: &[u8]) {
        let header = (payload.len() as u32).to_le_bytes();
        unsafe {
            frida_kmod_link_send(header.as_ptr() as *const c_void, header.len());
            frida_kmod_link_send(payload.as_ptr() as *const c_void, payload.len());
        }
    }

    pub fn process(&self) {
        let s = unsafe { &mut *self.state.get() };
        loop {
            if s.rx_lenhave < 4 {
                let lo = s.rx_lenhave;
                let n = recv_nonblocking(&mut s.rx_lenbuf[lo..4]);
                if n == 0 {
                    return;
                }
                s.rx_lenhave += n;
                if s.rx_lenhave < 4 {
                    continue;
                }
                s.rx_need = u32::from_le_bytes(s.rx_lenbuf) as usize;
                s.rx_have = 0;
                s.rx_buf.resize(s.rx_need, 0);
            }

            while s.rx_have < s.rx_need {
                let lo = s.rx_have;
                let hi = s.rx_need;
                let n = recv_nonblocking(&mut s.rx_buf[lo..hi]);
                if n == 0 {
                    return;
                }
                s.rx_have += n;
            }

            // Detach the frame and reset receive state before dispatching: the callback may
            // re-enter process() (a synchronous host RPC issued while handling a command), and
            // it must start from a clean state instead of re-dispatching this same frame.
            let frame = core::mem::take(&mut s.rx_buf);
            let need = s.rx_need;
            s.rx_lenhave = 0;
            s.rx_have = 0;
            s.rx_need = 0;

            if let Some(cb) = self.on_rx {
                cb(&frame[..need]);
            }
        }
    }
}

impl Drop for Hostlink {
    fn drop(&mut self) {
        LINK_OPEN.store(false, Ordering::Release);
        unsafe { frida_kmod_link_close() };
    }
}

pub fn a_turn_is_wanted() -> bool {
    LINK_OPEN.load(Ordering::Acquire) && unsafe { frida_kmod_link_pending() }
}

static LINK_OPEN: AtomicBool = AtomicBool::new(false);

fn recv_nonblocking(dst: &mut [u8]) -> usize {
    let n = unsafe { frida_kmod_link_recv(dst.as_mut_ptr() as *mut c_void, dst.len()) };
    if n <= 0 { 0 } else { n as usize }
}

#[cfg(feature = "xnu-kext")]
unsafe extern "C" {
    fn frida_kmod_link_open() -> c_int;
    fn frida_kmod_link_close();
    fn frida_kmod_link_send(data: *const c_void, size: usize) -> c_int;
    fn frida_kmod_link_recv(data: *mut c_void, size: usize) -> isize;
    fn frida_kmod_link_pending() -> bool;
}

#[cfg(all(feature = "linux-injected", not(target_arch = "x86")))]
unsafe extern "C" {
    #[link_name = "_frida_kmod_link_open"]
    static frida_kmod_link_open: unsafe extern "C" fn() -> c_int;
    #[link_name = "_frida_kmod_link_close"]
    static frida_kmod_link_close: unsafe extern "C" fn();
    #[link_name = "_frida_kmod_link_send"]
    static frida_kmod_link_send: unsafe extern "C" fn(*const c_void, usize) -> c_int;
    #[link_name = "_frida_kmod_link_recv"]
    static frida_kmod_link_recv: unsafe extern "C" fn(*mut c_void, usize) -> isize;
    #[link_name = "_frida_kmod_link_pending"]
    static frida_kmod_link_pending: unsafe extern "C" fn() -> bool;
}

#[cfg(all(feature = "linux-injected", target_arch = "x86"))]
unsafe extern "C" {
    #[link_name = "frida_k_frida_kmod_link_open"]
    fn frida_kmod_link_open() -> c_int;
    #[link_name = "frida_k_frida_kmod_link_close"]
    fn frida_kmod_link_close();
    #[link_name = "frida_k_frida_kmod_link_send"]
    fn frida_kmod_link_send(data: *const c_void, size: usize) -> c_int;
    #[link_name = "frida_k_frida_kmod_link_recv"]
    fn frida_kmod_link_recv(data: *mut c_void, size: usize) -> isize;
    #[link_name = "frida_k_frida_kmod_link_pending"]
    fn frida_kmod_link_pending() -> bool;
}
