// Linux hostlink over the Android emulator's QEMU pipe, which is how the emulator
// carries adb as well: open /dev/qemu_pipe, name the "pipe:unix:<path>" service,
// and the emulator joins that stream to the host UNIX socket <path>, where
// frida-core listens. Framed like the other hostlinks, with a 4-byte
// little-endian length in front of each payload.
//
// Every open of the pipe is a channel of its own, handed out by the guest's own
// driver, so the agent shares no device with the drivers already running.

use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use alloc::vec::Vec;

use super::native;

const O_RDWR: c_int = 2;
const PIPE_PATH: &str = "/dev/qemu_pipe\0";
const LAST_ERRNO: usize = 4095;

static PENDING: AtomicU32 = AtomicU32::new(0);
static WAKE_TOKEN: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
struct Shared(UnsafeCell<Vec<u8>>);

unsafe impl Sync for Shared {}

static INCOMING: Shared = Shared(UnsafeCell::new(Vec::new()));
static INCOMING_LOCK: AtomicU32 = AtomicU32::new(0);
static PIPE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

pub fn a_turn_is_wanted() -> bool {
    PENDING.load(Ordering::Acquire) != 0
}

struct Inner {
    file: *mut c_void,
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
unsafe impl Sync for Hostlink {}

impl Hostlink {
    pub fn init(path: &str, on_rx: Option<fn(&[u8])>, wake_token: *const u8) -> Result<Self, ()> {
        WAKE_TOKEN.store(wake_token as *mut u8, Ordering::Release);

        let file = open_the_pipe()?;
        PIPE.store(file, Ordering::Release);

        let mut service = Vec::with_capacity(path.len() + 12);
        service.extend_from_slice(b"pipe:unix:");
        service.extend_from_slice(path.as_bytes());
        service.push(0);
        if write_all(file, &service).is_err() {
            return Err(());
        }

        native::spawn_thread(read_forever, ptr::null_mut());

        Ok(Hostlink {
            state: UnsafeCell::new(Inner {
                file,
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
        let s = unsafe { &*self.state.get() };
        let length = (payload.len() as u32).to_le_bytes();
        let _ = write_all(s.file, &length);
        let _ = write_all(s.file, payload);
    }

    pub fn process(&self) {
        PENDING.store(0, Ordering::Release);

        let arrived = take_what_arrived();
        if arrived.is_empty() {
            return;
        }

        let s = unsafe { &mut *self.state.get() };
        let mut at = 0;
        while at < arrived.len() {
            if s.rx_lenhave < 4 {
                let want = core::cmp::min(4 - s.rx_lenhave, arrived.len() - at);
                s.rx_lenbuf[s.rx_lenhave..s.rx_lenhave + want]
                    .copy_from_slice(&arrived[at..at + want]);
                s.rx_lenhave += want;
                at += want;
                if s.rx_lenhave < 4 {
                    break;
                }
                s.rx_need = u32::from_le_bytes(s.rx_lenbuf) as usize;
                s.rx_have = 0;
                s.rx_buf.resize(s.rx_need, 0);
            }

            let want = core::cmp::min(s.rx_need - s.rx_have, arrived.len() - at);
            let lo = s.rx_have;
            s.rx_buf[lo..lo + want].copy_from_slice(&arrived[at..at + want]);
            s.rx_have += want;
            at += want;
            if s.rx_have < s.rx_need {
                break;
            }

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

    pub fn shutdown(&self) {
        PIPE.store(ptr::null_mut(), Ordering::Release);
    }
}

fn open_the_pipe() -> Result<*mut c_void, ()> {
    let file = unsafe { _filp_open(PIPE_PATH.as_ptr(), O_RDWR, 0) };
    if (file as usize) > usize::MAX - LAST_ERRNO {
        return Err(());
    }

    Ok(file)
}

// The pipe blocks until the host has something, so a thread of its own is what
// reads it; the loop is told there is a turn to take rather than asking.
unsafe extern "C" fn read_forever(_parameter: *mut c_void, _wait_result: i32) {
    let mut chunk = [0u8; 4096];

    loop {
        let file = PIPE.load(Ordering::Acquire);
        if file.is_null() {
            return;
        }

        let n = read_some(file, &mut chunk);
        if n <= 0 {
            return;
        }

        held(|| unsafe { (*INCOMING.0.get()).extend_from_slice(&chunk[..n as usize]) });

        PENDING.store(1, Ordering::Release);
        crate::nudge_the_loop(WAKE_TOKEN.load(Ordering::Acquire) as *const u8);
    }
}

fn take_what_arrived() -> Vec<u8> {
    held(|| core::mem::take(unsafe { &mut *INCOMING.0.get() }))
}

fn held<T>(action: impl FnOnce() -> T) -> T {
    while INCOMING_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }

    let outcome = action();

    INCOMING_LOCK.store(0, Ordering::Release);

    outcome
}

fn read_some(file: *mut c_void, into: &mut [u8]) -> isize {
    let mut position: i64 = 0;
    unsafe { native::pipe_read(file, into.as_mut_ptr(), into.len(), &mut position) }
}

fn write_all(file: *mut c_void, bytes: &[u8]) -> Result<(), ()> {
    let mut sent = 0;
    while sent < bytes.len() {
        let mut position: i64 = 0;
        let n = unsafe {
            native::pipe_write(file, bytes[sent..].as_ptr(), bytes.len() - sent, &mut position)
        };
        if n <= 0 {
            return Err(());
        }
        sent += n as usize;
    }

    Ok(())
}

unsafe extern "C" {
    static _filp_open: unsafe extern "C" fn(*const u8, c_int, c_int) -> *mut c_void;
}
