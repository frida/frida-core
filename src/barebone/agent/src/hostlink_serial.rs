// Same 4-byte LE length-prefix framing as hostlink_virtio so the host-side
// (yqv) protocol is identical across transports.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::kernel;
use crate::winnt::windows_fn;

pub struct Hostlink {
    state: UnsafeCell<Inner>,
    on_rx: Option<fn(&[u8])>,
}

struct Inner {
    port: *mut c_void,
}

unsafe impl Send for Hostlink {}

impl Hostlink {
    pub fn init(on_rx: Option<fn(&[u8])>, wake_token: *const u8) -> Result<Self, ()> {
        let port = open_first_serial_port()?;

        unsafe {
            WAKE_TOKEN = wake_token;
            READER_PORT = port;
        }
        kernel::spawn_thread(read_from_host, ptr::null_mut());

        Ok(Self {
            state: UnsafeCell::new(Inner { port }),
            on_rx,
        })
    }

    pub fn send(&self, payload: &[u8]) {
        let s = unsafe { &*self.state.get() };

        write_all(s.port, &(payload.len() as u32).to_le_bytes());
        write_all(s.port, payload);
    }

    pub fn process(&self) {
        loop {
            let Some(frame) = take_frame() else {
                return;
            };
            if let Some(on_rx) = self.on_rx {
                on_rx(&frame);
            }
        }
    }

    pub fn shutdown(&self) {
        let s = unsafe { &*self.state.get() };
        unsafe {
            (_ZwClose)(s.port);
        }
    }
}

unsafe extern "C" fn read_from_host(_parameter: *mut c_void, _wait_result: i32) {
    let port = unsafe { READER_PORT };

    let mut length = [0u8; FRAME_LENGTH_SIZE];
    loop {
        if !read_exactly(port, &mut length) {
            return;
        }

        let mut frame = alloc::vec![0u8; u32::from_le_bytes(length) as usize];
        if !read_exactly(port, &mut frame) {
            return;
        }

        put_frame(frame);
        kernel::wake(unsafe { WAKE_TOKEN });
    }
}

fn read_exactly(port: *mut c_void, buffer: &mut [u8]) -> bool {
    let mut read = 0;
    while read != buffer.len() {
        let mut status_block = [0usize; STATUS_BLOCK_WORDS];
        let mut offset = 0i64;
        let status = unsafe {
            (_ZwReadFile)(
                port,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                status_block.as_mut_ptr() as *mut c_void,
                buffer.as_mut_ptr().add(read),
                (buffer.len() - read) as u32,
                &mut offset,
                ptr::null_mut(),
            )
        };
        if status < 0 {
            return false;
        }

        let moved = status_block[STATUS_BLOCK_COUNT];
        if moved == 0 {
            return false;
        }
        read += moved;
    }

    true
}

fn write_all(port: *mut c_void, buffer: &[u8]) {
    let mut written = 0;
    while written != buffer.len() {
        let mut status_block = [0usize; STATUS_BLOCK_WORDS];
        let mut offset = 0i64;
        let status = unsafe {
            (_ZwWriteFile)(
                port,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                status_block.as_mut_ptr() as *mut c_void,
                buffer.as_ptr().add(written),
                (buffer.len() - written) as u32,
                &mut offset,
                ptr::null_mut(),
            )
        };
        if status < 0 {
            return;
        }

        let moved = status_block[STATUS_BLOCK_COUNT];
        if moved == 0 {
            return;
        }
        written += moved;
    }
}

fn put_frame(frame: Vec<u8>) {
    lock_frames();
    unsafe {
        (*ptr::addr_of_mut!(FRAMES)).push_back(frame);
    }
    unlock_frames();
}

fn take_frame() -> Option<Vec<u8>> {
    lock_frames();
    let frame = unsafe { (*ptr::addr_of_mut!(FRAMES)).pop_front() };
    unlock_frames();
    frame
}

fn lock_frames() {
    while FRAMES_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        kernel::yield_now();
    }
}

fn unlock_frames() {
    FRAMES_LOCK.store(0, Ordering::Release);
}

static mut FRAMES: VecDeque<Vec<u8>> = VecDeque::new();
static FRAMES_LOCK: AtomicU32 = AtomicU32::new(0);
static mut WAKE_TOKEN: *const u8 = ptr::null();
static mut READER_PORT: *mut c_void = ptr::null_mut();

fn open_first_serial_port() -> Result<*mut c_void, ()> {
    let ports = open_key(SERIAL_PORT_KEY)?;

    let mut name = [0u8; VALUE_NAME_SIZE];
    let mut size = 0u32;
    let status = unsafe {
        (_ZwEnumerateValueKey)(ports, 0, VALUE_NAME_INFORMATION, name.as_mut_ptr(),
            name.len() as u32, &mut size)
    };
    unsafe {
        (_ZwClose)(ports);
    }
    if status < 0 {
        return Err(());
    }

    let length = u32::from_le_bytes(name[VALUE_NAME_LENGTH..VALUE_NAME_LENGTH + 4]
        .try_into()
        .unwrap()) as usize;
    open_device(&name[VALUE_NAME_OFFSET..VALUE_NAME_OFFSET + length])
}

fn open_key(path: &[u16]) -> Result<*mut c_void, ()> {
    let mut handle: *mut c_void = ptr::null_mut();
    let mut name = unicode_string(path);
    let mut attributes = object_attributes(&mut name);

    let status =
        unsafe { (_ZwOpenKey)(&mut handle, KEY_READ, attributes.as_mut_ptr() as *mut c_void) };
    if status < 0 {
        return Err(());
    }

    Ok(handle)
}

fn open_device(path: &[u8]) -> Result<*mut c_void, ()> {
    let mut handle: *mut c_void = ptr::null_mut();
    let mut name = UnicodeString {
        length: path.len() as u16,
        maximum_length: path.len() as u16,
        buffer: path.as_ptr() as *const u16,
    };
    let mut attributes = object_attributes(&mut name);
    let mut status_block = [0usize; STATUS_BLOCK_WORDS];

    let status = unsafe {
        (_ZwCreateFile)(
            &mut handle,
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
            attributes.as_mut_ptr() as *mut c_void,
            status_block.as_mut_ptr() as *mut c_void,
            ptr::null_mut(),
            0,
            0,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        )
    };
    if status < 0 {
        return Err(());
    }

    configure_port(handle);

    Ok(handle)
}

fn configure_port(port: *mut c_void) {
    let mut baud_rate = [0u32; 1];
    baud_rate[0] = BAUD_RATE;
    control_port(port, SET_BAUD_RATE, baud_rate.as_ptr() as *const u8,
        core::mem::size_of_val(&baud_rate) as u32);

    let line_control = [DATA_BITS, NO_PARITY, ONE_STOP_BIT];
    control_port(port, SET_LINE_CONTROL, line_control.as_ptr(),
        core::mem::size_of_val(&line_control) as u32);

    let hand_flow = [0u32; HAND_FLOW_WORDS];
    control_port(port, SET_HAND_FLOW, hand_flow.as_ptr() as *const u8,
        core::mem::size_of_val(&hand_flow) as u32);

    control_port(port, SET_DTR, core::ptr::null(), 0);
    control_port(port, SET_RTS, core::ptr::null(), 0);

    let timeouts = [0u32; TIMEOUT_WORDS];
    control_port(port, SET_TIMEOUTS, timeouts.as_ptr() as *const u8,
        core::mem::size_of_val(&timeouts) as u32);
}

fn control_port(port: *mut c_void, code: u32, input: *const u8, length: u32) {
    let mut status_block = [0usize; STATUS_BLOCK_WORDS];
    unsafe {
        (_ZwDeviceIoControlFile)(
            port,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            status_block.as_mut_ptr() as *mut c_void,
            code,
            input,
            length,
            ptr::null_mut(),
            0,
        );
    }
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

fn unicode_string(text: &[u16]) -> UnicodeString {
    let bytes = (text.len() * 2) as u16;
    UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: text.as_ptr(),
    }
}

fn object_attributes(name: &mut UnicodeString) -> [usize; OBJECT_ATTRIBUTES_WORDS] {
    let mut attributes = [0usize; OBJECT_ATTRIBUTES_WORDS];
    attributes[0] = core::mem::size_of::<[usize; OBJECT_ATTRIBUTES_WORDS]>();
    attributes[2] = name as *mut UnicodeString as usize;
    attributes[3] = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
    attributes
}

const FRAME_LENGTH_SIZE: usize = 4;
const STATUS_BLOCK_WORDS: usize = 2;
const STATUS_BLOCK_COUNT: usize = 1;
const OBJECT_ATTRIBUTES_WORDS: usize = 6;

const SERIAL_PORT_KEY: &[u16] = &[
    0x5c, 0x52, 0x45, 0x47, 0x49, 0x53, 0x54, 0x52, 0x59, 0x5c, 0x4d, 0x41, 0x43, 0x48, 0x49, 0x4e,
    0x45, 0x5c, 0x48, 0x41, 0x52, 0x44, 0x57, 0x41, 0x52, 0x45, 0x5c, 0x44, 0x45, 0x56, 0x49, 0x43,
    0x45, 0x4d, 0x41, 0x50, 0x5c, 0x53, 0x45, 0x52, 0x49, 0x41, 0x4c, 0x43, 0x4f, 0x4d, 0x4d,
];

const VALUE_NAME_INFORMATION: u32 = 0;
const VALUE_NAME_SIZE: usize = 512;
const VALUE_NAME_LENGTH: usize = 0x08;
const VALUE_NAME_OFFSET: usize = 0x0c;

const SET_BAUD_RATE: u32 = 0x001b_0004;
const SET_LINE_CONTROL: u32 = 0x001b_000c;
const SET_TIMEOUTS: u32 = 0x001b_001c;
const SET_DTR: u32 = 0x001b_0024;
const SET_RTS: u32 = 0x001b_0030;
const SET_HAND_FLOW: u32 = 0x001b_0064;

const BAUD_RATE: u32 = 921_600;
const DATA_BITS: u8 = 8;
const NO_PARITY: u8 = 0;
const ONE_STOP_BIT: u8 = 0;
const HAND_FLOW_WORDS: usize = 4;
const TIMEOUT_WORDS: usize = 5;

const KEY_READ: u32 = 0x2_0019;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_OPEN: u32 = 1;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const OBJ_CASE_INSENSITIVE: usize = 0x40;
const OBJ_KERNEL_HANDLE: usize = 0x200;

use core::sync::atomic::{AtomicU32, Ordering};

unsafe extern "C" {
    static _ZwOpenKey: windows_fn!(*mut *mut c_void, u32, *mut c_void => i32);
    static _ZwEnumerateValueKey: windows_fn!(
        *mut c_void, u32, u32, *mut u8, u32, *mut u32 => i32);
    static _ZwCreateFile: windows_fn!(
        *mut *mut c_void, u32, *mut c_void, *mut c_void, *mut i64, u32, u32, u32, u32,
        *mut c_void, u32 => i32);
    static _ZwReadFile: windows_fn!(
        *mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut u8, u32, *mut i64,
        *mut u32 => i32);
    static _ZwWriteFile: windows_fn!(
        *mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void, *const u8, u32, *mut i64,
        *mut u32 => i32);
    static _ZwDeviceIoControlFile: windows_fn!(
        *mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void, u32, *const u8, u32,
        *mut u8, u32 => i32);
    static _ZwClose: windows_fn!(*mut c_void => i32);
}
