use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::{c_int, c_void};
use core::mem::size_of;
use core::ptr;

use super::layout::field_offset;
use super::native;
use super::processes::task_with_id;

pub fn spawn_process(words: &[&str]) -> u32 {
    let Some(words) = said_as(words) else {
        return 0;
    };

    super::injection::hold_what_is_spawned();

    let held = native::alloc(size_of::<Held>()) as *mut Held;
    unsafe {
        held.write(Held {
            id: 0,
            words,
            environment: environment(),
        })
    };

    let info = unsafe {
        _call_usermodehelper_setup(
            (*held).words.first_word(),
            (*held).words.as_argv(),
            (*held).environment.as_argv(),
            GFP_KERNEL,
            hold_this_one,
            let_go_of_the_words,
            held as *mut c_void,
        )
    };
    if info.is_null() {
        return 0;
    }

    if unsafe { _call_usermodehelper_exec(info, UMH_WAIT_EXEC) } != 0 {
        return 0;
    }

    unsafe { (*held).id }
}

pub fn resume_process(id: u32) -> bool {
    let Some(task) = task_with_id(id) else {
        return false;
    };

    native::send_signal(CONTINUE, task);

    true
}

pub fn holds_this_one(task: usize) -> bool {
    let Some(id) = super::injection::id_of(task) else {
        return false;
    };

    let held = unsafe { (&raw const HELD).read() };

    held != 0 && held == id
}

unsafe extern "C" fn hold_this_one(info: *mut c_void, _credentials: *mut c_void) -> c_int {
    let Some(at) = field_offset("subprocess_info", "data") else {
        return 0;
    };
    let held = unsafe { ((info as usize + at) as *const usize).read() } as *mut Held;

    let id = super::injection::id_of(native::current_task() as usize).unwrap_or(0);
    unsafe {
        (*held).id = id;
        (&raw mut HELD).write(id);
    }

    0
}

unsafe extern "C" fn let_go_of_the_words(info: *mut c_void) {
    let Some(at) = field_offset("subprocess_info", "data") else {
        return;
    };
    let held = unsafe { ((info as usize + at) as *const usize).read() } as *mut Held;

    unsafe { ptr::drop_in_place(held) };
    native::free(held as *mut u8, size_of::<Held>());
}

fn said_as(words: &[&str]) -> Option<Words> {
    let said: Vec<CString> = words.iter().map(|word| CString::new(*word).unwrap()).collect();
    if said.is_empty() {
        return None;
    }

    let mut pointers: Vec<*const u8> = said.iter().map(|word| word.as_ptr() as *const u8).collect();
    pointers.push(ptr::null());

    Some(Words { said, pointers })
}

fn environment() -> Words {
    said_as(&["HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", "TERM=linux"]).unwrap()
}

struct Held {
    id: u32,
    words: Words,
    environment: Words,
}

struct Words {
    said: Vec<CString>,
    pointers: Vec<*const u8>,
}

impl Words {
    fn first_word(&self) -> *const u8 {
        self.said[0].as_ptr() as *const u8
    }

    fn as_argv(&self) -> *const *const u8 {
        self.pointers.as_ptr()
    }
}

static mut HELD: u32 = 0;

const GFP_KERNEL: u32 = 0xcc0;
const UMH_WAIT_EXEC: c_int = 1;
const CONTINUE: c_int = 18;

unsafe extern "C" {
    static _call_usermodehelper_setup: unsafe extern "C" fn(
        *const u8,
        *const *const u8,
        *const *const u8,
        u32,
        unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int,
        unsafe extern "C" fn(*mut c_void),
        *mut c_void,
    ) -> *mut c_void;
    static _call_usermodehelper_exec: unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
}
