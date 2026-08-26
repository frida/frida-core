
use core::ffi::c_int;
use core::ffi::c_void;

pub fn hide_our_threads() {
    hide_us_from_the_thread_list();


    if unsafe { HIDDEN } {
        return;
    }
    unsafe { HIDDEN = true };

    let calls = unsafe { crate::xnu_bell::_sysent };
    if calls == 0 {
        return;
    }

    let signed = unsafe {
        ((calls + ASKING_ABOUT_A_PROCESS * AN_ENTRY) as *const u64).read_volatile()
    };
    let asking = unsafe { crate::pac::ptrauth_strip_data(signed as *const u8) };

    unsafe {
        WHERE_IT_IS_ASKED = asking as *mut c_void;
        let interceptor = crate::bindings::gum_interceptor_obtain();
        crate::bindings::gum_interceptor_begin_transaction(interceptor);
        crate::bindings::gum_interceptor_replace(interceptor, asking as *mut c_void,
            say_what_it_has as *mut c_void, (&raw mut THE_ANSWER) as *mut *mut c_void,
            core::ptr::null_mut());
        crate::bindings::gum_interceptor_end_transaction(interceptor);
    }
}

pub fn show_our_threads_again() {
    if !unsafe { HIDDEN } {
        return;
    }
    unsafe { HIDDEN = false };

    unsafe {
        let interceptor = crate::bindings::gum_interceptor_obtain();
        crate::bindings::gum_interceptor_begin_transaction(interceptor);
        if !WHERE_IT_IS_ASKED.is_null() {
            crate::bindings::gum_interceptor_revert(interceptor, WHERE_IT_IS_ASKED);
        }
        if !WHERE_THE_LIST_IS_ASKED.is_null() {
            crate::bindings::gum_interceptor_revert(interceptor, WHERE_THE_LIST_IS_ASKED);
        }
        crate::bindings::gum_interceptor_end_transaction(interceptor);
        THE_ANSWER = None;
        THE_LIST = None;
        WHERE_IT_IS_ASKED = core::ptr::null_mut();
        WHERE_THE_LIST_IS_ASKED = core::ptr::null_mut();
        HIDDEN_FROM_THE_LIST = false;
    }
}

fn hide_us_from_the_thread_list() {
    if unsafe { HIDDEN_FROM_THE_LIST } {
        return;
    }
    unsafe { HIDDEN_FROM_THE_LIST = true };

    let Some(asking) = (unsafe { _task_threads }) else {
        return;
    };

    unsafe {
        WHERE_THE_LIST_IS_ASKED = asking as *mut c_void;
        let interceptor = crate::bindings::gum_interceptor_obtain();
        crate::bindings::gum_interceptor_begin_transaction(interceptor);
        crate::bindings::gum_interceptor_replace(interceptor, asking as *mut c_void,
            say_which_threads as *mut c_void, (&raw mut THE_LIST) as *mut *mut c_void,
            core::ptr::null_mut());
        crate::bindings::gum_interceptor_end_transaction(interceptor);
    }
}

unsafe extern "C" fn say_which_threads(task: *mut c_void, threads: *mut *mut u64,
    how_many: *mut u32) -> c_int
{
    let went = match unsafe { THE_LIST } {
        Some(ask_it) => unsafe { ask_it(task, threads, how_many) },
        None => 0,
    };
    if went != 0 {
        return went;
    }
    let only_counting = asked_by_one_of_ours();

    let said = unsafe { *threads };
    let count = unsafe { *how_many } as usize;
    if said.is_null() || count == 0 {
        return went;
    }

    let mut kept = 0;
    for step in 0..count {
        let signed = unsafe { said.add(step).read() };
        if is_one_of_our_threads(signed) {
            continue;
        }
        if !only_counting {
            unsafe { said.add(kept).write(signed) };
        }
        kept += 1;
    }

    if only_counting {
        return went;
    }

    for step in kept..count {
        unsafe { said.add(step).write(0) };
    }
    unsafe { *how_many = kept as u32 };


    went
}

fn is_one_of_our_threads(signed: u64) -> bool {
    let held = unsafe { crate::pac::ptrauth_strip_pointer(signed as *const u8) } as u64;
    if !looks_like_the_kernel(held) {
        return false;
    }

    if our_threads().contains(&held) {
        return true;
    }

    let at = unsafe { WHERE_A_PORT_SAYS_ITS_THREAD };
    if at != 0 {
        return ours_is_held_at(held, at);
    }

    for word in 1..HOW_FAR_INTO_A_PORT {
        if ours_is_held_at(held, word * 8) {
            unsafe { WHERE_A_PORT_SAYS_ITS_THREAD = word * 8 };
            return true;
        }
    }

    false
}

fn ours_is_held_at(port: u64, at: usize) -> bool {
    let held = unsafe { ((port as usize + at) as *const u64).read_volatile() };
    let held = unsafe { crate::pac::ptrauth_strip_pointer(held as *const u8) } as u64;

    looks_like_the_kernel(held) && our_threads().contains(&held)
}

fn looks_like_the_kernel(at: u64) -> bool {
    at >= WHERE_THE_KERNEL_BEGINS && (at & 7) == 0
}

pub fn a_thread_of_ours(thread: *mut c_void) {
    let thread = thread as u64;
    if thread == 0 || our_threads().contains(&thread) {
        return;
    }

    if let Some(free) = our_threads().iter_mut().find(|kept| **kept == 0) {
        *free = thread;
    }
}

pub fn no_longer_a_thread_of_ours(thread: *mut c_void) {
    for kept in our_threads().iter_mut().filter(|kept| **kept == thread as u64) {
        *kept = 0;
    }
}

fn our_threads() -> &'static mut [u64; MOST_OF_OURS] {
    unsafe { (&raw mut OUR_THREADS).as_mut().unwrap() }
}

fn asked_by_one_of_ours() -> bool {
    let Some(this_thread) = (unsafe { _current_thread }) else {
        return false;
    };

    our_threads().contains(&(unsafe { this_thread() } as u64))
}

pub fn one_of_ours(number: u64) {
    if number == 0 || ours().contains(&number) {
        return;
    }

    if let Some(free) = ours().iter_mut().find(|kept| **kept == 0) {
        *free = number;
    }
}

pub fn forget_the_threads_of(arena: u64) {
    let said = unsafe { ((arena + crate::xnu_relay::OUR_THREADS) as *const u64) };
    for step in 0..MOST_OF_OURS_IN_ONE {
        let number = unsafe { said.add(step).read_volatile() };
        for kept in ours().iter_mut().filter(|kept| **kept == number && number != 0) {
            *kept = 0;
        }
    }
}

pub fn take_note_of_what_a_copy_says(arena: u64) {
    let said = unsafe { ((arena + crate::xnu_relay::OUR_THREADS) as *const u64) };
    for step in 0..MOST_OF_OURS_IN_ONE {
        one_of_ours(unsafe { said.add(step).read_volatile() });
    }

}

unsafe extern "C" fn say_what_it_has(process: *mut c_void, asked: *mut c_void, answer: *mut i32)
    -> c_int
{
    let went = match unsafe { THE_ANSWER } {
        Some(ask_it) => unsafe { ask_it(process, asked, answer) },
        None => 0,
    };

    if asked.is_null() || answer.is_null() {
        return went;
    }


    let asked = unsafe { &*(asked as *const Asked) };
    if went != 0 || asked.what != LISTING_ITS_THREADS {
        return went;
    }
    let only_counting = asked_by_one_of_ours();

    let said = unsafe { *answer } as usize;
    let how_many = said / core::mem::size_of::<u64>();
    if how_many == 0 || how_many > MOST_THREADS_IN_ONE || asked.into == 0 || only_counting {
        return went;
    }

    let (Some(fetch), Some(put_back)) = (unsafe { _copyin }, unsafe { _copyout }) else {
        return went;
    };

    let mut numbers = [0u64; MOST_THREADS_IN_ONE];
    let room = (how_many * core::mem::size_of::<u64>()) as u64;
    if unsafe { fetch(asked.into, numbers.as_mut_ptr() as *mut c_void, room) } != 0 {
        return went;
    }

    let mut kept = 0;
    for step in 0..how_many {
        if ours().contains(&numbers[step]) {
            continue;
        }
        numbers[kept] = numbers[step];
        kept += 1;
    }
    if kept == how_many {
        return went;
    }

    let left = (kept * core::mem::size_of::<u64>()) as u64;
    if unsafe { put_back(numbers.as_ptr() as *const c_void, asked.into, left) } != 0 {
        return went;
    }
    unsafe { *answer = left as i32 };

    went
}

#[repr(C)]
struct Asked {
    which: u64,
    id: u64,
    what: u64,
    about: u64,
    into: u64,
    room: u64,
}

fn ours() -> &'static mut [u64; MOST_OF_OURS] {
    unsafe { (&raw mut OURS).as_mut().unwrap() }
}

static mut HIDDEN: bool = false;
static mut HIDDEN_FROM_THE_LIST: bool = false;
static mut THE_LIST: Option<unsafe extern "C" fn(*mut c_void, *mut *mut u64, *mut u32) -> c_int> =
    None;
static mut WHERE_THE_LIST_IS_ASKED: *mut c_void = core::ptr::null_mut();
static mut WHERE_A_PORT_SAYS_ITS_THREAD: usize = 0;
static mut OUR_THREADS: [u64; MOST_OF_OURS] = [0; MOST_OF_OURS];
static mut THE_ANSWER: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, *mut i32) -> c_int> =
    None;
static mut WHERE_IT_IS_ASKED: *mut c_void = core::ptr::null_mut();
static mut OURS: [u64; MOST_OF_OURS] = [0; MOST_OF_OURS];

pub const MOST_OF_OURS_IN_ONE: usize = 8;
const MOST_OF_OURS: usize = 128;
const HOW_FAR_INTO_A_PORT: usize = 32;
const WHERE_THE_KERNEL_BEGINS: u64 = 0xffff_fe00_0000_0000;
const MOST_THREADS_IN_ONE: usize = 64;
const ASKING_ABOUT_A_PROCESS: usize = 336;
const AN_ENTRY: usize = 24;
const LISTING_ITS_THREADS: u64 = 6;

unsafe extern "C" {
    static _copyin: Option<unsafe extern "C" fn(u64, *mut c_void, u64) -> c_int>;
    static _copyout: Option<unsafe extern "C" fn(*const c_void, u64, u64) -> c_int>;
    static _current_thread: Option<unsafe extern "C" fn() -> *mut c_void>;
    static _task_threads:
        Option<unsafe extern "C" fn(*mut c_void, *mut *mut u64, *mut u32) -> c_int>;
}
