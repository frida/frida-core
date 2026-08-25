
use core::ffi::{c_char, c_int, c_void};

pub fn gate_spawns(on: bool) {
    unsafe { GATING = on };
}

pub fn look_for_new_processes() {
    if unsafe { GATING } {
        take_over_the_word_to_go();
    }
}

pub fn a_spawn_is_held() -> bool {
    each_held().iter().any(|held| held.waiting && !held.told_of)
}

pub fn tell_of_held_spawns(say: &mut dyn FnMut(u32, &[u8])) {
    for held in each_held().iter_mut() {
        if !held.waiting || held.told_of {
            continue;
        }
        held.told_of = true;
        let length = held.name.iter().position(|byte| *byte == 0).unwrap_or(held.name.len());
        say(held.id, &held.name[..length]);
    }
}

pub fn resume_process(id: u32) -> bool {
    let Some(held) = each_held().iter_mut().find(|held| held.waiting && held.id == id) else {
        return false;
    };
    held.waiting = false;

    say_the_word(held.task, held.flags);

    true
}

fn say_the_word(task: *mut c_void, flags: u32) {
    if let Some(let_it_go) = unsafe { THE_WORD_TO_GO } {
        unsafe { let_it_go(task, flags) };
    }
}

fn take_over_the_word_to_go() {
    if unsafe { TAKEN_OVER } {
        return;
    }
    unsafe { TAKEN_OVER = true };

    let Some(word) = (unsafe { _task_clear_return_wait }) else {
        return;
    };

    unsafe {
        let interceptor = crate::bindings::gum_interceptor_obtain();
        crate::bindings::gum_interceptor_begin_transaction(interceptor);
        crate::bindings::gum_interceptor_replace(interceptor, word as *mut c_void,
            hold_or_let_run as *mut c_void, (&raw mut THE_WORD_TO_GO) as *mut *mut c_void,
            core::ptr::null_mut());
        crate::bindings::gum_interceptor_end_transaction(interceptor);
    }
}

unsafe extern "C" fn hold_or_let_run(task: *mut c_void, flags: u32) {
    if unsafe { GATING } && (flags & THE_LAST_WORD) != 0 && note_it(task, flags) {
        return;
    }

    say_the_word(task, flags);
}

fn note_it(task: *mut c_void, flags: u32) -> bool {
    let (Some(process_of), Some(number_of), Some(name_of)) =
        (unsafe { _get_bsdtask_info }, unsafe { _proc_pid }, unsafe { _proc_best_name })
    else {
        return false;
    };

    let process = unsafe { process_of(task) };
    if process.is_null() {
        return false;
    }

    let Some(held) = each_held().iter_mut().find(|held| !held.waiting) else {
        return false;
    };

    held.id = unsafe { number_of(process) } as u32;
    held.task = task;
    held.flags = flags;
    held.told_of = false;
    held.name = [0; NAME_ROOM];

    let said = unsafe { name_of(process) } as *const u8;
    for (at, letter) in held.name.iter_mut().enumerate().take(NAME_ROOM - 1) {
        let byte = unsafe { said.add(at).read() };
        if byte == 0 {
            break;
        }
        *letter = byte;
    }

    held.waiting = true;

    true
}

fn each_held() -> &'static mut [Held; HOW_MANY_AT_ONCE] {
    unsafe { (&raw mut HELD).as_mut().unwrap() }
}

#[derive(Clone, Copy)]
struct Held {
    id: u32,
    name: [u8; NAME_ROOM],
    task: *mut c_void,
    flags: u32,
    waiting: bool,
    told_of: bool,
}

static mut GATING: bool = false;
static mut TAKEN_OVER: bool = false;
static mut THE_WORD_TO_GO: Option<unsafe extern "C" fn(*mut c_void, u32)> = None;
static mut HELD: [Held; HOW_MANY_AT_ONCE] = [Held {
    id: 0,
    name: [0; NAME_ROOM],
    task: core::ptr::null_mut(),
    flags: 0,
    waiting: false,
    told_of: false,
}; HOW_MANY_AT_ONCE];

const HOW_MANY_AT_ONCE: usize = 64;
const NAME_ROOM: usize = 64;
const THE_LAST_WORD: u32 = 0x2;

unsafe extern "C" {
    static _task_clear_return_wait: Option<unsafe extern "C" fn(*mut c_void, u32)>;
    static _get_bsdtask_info: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>;
    static _proc_pid: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
    static _proc_best_name: Option<unsafe extern "C" fn(*mut c_void) -> *const c_char>;
}
