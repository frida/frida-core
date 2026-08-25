
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::xnu_processes::{ProcessInfo, enumerate_processes};

pub fn gate_spawns(on: bool) {
    unsafe { GATING = on };
}

pub fn look_for_new_processes() {
    if unsafe { GATING } {
        take_over_the_word_to_go();
    }
    if unsafe { HELD_TASKS_USED } == 0 {
        return;
    }

    let now = crate::kernel::monotonic_micros();
    if now - unsafe { LAST_LOOKED } < BETWEEN_LOOKS {
        return;
    }
    unsafe { LAST_LOOKED = now };

    let mut appeared = Vec::new();
    each_process(&mut |process| {
        if !unsafe { seen() }.contains(&process.id) {
            unsafe { seen() }.push(process.id);
            appeared.push((process.id, name_of(process)));
        }
    });

    let Some(task_of) = (unsafe { _proc_task }) else {
        return;
    };

    for (id, name) in appeared {
        let Some(theirs) = crate::xnu_injection::process_with_id(id) else {
            continue;
        };
        let task = unsafe { task_of(theirs.handle) };
        unsafe { crate::xnu_injection::release_process(theirs.handle) };

        for step in 0..unsafe { HELD_TASKS_USED } {
            if unsafe { HELD_TASKS[step] }.0 != task {
                continue;
            }
            let flags = unsafe { HELD_TASKS[step] }.1;
            unsafe { HELD_TASKS[step].0 = core::ptr::null_mut() };
            unsafe { held() }.push(Held { id, name, task, flags, told_of: false });
            break;
        }
    }

    for step in 0..unsafe { HELD_TASKS_USED } {
        let (task, flags) = unsafe { HELD_TASKS[step] };
        if task.is_null() || now - unsafe { HELD_SINCE[step] } < LONG_ENOUGH_TO_BE_NAMED {
            continue;
        }
        unsafe { HELD_TASKS[step].0 = core::ptr::null_mut() };
        say_the_word(task, flags);
    }
}

pub fn a_spawn_is_held() -> bool {
    unsafe { held() }.iter().any(|held| !held.told_of)
}

pub fn tell_of_held_spawns(say: &mut dyn FnMut(u32, &[u8])) {
    for held in unsafe { held() }.iter_mut() {
        if held.told_of {
            continue;
        }
        held.told_of = true;
        say(held.id, &held.name);
    }
}

pub fn resume_process(id: u32) -> bool {
    let waiting = {
        let held = unsafe { held() };
        let Some(at) = held.iter().position(|held| held.id == id) else {
            return false;
        };
        held.remove(at)
    };

    say_the_word(waiting.task, waiting.flags);

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
    if unsafe { GATING } && (flags & THE_LAST_WORD) != 0 {
        let used = unsafe { HELD_TASKS_USED };
        if used < HELD_TASKS_ROOM {
            unsafe {
                HELD_TASKS[used] = (task, flags);
                HELD_SINCE[used] = crate::kernel::monotonic_micros();
                HELD_TASKS_USED = used + 1;
            }
            return;
        }
    }

    say_the_word(task, flags);
}

struct Held {
    id: u32,
    name: Vec<u8>,
    task: *mut c_void,
    flags: u32,
    told_of: bool,
}

fn each_process(found: &mut dyn FnMut(&ProcessInfo)) {
    enumerate_processes(&mut |process| found(&process));
}

fn name_of(process: &ProcessInfo) -> Vec<u8> {
    let mut said = Vec::new();
    for step in 0..LONGEST_NAME {
        let byte = unsafe { process.name.add(step).read() };
        if byte == 0 {
            break;
        }
        said.push(byte);
    }

    said
}

unsafe fn seen() -> &'static mut Vec<u32> {
    unsafe { (&raw mut SEEN).as_mut().unwrap() }
}

unsafe fn held() -> &'static mut Vec<Held> {
    unsafe { (&raw mut HELD).as_mut().unwrap() }
}

static mut GATING: bool = false;
static mut TAKEN_OVER: bool = false;
static mut LAST_LOOKED: i64 = 0;
static mut SEEN: Vec<u32> = Vec::new();
static mut HELD: Vec<Held> = Vec::new();
static mut THE_WORD_TO_GO: Option<unsafe extern "C" fn(*mut c_void, u32)> = None;

static mut HELD_TASKS: [(*mut c_void, u32); HELD_TASKS_ROOM] =
    [(core::ptr::null_mut(), 0); HELD_TASKS_ROOM];
static mut HELD_SINCE: [i64; HELD_TASKS_ROOM] = [0; HELD_TASKS_ROOM];
static mut HELD_TASKS_USED: usize = 0;

const HELD_TASKS_ROOM: usize = 32;
const THE_LAST_WORD: u32 = 0x2;
const BETWEEN_LOOKS: i64 = 20_000;
const LONG_ENOUGH_TO_BE_NAMED: i64 = 500_000;
const LONGEST_NAME: usize = 64;

unsafe extern "C" {
    static _task_clear_return_wait: Option<unsafe extern "C" fn(*mut c_void, u32)>;
    static _proc_task: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>;
}
