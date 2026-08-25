
use alloc::vec::Vec;
use core::ffi::{c_int, c_void};

use crate::xnu_processes::{ProcessInfo, enumerate_processes};

pub fn gate_spawns(on: bool) {
    unsafe { GATING = on };

    if on {
        unsafe { seen() }.clear();
        each_process(&mut |process| unsafe { seen() }.push(process.id));
    }
}

pub fn look_for_new_processes() {
    if !unsafe { GATING } {
        return;
    }

    let now = crate::kernel::monotonic_micros();
    if now - unsafe { LAST_LOOKED } < BETWEEN_LOOKS {
        return;
    }
    unsafe { LAST_LOOKED = now };

    let mut appeared = Vec::new();
    each_process(&mut |process| {
        let seen = unsafe { seen() };
        if seen.contains(&process.id) {
            return;
        }
        seen.push(process.id);
        appeared.push((process.id, name_of(&process)));
    });

    for (id, name) in appeared {
        if hold(id) {
            unsafe { held() }.push((id, name));
        }
    }
}

pub fn resume_process(id: u32) -> bool {
    let held = unsafe { held() };
    let was_held = held.iter().any(|(waiting, _)| *waiting == id);
    held.retain(|(waiting, _)| *waiting != id);

    let Some(release) = (unsafe { _task_resume }) else {
        return false;
    };
    let Some(process) = crate::xnu_injection::process_with_id(id) else {
        return was_held;
    };

    let told = unsafe { release(process.task) };
    unsafe { crate::xnu_injection::release_process(process.handle) };

    told == KERN_SUCCESS
}

pub fn a_spawn_is_held() -> bool {
    !unsafe { held() }.is_empty()
}

pub fn tell_of_held_spawns(say: &mut dyn FnMut(u32, &[u8])) {
    for (id, name) in core::mem::take(unsafe { held() }) {
        say(id, &name);
    }
}

fn hold(id: u32) -> bool {
    let Some(stop) = (unsafe { _task_suspend }) else {
        return false;
    };
    let Some(process) = crate::xnu_injection::process_with_id(id) else {
        return false;
    };

    let told = unsafe { stop(process.task) };
    unsafe { crate::xnu_injection::release_process(process.handle) };

    told == KERN_SUCCESS
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

unsafe fn held() -> &'static mut Vec<(u32, Vec<u8>)> {
    unsafe { (&raw mut HELD).as_mut().unwrap() }
}

static mut GATING: bool = false;
static mut LAST_LOOKED: i64 = 0;
static mut SEEN: Vec<u32> = Vec::new();
static mut HELD: Vec<(u32, Vec<u8>)> = Vec::new();

const BETWEEN_LOOKS: i64 = 20_000;
const LONGEST_NAME: usize = 64;
const KERN_SUCCESS: c_int = 0;

unsafe extern "C" {
    static _task_suspend: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
    static _task_resume: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
}
