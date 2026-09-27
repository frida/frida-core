use alloc::ffi::CString;
use alloc::format;
use alloc::vec::Vec;

use crate::bindings::{
    GumThreadState, GumThreadState_GUM_THREAD_HALTED, GumThreadState_GUM_THREAD_RUNNING,
    GumThreadState_GUM_THREAD_STOPPED, GumThreadState_GUM_THREAD_UNINTERRUPTIBLE,
    GumThreadState_GUM_THREAD_WAITING,
};
use crate::kernel::ThreadInfo;

use super::facade::{home_process_id, in_copy};
use super::processes::running_task_ids;
use super::user::{contents_of, names_in};

pub fn enumerate_threads(found: &mut dyn FnMut(ThreadInfo), with_registers: bool) {
    let copy = in_copy();
    let ids = if copy { running_threads() } else { running_task_ids() };
    for id in ids {
        if copy && super::user::thread_is_ours(id) {
            continue;
        }
        let (state, cpu_state) = if !with_registers {
            (None, None)
        } else if copy {
            (state_from_proc(id), super::user::ask_the_kernel_half_for_registers(id))
        } else {
            (super::injection::thread_state(id), super::injection::capture_registers(id))
        };
        found(ThreadInfo { id, state, cpu_state });
    }
}

fn state_from_proc(id: u32) -> Option<GumThreadState> {
    let path = CString::new(format!("/proc/{}/task/{}/stat", home_process_id(), id)).ok()?;
    let stat = contents_of(&path);
    let last_paren = stat.iter().rposition(|&byte| byte == b')')?;
    let state_letter = *stat.get(last_paren + 2)?;
    Some(gum_thread_state(state_letter))
}

fn gum_thread_state(letter: u8) -> GumThreadState {
    match letter {
        b'R' => GumThreadState_GUM_THREAD_RUNNING,
        b'S' => GumThreadState_GUM_THREAD_WAITING,
        b'D' => GumThreadState_GUM_THREAD_UNINTERRUPTIBLE,
        b'T' | b't' => GumThreadState_GUM_THREAD_STOPPED,
        _ => GumThreadState_GUM_THREAD_HALTED,
    }
}

fn running_threads() -> Vec<u32> {
    let where_they_are = CString::new(format!("/proc/{}/task", home_process_id())).unwrap();

    names_in(&where_they_are)
        .iter()
        .filter_map(|name| name.parse().ok())
        .collect()
}
