use alloc::ffi::CString;
use alloc::format;
use alloc::vec::Vec;

use crate::kernel::ThreadInfo;

use super::facade::{home_process_id, in_copy};
use super::processes::running_task_ids;
use super::user::names_in;

pub fn enumerate_threads(found: &mut dyn FnMut(ThreadInfo), with_registers: bool) {
    let copy = in_copy();
    let ids = if copy { running_threads() } else { running_task_ids() };
    for id in ids {
        if copy && super::user::thread_is_ours(id) {
            continue;
        }
        let cpu_state = if !with_registers {
            None
        } else if copy {
            super::user::ask_the_kernel_half_for_registers(id)
        } else {
            super::injection::capture_registers(id)
        };
        found(ThreadInfo { id, cpu_state });
    }
}

fn running_threads() -> Vec<u32> {
    let where_they_are = CString::new(format!("/proc/{}/task", home_process_id())).unwrap();

    names_in(&where_they_are)
        .iter()
        .filter_map(|name| name.parse().ok())
        .collect()
}
