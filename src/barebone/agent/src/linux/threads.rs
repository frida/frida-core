use alloc::ffi::CString;
use alloc::format;
use alloc::vec::Vec;

use crate::kernel::ThreadInfo;

use super::facade::home_process_id;
use super::user::names_in;

pub fn enumerate_threads(found: &mut dyn FnMut(ThreadInfo)) {
    for id in running_threads() {
        found(ThreadInfo { id, cpu_state: None });
    }
}

fn running_threads() -> Vec<u32> {
    let where_they_are = CString::new(format!("/proc/{}/task", home_process_id())).unwrap();

    names_in(&where_they_are)
        .iter()
        .filter_map(|name| name.parse().ok())
        .collect()
}
