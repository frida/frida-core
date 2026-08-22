use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_void};

pub struct ProcessInfo {
    pub id: u32,
    pub name: *const u8,
    pub path: *const u8,
    pub command_line: *const u8,
}

// The kernel keeps its own list and hands out what is in it through calls of its own, thus
// nothing here needs to know how a proc is laid out.
pub fn enumerate_processes(found: &mut dyn FnMut(ProcessInfo)) {
    let mut listed: Vec<(u32, [u8; NAME_SIZE])> = Vec::new();

    unsafe {
        _proc_iterate(
            ALL_PROCESSES,
            note_a_process,
            &mut listed as *mut Vec<(u32, [u8; NAME_SIZE])> as *mut c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };

    for (id, name) in &listed {
        found(ProcessInfo {
            id: *id,
            name: name.as_ptr(),
            path: name.as_ptr(),
            command_line: core::ptr::null(),
        });
    }
}

pub fn describe_process(process: &ProcessInfo) -> *const u8 {
    process.name
}

pub fn enumerate_icons(_path: *const u8, _found: &mut dyn FnMut(&[u8])) {}

unsafe extern "C" fn note_a_process(process: *mut c_void, listed: *mut c_void) -> c_int {
    let listed = listed as *mut Vec<(u32, [u8; NAME_SIZE])>;

    let mut name = [0u8; NAME_SIZE];
    unsafe {
        let said = _proc_best_name(process);
        for (at, letter) in name.iter_mut().enumerate().take(NAME_SIZE - 1) {
            let byte = said.add(at).read() as u8;
            if byte == 0 {
                break;
            }
            *letter = byte;
        }

        (*listed).push((_proc_pid(process) as u32, name));
    }

    KEEP_GOING
}

const NAME_SIZE: usize = 33;
const ALL_PROCESSES: c_int = 1;
const KEEP_GOING: c_int = 0;

unsafe extern "C" {
    static _proc_iterate: unsafe extern "C" fn(
        c_int,
        unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int,
        *mut c_void,
        *mut c_void,
        *mut c_void,
    );
    static _proc_pid: unsafe extern "C" fn(*mut c_void) -> c_int;
    static _proc_best_name: unsafe extern "C" fn(*mut c_void) -> *const c_char;
}
