use alloc::vec::Vec;
use core::ffi::{c_int, c_void};

pub struct ProcessInfo {
    pub id: u32,
    pub name: *const u8,
    pub path: *const u8,
    pub command_line: *const u8,
}

// The kernel walks its own list, and where a process keeps its number and its name is what the
// host looked up before any of this started.
pub fn enumerate_processes(found: &mut dyn FnMut(ProcessInfo)) {
    let (Some(number), Some(name)) = (
        crate::kernel::noted("process.number"),
        crate::kernel::noted("process.name"),
    ) else {
        return;
    };
    unsafe {
        WHERE_THE_NUMBER_IS = number as usize;
        WHERE_THE_NAME_IS = name as usize;
    }

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
        let said = (process as *const u8).add(WHERE_THE_NAME_IS);
        for (at, letter) in name.iter_mut().enumerate().take(NAME_SIZE - 1) {
            let byte = said.add(at).read();
            if byte == 0 {
                break;
            }
            *letter = byte;
        }

        let number = (process as *const u8).add(WHERE_THE_NUMBER_IS) as *const u32;
        (*listed).push((number.read(), name));
    }

    KEEP_GOING
}

const NAME_SIZE: usize = 33;
const ALL_PROCESSES: c_int = 1;
const KEEP_GOING: c_int = 0;

static mut WHERE_THE_NUMBER_IS: usize = 0;
static mut WHERE_THE_NAME_IS: usize = 0;

unsafe extern "C" {
    static _proc_iterate: unsafe extern "C" fn(
        c_int,
        unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int,
        *mut c_void,
        *mut c_void,
        *mut c_void,
    );
}
