
use core::ffi::{c_int, c_void};

pub fn inject_into_process(id: u32) -> u32 {
    let Some(process) = process_with_id(id) else {
        return 0;
    };

    let placed = give_the_copy_a_home(process.map);
    unsafe { release_process(process.handle) };

    let Some(home) = placed else {
        return 0;
    };

    if !start(process.task, home) {
        return 0;
    }

    id
}

struct Process {
    handle: *mut c_void,
    task: *mut c_void,
    map: *mut c_void,
}

struct Home {
    code: u64,
    stack: u64,
}

fn process_with_id(id: u32) -> Option<Process> {
    let find = unsafe { _proc_find }?;
    let task_of = unsafe { _proc_task }?;
    let map_of = unsafe { _get_task_map }?;

    let handle = unsafe { find(id as c_int) };
    if handle.is_null() {
        return None;
    }

    let task = unsafe { task_of(handle) };
    Some(Process { handle, task, map: unsafe { map_of(task) } })
}

fn give_the_copy_a_home(map: *mut c_void) -> Option<Home> {
    let code = put(map, bootstrap())?;
    let stack = take_memory(map, STACK)?;

    let protect = unsafe { _mach_vm_protect }?;
    if unsafe { protect(map, code, PAGE, 0, READ | EXECUTE) } != KERN_SUCCESS {
        return None;
    }

    Some(Home { code, stack })
}

fn take_memory(map: *mut c_void, size: u64) -> Option<u64> {
    let allocate = unsafe { _mach_vm_allocate }?;

    let mut address: u64 = 0;
    if unsafe { allocate(map, &mut address as *mut u64, size, ANYWHERE) } != KERN_SUCCESS {
        return None;
    }

    Some(address)
}

fn put(map: *mut c_void, bytes: &[u8]) -> Option<u64> {
    let copy_in = unsafe { _vm_map_copyin }?;
    let copy_out = unsafe { _vm_map_copyout }?;
    let ours = ourselves()?;

    let held = crate::kernel::alloc(PAGE as usize);
    unsafe {
        core::ptr::write_bytes(held, 0, PAGE as usize);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), held, bytes.len());
    }

    let mut copy: *mut c_void = core::ptr::null_mut();
    let taken = unsafe { copy_in(ours, held as u64, PAGE, 0, &mut copy as *mut *mut c_void) };
    crate::kernel::free(held, PAGE as usize);
    if taken != KERN_SUCCESS {
        return None;
    }

    let mut landed: u64 = 0;
    if unsafe { copy_out(map, &mut landed as *mut u64, copy) } != KERN_SUCCESS {
        return None;
    }

    Some(landed)
}

fn ourselves() -> Option<*mut c_void> {
    let map_of = unsafe { _get_task_map }?;
    let task_of = unsafe { _current_task }?;

    Some(unsafe { map_of(task_of()) })
}

fn bootstrap() -> &'static [u8] {
    &[0x00, 0x00, 0x00, 0x14]
}

fn start(task: *mut c_void, home: Home) -> bool {
    let create = unsafe { _thread_create };
    let set_state = unsafe { _thread_set_state };
    let resume = unsafe { _thread_resume };
    let (Some(create), Some(set_state), Some(resume)) = (create, set_state, resume) else {
        return false;
    };

    let mut thread: *mut c_void = core::ptr::null_mut();
    if unsafe { create(task, &mut thread as *mut *mut c_void) } != KERN_SUCCESS {
        return false;
    }

    let mut state = [0u32; STATE_WORDS];
    let places = state.as_mut_ptr() as *mut u8;
    unsafe {
        (places.add(STACK_POINTER) as *mut u64).write(home.stack + STACK - 0x100);
        (places.add(PROGRAM_COUNTER) as *mut u64).write(home.code);
        (places.add(FLAGS) as *mut u32).write(PLAIN_ADDRESSES);
    }

    if unsafe { set_state(thread, ARM_THREAD_STATE64, state.as_ptr(), STATE_WORDS as c_int) }
        != KERN_SUCCESS
    {
        return false;
    }

    unsafe { resume(thread) == KERN_SUCCESS }
}

const PAGE: u64 = 0x4000;
const STACK: u64 = 0x4000;
const KERN_SUCCESS: c_int = 0;
const ANYWHERE: c_int = 1;
const READ: c_int = 1;
const EXECUTE: c_int = 4;
const ARM_THREAD_STATE64: c_int = 6;
const STATE_WORDS: usize = 68;
const STACK_POINTER: usize = 29 * 8 + 16;
const PROGRAM_COUNTER: usize = 29 * 8 + 24;
const FLAGS: usize = 29 * 8 + 36;
const PLAIN_ADDRESSES: u32 = 1;

unsafe fn release_process(handle: *mut c_void) {
    if let Some(release) = unsafe { _proc_rele } {
        unsafe { release(handle) };
    }
}

unsafe extern "C" {
    static _proc_find: Option<unsafe extern "C" fn(c_int) -> *mut c_void>;
    static _proc_rele: Option<unsafe extern "C" fn(*mut c_void)>;
    static _proc_task: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>;
    static _current_task: Option<unsafe extern "C" fn() -> *mut c_void>;
    static _get_task_map: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>;
    static _mach_vm_allocate: Option<unsafe extern "C" fn(*mut c_void, *mut u64, u64, c_int) -> c_int>;
    static _mach_vm_protect: Option<unsafe extern "C" fn(*mut c_void, u64, u64, c_int, c_int) -> c_int>;
    static _vm_map_copyin: Option<unsafe extern "C" fn(*mut c_void, u64, u64, c_int, *mut *mut c_void) -> c_int>;
    static _vm_map_copyout: Option<unsafe extern "C" fn(*mut c_void, *mut u64, *mut c_void) -> c_int>;
    static _thread_create: Option<unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> c_int>;
    static _thread_set_state: Option<unsafe extern "C" fn(*mut c_void, c_int, *const u32, c_int) -> c_int>;
    static _thread_resume: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
}
