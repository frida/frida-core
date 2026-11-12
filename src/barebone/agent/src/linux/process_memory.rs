use core::ffi::{c_int, c_void};

use super::processes::HeldTask;

pub fn allocate(id: u32, size: usize, protection: usize) -> usize {
    let Some(mm) = BorrowedMemory::of(id) else {
        return 0;
    };

    let address = unsafe { _vm_mmap(core::ptr::null_mut(), 0, size, protection, MAP_PRIVATE | MAP_ANONYMOUS, 0) };
    drop(mm);

    if address >= FIRST_ERROR_ADDRESS { 0 } else { address }
}

pub fn release(id: u32, address: usize, size: usize) -> c_int {
    let Some(mm) = BorrowedMemory::of(id) else {
        return -ESRCH;
    };

    let result = unsafe { _vm_munmap(address, size) };
    drop(mm);

    result
}

pub fn write(id: u32, address: usize, data: &[u8]) -> usize {
    transfer(id, address, data.as_ptr() as *mut c_void, data.len(), FOLL_WRITE)
}

pub fn read(id: u32, address: usize, buffer: &mut [u8]) -> usize {
    transfer(id, address, buffer.as_mut_ptr() as *mut c_void, buffer.len(), 0)
}

pub fn read_own(address: usize, buffer: &mut [u8]) -> bool {
    let len = buffer.len();
    transfer_with(super::native::current_task() as usize, address, buffer.as_mut_ptr() as *mut c_void,
        len, 0) == len
}

pub fn write_own(address: usize, data: &[u8]) -> bool {
    transfer_with(super::native::current_task() as usize, address, data.as_ptr() as *mut c_void,
        data.len(), FOLL_WRITE) == data.len()
}

fn transfer(id: u32, address: usize, buffer: *mut c_void, size: usize, flags: u32) -> usize {
    let Some(task) = HeldTask::with_id(id) else {
        return 0;
    };

    transfer_with(task.address(), address, buffer, size, flags)
}

fn transfer_with(task: usize, address: usize, buffer: *mut c_void, size: usize, flags: u32) -> usize {
    let transferred = unsafe { _access_process_vm(task as *mut c_void, address, buffer, size as c_int, flags) };

    transferred.max(0) as usize
}

struct BorrowedMemory(*mut c_void);

impl BorrowedMemory {
    fn of(id: u32) -> Option<Self> {
        let task = HeldTask::with_id(id)?;
        let mm = unsafe { _get_task_mm(task.address() as *mut c_void) };
        if mm.is_null() {
            return None;
        }

        unsafe { _kthread_use_mm(mm) };

        Some(Self(mm))
    }
}

impl Drop for BorrowedMemory {
    fn drop(&mut self) {
        unsafe {
            _kthread_unuse_mm(self.0);
            _mmput(self.0);
        }
    }
}

const MAP_PRIVATE: usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;
const FOLL_WRITE: u32 = 0x01;
const FIRST_ERROR_ADDRESS: usize = usize::MAX - 4095;
const ESRCH: c_int = 3;

unsafe extern "C" {
    static _get_task_mm: unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    static _mmput: unsafe extern "C" fn(*mut c_void);
    static _kthread_use_mm: unsafe extern "C" fn(*mut c_void);
    static _kthread_unuse_mm: unsafe extern "C" fn(*mut c_void);
    static _vm_mmap: unsafe extern "C" fn(*mut c_void, usize, usize, usize, usize, usize) -> usize;
    static _vm_munmap: unsafe extern "C" fn(usize, usize) -> c_int;
    static _access_process_vm: unsafe extern "C" fn(*mut c_void, usize, *mut c_void, c_int, u32) -> c_int;
}
