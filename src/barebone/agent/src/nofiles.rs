use core::ffi::{c_char, c_int};

use crate::bindings::{self, ENOSYS};

pub fn open(_path: *const c_char, _flags: c_int, _mode: c_int) -> Result<i64, c_int> {
    Err(ENOSYS as c_int)
}

pub fn close(_fd: c_int) -> Result<i64, c_int> {
    Ok(0)
}

pub fn read(_fd: c_int, _buffer: *mut u8, _count: usize) -> Result<i64, c_int> {
    Ok(0)
}

pub fn write(_fd: c_int, _buffer: *const u8, count: usize) -> Result<i64, c_int> {
    Ok(count as i64)
}

pub fn lseek(_fd: c_int, _offset: i64, _whence: c_int) -> Result<i64, c_int> {
    Ok(0)
}

pub fn ftruncate(_fd: c_int, _length: i64) -> Result<i64, c_int> {
    Err(ENOSYS as c_int)
}

pub fn fstat(_fd: c_int, _into: *mut bindings::stat) -> Result<i64, c_int> {
    Ok(0)
}

pub fn stat(_path: *const c_char, _into: *mut bindings::stat) -> Result<i64, c_int> {
    Err(ENOSYS as c_int)
}

pub fn unlink(_path: *const c_char) -> Result<i64, c_int> {
    Err(ENOSYS as c_int)
}

pub fn rmdir(_path: *const c_char) -> Result<i64, c_int> {
    Err(ENOSYS as c_int)
}

pub fn rename(_old: *const c_char, _new: *const c_char) -> Result<i64, c_int> {
    Err(ENOSYS as c_int)
}

pub fn access(_path: *const c_char, _mode: c_int) -> Result<i64, c_int> {
    Err(ENOSYS as c_int)
}

pub fn chmod(_path: *const c_char, _mode: c_int) -> Result<i64, c_int> {
    Err(ENOSYS as c_int)
}
