use core::ffi::{c_char, c_int};

use crate::bindings::{
    self, timespec, EIO, ELOOP, ENAMETOOLONG, ENOSYS, ENOTEMPTY, EOPNOTSUPP,
};

use super::user::{self, syscall, OPENAT, WORKING_DIRECTORY};

pub fn open(path: *const c_char, flags: c_int, mode: c_int) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::open(path, flags, mode);
    }
    answer(syscall(OPENAT, WORKING_DIRECTORY, path as usize, linux_flags(flags as u32), mode as usize, 0, 0))
}

pub fn close(fd: c_int) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::close(fd);
    }
    answer(user::close(fd))
}

pub fn read(fd: c_int, buffer: *mut u8, count: usize) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::read(fd, buffer, count);
    }
    answer(user::read(fd, buffer, count))
}

pub fn write(fd: c_int, buffer: *const u8, count: usize) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::write(fd, buffer, count);
    }
    answer(user::write(fd, buffer, count))
}

pub fn lseek(fd: c_int, offset: i64, whence: c_int) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::lseek(fd, offset, whence);
    }
    seek(fd, offset, whence)
}

pub fn ftruncate(fd: c_int, length: i64) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::ftruncate(fd, length);
    }
    truncate(fd, length)
}

pub fn fstat(fd: c_int, into: *mut bindings::stat) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::fstat(fd, into);
    }
    describe(fd as usize, c"".as_ptr(), AT_EMPTY_PATH, into)
}

pub fn stat(path: *const c_char, into: *mut bindings::stat) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::stat(path, into);
    }
    describe(WORKING_DIRECTORY, path, 0, into)
}

pub fn unlink(path: *const c_char) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::unlink(path);
    }
    answer(syscall(UNLINKAT, WORKING_DIRECTORY, path as usize, 0, 0, 0, 0))
}

pub fn rmdir(path: *const c_char) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::rmdir(path);
    }
    answer(syscall(UNLINKAT, WORKING_DIRECTORY, path as usize, AT_REMOVEDIR, 0, 0, 0))
}

pub fn rename(old: *const c_char, new: *const c_char) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::rename(old, new);
    }
    answer(syscall(RENAMEAT2, WORKING_DIRECTORY, old as usize, WORKING_DIRECTORY, new as usize, 0, 0))
}

pub fn access(path: *const c_char, mode: c_int) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::access(path, mode);
    }
    answer(syscall(FACCESSAT, WORKING_DIRECTORY, path as usize, mode as usize, 0, 0, 0))
}

pub fn chmod(path: *const c_char, mode: c_int) -> Result<i64, c_int> {
    if !crate::kernel::in_copy() {
        return crate::nofiles::chmod(path, mode);
    }
    answer(syscall(FCHMODAT, WORKING_DIRECTORY, path as usize, mode as usize, 0, 0, 0))
}

fn linux_flags(flags: u32) -> usize {
    let mut linux = (flags & ACCESS_MODE) as usize | O_LARGEFILE;
    for (ours, theirs) in FLAGS {
        if flags & ours != 0 {
            linux |= theirs;
        }
    }
    linux
}

#[cfg(target_pointer_width = "64")]
fn seek(fd: c_int, offset: i64, whence: c_int) -> Result<i64, c_int> {
    answer(syscall(LSEEK, fd as usize, offset as usize, whence as usize, 0, 0, 0))
}

#[cfg(target_pointer_width = "32")]
fn seek(fd: c_int, offset: i64, whence: c_int) -> Result<i64, c_int> {
    let mut position = 0i64;
    answer(syscall(LLSEEK, fd as usize, (offset >> 32) as usize, offset as usize,
        &mut position as *mut i64 as usize, whence as usize, 0))?;
    Ok(position)
}

#[cfg(target_pointer_width = "64")]
fn truncate(fd: c_int, length: i64) -> Result<i64, c_int> {
    answer(syscall(FTRUNCATE, fd as usize, length as usize, 0, 0, 0, 0))
}

#[cfg(target_arch = "x86")]
fn truncate(fd: c_int, length: i64) -> Result<i64, c_int> {
    answer(syscall(FTRUNCATE64, fd as usize, length as usize, (length >> 32) as usize, 0, 0, 0))
}

#[cfg(target_arch = "arm")]
fn truncate(fd: c_int, length: i64) -> Result<i64, c_int> {
    answer(syscall(FTRUNCATE64, fd as usize, 0, length as usize, (length >> 32) as usize, 0, 0))
}

fn describe(directory: usize, path: *const c_char, flags: usize, into: *mut bindings::stat) -> Result<i64, c_int> {
    let mut described = Statx::default();
    answer(syscall(STATX, directory, path as usize, flags, STATX_BASIC_STATS,
        &mut described as *mut Statx as usize, 0))?;
    unsafe { into.write(described.as_stat()) };
    Ok(0)
}

fn answer(result: isize) -> Result<i64, c_int> {
    if result >= 0 {
        return Ok(result as i64);
    }
    Err(our_errno(-result))
}

fn our_errno(linux: isize) -> c_int {
    let ours = match linux {
        1..=34 => return linux as c_int,
        36 => ENAMETOOLONG,
        38 => ENOSYS,
        39 => ENOTEMPTY,
        40 => ELOOP,
        95 => EOPNOTSUPP,
        _ => EIO,
    };
    ours as c_int
}

#[repr(C)]
#[derive(Default)]
struct Statx {
    mask: u32,
    blksize: u32,
    attributes: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    spare0: u16,
    ino: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    atime: StatxTimestamp,
    btime: StatxTimestamp,
    ctime: StatxTimestamp,
    mtime: StatxTimestamp,
    rdev_major: u32,
    rdev_minor: u32,
    dev_major: u32,
    dev_minor: u32,
    spare: [u64; 16],
}

#[repr(C)]
#[derive(Default)]
struct StatxTimestamp {
    sec: i64,
    nsec: u32,
    reserved: i32,
}

impl Statx {
    fn as_stat(&self) -> bindings::stat {
        bindings::stat {
            st_dev: device(self.dev_major, self.dev_minor) as _,
            st_ino: self.ino as _,
            st_mode: self.mode as _,
            st_nlink: self.nlink as _,
            st_uid: self.uid as _,
            st_gid: self.gid as _,
            st_rdev: device(self.rdev_major, self.rdev_minor) as _,
            st_size: self.size as _,
            st_blksize: self.blksize as _,
            st_blocks: self.blocks as _,
            st_atim: self.atime.as_timespec(),
            st_mtim: self.mtime.as_timespec(),
            st_ctim: self.ctime.as_timespec(),
        }
    }
}

impl StatxTimestamp {
    fn as_timespec(&self) -> timespec {
        timespec { tv_sec: self.sec as _, tv_nsec: self.nsec as _ }
    }
}

fn device(major: u32, minor: u32) -> u64 {
    ((major as u64) << 8) | minor as u64
}

const FLAGS: [(u32, usize); 8] = [
    (bindings::O_CREAT, 0o100),
    (bindings::O_EXCL, 0o200),
    (bindings::O_TRUNC, 0o1000),
    (bindings::O_APPEND, 0o2000),
    (bindings::O_NONBLOCK, 0o4000),
    (bindings::O_CLOEXEC, 0o2000000),
    (bindings::O_NOFOLLOW, O_NOFOLLOW),
    (bindings::O_DIRECTORY, O_DIRECTORY),
];

const ACCESS_MODE: u32 = bindings::O_RDONLY | bindings::O_WRONLY | bindings::O_RDWR;
const AT_EMPTY_PATH: usize = 0x1000;
const AT_REMOVEDIR: usize = 0x200;
const STATX_BASIC_STATS: usize = 0x7ff;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const O_NOFOLLOW: usize = 0o400000;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
const O_NOFOLLOW: usize = 0o100000;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const O_DIRECTORY: usize = 0o200000;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
const O_DIRECTORY: usize = 0o40000;
#[cfg(target_arch = "x86")]
const O_LARGEFILE: usize = 0o100000;
#[cfg(target_arch = "arm")]
const O_LARGEFILE: usize = 0o400000;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const O_LARGEFILE: usize = 0;

#[cfg(target_arch = "x86_64")]
const LSEEK: usize = 8;
#[cfg(target_arch = "aarch64")]
const LSEEK: usize = 62;
#[cfg(any(target_arch = "x86", target_arch = "arm"))]
const LLSEEK: usize = 140;

#[cfg(target_arch = "x86_64")]
const FTRUNCATE: usize = 77;
#[cfg(target_arch = "aarch64")]
const FTRUNCATE: usize = 46;
#[cfg(any(target_arch = "x86", target_arch = "arm"))]
const FTRUNCATE64: usize = 194;

#[cfg(target_arch = "x86_64")]
const STATX: usize = 332;
#[cfg(target_arch = "x86")]
const STATX: usize = 383;
#[cfg(target_arch = "aarch64")]
const STATX: usize = 291;
#[cfg(target_arch = "arm")]
const STATX: usize = 397;

#[cfg(target_arch = "x86_64")]
const UNLINKAT: usize = 263;
#[cfg(target_arch = "x86")]
const UNLINKAT: usize = 301;
#[cfg(target_arch = "aarch64")]
const UNLINKAT: usize = 35;
#[cfg(target_arch = "arm")]
const UNLINKAT: usize = 328;

#[cfg(target_arch = "x86_64")]
const RENAMEAT2: usize = 316;
#[cfg(target_arch = "x86")]
const RENAMEAT2: usize = 353;
#[cfg(target_arch = "aarch64")]
const RENAMEAT2: usize = 276;
#[cfg(target_arch = "arm")]
const RENAMEAT2: usize = 382;

#[cfg(target_arch = "x86_64")]
const FACCESSAT: usize = 269;
#[cfg(target_arch = "x86")]
const FACCESSAT: usize = 307;
#[cfg(target_arch = "aarch64")]
const FACCESSAT: usize = 48;
#[cfg(target_arch = "arm")]
const FACCESSAT: usize = 334;

#[cfg(target_arch = "x86_64")]
const FCHMODAT: usize = 268;
#[cfg(target_arch = "x86")]
const FCHMODAT: usize = 306;
#[cfg(target_arch = "aarch64")]
const FCHMODAT: usize = 53;
#[cfg(target_arch = "arm")]
const FCHMODAT: usize = 333;
