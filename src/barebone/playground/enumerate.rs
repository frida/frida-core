use core::arch::asm;
use core::{ffi::c_void, ffi::CStr, mem, ptr};
use core::mem::transmute;

#[repr(C)]
pub struct PidName {
    pid:  Pid,
    name: [CChar; NAME_LEN],
}

#[repr(C)]
struct BufHdr {
    out: *mut PidName,
    cap: usize,
    len: usize,
}

const NAME_LEN: usize = 32;

const PROC_ITERATE_ADDR: usize   = 0xfffffff0_07e7_758c;
const PROC_BEST_NAME_ADDR: usize = 0xfffffff0_07e7_3ea0;

const PROC_ALLPROCLIST: u32 = 1;

#[no_mangle]
pub unsafe extern "C" fn enumerate_processes(out: *mut PidName, bytes: usize) -> CInt {
    let proc_iterate: ProcIterateFn = transmute(PROC_ITERATE_ADDR);

    let cap = bytes / mem::size_of::<PidName>();
    let mut hdr = BufHdr { out, cap, len: 0 };

    proc_iterate(
        PROC_ALLPROCLIST,
        transmute(ptrauth_sign(collect_process as *const u8, 0xe4fe)),
        &mut hdr as *mut _ as *mut c_void,
        None, ptr::null_mut(),
    );

    hdr.len.try_into().unwrap()
}

unsafe extern "C" fn collect_process(p: ProcT, arg: *mut c_void) -> CInt {
    let hdr = &mut *(arg as *mut BufHdr);
    if hdr.len == hdr.cap {
        return 0;
    }

    let entry = &mut *hdr.out.add(hdr.len);
    entry.pid = (*p).p_pid;

    let proc_best_name: ProcBestNameFn = mem::transmute(PROC_BEST_NAME_ADDR);
    let name_ptr = proc_best_name(p);

    if !name_ptr.is_null() {
        let cstr  = CStr::from_ptr(name_ptr);
        let bytes = cstr.to_bytes();
        let n     = core::cmp::min(bytes.len(), NAME_LEN - 1);

        ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            entry.name.as_mut_ptr() as *mut u8,
            n,
        );
        entry.name[n] = 0;
    } else {
        entry.name[0] = 0;
    }

    hdr.len += 1;
    0
}

type ProcT = *mut Proc;
type ProcIterateCallout = unsafe extern "C" fn(ProcT, *mut c_void) -> CInt;

type ProcIterateFn = unsafe extern "C" fn(
    flags: u32,
    callout: ProcIterateCallout,
    arg: *mut c_void,
    filterfn: Option<ProcIterateCallout>,
    filterarg: *mut c_void,
);

type ProcBestNameFn = unsafe extern "C" fn(ProcT) -> *const u8;

#[repr(C)]
pub struct Proc {
    pub p_list:          LIST_ENTRY_proc,
    pub task:            *mut c_void,
    pub p_pptr:          *mut Proc,
    pub p_ppid:          Pid,
    pub p_original_ppid: Pid,
    pub p_pgrpid:        Pid,
    pub p_uid:           Uid,
    pub p_gid:           Gid,
    pub p_ruid:          Uid,
    pub p_rgid:          Gid,
    pub p_svuid:         Uid,
    pub p_svgid:         Gid,
    pub p_uniqueid:      u64,
    pub p_puniqueid:     u64,

    pub p_mlock:         [u8; 16],

    pub p_pid:           Pid,
    pub p_stat:          CChar,
}

#[repr(C)]
pub struct LIST_ENTRY_proc {
    pub le_next: *mut Proc,
    pub le_prev: *mut *mut Proc,
}

pub type Pid = CInt;
pub type Uid = CUInt;
pub type Gid = CUInt;

pub type CChar = i8;
pub type CInt  = i32;
pub type CUInt = u32;

unsafe fn ptrauth_sign(ptr: *const u8, discriminator: usize) -> *const u8 {
    let signed: usize;
    asm!(
        ".inst 0xdac10020",       // pacia x0, x1
        in("x0") ptr as usize,
        in("x1") discriminator,
        lateout("x0") signed,
        options(nomem, nostack),
    );
    signed as *const u8
}
