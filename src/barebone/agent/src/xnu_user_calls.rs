
use core::arch::asm;
use core::ffi::c_void;

use crate::kernel::{CpuState, ThreadEntry, ThreadInfo};
use crate::xnu::Primitives;

pub static USER: Primitives = Primitives {
    alloc,
    free,
    alloc_code,
    free_code,
    spawn_thread,
    wait,
    wake,
    yield_now,
    monotonic_micros,
    current_process_id,
    current_thread_id,
    protect,
    protection_at,
    enumerate_ranges,
    enumerate_threads,
    find_thread,
    modify_thread,
};

fn alloc(size: usize) -> *mut u8 {
    take_memory(size).unwrap_or(0) as *mut u8
}

fn free(ptr: *mut u8, size: usize) {
    give_memory_back(ptr as u64, size);
}

fn alloc_code(size: usize) -> *mut u8 {
    let Some(address) = take_memory(size) else {
        return core::ptr::null_mut();
    };

    if !set_protection(address, size, READ | EXECUTE) {
        give_memory_back(address, size);
        return core::ptr::null_mut();
    }

    address as *mut u8
}

fn free_code(ptr: *mut u8, size: usize) {
    give_memory_back(ptr as u64, size);
}

fn protect(address: u64, size: usize, may: u32) -> bool {
    set_protection(address, size, may as u64)
}

fn wait(token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    if check() {
        return;
    }

    let value = unsafe { (token as *const u32).read_volatile() };
    unsafe {
        ask(ULOCK_WAIT, [COMPARE_AND_WAIT, token as u64, value as u64,
            timeout_us.unwrap_or(0)])
    };
}

fn wake(token: *const u8) {
    unsafe { ask(ULOCK_WAKE, [COMPARE_AND_WAIT | WAKE_ALL, token as u64, 0, 0]) };
}

fn yield_now() {
    give_up_the_processor();
}

fn monotonic_micros() -> i64 {
    micros() as i64
}

fn current_process_id() -> u32 {
    process_id()
}

fn current_thread_id() -> u64 {
    thread_id()
}

fn protection_at(address: u64) -> u32 {
    crate::xnu_ranges::protection_at(address)
}

fn enumerate_ranges(found: &mut dyn FnMut(u64, usize, u32)) {
    crate::xnu_ranges::enumerate_ranges(found);
}

fn spawn_thread(entry: ThreadEntry, parameter: *mut c_void) -> isize {
    let Some(stack) = take_memory(STACK) else {
        return 0;
    };

    let mut state = [0u32; crate::xnu_mig::STATE_WORDS];
    put(&mut state, 0, parameter as u64);
    put(&mut state, SP, stack + STACK as u64 - STACK_HEADROOM);
    put(&mut state, PC, entry as usize as u64);
    state[FLAGS + 1] = PLAIN_ADDRESSES;

    if !crate::xnu_mig::start_a_thread(&state) {
        give_memory_back(stack, STACK);
        return 0;
    }

    1
}

const STACK: usize = 0x20000;
const STACK_HEADROOM: u64 = 0x100;
const PLAIN_ADDRESSES: u32 = 1;

fn enumerate_threads(found: &mut dyn FnMut(ThreadInfo)) {
    let mut threads = [0u32; MOST_THREADS];
    let counted = crate::xnu_mig::threads_here(&mut threads);
    for thread in &threads[..counted] {
        found(ThreadInfo { id: *thread, cpu_state: state_of(*thread) });
    }
}

fn find_thread(id: u32) -> Option<ThreadInfo> {
    let mut threads = [0u32; MOST_THREADS];
    let counted = crate::xnu_mig::threads_here(&mut threads);
    threads[..counted].contains(&id).then(|| ThreadInfo { id, cpu_state: state_of(id) })
}

fn modify_thread(id: u32, change: &mut dyn FnMut(&mut CpuState)) -> bool {
    if !crate::xnu_mig::hold_still(id) {
        return false;
    }

    let mut state = [0u32; crate::xnu_mig::STATE_WORDS];
    let changed = crate::xnu_mig::state_of(id, &mut state) && {
        let mut cpu = as_cpu_state(&state);
        change(&mut cpu);
        write_cpu_state(&cpu, &mut state);
        crate::xnu_mig::set_state_of(id, &state)
    };

    crate::xnu_mig::let_go(id);

    changed
}

fn state_of(thread: u32) -> Option<CpuState> {
    let mut state = [0u32; crate::xnu_mig::STATE_WORDS];
    crate::xnu_mig::state_of(thread, &mut state).then(|| as_cpu_state(&state))
}

fn as_cpu_state(state: &[u32; crate::xnu_mig::STATE_WORDS]) -> CpuState {
    let mut cpu = CpuState { pc: word(state, PC), sp: word(state, SP), nzcv: state[FLAGS] as u64,
        x: [0; 29], fp: word(state, FP), lr: word(state, LR) };
    for (index, register) in cpu.x.iter_mut().enumerate() {
        *register = word(state, index);
    }

    cpu
}

fn write_cpu_state(cpu: &CpuState, state: &mut [u32; crate::xnu_mig::STATE_WORDS]) {
    for (index, register) in cpu.x.iter().enumerate() {
        put(state, index, *register);
    }
    put(state, FP, cpu.fp);
    put(state, LR, cpu.lr);
    put(state, SP, cpu.sp);
    put(state, PC, cpu.pc);
    state[FLAGS] = cpu.nzcv as u32;
}

fn word(state: &[u32; crate::xnu_mig::STATE_WORDS], index: usize) -> u64 {
    (state[index * 2] as u64) | ((state[index * 2 + 1] as u64) << 32)
}

fn put(state: &mut [u32; crate::xnu_mig::STATE_WORDS], index: usize, value: u64) {
    state[index * 2] = value as u32;
    state[index * 2 + 1] = (value >> 32) as u32;
}

const MOST_THREADS: usize = 128;
const FP: usize = 29;
const LR: usize = 30;
const SP: usize = 31;
const PC: usize = 32;
const FLAGS: usize = 66;

pub fn process_id() -> u32 {
    unsafe { ask(GET_PID, [0; 4]) as u32 }
}

pub fn thread_id() -> u64 {
    unsafe { ask(THREAD_SELF_ID, [0; 4]) as u64 }
}

pub fn give_up_the_processor() {
    unsafe { ask(SCHED_YIELD, [0; 4]) };
}

pub fn micros() -> u64 {
    let ticks: u64;
    let rate: u64;
    unsafe {
        asm!("isb", "mrs {0}, cntvct_el0", "mrs {1}, cntfrq_el0", out(reg) ticks, out(reg) rate);
    }

    ticks / (rate / 1_000_000)
}

pub fn take_memory(size: usize) -> Option<u64> {
    let mut address: u64 = 0;
    let told = unsafe {
        trap(MACH_VM_ALLOCATE, [task(), &mut address as *mut u64 as u64, size as u64, ANYWHERE])
    };

    (told == KERN_SUCCESS).then_some(address)
}

pub fn give_memory_back(address: u64, size: usize) {
    unsafe { trap(MACH_VM_DEALLOCATE, [task(), address, size as u64, 0]) };
}

fn set_protection(address: u64, size: usize, may: u64) -> bool {
    unsafe { trap(MACH_VM_PROTECT, [task(), address, size as u64, may]) == KERN_SUCCESS }
}

unsafe fn task() -> u64 {
    unsafe { trap(TASK_SELF, [0; 4]) as u64 }
}

unsafe fn trap(number: i64, args: [u64; 4]) -> i64 {
    unsafe { svc(number, args).0 }
}

unsafe fn ask(number: i64, args: [u64; 4]) -> i64 {
    let (answer, went_wrong) = unsafe { svc(number, args) };
    if went_wrong {
        return -answer;
    }

    answer
}

pub(crate) unsafe fn svc7(number: i64, args: [u64; 7]) -> i64 {
    let answer: i64;
    unsafe {
        asm!(
            "svc #0x80",
            inlateout("x16") number => _,
            inlateout("x0") args[0] => answer,
            inlateout("x1") args[1] => _,
            inlateout("x2") args[2] => _,
            inlateout("x3") args[3] => _,
            inlateout("x4") args[4] => _,
            inlateout("x5") args[5] => _,
            inlateout("x6") args[6] => _,
            clobber_abi("C"),
        );
    }

    answer
}

pub(crate) fn own_task() -> u32 {
    unsafe { trap(TASK_SELF, [0; 4]) as u32 }
}

pub fn own_thread() -> u32 {
    unsafe { trap(THREAD_SELF, [0; 4]) as u32 }
}

pub(crate) fn a_port_to_answer_on() -> u32 {
    unsafe { trap(REPLY_PORT, [0; 4]) as u32 }
}

unsafe fn svc(number: i64, args: [u64; 4]) -> (i64, bool) {
    let answer: i64;
    let went_wrong: u64;
    unsafe {
        asm!(
            "svc #0x80",
            "cset x4, cs",
            inlateout("x16") number => _,
            inlateout("x0") args[0] => answer,
            inlateout("x1") args[1] => _,
            inlateout("x2") args[2] => _,
            inlateout("x3") args[3] => _,
            lateout("x4") went_wrong,
            clobber_abi("C"),
        );
    }

    (answer, went_wrong != 0)
}
const KERN_SUCCESS: i64 = 0;
const ANYWHERE: u64 = 1;

const MACH_VM_ALLOCATE: i64 = -10;
const MACH_VM_DEALLOCATE: i64 = -12;
const MACH_VM_PROTECT: i64 = -14;
const TASK_SELF: i64 = -28;
const REPLY_PORT: i64 = -26;
const THREAD_SELF: i64 = -27;
pub(crate) const MACH_MSG: i64 = -31;

const READ: u64 = 1;
const EXECUTE: u64 = 4;
const COMPARE_AND_WAIT: u64 = 1;
const WAKE_ALL: u64 = 0x100;

const GET_PID: i64 = 20;
const ULOCK_WAIT: i64 = 515;
const ULOCK_WAKE: i64 = 516;
const SCHED_YIELD: i64 = 331;
const THREAD_SELF_ID: i64 = 372;
