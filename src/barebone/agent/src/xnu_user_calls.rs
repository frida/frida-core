
use core::arch::asm;

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

pub fn protect(address: u64, size: usize, may: u64) -> bool {
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

const GET_PID: i64 = 20;
const SCHED_YIELD: i64 = 331;
const THREAD_SELF_ID: i64 = 372;
