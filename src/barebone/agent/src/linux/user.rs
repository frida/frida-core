use super::arena::{Arena, TO_COPY};

pub fn entry_offset() -> usize {
    (frida_linux_user_entry as usize) - crate::own_range().0
}

// The copy's first word in the address space it was placed in: it says it is up, and from then
// on it sleeps until the kernel half has something for it. Nothing here looks at a clock.
pub extern "C" fn frida_linux_user_entry(arena: usize) -> ! {
    let arena = Arena::at(arena);

    arena.report_home();
    arena.tell_the_kernel_half();

    let mut served = arena.told_by_the_kernel_half();
    loop {
        wait_on(arena.at_offset(TO_COPY), served);

        served = arena.told_by_the_kernel_half();
        arena.tell_the_kernel_half();
    }
}

fn wait_on(word: usize, until_it_changes: u32) {
    syscall(
        FUTEX,
        word,
        FUTEX_WAIT_PRIVATE,
        until_it_changes as usize,
        0,
        0,
        0,
    );
}

pub fn wake_up(word: usize) {
    syscall(FUTEX, word, FUTEX_WAKE_PRIVATE, WAKE_EVERY_WAITER, 0, 0, 0);
}

#[cfg(target_arch = "aarch64")]
fn syscall(number: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
    let answer: isize;

    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") a => answer,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            in("x4") e,
            in("x5") f,
            options(nostack)
        );
    }

    answer
}

#[cfg(target_arch = "aarch64")]
const FUTEX: usize = 98;

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const WAKE_EVERY_WAITER: usize = i32::MAX as usize;
