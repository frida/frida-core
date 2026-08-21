use core::sync::atomic::{AtomicU32, Ordering};

// What the kernel half and the copy leave for each other. Both reach it by its own address, so
// each side is told only where it begins.
#[derive(Clone, Copy)]
pub struct Arena {
    begins: usize,
}

impl Arena {
    pub fn at(begins: usize) -> Self {
        Arena { begins }
    }

    pub fn at_offset(&self, offset: usize) -> usize {
        self.begins + offset
    }

    pub fn report_home(&self) {
        self.word(REPORTED).store(self.word(HOME).load(Ordering::Acquire), Ordering::Release);
    }

    pub fn told_by_the_kernel_half(&self) -> u32 {
        self.word(TO_COPY).load(Ordering::Acquire)
    }

    pub fn tell_the_kernel_half(&self) {
        self.word(TO_KERNEL).fetch_add(1, Ordering::AcqRel);
        super::user::wake_up(self.at_offset(TO_KERNEL));
    }

    fn word(&self, offset: usize) -> &AtomicU32 {
        unsafe { &*((self.begins + offset) as *const AtomicU32) }
    }
}

pub const REPORTED: usize = 0;
pub const HOME: usize = 4;
pub const TO_COPY: usize = 8;
pub const TO_KERNEL: usize = 12;
