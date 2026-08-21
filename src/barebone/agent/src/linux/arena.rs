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

    // Until the frames flow, what the copy has to say is left here for the kernel half to read.
    pub fn say(&self, msg: &str) {
        let said = msg.as_bytes();
        let length = said.iter().position(|byte| *byte == 0).unwrap_or(said.len());
        let kept = length.min(SAID_SIZE - 1);

        unsafe {
            core::ptr::copy_nonoverlapping(said.as_ptr(), (self.begins + SAID) as *mut u8, kept);
            ((self.begins + SAID + kept) as *mut u8).write(0);
        }
    }

    pub fn page_size(&self) -> u32 {
        self.word(PAGE_SIZE).load(Ordering::Acquire)
    }

    pub fn leave(&self, offset: usize, value: u64) {
        unsafe { ((self.begins + offset) as *mut u64).write_volatile(value) };
    }

    pub fn note(&self, step: u32) {
        self.word(PROGRESS).store(step, Ordering::Release);
    }

    pub fn home(&self) -> u32 {
        self.word(HOME).load(Ordering::Acquire)
    }

    pub fn report_home(&self) {
        self.word(REPORTED).store(self.word(HOME).load(Ordering::Acquire), Ordering::Release);
    }

    pub fn tell_the_kernel_half(&self) {
        self.word(TO_KERNEL).fetch_add(1, Ordering::AcqRel);
        super::user::wake_up(self.at_offset(TO_KERNEL));
    }

    fn word(&self, offset: usize) -> &AtomicU32 {
        unsafe { &*((self.begins + offset) as *const AtomicU32) }
    }
}

pub const PROGRESS: usize = 20;
pub const PAGE_SIZE: usize = 48;
pub const FAULT_KIND: usize = 24;
pub const FAULT_ADDRESS: usize = 32;
pub const FAULT_PC: usize = 40;
pub const SAID: usize = 64;
pub const SAID_SIZE: usize = 192;


pub const REPORTED: usize = 0;
pub const HOME: usize = 4;
pub const TO_KERNEL: usize = 12;
pub const WOKEN: usize = 16;
