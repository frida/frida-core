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

    pub fn said(&self) -> &str {
        let bytes =
            unsafe { core::slice::from_raw_parts((self.begins + SAID) as *const u8, SAID_SIZE) };
        let length = bytes.iter().position(|byte| *byte == 0).unwrap_or(SAID_SIZE);

        core::str::from_utf8(&bytes[..length]).unwrap_or("")
    }

    pub fn page_size(&self) -> u32 {
        self.word(PAGE_SIZE).load(Ordering::Acquire)
    }

    pub fn leave(&self, offset: usize, value: u64) {
        unsafe { ((self.begins + offset) as *mut u64).write_volatile(value) };
    }

    pub fn progress(&self) -> u32 {
        self.word(PROGRESS).load(Ordering::Acquire)
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

    pub fn reachable_at(&self, says: u32, hears: u32) {
        self.word(SAYS).store(says, Ordering::Release);
        self.word(HEARS).store(hears, Ordering::Release);
    }

    pub fn tell_it_to_go(&self) {
        self.word(GO).store(1, Ordering::Release);
    }

    pub fn was_told_to_go(&self) -> bool {
        self.word(GO).load(Ordering::Acquire) != 0
    }

    pub fn gone(&self) {
        self.word(GONE).store(1, Ordering::Release);
    }

    pub fn has_gone(&self) -> bool {
        self.word(GONE).load(Ordering::Acquire) != 0
    }

    pub fn says_through(&self) -> u32 {
        self.word(SAYS).load(Ordering::Acquire)
    }

    pub fn hears_through(&self) -> u32 {
        self.word(HEARS).load(Ordering::Acquire)
    }

    pub fn tell_the_kernel_half(&self) {
        self.word(TO_KERNEL).fetch_add(1, Ordering::AcqRel);
        super::user::say_something();
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
pub const FAULT_LR: usize = 56;
pub const SAID: usize = 64;
pub const GO: usize = 288;
pub const GONE: usize = 292;
pub const SAID_SIZE: usize = 192;


pub const REPORTED: usize = 0;
pub const HOME: usize = 4;
pub const SAYS: usize = 8;
pub const HEARS: usize = 52;
pub const TO_KERNEL: usize = 12;
pub const WOKEN: usize = 16;
