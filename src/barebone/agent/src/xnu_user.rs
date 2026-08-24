
pub fn entry_offset() -> usize {
    (frida_xnu_user_entry as usize) - crate::own_range().0
}

pub extern "C" fn frida_xnu_user_entry(arena: usize) -> ! {
    unsafe { (arena as *mut u64).write_volatile(AWAKE) };

    loop {
        core::hint::spin_loop();
    }
}

pub const AWAKE: u64 = 0x6672_6964_6100_0001;
