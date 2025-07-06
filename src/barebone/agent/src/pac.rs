use core::arch::asm;

pub unsafe fn ptrauth_sign(ptr: *const u8, discriminator: usize) -> *const u8 {
    let signed: usize;
    unsafe {
        asm!(
            ".inst 0xdac10020",       // pacia x0, x1
            in("x0") ptr as usize,
            in("x1") discriminator,
            lateout("x0") signed,
            options(nomem, nostack),
        );
    }
    signed as *const u8
}
