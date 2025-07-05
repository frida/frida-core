#![no_std]
#![no_main]
mod xnu;
use core::alloc::{GlobalAlloc, Layout};
use alloc::format;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    //needs alloc
    let mut s = format!("{}", info.message());
    s.push('\0');
    xnu::panic(s.as_str());
    loop {}
}

pub struct XnuAllocator;
unsafe impl GlobalAlloc for XnuAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        xnu::kalloc(layout.size())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        xnu::free(ptr, layout.size());
    }
}

#[global_allocator]
static GLOBAL: XnuAllocator = XnuAllocator;
extern crate alloc;

#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut buf = alloc::string::String::new();
        write!(&mut buf, $($arg)*).unwrap();
        buf.push('\n');
        buf.push('\0');
        xnu::IOLog(&buf)
    }};
}

#[derive(Debug)]
struct Banan {
    helsinki: u64
}

unsafe extern "C" fn worker(_parameter: *mut core::ffi::c_void, _wait_result: i32) {
    for i in 0..10 {
        kprintln!("Hekkane! {:?}", Banan{ helsinki : i})
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> usize {
    xnu::kernel_thread_start(worker);
    0
}
