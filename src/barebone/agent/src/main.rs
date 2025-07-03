#![no_main]
#![no_std]

mod syscalls;

mod bindings {
    #![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use bindings::*;
use core::ffi::CStr;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> i32 {
    let mut sum: i32 = 0;

    unsafe {
        let rt = JS_NewRuntime();
        let ctx = JS_NewContext(rt);

        let name_str = "sum.js\0";
        let code_str = "3 + 4;\0";

        let name = CStr::from_bytes_with_nul(name_str.as_bytes()).unwrap();
        let code = CStr::from_bytes_with_nul(code_str.as_bytes()).unwrap();

        let sum_val = JS_Eval(ctx, code.as_ptr(), code_str.len() - 1, name.as_ptr(),
            (JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT) as i32);

        JS_ToInt32(ctx, &mut sum, sum_val);

        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);
    }

    sum
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
