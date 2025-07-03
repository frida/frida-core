mod bindings {
    #![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use bindings::*;
use std::ptr;

fn main() {
    unsafe {
        let rt = JS_NewRuntime();
        if rt.is_null() {
            eprintln!("Failed to create JS runtime");
        } else {
            println!("QuickJS runtime created!");
            JS_FreeRuntime(rt);
        }
    }
}
