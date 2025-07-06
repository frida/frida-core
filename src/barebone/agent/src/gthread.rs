use core::ffi::c_void;

pub type GMutex = c_void;

#[unsafe(no_mangle)]
pub extern "C" fn _frida_g_mutex_lock(_mutex: *mut GMutex) {
}

#[unsafe(no_mangle)]
pub extern "C" fn _frida_g_mutex_unlock(_mutex: *mut GMutex) {
}
