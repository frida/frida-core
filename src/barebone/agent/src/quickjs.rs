use core::ptr;
use core::ffi::CStr;

mod bindings {
    #![allow(
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        dead_code
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub struct JSRuntime {
    runtime: *mut bindings::JSRuntime,
}

impl JSRuntime {
    pub fn new() -> Self {
        let runtime = unsafe { bindings::JS_NewRuntime() };
        Self { runtime }
    }

    pub fn create_context(&self) -> JSContext<'_> {
        let ctx = unsafe { bindings::JS_NewContext(self.runtime) };
        JSContext {
            context: ctx,
            _runtime: core::marker::PhantomData,
        }
    }
}

impl Drop for JSRuntime {
    fn drop(&mut self) {
        unsafe {
            bindings::JS_FreeRuntime(self.runtime);
        }
    }
}

pub struct JSContext<'rt> {
    context: *mut bindings::JSContext,
    _runtime: core::marker::PhantomData<&'rt JSRuntime>,
}

impl<'rt> JSContext<'rt> {
    pub fn eval(&'rt self, name: &str, code: &str) -> JSValue<'rt> {
        return unsafe {
            let c_name = core::ffi::CStr::from_bytes_with_nul_unchecked(name.as_bytes());
            let c_code = core::ffi::CStr::from_bytes_with_nul_unchecked(code.as_bytes());
            let value = bindings::JS_Eval(
                self.context,
                c_code.as_ptr(),
                code.len(),
                c_name.as_ptr(),
                (bindings::JS_EVAL_TYPE_GLOBAL | bindings::JS_EVAL_FLAG_STRICT) as i32,
            );
            JSValue::new(value, self)
        };
    }

    pub fn steal_exception(&'rt self) -> Option<JSValue<'rt>> {
        unsafe {
            let value = bindings::JS_GetException(self.context);
            if bindings::JSGlue_GetValueTag(value) != bindings::JS_TAG_NULL {
                Some(JSValue::new(value, self))
            } else {
                None
            }
        }
    }

    pub fn as_ptr(&self) -> *mut bindings::JSContext {
        self.context
    }
}

impl<'rt> Drop for JSContext<'rt> {
    fn drop(&mut self) {
        unsafe {
            bindings::JS_FreeContext(self.context);
        }
    }
}

pub struct JSValue<'rt> {
    value: bindings::JSValue,
    ctx: &'rt JSContext<'rt>,
}

impl<'rt> JSValue<'rt> {
    pub fn new(value: bindings::JSValue, ctx: &'rt JSContext<'rt>) -> Self {
        Self { value, ctx }
    }

    pub fn is_exception(&self) -> bool {
        return unsafe { bindings::JSGlue_GetValueTag(self.value) == bindings::JS_TAG_EXCEPTION }
    }

    pub fn to_cstring(&self) -> JSCString {
        let cstr = unsafe {
            bindings::JS_ToCStringLen2(self.ctx.as_ptr(), ptr::null_mut(), self.value, false as i32)
        };
        JSCString::new(cstr, self.ctx.as_ptr())
    }
}

impl Drop for JSValue<'_> {
    fn drop(&mut self) {
        unsafe {
            bindings::JSGlue_FreeValue(self.ctx.as_ptr(), self.value);
        }
    }
}

pub struct JSCString {
    ptr: *const u8,
    ctx: *mut bindings::JSContext,
}

impl JSCString {
    pub fn new(ptr: *const u8, ctx: *mut bindings::JSContext) -> Self {
        Self { ptr, ctx }
    }

    pub fn as_str(&self) -> Result<&str, core::str::Utf8Error> {
        if self.ptr.is_null() {
            return Ok("");
        }
        unsafe {
            let cstr = CStr::from_ptr(self.ptr as *const core::ffi::c_char);
            core::str::from_utf8(cstr.to_bytes())
        }
    }

    pub fn as_str_unchecked(&self) -> &str {
        self.as_str().unwrap()
    }
}

impl Drop for JSCString {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                bindings::JS_FreeCString(self.ctx, self.ptr);
            }
        }
    }
}
