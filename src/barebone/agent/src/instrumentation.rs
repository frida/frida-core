use crate::bindings::{
    g_object_unref, gpointer, gum_interceptor_begin_transaction, gum_interceptor_end_transaction,
    gum_interceptor_obtain, GumInterceptor,
};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

pub(crate) struct Instrumentation {
    interceptor: AtomicPtr<GumInterceptor>,
}

impl Instrumentation {
    pub(crate) const fn new() -> Self {
        Self { interceptor: AtomicPtr::new(ptr::null_mut()) }
    }

    pub(crate) fn apply<R>(&self, changes: impl FnOnce(*mut GumInterceptor) -> R) -> R {
        let interceptor = self.held();
        unsafe { gum_interceptor_begin_transaction(interceptor) };
        let result = changes(interceptor);
        unsafe { gum_interceptor_end_transaction(interceptor) };
        result
    }

    pub(crate) fn revert(&self, changes: impl FnOnce(*mut GumInterceptor)) {
        let interceptor = self.interceptor.swap(ptr::null_mut(), Ordering::AcqRel);
        if interceptor.is_null() {
            return;
        }
        unsafe { gum_interceptor_begin_transaction(interceptor) };
        changes(interceptor);
        unsafe {
            gum_interceptor_end_transaction(interceptor);
            g_object_unref(interceptor as gpointer);
        }
    }

    fn held(&self) -> *mut GumInterceptor {
        let held = self.interceptor.load(Ordering::Acquire);
        if !held.is_null() {
            return held;
        }
        let obtained = unsafe { gum_interceptor_obtain() };
        self.interceptor.store(obtained, Ordering::Release);
        obtained
    }
}
