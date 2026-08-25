
use core::ffi::c_void;

pub fn list_applications_when_the_loop_can(request_id: u16) {
    unsafe {
        ASKED_BY = request_id;
        ASKED_FOR = true;
    }
}

pub fn asked_for_applications() -> Option<u16> {
    if !unsafe { ASKED_FOR } {
        return None;
    }
    unsafe { ASKED_FOR = false };

    Some(unsafe { ASKED_BY })
}

pub fn each_application(found: &mut dyn FnMut(&[u8], &[u8], &[u8])) {
    let Some(arena) = crate::xnu_injection::a_copy_that_can_ask_the_system() else {
        return;
    };

    let put = |at: u64, value: u64| unsafe { ((arena + at) as *mut u64).write_volatile(value) };
    put(crate::xnu_relay::APPS_ANSWER, crate::xnu_relay::NOTHING_WANTED);
    put(crate::xnu_relay::APPS_WANTED, 1);

    let began = crate::xnu::absolutetime_to_nanoseconds(crate::xnu::mach_absolute_time());
    let said;
    loop {
        let answer = unsafe {
            ((arena + crate::xnu_relay::APPS_ANSWER) as *const u64).read_volatile()
        };
        if answer != crate::xnu_relay::NOTHING_WANTED {
            said = answer;
            break;
        }

        let now = crate::xnu::absolutetime_to_nanoseconds(crate::xnu::mach_absolute_time());
        if now - began > LONG_ENOUGH_TO_LOOK {
            said = crate::xnu_relay::NOTHING_WANTED;
            break;
        }
        crate::kernel::yield_now();
    }
    put(crate::xnu_relay::APPS_WANTED, crate::xnu_relay::NOTHING_WANTED);
    if said != crate::xnu_relay::DONE {
        return;
    }

    let mut at = arena + crate::xnu_relay::SAYING;
    let past = at + crate::xnu_relay::SAYING_ROOM;
    while at < past && unsafe { (at as *const u8).read_volatile() } != 0 {
        let identifier = word_at(&mut at, past);
        let program = word_at(&mut at, past);
        let shown = word_at(&mut at, past);
        found(identifier, program, shown);
    }
}

fn word_at(at: &mut u64, past: u64) -> &'static [u8] {
    let from = *at;
    while *at < past && unsafe { (*at as *const u8).read_volatile() } != 0 {
        *at += 1;
    }
    let length = (*at - from) as usize;
    *at += 1;

    unsafe { core::slice::from_raw_parts(from as *const u8, length) }
}

static mut ASKED_FOR: bool = false;
static mut ASKED_BY: u16 = 0;

const LONG_ENOUGH_TO_LOOK: u64 = 20_000_000_000;

pub fn say_what_is_installed(arena: u64) {
    let mut at = arena + crate::xnu_relay::SAYING;
    let past = at + crate::xnu_relay::SAYING_ROOM - (3 * MOST_ONE_SAYS) as u64;

    if let Some(asking) = AskingTheSystem::found() {
        asking.each_one(&mut |identifier, program, shown| {
            if at >= past {
                return;
            }
            for piece in [identifier, program, shown] {
                for byte in piece {
                    unsafe { (at as *mut u8).write_volatile(*byte) };
                    at += 1;
                }
                unsafe { (at as *mut u8).write_volatile(0) };
                at += 1;
            }
        });
    }

    unsafe {
        (at as *mut u8).write_volatile(0);
        ((arena + crate::xnu_relay::APPS_ANSWER) as *mut u64)
            .write_volatile(crate::xnu_relay::DONE);
    }
}

struct AskingTheSystem {
    class_named: unsafe extern "C" fn(*const u8) -> *const c_void,
    what_to_do: unsafe extern "C" fn(*const u8) -> *const c_void,
    ask: unsafe extern "C" fn(*const c_void, *const c_void) -> *const c_void,
    how_many: unsafe extern "C" fn(*const c_void) -> isize,
    the_one_at: unsafe extern "C" fn(*const c_void, isize) -> *const c_void,
    text_into: unsafe extern "C" fn(*const c_void, *mut u8, isize, i32) -> i32,
}

impl AskingTheSystem {
    fn found() -> Option<&'static AskingTheSystem> {
        let held = unsafe { (&raw const ASKING).as_ref().unwrap() };
        if held.is_some() {
            return held.as_ref();
        }

        for framework in [
            c"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
            c"/System/Library/Frameworks/CoreServices.framework/CoreServices",
            c"/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices",
        ] {
            open_the_framework(framework.as_ptr() as *const u8);
        }

        let runtime = |wanted: &[u8]| crate::xnu_libsystem::function_named(b"/libobjc.A.dylib",
            wanted);
        let foundation = |wanted: &[u8]| crate::xnu_libsystem::function_named(b"/CoreFoundation",
            wanted);
        let found = AskingTheSystem {
            class_named: unsafe { core::mem::transmute(runtime(b"_objc_getClass")?) },
            what_to_do: unsafe { core::mem::transmute(runtime(b"_sel_registerName")?) },
            ask: unsafe { core::mem::transmute(runtime(b"_objc_msgSend")?) },
            how_many: unsafe { core::mem::transmute(foundation(b"_CFArrayGetCount")?) },
            the_one_at: unsafe { core::mem::transmute(foundation(b"_CFArrayGetValueAtIndex")?) },
            text_into: unsafe { core::mem::transmute(foundation(b"_CFStringGetCString")?) },
        };

        unsafe { ASKING = Some(found) };
        unsafe { (&raw const ASKING).as_ref().unwrap().as_ref() }
    }

    fn each_one(&self, found: &mut dyn FnMut(&[u8], &[u8], &[u8])) {
        let workspace = self.tell(self.class(b"LSApplicationWorkspace\0"), b"defaultWorkspace\0");
        if workspace.is_null() {
            return;
        }

        let all = self.tell(workspace, b"allApplications\0");
        if all.is_null() {
            return;
        }

        for step in 0..unsafe { (self.how_many)(all) } {
            let one = unsafe { (self.the_one_at)(all, step) };
            let mut identifier = [0u8; MOST_ONE_SAYS];
            let mut program = [0u8; MOST_ONE_SAYS];
            let mut shown = [0u8; MOST_ONE_SAYS];
            if !self.text(self.tell(one, b"applicationIdentifier\0"), &mut identifier) {
                continue;
            }
            self.text(self.tell(one, b"canonicalExecutablePath\0"), &mut program);
            self.text(self.tell(one, b"localizedName\0"), &mut shown);

            found(&identifier[..length_of(&identifier)], &program[..length_of(&program)],
                &shown[..length_of(&shown)]);
        }
    }

    fn class(&self, named: &[u8]) -> *const c_void {
        unsafe { (self.class_named)(named.as_ptr()) }
    }

    fn tell(&self, what: *const c_void, to_do: &[u8]) -> *const c_void {
        if what.is_null() {
            return core::ptr::null();
        }

        unsafe { (self.ask)(what, (self.what_to_do)(to_do.as_ptr())) }
    }

    fn text(&self, said: *const c_void, into: &mut [u8; MOST_ONE_SAYS]) -> bool {
        if said.is_null() {
            return false;
        }

        unsafe {
            (self.text_into)(said, into.as_mut_ptr(), into.len() as isize, WHAT_TEXT_IS_KEPT_AS) != 0
        }
    }
}

fn open_the_framework(path: *const u8) {
    let Some(open) = crate::xnu_libsystem::function_named(b"/libdyld.dylib", b"_dlopen") else {
        return;
    };

    type Open = unsafe extern "C" fn(*const u8, i32) -> *mut c_void;
    let open: Open = unsafe { core::mem::transmute(open) };
    unsafe { open(path, WHEN_IT_IS_ASKED_FOR) };
}

fn length_of(said: &[u8]) -> usize {
    said.iter().position(|byte| *byte == 0).unwrap_or(said.len())
}

static mut ASKING: Option<AskingTheSystem> = None;

const WHEN_IT_IS_ASKED_FOR: i32 = 2;
const WHAT_TEXT_IS_KEPT_AS: i32 = 0x0800_0100;
const MOST_ONE_SAYS: usize = 256;
