
pub fn entry_offset() -> usize {
    (frida_xnu_user_entry as usize) - crate::own_range().0
}

pub extern "C" fn frida_xnu_user_entry(arena: usize) -> ! {
    crate::xnu::select_user();
    unsafe { (arena as *mut u64).write_volatile(AWAKE) };

    let arena = arena as u64;
    let mut said = [0u8; MOST_AT_ONCE];
    loop {
        if let Some(length) = hear(arena, &mut said) {
            answer(arena, &said[..length]);
        }
        core::hint::spin_loop();
    }
}

fn answer(arena: u64, asked: &[u8]) {
    match asked {
        b"pid" => say(arena, &crate::xnu_user_calls::process_id().to_le_bytes()),
        b"tid" => say(arena, &crate::xnu_user_calls::thread_id().to_le_bytes()),
        b"mem" => say(arena, &(took_a_page() as u64).to_le_bytes()),
        b"st" => say(arena, &(a_thread_is_running_somewhere() as u64).to_le_bytes()),
        b"chg" => say(arena, &(a_thread_takes_a_change() as u64).to_le_bytes()),
        b"new" => say(arena, &(a_new_thread_appears() as u64).to_le_bytes()),
        b"thr" => {
            let mut ports = [0u32; 64];
            say(arena, &(crate::xnu_mig::threads_here(&mut ports) as u32).to_le_bytes())
        }
        said => say(arena, said),
    }
}

fn took_a_page() -> bool {
    let page = crate::kernel::alloc(0x4000);
    if page.is_null() {
        return false;
    }
    unsafe { page.write_volatile(1) };
    crate::kernel::free(page, 0x4000);

    true
}

fn a_thread_is_running_somewhere() -> bool {
    let mut counted = 0;
    let mut plausible = 0;
    crate::kernel::enumerate_threads(&mut |thread| {
        counted += 1;
        if let Some(state) = thread.cpu_state {
            if state.pc != 0 && state.pc < HIGHEST_A_PROCESS_SEES && state.sp != 0 {
                plausible += 1;
            }
        }
    });

    counted != 0 && counted == plausible
}

const HIGHEST_A_PROCESS_SEES: u64 = 1 << 47;

fn a_new_thread_appears() -> bool {
    let before = how_many_threads();
    if crate::kernel::spawn_thread(waits_forever, core::ptr::null_mut()) == 0 {
        return false;
    }

    for _ in 0..LONG_ENOUGH {
        if how_many_threads() > before {
            return true;
        }
        crate::kernel::yield_now();
    }

    false
}

unsafe extern "C" fn waits_forever(_parameter: *mut core::ffi::c_void, _wait_result: i32) {
    loop {
        crate::kernel::yield_now();
    }
}

fn how_many_threads() -> usize {
    let mut counted = 0;
    crate::kernel::enumerate_threads(&mut |_| counted += 1);

    counted
}

const LONG_ENOUGH: u32 = 10_000;

fn a_thread_takes_a_change() -> bool {
    let mine = crate::xnu_user_calls::own_thread();
    let mut someone_else = None;
    crate::kernel::enumerate_threads(&mut |thread| {
        if thread.id != mine && someone_else.is_none() {
            someone_else = Some(thread.id);
        }
    });

    let Some(thread) = someone_else else {
        return false;
    };

    crate::kernel::modify_thread(thread, &mut |_state| {})
}

fn hear(arena: u64, into: &mut [u8]) -> Option<usize> {
    let ring = &crate::xnu_relay::TO_COPY;
    let head = word(arena + ring.head);
    let tail = word(arena + ring.tail);
    if head == tail {
        return None;
    }

    let buffer = arena + ring.buffer;
    let header = read_word(buffer, tail, ring.size);
    let piece = (header & !MORE) as usize;

    for i in 0..piece.min(into.len()) {
        into[i] = unsafe {
            ((buffer + ((tail as usize + HEADER + i) & (ring.size - 1)) as u64) as *const u8).read()
        };
    }

    put_word(arena + ring.tail, tail.wrapping_add((HEADER + piece) as u32));

    Some(piece.min(into.len()))
}

fn say(arena: u64, frame: &[u8]) {
    let ring = &crate::xnu_relay::TO_KERNEL;
    let head = word(arena + ring.head);
    let tail = word(arena + ring.tail);
    if ring.size - head.wrapping_sub(tail) as usize <= HEADER + frame.len() {
        return;
    }

    let buffer = arena + ring.buffer;
    write_word(buffer, head, frame.len() as u32, ring.size);
    for (i, byte) in frame.iter().enumerate() {
        unsafe {
            ((buffer + ((head as usize + HEADER + i) & (ring.size - 1)) as u64) as *mut u8)
                .write(*byte)
        };
    }

    put_word(arena + ring.head, head.wrapping_add((HEADER + frame.len()) as u32));
}

fn word(at: u64) -> u32 {
    unsafe { (at as *const u32).read_volatile() }
}

fn put_word(at: u64, value: u32) {
    unsafe { (at as *mut u32).write_volatile(value) };
}

fn read_word(buffer: u64, at: u32, size: usize) -> u32 {
    let mut bytes = [0u8; HEADER];
    for (i, byte) in bytes.iter_mut().enumerate() {
    }

    u32::from_le_bytes(bytes)
}

fn write_word(buffer: u64, at: u32, value: u32, size: usize) {
    for (i, byte) in value.to_le_bytes().iter().enumerate() {
        unsafe { ((buffer + ((at as usize + i) & (size - 1)) as u64) as *mut u8).write(*byte) };
    }
}

const HEADER: usize = 4;
const MORE: u32 = 0x8000_0000;
const MOST_AT_ONCE: usize = 4096;

pub const AWAKE: u64 = 0x6672_6964_6100_0001;
