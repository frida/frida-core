
pub fn entry_offset() -> usize {
    (frida_xnu_user_entry as usize) - crate::own_range().0
}

pub extern "C" fn frida_xnu_user_entry(arena: usize) -> ! {
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
        said => say(arena, said),
    }
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
