
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::ring::{Ring, Taken};

pub fn forward_frame(arena: u64, frame: &[u8]) -> bool {
    unsafe { waiting() }.entry(arena).or_default().push_back(frame.to_vec());
    send_what_waits(arena);

    true
}

pub fn serve_waiting_frames() {
    let arenas: Vec<u64> = unsafe { waiting() }.keys().copied().collect();
    for arena in arenas {
        send_what_waits(arena);
    }
}

pub fn take_frame_from_target(arena: u64) -> Option<Vec<u8>> {
    read_frame(&TO_KERNEL, arena)
}

pub fn holds_a_frame_from_target(arena: u64) -> bool {
    TO_KERNEL.holds_anything(arena)
}

pub fn a_frame_waits_for_room() -> bool {
    unsafe { waiting() }
        .iter()
        .any(|(arena, frames)| !frames.is_empty() && TO_COPY.has_room(*arena))
}

pub fn publish_frame_to_host(arena: u64, frame: &[u8]) -> bool {
    write_frame(&TO_KERNEL, arena, frame)
}

pub fn take_frame_from_host(arena: u64) -> Option<Vec<u8>> {
    read_frame(&TO_COPY, arena)
}

pub fn holds_a_frame_from_host(arena: u64) -> bool {
    TO_COPY.holds_anything(arena)
}

pub fn forget(arena: u64) {
    unsafe { holds() }.retain(|(of, _), _| *of != arena);
    unsafe { waiting() }.remove(&arena);
}

fn send_what_waits(arena: u64) {
    let frames = unsafe { waiting() }.get_mut(&arena).unwrap();

    while let Some(frame) = frames.front_mut() {
        if !write_frame(&TO_COPY, arena, frame) {
            break;
        }
        frames.pop_front();
    }
}

fn write_frame(ring: &Ring, arena: u64, frame: &[u8]) -> bool {
    ring.take_lock(arena, rest);

    let mut written = 0;
    while written < frame.len() {
        match ring.write(arena, arena + ring.buffer, frame, written) {
            Some(now) => written = now,
            None => break,
        }
    }

    ring.let_lock_go(arena);

    if written != frame.len() {
        ring.ask_for_room(arena);
        return false;
    }

    true
}

fn read_frame(ring: &Ring, arena: u64) -> Option<Vec<u8>> {
    let mut frame = unsafe { holds() }.remove(&(arena, ring.buffer)).unwrap_or_default();

    loop {
        match ring.read(arena, arena + ring.buffer, &mut frame) {
            Taken::Nothing => {
                if !frame.is_empty() {
                    unsafe { holds() }.insert((arena, ring.buffer), frame);
                }
                return None;
            }
            Taken::Piece => {}
            Taken::Frame => return Some(frame),
        }
    }
}

fn rest() {
    core::hint::spin_loop();
}

unsafe fn holds() -> &'static mut BTreeMap<(u64, u64), Vec<u8>> {
    unsafe { (&raw mut HOLDS).as_mut().unwrap() }
}

static mut HOLDS: BTreeMap<(u64, u64), Vec<u8>> = BTreeMap::new();

unsafe fn waiting() -> &'static mut BTreeMap<u64, VecDeque<Vec<u8>>> {
    unsafe { (&raw mut WAITING).as_mut().unwrap() }
}

static mut WAITING: BTreeMap<u64, VecDeque<Vec<u8>>> = BTreeMap::new();

pub const ARENA_SIZE: u64 = 0x1000 + (2 * FRAME_BUFFER_SIZE as u64);

pub const AWAKE_AT: u64 = 0;
pub const IMAGE_BASE: u64 = 8;
pub const IMAGE_SIZE: u64 = 16;
pub const STOP_REQUEST: u64 = 24;
pub const WORKER_STOPPED: u64 = 28;
pub const PAGE_SIZE: u64 = 40;

pub const THREAD_WANTED: u64 = 512;
pub const THREAD_STACK: u64 = 520;
pub const THREAD_ARGUMENT: u64 = 528;
pub const THREAD_ANSWER: u64 = 536;

pub const NOTHING_WANTED: u64 = 0;
pub const THREAD_STARTED: u64 = 1;
pub const THREAD_REFUSED: u64 = 2;

pub const TO_COPY: Ring = Ring {
    buffer: 0x1000,
    head: 256,
    tail: 260,
    lock: 264,
    room: 268,
    size: FRAME_BUFFER_SIZE,
};

pub const TO_KERNEL: Ring = Ring {
    buffer: 0x1000 + FRAME_BUFFER_SIZE as u64,
    head: 272,
    tail: 276,
    lock: 280,
    room: 284,
    size: FRAME_BUFFER_SIZE,
};

const FRAME_BUFFER_SIZE: usize = 0x10000;
