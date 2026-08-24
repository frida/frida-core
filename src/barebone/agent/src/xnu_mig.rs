
use crate::xnu_user_calls::{MACH_MSG, a_port_to_answer_on, own_task, svc7};

pub fn threads_here(into: &mut [u32]) -> usize {
    let mut message = [0u32; MESSAGE_WORDS];
    let Some(reply) = ask(own_task(), TASK_THREADS, &mut message) else {
        return 0;
    };

    let described = message[HEADER_WORDS] as usize;
    if described != 1 {
        return 0;
    }

    let ports = u64::from_le_bytes([
        message[HEADER_WORDS + 1].to_le_bytes()[0], message[HEADER_WORDS + 1].to_le_bytes()[1],
        message[HEADER_WORDS + 1].to_le_bytes()[2], message[HEADER_WORDS + 1].to_le_bytes()[3],
        message[HEADER_WORDS + 2].to_le_bytes()[0], message[HEADER_WORDS + 2].to_le_bytes()[1],
        message[HEADER_WORDS + 2].to_le_bytes()[2], message[HEADER_WORDS + 2].to_le_bytes()[3],
    ]);
    let counted = message[HEADER_WORDS + 6] as usize;
    let _ = reply;

    let taken = counted.min(into.len());
    for (index, slot) in into[..taken].iter_mut().enumerate() {
    }

    taken
}

pub fn state_of(thread: u32, into: &mut [u32; STATE_WORDS]) -> bool {
    let mut message = [0u32; MESSAGE_WORDS];
    message[HEADER_WORDS + 2] = ARM_THREAD_STATE64 as u32;
    message[HEADER_WORDS + 3] = STATE_WORDS as u32;

    if ask_about(thread, THREAD_GET_STATE, &mut message, ASKING_ABOUT_STATE).is_none() {
        return false;
    }

    if message[HEADER_WORDS + 2] != 0 || message[HEADER_WORDS + 3] as usize > STATE_WORDS {
        return false;
    }

    into.copy_from_slice(&message[HEADER_WORDS + 4..HEADER_WORDS + 4 + STATE_WORDS]);

    true
}

pub fn set_state_of(thread: u32, state: &[u32; STATE_WORDS]) -> bool {
    let mut message = [0u32; MESSAGE_WORDS];
    message[HEADER_WORDS + 2] = ARM_THREAD_STATE64 as u32;
    message[HEADER_WORDS + 3] = STATE_WORDS as u32;
    message[HEADER_WORDS + 4..HEADER_WORDS + 4 + STATE_WORDS].copy_from_slice(state);

    let words = HEADER_WORDS + 4 + STATE_WORDS;
    ask_about(thread, THREAD_SET_STATE, &mut message, words * 4).is_some()
}

pub fn hold_still(thread: u32) -> bool {
    let mut message = [0u32; MESSAGE_WORDS];
    ask_about(thread, THREAD_SUSPEND, &mut message, HEADER_BYTES).is_some()
}

pub fn let_go(thread: u32) -> bool {
    let mut message = [0u32; MESSAGE_WORDS];
    ask_about(thread, THREAD_RESUME, &mut message, HEADER_BYTES).is_some()
}

pub fn start_a_thread(state: &[u32; STATE_WORDS]) -> bool {
    let mut message = [0u32; MESSAGE_WORDS];
    message[HEADER_WORDS + 2] = ARM_THREAD_STATE64 as u32;
    message[HEADER_WORDS + 3] = STATE_WORDS as u32;
    message[HEADER_WORDS + 4..HEADER_WORDS + 4 + STATE_WORDS].copy_from_slice(state);

    let words = HEADER_WORDS + 4 + STATE_WORDS;
    let Some(_) = ask_about(own_task(), THREAD_CREATE_RUNNING, &mut message, words * 4) else {
        return false;
    };

    message[HEADER_WORDS] == 1
}

fn ask(port: u32, what: i32, message: &mut [u32; MESSAGE_WORDS]) -> Option<u32> {
    ask_about(port, what, message, HEADER_BYTES)
}

fn ask_about(port: u32, what: i32, message: &mut [u32; MESSAGE_WORDS], sending: usize)
    -> Option<u32>
{
    let reply = a_port_to_answer_on();
    if reply == 0 {
        return None;
    }

    message[0] = COPY_SEND | (MAKE_SEND_ONCE << 8);
    message[1] = HEADER_BYTES as u32;
    message[2] = port;
    message[3] = reply;
    message[4] = 0;
    message[5] = what as u32;

    message[1] = sending as u32;

    let told = unsafe {
        svc7(MACH_MSG, [message.as_mut_ptr() as u64, (SEND | RECEIVE) as u64,
            sending as u64, (MESSAGE_WORDS * 4) as u64, reply as u64, 0, 0])
    };

    (told == MACH_MSG_SUCCESS).then_some(reply)
}

const HEADER_BYTES: usize = 24;
const HEADER_WORDS: usize = HEADER_BYTES / 4;
const MESSAGE_WORDS: usize = 128;

const COPY_SEND: u32 = 19;
const MAKE_SEND_ONCE: u32 = 21;
const SEND: i32 = 1;
const RECEIVE: i32 = 2;
const MACH_MSG_SUCCESS: i64 = 0;

const TASK_THREADS: i32 = 3402;
const THREAD_CREATE_RUNNING: i32 = 3412;
const THREAD_GET_STATE: i32 = 3603;
const THREAD_SET_STATE: i32 = 3604;
const THREAD_SUSPEND: i32 = 3605;
const THREAD_RESUME: i32 = 3606;

const ASKING_ABOUT_STATE: usize = HEADER_BYTES + 16;
const ARM_THREAD_STATE64: i32 = 6;
pub const STATE_WORDS: usize = 68;
