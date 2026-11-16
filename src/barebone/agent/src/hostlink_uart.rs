use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::kernel::{self, InterruptLine};

pub struct Hostlink {
    state: UnsafeCell<Inner>,
    on_rx: Option<fn(&[u8])>,
}

struct Inner {
    regs: Regs,
    line: InterruptLine,
    incoming: Incoming,
    received: VecDeque<Vec<u8>>,
}

impl Hostlink {
    pub fn init(
        mmio: u64,
        irq: u32,
        interrupt_parent: u32,
        on_rx: Option<fn(&[u8])>,
        wake_token: *const u8,
    ) -> Result<Self, ()> {
        let regs = Regs(kernel::map_io(mmio, REGS_SIZE) as *mut u32);
        regs.write(UCON, 0);
        regs.write(UFCON, UFCON_FIFO_ENABLE | UFCON_RX_FIFO_RESET | UFCON_TX_FIFO_RESET);

        let line = kernel::hook_interrupt(
            interrupt_parent,
            irq,
            wake_token as *mut c_void,
            on_interrupt,
            ptr::null_mut(),
        )
        .map_err(|_| ())?;
        unsafe {
            WIRING = Some(Wiring { regs, line });
        }
        line.enable();

        Ok(Self {
            state: UnsafeCell::new(Inner {
                regs,
                line,
                incoming: Incoming::new(),
                received: VecDeque::new(),
            }),
            on_rx,
        })
    }

    pub fn send(&self, payload: &[u8]) {
        let s = unsafe { &mut *self.state.get() };
        s.transmit(&(payload.len() as u32).to_le_bytes());
        s.transmit(payload);
    }

    pub fn process(&self) {
        A_TURN_IS_WANTED.store(false, Ordering::Release);

        let s = self.state.get();
        unsafe {
            (*s).drain_received();
            (*s).line.enable();
        }

        while let Some(frame) = unsafe { (*s).received.pop_front() } {
            if let Some(on_rx) = self.on_rx {
                on_rx(&frame);
            }
        }
    }

    pub fn shutdown(&self) {
        let s = unsafe { &*self.state.get() };
        s.line.disable();
    }
}

impl Inner {
    fn transmit(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            while self.regs.transmitter_is_full() {
                self.wait_for_room();
            }
            self.regs.write(UTXH, byte as u32);
        }
    }

    fn wait_for_room(&mut self) {
        self.drain_received();
        INTERRUPTED.store(false, Ordering::Release);
        self.regs.write(UCON, UCON_TXTHRESH_ENA);
        self.line.enable();

        kernel::wait(&ROOM_TOKEN, None, &mut || INTERRUPTED.load(Ordering::Acquire));
    }

    fn drain_received(&mut self) {
        while self.regs.has_received() {
            if let Some(frame) = self.incoming.take(self.regs.receive()) {
                self.received.push_back(frame);
            }
        }
    }
}

pub fn a_turn_is_wanted() -> bool {
    A_TURN_IS_WANTED.load(Ordering::Acquire)
}

extern "C" fn on_interrupt(token: *mut c_void, _refcon: *mut c_void, _nub: *mut c_void, _source: i32) {
    if let Some(wiring) = unsafe { (*&raw const WIRING).as_ref() } {
        wiring.line.disable();
        wiring.regs.write(UCON, 0);
        wiring.regs.write(UTRSTAT, UTRSTAT_TX_THRESH);
    }
    INTERRUPTED.store(true, Ordering::Release);
    A_TURN_IS_WANTED.store(true, Ordering::Release);
    kernel::wake(&ROOM_TOKEN);
    crate::nudge_the_loop(token as *const u8);
}

struct Wiring {
    regs: Regs,
    line: InterruptLine,
}

static A_TURN_IS_WANTED: AtomicBool = AtomicBool::new(false);
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static ROOM_TOKEN: u8 = 0;
static mut WIRING: Option<Wiring> = None;

struct Incoming {
    length: [u8; FRAME_LENGTH_SIZE],
    length_seen: usize,
    frame: Vec<u8>,
    frame_size: usize,
}

impl Incoming {
    fn new() -> Self {
        Self {
            length: [0; FRAME_LENGTH_SIZE],
            length_seen: 0,
            frame: Vec::new(),
            frame_size: 0,
        }
    }

    fn take(&mut self, byte: u8) -> Option<Vec<u8>> {
        if self.length_seen != FRAME_LENGTH_SIZE {
            self.length[self.length_seen] = byte;
            self.length_seen += 1;
            if self.length_seen != FRAME_LENGTH_SIZE {
                return None;
            }
            self.frame_size = u32::from_le_bytes(self.length) as usize;
            self.frame = Vec::with_capacity(self.frame_size);
        } else {
            self.frame.push(byte);
        }

        if self.frame.len() != self.frame_size {
            return None;
        }
        self.length_seen = 0;
        Some(core::mem::take(&mut self.frame))
    }
}

#[derive(Clone, Copy)]
struct Regs(*mut u32);

impl Regs {
    fn transmitter_is_full(&self) -> bool {
        self.read(UFSTAT) & UFSTAT_TX_FIFO_FULL != 0
    }

    fn has_received(&self) -> bool {
        self.read(UFSTAT) & UFSTAT_RX_FIFO_COUNT != 0
    }

    fn receive(&self) -> u8 {
        self.read(URXH) as u8
    }

    fn read(&self, offset: usize) -> u32 {
        unsafe { ptr::read_volatile(self.0.byte_add(offset)) }
    }

    fn write(&self, offset: usize, value: u32) {
        unsafe { ptr::write_volatile(self.0.byte_add(offset), value) }
    }
}

const FRAME_LENGTH_SIZE: usize = 4;

const REGS_SIZE: u64 = 0x4000;
const UCON: usize = 0x04;
const UFCON: usize = 0x08;
const UTRSTAT: usize = 0x10;
const UFSTAT: usize = 0x18;
const UTXH: usize = 0x20;
const URXH: usize = 0x24;

const UCON_TXTHRESH_ENA: u32 = 1 << 13;

const UFCON_FIFO_ENABLE: u32 = 1 << 0;
const UFCON_RX_FIFO_RESET: u32 = 1 << 1;
const UFCON_TX_FIFO_RESET: u32 = 1 << 2;

const UTRSTAT_TX_THRESH: u32 = 1 << 5;

const UFSTAT_RX_FIFO_COUNT: u32 = 0xf;
const UFSTAT_TX_FIFO_FULL: u32 = 1 << 9;
