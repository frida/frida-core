use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::gum::gum_barebone_query_page_size;
use crate::xnu;

const MMIO_SIZE: u64 = 0x200;

static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

const QSZ: u16 = 64;

const MAGIC: usize = 0x000;
const VERSION: usize = 0x004;
const DEVICE: usize = 0x008;
const STATUS: usize = 0x070;

const DEVFEAT: usize = 0x010;
const DEVFEAT_SEL: usize = 0x014;
const DRVFEAT: usize = 0x020;
const DRVFEAT_SEL: usize = 0x024;

const QSEL: usize = 0x030;
const QNUM_MAX: usize = 0x034;
const QNUM: usize = 0x038;
const QREADY: usize = 0x044;

const QDESC_LO: usize = 0x080;
const QDESC_HI: usize = 0x084;
const QAVAIL_LO: usize = 0x090;
const QAVAIL_HI: usize = 0x094;
const QUSED_LO: usize = 0x0a0;
const QUSED_HI: usize = 0x0a4;

const QNOTIFY: usize = 0x050;
const ISR: usize = 0x060;
const ISR_ACK: usize = 0x064;

const ST_ACK: u32 = 1;
const ST_DRV: u32 = 2;
const ST_DRV_OK: u32 = 4;
const ST_FEAT_OK: u32 = 8;
const ST_FAILED: u32 = 0x80;

const DEV_ID_CONSOLE: u32 = 3;
const F_VERSION_1: u64 = 1u64 << 32;
const F_MULTIPORT: u64 = 1u64 << 1;

const INT_VRING: u32 = 1;

const Q_RX0: u16 = 0;
const Q_TX0: u16 = 1;
const Q_CTRL_RX: u16 = 2;
const Q_CTRL_TX: u16 = 3;

#[repr(C)]
#[derive(Copy, Clone)]
struct VConsCtrl {
    id: u32,
    event: u16,
    value: u16,
}
const EV_DEVICE_READY: u16 = 0;
const EV_DEVICE_ADD: u16 = 1;
const EV_PORT_READY: u16 = 3;
const EV_PORT_OPEN: u16 = 6;
const EV_CONSOLE_PORT: u16 = 4;

#[repr(C)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}
const D_NEXT: u16 = 1;
const D_WRITE: u16 = 2;

#[repr(C)]
#[derive(Copy, Clone)]
struct Avail {
    flags: u16,
    idx: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct UsedElem {
    id: u32,
    len: u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
struct Used {
    flags: u16,
    idx: u16,
}

#[derive(Copy, Clone)]
struct DmaPage {
    va: *mut u8,
    pa: u64,
}

fn dma_page_alloc() -> DmaPage {
    let len = PAGE_SIZE.load(Ordering::Relaxed);
    let va = xnu::kalloc(len);
    let pa = xnu::ml_vtophys(va as u64);
    DmaPage { va, pa }
}

fn dma_page_free(p: DmaPage) {
    let len = PAGE_SIZE.load(Ordering::Relaxed);
    xnu::free(p.va, len);
}

struct Vq {
    sel: u16,
    size: u16,
    desc_va: *mut u8,
    avail_va: *mut u8,
    used_va: *mut u8,
    avail_idx: u16,
    used_idx: u16,
    free_head: u16,
    free_cnt: u16,
}
impl Vq {
    fn new(mmio: *mut u8, sel: u16, size: u16) -> Self {
        w32(mmio, QSEL, sel as u32);
        let max = r32(mmio, QNUM_MAX) as u16;
        debug_assert!(max >= size && max != 0);
        w32(mmio, QNUM, size as u32);

        let d = dma_page_alloc();
        let a = dma_page_alloc();
        let u = dma_page_alloc();

        let ps = PAGE_SIZE.load(core::sync::atomic::Ordering::Relaxed);
        unsafe {
            core::ptr::write_bytes(d.va, 0, ps);
            core::ptr::write_bytes(a.va, 0, ps);
            core::ptr::write_bytes(u.va, 0, ps);
        }

        w64(mmio, QDESC_LO, QDESC_HI, d.pa);
        w64(mmio, QAVAIL_LO, QAVAIL_HI, a.pa);
        w64(mmio, QUSED_LO, QUSED_HI, u.pa);

        let dp = d.va as *mut Desc;
        for i in 0..size {
            unsafe {
                (*dp.add(i as usize)).flags = 0;
                (*dp.add(i as usize)).next = if i + 1 < size { i + 1 } else { 0xFFFF };
            }
        }

        w32(mmio, QREADY, 1);

        Self {
            sel,
            size,
            desc_va: d.va,
            avail_va: a.va,
            used_va: u.va,
            avail_idx: 0,
            used_idx: 0,
            free_head: 0,
            free_cnt: size,
        }
    }

    fn alloc(&mut self) -> u16 {
        debug_assert!(self.free_cnt > 0);
        let h = self.free_head;
        let dp = self.desc_va as *mut Desc;
        unsafe {
            self.free_head = (*dp.add(h as usize)).next;
        }
        self.free_cnt -= 1;
        h
    }

    fn free_chain(&mut self, mut idx: u16) {
        let dp = self.desc_va as *mut Desc;
        loop {
            self.free_cnt += 1;
            let (flags, next) = unsafe {
                let p = dp.add(idx as usize);
                ((*p).flags, (*p).next)
            };
            if (flags & D_NEXT) == 0 {
                break;
            }
            idx = next;
        }
        unsafe {
            (*dp.add(idx as usize)).next = self.free_head;
        }
        self.free_head = idx;
    }

    fn push_avail(&mut self, head: u16) {
        let ap = self.avail_va as *mut Avail;
        let ring = unsafe { (ap as *mut u8).add(size_of::<Avail>()) as *mut u16 };
        let slot = (self.avail_idx % self.size) as usize;
        unsafe {
            *ring.add(slot) = head;
        }
        wmb();
        self.avail_idx = self.avail_idx.wrapping_add(1);
        unsafe {
            (*ap).idx = self.avail_idx;
        }
    }

    fn pop_used(&mut self) -> Option<UsedElem> {
        let up = self.used_va as *mut Used;
        if unsafe { (*up).idx } == self.used_idx {
            return None;
        }
        let ring = unsafe { (up as *mut u8).add(size_of::<Used>()) as *mut UsedElem };
        let elem = unsafe { *ring.add((self.used_idx % self.size) as usize) };
        self.used_idx = self.used_idx.wrapping_add(1);
        Some(elem)
    }
}

struct Inner {
    mmio: *mut u8,

    ctrl_rx: Vq,
    ctrl_tx: Vq,

    port_id: Option<u32>,
    rx: Option<Vq>,
    tx: Option<Vq>,

    rx_need: usize,
    rx_have: usize,
    rx_lenbuf: [u8; 4],
    rx_lenhave: usize,
    rx_buf: Option<&'static mut [u8]>,

    tx_head: *mut TxNode,
    tx_tail: *mut TxNode,

    ctrl_rx_pages: [Option<DmaPage>; QSZ as usize],
    data_rx_pages: [Option<DmaPage>; QSZ as usize],
    tx_pages: [Option<DmaPage>; QSZ as usize],

    wake_token: *const u8,

    on_rx: Option<fn(&[u8])>,
}

#[repr(C)]
struct TxNode {
    next: *mut TxNode,
    frame: &'static [u8],
}

pub struct Hostlink {
    state: UnsafeCell<Inner>,
}

unsafe impl Send for Hostlink {}

impl Hostlink {
    pub fn init(mmio_base: u64, irq_line: u32, on_rx: Option<fn(&[u8])>, wake_token: *const u8) -> Result<Self, ()> {
        let page_size = gum_barebone_query_page_size();
        PAGE_SIZE.store(page_size as usize, Ordering::Relaxed);

        let mmio = xnu::ml_io_map(mmio_base, MMIO_SIZE) as *mut u8;
        if mmio.is_null() {
            return Err(());
        }

        w32(mmio, STATUS, 0);
        w32(mmio, STATUS, ST_ACK | ST_DRV);

        let magic_ok = r32(mmio, MAGIC) == 0x7472_6976;
        let version_ok = r32(mmio, VERSION) == 2;
        let device_ok = r32(mmio, DEVICE) == DEV_ID_CONSOLE;
        if !(magic_ok && version_ok && device_ok) {
            w32(mmio, STATUS, ST_FAILED);
            return Err(());
        }

        let dev_lo = feat_get(mmio, 0) as u64;
        let dev_hi = (feat_get(mmio, 1) as u64) << 32;
        let mut drv: u64 = 0;
        if (dev_hi & F_VERSION_1) != 0 {
            drv |= F_VERSION_1;
        }
        if (dev_lo & F_MULTIPORT) != 0 {
            drv |= F_MULTIPORT;
        }
        feat_set(mmio, 0, (drv & 0xffff_ffff) as u32);
        feat_set(mmio, 1, (drv >> 32) as u32);
        w32(mmio, STATUS, r32(mmio, STATUS) | ST_FEAT_OK);
        let feats_ok = (r32(mmio, STATUS) & ST_FEAT_OK) != 0;
        if !feats_ok {
            w32(mmio, STATUS, ST_FAILED);
            return Err(());
        }

        let ctrl_rx = Vq::new(mmio, Q_CTRL_RX, QSZ);
        let ctrl_tx = Vq::new(mmio, Q_CTRL_TX, QSZ);

        w32(mmio, STATUS, r32(mmio, STATUS) | ST_DRV_OK);

        xnu::install_interrupt_handler(
            irq_line,
            wake_token as *mut c_void,
            isr_wake,
            core::ptr::null_mut(),
        );

        let inner = Inner {
            mmio,
            ctrl_rx,
            ctrl_tx,
            port_id: None,
            rx: None,
            tx: None,
            rx_need: 0,
            rx_have: 0,
            rx_lenbuf: [0; 4],
            rx_lenhave: 0,
            rx_buf: None,
            tx_head: core::ptr::null_mut(),
            tx_tail: core::ptr::null_mut(),
            ctrl_rx_pages: [None; QSZ as usize],
            data_rx_pages: [None; QSZ as usize],
            tx_pages: [None; QSZ as usize],
            wake_token,
            on_rx,
        };

        let hl = Hostlink {
            state: UnsafeCell::new(inner),
        };

        hl.ctrl_prime_rx(8);
        hl.ctrl_send(VConsCtrl {
            id: 0,
            event: EV_DEVICE_READY,
            value: 1,
        });

        Ok(hl)
    }

    pub fn send(&self, payload: &[u8]) {
        let s = unsafe { &mut *self.state.get() };

        let total = 4 + payload.len();
        let buf = xnu::kalloc(total);
        unsafe {
            let len = payload.len() as u32;
            *buf.add(0) = (len & 0xFF) as u8;
            *buf.add(1) = ((len >> 8) & 0xFF) as u8;
            *buf.add(2) = ((len >> 16) & 0xFF) as u8;
            *buf.add(3) = ((len >> 24) & 0xFF) as u8;
            core::ptr::copy_nonoverlapping(payload.as_ptr(), buf.add(4), payload.len());
        }
        let frame: &'static [u8] = unsafe { core::slice::from_raw_parts(buf, total) };

        let node = xnu::kalloc(size_of::<TxNode>()) as *mut TxNode;
        unsafe {
            (*node).next = core::ptr::null_mut();
            (*node).frame = frame;
        }

        if s.tx_tail.is_null() {
            s.tx_head = node;
            s.tx_tail = node;
        } else {
            unsafe {
                (*s.tx_tail).next = node;
            }
            s.tx_tail = node;
        }

        xnu::thread_wakeup(s.wake_token);
    }

    pub fn process(&self) {
        let s = unsafe { &mut *self.state.get() };

        if (r32(s.mmio, ISR) & INT_VRING) != 0 {
            w32(s.mmio, ISR_ACK, INT_VRING);
        }

        self.ctrl_complete();
        self.ctrl_prime_rx(QSZ as usize);

        self.data_rx_complete();
        self.data_tx_complete();
        self.data_tx_push();
        self.data_rx_refill();
    }

    fn ctrl_prime_rx(&self, count: usize) {
        let s = unsafe { &mut *self.state.get() };
        let mut posted = 0usize;
        while posted < count {
            if s.ctrl_rx.free_cnt == 0 {
                break;
            }
            let pg = dma_page_alloc();
            let h = s.ctrl_rx.alloc();
            let d = s.ctrl_rx.desc_va as *mut Desc;
            unsafe {
                (*d.add(h as usize)).addr = pg.pa;
                (*d.add(h as usize)).len = PAGE_SIZE.load(Ordering::Relaxed) as u32;
                (*d.add(h as usize)).flags = D_WRITE;
                (*d.add(h as usize)).next = 0;
            }
            s.ctrl_rx_pages[h as usize] = Some(pg);
            s.ctrl_rx.push_avail(h);
            posted += 1;
        }
        let sel = s.ctrl_rx.sel;
        self.kick(sel);
    }

    fn ctrl_send(&self, msg: VConsCtrl) {
        let s = unsafe { &mut *self.state.get() };
        let pg = dma_page_alloc();
        unsafe {
            core::ptr::write(pg.va as *mut VConsCtrl, msg);
        }
        let h = s.ctrl_tx.alloc();
        let d = s.ctrl_tx.desc_va as *mut Desc;
        unsafe {
            (*d.add(h as usize)).addr = pg.pa;
            (*d.add(h as usize)).len = size_of::<VConsCtrl>() as u32;
            (*d.add(h as usize)).flags = 0;
            (*d.add(h as usize)).next = 0;
        }
        s.tx_pages[h as usize] = Some(pg);
        s.ctrl_tx.push_avail(h);
        let sel = s.ctrl_tx.sel;
        self.kick(sel);
    }

    fn ctrl_complete(&self) {
        let s = unsafe { &mut *self.state.get() };
        while let Some(u) = s.ctrl_rx.pop_used() {
            let h = u.id as u16;
            if let Some(pg) = s.ctrl_rx_pages[h as usize].take() {
                let ev = unsafe { *(pg.va as *const VConsCtrl) };
                dma_page_free(pg);

                match ev.event {
                    EV_DEVICE_ADD | EV_CONSOLE_PORT => {
                        if s.port_id.is_none() {
                            self.setup_data_port(ev.id);
                            self.ctrl_send(VConsCtrl {
                                id: ev.id,
                                event: EV_PORT_READY,
                                value: 1,
                            });
                            self.ctrl_send(VConsCtrl {
                                id: ev.id,
                                event: EV_PORT_OPEN,
                                value: 1,
                            });
                        }
                    }
                    _ => {}
                }

                let pg2 = dma_page_alloc();
                let d = s.ctrl_rx.desc_va as *mut Desc;
                unsafe {
                    (*d.add(h as usize)).addr = pg2.pa;
                    (*d.add(h as usize)).len = PAGE_SIZE.load(Ordering::Relaxed) as u32;
                    (*d.add(h as usize)).flags = D_WRITE;
                    (*d.add(h as usize)).next = 0;
                }
                s.ctrl_rx_pages[h as usize] = Some(pg2);
                s.ctrl_rx.push_avail(h);
            }
        }
        let sel = s.ctrl_rx.sel;
        self.kick(sel);

        while let Some(u) = s.ctrl_tx.pop_used() {
            let head = u.id as u16;
            if let Some(pg) = s.tx_pages[head as usize].take() {
                dma_page_free(pg);
            }
            s.ctrl_tx.free_chain(head);
        }
    }

    fn setup_data_port(&self, id: u32) {
        let s = unsafe { &mut *self.state.get() };
        if s.port_id.is_some() {
            return;
        }
        let (rx_i, tx_i) = if id == 0 {
            (Q_RX0, Q_TX0)
        } else {
            let base = 4 + ((id as u16 - 1) * 2);
            (base, base + 1)
        };
        let rx = Vq::new(s.mmio, rx_i, QSZ);
        let tx = Vq::new(s.mmio, tx_i, QSZ);
        s.rx = Some(rx);
        s.tx = Some(tx);
        s.port_id = Some(id);
        self.data_rx_refill();
    }

    fn data_rx_refill(&self) {
        let s = unsafe { &mut *self.state.get() };
        let Some(rxq) = s.rx.as_mut() else {
            return;
        };
        while rxq.free_cnt > 0 {
            let h = rxq.alloc();
            let pg = dma_page_alloc();
            let d = rxq.desc_va as *mut Desc;
            unsafe {
                (*d.add(h as usize)).addr = pg.pa;
                (*d.add(h as usize)).len = PAGE_SIZE.load(Ordering::Relaxed) as u32;
                (*d.add(h as usize)).flags = D_WRITE;
                (*d.add(h as usize)).next = 0;
            }
            s.data_rx_pages[h as usize] = Some(pg);
            rxq.push_avail(h);
        }
        let sel = rxq.sel;
        self.kick(sel);
    }

    fn data_rx_complete(&self) {
        let s = unsafe { &mut *self.state.get() };
        let Some(rxq) = s.rx.as_mut() else {
            return;
        };
        while let Some(u) = rxq.pop_used() {
            let h = u.id as u16;
            let n = u.len as usize;

            if let Some(pg) = s.data_rx_pages[h as usize].take() {
                {
                    let bytes = unsafe { core::slice::from_raw_parts(pg.va, n) };
                    self.feed_rx_stream(bytes);
                }
                dma_page_free(pg);

                let pg2 = dma_page_alloc();
                let d = rxq.desc_va as *mut Desc;
                unsafe {
                    (*d.add(h as usize)).addr = pg2.pa;
                    (*d.add(h as usize)).len = PAGE_SIZE.load(Ordering::Relaxed) as u32;
                    (*d.add(h as usize)).flags = D_WRITE;
                    (*d.add(h as usize)).next = 0;
                }
                s.data_rx_pages[h as usize] = Some(pg2);
                rxq.push_avail(h);
            }
        }
        let sel = rxq.sel;
        self.kick(sel);
    }

    fn feed_rx_stream(&self, mut chunk: &[u8]) {
        let s = unsafe { &mut *self.state.get() };
        while !chunk.is_empty() {
            if s.rx_lenhave < 4 {
                let need = 4 - s.rx_lenhave;
                let take = core::cmp::min(need, chunk.len());
                s.rx_lenbuf[s.rx_lenhave..s.rx_lenhave + take].copy_from_slice(&chunk[..take]);
                s.rx_lenhave += take;
                chunk = &chunk[take..];
                if s.rx_lenhave < 4 {
                    return;
                }

                let len = (s.rx_lenbuf[0] as usize)
                    | ((s.rx_lenbuf[1] as usize) << 8)
                    | ((s.rx_lenbuf[2] as usize) << 16)
                    | ((s.rx_lenbuf[3] as usize) << 24);

                if s.rx_buf.is_none() && len > 0 {
                    let buf = xnu::kalloc(len);
                    let slice: &'static mut [u8] =
                        unsafe { core::slice::from_raw_parts_mut(buf, len) };
                    s.rx_buf = Some(slice);
                    s.rx_need = len;
                    s.rx_have = 0;
                }
            }

            let need = s.rx_need.saturating_sub(s.rx_have);
            let take = core::cmp::min(need, chunk.len());
            if let Some(ref mut buf) = s.rx_buf {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        chunk.as_ptr(),
                        buf.as_mut_ptr().wrapping_add(s.rx_have),
                        take,
                    );
                }
            }
            s.rx_have += take;
            chunk = &chunk[take..];

            if s.rx_have == s.rx_need {
                if let (Some(cb), Some(buf)) = (s.on_rx, &s.rx_buf) {
                    cb(&buf[..]);
                }
                s.rx_buf = None;
                s.rx_need = 0;
                s.rx_have = 0;
                s.rx_lenhave = 0;
            }
        }
    }

    fn data_tx_complete(&self) {
        let s = unsafe { &mut *self.state.get() };
        let Some(txq) = s.tx.as_mut() else {
            return;
        };
        while let Some(u) = txq.pop_used() {
            let mut i = u.id as u16;
            loop {
                if let Some(pg) = s.tx_pages[i as usize].take() {
                    dma_page_free(pg);
                }
                let d = txq.desc_va as *mut Desc;
                let (f, n) = unsafe {
                    let p = d.add(i as usize);
                    ((*p).flags, (*p).next)
                };
                if (f & D_NEXT) == 0 {
                    break;
                }
                i = n;
            }
            txq.free_chain(u.id as u16);
        }
    }

    fn data_tx_push(&self) {
        let s = unsafe { &mut *self.state.get() };
        let Some(txq) = s.tx.as_mut() else {
            return;
        };
        loop {
            let node = if s.tx_head.is_null() {
                core::ptr::null_mut()
            } else {
                let n = s.tx_head;
                s.tx_head = unsafe { (*n).next };
                if s.tx_head.is_null() {
                    s.tx_tail = core::ptr::null_mut();
                }
                n
            };
            if node.is_null() {
                break;
            }
            let frame = unsafe { (*node).frame };

            let mut off = 0usize;
            let mut head: Option<u16> = None;
            let mut prev = 0u16;

            while off < frame.len() {
                if txq.free_cnt == 0 {
                    break;
                }
                let page = PAGE_SIZE.load(Ordering::Relaxed);
                let chunk = core::cmp::min(page, frame.len() - off);
                let pg = dma_page_alloc();
                unsafe {
                    core::ptr::copy_nonoverlapping(frame.as_ptr().add(off), pg.va, chunk);
                }

                let i = txq.alloc();
                let d = txq.desc_va as *mut Desc;
                unsafe {
                    (*d.add(i as usize)).addr = pg.pa;
                    (*d.add(i as usize)).len = chunk as u32;
                    (*d.add(i as usize)).flags = 0;
                    (*d.add(i as usize)).next = 0;
                }
                s.tx_pages[i as usize] = Some(pg);

                if let Some(_h) = head {
                    unsafe {
                        (*d.add(prev as usize)).flags |= D_NEXT;
                        (*d.add(prev as usize)).next = i;
                    }
                    prev = i;
                } else {
                    head = Some(i);
                    prev = i;
                }

                off += chunk;
            }

            if let Some(h) = head {
                let sel = txq.sel;
                txq.push_avail(h);
                self.kick(sel);
            }

            xnu::free(frame.as_ptr() as *mut u8, frame.len());
            xnu::free(node as *mut u8, core::mem::size_of::<TxNode>());
        }
    }

    fn kick(&self, sel: u16) {
        let s = unsafe { &*self.state.get() };
        wmb();
        w32(s.mmio, QSEL, sel as u32);
        w32(s.mmio, QNOTIFY, sel as u32);
    }
}

extern "C" fn isr_wake(token: *mut c_void, _refcon: *mut c_void, _nub: *mut c_void, _src: i32) {
    xnu::thread_wakeup(token as *const u8);
}

fn r32(mmio: *mut u8, off: usize) -> u32 {
    unsafe { read_volatile(mmio.add(off) as *const u32) }
}

fn w32(mmio: *mut u8, off: usize, val: u32) {
    unsafe { write_volatile(mmio.add(off) as *mut u32, val) }
}

fn w64(mmio: *mut u8, lo: usize, hi: usize, v: u64) {
    w32(mmio, lo, (v & 0xffff_ffff) as u32);
    w32(mmio, hi, (v >> 32) as u32);
}

fn feat_get(mmio: *mut u8, sel: u32) -> u32 {
    w32(mmio, DEVFEAT_SEL, sel);
    r32(mmio, DEVFEAT)
}

fn feat_set(mmio: *mut u8, sel: u32, v: u32) {
    w32(mmio, DRVFEAT_SEL, sel);
    w32(mmio, DRVFEAT, v)
}

fn wmb() {
    unsafe { core::arch::asm!("dmb ishst", options(nostack, preserves_flags)) }
}
