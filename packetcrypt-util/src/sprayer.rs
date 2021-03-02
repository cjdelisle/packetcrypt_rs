// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::protocol::SprayerReq;
use crate::util;
use anyhow::{Context, Result};
use log::{debug, info, warn};
use socket2::Socket;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::atomic::{self, AtomicUsize};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

// 200MB incoming buffer per thread
const INCOMING_BUF_ANN_PER_THREAD: usize = 200 * 1024;

// Don't callback until we have at least this many anns
const ANNS_TO_ACCUMULATE: usize = 50 * 1024;

// 128MB shared outgoing buffer
const MAX_SEND_QUEUE: usize = 256 * 1024;

// 256k per send batch
const SEND_CHUNK_SZ: usize = 256;

// How long a node doesn't send a subscription update before we stop flooding them
const SECONDS_UNTIL_SUB_TIMEOUT: usize = 30;

// How often to resend subscriptions
const SECONDS_UNTIL_RESUB: usize = 5;

const STATS_EVERY: usize = 10;

const RECV_BUF_SZ: usize = 1 << 26;

pub const MSG_PREFIX: usize = 8;
pub const MSG_TOTAL_LEN: usize = 1024 + MSG_PREFIX;

#[derive(Clone)]
pub struct Packet {
    peer: SocketAddr,
    len: usize,
    bytes: [u8; MSG_TOTAL_LEN],
}
impl Packet {
    pub fn ann_bytes(&self) -> Option<&[u8]> {
        if self.len == MSG_TOTAL_LEN {
            Some(&self.bytes[MSG_PREFIX..])
        } else {
            None
        }
    }
    pub fn ann_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[MSG_PREFIX..]
    }
}
impl Default for Packet {
    fn default() -> Packet {
        Packet {
            peer: SocketAddr::new([127, 0, 0, 1].into(), 0),
            len: 0,
            bytes: [0_u8; MSG_TOTAL_LEN],
        }
    }
}

struct Subscriber {
    peer: SocketAddr,
    num: u32,
    count: u32,
    last_update_sec: AtomicUsize,
    packets_sent: AtomicUsize,
}

struct Subscription {
    peer: SocketAddr,
    last_update_sec: AtomicUsize,
    packets_received: AtomicUsize,
}

struct SprayerMut {
    subscribers: Vec<Subscriber>,
}

pub trait OnAnns: Send + Sync {
    fn on_anns(&self, anns: &[Packet]);
}
// So you can pass None
impl<T: Send + Sync> OnAnns for Option<T> {
    fn on_anns(&self, _anns: &[Packet]) {}
}

struct PeerCounters {
    last_logged_ms: u64,
    last_packets_recv: usize,
    last_packets_sent: usize,
}
#[derive(Clone)]
pub struct PeerStats {
    pub peer: SocketAddr,
    pub kbps_in: f64,
    pub kbps_out: f64,
    pub packets_in: u64,
    pub packets_out: u64,
}

struct SprayerS {
    m: RwLock<SprayerMut>,
    send_queue: Mutex<VecDeque<Packet>>,
    passwd: String,
    socket: socket2::Socket,
    handler: RwLock<Option<Box<dyn OnAnns>>>,
    subscribed_to: Vec<Subscription>,
    workers: usize,
    last_computed_stats: AtomicUsize,
    peer_counters: Mutex<HashMap<SocketAddr, PeerCounters>>,
    peer_stats: Mutex<Vec<PeerStats>>,
    log_peer_stats: bool,
}
pub struct Sprayer(Arc<SprayerS>);

fn compute_kbps(packets_sent: u64, ms_elapsed: u64) -> f64 {
    // consider the headers here
    let bits_sent = packets_sent * (MSG_TOTAL_LEN as u64 + 8 + 20 + 14) * 8;
    // bits per millisecond = kilobits per second
    bits_sent as f64 / ms_elapsed as f64
}

pub struct Config {
    pub passwd: String,
    pub bind: String,
    pub workers: usize,
    pub subscribe_to: Vec<String>,
    pub always_send_all: bool,
    pub log_peer_stats: bool,
}

impl Sprayer {
    pub fn new(cfg: &Config) -> Result<Sprayer> {
        let addr: SocketAddr = cfg
            .bind
            .parse()
            .with_context(|| format!("SocketAddr parse({})", cfg.bind))?;
        let socket = UdpSocket::bind(addr).with_context(|| format!("UdpSocket::bind({})", addr))?;
        socket.set_nonblocking(true)?;
        let s = Socket::from(socket);
        if let Err(e) = s.set_recv_buffer_size(RECV_BUF_SZ) {
            warn!(
                "Unable to set SO_RCVBUF to {}: {} - expect packet loss at high load",
                RECV_BUF_SZ, e
            );
        }

        let m = RwLock::new(SprayerMut {
            subscribers: Vec::new(),
        });
        let send_queue = Mutex::new(VecDeque::new());
        let mut subs = Vec::with_capacity(cfg.subscribe_to.len());
        for s in &cfg.subscribe_to {
            subs.push(s.parse()?);
        }
        Ok(Sprayer(Arc::new(SprayerS {
            m,
            subscribed_to: subs
                .iter()
                .map(|peer| Subscription {
                    peer: *peer,
                    last_update_sec: AtomicUsize::new(0),
                    packets_received: AtomicUsize::new(0),
                })
                .collect(),
            send_queue,
            passwd: cfg.passwd.clone(),
            socket: s,
            workers: cfg.workers,
            handler: RwLock::new(None),
            last_computed_stats: AtomicUsize::new(0),
            peer_counters: Mutex::new(HashMap::new()),
            peer_stats: Mutex::new(Vec::new()),
            log_peer_stats: cfg.log_peer_stats,
        })))
    }

    pub fn set_handler<T: 'static + OnAnns>(&self, handler: T) {
        self.0.handler.write().unwrap().replace(Box::new(handler));
    }

    pub fn push_anns(&self, anns: &[Packet]) -> usize {
        let oldest_allowed_time = (util::now_ms() / 1000) as usize - SECONDS_UNTIL_SUB_TIMEOUT;
        let m = self.0.m.read().unwrap();
        let mut sq = self.0.send_queue.lock().unwrap();
        let mut overflow = 0;
        for ann in anns {
            for s in &m.subscribers {
                let lus = s.last_update_sec.load(atomic::Ordering::Relaxed);
                if lus < oldest_allowed_time {
                    continue;
                }
                if sq.len() >= MAX_SEND_QUEUE {
                    sq.pop_front();
                    overflow += 1;
                }
                let mut ts = ann.clone();
                ts.peer = s.peer;
                let number = s.packets_sent.fetch_add(1, atomic::Ordering::Relaxed) as u64;
                ts.bytes[0..MSG_PREFIX].copy_from_slice(&number.to_le_bytes());
                sq.push_back(ts);
            }
        }
        overflow
    }

    pub fn start(&self) {
        for tid in 0..self.0.workers {
            let g = Sprayer(Arc::clone(&self.0));
            std::thread::spawn(move || {
                Box::new(SprayWorker {
                    g,
                    rbuf: vec![Packet::default(); INCOMING_BUF_ANN_PER_THREAD],
                    sbuf: vec![Packet::default(); SEND_CHUNK_SZ],
                    rindex: 0,
                    time_of_last_log: AtomicUsize::new(0),
                    tid,
                })
                .run();
            });
        }
    }

    fn get_to_send(&self, send: &mut [Packet]) -> usize {
        let mut sql = self.0.send_queue.lock().unwrap();
        let mut i = 0;
        for s in send {
            match sql.pop_front() {
                Some(x) => {
                    *s = x;
                    i += 1;
                }
                None => break,
            }
        }
        i
    }

    fn return_to_send(&self, send: &[Packet]) {
        let mut sql = self.0.send_queue.lock().unwrap();
        for s in send {
            sql.push_front(s.clone());
        }
    }

    fn send_subs(&self) -> Option<(std::io::Error, SocketAddr)> {
        let now_sec = (util::now_ms() / 1000) as usize;
        let update_time = now_sec - SECONDS_UNTIL_RESUB;
        for (sub, num) in self.0.subscribed_to.iter().zip(0..) {
            let time_sec = sub.last_update_sec.load(atomic::Ordering::Relaxed);
            if time_sec > update_time {
                continue;
            }
            let req = serde_json::to_string(&SprayerReq {
                yes_please_dos_me_passwd: self.0.passwd.clone(),
                num,
                count: self.0.subscribed_to.len() as u32,
            })
            .unwrap();
            debug!("subscribing to {}", sub.peer);
            if let Err(e) = self
                .0
                .socket
                .send_to(&req.as_bytes(), &socket2::SockAddr::from(sub.peer))
            {
                return Some((e, sub.peer));
            }
            sub.last_update_sec
                .store(now_sec, atomic::Ordering::Relaxed);
        }
        None
    }

    #[allow(clippy::if_same_then_else)] // dumb rule
    fn incoming_subscription(&self, from: SocketAddr, req: SprayerReq) {
        let now_sec = (util::now_ms() / 1000) as usize;
        let oldest_allowed_time = now_sec - SECONDS_UNTIL_SUB_TIMEOUT;
        {
            let m = self.0.m.read().unwrap();
            for s in &m.subscribers {
                if s.peer != from {
                } else if s.num != req.num {
                } else if s.count != req.count {
                } else {
                    s.last_update_sec.store(now_sec, atomic::Ordering::Relaxed);
                    return;
                }
            }
        }
        {
            let mut m = self.0.m.write().unwrap();
            let mut i = 0;
            while i < m.subscribers.len() {
                let s = &mut m.subscribers[i];
                if s.peer == from {
                    s.num = req.num;
                    s.count = req.count;
                    s.last_update_sec.store(now_sec, atomic::Ordering::Relaxed);
                    return;
                }
                // Remove entries which are expired at the same time...
                if s.last_update_sec.load(atomic::Ordering::Relaxed) < oldest_allowed_time {
                    m.subscribers.remove(i);
                } else {
                    i += 1;
                }
            }
            m.subscribers.push(Subscriber {
                peer: from,
                num: req.num,
                count: req.count,
                last_update_sec: AtomicUsize::new(now_sec),
                packets_sent: AtomicUsize::new(0),
            });
        }
    }

    pub fn get_peer_stats(&self) -> Vec<PeerStats> {
        let now_ms = util::now_ms();
        let now_sec = (now_ms / 1000) as usize;
        let last_computed_stats = self.0.last_computed_stats.load(atomic::Ordering::Relaxed);
        if last_computed_stats + STATS_EVERY > now_sec {
            return self.0.peer_stats.lock().unwrap().clone();
        }
        self.0
            .last_computed_stats
            .store(now_sec, atomic::Ordering::Relaxed);

        let mut ps = self.0.peer_counters.lock().unwrap();
        let m = self.0.m.read().unwrap();
        let mut peer_stats = Vec::new();
        if self.0.log_peer_stats {
            info!("Sprayer links:");
        }
        for sub in &m.subscribers {
            match ps.get_mut(&sub.peer) {
                Some(p) => {
                    let packets_sent_ever = sub.packets_sent.load(atomic::Ordering::Relaxed);
                    let packets = (packets_sent_ever - p.last_packets_sent) as u64;
                    let ms = now_ms - p.last_logged_ms;
                    let st = PeerStats {
                        peer: sub.peer,
                        packets_out: packets,
                        kbps_out: compute_kbps(packets, ms),
                        packets_in: 0,
                        kbps_in: 0.0,
                    };
                    if self.0.log_peer_stats {
                        info!(
                            "{} <- anns: {} {}",
                            sub.peer,
                            packets,
                            util::format_kbps(st.kbps_out)
                        );
                    }
                    peer_stats.push(st);
                    p.last_logged_ms = now_ms;
                    p.last_packets_sent = packets_sent_ever;
                }
                None => {
                    ps.insert(
                        sub.peer,
                        PeerCounters {
                            last_logged_ms: now_ms,
                            last_packets_sent: sub.packets_sent.load(atomic::Ordering::Relaxed),
                            last_packets_recv: 0,
                        },
                    );
                }
            }
        }
        for sub in &self.0.subscribed_to {
            match ps.get_mut(&sub.peer) {
                Some(p) => {
                    let packets_recv_ever = sub.packets_received.load(atomic::Ordering::Relaxed);
                    let packets = (packets_recv_ever - p.last_packets_recv) as u64;
                    let ms = now_ms - p.last_logged_ms;
                    let st = PeerStats {
                        peer: sub.peer,
                        kbps_in: compute_kbps(packets, ms),
                        kbps_out: 0.0,
                        packets_in: packets,
                        packets_out: 0,
                    };
                    if self.0.log_peer_stats {
                        info!(
                            "{} -> {} ({})",
                            sub.peer,
                            util::big_number(packets as f64),
                            util::format_kbps(st.kbps_in)
                        );
                    }
                    peer_stats.push(st);
                    p.last_logged_ms = now_ms;
                    p.last_packets_recv = sub.packets_received.load(atomic::Ordering::Relaxed);
                }
                None => {
                    ps.insert(
                        sub.peer,
                        PeerCounters {
                            last_logged_ms: now_ms,
                            last_packets_recv: sub.packets_received.load(atomic::Ordering::Relaxed),
                            last_packets_sent: 0,
                        },
                    );
                }
            }
        }
        *self.0.peer_stats.lock().unwrap() = peer_stats.clone();
        peer_stats
    }
}

struct SprayWorker {
    g: Sprayer,
    rbuf: Vec<Packet>,
    sbuf: Vec<Packet>,
    time_of_last_log: AtomicUsize,
    tid: usize,
    rindex: usize,
}

impl SprayWorker {
    fn log(&self, f: &dyn Fn()) -> bool {
        let now = util::now_ms() as usize;
        if now > self.time_of_last_log.load(atomic::Ordering::Relaxed) + 1000 {
            f();
            self.time_of_last_log.store(now, atomic::Ordering::Relaxed);
            true
        } else {
            false
        }
    }
    fn try_send(&mut self) {
        if self.tid == 0 {
            if let Some((e, to)) = self.g.send_subs() {
                self.log(&|| info!("Error sending subscription to {}: {}", to, e));
            }
        }
        loop {
            let count = self.g.get_to_send(&mut self.sbuf);
            if count == 0 {
                return;
            }
            for i in 0..count {
                match self.g.0.socket.send_to(
                    &self.sbuf[i].bytes[..],
                    &socket2::SockAddr::from(self.sbuf[i].peer),
                ) {
                    Ok(l) => {
                        if l == MSG_TOTAL_LEN {
                            continue;
                        }
                        self.log(&|| info!("Sending to sprayer socket length {}", l));
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            self.log(&|| info!("Error sending to sprayer socket {}", e));
                        } else {
                            self.log(&|| debug!("Send got EWOULDBLOCK"));
                        }
                    }
                }
                self.g.return_to_send(&self.sbuf[i..count]);
                return;
            }
        }
    }
    fn maybe_subscribe(&self, msg: &[u8], from: SocketAddr) {
        let msg = if let Ok(x) = serde_json::from_slice::<SprayerReq>(msg) {
            x
        } else {
            self.log(&|| {
                debug!(
                    "Got packet from {} which could not be decoded {}",
                    from,
                    hex::encode(msg)
                )
            });
            return;
        };
        if msg.yes_please_dos_me_passwd != self.g.0.passwd {
            self.log(&|| debug!("Packet from {} with wrong password", from));
            return;
        }
        self.log(&|| debug!("Got subscription from {}", from));
        self.g.incoming_subscription(from, msg);
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
    ))]
    fn do_recv(&mut self) -> Result<usize> {
        use nix::sys::socket::{recvmmsg, MsgFlags, RecvMmsgData, RecvMsg};
        use nix::sys::uio::IoVec;
        use std::os::unix::io::AsRawFd;

        let fd = self.g.0.socket.as_raw_fd();
        let iovs: Vec<_> = self.rbuf[self.rindex..]
            .iter_mut()
            .map(|buf| [IoVec::from_mut_slice(&mut buf[..])])
            .collect();
        let mut msgs = std::collections::LinkedList::new();
        for iov in &iovs {
            msgs.push_back(RecvMmsgData {
                iov,
                cmsg_buffer: None,
            })
        }
        let res = recvmmsg(fd, &mut msgs, MsgFlags::MSG_DONTWAIT, None)?;
        let out = Vec::with_capacity(res.len());
        for (RecvMsg { address, bytes, .. }, i) in res.into_iter().zip(self.rindex..) {
            if let Some(addr) = address {
                self.rbuf[i].peer = addr.to_std();
                self.rbuf[i].len = bytes;
            } else {
                self.rbuf[i].len = 0;
            }
        }
        Ok(out)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
    )))]
    fn do_recv(&mut self) -> Result<usize> {
        for i in self.rindex..self.rbuf.len() {
            match self.g.0.socket.recv_from(&mut self.rbuf[i].bytes[..]) {
                Ok((len, fr)) => {
                    self.rbuf[i].len = len;
                    self.rbuf[i].peer = fr.as_std().unwrap();
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        self.log(&|| info!("Error reading sprayer socket {}", e));
                    }
                    return Ok(i);
                }
            }
        }
        Ok(self.rbuf.len())
    }

    fn recv(&mut self) {
        let next_i = match self.do_recv() {
            Err(e) => {
                self.log(&|| info!("Error receiving packets {}", e));
                return;
            }
            Ok(m) => m,
        };
        for i in self.rindex..next_i {
            {
                let msg = &self.rbuf[i];
                if msg.len < MSG_TOTAL_LEN {
                    let mut x = [0_u8; MSG_TOTAL_LEN];
                    x[0..msg.len].copy_from_slice(&msg.bytes[0..msg.len]);
                    self.maybe_subscribe(&x[0..msg.len], msg.peer);
                } else if let Some(sub) = self
                    .g
                    .0
                    .subscribed_to
                    .iter()
                    .find(|sub| sub.peer == msg.peer)
                {
                    sub.packets_received.fetch_add(1, atomic::Ordering::Relaxed);
                    continue;
                }
            }
            // Packets we don't want being processed...
            self.rbuf[i].len = 0;
        }
        self.rindex = next_i;
    }

    #[allow(clippy::comparison_chain)]
    fn run(mut self) {
        info!("Launched sprayer thread");
        let mut i = 0;
        let mut last_i = 0;
        let mut overflow = 0;
        loop {
            self.recv();
            self.try_send();
            if self.g.0.log_peer_stats {
                self.g.get_peer_stats();
            }
            if i == 0 {
                std::thread::sleep(std::time::Duration::from_micros(100));
                continue;
            }
            if i > last_i {
                overflow += self.g.push_anns(&self.rbuf[last_i..i]);
                if overflow > 0 && self.log(&|| info!("Send overflow of {} anns", overflow)) {
                    overflow = 0;
                }
                last_i = i;
            }
            if i > ANNS_TO_ACCUMULATE {
                let handler = self.g.0.handler.read().unwrap();
                match &*handler {
                    Some(h) => h.on_anns(&self.rbuf[0..i]),
                    None => (),
                }
                i = 0;
                last_i = 0;
            }
        }
    }
}
