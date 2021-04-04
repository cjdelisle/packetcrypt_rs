// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Context, Result};
use log::{debug, info, warn};
use packetcrypt_util::protocol::SprayerReq;
use packetcrypt_util::util;
use parking_lot::{Mutex, RwLock};

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::atomic::{self, AtomicUsize};
use std::sync::Arc;

// 1MB per send/recv chunk
const ANN_PER_CHUNK: usize = 1024;

// Never store more tha 128MB to be sent to any given address
const MAX_SEND_QUEUE_CHUNKS_PER_PEER: usize = 128;

// How long a node doesn't send a subscription update before we stop flooding them
const SECONDS_UNTIL_SUB_TIMEOUT: usize = 30;

// How often to resend subscriptions
const SECONDS_UNTIL_RESUB: usize = 5;

///

const STATS_EVERY: usize = 10;

// 512M incoming buffer
const RECV_BUF_SZ: usize = 512 * 1024 * 1024;

const MSG_PREFIX: usize = 8;
const PKT_LENGTH: usize = 1024 + MSG_PREFIX;
const CHUNK_LEN: usize = ANN_PER_CHUNK * PKT_LENGTH;
const LOG_CREDITS: usize = 16;

#[derive(Clone)]
pub struct Chunk {
    bcur: usize,
    ecur: usize,
    bytes: [u8; CHUNK_LEN],
}
impl Chunk {
    pub fn ann_iter(&self) -> impl Iterator<Item = &[u8]> {
        let mut c = self.bcur;
        std::iter::from_fn(move || {
            if c + PKT_LENGTH > self.ecur {
                None
            } else {
                let c0 = c;
                c += PKT_LENGTH;
                Some(&self.bytes[c0..c])
            }
        })
    }
    pub fn all_anns(&self) -> &[u8] {
        &self.bytes[self.bcur..self.ecur]
    }
    pub fn len(&self) -> usize {
        (self.ecur - self.bcur) / PKT_LENGTH
    }
    pub fn cap(&self) -> usize {
        CHUNK_LEN / PKT_LENGTH
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn reset(&mut self) {
        self.bcur = 0;
        self.ecur = 0;
    }
    // pub fn cap(&self) -> usize {
    //     ANN_PER_CHUNK
    // }
    pub fn push_ann(&mut self, ann: &[u8], number: u64) -> bool {
        let (c0, c1) = if self.bcur >= PKT_LENGTH {
            // Try pushing to the back
            let c0 = self.bcur;
            self.bcur -= PKT_LENGTH;
            (self.bcur, c0)
        } else if self.ecur + PKT_LENGTH <= self.bytes.len() {
            // Try pushing to the front then
            let c0 = self.ecur;
            self.ecur += PKT_LENGTH;
            (c0, self.ecur)
        } else {
            return false;
        };
        let num_u8 = number.to_le_bytes();
        self.bytes[c0..(c0 + 8)].copy_from_slice(&num_u8[..]);
        self.bytes[(c0 + 8)..c1].copy_from_slice(ann);
        true
    }
}

struct ChunkPool {
    q: Mutex<VecDeque<Box<Chunk>>>,
}
impl ChunkPool {
    fn take(&self) -> Box<Chunk> {
        if let Some(c) = self.q.lock().pop_back() {
            c
        } else {
            Box::new(Chunk {
                bcur: 0,
                ecur: 0,
                bytes: [0_u8; CHUNK_LEN],
            })
        }
    }
    fn give(&self, bc: Box<Chunk>) {
        self.q.lock().push_back(bc)
    }
}

struct SendQueue {
    next_num: u64,
    q: VecDeque<Box<Chunk>>,
    chunk_pool: Arc<ChunkPool>,
}
impl SendQueue {
    fn push_ann(&mut self, ann: &[u8]) -> usize {
        let mut overflow = 0;
        loop {
            let mut done = false;
            if let Some(mut c) = self.q.pop_back() {
                if c.push_ann(ann, self.next_num) {
                    self.next_num += 1;
                    done = true;
                }
                self.q.push_back(c);
            }
            if done {
                break;
            }
            self.q.push_back(self.chunk_pool.take());
            if self.q.len() > MAX_SEND_QUEUE_CHUNKS_PER_PEER {
                let c = self.q.pop_front().unwrap();
                overflow += c.len();
            }
        }
        overflow
    }
}
struct Subscriber {
    peer: SocketAddr,
    last_update_sec: AtomicUsize,
    send_queue: Mutex<SendQueue>,
}

struct Subscription {
    //    peer: SocketAddr,
    last_update_sec: AtomicUsize,
    packets_received: AtomicUsize,
}

struct SprayerMut {
    subscribers: Vec<Subscriber>,
}

pub trait OnAnns: Send + Sync {
    fn on_anns(&self, anns: &[&[u8]]);
}
// So you can pass None
impl<T: Send + Sync> OnAnns for Option<T> {
    fn on_anns(&self, _anns: &[&[u8]]) {}
}

struct PeerCounters {
    last_logged_ms: u64,
    last_packets_recv: usize,
    last_packets_sent: u64,
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
    subscribe_to: Vec<SocketAddr>,
    passwd: String,
    socket: UdpSocket,
    handler: RwLock<Option<Box<dyn OnAnns>>>,
    subscribed_to: HashMap<SocketAddr, Subscription>,
    force_subscribe: Vec<Subscriber>,
    workers: usize,
    gso_ok: bool,
    is_mcast: bool,
    last_computed_stats: AtomicUsize,
    peer_counters: Mutex<HashMap<SocketAddr, PeerCounters>>,
    peer_stats: Mutex<Vec<PeerStats>>,
    log_peer_stats: bool,
    chunk_pool: Arc<ChunkPool>,
    pkt_size: usize,
    self_addr: SocketAddr,
}
pub struct Sprayer(Arc<SprayerS>);

fn compute_kbps(packets_sent: u64, ms_elapsed: u64) -> f64 {
    // consider the headers here
    let bits_sent = packets_sent * (PKT_LENGTH as u64 + 8 + 20 + 14) * 8;
    // bits per millisecond = kilobits per second
    bits_sent as f64 / ms_elapsed as f64
}

pub struct Config {
    pub passwd: String,
    pub bind: String,
    pub workers: usize,
    pub subscribe_to: Vec<String>,
    pub log_peer_stats: bool,
    pub mss: usize,
    pub spray_at: Vec<String>,
    pub mcast: String,
}

#[cfg(windows)]
fn raw_fd(_s: &UdpSocket) -> i32 {
    panic!("sprayer is not supported in windows");
}

#[cfg(not(windows))]
fn raw_fd(s: &UdpSocket) -> i32 {
    use std::os::unix::io::AsRawFd;
    s.as_raw_fd()
}

impl Sprayer {
    pub fn new(cfg: &Config) -> Result<Sprayer> {
        let gso_err = unsafe {
            let err = packetcrypt_sys::UdpGso_supported();
            if !err.is_null() {
                Some(std::ffi::CStr::from_ptr(err).to_string_lossy())
            } else {
                None
            }
        };

        let mcast: Option<Ipv4Addr> = if !cfg.mcast.is_empty() {
            Some(
                cfg.mcast
                    .parse()
                    .with_context(|| format!("mcast parse({})", cfg.mcast))?,
            )
        } else {
            None
        };

        let addr: SocketAddr = cfg
            .bind
            .parse()
            .with_context(|| format!("SocketAddr parse({})", cfg.bind))?;
        let socket = UdpSocket::bind(addr).with_context(|| format!("UdpSocket::bind({})", addr))?;
        socket.set_nonblocking(true)?;
        if let Some(mcast) = mcast {
            if let SocketAddr::V4(addr) = addr {
                socket.join_multicast_v4(&mcast, addr.ip())?;
            } else {
                bail!("Cannot do multicast with ipv6 bind");
            }
        }

        let fd = raw_fd(&socket);
        let pkt_size = (cfg.mss / PKT_LENGTH) * PKT_LENGTH;
        if let Some(ref err) = gso_err {
            warn!("UDP_GSO not supported {}, expect high CPU usage", err);
        } else {
            let res = unsafe { packetcrypt_sys::UdpGro_enable(fd, pkt_size as i32) };
            if res != 0 {
                bail!("UdpGro_enable() failed {}", res);
            }
        }

        let res = unsafe { packetcrypt_sys::UdpGro_setRecvBuf(fd, RECV_BUF_SZ as i32) };
        if res != 0 {
            warn!(
                "Unable to set SO_RCVBUF to {}: {} - expect packet loss at high load",
                RECV_BUF_SZ, res
            );
        }

        let m = RwLock::new(SprayerMut {
            subscribers: Vec::new(),
        });

        let mut subscribed_to: HashMap<SocketAddr, Subscription> = HashMap::new();
        let mut subscribe_to = Vec::new();
        for s in &cfg.subscribe_to {
            let peer = s.parse()?;
            subscribe_to.push(peer);
            subscribed_to.insert(
                peer,
                Subscription {
                    last_update_sec: AtomicUsize::new(0),
                    packets_received: AtomicUsize::new(0),
                },
            );
        }

        let chunk_pool = Arc::new(ChunkPool {
            q: Mutex::new(VecDeque::new()),
        });

        let mut force_subscribe = Vec::new();
        for s in &cfg.spray_at {
            let peer = s.parse()?;
            force_subscribe.push(Subscriber {
                peer,
                send_queue: Mutex::new(SendQueue {
                    next_num: 0,
                    q: VecDeque::new(),
                    chunk_pool: Arc::clone(&chunk_pool),
                }),
                last_update_sec: AtomicUsize::new(0),
            });
        }

        Ok(Sprayer(Arc::new(SprayerS {
            m,
            subscribe_to,
            subscribed_to,
            force_subscribe,
            passwd: cfg.passwd.clone(),
            socket,
            gso_ok: gso_err.is_none(),
            is_mcast: mcast.is_some(),
            workers: cfg.workers,
            handler: RwLock::new(None),
            last_computed_stats: AtomicUsize::new(0),
            peer_counters: Mutex::new(HashMap::new()),
            peer_stats: Mutex::new(Vec::new()),
            log_peer_stats: cfg.log_peer_stats,
            chunk_pool,
            pkt_size,
            self_addr: addr,
        })))
    }

    pub fn set_handler<T: 'static + OnAnns>(&self, handler: T) {
        self.0.handler.write().replace(Box::new(handler));
    }

    pub fn push_anns(&self, anns: &[&[u8]]) -> usize {
        let oldest_allowed_time = (util::now_ms() / 1000) as usize - SECONDS_UNTIL_SUB_TIMEOUT;
        let mut overflow = 0;
        for s in &self.0.force_subscribe {
            let mut sq = s.send_queue.lock();
            for ann in anns {
                overflow += sq.push_ann(ann);
            }
        }
        let m = self.0.m.read();
        for s in &m.subscribers {
            let lus = s.last_update_sec.load(atomic::Ordering::Relaxed);
            if lus < oldest_allowed_time {
                continue;
            }
            let mut sq = s.send_queue.lock();
            for ann in anns {
                overflow += sq.push_ann(ann);
            }
        }
        overflow
    }

    pub fn start(&self) {
        for tid in 0..self.0.workers {
            let g = Sprayer(Arc::clone(&self.0));
            let rchunk = self.0.chunk_pool.take();
            std::thread::spawn(move || {
                Box::new(SprayWorker {
                    g,
                    rchunk,
                    time_of_last_log: 0,
                    log_credits: LOG_CREDITS,
                    tid,
                })
                .run();
            });
        }
    }

    fn get_to_send(&self, tid: usize) -> Option<(Box<Chunk>, SocketAddr)> {
        {
            let m = self.0.m.read();
            if !m.subscribers.is_empty() {
                let start = tid % m.subscribers.len();
                for sub in &m.subscribers[start..] {
                    if let Some(chunk) = sub.send_queue.lock().q.pop_back() {
                        return Some((chunk, sub.peer));
                    }
                }
                for sub in &m.subscribers[0..start] {
                    if let Some(chunk) = sub.send_queue.lock().q.pop_back() {
                        return Some((chunk, sub.peer));
                    }
                }
            }
        }
        for sub in &self.0.force_subscribe {
            if let Some(chunk) = sub.send_queue.lock().q.pop_back() {
                return Some((chunk, sub.peer));
            }
        }
        None
    }

    fn return_to_send(&self, chunk: Box<Chunk>, addr: SocketAddr) {
        for sub in &self.0.force_subscribe {
            if sub.peer == addr {
                sub.send_queue.lock().q.push_back(chunk);
                return;
            }
        }
        let m = self.0.m.read();
        for sub in &m.subscribers {
            if sub.peer == addr {
                sub.send_queue.lock().q.push_back(chunk);
                return;
            }
        }
        warn!(
            "Could not return chunk to peer {}, it seems they disappeared",
            addr
        );
    }

    fn send_subs(&self) -> Option<(std::io::Error, SocketAddr)> {
        let now_sec = (util::now_ms() / 1000) as usize;
        let update_time = now_sec - SECONDS_UNTIL_RESUB;
        for (peer, sub) in self.0.subscribed_to.iter() {
            let time_sec = sub.last_update_sec.load(atomic::Ordering::Relaxed);
            if time_sec > update_time {
                continue;
            }
            let req = serde_json::to_string(&SprayerReq {
                yes_please_dos_me_passwd: self.0.passwd.clone(),
                num: Some(0),
                count: Some(1),
            })
            .unwrap();
            debug!("subscribing to {}", peer);
            if let Err(e) = self.0.socket.send_to(&req.as_bytes(), peer) {
                return Some((e, *peer));
            }
            sub.last_update_sec
                .store(now_sec, atomic::Ordering::Relaxed);
        }
        None
    }

    fn incoming_subscription(&self, from: SocketAddr) {
        let now_sec = (util::now_ms() / 1000) as usize;
        let oldest_allowed_time = now_sec - SECONDS_UNTIL_SUB_TIMEOUT;
        {
            let m = self.0.m.read();
            for s in &m.subscribers {
                if s.peer == from {
                    s.last_update_sec.store(now_sec, atomic::Ordering::Relaxed);
                    return;
                }
            }
        }
        {
            let mut m = self.0.m.write();
            let mut i = 0;
            while i < m.subscribers.len() {
                let s = &mut m.subscribers[i];
                if s.peer == from {
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
                send_queue: Mutex::new(SendQueue {
                    next_num: 0,
                    q: VecDeque::new(),
                    chunk_pool: Arc::clone(&self.0.chunk_pool),
                }),
                last_update_sec: AtomicUsize::new(now_sec),
            });
        }
    }

    pub fn get_peer_stats(&self) -> Vec<PeerStats> {
        let now_ms = util::now_ms();
        let now_sec = (now_ms / 1000) as usize;
        let last_computed_stats = self.0.last_computed_stats.load(atomic::Ordering::Relaxed);
        if last_computed_stats + STATS_EVERY > now_sec {
            return self.0.peer_stats.lock().clone();
        }
        self.0
            .last_computed_stats
            .store(now_sec, atomic::Ordering::Relaxed);

        let mut ps = self.0.peer_counters.lock();
        let m = self.0.m.read();
        let mut peer_stats = Vec::new();
        if self.0.log_peer_stats {
            info!("Sprayer links:");
        }
        for sub in m.subscribers.iter().chain(self.0.force_subscribe.iter()) {
            let packets_sent_ever = { sub.send_queue.lock().next_num };
            match ps.get_mut(&sub.peer) {
                Some(p) => {
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
                            "<- {} sent {} anns {}",
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
                            last_packets_sent: packets_sent_ever,
                            last_packets_recv: 0,
                        },
                    );
                }
            }
        }
        for peer in &self.0.subscribe_to {
            let sub = if let Some(p) = self.0.subscribed_to.get(peer) {
                p
            } else {
                continue;
            };
            match ps.get_mut(peer) {
                Some(p) => {
                    let packets_recv_ever = sub.packets_received.load(atomic::Ordering::Relaxed);
                    let packets = (packets_recv_ever - p.last_packets_recv) as u64;
                    let ms = now_ms - p.last_logged_ms;
                    let st = PeerStats {
                        peer: *peer,
                        kbps_in: compute_kbps(packets, ms),
                        kbps_out: 0.0,
                        packets_in: packets,
                        packets_out: 0,
                    };
                    if self.0.log_peer_stats {
                        info!(
                            "-> {} recv {} anns ({})",
                            peer,
                            packets,
                            util::format_kbps(st.kbps_in)
                        );
                    }
                    peer_stats.push(st);
                    p.last_logged_ms = now_ms;
                    p.last_packets_recv = sub.packets_received.load(atomic::Ordering::Relaxed);
                }
                None => {
                    ps.insert(
                        *peer,
                        PeerCounters {
                            last_logged_ms: now_ms,
                            last_packets_recv: sub.packets_received.load(atomic::Ordering::Relaxed),
                            last_packets_sent: 0,
                        },
                    );
                }
            }
        }
        *self.0.peer_stats.lock() = peer_stats.clone();
        peer_stats
    }
}

struct SprayWorker {
    g: Sprayer,
    rchunk: Box<Chunk>,
    time_of_last_log: usize,
    log_credits: usize,
    tid: usize,
}

impl SprayWorker {
    fn log(&mut self, f: &dyn Fn()) -> bool {
        let now = util::now_ms() as usize;
        if now > self.time_of_last_log + 1000 {
            self.log_credits = LOG_CREDITS;
            self.time_of_last_log = now;
        }
        if self.log_credits > 0 {
            self.log_credits -= 1;
            f();
            true
        } else {
            false
        }
    }

    fn send_slow(&mut self, chunk: &mut Box<Chunk>, addr: SocketAddr) {
        while chunk.bcur + PKT_LENGTH <= chunk.ecur {
            let buf = &chunk.bytes[chunk.bcur..(chunk.bcur + PKT_LENGTH)];
            match self.g.0.socket.send_to(buf, &addr) {
                Ok(l) => {
                    if l == PKT_LENGTH {
                        chunk.bcur += PKT_LENGTH;
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
                    break;
                }
            }
        }
    }

    fn send_gso(&mut self, chunk: &mut Box<Chunk>, addr: SocketAddr) {
        let fd = raw_fd(&self.g.0.socket);
        let mut caddr = packetcrypt_sys::UdpGro_Sockaddr {
            isIpv6: if addr.is_ipv6() { 1 } else { 0 },
            port: addr.port(),
            addr: [0_u8; 16usize],
        };
        match addr.ip() {
            IpAddr::V6(a) => caddr.addr.copy_from_slice(&a.octets()),
            IpAddr::V4(a) => caddr.addr[0..4].copy_from_slice(&a.octets()),
        }
        let max_len = 0xffff / PKT_LENGTH * PKT_LENGTH;
        let pkt_size = if addr.ip() == self.g.0.self_addr.ip() {
            // If same IP as our socket, this is going to internally use the loopback
            // which does not support GRO/GSO but does have a big MTU so we need to send
            // a max size packet otherwise CPU usage will spike.
            //self.log(&|| info!("sending max_len packet"));
            max_len
        } else {
            self.g.0.pkt_size
        } as i32;
        let ret = loop {
            let buf = &chunk.bytes[chunk.bcur..chunk.ecur];
            if buf.is_empty() {
                break 0;
            }
            let len = std::cmp::min(buf.len(), max_len) as i32;
            let ret =
                unsafe { packetcrypt_sys::UdpGro_sendmsg(fd, &caddr, buf.as_ptr(), len, pkt_size) };
            if ret > 0 {
                let uret = ret as usize;
                let count = uret / PKT_LENGTH;
                if (count * PKT_LENGTH) != uret {
                    self.log(&|| {
                        warn!(
                            "Partial write to {}, only {} of {}",
                            addr,
                            uret,
                            chunk.len() * PKT_LENGTH
                        )
                    });
                }
                chunk.bcur += count * PKT_LENGTH;
            }
            if ret != len {
                break ret;
            }
        };
        if ret < 0 {
            self.log(&|| warn!("Unable to send packet to {}, {}", addr, ret));
            return;
        }
    }

    fn try_send(&mut self) -> bool {
        if self.tid == 0 && !self.g.0.is_mcast {
            // Busyloop until we manage to send the subscriptions.
            loop {
                if let Some((e, to)) = self.g.send_subs() {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    self.log(&|| info!("Error sending subscription to {}: {}", to, e));
                }
                break;
            }
        }
        let mut did_something = false;
        while let Some((mut chunk, addr)) = self.g.get_to_send(self.tid) {
            did_something = true;
            if self.g.0.gso_ok {
                self.send_gso(&mut chunk, addr);
            } else {
                self.send_slow(&mut chunk, addr);
            }
            if chunk.len() > 0 {
                self.g.return_to_send(chunk, addr);
                break;
            } else {
                self.g.0.chunk_pool.give(chunk);
            }
        }
        did_something
    }

    fn maybe_subscribe(&mut self, msg: &[u8], from: SocketAddr) {
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
        self.g.incoming_subscription(from);
    }

    // If there's a stub packet then this is returned
    fn recv_slow(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        let mut out = None;
        loop {
            let max_recv = self.rchunk.bytes.len() - self.rchunk.ecur;
            if max_recv < PKT_LENGTH {
                break;
            }
            let buf = &mut self.rchunk.bytes[self.rchunk.ecur..(self.rchunk.ecur + max_recv)];
            match self.g.0.socket.recv_from(buf) {
                Ok((len, fr)) => {
                    let mut ok = false;
                    let pkt_recv = len / PKT_LENGTH * PKT_LENGTH;
                    if pkt_recv > 0 {
                        if let Some(sub) = self.g.0.subscribed_to.get(&fr) {
                            sub.packets_received.fetch_add(pkt_recv / 1024, atomic::Ordering::Relaxed);
                            self.rchunk.ecur += pkt_recv;
                            ok = true;
                        }
                    }
                    if len > pkt_recv {
                        out = Some((fr, Vec::from(&buf[pkt_recv..len])));
                        ok = true;
                    }
                    if !ok {
                      self.log(&|| warn!("Got message (len {}) from unsubscribed node {}", len, fr));
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        self.log(&|| info!("Error reading sprayer socket {}", e));
                    }
                    break;
                }
            }
        }
        out
    }

    fn recv_gso(&mut self) {
        let fd = raw_fd(&self.g.0.socket);
        let mut addr = packetcrypt_sys::UdpGro_Sockaddr {
            isIpv6: 0,
            port: 0,
            addr: [0_u8; 16usize],
        };
        let mut pkt_sz = 0_i32;
        let buf = &mut self.rchunk.bytes[self.rchunk.ecur..];
        if buf.len() < PKT_LENGTH {
            return;
        }
        let res_len = unsafe {
            packetcrypt_sys::UdpGro_recvmsg(
                fd,
                &mut addr,
                buf.as_mut_ptr(),
                buf.len() as i32,
                &mut pkt_sz,
            )
        };
        if res_len <= 0 {
            if res_len < 0 {
                self.log(&|| info!("Error reading sprayer socket {}", res_len));
            }
            return;
        }
        let len = res_len as usize;
        if pkt_sz != self.g.0.pkt_size as i32 {
            // This is when GRO was not invoked and it pulled just one packet
            if pkt_sz != -1 {
                self.log(&|| info!("Hmmm pkt_sz is {}, len is {}", pkt_sz, len));
            }
        } else {
            //self.log(&|| info!("pkt_sz is {}", pkt_sz));
            // GRO was invoked
        }

        // IP addr
        let address: SocketAddr = if addr.isIpv6 != 0 {
            (addr.addr, addr.port).into()
        } else {
            let mut ip4 = [0_u8; 4];
            ip4.copy_from_slice(&addr.addr[0..4]);
            (ip4, addr.port).into()
        };

        // Stub message at the end? maybe it's a subscribe...
        let count = len / PKT_LENGTH;
        let anns_len = count * PKT_LENGTH;
        let stub_len = len - anns_len;
        if stub_len != 0 {
            let mut x = [0_u8; PKT_LENGTH];
            x[0..stub_len].copy_from_slice(
                &self.rchunk.bytes[self.rchunk.ecur + anns_len..self.rchunk.ecur + len],
            );
            self.maybe_subscribe(&x[0..stub_len], address);
        } else if let Some(sub) = self.g.0.subscribed_to.get(&address) {
            sub.packets_received
                .fetch_add(count, atomic::Ordering::Relaxed);
            self.rchunk.ecur += len;
        } else {
            self.log(&|| {
                warn!(
                    "Got message from unsubscribed node {} (len: {})",
                    address, len
                )
            });
        }
    }

    fn recv(&mut self) {
        if self.g.0.gso_ok {
            self.recv_gso();
        } else if let Some(v) = self.recv_slow() {
            self.maybe_subscribe(&v.1, v.0);
        }
    }

    #[allow(clippy::comparison_chain)]
    fn run(mut self) {
        info!("Launched sprayer thread");
        let mut overflow = 0;
        loop {
            if overflow > 0 && self.log(&|| info!("Send overflow of {} anns", overflow)) {
                overflow = 0;
            }
            self.recv();
            let sent_something = self.try_send();
            if self.g.0.log_peer_stats {
                self.g.get_peer_stats();
            }
            if self.rchunk.is_empty() && !sent_something {
                std::thread::sleep(std::time::Duration::from_micros(100));
                continue;
            }
            if self.rchunk.len() < self.rchunk.cap() - 64 {
                // keep polling until we have neatly a full buffer
                continue;
            }
            let bufs = self
                .rchunk
                .ann_iter()
                .map(|v| &v[MSG_PREFIX..])
                .collect::<Vec<_>>();
            overflow += self.g.push_anns(&bufs);
            let handler = self.g.0.handler.read();
            match &*handler {
                Some(h) => h.on_anns(&bufs),
                None => (),
            }
            self.rchunk.reset();
        }
    }
}
