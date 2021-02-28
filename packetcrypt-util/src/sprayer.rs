// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::protocol::SprayerReq;
use crate::util;
use anyhow::{Context, Result};
use log::{debug, info};

use std::collections::HashMap;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::atomic::{self, AtomicUsize};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

// 8MB incoming buffer per thread
const INCOMING_BUF_ANN_PER_THREAD: usize = 8 * 1024;

// 128MB shared outgoing buffer
const MAX_SEND_QUEUE: usize = 128 * 1024;

// 128k per send attempt
const SEND_CHUNK_SZ: usize = 128;

// How long a node doesn't send a subscription update before we stop flooding them
const SECONDS_UNTIL_SUB_TIMEOUT: usize = 30;

// How often to resend subscriptions
const SECONDS_UNTIL_RESUB: usize = 5;

const STATS_EVERY: usize = 10;

pub type Ann = [u8; 1024];

#[derive(Copy, Clone)]
struct ToSend {
    dest: SocketAddr,
    ann: Ann,
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
    fn on_anns(&self, anns: &[Ann]);
}
// So you can pass None
impl<T: Send + Sync> OnAnns for Option<T> {
    fn on_anns(&self, _anns: &[Ann]) {}
}

struct PeerStats {
    last_logged_sec: usize,
    last_packets_received: usize,
    last_packets_sent: usize,
}

struct SprayerS {
    m: RwLock<SprayerMut>,
    send_queue: Mutex<VecDeque<ToSend>>,
    passwd: String,
    socket: UdpSocket,
    handler: RwLock<Option<Box<dyn OnAnns>>>,
    subscribed_to: Vec<Subscription>,
    always_send_all: bool,
    workers: usize,
    last_logged_stats: AtomicUsize,
    peer_stats: Mutex<HashMap<SocketAddr, PeerStats>>,
}
pub struct Sprayer(Arc<SprayerS>);

fn get_ann_key(ann: &Ann) -> u32 {
    u32::from_le_bytes(ann[64..68].try_into().unwrap())
}

pub struct Config {
    pub passwd: String,
    pub bind: String,
    pub workers: usize,
    pub subscribe_to: Vec<String>,
    pub always_send_all: bool,
}

impl Sprayer {
    pub fn new(cfg: &Config) -> Result<Sprayer> {
        let addr: SocketAddr = cfg
            .bind
            .parse()
            .with_context(|| format!("SocketAddr parse({})", cfg.bind))?;
        let socket = UdpSocket::bind(addr).with_context(|| format!("UdpSocket::bind({})", addr))?;
        socket.set_nonblocking(true)?;

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
            socket,
            workers: cfg.workers,
            handler: RwLock::new(None),
            always_send_all: cfg.always_send_all,
            last_logged_stats: AtomicUsize::new(0),
            peer_stats: Mutex::new(HashMap::new()),
        })))
    }

    pub fn set_handler<T: 'static + OnAnns>(&self, handler: T) {
        self.0.handler.write().unwrap().replace(Box::new(handler));
    }

    pub fn push_anns(&self, anns: &[Ann]) -> usize {
        let oldest_allowed_time = (util::now_ms() / 1000) as usize - SECONDS_UNTIL_SUB_TIMEOUT;
        let m = self.0.m.read().unwrap();
        let mut sq = self.0.send_queue.lock().unwrap();
        let mut overflow = 0;
        for ann in anns {
            let k = get_ann_key(ann);
            for s in &m.subscribers {
                let lus = s.last_update_sec.load(atomic::Ordering::Relaxed);
                if lus < oldest_allowed_time {
                    continue;
                }
                if self.0.always_send_all || k % s.count == s.num {
                    if sq.len() >= MAX_SEND_QUEUE {
                        sq.pop_front();
                        overflow += 1;
                    } else {
                        s.packets_sent.fetch_add(1, atomic::Ordering::Relaxed);
                    }
                    sq.push_back(ToSend {
                        dest: s.peer,
                        ann: *ann,
                    })
                }
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
                    rbuf: vec![[0_u8; 1024]; INCOMING_BUF_ANN_PER_THREAD],
                    sbuf: [ToSend {
                        dest: SocketAddr::new([127, 0, 0, 1].into(), 0),
                        ann: [0_u8; 1024],
                    }; SEND_CHUNK_SZ],
                    time_of_last_log: 0_u64,
                    tid,
                })
                .run();
            });
        }
    }

    fn get_to_send(&self, send: &mut [ToSend]) -> usize {
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

    fn return_to_send(&self, send: &[ToSend]) {
        let mut sql = self.0.send_queue.lock().unwrap();
        for s in send {
            sql.push_front(*s);
        }
    }

    fn send_subs(&self, tid: usize) -> Option<(std::io::Error, SocketAddr)> {
        let now_sec = (util::now_ms() / 1000) as usize;
        let update_time = now_sec - SECONDS_UNTIL_RESUB;
        for (sub, num) in self.0.subscribed_to.iter().zip(0..) {
            let time_sec = sub.last_update_sec.load(atomic::Ordering::Relaxed);
            if time_sec > update_time + tid {
                continue;
            }
            let req = serde_json::to_string(&SprayerReq {
                yes_please_dos_me_passwd: self.0.passwd.clone(),
                num,
                count: self.0.subscribed_to.len() as u32,
            })
            .unwrap();
            debug!("subscribing to {}", sub.peer);
            if let Err(e) = self.0.socket.send_to(&req.as_bytes(), &sub.peer) {
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

    fn log_stats(&self) {
        let now_sec = (util::now_ms() / 1000) as usize;
        let last_logged_stats = self.0.last_logged_stats.load(atomic::Ordering::Relaxed);
        if last_logged_stats + STATS_EVERY > now_sec {
            return;
        }
        self.0
            .last_logged_stats
            .store(now_sec, atomic::Ordering::Relaxed);

        let mut ps = self.0.peer_stats.lock().unwrap();
        let m = self.0.m.read().unwrap();
        for sub in &m.subscribers {
            match ps.get_mut(&sub.peer) {
                Some(p) => {
                    let packets_sent = sub.packets_sent.load(atomic::Ordering::Relaxed);
                    let kbps = (packets_sent - p.last_packets_sent) / (now_sec - p.last_logged_sec);
                    info!("{} <- {}", sub.peer, util::format_kbps(kbps as f64));
                    p.last_logged_sec = now_sec;
                    p.last_packets_sent = packets_sent;
                }
                None => {
                    ps.insert(
                        sub.peer,
                        PeerStats {
                            last_logged_sec: now_sec,
                            last_packets_sent: sub.packets_sent.load(atomic::Ordering::Relaxed),
                            last_packets_received: 0,
                        },
                    );
                }
            }
        }
        for sub in &self.0.subscribed_to {
            match ps.get_mut(&sub.peer) {
                Some(p) => {
                    let packets_recv = sub.packets_received.load(atomic::Ordering::Relaxed);
                    let kbps =
                        (packets_recv - p.last_packets_received) / (now_sec - p.last_logged_sec);
                    info!("{} -> {}", sub.peer, util::format_kbps(kbps as f64));
                    p.last_logged_sec = now_sec;
                    p.last_packets_received = sub.packets_received.load(atomic::Ordering::Relaxed);
                }
                None => {
                    ps.insert(
                        sub.peer,
                        PeerStats {
                            last_logged_sec: now_sec,
                            last_packets_received: sub
                                .packets_received
                                .load(atomic::Ordering::Relaxed),
                            last_packets_sent: 0,
                        },
                    );
                }
            }
        }
    }
}

struct SprayWorker {
    g: Sprayer,
    rbuf: Vec<Ann>,
    sbuf: [ToSend; SEND_CHUNK_SZ],
    time_of_last_log: u64,
    tid: usize,
}

impl SprayWorker {
    fn log(&mut self, f: &dyn Fn()) -> bool {
        let now = util::now_ms();
        if now > self.time_of_last_log + 1000 {
            f();
            self.time_of_last_log = now;
            true
        } else {
            false
        }
    }
    fn try_send(&mut self) {
        if let Some((e, to)) = self.g.send_subs(self.tid) {
            self.log(&|| info!("Error sending subscription to {}: {}", to, e));
        }
        let count = self.g.get_to_send(&mut self.sbuf);
        for i in 0..count {
            match self
                .g
                .0
                .socket
                .send_to(&self.sbuf[i].ann[..], &self.sbuf[i].dest)
            {
                Ok(l) => {
                    if l == 1024 {
                        continue;
                    }
                    self.log(&|| info!("Sending to sprayer socket length {}", l));
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        self.log(&|| info!("Error sending to sprayer socket {}", e));
                    }
                }
            }
            self.g.return_to_send(&self.sbuf[i..count]);
            return;
        }
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
        self.g.incoming_subscription(from, msg);
    }
    fn run(mut self) {
        info!("Launched sprayer thread");
        let mut i = 0;
        let mut overflow = 0;
        loop {
            match self.g.0.socket.recv_from(&mut self.rbuf[i][..]) {
                Ok((l, from)) => {
                    if l != 1024 {
                        let mut x = [0_u8; 1024];
                        x[0..1].copy_from_slice(&self.rbuf[i][0..l]);
                        self.maybe_subscribe(&x[0..l], from);
                        continue;
                    }
                    match self.g.0.subscribed_to.iter().find(|sub| sub.peer == from) {
                        Some(sub) => {
                            i += 1;
                            sub.packets_received.fetch_add(1, atomic::Ordering::Relaxed);
                            if i < self.rbuf.len() {
                                continue;
                            }
                        }
                        None => {
                            // spurious packet
                            continue;
                        }
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        self.log(&|| info!("Error reading sprayer socket {}", e));
                    }
                }
            }
            self.try_send();
            self.g.log_stats();
            if i == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            {
                let handler = self.g.0.handler.read().unwrap();
                match &*handler {
                    Some(h) => h.on_anns(&self.rbuf[0..i]),
                    None => (),
                }
            }
            overflow += self.g.push_anns(&self.rbuf[0..i]);
            if overflow > 0 && self.log(&|| info!("Send overflow of {} anns", overflow)) {
                overflow = 0;
            }
        }
    }
}
