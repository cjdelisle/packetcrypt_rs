// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::ann_store::AnnStore;
use crate::blkminer::{BlkMiner, BlkResult, OnShare};
use crate::prooftree::ProofTree;
use crate::databuf::DataBuf;
use crate::types::{HeightWork,ClassSet};
use anyhow::{bail, Result};
use bytes::BufMut;
use log::{debug, info, trace, warn};
use packetcrypt_sys::difficulty::pc_degrade_announcement_target;
use packetcrypt_sys::difficulty::pc_get_effective_target;
use packetcrypt_util::poolclient::{self, PoolClient, PoolUpdate};
use packetcrypt_util::protocol;
use packetcrypt_util::{hash, util};
use rayon::prelude::*;
use std::iter;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct BlkArgs {
    pub payment_addr: String,
    pub threads: usize,
    pub downloader_count: usize,
    pub pool_master: String,
    pub max_mem: usize,
    pub min_free_space: f64,
    pub upload_timeout: usize,
    pub uploaders: usize,
    pub handler_pass: String,
    pub spray_cfg: Option<packetcrypt_sprayer::Config>,
}

#[derive(Default, Clone)]
struct CurrentMining {
    count: u32,
    ann_min_work: u32,
    using_tree: usize,
    mining_height: i32,
    time_started_ms: u64,
    coinbase_commit: bytes::BytesMut,
    block_header: bytes::BytesMut,

    // Number of shares found since last log report
    shares: usize,
}

struct CurrentWork {
    work: protocol::Work,
    conf: protocol::MasterConf,
}

pub struct BlkMineS {
    // Memory location where the actual announcements are stored
    block_miner: Arc<BlkMiner>,

    // The new specialized announcement store
    ann_store: AnnStore,

    trees: [Mutex<ProofTree>; 2],

    current_mining: Mutex<Option<CurrentMining>>,

    current_work: Mutex<Option<CurrentWork>>,

    // Maximum number of anns which we allow to mine at a time
    // This should be less than the size of the slab in order to allow
    // new anns to be added while mining is ongoing
    max_mining: u32,

    pcli: PoolClient,
    ba: BlkArgs,

    spray: Option<packetcrypt_sprayer::Sprayer>,

    share_channel_send: Mutex<tokio::sync::mpsc::UnboundedSender<Share>>,
    share_channel_recv: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Share>>,

    share_num: AtomicUsize,
}

#[derive(Clone)]
pub struct BlkMine(Arc<BlkMineS>);
impl std::ops::Deref for BlkMine {
    type Target = BlkMineS;
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

fn get_tree(bm: &BlkMine, active: bool) -> (&Mutex<ProofTree>, usize) {
    let at = bm
        .current_mining
        .lock()
        .unwrap()
        .as_ref()
        .unwrap_or(&CurrentMining::default())
        .using_tree;
    let tree_num = if active { at & 1 } else { (at & 1) ^ 1 };
    (&bm.trees[tree_num], tree_num)
}

fn get_current_mining(bm: &BlkMine) -> Option<CurrentMining> {
    let mut cm_l = bm.current_mining.lock().unwrap();
    let cm_o: &mut Option<CurrentMining> = &mut *cm_l;
    let out = cm_o.clone();
    if let Some(mut cm) = cm_o.as_mut() {
        cm.shares = 0;
    }
    out
}

trait GetAnn {
    fn get_ann(&self, num: usize) -> &[u8];
    fn ann_count(&self) -> usize;
}
impl GetAnn for bytes::Bytes {
    fn get_ann(&self, num: usize) -> &[u8] {
        &self[num * 1024..(num + 1) * 1024]
    }
    fn ann_count(&self) -> usize {
        self.len() / 1024
    }
}

pub struct AnnChunk<'a> {
    pub anns: &'a [&'a [u8]],
    pub indexes: &'a [u32],
}

impl<'a> GetAnn for AnnChunk<'a> {
    fn get_ann(&self, num: usize) -> &[u8] {
        self.anns[self.indexes[num] as usize]
    }
    fn ann_count(&self) -> usize {
        self.indexes.len()
    }
}

fn on_anns2(bm: &BlkMine, hw: HeightWork, ac: AnnChunk) {
    let total = bm.ann_store.push_anns(hw, &ac);

    // Stats
    if total < ac.indexes.len() {
        trace!(
            "Out of slab space, could only store {} out of {} anns",
            total,
            ac.indexes.len()
        );
    }
    // MY EARS!
    // trace!("Loaded {} ANNS", total);
}

impl packetcrypt_sprayer::OnAnns for BlkMine {
    fn on_anns(&self, anns: &[&[u8]]) {
        struct Ai {
            hw: HeightWork,
            index: u32,
        }
        let mut v: Vec<Ai> = Vec::with_capacity(anns.len());
        for (bytes, i) in anns.iter().zip(0..) {
            v.push(Ai {
                hw: HeightWork {
                    block_height: packetcrypt_sys::parent_block_height(bytes),
                    work: packetcrypt_sys::work_bits(bytes),
                },
                index: i,
            });
        }
        v.par_sort_unstable_by_key(|a| a.hw);

        let mut indexes: Vec<u32> = Vec::with_capacity(anns.len());
        let mut height_work: Option<HeightWork> = None;
        for ai in v {
            let hw = match height_work {
                None => {
                    indexes.push(ai.index);
                    height_work = Some(ai.hw);
                    continue;
                }
                Some(hw) => {
                    if hw == ai.hw {
                        indexes.push(ai.index);
                        continue;
                    }
                    hw
                }
            };
            // MY EARS!
            // trace!(
            //     "Batch of {} anns {} @ {}",
            //     indexes.len(),
            //     hw.block_height,
            //     packetcrypt_sys::difficulty::tar_to_diff(hw.work)
            // );
            on_anns2(
                self,
                hw,
                AnnChunk {
                    anns,
                    indexes: &indexes[..],
                },
            );
            indexes.clear();
            indexes.push(ai.index);
            height_work = Some(ai.hw);
        }
        if let Some(hw) = height_work {
            // Too much noise
            // trace!(
            //     "Batch of {} anns {} @ {}",
            //     indexes.len(),
            //     hw.block_height,
            //     packetcrypt_sys::difficulty::tar_to_diff(hw.work)
            // );
            on_anns2(
                self,
                hw,
                AnnChunk {
                    anns,
                    indexes: &indexes[..],
                },
            );
        }
    }
}

fn class_set_min_effective_work(cs: &ClassSet, next_work: &protocol::Work) -> u32 {
    cs.best_set.iter().map(|hw|{
        let age = std::cmp::max(0, next_work.height - hw.block_height) as u32;
        pc_degrade_announcement_target(hw.work, age)
    }).max().unwrap()
}

/// Get all ready classes, already ranked by effective ann work, compute effective work target for each
/// sub-set, and find the sub-set for which this resulting effective target is the highest.
fn reload_classes(bm: &BlkMine, next_height: i32) -> Option<ClassSet> {
    let mut ready = bm.ann_store.classes(next_height);
    ready.retain(|c| c.can_mine());

    // computes the cummulative counts of the anns within the classes.
    let counts = ready
        .iter()
        .scan(0u64, |acc, ci| {
            *acc += ci.ann_count as u64;
            Some(*acc)
        })
        .take_while(|&t| t < bm.max_mining as u64);

    // computes the effective work target, and find the sub-set of classes for which it is the highest.
    let (best, count) = ready.iter().zip(counts).max_by_key(|&(ci, count)| {
        pc_get_effective_target(0x1c160000, ci.ann_effective_work, count)
    })?;

    let best_set: Vec<HeightWork> = ready
        .iter()
        .take_while(|&ci| ci.hw != best.hw)
        .chain(iter::once(best))
        .map(|ci| ci.hw)
        .collect();

    let min_orig_work = best_set.iter().map(|hw|hw.work).max().unwrap();

    Some(ClassSet {
        min_orig_work,
        best_set,
        count,
    })
}

const COINBASE_COMMIT_LEN: usize = 50;
const COINBASE_COMMIT_PATTERN: [u8; COINBASE_COMMIT_LEN] = hex_literal::hex!(
    "
    6a3009f91102fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
    fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
"
);

fn compute_block_header(next_work: &protocol::Work, commit: &[u8]) -> bytes::BytesMut {
    let mut cnw = bytes::BytesMut::from(&next_work.coinbase_no_witness[..]);
    let pos = if let Some(pos) = cnw[..]
        .windows(COINBASE_COMMIT_LEN)
        .position(|w| w == COINBASE_COMMIT_PATTERN)
    {
        pos
    } else {
        panic!("Work did not contain commit pattern");
    };
    cnw[(pos + 2)..(pos + COINBASE_COMMIT_LEN)].copy_from_slice(&commit[..]);
    let txid = hash::compress_dsha256(&cnw[..]);
    let mut buf = [0; 64];
    buf[0..32].copy_from_slice(&txid[..]);
    for hash in &next_work.coinbase_merkle {
        buf[32..].copy_from_slice(&hash);
        let h = hash::compress_dsha256(&buf[..]);
        buf[0..32].copy_from_slice(&h[..]);
    }
    let mut bh = bytes::BytesMut::with_capacity(80);
    bh.put_u32_le(next_work.header.version);
    bh.put(&next_work.header.hash_prev_block[..]);
    bh.put(&buf[0..32]);
    bh.put_i32_le(next_work.header.time_seconds);
    bh.put_u32_le(next_work.header.work_bits);
    bh.put_u32_le(next_work.header.nonce);
    bh
}

pub struct Time {
    t0: Instant,
    tp: Instant,
}
impl Time {
    const PADDING: usize = 40;
    pub fn start() -> Time {
        let t = Instant::now();
        Time { t0: t, tp: t }
    }
    pub fn next(&mut self, name: &str) -> String {
        let t = Instant::now();
        let ms = (t - self.tp).as_millis();
        self.tp = t;
        format!(
            "{} : {}ms",
            &util::pad_to(Self::PADDING, name.to_string()),
            ms
        )
    }
    pub fn total(&self, name: &str) -> String {
        let t = Instant::now();
        let ms = (t - self.t0).as_millis();
        format!(
            "{} : {}ms",
            &util::pad_to(Self::PADDING, name.to_string()),
            ms
        )
    }
}

fn build_off_tree(bm: &BlkMine, next_height: i32) {
    let mut time = Time::start();
    let reload = if let Some(r) = reload_classes(bm, next_height) {
        r
    } else {
        debug!("Not mining, no anns ready");
        return;
    };
    debug!("Building tree for height {} in background ({}) classes", next_height, reload.best_set.len());
    //debug!("{}", time.next("tree.lock()"));
    let (tree, _) = get_tree(bm, false);
    //debug!("{}", time.next("get_tree"));
    let mut tree_l = tree.lock().unwrap();
    tree_l.reset();
    debug!("{}", time.next("Prepare"));
    bm.ann_store
        .compute_tree(reload, &mut tree_l, &mut time)
        .unwrap();
    debug!("{}", time.next("Background tree complete"));
}

fn on_work2(bm: &BlkMine, next_work: &protocol::Work) {
    let mut time = Time::start();

    bm.block_miner.request_stop();
    //debug!("{}", time.next("lock_miner.stop"));

    bm.ann_store
        .block(next_work.height - 1, next_work.header.hash_prev_block);
    //debug!("{}", time.next("ann_store.block"));

    let (tree, tree_num) = get_tree(bm, false);
    //debug!("{}", time.next("get_tree"));
    let mut tree_l = tree.lock().unwrap();

    let (real_target, current_mining);
    {
        let mew = if let Some((_,cs)) = tree_l.locked.as_ref() {
            let mew = class_set_min_effective_work(&cs, next_work);
            if mew < u32::MAX {
                debug!("Tree exists with ({}) classes, ({}) anns", cs.best_set.len(), cs.count);
            }
            mew
        } else {
            u32::MAX
        };
        let mew = if mew == u32::MAX {
            let reload = if let Some(r) = reload_classes(bm, next_work.height) {
                r
            } else {
                debug!("Not mining, no anns ready");
                return;
            };
            debug!("No usable tree, must build one now ({}) classes", reload.best_set.len());
            //debug!("{}", time.next("tree.lock()"));
            tree_l.reset();
            debug!("{}", time.next("Prepare"));
            let mew = class_set_min_effective_work(&reload, next_work);
            bm.ann_store
                .compute_tree(reload, &mut tree_l, &mut time)
                .unwrap();
            //debug!("{}", time.next("ann_store.compute_tree()"));
            mew
        } else {
            mew
        };

        //debug!("Computing block header");
        let coinbase_commit = tree_l.get_commit(mew).unwrap();
        //debug!("{}", time.next("tree_l.get_commit()"));
        let block_header = compute_block_header(next_work, &coinbase_commit[..]);
        //debug!("{}", time.next("compute_block_header()"));

        let count = tree_l.index_table.len();
        real_target = pc_get_effective_target(next_work.share_target, mew, count as u64);
        //debug!("{}", time.next("pc_get_effective_target()"));
        current_mining = CurrentMining {
            count: count as u32,
            ann_min_work: mew,
            using_tree: tree_num,
            mining_height: next_work.height,
            time_started_ms: util::now_ms(),
            coinbase_commit,
            block_header,
            shares: 0,
        };
    };

    //debug!("{}", time.next("Create Block Header"));

    bm.block_miner.await_stop();
    debug!("{}", time.next("block_miner.await_stop()"));

    // Self-test
    let br = bm
        .block_miner
        .fake_mine(&current_mining.block_header[..], &tree_l.index_table[..]);

    //debug!("Start mining...");
    bm.block_miner.mine(
        &current_mining.block_header[..],
        &tree_l.index_table[..],
        real_target,
        0,
    );
    //debug!("{}", time.next("block_miner.mine()"));

    trace!(
        "Mining with header {}",
        hex::encode(&current_mining.block_header)
    );
    debug!(
        "Mining {} with {} @ {}",
        next_work.height,
        tree_l.index_table.len(),
        packetcrypt_sys::difficulty::tar_to_diff(current_mining.ann_min_work),
    );

    drop(tree_l);

    debug!("{}", time.total("total time spent:"));

    bm.current_mining.lock().unwrap().replace(current_mining);

    // Validate self-test
    match make_share(bm, br, true) {
        Ok(_) => (),
        Err(e) => warn!("Failed to validate PcP, maybe hardware issues? {}", e),
    };

    build_off_tree(bm, next_work.height + 1);
}

pub async fn new(ba: BlkArgs) -> Result<BlkMine> {
    let pcli = poolclient::new(&ba.pool_master, 1, 1);
    let block_miner = Arc::new(BlkMiner::new(ba.max_mem as u64, ba.threads as u32)?);
    let max_anns = block_miner.max_anns;
    let spray = if let Some(sc) = &ba.spray_cfg {
        Some(packetcrypt_sprayer::Sprayer::new(sc)?)
    } else {
        None
    };
    let (send, recv) = tokio::sync::mpsc::unbounded_channel();
    let db = Arc::new(DataBuf::new(Arc::clone(&block_miner)));
    let bm = BlkMine(Arc::new(BlkMineS {
        block_miner: Arc::clone(&block_miner),
        ann_store: AnnStore::new(Arc::clone(&db)),
        trees: [
            Mutex::new(ProofTree::new(max_anns, Arc::clone(&db))),
            Mutex::new(ProofTree::new(max_anns, db)),
        ],
        current_mining: Mutex::new(None),
        current_work: Mutex::new(None),
        max_mining: ((1.0 - ba.min_free_space) * max_anns as f64) as u32,
        pcli,
        ba,
        spray,
        share_channel_recv: tokio::sync::Mutex::new(recv),
        share_channel_send: Mutex::new(send),
        share_num: AtomicUsize::new(0),
    }));
    bm.block_miner.set_handler(bm.clone());
    Ok(bm)
}

async fn update_work_cycle(bm: &BlkMine, chan: &mut tokio::sync::broadcast::Receiver<PoolUpdate>) {
    //debug!("Waiting for work");
    let update = if let Ok(x) = chan.recv().await {
        x
    } else {
        info!("Unable to get data from chan");
        util::sleep_ms(5_000).await;
        return;
    };
    let work_url = format!("{}/work_{}.bin", bm.pcli.url, update.conf.current_height);
    debug!("Getting work {}", work_url);
    let mut work_bin = if let Ok(x) = util::get_url_bin(&work_url).await {
        x
    } else {
        info!("Unable to download {}", work_url);
        util::sleep_ms(5_000).await;
        return;
    };
    let mut work = protocol::Work::default();
    if let Err(e) = protocol::work_decode(&mut work, &mut work_bin) {
        info!("Failed to deserialize work {} {:?}", work_url, e);
        util::sleep_ms(5000).await;
        return;
    };
    debug!("Got work {}", work_url);
    bm.current_work.lock().unwrap().replace(CurrentWork {
        work: work.clone(),
        conf: update.conf.clone(),
    });
    on_work2(bm, &work);
}

async fn update_work_loop(bm: &BlkMine) {
    let mut chan = poolclient::update_chan(&bm.pcli).await;
    loop {
        update_work_cycle(bm, &mut chan).await;
    }
}

async fn stats_loop(bm: &BlkMine) {
    loop {
        let (rdy, spare, cls, imm) = {
            let cw_l = bm.current_work.lock().unwrap();
            if let Some(w) = &*cw_l {
                let classes = bm.ann_store.classes(w.work.height);
                let (mut rdy, mut spr, mut cls, mut imm) = (0_isize, 0_isize, 0_isize, 0_isize);
                for c in classes {
                    cls += 1;
                    if c.can_mine() {
                        rdy += c.ann_count as isize;
                    } else if c.immature {
                        imm += c.ann_count as isize;
                    } else {
                        spr += crate::ann_class::ANNBUF_SZ as isize;
                    }
                }
                (rdy, spr, cls, imm)
            } else {
                (-1, -1, -1, -1)
            }
        };
        let spr = util::pad_to(
            27,
            format!("rdy: {} spr: {} imm: {} cls: {}", rdy, spare, imm, cls),
        );
        let dlst = if let Some(spray) = &bm.spray {
            let st = spray.get_peer_stats();
            let v = st
                .iter()
                .map(|s| format!("{}", s.packets_in / 1024))
                .collect::<Vec<_>>()
                .join(", ");
            format!(" {} <- [ {} ]", spr, v)
        } else {
            format!(" {} <- <sprayer disabled>", spr)
        };
        let start_mining = match get_current_mining(bm) {
            None => {
                info!("Not mining{}", dlst);
                true
            }
            Some(cm) => {
                let hashrate = bm.block_miner.hashes_per_second() as f64;
                let hrm = packetcrypt_sys::difficulty::pc_get_hashrate_multiplier(
                    cm.ann_min_work,
                    cm.count as u64,
                );

                let shr = util::pad_to(8, format!("shr: {} ", cm.shares));
                let hr = util::pad_to(
                    30,
                    format!(
                        "real: {}e/s eff: {}e/s ",
                        util::big_number(hashrate),
                        util::big_number(hashrate * hrm as f64)
                    ),
                );
                let diff = packetcrypt_sys::difficulty::tar_to_diff(cm.ann_min_work);
                let anns = util::pad_to(20, format!("anns: {} @ {}", cm.count, diff));
                info!("{}{}{}{}", shr, hr, anns, dlst);
                // Restart mining after 45s w/o a block
                util::now_ms() - cm.time_started_ms > 300_000
            }
        };
        if spare == 0 {
            info!("Out of buffer space, increasing --memorysizemb will improve efficiency");
        }
        // We relock every time if unused space is zero, in order to
        // keep fresh anns flowing in.
        #[allow(clippy::never_loop)] // yes, it's for the break statements.
        if start_mining {
            loop {
                let work = {
                    let cw_l = bm.current_work.lock().unwrap();
                    if let Some(w) = &*cw_l {
                        w.work.clone()
                    } else {
                        debug!("Could not launch miner, no work");
                        break;
                    }
                };
                on_work2(bm, &work);
                //debug!("Launched miner");
                break;
            }
        }
        util::sleep_ms(10_000).await;
    }
}

const PC_TYPE_PROOF: u64 = 1;
const PC_TYPE_VER: u64 = 4;
const PC_VERSION: u64 = 2;

fn share_id(block_header: &[u8], low_nonce: u32) -> u32 {
    let x = hash::compress32(block_header);
    let mut out: u32 = 0;
    let mut i = 4;
    loop {
        i -= 1;
        out <<= 8;
        out |= x[i] as u32;
        if i == 0 {
            return out ^ low_nonce;
        }
    }
}

struct Share {
    json: String,
    handler_url: String,
    num: usize,
}

impl OnShare for BlkMine {
    fn on_share(&self, res: BlkResult) {
        let s = match make_share(self, res, false) {
            Err(e) => {
                warn!("Unable to make share because {}", e);
                return;
            }
            Ok(s) => s,
        };
        if let Err(e) = self.share_channel_send.lock().unwrap().send(s) {
            warn!("Unable to send share to channel {}", e);
        }
    }
}

fn make_share(bm: &BlkMine, share: BlkResult, dry_run: bool) -> Result<Share> {
    // Get the header and commit
    let (mut header_and_proof, coinbase_commit, mining_height) = {
        let mut cm_l = bm.current_mining.lock().unwrap();
        let cm = match &mut *cm_l {
            Some(x) => x,
            None => bail!("no current_mining"),
        };
        if !dry_run {
            cm.shares += 1;
        }
        (
            cm.block_header.clone(),
            cm.coinbase_commit.clone().freeze(),
            cm.mining_height,
        )
    };

    // Set the correct nonce in the header
    header_and_proof.truncate(76);
    header_and_proof.put_u32_le(share.high_nonce);

    let (share_target, handler_url) = if dry_run {
        (0x207fffff, "dry_run".to_owned())
    } else {
        let id = share_id(&header_and_proof[..], share.low_nonce) as usize;
        let cw_l = bm.current_work.lock().unwrap();
        let cw = match &*cw_l {
            Some(x) => x,
            None => bail!("no current_work"),
        };
        (
            cw.work.share_target,
            cw.conf.submit_block_urls[id % cw.conf.submit_block_urls.len()].clone(),
        )
    };

    // Get the proof tree
    let (pb, tree_size) = {
        let mut tree_l = get_tree(bm, true).0.lock().unwrap();
        let mut llocs64 = [0u64; 4];
        for (i, x) in (0..).zip(share.ann_llocs.iter()) {
            llocs64[i] = *x as u64;
        }
        (match tree_l.mk_proof(&llocs64) {
            Ok(b) => b,
            // TODO(cjd): "Ann number out of range" every so often, random big number
            Err(e) => bail!("Mystery error - tree.mk_proof() -> {}", e),
        }, tree_l.size())
    };
    let pb = pb.freeze();

    // Get the 4 anns
    let anns = (0..4)
        .map(|i| {
            let mut ann = [0u8; 1024];
            bm.block_miner.get_ann(share.ann_mlocs[i], &mut ann[..]);
            ann
        })
        .collect::<Vec<_>>();

    trace!("Got share / {} / {} (tree_size: {})", share.high_nonce, share.low_nonce, tree_size);
    trace!("{}", hex::encode(&header_and_proof));
    trace!("{}", hex::encode(hash::compress32(&header_and_proof)));
    trace!("{}", hex::encode(&coinbase_commit));
    for (ann, i) in anns.iter().zip(0..) {
        trace!("{} - {}", share.ann_llocs[i], hex::encode(&ann[0..32]));
    }

    // At this point header_and_proof is really just the block header
    let share_n = match packetcrypt_sys::check_block_work(
        &header_and_proof,
        share.low_nonce,
        share_target,
        &anns,
        &coinbase_commit,
        mining_height,
        &pb,
    ) {
        Err(e) => {
            if e.contains("INSUF_POW") && dry_run {
                usize::MAX
            } else {
                bail!("Unable to validate share [{}]", e);
            }
        }
        Ok(h) => {
            if dry_run {
                usize::MAX
            } else {
                let share_n = bm
                    .share_num
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if !dry_run {
                    info!("[{}] Got share [{}]", share_n, hex::encode(h));
                }
                share_n
            }
        }
    };

    let proof_len = 4 + // low_nonce
            1024 * 4 + // anns
            pb.len(); // proof

    // reserve proof space
    header_and_proof.reserve(
        8 + // proof type + proof length
            proof_len +
            8, // version type + version length + version
    );
    protocol::put_varint(PC_TYPE_PROOF, &mut header_and_proof);
    protocol::put_varint(proof_len as u64, &mut header_and_proof);
    header_and_proof.put_u32_le(share.low_nonce);

    // Put the anns in the header_and_proof
    for ann in anns {
        header_and_proof.put(&ann[..]);
    }

    header_and_proof.put(pb);

    protocol::put_varint(PC_TYPE_VER, &mut header_and_proof);
    protocol::put_varint(1, &mut header_and_proof);
    protocol::put_varint(PC_VERSION, &mut header_and_proof);

    Ok(Share {
        json: serde_json::to_string(&protocol::BlkShare {
            header_and_proof: header_and_proof.freeze(),
            coinbase_commit,
        })?,
        handler_url,
        num: share_n,
    })
}

async fn post_share(bm: &BlkMine, share: Share) -> Result<()> {
    debug!("[{}] Posting share", share.num);
    let res = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(bm.ba.upload_timeout as u64))
        .build()?
        .post(&share.handler_url)
        .header("x-pc-payto", &bm.ba.payment_addr)
        .header("x-pc-sver", 1)
        .body(share.json)
        .send()
        .await?;

    let status = res.status();
    let resbytes = res.bytes().await?;
    let reply = if let Ok(x) = serde_json::from_slice::<protocol::BlkShareReply>(&resbytes) {
        x
    } else {
        bail!(
            "[{}] [{}] replied [{}]: [{}] which cannot be parsed",
            share.num,
            &share.handler_url,
            status,
            String::from_utf8_lossy(&resbytes[..])
        );
    };
    for e in &reply.error {
        let ee = if e.contains("Share is for wrong work, expecting previous hash") {
            "Stale share"
        } else {
            &e
        };
        warn!(
            "[{}] handler [{}] replied with error [{}]",
            share.num, &share.handler_url, ee
        );
    }
    for w in &reply.warn {
        warn!(
            "[{}] handler [{}] replied with warning [{}]",
            share.num, &share.handler_url, w
        );
    }
    //Validate_checkBlock_INSUF_POW
    let result = match reply.result {
        protocol::MaybeBlkShareEvent::Bse(bse) => bse,
        protocol::MaybeBlkShareEvent::Str(_) => {
            if !reply.error.is_empty() {
                // We don't need to continue to complain
                // The issue was raised already above
                return Ok(());
            }
            bail!(
                "[{}] handler [{}] replied with no result [{}]",
                share.num,
                &share.handler_url,
                String::from_utf8_lossy(&resbytes[..])
            );
        }
    };
    if let Some(hash) = result.header_hash {
        info!("[{}] BLOCK [{}]", share.num, hash);
    } else {
        debug!(
            "[{}] handler [{}] replied share: {}",
            share.num,
            &share.handler_url,
            result.header_hash.unwrap_or(result.event_id),
        );
    }
    Ok(())
}

async fn get_share_loop(bm: &BlkMine) {
    loop {
        let share = if let Some(s) = bm.share_channel_recv.lock().await.recv().await {
            s
        } else {
            warn!("Got a none from the receiver");
            continue;
        };
        if let Err(e) = post_share(bm, share).await {
            warn!("{}", e);
        }
    }
}

impl BlkMine {
    pub async fn start(&self) -> Result<()> {
        for _ in 0..self.ba.uploaders {
            let a = self.clone();
            tokio::spawn(async move { get_share_loop(&a).await });
        }
        {
            let a = self.clone();
            tokio::spawn(async move { update_work_loop(&a).await });
        }
        if let Some(spray) = &self.spray {
            spray.set_handler(self.clone());
            spray.start();
        } else {
            warn!("Sprayer disabled.")
        }
        {
            let a = self.clone();
            tokio::spawn(async move { stats_loop(&a).await });
        }
        poolclient::start(&self.pcli).await;
        Ok(())
    }
}
