// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::prooftree::ProofTree;
use crate::{blkslab, downloader};
use anyhow::{bail, Result};
use bytes::BufMut;
use log::{debug, info};
use packetcrypt_sys::difficulty::{pc_degrade_announcement_target, pc_get_effective_target};
use packetcrypt_util::poolclient::{self, PoolClient};
use packetcrypt_util::protocol;
use packetcrypt_util::{hash, util};
use std::cmp::max;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

pub struct BlkArgs {
    pub payment_addr: String,
    pub threads: usize,
    pub downloader_count: usize,
    pub pool_master: String,
    pub max_mem: usize,
    pub min_free_space: f64,
}

struct FreeInfo {
    // Number of anns at this location
    ann_count: u32,

    // Location of the ann in the memory slab
    mloc: u32,
}

#[derive(Clone, Default)]
struct AnnInfo {
    // Parent block height for this batch of anns
    parent_block_height: i32,

    // Work for this batch
    ann_min_work: u32,

    // Effective work for this batch, temporary and used when sorting active_infos
    ann_effective_work: u32,

    // Number of anns or ann slots at this memory location
    ann_count: u32,

    // Location of the ann in the memory slab
    mloc: u32,

    // Hashes of anns, empty if this represents a block of free space
    hashes: Vec<[u8; 32]>,
}

pub struct BlkMineS {
    // Memory location where the actual announcements are stored
    slab: blkslab::BlkSlab,

    // Free space and discards from last mining lock
    inactive_infos: Mutex<Vec<AnnInfo>>,

    // Newly added, not yet selected for mining
    new_infos: Mutex<Vec<AnnInfo>>,

    // Currently in use mining, do not touch
    active_infos: Mutex<Vec<AnnInfo>>,

    trees: [Mutex<ProofTree>; 2],
    active_tree: AtomicUsize,

    // Maximum number of anns which we allow to mine at a time
    // This should be less than the size of the slab in order to allow
    // new anns to be added while mining is ongoing
    max_mining: u32,

    pc: PoolClient,
    ba: BlkArgs,
}
pub type BlkMine = Arc<BlkMineS>;

fn get_tree(bm: &BlkMineS, active: bool) -> &Mutex<ProofTree> {
    let at = bm.active_tree.load(Ordering::Acquire);
    if active {
        &bm.trees[at]
    } else {
        &bm.trees[at ^ 1]
    }
}

// Reclaims free space or poor quality AnnInfos which are not currently being mined
// This might not return the number of free items you want, it can even return 0
// if there is no space available.
fn get_free(bm: &BlkMineS, mut count: u32) -> Vec<FreeInfo> {
    let mut inactive_l = bm.inactive_infos.lock().unwrap();
    let mut out = Vec::new();
    loop {
        if count == 0 {
            return out;
        }
        out.push(if let Some(mut ai) = inactive_l.pop() {
            if ai.ann_count > count {
                // Split the AnnInfo, taking the low mloc's and leaving the high ones
                let fi = FreeInfo {
                    ann_count: count,
                    mloc: ai.mloc,
                };
                ai.mloc += count;
                ai.ann_count -= count;
                if ai.hashes.len() > count as usize {
                    // remove the first n hashes so that the AnnInfo returned
                    // is still valid
                    ai.hashes.drain(0..(count as usize)).count();
                }
                inactive_l.push(ai);
                count = 0;
                fi
            } else {
                count -= ai.ann_count;
                FreeInfo {
                    ann_count: ai.ann_count,
                    mloc: ai.mloc,
                }
            }
        } else {
            return out;
        });
    }
}

struct AnnStats {
    parent_block_height: i32,
    ann_min_work: u32,
    hash: [u8; 32],
}
fn get_ann_stats(b: bytes::Bytes) -> AnnStats {
    let hash = hash::compress32(&b[..]);
    let a = packetcrypt_sys::PacketCryptAnn { bytes: b };
    AnnStats {
        parent_block_height: a.parent_block_height(),
        ann_min_work: a.work_bits(),
        hash,
    }
}

fn mk_ann_info(anns: &bytes::Bytes, mut free: Vec<FreeInfo>) -> Vec<AnnInfo> {
    let mut out = Vec::with_capacity(anns.len() / 1024);
    let mut ann_index = 0;
    let mut maybe_fi = free.pop();
    let mut maybe_ai: Option<AnnInfo> = None;
    loop {
        let mloc = if let Some(fi) = &mut maybe_fi {
            if fi.ann_count == 0 {
                maybe_fi = free.pop();
                continue;
            } else {
                fi.ann_count -= 1;
                fi.mloc += 1;
                fi.mloc - 1
            }
        } else {
            // Ran out of free space
            return out;
        };
        let stats = get_ann_stats(anns.slice(ann_index..(ann_index + 1024)));
        ann_index += 1024;
        maybe_ai = {
            let mut next_ai = None;
            if let Some(mut ai) = maybe_ai {
                if ai.ann_min_work == stats.ann_min_work
                    && ai.parent_block_height == stats.parent_block_height
                    && mloc == ai.mloc + ai.ann_count
                {
                    ai.ann_count += 1;
                    ai.hashes.push(stats.hash);
                    next_ai = Some(ai)
                } else {
                    out.push(ai);
                }
            }
            if let Some(ai) = next_ai {
                Some(ai)
            } else {
                Some(AnnInfo {
                    parent_block_height: stats.parent_block_height,
                    ann_min_work: stats.ann_min_work,
                    ann_effective_work: u32::MAX,
                    ann_count: 1,
                    hashes: vec![stats.hash],
                    mloc,
                })
            }
        };
    }
}

impl downloader::OnAnns for BlkMineS {
    fn on_anns(&self, anns: bytes::Bytes, url: &str) {
        // Get the number of anns
        let count = if anns.len() % 1024 == 0 {
            anns.len() / 1024
        } else {
            info!(
                "Anns [{}] had unexpected length [{}] (not a multiple of 1024)",
                url,
                anns.len()
            );
            return;
        } as u32;

        // Try to get unused space to place them
        let free = get_free(self, count);

        // generate ann infos from them
        let num_frees = free.len();
        let mut info = mk_ann_info(&anns, free);

        // place anns in the data buffer
        let mut ann_index = 0;
        let mut count_landed = 0;
        for r in &info {
            for i in 0..r.ann_count {
                blkslab::put_ann(&self.slab, &anns[ann_index..(ann_index + 1024)], r.mloc + i);
                ann_index += 1024;
                count_landed += 1;
            }
        }

        // place the ann infos, this is what will make it possible to use the data
        let num_infos = info.len();
        self.new_infos.lock().unwrap().append(&mut info);

        // Stats
        if count_landed != count {
            info!(
                "Out of slab space, could only store {} of {} anns from req {}",
                count_landed, count, url
            );
        }
        debug!(
            "Loaded {} ANNS - {} frees, {} infos",
            count_landed, num_frees, num_infos
        );
    }
}

fn reload_anns(bm: &BlkMine, next_work: &protocol::Work, active_l: &mut Vec<AnnInfo>) -> u32 {
    // Collect all of the active infos, inactive infos and new infos
    // compute effective work for everything
    // place discards into inactive, accepted into active, leave new as empty

    // Lets avoid unlocking inactive until we've re-added entries to it because
    // otherwise a call to on_anns will have no free work
    let mut inactive_l = bm.inactive_infos.lock().unwrap();
    let mut new_l = bm.new_infos.lock().unwrap();

    let mut v = Vec::with_capacity(inactive_l.len() + new_l.len() + active_l.len());
    v.append(&mut inactive_l);
    v.append(&mut new_l);
    v.append(active_l);
    for ai in &mut v {
        if ai.hashes.len() == 0 {
            ai.ann_effective_work = u32::MAX;
        } else {
            let age = max(0, next_work.height - ai.parent_block_height) as u32;
            ai.ann_effective_work = pc_degrade_announcement_target(ai.ann_min_work, age);
        }
    }
    // Sort by effective work, lowest numbers (most work) first
    v.sort_by(|a, b| {
        a.ann_effective_work
            .partial_cmp(&b.ann_effective_work)
            .unwrap()
    });

    // Get the best subset
    let mut best_tar = 0;
    let mut best_i = 0;
    let mut sum_count = 0;
    for (i, elem) in (0..).zip(v.iter()) {
        sum_count += elem.ann_count;
        let tar = pc_get_effective_target(
            next_work.share_target,
            elem.ann_effective_work,
            sum_count as u64,
        );
        if tar > best_tar {
            best_tar = tar;
            best_i = i;
        }
        if sum_count >= bm.max_mining {
            break;
        }
    }

    for (i, elem) in (0..).zip(v.drain(..)) {
        if i >= best_i {
            inactive_l.push(elem);
        } else {
            active_l.push(elem);
        }
    }

    best_tar
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
        .rev()
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

fn on_work(bm: &BlkMine, next_work: &protocol::Work) {
    let mut tree = get_tree(bm, false).lock().unwrap();
    let mut active_l = bm.active_infos.lock().unwrap();
    let min_work = reload_anns(bm, next_work, &mut active_l);
    tree.reset();
    for ai in active_l.iter() {
        for (h, i) in ai.hashes.iter().zip(0..) {
            tree.push(h, ai.mloc + i).unwrap();
        }
    }
    let index_table = tree.compute().unwrap();
    let commit = tree.get_commit(min_work).unwrap();
    let block_header = compute_block_header(next_work, &commit[..]);
    blkslab::put_work(&bm.slab, &block_header[..], &index_table[..]);
}

pub async fn new(ba: BlkArgs) -> Result<BlkMine> {
    let pc = poolclient::new(&ba.pool_master, 32);
    let slab = blkslab::alloc(ba.max_mem)?;
    let max_anns = slab.max_anns;
    Ok(Arc::new(BlkMineS {
        slab,
        inactive_infos: Mutex::new(Vec::new()),
        new_infos: Mutex::new(Vec::new()),
        active_infos: Mutex::new(Vec::new()),
        trees: [
            Mutex::new(ProofTree::new(max_anns as u32)),
            Mutex::new(ProofTree::new(max_anns as u32)),
        ],
        active_tree: AtomicUsize::new(0),
        max_mining: (1.0 - ba.min_free_space * max_anns as f64) as u32,
        pc,
        ba,
    }))
}

// On download, call add_anns()
// on new height, call on_work()

async fn downloader_loop(bm: &BlkMine) {
    let mut chan = poolclient::update_chan(&bm.pc).await;
    let mut downloaders: Vec<downloader::Downloader<BlkMineS>> = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    loop {
        let upd = match chan.recv().await {
            Ok(x) => x,
            Err(e) => {
                info!("Error recv from pool client channel {}", e);
                util::sleep_ms(5_000).await;
                continue;
            }
        };
        if upd.conf.download_ann_urls != urls {
            if urls.len() > 0 {
                info!(
                    "Change of ann handler list {:?} -> {:?}",
                    urls, upd.conf.download_ann_urls
                )
            } else {
                info!("Got ann handler list {:?}", upd.conf.download_ann_urls)
            }
            for d in downloaders.drain(..) {
                downloader::stop(&d).await;
            }
            for url in &upd.conf.download_ann_urls {
                let dl = downloader::new(bm.ba.downloader_count, url.to_owned(), bm).await;
                downloader::start(&dl).await.unwrap();
                downloaders.push(dl);
            }
            urls = upd.conf.download_ann_urls;
        }
    }
}

fn start_mining() {}
fn stop_mining() {}

pub async fn start(bm: &BlkMine) -> Result<()> {
    // 1. Launch mining threads
    // 2. Listen for update of chain tip
    // 3. On chain tip update -> download work
    // 4. On work -> call on_work()
    poolclient::start(&bm.pc).await;
    Ok(())
}
