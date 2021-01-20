// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::blkminer::{BlkMiner, BlkResult};
use crate::downloader;
use crate::prooftree::ProofTree;
use anyhow::{bail, Result};
use bytes::BufMut;
use log::{debug, info, trace, warn};
use packetcrypt_sys::difficulty::{pc_degrade_announcement_target, pc_get_effective_target};
use packetcrypt_util::poolclient::{self, PoolClient, PoolUpdate};
use packetcrypt_util::protocol;
use packetcrypt_util::{hash, util};
use std::cmp::max;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

pub struct BlkArgs {
    pub payment_addr: String,
    pub threads: usize,
    pub downloader_count: usize,
    pub pool_master: String,
    pub max_mem: usize,
    pub min_free_space: f64,
    pub upload_timeout: usize,
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
    block_miner: BlkMiner,

    // Free space and discards from last mining lock
    inactive_infos: Mutex<Vec<AnnInfo>>,

    // Newly added, not yet selected for mining
    new_infos: Mutex<Vec<AnnInfo>>,

    // Currently in use mining (do not touch these anns)
    active_infos: Mutex<Vec<AnnInfo>>,

    trees: [Mutex<ProofTree>; 2],

    current_mining: Mutex<Option<CurrentMining>>,

    downloaders: tokio::sync::Mutex<Vec<downloader::Downloader<BlkMine>>>,

    current_work: Mutex<Option<CurrentWork>>,

    // Maximum number of anns which we allow to mine at a time
    // This should be less than the size of the slab in order to allow
    // new anns to be added while mining is ongoing
    max_mining: u32,

    pcli: PoolClient,
    ba: BlkArgs,
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

// Reclaims free space or poor quality AnnInfos which are not currently being mined
// This might not return the number of free items you want, it can even return 0
// if there is no space available.
fn get_free(bm: &BlkMine, mut count: u32) -> Vec<FreeInfo> {
    let mut inactive_l = bm.inactive_infos.lock().unwrap();
    let mut out = Vec::new();
    //debug!("Get {} free from {} inactives", count, inactive_l.len());
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
            if let Some(ai) = maybe_ai {
                out.push(ai);
            }
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
            if next_ai.is_none() {
                next_ai = Some(AnnInfo {
                    parent_block_height: stats.parent_block_height,
                    ann_min_work: stats.ann_min_work,
                    ann_effective_work: u32::MAX,
                    ann_count: 1,
                    hashes: vec![stats.hash],
                    mloc,
                })
            }
            next_ai
        };
    }
}

impl downloader::OnAnns for BlkMine {
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

        let stats = get_ann_stats(anns.slice(0..1024));
        {
            let cw_l = self.current_work.lock().unwrap();
            match &*cw_l {
                Some(cw) => {
                    let age = max(0, cw.work.height - stats.parent_block_height) as u32;
                    let ann_effective_work =
                        pc_degrade_announcement_target(stats.ann_min_work, age);
                    if age > 3 && ann_effective_work == 0xffffffff {
                        debug!("Discarding {} because it is already out of date", url);
                        return;
                    }
                }
                None => (),
            }
        }

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
                self.block_miner
                    .put_ann(r.mloc + i, &anns[ann_index..(ann_index + 1024)]);
                ann_index += 1024;
                count_landed += 1;
            }
        }

        // place the ann infos, this is what will make it possible to use the data
        let num_infos = info.len();
        self.new_infos.lock().unwrap().append(&mut info);

        // Stats
        if count_landed != count {
            debug!(
                "Out of slab space, could only store {} of {} anns from req {}",
                count_landed, count, url
            );
        }
        trace!(
            "Loaded {} ANNS - {} frees, {} infos",
            count_landed,
            num_frees,
            num_infos
        );
    }
}

struct ReloadAnns {
    ann_min_work: u32,
    effective_block_tar: u32,
}
fn reload_anns(
    bm: &BlkMine,
    next_work: &protocol::Work,
    active_l: &mut Vec<AnnInfo>,
) -> ReloadAnns {
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
        if ai.hashes.is_empty() {
            // This is the free space marker
            ai.ann_effective_work = u32::MAX;
        } else {
            let age = max(0, next_work.height - ai.parent_block_height) as u32;
            ai.ann_effective_work = pc_degrade_announcement_target(ai.ann_min_work, age);
            trace!(
                "computed effective work of ann {:#x} with age {} -> {:#x}",
                ai.ann_min_work,
                age,
                ai.ann_effective_work
            );
        }
    }
    debug!("reload_anns() processing {} ann files", v.len());
    // Sort by effective work, lowest numbers (most work) first
    v.sort_by(|a, b| a.ann_effective_work.cmp(&b.ann_effective_work));

    // Get the best subset
    let mut best_aew = 0xffffffff;
    let mut best_tar = 0;
    let mut best_i = 0;
    let mut sum_count = 0;
    for (i, elem) in (0..).zip(v.iter()) {
        if elem.ann_effective_work == 0xffffffff {
            continue;
        }
        sum_count += elem.ann_count;
        let tar = pc_get_effective_target(
            next_work.share_target,
            elem.ann_effective_work,
            sum_count as u64,
        );
        trace!(
            "reload_anns() try {}/{:#x}",
            sum_count,
            elem.ann_effective_work
        );
        if tar > best_tar {
            best_tar = tar;
            best_i = i;
            best_aew = elem.ann_effective_work;
        }
        if sum_count >= bm.max_mining {
            break;
        }
    }
    //debug!("Best target is {}, best_i {}", best_tar, best_i);

    for (i, elem) in (0..).zip(v.drain(..)) {
        if i >= best_i {
            inactive_l.push(elem);
        } else {
            active_l.push(elem);
        }
    }
    // This is important because if we keep inactive sorted
    inactive_l.sort_by(|b, a| a.parent_block_height.cmp(&b.parent_block_height));
    //debug!("active_l.len() -> {}", active_l.len());

    ReloadAnns {
        ann_min_work: best_aew,
        effective_block_tar: best_tar,
    }
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

fn on_work(bm: &BlkMine, next_work: &protocol::Work) {
    let (tree, tree_num) = get_tree(bm, false);
    let mut tree_l = tree.lock().unwrap();
    let mut active_l = bm.active_infos.lock().unwrap();
    let reload = reload_anns(bm, next_work, &mut active_l);
    tree_l.reset();
    for ai in active_l.iter() {
        //debug!("active_l has {} hashes", ai.hashes.len());
        for (h, i) in ai.hashes.iter().zip(0..) {
            let mloc = ai.mloc + i;
            assert!(mloc < bm.block_miner.max_anns);
            tree_l.push(h, ai.mloc + i).unwrap();
        }
    }
    if tree_l.size() == 0 {
        bm.block_miner.stop();
        debug!("Not mining, no anns ready");
        return;
    }
    debug!(
        "Start mining {} with {} anns, min_work={:#x}",
        next_work.height,
        tree_l.size(),
        reload.ann_min_work,
    );
    let index_table = tree_l.compute().unwrap();
    let coinbase_commit = tree_l.get_commit(reload.ann_min_work).unwrap();
    let block_header = compute_block_header(next_work, &coinbase_commit[..]);
    bm.block_miner.mine(
        &block_header[..],
        &index_table[..],
        reload.effective_block_tar,
    );
    bm.current_mining.lock().unwrap().replace(CurrentMining {
        count: index_table.len() as u32,
        ann_min_work: reload.ann_min_work,
        using_tree: tree_num,
        mining_height: next_work.height,
        time_started_ms: util::now_ms(),
        coinbase_commit,
        block_header,
        shares: 0,
    });
    debug!(
        "Started mining {} with {} anns",
        next_work.height,
        index_table.len()
    );
}

pub async fn new(ba: BlkArgs) -> Result<BlkMine> {
    let pcli = poolclient::new(&ba.pool_master, 1, 1);
    let block_miner = BlkMiner::new(ba.max_mem as u64, ba.threads as u32)?;
    let max_anns = block_miner.max_anns;
    Ok(BlkMine(Arc::new(BlkMineS {
        block_miner,
        inactive_infos: Mutex::new(vec![AnnInfo {
            parent_block_height: 0,
            ann_min_work: 0,
            ann_effective_work: 0,
            ann_count: max_anns,
            mloc: 0,
            hashes: Vec::new(),
        }]),
        new_infos: Mutex::new(Vec::new()),
        active_infos: Mutex::new(Vec::new()),
        trees: [
            Mutex::new(ProofTree::new(max_anns)),
            Mutex::new(ProofTree::new(max_anns)),
        ],
        downloaders: tokio::sync::Mutex::new(Vec::new()),
        current_mining: Mutex::new(None),
        current_work: Mutex::new(None),
        max_mining: ((1.0 - ba.min_free_space) * max_anns as f64) as u32,
        pcli,
        ba,
    })))
}

async fn downloader_loop(bm: &BlkMine) {
    let mut chan = poolclient::update_chan(&bm.pcli).await;
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
            if !urls.is_empty() {
                info!(
                    "Change of ann handler list {:?} -> {:?}",
                    urls, upd.conf.download_ann_urls
                )
            } else {
                info!("Got ann handler list {:?}", upd.conf.download_ann_urls)
            }
            let mut downloaders = bm.downloaders.lock().await.drain(..).collect::<Vec<_>>();
            for d in downloaders.drain(..) {
                downloader::stop(&d).await;
            }
            for url in &upd.conf.download_ann_urls {
                let dl = downloader::new(bm.ba.downloader_count, url.to_owned(), bm).await;
                downloader::start(&dl).await.unwrap();
                downloaders.push(dl);
            }
            bm.downloaders.lock().await.append(&mut downloaders);
            urls = upd.conf.download_ann_urls;
        }
    }
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
    on_work(bm, &work);
}

async fn update_work_loop(bm: &BlkMine) {
    let mut chan = poolclient::update_chan(&bm.pcli).await;
    loop {
        update_work_cycle(bm, &mut chan).await;
    }
}

async fn stats_loop(bm: &BlkMine) {
    loop {
        let unused = bm.inactive_infos.lock().unwrap().len();
        let ready = bm.new_infos.lock().unwrap().len();
        let mut downloaded: Vec<usize> = Vec::new();
        let mut downloading: Vec<usize> = Vec::new();
        let mut queued: Vec<usize> = Vec::new();
        for dl in bm.downloaders.lock().await.iter() {
            let st = downloader::stats(dl, true).await;
            downloaded.push(st.downloaded);
            downloading.push(st.downloading);
            queued.push(st.queued);
        }
        let spr = util::pad_to(27, format!("spare: {} rdy: {} ", unused, ready));
        let got = util::pad_to(19, format!("<- got: {:?} ", downloaded));
        let get = util::pad_to(19, format!("<- get: {:?} ", downloading));
        let dlst = format!("{} {} {} <- q: {:?}", spr, got, get, queued);
        let start_mining = match get_current_mining(bm) {
            None => {
                info!("Not mining - {}", dlst);
                true
            }
            Some(mut cm) => {
                let hashrate = bm.block_miner.hashes_per_second() as f64;
                let hrm = packetcrypt_sys::difficulty::pc_get_hashrate_multiplier(
                    cm.ann_min_work,
                    cm.count as u64,
                );
                let (tree, _) = get_tree(bm, true);
                let anns = tree.lock().unwrap().size();
                let shares = cm.shares;
                cm.shares = 0;

                let shr = util::pad_to(8, format!("shr: {} ", shares));
                let hr = util::pad_to(
                    30,
                    format!(
                        "real: {}e/s eff: {}e/s ",
                        util::big_number(hashrate),
                        util::big_number(hashrate * hrm as f64)
                    ),
                );
                let diff = packetcrypt_sys::difficulty::tar_to_diff(cm.ann_min_work);
                let anns = util::pad_to(20, format!("anns: {} @ {}", anns, diff));
                info!("{}{}{}{}", shr, hr, anns, dlst);
                // Restart mining after 45s w/o a block
                util::now_ms() - cm.time_started_ms > 45_000
            }
        };
        if unused == 0 {
            info!("Out of buffer space, increasing --memorysizemb will improve efficiency");
        }
        // We relock every time if unused space is zero, in order to
        // keep fresh anns flowing in.
        if start_mining || unused == 0 {
            let cw_l = bm.current_work.lock().unwrap();
            if let Some(w) = &*cw_l {
                on_work(bm, &w.work);
                debug!("Launched miner");
            } else {
                debug!("Could not launch miner, no work");
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

async fn post_share(bm: &BlkMine, share: BlkResult) -> Result<()> {
    // Get the header and commit
    let (mut header_and_proof, coinbase_commit) = {
        let mut cm_l = bm.current_mining.lock().unwrap();
        let cm = match &mut *cm_l {
            Some(x) => x,
            None => bail!("no current_mining"),
        };
        cm.shares += 1;
        (cm.block_header.clone(), cm.coinbase_commit.clone())
    };

    // Set the correct nonce in the header
    header_and_proof.truncate(76);
    header_and_proof.put_u32_le(share.high_nonce);

    let handler_url = {
        let id = share_id(&header_and_proof[..], share.low_nonce) as usize;
        let cw_l = bm.current_work.lock().unwrap();
        let cw = match &*cw_l {
            Some(x) => x,
            None => bail!("no current_work"),
        };
        cw.conf.submit_block_urls[id % cw.conf.submit_block_urls.len()].clone()
    };

    // Get the proof tree
    let pb = {
        let mut tree_l = get_tree(bm, true).0.lock().unwrap();
        let mut llocs64 = [0u64; 4];
        for (i, x) in (0..).zip(share.ann_llocs.iter()) {
            llocs64[i] = *x as u64;
        }
        match tree_l.mk_proof(&llocs64) {
            Ok(b) => b,
            // TODO(cjd): "Ann number out of range" every so often, random big number
            Err(e) => bail!("Mystery error - tree.mk_proof() -> {}", e),
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

    // Get the anns
    for i in 0..4 {
        let mut ann = [0u8; 1024];
        bm.block_miner.get_ann(share.ann_mlocs[i], &mut ann[..]);
        header_and_proof.put(&ann[..]);
    }

    header_and_proof.put(pb);

    protocol::put_varint(PC_TYPE_VER, &mut header_and_proof);
    protocol::put_varint(1, &mut header_and_proof);
    protocol::put_varint(PC_VERSION, &mut header_and_proof);

    let to_submit = serde_json::to_string(&protocol::BlkShare {
        header_and_proof: header_and_proof.freeze(),
        coinbase_commit: coinbase_commit.freeze(),
    })?;

    let res = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(bm.ba.upload_timeout as u64))
        .build()?
        .post(&handler_url)
        .header("x-pc-payto", &bm.ba.payment_addr)
        .header("x-pc-sver", 1)
        .body(to_submit)
        .send()
        .await?;

    let status = res.status();
    let resbytes = res.bytes().await?;
    let reply = if let Ok(x) = serde_json::from_slice::<protocol::BlkShareReply>(&resbytes) {
        x
    } else {
        bail!(
            "[{}] replied [{}]: [{}] which cannot be parsed",
            &handler_url,
            status,
            String::from_utf8_lossy(&resbytes[..])
        );
    };
    for e in &reply.error {
        let ee = if e.contains("Validate_checkBlock_INSUF_POW") {
            "Validate_checkBlock_INSUF_POW"
        } else {
            &e
        };
        warn!("handler [{}] replied with error [{}]", &handler_url, ee);
    }
    for w in &reply.warn {
        warn!("handler [{}] replied with warning [{}]", &handler_url, w);
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
                "handler [{}] replied with no result [{}]",
                &handler_url,
                String::from_utf8_lossy(&resbytes[..])
            );
        }
    };
    if let Some(hash) = result.header_hash {
        info!("BLOCK [{}]", hash);
    } else {
        debug!(
            "handler [{}] replied share: {}",
            &handler_url,
            result.header_hash.unwrap_or(result.event_id),
        );
    }
    Ok(())
}

async fn get_share_loop(bm: &BlkMine) {
    let mut receiver = bm.block_miner.receiver.lock().unwrap().take().unwrap();
    loop {
        let share = if let Some(s) = receiver.recv().await {
            s
        } else {
            debug!("Got a none from the receiver");
            util::sleep_ms(5_000).await;
            continue;
        };

        loop {
            // Drain the channel to prevent stales
            if receiver.try_recv().is_err() {
                break;
            }
        }

        debug!("share {} {}", share.high_nonce, share.low_nonce);
        if let Err(e) = post_share(bm, share).await {
            warn!("{}", e);
        }
        // header_and_proof -> header (fix nonce) + pad + proof
        // commit -> done already
    }
}

impl BlkMine {
    pub async fn start(&self) -> Result<()> {
        {
            let a = self.clone();
            tokio::spawn(async move { get_share_loop(&a).await });
        }
        {
            let a = self.clone();
            tokio::spawn(async move { update_work_loop(&a).await });
        }
        {
            let a = self.clone();
            tokio::spawn(async move { downloader_loop(&a).await });
        }
        {
            let a = self.clone();
            tokio::spawn(async move { stats_loop(&a).await });
        }
        poolclient::start(&self.pcli).await;
        Ok(())
    }
}
