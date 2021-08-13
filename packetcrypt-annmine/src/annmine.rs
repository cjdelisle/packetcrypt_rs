// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::annminer::{self, AnnResult};
use anyhow::{bail, Result};
use core::time::Duration;
use log::{debug, info, trace, warn};
use packetcrypt_sys::PacketCryptAnn;
use packetcrypt_util::poolclient::{self, PoolClient, PoolUpdate};
use packetcrypt_util::protocol::{AnnPostReply, BlockInfo};
use packetcrypt_util::util;
use std::cmp::max;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver};

const RECENT_WORK_BUF: usize = 8;
const MAX_ANN_BATCH_SIZE: usize = 1024;
const MAX_MS_BETWEEN_POSTS: u64 = 10_000;

struct AnnBatch {
    parent_block_height: i32,
    create_time: u64,
    anns: Vec<PacketCryptAnn>,
}

struct Handler {
    tip: Mutex<AnnBatch>,
    url: Arc<String>,
    recv_upload: tokio::sync::Mutex<Receiver<AnnBatch>>,
    send_upload: Sender<AnnBatch>,
}

const STATS_SECONDS_TO_KEEP: usize = 10;

#[derive(Default, Clone, Copy)]
struct AnnsPerSecond {
    time_sec: usize,
    count: usize,
    target: u32,
}

struct PoolMut {
    currently_mining: i32,
    recent_work: [Option<BlockInfo>; RECENT_WORK_BUF],
    handlers: Vec<Arc<Handler>>,
}
struct Pool {
    primary: bool,
    pcli: PoolClient,
    m: Mutex<PoolMut>,
    inflight_anns: AtomicUsize,
    lost_anns: AtomicUsize,
    accepted_anns: AtomicUsize,
    rejected_anns: AtomicUsize,
    overload_anns: AtomicUsize,
}

struct AnnMineM {
    recv_ann: Option<UnboundedReceiver<AnnResult>>,
    send_anns_per_second: Option<Sender<[AnnsPerSecond; STATS_SECONDS_TO_KEEP]>>,
    recv_anns_per_second: Option<Receiver<[AnnsPerSecond; STATS_SECONDS_TO_KEEP]>>,
}

pub struct AnnMineS {
    m: tokio::sync::Mutex<AnnMineM>,
    miner: annminer::AnnMiner,
    pools: Vec<Arc<Pool>>,
    cfg: AnnMineCfg,
    upload_num: AtomicUsize,
}
pub type AnnMine = Arc<AnnMineS>;

pub struct AnnMineCfg {
    pub pools: Vec<String>,
    pub miner_id: u32,
    pub workers: usize,
    pub uploaders: usize,
    pub pay_to: String,
    pub upload_timeout: usize,
    pub mine_old_anns: i32,
}

const UPLOAD_CHANNEL_LEN: usize = 100;

const PREFETCH_HISTORY_DEPTH: i32 = 6;

pub async fn new(cfg: AnnMineCfg) -> Result<AnnMine> {
    let pools = cfg
        .pools
        .iter()
        .zip(0..)
        .map(|(x, i)| {
            Arc::new(Pool {
                primary: i == 0,
                m: Mutex::new(PoolMut {
                    currently_mining: -1,
                    recent_work: [None; RECENT_WORK_BUF],
                    handlers: Vec::new(),
                }),
                pcli: poolclient::new(x, PREFETCH_HISTORY_DEPTH, 5),
                inflight_anns: AtomicUsize::new(0),
                lost_anns: AtomicUsize::new(0),
                accepted_anns: AtomicUsize::new(0),
                rejected_anns: AtomicUsize::new(0),
                overload_anns: AtomicUsize::new(0),
            })
        })
        .collect::<Vec<_>>();
    let (miner, recv_ann) = annminer::new(cfg.miner_id, cfg.workers);
    let (send_anns_per_second, recv_anns_per_second) = mpsc::channel(32);
    Ok(Arc::new(AnnMineS {
        m: tokio::sync::Mutex::new(AnnMineM {
            recv_ann: Some(recv_ann),
            send_anns_per_second: Some(send_anns_per_second),
            recv_anns_per_second: Some(recv_anns_per_second),
        }),
        miner,
        pools,
        cfg,
        upload_num: AtomicUsize::new(0),
    }))
}

fn update_work_cycle(am: &AnnMine, p: &Arc<Pool>, update: PoolUpdate) -> Vec<Arc<Handler>> {
    let mut pm = p.m.lock().unwrap();
    let mut top = 0;
    for bi in update.update_blocks {
        if let Some(rw) = pm.recent_work[(bi.header.height as usize) % RECENT_WORK_BUF].as_ref() {
            if rw.header.height > bi.header.height {
                // Old
                return Vec::new();
            }
        }
        top = max(bi.header.height, top);
        pm.recent_work[(bi.header.height as usize) % RECENT_WORK_BUF] = Some(bi);
    }
    let mine_old = if am.cfg.mine_old_anns > -1 {
        am.cfg.mine_old_anns
    } else {
        update.conf.mine_old_anns as i32
    };
    pm.currently_mining = max(pm.currently_mining, top - mine_old);

    // We're synced to the tip, begin mining (or start mining new anns)
    let job = if let Some(x) = pm.recent_work[(pm.currently_mining as usize) % RECENT_WORK_BUF] {
        x
    } else {
        // We don't have the work yet
        return Vec::new();
    };
    let mut changes = false;
    let mut out = Vec::new();
    {
        let mut i = 0;
        while i < pm.handlers.len() {
            let h = &pm.handlers[i];
            if !update.conf.submit_ann_urls.contains(&h.url) {
                info!(
                    "Dropping handler {} because it is nolonger in the pool",
                    h.url
                );
                out.push(pm.handlers.remove(i));
                changes = true;
            } else {
                i += 1;
            }
        }
    }
    for url in &update.conf.submit_ann_urls {
        if pm.handlers.iter().any(|h| &*h.url == url) {
            continue;
        }
        changes = true;
        info!("Adding handler {}", url);
        let (send_upload, recv_upload) = mpsc::channel(UPLOAD_CHANNEL_LEN);
        let h = Arc::new(Handler {
            recv_upload: tokio::sync::Mutex::new(recv_upload),
            tip: Mutex::new(AnnBatch {
                create_time: util::now_ms(),
                parent_block_height: job.header.height,
                anns: Vec::new(),
            }),
            url: Arc::new(url.clone()),
            send_upload,
        });
        for _ in 0..am.cfg.uploaders {
            let p1 = Arc::clone(p);
            let h1 = Arc::clone(&h);
            packetcrypt_util::async_spawn!(am, {
                uploader_loop(&am, p1, h1).await;
            });
        }
        pm.handlers.push(h);
    }

    if changes {
        // If there are any changes in the list of handlers then put them in the right order
        // because order of handlers is used to determine which ann should be sent where...
        let mut new_handlers = Vec::new();
        for url in &update.conf.submit_ann_urls {
            let mut i = 0;
            while i < pm.handlers.len() {
                let h = &pm.handlers[i];
                if &*h.url == url {
                    new_handlers.push(pm.handlers.remove(i));
                    break;
                }
                i += 1;
            }
        }
        assert!(pm.handlers.is_empty());
        pm.handlers = new_handlers;
    }

    if !p.primary {
        // got an update from a secondary pool
        return out;
    }

    let ann_target = if let Some(ann_target) = update.conf.ann_target {
        ann_target
    } else {
        info!("Pool did not provide ann_target, buggy pool");
        return out;
    };

    info!(
        "Start mining with parent_block_height: [{} @ {}] old: [{}]",
        hex::encode(job.header.hash),
        job.header.height,
        mine_old
    );
    // Reverse the parent block hash because hashes in bitcoin are always expressed backward
    let mut rev_hash = job.header.hash;
    rev_hash.reverse();
    if let Err(e) = annminer::start(
        &am.miner,
        rev_hash,
        job.header.height,
        ann_target,
        job.sig_key,
    ) {
        warn!("Error starting annminer {}", e);
    }
    out
}
async fn update_work_loop(am: &AnnMine, p: Arc<Pool>) {
    let mut chan = poolclient::update_chan(&p.pcli).await;
    loop {
        let update = if let Ok(x) = chan.recv().await {
            x
        } else {
            info!("Unable to get data from chan");
            util::sleep_ms(5_000).await;
            continue;
        };
        for to_shutdown in update_work_cycle(am, &p, update) {
            to_shutdown.recv_upload.lock().await.close();
        }
    }
}

fn submit_anns(
    p: &Pool,
    h: &Arc<Handler>,
    to_submit: &mut AnnBatch,
    send_upload: &mut Sender<AnnBatch>,
    next_parent_block_height: i32,
) {
    let mut tip = AnnBatch {
        create_time: util::now_ms(),
        parent_block_height: next_parent_block_height,
        anns: Vec::new(),
    };
    std::mem::swap(to_submit, &mut tip);
    trace!("Submit [{}] to [{}]", tip.anns.len(), h.url);
    match send_upload.try_send(tip) {
        Ok(_) => (),
        Err(tokio::sync::mpsc::error::TrySendError::Full(tip)) => {
            debug!("Failed to submit {} anns to {}", tip.anns.len(), h.url);
            p.lost_anns.fetch_add(tip.anns.len(), Ordering::Relaxed);
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            warn!("Failed to submit anns to {}, channel closed", h.url);
        }
    }
}

fn submit_to_pool(p: &Pool, ann_struct: &AnnResult, now: u64) {
    let parent_block_height = ann_struct.ann.parent_block_height();
    let handler = {
        let pm = p.m.lock().unwrap();
        let hcount = pm.handlers.len() as u64;
        if hcount == 0 {
            // no handlers for this pool yet
            return;
        }
        Arc::clone(&pm.handlers[(ann_struct.dedup_hash as u64 % hcount) as usize])
    };
    let mut tip = handler.tip.lock().unwrap();
    match tip.parent_block_height.cmp(&parent_block_height) {
        std::cmp::Ordering::Greater => {
            debug!(
                "Miner produced an old announcement, want parent_block_height {} got {}",
                tip.parent_block_height, parent_block_height
            );
            return;
        }
        std::cmp::Ordering::Less => {
            // this prints for each handler
            trace!(
                "New block number {} -> {}",
                tip.parent_block_height,
                parent_block_height
            );
            submit_anns(
                p,
                &handler,
                &mut *tip,
                &mut handler.send_upload.clone(),
                parent_block_height,
            );
        }
        std::cmp::Ordering::Equal => (),
    }

    tip.anns.push(ann_struct.ann.clone());
    if tip.anns.len() >= MAX_ANN_BATCH_SIZE || tip.create_time + MAX_MS_BETWEEN_POSTS < now {
        submit_anns(
            p,
            &handler,
            &mut *tip,
            &mut handler.send_upload.clone(),
            parent_block_height,
        );
    }
}

async fn handle_ann_loop(am: &AnnMine) {
    debug!("receive_ann begin0");
    let (mut recv_ann, mut send_anns_per_second) = {
        let mut m = am.m.lock().await;
        (
            m.recv_ann.take().unwrap(),
            m.send_anns_per_second.take().unwrap(),
        )
    };
    let mut stats: [AnnsPerSecond; STATS_SECONDS_TO_KEEP] =
        [AnnsPerSecond::default(); STATS_SECONDS_TO_KEEP];
    loop {
        let ann_struct = if let Some(x) = recv_ann.recv().await {
            x
        } else {
            debug!("polling recv() yielded nothing");
            continue;
        };
        //info!("ann {}", ann_struct.ann.hard_nonce());

        let now = util::now_ms();
        let now_sec = now as usize / 1000;
        let st = &mut stats[(now as usize / 1000) % STATS_SECONDS_TO_KEEP];
        let send_stats = if st.time_sec != now_sec {
            st.time_sec = now_sec;
            st.count = 1;
            st.target = ann_struct.ann.work_bits();
            true
        } else {
            st.count += 1;
            false
        };
        if send_stats {
            match send_anns_per_second.try_send(stats) {
                Ok(_) => (),
                Err(e) => info!("Unable to send anns per second [{}]", e),
            }
        }

        for p in &am.pools {
            submit_to_pool(p, &ann_struct, now);
        }
    }
}

async fn upload_batch(
    am: &AnnMine,
    client: &reqwest::Client,
    mut batch: AnnBatch,
    url: &str,
    upload_n: usize,
    p: &Arc<Pool>,
) -> Result<()> {
    debug!(
        "[{}] uploading [{}] anns to [{}]",
        upload_n,
        batch.anns.len(),
        url
    );
    let count = batch.anns.len();
    let v: Vec<Result<bytes::Bytes>> = batch
        .anns
        .drain(..)
        .map(|a| Ok(a.bytes) as Result<bytes::Bytes>)
        .collect();
    let stream = tokio::stream::iter(v);
    let body = reqwest::Body::wrap_stream(stream);
    // The server wants to see "work num" which is the height of the next block
    // and the parent_block_height is the height of the most recent mined block.
    let worknum = batch.parent_block_height + 1;
    let res = client
        .post(url)
        .header("x-pc-payto", &am.cfg.pay_to)
        .header("x-pc-sver", 1)
        .header("x-pc-annver", 1)
        .header("x-pc-worknum", worknum)
        .body(body)
        .send()
        .await?;
    let status = res.status();
    let resbytes = res.bytes().await?;
    let reply = if let Ok(x) = serde_json::from_slice::<AnnPostReply>(&resbytes) {
        x
    } else {
        bail!(
            "[{}] handler [{}] replied [{}]: [{}] which cannot be parsed",
            upload_n,
            url,
            status,
            String::from_utf8_lossy(&resbytes[..])
        );
    };
    let result = if let Some(x) = reply.result {
        x
    } else {
        if reply.error.iter().any(|x| x == "overloaded") {
            //am.overload_anns
            p.overload_anns.fetch_add(count, Ordering::Relaxed);
            return Ok(());
        }
        bail!(
            "[{}] handler [{}] replied with no result [{}]",
            upload_n,
            url,
            String::from_utf8_lossy(&resbytes[..])
        );
    };
    debug!(
        "[{}] handler [{}] replied: OK [{}]{}",
        upload_n,
        url,
        result.accepted,
        if result.dup > 0 {
            format!(", [{}] DUP", result.dup)
        } else {
            String::new()
        }
    );
    if !reply.error.is_empty() {
        warn!(
            "[{}] handler [{}] replied with error [{:?}]",
            upload_n, url, reply.error
        );
    } else if !reply.warn.is_empty() {
        warn!(
            "[{}] handler [{}] replied with warnings [{:?}]",
            upload_n, url, reply.warn
        );
    }
    //Ok(result.accepted as usize)
    p.accepted_anns
        .fetch_add(result.accepted as usize, Ordering::Relaxed);
    let rejected = count - (result.accepted as usize);
    if rejected > 0 {
        p.rejected_anns.fetch_add(rejected, Ordering::Relaxed);
    }
    Ok(())
}

async fn stats_loop(am: &AnnMine) {
    let mut recv_anns_per_second = {
        let mut m = am.m.lock().await;
        m.recv_anns_per_second.take().unwrap()
    };
    let mut time_of_last_msg: u64 = 0;
    loop {
        let raps = if let Some(x) = recv_anns_per_second.recv().await {
            x
        } else {
            warn!("Got nothing from recv_anns_per_second channel");
            continue;
        };
        let now = util::now_ms();
        if now - time_of_last_msg > 10_000 {
            let aps = raps[..].iter().map(|a| a.count).sum::<usize>() / (STATS_SECONDS_TO_KEEP - 1);
            let diff = packetcrypt_sys::difficulty::tar_to_diff(raps[0].target);
            let estimated_eps = diff * aps as f64;
            let kbps = (aps * am.pools.len()) as f64 * 8.0;

            let mut lost_anns = Vec::new();
            let mut inflight_anns = Vec::new();
            let mut accepted_rejected_over_anns = Vec::new();
            let mut rate = Vec::new();
            for p in &am.pools {
                let lost = p.lost_anns.swap(0, Ordering::Relaxed);
                lost_anns.push(format!("{}", lost));
                let inflight = p.inflight_anns.load(Ordering::Relaxed);
                inflight_anns.push(format!("{}", inflight));
                let accepted = p.accepted_anns.swap(0, Ordering::Relaxed);
                let rejected = p.rejected_anns.swap(0, Ordering::Relaxed);
                let over = p.overload_anns.swap(0, Ordering::Relaxed);
                accepted_rejected_over_anns.push(format!("{}/{}/{}", accepted, rejected, over));
                let total = lost + over + rejected + accepted;
                rate.push(format!(
                    "{}%",
                    ((if total > 0 {
                        accepted as f32 / total as f32
                    } else {
                        1.0
                    }) * 100.0) as u32,
                ));
            }

            if kbps > 0.0 {
                info!(
                    "{} {} overflow: {} uploading: {} accept/reject/overload: {} - goodrate: {}",
                    util::pad_to(10, format!("{}e/s", util::big_number(estimated_eps))),
                    util::pad_to(11, util::format_kbps(kbps)),
                    util::pad_to(5 * am.pools.len(), format!("[{}]", lost_anns.join(", "))),
                    util::pad_to(
                        8 * am.pools.len(),
                        format!("[{}]", inflight_anns.join(", "))
                    ),
                    util::pad_to(
                        12 * am.pools.len(),
                        format!("[{}]", accepted_rejected_over_anns.join(", "))
                    ),
                    format!("[{}]", rate.join(", "))
                );
            }
            time_of_last_msg = now;
        }
    }
}

async fn uploader_loop(am: &AnnMine, p: Arc<Pool>, h: Arc<Handler>) {
    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(am.cfg.upload_timeout as u64))
        .build()
        .unwrap();
    loop {
        let mut batch : Option<AnnBatch> = None;
        match h.recv_upload.lock().await.try_recv() {
            Ok(x) => {
                batch = Some(x);
            },
            Err(tokio::sync::mpsc::error::TryRecvError::Closed) => {
                break;
            },
            Err(_e) => (),
        }
        match batch {
            Some(batch) => {
                let upload_n = am
                    .upload_num
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let count = batch.anns.len();
                p.inflight_anns.fetch_add(count, Ordering::Relaxed);
                match upload_batch(am, &client, batch, &h.url, upload_n, &p).await {
                    Ok(_) => (),
                    Err(e) => {
                        warn!(
                            "[{}] Error uploading ann batch to {}: {}",
                            upload_n, h.url, e
                        );
                        p.lost_anns.fetch_add(count, Ordering::Relaxed);
                    }
                };
                p.inflight_anns.fetch_sub(count, Ordering::Relaxed);
            }
            None => {
                util::sleep_ms(10).await;
            }
        }
    }
    debug!("Uploader for {} shutting down", h.url);
}

pub async fn start(am: &AnnMine) -> Result<()> {
    packetcrypt_util::async_spawn!(am, {
        handle_ann_loop(&am).await;
    });
    packetcrypt_util::async_spawn!(am, {
        stats_loop(&am).await;
    });
    for p in &am.pools {
        poolclient::start(&p.pcli).await;
        let p1 = Arc::clone(p);
        packetcrypt_util::async_spawn!(am, {
            update_work_loop(&am, p1).await;
        });
    }
    Ok(())
}
