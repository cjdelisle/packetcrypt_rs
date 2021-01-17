// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::annminer::{self, AnnResult};
use anyhow::Result;
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
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver};
use tokio::sync::Mutex;

const RECENT_WORK_BUF: usize = 8;
const MAX_ANN_BATCH_SIZE: usize = 1024;
const MAX_MS_BETWEEN_POSTS: u64 = 30_000;

struct AnnBatch {
    url: Arc<String>,
    parent_block_height: i32,
    create_time: u64,
    anns: Vec<PacketCryptAnn>,
}

struct Handler {
    url: Arc<String>,
    tip: AnnBatch,
}

struct HandlersMsg {
    urls: Vec<String>,
    parent_block_height: i32,
}

const STATS_SECONDS_TO_KEEP: usize = 10;

#[derive(Default, Clone, Copy)]
struct AnnsPerSecond {
    time_sec: usize,
    count: usize,
}

struct AnnMineM {
    currently_mining: i32,
    recent_work: [Option<BlockInfo>; RECENT_WORK_BUF],
    recv_ann: Option<UnboundedReceiver<AnnResult>>,
    recv_handlers: Option<Receiver<HandlersMsg>>,
    send_handlers: Sender<HandlersMsg>,
    send_upload: Option<Sender<AnnBatch>>,
    send_anns_per_second: Option<Sender<[AnnsPerSecond; STATS_SECONDS_TO_KEEP]>>,
    recv_anns_per_second: Option<Receiver<[AnnsPerSecond; STATS_SECONDS_TO_KEEP]>>,
}

pub struct AnnMineS {
    m: Arc<Mutex<AnnMineM>>,
    miner: annminer::AnnMiner,
    pcli: PoolClient,
    recv_upload: Mutex<Receiver<AnnBatch>>,
    cfg: AnnMineCfg,
    upload_num: AtomicUsize,

    lost_anns: AtomicUsize,
    inflight_anns: AtomicUsize,
    accepted_anns: AtomicUsize,
    rejected_anns: AtomicUsize,
}
pub type AnnMine = Arc<AnnMineS>;

pub struct AnnMineCfg {
    pub master_url: String,
    pub miner_id: u32,
    pub workers: usize,
    pub uploaders: usize,
    pub pay_to: String,
    pub upload_timeout: usize,
    pub mine_old_anns: i32,
}

const UPLOAD_CHANNEL_LEN: usize = 200;

const PREFETCH_HISTORY_DEPTH: i32 = 6;

pub async fn new(cfg: AnnMineCfg) -> Result<AnnMine> {
    let pcli = poolclient::new(&cfg.master_url, PREFETCH_HISTORY_DEPTH, 30);
    let (miner, recv_ann) = annminer::new(cfg.miner_id, cfg.workers);
    let (send_upload, recv_upload) = mpsc::channel(UPLOAD_CHANNEL_LEN);
    let (send_handlers, recv_handlers) = mpsc::channel(32);
    let (send_anns_per_second, recv_anns_per_second) = mpsc::channel(32);
    Ok(Arc::new(AnnMineS {
        m: Arc::new(Mutex::new(AnnMineM {
            currently_mining: -1,
            recent_work: [None; RECENT_WORK_BUF],
            recv_ann: Some(recv_ann),
            recv_handlers: Some(recv_handlers),
            send_handlers,
            send_upload: Some(send_upload),
            send_anns_per_second: Some(send_anns_per_second),
            recv_anns_per_second: Some(recv_anns_per_second),
        })),
        miner,
        pcli,
        recv_upload: Mutex::new(recv_upload),
        cfg,
        upload_num: AtomicUsize::new(0),
        lost_anns: AtomicUsize::new(0),
        inflight_anns: AtomicUsize::new(0),
        accepted_anns: AtomicUsize::new(0),
        rejected_anns: AtomicUsize::new(0),
    }))
}

async fn update_work_cycle(am: &AnnMine, chan: &mut tokio::sync::broadcast::Receiver<PoolUpdate>) {
    let update = if let Ok(x) = chan.recv().await {
        x
    } else {
        info!("Unable to get data from chan");
        util::sleep_ms(5_000).await;
        return;
    };
    let ann_target = if let Some(ann_target) = update.conf.ann_target {
        ann_target
    } else {
        info!("Pool did not provide ann_target, buggy pool");
        util::sleep_ms(5_000).await;
        return;
    };
    let mut m = am.m.lock().await;
    let mut top = 0;
    for bi in update.update_blocks {
        if let Some(rw) = m.recent_work[(bi.header.height as usize) % RECENT_WORK_BUF].as_ref() {
            if rw.header.height > bi.header.height {
                // Old
                return;
            }
        }
        top = max(bi.header.height, top);
        m.recent_work[(bi.header.height as usize) % RECENT_WORK_BUF] = Some(bi);
    }
    let mine_old = if am.cfg.mine_old_anns > -1 {
        am.cfg.mine_old_anns
    } else {
        update.conf.mine_old_anns as i32
    };
    m.currently_mining = max(m.currently_mining, top - mine_old);

    // We're synced to the tip, begin mining (or start mining new anns)
    let job = if let Some(x) = m.recent_work[(m.currently_mining as usize) % RECENT_WORK_BUF] {
        x
    } else {
        // We don't have the work yet
        return;
    };
    match m.send_handlers.try_send(HandlersMsg {
        urls: update.conf.submit_ann_urls,
        parent_block_height: job.header.height,
    }) {
        Ok(_) => (),
        Err(e) => info!("Error sending handler list, trying again later [{}]", e),
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
}
async fn update_work_loop(am: &AnnMine) {
    let mut chan = poolclient::update_chan(&am.pcli).await;
    loop {
        update_work_cycle(am, &mut chan).await;
    }
}

fn check_get_handlers(
    recv_handlers: &mut Receiver<HandlersMsg>,
    handlers: Vec<Handler>,
) -> Vec<Handler> {
    if let Some(mut h) = {
        // Busy poll the channel until we get to the last item
        let mut last: Option<HandlersMsg> = None;
        while let Ok(x) = recv_handlers.try_recv() {
            last = Some(x);
        }
        last
    } {
        if h.urls.iter().eq(handlers.iter().map(|x| &*x.url)) {
            handlers
        } else {
            if !handlers.is_empty() {
                warn!(
                    "Change of handlers from {:?} to {:?}",
                    handlers.iter().map(|x| &*x.url).collect::<Vec<&String>>(),
                    h.urls
                );
            } else {
                info!("Got the list of handlers {:?}", h.urls);
            }
            let parent_block_height = h.parent_block_height;
            h.urls
                .drain(..)
                .map(|x| {
                    let url = Arc::new(x);
                    Handler {
                        url: Arc::clone(&url),
                        tip: AnnBatch {
                            create_time: util::now_ms(),
                            url,
                            parent_block_height,
                            anns: Vec::new(),
                        },
                    }
                })
                .collect()
        }
    } else {
        handlers
    }
}

fn submit_anns(
    am: &AnnMine,
    handler: &mut Handler,
    send_upload: &mut Sender<AnnBatch>,
    next_parent_block_height: i32,
) {
    let mut tip = AnnBatch {
        create_time: util::now_ms(),
        url: Arc::clone(&handler.tip.url),
        parent_block_height: next_parent_block_height,
        anns: Vec::new(),
    };
    std::mem::swap(&mut handler.tip, &mut tip);
    trace!("Submit [{}] to [{}]", tip.anns.len(), tip.url);
    match send_upload.try_send(tip) {
        Ok(_) => (),
        Err(tokio::sync::mpsc::error::TrySendError::Full(tip)) => {
            debug!("Failed to submit {} anns to {}", tip.anns.len(), tip.url);
            am.lost_anns.fetch_add(tip.anns.len(), Ordering::Relaxed);
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(tip)) => {
            warn!("Failed to submit anns to {}, channel closed", tip.url);
        }
    }
}

async fn handle_ann_loop(am: &AnnMine) {
    let (mut recv_ann, mut recv_handlers, mut send_upload, mut send_anns_per_second) = {
        let mut m = am.m.lock().await;
        (
            m.recv_ann.take().unwrap(),
            m.recv_handlers.take().unwrap(),
            m.send_upload.take().unwrap(),
            m.send_anns_per_second.take().unwrap(),
        )
    };
    let mut stats: [AnnsPerSecond; STATS_SECONDS_TO_KEEP] =
        [AnnsPerSecond::default(); STATS_SECONDS_TO_KEEP];
    let mut handlers: Vec<Handler> = Vec::new();
    loop {
        // TODO maybe not every time?
        handlers = check_get_handlers(&mut recv_handlers, handlers);
        let ann_struct = if let Some(x) = recv_ann.recv().await {
            x
        } else {
            debug!("polling recv() yielded nothing");
            continue;
        };
        //debug!("ann {}", ann_struct.ann.hard_nonce());
        if handlers.is_empty() {
            // no handlers yet
            continue;
        }

        let now = util::now_ms();
        let now_sec = now as usize / 1000;
        let st = &mut stats[(now as usize / 1000) % STATS_SECONDS_TO_KEEP];
        let send_stats = if st.time_sec != now_sec {
            st.time_sec = now_sec;
            st.count = 1;
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

        let parent_block_height = ann_struct.ann.parent_block_height();
        let hcount = handlers.len();
        let handler = &mut handlers[(ann_struct.dedup_hash as usize) % hcount];
        match handler.tip.parent_block_height.cmp(&parent_block_height) {
            std::cmp::Ordering::Greater => {
                debug!(
                    "Miner produced an old announcement, want parent_block_height {} got {}",
                    handler.tip.parent_block_height, parent_block_height
                );
                continue;
            }
            std::cmp::Ordering::Less => {
                // this prints for each handler
                trace!(
                    "New block number {} -> {}",
                    handler.tip.parent_block_height,
                    parent_block_height
                );
                submit_anns(am, handler, &mut send_upload, parent_block_height);
            }
            std::cmp::Ordering::Equal => (),
        }

        handler.tip.anns.push(ann_struct.ann);
        if handler.tip.anns.len() >= MAX_ANN_BATCH_SIZE
            || handler.tip.create_time + MAX_MS_BETWEEN_POSTS < now
        {
            submit_anns(am, handler, &mut send_upload, parent_block_height);
        }
    }
}

async fn upload_batch(
    am: &AnnMine,
    client: &reqwest::Client,
    mut batch: AnnBatch,
    upload_n: usize,
) -> Result<usize> {
    debug!(
        "[{}] uploading [{}] anns to [{}]",
        upload_n,
        batch.anns.len(),
        batch.url
    );
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
        .post(&*batch.url)
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
        warn!(
            "[{}] handler [{}] replied [{}]: [{}] which cannot be parsed",
            upload_n,
            &*batch.url,
            status,
            String::from_utf8_lossy(&resbytes[..])
        );
        return Ok(0);
    };
    let result = if let Some(x) = reply.result {
        x
    } else {
        warn!(
            "[{}] handler [{}] replied with no result [{}]",
            upload_n,
            &*batch.url,
            String::from_utf8_lossy(&resbytes[..])
        );
        return Ok(0);
    };
    debug!(
        "[{}] handler [{}] replied: OK [{}]{}",
        upload_n,
        &*batch.url,
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
            upload_n, &*batch.url, reply.error
        );
    } else if !reply.warn.is_empty() {
        warn!(
            "[{}] handler [{}] replied with warnings [{:?}]",
            upload_n, &*batch.url, reply.warn
        );
    }
    Ok(result.accepted as usize)
}

fn format_kbps(mut kbps: f64) -> String {
    for letter in "KMGPYZ".chars() {
        if kbps < 1000.0 {
            return format!("{}{}b/s", ((kbps * 100.0) as u32) as f64 / 100.0, letter);
        }
        kbps /= 1024.0;
    }
    String::from("???")
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
            let kbps = aps as f64 * 8.0;

            let lost_anns = am.lost_anns.swap(0, Ordering::Relaxed);
            let inflight_anns = am.inflight_anns.load(Ordering::Relaxed);
            let accepted_anns = am.accepted_anns.swap(0, Ordering::Relaxed);
            let rejected_anns = am.rejected_anns.swap(0, Ordering::Relaxed);
            let eps = annminer::encryptions_per_second(&am.miner);

            let total_anns = lost_anns + rejected_anns + accepted_anns;

            let rate = if total_anns > 0 {
                accepted_anns as f32 / total_anns as f32
            } else {
                1.0
            };
            if kbps > 0.0 {
                info!(
                    "{} {} overflow: {} uploading: {} accept/reject: {} - goodrate: {}%",
                    util::pad_to(10, format!("{}e/s", util::big_number(eps))),
                    util::pad_to(11, format_kbps(kbps)),
                    util::pad_to(3, format!("{}", lost_anns)),
                    util::pad_to(6, format!("{}", inflight_anns)),
                    util::pad_to(10, format!("{}/{}", accepted_anns, rejected_anns)),
                    (rate * 100.0) as u32,
                );
            }
            time_of_last_msg = now;
        }
    }
}

async fn uploader_loop(am: &AnnMine) {
    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(am.cfg.upload_timeout as u64))
        .build()
        .unwrap();
    loop {
        let batch = if let Some(x) = am.recv_upload.lock().await.recv().await {
            x
        } else {
            warn!("Got nothing polling upload channel");
            continue;
        };
        let upload_n = am
            .upload_num
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let url = Arc::clone(&batch.url);
        let count = batch.anns.len();
        am.inflight_anns.fetch_add(count, Ordering::Relaxed);
        match upload_batch(am, &client, batch, upload_n).await {
            Ok(accepted) => {
                am.accepted_anns.fetch_add(accepted, Ordering::Relaxed);
                if count > accepted {
                    let rejected = count - accepted;
                    am.rejected_anns.fetch_add(rejected, Ordering::Relaxed);
                }
            }
            Err(e) => warn!("[{}] Error uploading ann batch to {}: {}", upload_n, url, e),
        };
        am.inflight_anns.fetch_sub(count, Ordering::Relaxed);
    }
}

pub async fn start(am: &AnnMine) -> Result<()> {
    poolclient::start(&am.pcli).await;
    packetcrypt_util::async_spawn!(am, {
        update_work_loop(&am).await;
    });
    packetcrypt_util::async_spawn!(am, {
        handle_ann_loop(&am).await;
    });
    packetcrypt_util::async_spawn!(am, {
        stats_loop(&am).await;
    });
    for _ in 0..am.cfg.uploaders {
        packetcrypt_util::async_spawn!(am, {
            uploader_loop(&am).await;
        });
    }
    Ok(())
}
