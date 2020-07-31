// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::annminer::{self, AnnResult};
use crate::poolclient::{self, PoolClient};
use crate::protocol::AnnPostReply;
use crate::util;
use anyhow::Result;
use core::time::Duration;
use log::{debug, info, trace, warn};
use packetcrypt_sys::PacketCryptAnn;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver};
use tokio::sync::Mutex;

const RECENT_WORK_BUF: usize = 8;
const MAX_ANN_BATCH_SIZE: usize = 1024;
const MAX_MS_BETWEEN_POSTS: u64 = 30_000;

#[derive(Clone, Copy)]
struct WorkData {
    pub signing_key: [u8; 32],
    pub parent_block_hash: [u8; 32],
    pub parent_block_height: i32,
    pub ann_target: u32,
}

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

#[derive(Default, Clone, Copy, Debug)]
struct GoodRate {
    produced: usize,
    accepted: usize,
    time_sec: usize,
}

struct AnnMineM {
    top_work_number: i32,
    recent_work: [Option<WorkData>; RECENT_WORK_BUF],
    recv_ann: Option<UnboundedReceiver<AnnResult>>,
    recv_handlers: Option<Receiver<HandlersMsg>>,
    send_handlers: Sender<HandlersMsg>,
    send_upload: Option<Sender<AnnBatch>>,
    send_anns_per_second: Option<Sender<[AnnsPerSecond; STATS_SECONDS_TO_KEEP]>>,
    recv_anns_per_second: Option<Receiver<[AnnsPerSecond; STATS_SECONDS_TO_KEEP]>>,
    send_goodrate: Sender<GoodRate>,
    recv_goodrate: Option<Receiver<GoodRate>>,
}

pub struct AnnMineS {
    m: Arc<Mutex<AnnMineM>>,
    miner: annminer::AnnMiner,
    pcli: PoolClient,
    recv_upload: Mutex<Receiver<AnnBatch>>,
    cfg: AnnMineCfg,
    upload_num: AtomicUsize,
}
pub type AnnMine = Arc<AnnMineS>;

pub struct AnnMineCfg {
    pub miner_id: u32,
    pub workers: usize,
    pub uploaders: usize,
    pub pay_to: String,
    pub upload_timeout: usize,
}

const UPLOAD_CHANNEL_LEN: usize = 200;

pub async fn new(pcli: &PoolClient, cfg: AnnMineCfg) -> Result<AnnMine> {
    let (miner, recv_ann) = annminer::new(cfg.miner_id, cfg.workers);
    let (send_upload, recv_upload) = mpsc::channel(UPLOAD_CHANNEL_LEN);
    let (send_handlers, recv_handlers) = mpsc::channel(10);
    let (send_anns_per_second, recv_anns_per_second) = mpsc::channel(10);
    let (send_goodrate, recv_goodrate) = mpsc::channel(10);
    Ok(Arc::new(AnnMineS {
        m: Arc::new(Mutex::new(AnnMineM {
            top_work_number: -1,
            recent_work: [None; RECENT_WORK_BUF],
            recv_ann: Some(recv_ann),
            recv_handlers: Some(recv_handlers),
            send_handlers,
            send_upload: Some(send_upload),
            send_anns_per_second: Some(send_anns_per_second),
            recv_anns_per_second: Some(recv_anns_per_second),
            send_goodrate,
            recv_goodrate: Some(recv_goodrate),
        })),
        miner,
        pcli: Arc::clone(pcli),
        recv_upload: Mutex::new(recv_upload),
        cfg,
        upload_num: AtomicUsize::new(0),
    }))
}

// Don't exactly believe what the master says we should mine old anns, because we
// want to submit anns after the block changes and the js handler doesn't like this
// idea very much. TODO: When the js handler is gone, this can be dropped.
const SUPPORT_OLD_HANDLER: bool = true;

async fn update_work_loop(am: &AnnMine) {
    let mut chan = poolclient::update_chan(&am.pcli).await;
    loop {
        let update = if let Ok(x) = chan.recv().await {
            x
        } else {
            info!("Unable to get data from chan");
            util::sleep_ms(5_000).await;
            continue;
        };
        let pbh = update.work.height - 1;
        let mut m = am.m.lock().await;
        m.recent_work[(pbh as usize) % RECENT_WORK_BUF] = Some(WorkData {
            signing_key: update.work.signing_key,
            parent_block_hash: update.work.header.hash_prev_block,
            parent_block_height: update.work.height - 1,
            ann_target: update.work.ann_target,
        });
        if m.top_work_number > pbh {
            info!("Old work");
            continue;
        }
        m.top_work_number = pbh;
        if update.work.height < update.conf.current_height {
            // this is normal, it means we're syncing up old work
            continue;
        }

        let mine_old = if SUPPORT_OLD_HANDLER {
            if update.conf.mine_old_anns > 1 {
                update.conf.mine_old_anns - 2
            } else {
                0
            }
        } else {
            update.conf.mine_old_anns
        } as i32;

        // We're synced to the tip, begin mining (or start mining new anns)
        let job = if let Some(x) = m.recent_work[((pbh - mine_old) as usize) % RECENT_WORK_BUF] {
            x
        } else {
            // We don't have the old work yet
            continue;
        };
        match m.send_handlers.try_send(HandlersMsg {
            urls: update.conf.submit_ann_urls,
            parent_block_height: job.parent_block_height,
        }) {
            Ok(_) => (),
            Err(e) => info!("Error sending handler list, trying again later [{}]", e),
        };

        let signing_key = if util::is_zero(&job.signing_key) {
            None
        } else {
            Some(&job.signing_key[..])
        };
        debug!(
            "Start mining with parent_block_height: [{}] top: [{}] old: [{}]",
            job.parent_block_height, pbh, mine_old
        );
        match annminer::start(
            &am.miner,
            &job.parent_block_hash[..],
            job.parent_block_height,
            job.ann_target,
            signing_key,
        ) {
            Err(e) => warn!("Error starting annminer {}", e),
            _ => (),
        }
    }
}

fn check_get_handlers(
    recv_handlers: &mut Receiver<HandlersMsg>,
    handlers: Vec<Handler>,
) -> Vec<Handler> {
    if let Some(mut h) = {
        // Busy poll the channel until we get to the last item
        let mut last: Option<HandlersMsg> = None;
        loop {
            if let Ok(x) = recv_handlers.try_recv() {
                last = Some(x)
            } else {
                break;
            }
        }
        last
    } {
        if h.urls.iter().eq(handlers.iter().map(|x| &*x.url)) {
            handlers
        } else {
            if handlers.len() > 0 {
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
        Err(e) => info!("Failed to submit anns for upload {}", e),
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
        if handlers.len() < 1 {
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
        if handler.tip.parent_block_height > parent_block_height {
            debug!(
                "Miner produced an old announcement, want parent_block_height {} got {}",
                handler.tip.parent_block_height, parent_block_height
            );
            continue;
        } else if handler.tip.parent_block_height < parent_block_height {
            // this prints for each handler
            trace!(
                "New block number {} -> {}",
                handler.tip.parent_block_height,
                parent_block_height
            );
            submit_anns(handler, &mut send_upload, parent_block_height);
        }

        handler.tip.anns.push(ann_struct.ann);
        if handler.tip.anns.len() >= MAX_ANN_BATCH_SIZE
            || handler.tip.create_time + MAX_MS_BETWEEN_POSTS < now
        {
            submit_anns(handler, &mut send_upload, parent_block_height);
        }
    }
}

async fn upload_batch(am: &AnnMine, mut batch: AnnBatch, upload_n: usize) -> Result<u32> {
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
    let res = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(am.cfg.upload_timeout as u64))
        .build()?
        .post(&*batch.url)
        .header("x-pc-payto", &am.cfg.pay_to)
        .header("x-pc-sver", 1 as u32)
        .header("x-pc-annver", 1 as u32)
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
    if reply.error.len() > 0 {
        warn!(
            "[{}] handler [{}] replied with error [{:?}]",
            upload_n, &*batch.url, reply.error
        );
    } else if reply.warn.len() > 0 {
        warn!(
            "[{}] handler [{}] replied with warnings [{:?}]",
            upload_n, &*batch.url, reply.warn
        );
    }
    Ok(result.accepted)
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
    let (mut recv_anns_per_second, mut recv_goodrate) = {
        let mut m = am.m.lock().await;
        (
            m.recv_anns_per_second.take().unwrap(),
            m.recv_goodrate.take().unwrap(),
        )
    };
    let mut time_of_last_msg: u64 = 0;
    let mut goodrate_slots: [GoodRate; STATS_SECONDS_TO_KEEP] =
        [GoodRate::default(); STATS_SECONDS_TO_KEEP];
    loop {
        while let Ok(gr) = recv_goodrate.try_recv() {
            let slot = &mut goodrate_slots[gr.time_sec % STATS_SECONDS_TO_KEEP];
            if slot.time_sec != gr.time_sec {
                *slot = gr;
            } else {
                slot.accepted += gr.accepted;
                slot.produced += gr.produced;
            }
        }
        let raps = if let Some(x) = recv_anns_per_second.recv().await {
            x
        } else {
            warn!("Got nothing from recv_anns_per_second channel");
            continue;
        };
        let now = util::now_ms();
        if now - time_of_last_msg > 10_000 {
            let aps = raps[..].iter().map(|a| a.count).fold(0, |acc, x| acc + x)
                / (STATS_SECONDS_TO_KEEP - 1);
            let goodrate = goodrate_slots[..]
                .iter()
                .fold((0, 0), |acc, gr| (acc.0 + gr.accepted, acc.1 + gr.produced));
            let rate = if goodrate.1 > 0 {
                goodrate.0 as f32 / goodrate.1 as f32
            } else {
                1.0
            };
            let kbps = aps as f64 * 8.0;
            let kbps_reported = annminer::anns_per_second(&am.miner) * 8.0;
            if kbps > 0.0 {
                info!(
                    "{} ok: {}% (old metric reports: {})",
                    format_kbps(kbps),
                    (rate * 100.0) as u32,
                    format_kbps(kbps_reported),
                );
            }
            time_of_last_msg = now;
        }
    }
}

async fn uploader_loop(am: &AnnMine) {
    let mut send_goodrate = am.m.lock().await.send_goodrate.clone();
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
        let mut goodrate = GoodRate {
            produced: batch.anns.len(),
            accepted: 0,
            time_sec: util::now_ms() as usize / 1000,
        };
        match upload_batch(am, batch, upload_n).await {
            Ok(accepted) => goodrate.accepted = accepted as usize,
            Err(e) => warn!("[{}] Error uploading ann batch to {}: {}", upload_n, url, e),
        };
        match send_goodrate.try_send(goodrate) {
            Ok(_) => (),
            Err(e) => warn!("Unable to send goodrate to channel {}", e),
        };
    }
}

pub async fn start(am: &AnnMine) -> Result<()> {
    async_spawn!(am, {
        update_work_loop(&am).await;
    });
    async_spawn!(am, {
        handle_ann_loop(&am).await;
    });
    async_spawn!(am, {
        stats_loop(&am).await;
    });
    for _ in 0..am.cfg.uploaders {
        async_spawn!(am, {
            uploader_loop(&am).await;
        });
    }
    Ok(())
}
