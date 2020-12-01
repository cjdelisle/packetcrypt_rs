// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Result};
use crossbeam_channel::{
    Receiver as ReceiverCB, RecvTimeoutError, Sender as SenderCB, TryRecvError,
};
use log::{debug, error, info, trace, warn};
use packetcrypt_pool::paymakerclient::{self, PaymakerClient};
use packetcrypt_pool::poolcfg::AnnHandlerCfg;
use packetcrypt_sys::{check_ann, PacketCryptAnn, ValidateCtx};
use packetcrypt_util::poolclient::{self, PoolClient, PoolUpdate};
use packetcrypt_util::protocol::{AnnPostReply, AnnsEvent, BlockInfo, IndexFile, MasterConf};
use packetcrypt_util::{hash, util};
use regex::Regex;
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::sync::Mutex as MutexB; // blocking
use tokio::sync::oneshot;
use warp::Filter;

#[derive(Default, Clone, Copy)]
struct DedupEntry {
    hash: u64,
    ann_num: usize,
}

const NUM_BLOCKS_TRACKING: usize = 6;
const OUT_ANN_CAP: usize = 1024;
const WRITE_EVERY_MS: u64 = 30_000;
const POOL_UPDATE_QUEUE_LEN: usize = 20;
const RECV_WAIT_MS: u64 = 1000;
const FILE_WRITE_WORKERS: usize = 10;
const FILE_DELETE_WORKERS: usize = 20;

fn mk_dedups(w: &mut Worker) {
    w.dedups.clear();
    for (i, ann_opt) in (0..).zip(w.anns.iter()) {
        let h = hash::compress32(&ann_opt.as_ref().unwrap().bytes[..]);
        w.dedups.push(DedupEntry {
            hash: u64::from_le_bytes(h[..8].try_into().unwrap()),
            ann_num: i,
        });
    }
}

#[derive(Debug)]
struct Output {
    config: Config,
    time_of_last_write: u64,
    out: VecDeque<PacketCryptAnn>,
    dedup_tbl: VecDeque<u64>,
}

pub struct Global {
    outputs: [MutexB<Output>; NUM_BLOCKS_TRACKING],

    cfg: AnnHandlerCfg,

    // Http posts
    submit_send: SenderCB<AnnPost>,
    submit_recv: ReceiverCB<AnnPost>,

    // Work updates
    pc: PoolClient,
    pc_update_send: SenderCB<PoolUpdate>,
    pc_update_recv: ReceiverCB<PoolUpdate>,

    // Next file number
    fileno: AtomicUsize,

    pmc: PaymakerClient,

    // Write file jobs
    write_file_send: tokio::sync::mpsc::UnboundedSender<WriteJob>,
    write_file_recv: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<WriteJob>>,

    delete_list: tokio::sync::Mutex<VecDeque<String>>,

    sockaddr: std::net::SocketAddr,

    ann_file_regex: Regex,
    skip_check_chance: u8,

    anndir: String,
    tmpdir: String,
}

struct Worker {
    global: Arc<Global>,
    random: u8,
    payto_regex: Regex,
    anns: Vec<Option<PacketCryptAnn>>,
    dedups: Vec<DedupEntry>,
    vctx: ValidateCtx,
    write_jobs: VecDeque<WriteJob>,
}

const SUPPORT_V1: bool = true;

// This is a little bit tricky.
// Soft version 1 changes the rule from splitting by hash to splitting by soft nonce
// which allows the miners to send more anns to each handler.
//
// However, the soft version is not committed in the ann itself so someone could submit
// an ann to different handlers claiming versions 1 and 2 and get paid twice.
// To allow both version 1 and version 2 at the same time without opening up the chance
// of this happening, we use a hack. We reject any v1 announcements where the content/hash
// field is non-zero and reject any v2 anns where it is.
//
// If v1 is not supported then this rule is removed.
//
fn hash_num_ok(pnr: &AnnPostMeta, ann: &PacketCryptAnn, dedup: u64, conf: &Config) -> bool {
    if SUPPORT_V1 {
        if pnr.sver < 2 {
            if !util::is_zero(ann.content_hash()) {
                debug!("non-zero content hash, failing the ann");
                false
            } else if (dedup as usize % conf.handler_count) == conf.handler_num {
                true
            } else {
                debug!(
                    "dedup hash {} mod handler count {} != handler num {}",
                    dedup, conf.handler_count, conf.handler_num
                );
                false
            }
        } else if util::is_zero(ann.content_hash()) {
            debug!("zero content hash sver 2, failing the ann");
            false
        } else {
            (ann.hard_nonce() as usize % conf.handler_count) == conf.handler_num
        }
    } else {
        (ann.hard_nonce() as usize % conf.handler_count) == conf.handler_num
    }
}

fn validate_anns(
    w: &mut Worker,
    res: &mut AnnsEvent,
    pnr: &AnnPostMeta,
    conf: &Config,
) -> Result<()> {
    res.target = 0;
    for (ann_opt, dedup) in w.anns.iter().zip(w.dedups.iter()) {
        let ann = if let Some(x) = ann_opt {
            x
        } else {
            bail!("empty ann entry");
        };
        let unsigned = util::is_zero(ann.signing_key());
        if unsigned {
        } else if let Some(sk) = conf.signing_key {
            if sk != ann.signing_key() {
                bail!("wrong signing key");
            }
        } else {
            bail!("unexpected signed ann");
        }
        if conf.parent_block_height != ann.parent_block_height() {
            bail!(
                "wrong parent block height, want {} got {}",
                conf.parent_block_height,
                ann.parent_block_height()
            );
        } else if conf.min_work < ann.work_bits() {
            bail!("not enough work");
        } else if dedup.hash == 0 || dedup.hash == u64::MAX {
            bail!("zero or fff hash");
        } else if !hash_num_ok(pnr, ann, dedup.hash, conf) {
            bail!("submit elsewhere");
        } else if conf.ann_version != ann.version() {
            bail!("unsupported ann version");
        } else if (dedup.hash as u8 ^ w.random) < w.global.skip_check_chance {
            // fallthrough
        } else {
            let mut pbh = conf.parent_block_hash;
            pbh.reverse();
            if let Err(x) = check_ann(ann, &pbh, &mut w.vctx) {
                bail!("check_ann() -> {}", x);
            }
        }
        res.unsigned += unsigned as u32;
        // higher number represents less work
        res.target = max(res.target, ann.work_bits());
    }
    res.target = if res.target == 0 {
        conf.min_work
    } else {
        res.target
    };
    Ok(())
}

fn self_dedup(dedups: &mut Vec<DedupEntry>) -> u32 {
    let mut dupes = 0;
    let mut last_hash: u64 = 0;
    for dd in dedups.iter_mut() {
        if dd.hash == last_hash {
            dd.hash = 0;
            dupes += 1;
        }
        last_hash = dd.hash;
    }
    dupes
}

fn get_output(g: &Arc<Global>, parent_block_height: i32) -> &MutexB<Output> {
    &g.outputs[(parent_block_height as usize) % NUM_BLOCKS_TRACKING]
}

struct WriteJob {
    handler_num: usize,
    parent_block_height: i32,
    fileno: usize,
    anns: Vec<PacketCryptAnn>,
}

fn enqueue_write(w: &mut Worker, output: &mut Output) {
    output.time_of_last_write = util::now_ms();
    let anns: Vec<_> = {
        if output.out.len() == 0 {
            debug!("Nothing to write");
            return;
        }
        let l = min(OUT_ANN_CAP, output.out.len());
        output.out.drain(..l).collect()
    };
    //debug!("enqueue_write() with {} anns", anns.len());
    w.write_jobs.push_back(WriteJob {
        handler_num: output.config.handler_num,
        parent_block_height: output.config.parent_block_height,
        fileno: w
            .global
            .fileno
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        anns,
    });
}

fn optr<T>(o: Option<T>) -> Result<T> {
    match o {
        Some(t) => Ok(t),
        None => bail!("Option was none"),
    }
}

fn perform_dedup(w: &mut Worker, output: &mut Output, res: &mut AnnsEvent) -> Result<()> {
    //debug!("Perform dedup {} {}", w.dedups.len(), output.dedup_tbl.len());
    if output.dedup_tbl.front() == None {
        output.dedup_tbl.push_back(u64::MAX);
    } else if output.dedup_tbl.back() != Some(&u64::MAX) {
        bail!("Corrupt dedup table");
    }
    for dd in w.dedups.iter() {
        if dd.hash == 0 {
            // collision with zero, or it was marked invalid earlier
            continue;
        }
        let mut h = *output.dedup_tbl.front().unwrap();
        while h < dd.hash {
            output.dedup_tbl.rotate_left(1);
            h = *output.dedup_tbl.front().unwrap();
        }
        if h > dd.hash {
            output.dedup_tbl.push_back(dd.hash);
            output.out.push_back(optr(w.anns[dd.ann_num].take())?);
            res.accepted += 1;
        //debug!("Pushing ann");
        } else if h == dd.hash {
            res.dup += 1;
        }
    }
    while output.dedup_tbl.back() != Some(&u64::MAX) {
        output.dedup_tbl.rotate_left(1);
    }
    Ok(())
}

fn process_batch(
    w: &mut Worker,
    res: &mut AnnsEvent,
    pnr: &AnnPostMeta,
    conf: &Config,
) -> Result<()> {
    mk_dedups(w);
    validate_anns(w, res, pnr, conf)?;
    w.dedups.sort_by(|a, b| a.hash.cmp(&b.hash));
    res.dup += self_dedup(&mut w.dedups);
    let now = util::now_ms();

    let g = w.global.clone();
    let output_mtx = get_output(&g, conf.parent_block_height);
    {
        let mut output = output_mtx.lock().unwrap();
        //if let Some(out) = output.
        if output.config.parent_block_height != conf.parent_block_height {
            // we were too late
            bail!("block number out of range");
        }
        perform_dedup(w, &mut *output, res)?;
        while output.out.len() >= OUT_ANN_CAP || output.time_of_last_write + WRITE_EVERY_MS < now {
            enqueue_write(w, &mut *output);
        }
    }

    Ok(())
}

fn process_update(w: &mut Worker, conf: &MasterConf, bi: BlockInfo) {
    let g = w.global.clone();
    // note: this conf.current_height is the next height to be made, so we subtract 1
    let mut output = get_output(&g, bi.header.height).lock().unwrap();
    if bi.header.height != output.config.parent_block_height {
        if bi.header.height < output.config.parent_block_height {
            info!(
                "Ignoring old work: height: {} because we already have {}",
                bi.header.height, output.config.parent_block_height
            );
            return;
        }
        let out = &mut *output;
        while out.out.len() > 0 {
            enqueue_write(w, out);
        }
        out.dedup_tbl.clear();
        out.time_of_last_write = util::now_ms();
        debug!("New work: height: {}", bi.header.height);
    } else if bi.header.hash != output.config.parent_block_hash {
        info!(
            "Change of parent block {} -> {}",
            hex::encode(bi.header.hash),
            hex::encode(output.config.parent_block_hash)
        );
        output.out.clear();
        output.dedup_tbl.clear();
        output.time_of_last_write = util::now_ms();
    }
    output.config.handler_num = if let Some(x) = conf
        .submit_ann_urls
        .iter()
        .position(|u| u == &g.cfg.public_url)
    {
        x
    } else {
        error!(
            "This annhandler's URL {} is not in the list from the pool",
            &g.cfg.public_url
        );
        output.config.parent_block_height = -1;
        return;
    };
    output.config.handler_count = conf.submit_ann_urls.len();
    output.config.ann_version = *conf.ann_versions.get(0).unwrap_or(&1);
    output.config.signing_key = bi.sig_key;
    output.config.parent_block_hash = bi.header.hash;
    output.config.min_work = conf.ann_target.unwrap();
    output.config.parent_block_height = bi.header.height;
}

#[derive(Debug, Default, Clone, Copy)]
struct Config {
    // Accept only this version of announcements
    ann_version: u8,

    // 0-indexed number of this handler
    handler_num: usize,

    // Number of ann handlers
    handler_count: usize,

    // Refuse any ann signed with a different key, consider
    // anns unsigned if they don't bear any signature at all
    signing_key: Option<[u8; 32]>,

    // Hash of the parent block to expect for anns at this height
    parent_block_hash: [u8; 32],

    // Minimum amount of work that is acceptable for anns
    min_work: u32,

    // Height which must be used
    parent_block_height: i32,
}

struct AnnPostMeta {
    sver: u32,
    next_block_height: i32,
    pay_to: String,
    remote_addr: Option<SocketAddr>,
}

struct AnnPost {
    meta: AnnPostMeta,
    bytes: bytes::Bytes,
    reply: Option<oneshot::Sender<AnnPostReply>>,
}
fn process_submit1(w: &mut Worker, sub: AnnPost) -> Result<AnnPostReply> {
    let (meta, mut bytes) = (sub.meta, sub.bytes);
    let config = get_output(&w.global, meta.next_block_height - 1)
        .lock()
        .unwrap()
        .config;
    if config.parent_block_height != meta.next_block_height - 1 {
        if config.parent_block_height < 1 {
            bail!("server not ready");
        }
        bail!(
            "block number out of range, expect {} got {}",
            config.parent_block_height,
            meta.next_block_height - 1
        );
    }
    if !w.payto_regex.is_match(meta.pay_to.as_str()) {
        bail!("invalid payto {}", meta.pay_to.as_str());
    }
    if meta.pay_to.len() > 63 {
        bail!("payto too long");
    }
    if (bytes.as_ptr() as usize) % 4 != 0 {
        bytes = util::aligned_bytes(&bytes[..], 4);
        if (bytes.as_ptr() as usize) % 4 != 0 {
            bail!("bytes not aligned");
        }
    }
    if bytes.len() % 1024 != 0 {
        bail!("size not an even multiple of 1024");
    }
    w.anns.clear();
    for i in (0..bytes.len()).step_by(1024) {
        w.anns.push(Some(PacketCryptAnn {
            bytes: bytes.slice(i..(i + 1024)),
        }));
    }
    let mut res = AnnsEvent::default();
    res.anns_type = String::from("anns");
    res.pay_to = meta.pay_to.clone();
    res.event_id = hex::encode(&hash::compress32(&bytes)[..16]);
    res.time = util::now_ms();
    process_batch(w, &mut res, &meta, &config)?;
    Ok(AnnPostReply {
        error: vec![],
        warn: vec![],
        result: Some(res),
    })
}

fn process_submit0(w: &mut Worker, mut sub: AnnPost) {
    let remote_addr: Option<SocketAddr> = sub.meta.remote_addr.take();
    match sub
        .reply
        .take()
        .unwrap()
        .send(match process_submit1(w, sub) {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Error processing req from [{:?}] [{:?}]", &remote_addr, e);
                AnnPostReply {
                    error: vec![e.to_string()],
                    warn: vec![],
                    result: None,
                }
            }
        }) {
        Ok(_) => (),
        Err(e) => {
            info!("Error sending reply [{:?}]", e);
        }
    }
}

fn worker_loop(g: Arc<Global>) {
    let pc_update_recv = g.pc_update_recv.clone();
    let submit_recv = g.submit_recv.clone();
    let mut w: Worker = Worker {
        global: g,
        random: util::rand_u32() as u8,
        payto_regex: Regex::new(r"^[a-zA-Z0-9]+$").unwrap(),
        anns: Vec::new(),
        dedups: Vec::new(),
        vctx: ValidateCtx::default(),
        write_jobs: VecDeque::new(),
    };
    loop {
        for j in w.write_jobs.drain(..) {
            if let Err(e) = w.global.write_file_send.send(j) {
                warn!("error sending to write_file_send {}", e);
            }
        }
        loop {
            match pc_update_recv.try_recv() {
                Ok(upd) => {
                    for bi in upd.update_blocks {
                        process_update(&mut w, &upd.conf, bi);
                    }
                    continue;
                }
                Err(TryRecvError::Empty) => {
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    error!("pc_update_recv disconnected");
                }
            }
        }
        match submit_recv.recv_timeout(core::time::Duration::from_millis(RECV_WAIT_MS)) {
            Ok(sub) => {
                process_submit0(&mut w, sub);
                continue;
            }
            Err(RecvTimeoutError::Timeout) => (),
            Err(RecvTimeoutError::Disconnected) => {
                error!("submit_recv disconnected");
            }
        }
    }
}

pub type AnnHandler = Arc<Global>;

pub async fn new(
    pc: &PoolClient,
    pmc: &PaymakerClient,
    workdir: String,
    cfg: AnnHandlerCfg,
) -> Result<AnnHandler> {
    if cfg.skip_check_chance > 1.0 || cfg.skip_check_chance < 0.0 {
        bail!(
            "skip_check_chance must be a number between 0 and 1, got {}",
            cfg.skip_check_chance
        );
    }
    let now = util::now_ms();
    let outputs: Box<[_; NUM_BLOCKS_TRACKING]> = (0..NUM_BLOCKS_TRACKING)
        .map(|_| {
            MutexB::new(Output {
                config: Config::default(),
                time_of_last_write: now,
                out: VecDeque::new(),
                dedup_tbl: VecDeque::new(),
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
        .try_into()
        .unwrap();

    let anndir = format!("{}/anndir", workdir);
    util::ensure_exists_dir(&anndir).await?;
    let tmpdir = format!("{}/tmpdir", workdir);
    util::ensure_exists_dir(&tmpdir).await?;

    let ann_file_regex = Regex::new("^anns_[0-9]+_[0-9]+_([0-9]+).bin$")?;
    let top_ann_file = util::highest_num_file(&anndir, &ann_file_regex).await?;

    let (submit_send, submit_recv) = crossbeam_channel::bounded(cfg.input_queue_len);
    let (write_file_send, write_file_recv) = tokio::sync::mpsc::unbounded_channel();
    let (pc_update_send, pc_update_recv) = crossbeam_channel::bounded(POOL_UPDATE_QUEUE_LEN);
    let global = Arc::new(Global {
        outputs: *outputs,
        submit_send,
        submit_recv,
        pc: pc.clone(),
        pc_update_recv,
        pc_update_send,
        fileno: AtomicUsize::new(top_ann_file + 1),
        pmc: pmc.clone(),
        sockaddr: ([0; 16], cfg.bind_port).into(),
        skip_check_chance: 255 * cfg.skip_check_chance as u8,
        write_file_send,
        write_file_recv: tokio::sync::Mutex::new(write_file_recv),
        delete_list: tokio::sync::Mutex::new(VecDeque::new()),
        cfg,
        ann_file_regex,
        anndir,
        tmpdir,
    });

    Ok(global)
}

async fn handle_submit(
    ah: AnnHandler,
    remote_addr: Option<SocketAddr>,
    bytes: bytes::Bytes,
    //content_length: usize,
    sver: u32,
    next_block_height: i32,
    pay_to: String,
) -> Result<impl warp::Reply, Infallible> {
    let (reply, getreply) = oneshot::channel();
    match ah.submit_send.try_send(AnnPost {
        meta: AnnPostMeta {
            sver,
            next_block_height,
            pay_to,
            remote_addr,
        },
        bytes,
        reply: Some(reply),
    }) {
        Ok(_) => {
            let reply = getreply.await.unwrap();
            let ok = reply.error.len() == 0;
            if let Some(res) = &reply.result {
                if let Err(e) = paymakerclient::handle_paylog(&ah.pmc, &res).await {
                    error!("Unable to send paylog {}", e);
                }
            }
            Ok(warp::reply::with_status(
                warp::reply::json(&reply),
                if ok {
                    warp::http::StatusCode::OK
                } else {
                    warp::http::StatusCode::BAD_REQUEST
                },
            ))
        }
        Err(e) => {
            let err: String = (if e.is_full() {
                info!("server overloaded");
                "overloaded"
            } else {
                error!("channel disconnected");
                "disconnected"
            })
            .into();
            Ok(warp::reply::with_status(
                warp::reply::json(&AnnPostReply {
                    error: vec![err],
                    warn: vec![],
                    result: None,
                }),
                warp::http::StatusCode::SERVICE_UNAVAILABLE,
            ))
        }
    }
}

async fn write_file_loop(ah: &AnnHandler) {
    loop {
        let job = if let Some(x) = ah.write_file_recv.lock().await.recv().await {
            x
        } else {
            continue;
        };
        match util::write_file(
            &format!(
                "anns_{}_{}_{}.bin",
                job.parent_block_height, job.handler_num, job.fileno
            ),
            &ah.tmpdir,
            &ah.anndir,
            job.anns.iter().map(|ann| &ann.bytes),
        )
        .await
        {
            Ok(_) => (),
            Err(e) => {
                error!("write_file() -> {}", e);
            }
        }
    }
}

async fn delete_loop(ah: &AnnHandler) {
    loop {
        let file = {
            if let Some(x) = ah.delete_list.lock().await.pop_back() {
                x
            } else {
                continue;
            }
        };
        trace!("deleting old ann file [{}]", file);
        match tokio::fs::remove_file(file).await {
            Ok(_) => (),
            Err(e) => {
                error!("remove_file() -> {}", e);
            }
        }
    }
}

async fn try_maintanence(ah: &AnnHandler) -> Result<()> {
    let mut files = util::numbered_files(&ah.anndir, &ah.ann_file_regex).await?;
    files.sort_by(|a, b| b.1.cmp(&a.1));
    if files.len() > ah.cfg.files_to_keep {
        let mut delete_list_l = ah.delete_list.lock().await;
        for f in files.drain(ah.cfg.files_to_keep..) {
            let x = format!("{}/{}", &ah.anndir, f.0);
            if !delete_list_l.contains(&x) {
                delete_list_l.push_front(x);
            }
        }
    }
    let vecu8 = serde_json::to_vec(&IndexFile {
        highest_ann_file: files.get(0).map(|f| f.1).unwrap_or(0),
        files: files.drain(0..).map(|f| f.0).rev().collect(),
    })?;
    util::write_file(
        &String::from("index.json"),
        &ah.tmpdir,
        &ah.anndir,
        std::iter::once(&bytes::Bytes::from(vecu8)),
    )
    .await
}

const PAUSE_BETWEEN_MAINTANENCE_MS: u64 = 10_000;

async fn maintanence_loop(ah: &AnnHandler) {
    loop {
        if let Err(e) = try_maintanence(ah).await {
            error!("Failed maintanence loop [{}]", e);
        }
        util::sleep_ms(PAUSE_BETWEEN_MAINTANENCE_MS).await;
    }
}

pub async fn start(ah: &AnnHandler) {
    let sub = warp::post()
        .and(warp::path("submit"))
        .and(warp::path::end())
        .and((|ah: AnnHandler| warp::any().map(move || ah.clone()))(
            ah.clone(),
        ))
        .and(warp::filters::addr::remote())
        .and(warp::body::bytes())
        //.and(warp::header::<usize>("content-length"))
        .and(warp::header::<u32>("x-pc-sver"))
        .and(warp::header::<i32>("x-pc-worknum"))
        .and(warp::header::<String>("x-pc-payto"))
        .and_then(handle_submit);

    let anns = warp::path("anns").and(warp::fs::dir(ah.anndir.clone()));

    // Pipe new work updates through to a crossbeam channel
    util::tokio_bcast_to_crossbeam(
        "poolclient update",
        poolclient::update_chan(&ah.pc).await,
        ah.pc_update_send.clone(),
    )
    .await;

    for _ in 0..FILE_WRITE_WORKERS {
        packetcrypt_util::async_spawn!(ah, { write_file_loop(&ah).await });
    }
    for _ in 0..FILE_DELETE_WORKERS {
        packetcrypt_util::async_spawn!(ah, { delete_loop(&ah).await });
    }

    packetcrypt_util::async_spawn!(ah, { maintanence_loop(&ah).await });
    packetcrypt_util::async_spawn!(ah, { warp::serve(sub.or(anns)).run(ah.sockaddr).await });

    for _ in 0..(ah.cfg.num_workers) {
        let g = ah.clone();
        std::thread::spawn(move || {
            worker_loop(g);
        });
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use packetcrypt_sys::{check_ann, PacketCryptAnn, ValidateCtx};
    use packetcrypt_util::{hash, util};

    static ANN: [u8; 1024] = hex!(
        "
        01cd06000baf7821000002204398070000000000000000000000000000000000
        0000000000000000000000000000000000000000000000008a48028ff7d392a5
        dad2ecf812793d3d1f052053fe6947da093ab56ab2c7731fc7a0d07887b5e81c
        099d7a8976e3927bb0161a6fdad11b3906d0022eb173e8f1fd979ddc2e7a8415
        a5576a5427e9cae65a6a7f06450b4cf0b6cf7dc4a6096b4d64b1e9246aa4d5ac
        662502abbdb245e9600584c12469178ca8dea73edb0fcfa18f0eb776a40fe761
        041711b1c22454d225e51e27c267ead7b89a35e77c8c1806eb3cf5c846a86c3f
        c79908119cd2cd23a23812c38cf30cc4aec2fa24565db6c99302534cc0475b09
        c4544ba0cb1e68fc61cc7ff76da5b381becf4da233dbfe93f3b8736ca83d1474
        1692a466a5d0a4d085f4324c9d7ba40d5052319086338d85eb98d2065297be9e
        c4e9dedc4b92417deb1fdcb7103b2d4c65b779d30f02a6657887c623e2641ead
        0a8a8cb60cadb56e23984a32ce5d5581c6f0bceee3b6d70d8678a99d96a68fb4
        48e04c542823469c431c1fb8ca17f50d52560f0eb2f83964f7c5e64313e63c17
        9cac2d3381e39f272aecbc5e9859d75fe9734544c9df32203ade078a17f9bf2e
        2cb8f1c8b1ca631f502fac1985bcd92e3e58dfec535992182fce953df7c6fd6b
        8f31d78c4b7ec53e55135bf7a264d2217d1984a444bb421d42680a6ea9721b23
        d6dd937f6a0e1e102bfb50e6175425a80729643e49e1fa28882e5b790e14e1a9
        368a28e052ea0d46e29adb311b8291499ee0da03acd654677454b0f3410d1900
        da31fe77b9b382ec6a3d25ad959b502d89855c908e59d7000c7104f175bb1005
        5d3ad4a9557473d63878f9d8494bda01a3688f1f1bfdf26d73acbe93cd8bc890
        bbd9b81cf915ad8fd52e7b5ee3f35cabe6da2b74345d541da0b38a940321ac67
        d95e0cd0749644227da765a6d6319195f831cdda571e188fe01ac60e6218359d
        18cfed8aae4449011ee2d7bd0c637328fdfb589434d564a53b26009c8c0b4d8a
        9bc99c3992378f7dd251d248217bbd0b1e5b9905cfdfabb0bec0bee677a5a65e
        bb5cda542ae4076f6e0e4dba248639ce5861a7bca1748c4386941003d6375f0a
        fa79b921982d4ce6857df031b66865db723bf6068424e414da2714c9c31a0a5f
        8e2f16d673a5b11621158123414cf698ba85603c4be66b98c52df8ed0c58d7a0
        3db7362c9589a258cb3217d7df2cd3ef8c12dd879af19cd55b2e392900969948
        217c404b1dec0abad3dab0e5195825d0d3a5842ce5d181ce850a21b31041bd30
        bc4cac295da680057d83bdd67bf7c0ecc405c406c5a903cf67e0fd7ae128cca6
        1a7dc56366de128f1a662779699490f926acbf5e79aad7e3f6f1a1c8a4f1ff46
        83c622154dac17ad9141c4b4b2a733934af0b24ff24f81ec9a16058f2fee88d4"
    );

    #[test]
    fn hash() {
        let ann_hash = hash::compress32(&ANN);
        assert_eq!(
            hex::encode(&ann_hash[..]),
            "2684bd8f044073677ffd921023dd1cdd28c0605e6ba889d05b0f63663f7d50d4"
        );
    }

    #[test]
    fn validate() {
        let ann = PacketCryptAnn {
            bytes: util::aligned_bytes(&ANN, 4),
        };
        let mut parent_block_hash =
            hex!("255094b788fe98be51bafb4d941d507d4d5a949c751d1f68dfad0715215e1e48");
        // Bitcoin block header hashes are printed in reverse order
        parent_block_hash.reverse();
        let mut vctx = ValidateCtx::default();
        match check_ann(&ann, &parent_block_hash, &mut vctx) {
            Ok(_) => (),
            Err(x) => panic!("Checkanns failed with {}", x),
        }
    }
}
