// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Result};
use core::time::Duration;
use log::{debug, error, trace, warn};
use packetcrypt_util::poolclient::{self, PoolClient};
use packetcrypt_util::protocol::PaymakerReply;
use packetcrypt_util::{hash, util};
use regex::Regex;
use serde::Serialize;
use std::ops::Add;
use std::sync::Arc;
use tokio::fs::{read_dir, File};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

pub struct PaymakerClientMut {
    time_of_last_post: u64,
    current_pay_file: File,
    current_file_name: String,
    next_file_num: usize,
    maybe_paymaker_url: Option<String>,
}

pub struct _PaymakerClient {
    pmcm: Mutex<PaymakerClientMut>,
    payfile_regex: Regex,
    pc: PoolClient,
    cfg: PaymakerClientCfg,
}
pub type PaymakerClient = Arc<_PaymakerClient>;

pub struct PaymakerClientCfg {
    pub paylogdir: String,
    pub password: String,
    pub paylog_submit_every_ms: u64,
}

pub async fn new(pc: &PoolClient, cfg: PaymakerClientCfg) -> Result<PaymakerClient> {
    let payfile_regex = Regex::new("^paylog_([0-9]+).ndjson$")?;
    util::ensure_exists_dir(&cfg.paylogdir).await?;
    let next_file_num = util::highest_num_file(&cfg.paylogdir, &payfile_regex).await? + 1;
    let name = format!("{}/paylog_{}.ndjson", &cfg.paylogdir, next_file_num);
    Ok(Arc::new(_PaymakerClient {
        pmcm: Mutex::new(PaymakerClientMut {
            current_pay_file: File::create(&name).await?,
            current_file_name: name,
            time_of_last_post: util::now_ms(),
            next_file_num: next_file_num + 1,
            maybe_paymaker_url: None,
        }),
        payfile_regex,
        cfg,
        pc: pc.clone(),
    }))
}

async fn switch_paylogs(pmc: &PaymakerClient) -> Result<()> {
    let pmcm = &mut pmc.pmcm.lock().await;
    if pmcm.time_of_last_post + pmc.cfg.paylog_submit_every_ms > util::now_ms() {
    } else if pmcm.current_pay_file.metadata().await?.len() > 0 {
        pmcm.current_pay_file.shutdown();
        pmcm.current_file_name = format!(
            "{}/paylog_{}.ndjson",
            &pmc.cfg.paylogdir, pmcm.next_file_num
        );
        pmcm.current_pay_file = File::create(&pmcm.current_file_name).await?;
        pmcm.next_file_num += 1;
    }
    Ok(())
}

async fn switch_loop(pmc: &PaymakerClient) {
    loop {
        if let Err(e) = switch_paylogs(&pmc).await {
            error!("Unable to switch paylogs {}", e);
        }
        util::sleep_ms(30_000).await;
    }
}

async fn submit_loop(pmc: &PaymakerClient) {
    loop {
        match submit_paylogs(&pmc).await {
            Err(e) => {
                error!("Unable to submit paylogs {}", e);
                util::sleep_ms(5000).await;
            }
            Ok(t) => util::sleep_ms(t).await,
        }
    }
}

async fn pc_update_loop(pmc: &PaymakerClient) {
    let mut chan = poolclient::update_chan(&pmc.pc).await;
    loop {
        let update = if let Ok(x) = chan.recv().await {
            x
        } else {
            continue;
        };
        pmc.pmcm
            .lock()
            .await
            .maybe_paymaker_url
            .replace(update.conf.paymaker_url);
    }
}

pub async fn start(pmc: &PaymakerClient) {
    packetcrypt_util::async_spawn!(pmc, {
        switch_loop(&pmc).await;
    });
    packetcrypt_util::async_spawn!(pmc, {
        submit_loop(&pmc).await;
    });
    packetcrypt_util::async_spawn!(pmc, {
        pc_update_loop(&pmc).await;
    });
}

pub async fn handle_paylog<T>(pmc: &PaymakerClient, log: &T) -> Result<()>
where
    T: ?Sized + Serialize,
{
    let ser = serde_json::to_string(log)?;
    let mut pmcm = pmc.pmcm.lock().await;
    trace!("Writing to paylog {} {}", pmcm.current_file_name, ser);
    pmcm.current_pay_file
        .write_all(ser.add("\n").as_bytes())
        .await?;
    Ok(())
}
async fn submit_paylogs(pmc: &PaymakerClient) -> Result<u64> {
    let (maybe_paymaker_url, current_file_name) = {
        let pmcm = pmc.pmcm.lock().await;
        (
            pmcm.maybe_paymaker_url.clone(),
            pmcm.current_file_name.clone(),
        )
    };
    let paymaker_url = if let Some(x) = maybe_paymaker_url {
        x
    } else {
        //debug!("No paymaker_url yet");
        return Ok(10000);
    };
    let mut dir = read_dir(&pmc.cfg.paylogdir).await?;
    let mut uploaded = false;
    while let Some(f) = dir.next_entry().await? {
        let filename = if let Ok(s) = f.file_name().into_string() {
            s
        } else {
            continue;
        };
        let cap = if let Some(c) = pmc.payfile_regex.captures(&filename) {
            c
        } else {
            continue;
        };
        let fileno = if let Some(c) = cap.get(1) {
            c.as_str()
        } else {
            bail!("filename {:?} does not have a 1st capture group", filename);
        };
        if fileno.parse::<usize>().is_err() {
            warn!("Invalid file {:?}", filename);
            continue;
        }
        if current_file_name.ends_with(&filename) {
            // current_file_name is a full path and filename is just a file
            // Don't try to publish the file we currently have open
            continue;
        }
        let file = tokio::fs::read(f.path()).await?;
        if file.is_empty() {
            debug!("{} empty ({})", filename, current_file_name);
            tokio::fs::remove_file(f.path()).await?;
            continue;
        }
        let event_id = hex::encode(&hash::compress_sha256(&file)[..16]);
        uploaded = true;
        let res = reqwest::ClientBuilder::new()
            .timeout(Duration::from_millis(30_000))
            .build()?
            .post(&format!("{}/events", paymaker_url))
            .basic_auth("x", Some(&pmc.cfg.password))
            .body(file)
            .send()
            .await?;
        let status = res.status();
        let resbytes = res.bytes().await?;
        let reply = if let Ok(x) = serde_json::from_slice::<PaymakerReply>(&resbytes) {
            x
        } else {
            warn!(
                "{} Paymaker replied {}: {} which cannot be parsed",
                filename,
                status,
                String::from_utf8_lossy(&resbytes[..])
            );
            util::sleep_ms(5000).await;
            continue;
        };
        if reply.error.is_empty() {
            warn!(
                "{} Paymaker replied with errors: {}",
                filename,
                reply.error.join(", ")
            );
        }
        if reply.warn.is_empty() {
            warn!(
                "{} Paymaker is warning us: {}",
                filename,
                reply.warn.join(", ")
            );
        }
        let result = if let Some(x) = reply.result {
            x
        } else {
            warn!("{} Paymaker replied without a result", filename);
            util::sleep_ms(5000).await;
            continue;
        };
        if result.event_id != event_id {
            warn!(
                "{} Paymaker replied with event id {} which is different from ours {}",
                filename,
                status,
                String::from_utf8_lossy(&resbytes[..])
            );
            util::sleep_ms(5000).await;
            continue;
        }
        debug!("{} ok", filename);
        tokio::fs::remove_file(f.path()).await?;
    }
    Ok(if uploaded { 10_000 } else { 30_000 })
}
