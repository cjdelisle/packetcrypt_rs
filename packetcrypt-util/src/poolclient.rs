// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::protocol::{BlockInfo, MasterConf};
use crate::util;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct PoolClientM {
    mc: Option<MasterConf>,
    chain: HashMap<i32, BlockInfo>,
}

#[derive(Debug)]
pub struct PoolClientS {
    m: RwLock<PoolClientM>,
    pub url: String,
    poll_seconds: u64,
    notify: broadcast::Sender<PoolUpdate>,
    history_depth: i32,
}
pub type PoolClient = Arc<PoolClientS>;

pub fn new(url: &str, history_depth: i32, poll_seconds: u64) -> PoolClient {
    let (tx, _) = broadcast::channel::<PoolUpdate>(32);
    Arc::new(PoolClientS {
        m: RwLock::new(PoolClientM {
            mc: None,
            chain: HashMap::new(),
        }),
        poll_seconds,
        url: String::from(url),
        notify: tx,
        history_depth,
    })
}

#[derive(Clone)]
pub struct PoolUpdate {
    pub conf: MasterConf,
    pub update_blocks: Vec<BlockInfo>,
}

pub async fn update_chan(pcli: &PoolClient) -> Receiver<PoolUpdate> {
    pcli.notify.subscribe()
}

fn fmt_blk(hash: &[u8; 32], height: i32) -> String {
    format!("{} @ {}", hex::encode(&hash[..]), height)
}

async fn discover_block(pcli: &PoolClient, height: i32, hash: &[u8; 32]) -> Option<BlockInfo> {
    if let Some(bi) = pcli.m.read().await.chain.get(&height) {
        if &bi.header.hash == hash {
            debug!("We already know about block [{}]", fmt_blk(hash, height));
            return None;
        } else {
            // we have an entry for this block, but it is incorrect (rollback)
            info!(
                "ROLLBACK [{}] incorrect, replace with [{}]",
                fmt_blk(&bi.header.hash, height),
                fmt_blk(hash, height)
            );
        }
    } else {
        //debug!("New block [{}]", fmt_blk(&hash, height));
    }
    let url = format!("{}/blkinfo_{}.json", pcli.url, hex::encode(&hash[..]));
    loop {
        let text = match util::get_url_text(&url).await {
            Err(e) => {
                warn!(
                    "Failed to make request to {} because {:?} retry in 5 seconds",
                    &url, e
                );
                util::sleep_ms(5000).await;
                continue;
            }
            Ok(r) => r,
        };
        let bi = match serde_json::from_str::<BlockInfo>(text.as_str()) {
            Err(e) => {
                info!("Failed to deserialize block info {:?} {:?}", text, e);
                util::sleep_ms(5000).await;
                continue;
            }
            Ok(r) => r,
        };
        info!(
            "Discovered block [{}]",
            fmt_blk(&bi.header.hash, bi.header.height)
        );
        pcli.m.write().await.chain.insert(bi.header.height, bi);
        return Some(bi);
    }
}

// This takes a newly discovered block and returns a vector of blocks which have
// been changed. It calls the pool master iteratively in order to back-fill any
// blocks which are incorrect and it updates the local state appropriately.
async fn discover_blocks(pcli: &PoolClient, height: i32, hash: &[u8; 32]) -> Vec<BlockInfo> {
    let mut out: Vec<BlockInfo> = Vec::new();
    let mut xhash = *hash;
    let mut xheight = height;
    loop {
        if let Some(bi) = discover_block(pcli, xheight, &xhash).await {
            if bi.header.height <= height - pcli.history_depth {
                // We've backfilled enough history
                return out;
            }
            xhash = bi.header.previousblockhash;
            xheight -= 1;
            out.push(bi);
        } else {
            return out;
        };
    }
}

async fn cfg_loop(pcli: &PoolClient) {
    loop {
        let url = format!("{}/config.json", pcli.url);
        let text = match util::get_url_text(&url).await {
            Err(e) => {
                warn!(
                    "Failed to make request to {} because {:?} retry in 5 seconds",
                    &url, e
                );
                util::sleep_ms(5000).await;
                continue;
            }
            Ok(r) => r,
        };
        let conf = match serde_json::from_str::<MasterConf>(text.as_str()) {
            Err(e) => {
                info!("Failed to deserialize master conf {:?} {:?}", text, e);
                util::sleep_ms(5000).await;
                continue;
            }
            Ok(r) => r,
        };
        let tip_hash = if let Some(tip_hash) = conf.tip_hash {
            tip_hash
        } else {
            error!("Pool missing tipHash, this pool is too old to mine with");
            util::sleep_ms(5000).await;
            continue;
        };
        if {
            let pcr = pcli.m.read().await;
            if let Some(mcx) = &pcr.mc {
                !mcx.eq(&conf)
            } else {
                if pcr.mc == None {
                    info!("Got master config");
                } else {
                    info!("Change of master config");
                }
                true
            }
        } {
            let update_blocks = discover_blocks(pcli, conf.current_height - 1, &tip_hash).await;
            let mut pc = pcli.m.write().await;
            pc.mc = Some(conf.clone());
            if let Err(_) = pcli.notify.send(PoolUpdate {
                conf,
                update_blocks,
            }) {
                info!("Failed to send conf update to channel");
            }
        }
        util::sleep_ms(1_000 * pcli.poll_seconds).await;
    }
}

pub async fn start(pcli: &PoolClient) {
    async_spawn!(pcli, {
        cfg_loop(&pcli).await;
    });
}
