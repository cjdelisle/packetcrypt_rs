// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::protocol::{work_decode, MasterConf, Work};
use crate::util;
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct PoolClientS {
    url: String,
    mc: Option<MasterConf>,
    work: Option<Work>,
    notify: broadcast::Sender<PoolUpdate>,
}
pub type PoolClient = Arc<RwLock<PoolClientS>>;

pub fn new(url: &str) -> PoolClient {
    let (tx, _) = broadcast::channel::<PoolUpdate>(3);
    Arc::new(RwLock::new(PoolClientS {
        url: String::from(url),
        mc: None,
        work: None,
        notify: tx,
    }))
}

#[derive(Clone)]
pub struct PoolUpdate {
    pub conf: MasterConf,
    pub work: Work,
}

pub async fn update_chan(pcli: &PoolClient) -> Receiver<PoolUpdate> {
    pcli.read().await.notify.subscribe()
}

async fn cfg_loop(pcli: PoolClient) {
    loop {
        let url = {
            let locked = pcli.write().await;
            format!("{}/config.json", locked.url)
        };
        let text = match util::get_url_text(&url).await {
            Err(e) => {
                info!("Failed to make request {:?} retry in 5 seconds", e);
                util::sleep_ms(5000).await;
                continue;
            }
            Ok(r) => r,
        };
        let mc = match serde_json::from_str::<MasterConf>(text.as_str()) {
            Err(e) => {
                info!("Failed to deserialize master conf {:?} {:?}", text, e);
                util::sleep_ms(5000).await;
                continue;
            }
            Ok(r) => r,
        };
        if {
            let pcr = pcli.read().await;
            if let Some(mcx) = &pcr.mc {
                !mcx.eq(&mc)
            } else {
                if pcr.mc == None {
                    info!("Got master config");
                } else {
                    info!("Change of master config");
                }
                true
            }
        } {
            let mut pc = pcli.write().await;
            pc.mc = Some(mc.clone());
            if let Some(w) = &pc.work {
                if let Err(_) = pc.notify.send(PoolUpdate {
                    conf: mc,
                    work: w.clone(),
                }) {
                    info!("Failed to send conf update to channel");
                }
            }
        }
        util::sleep_ms(120_000).await;
    }
}

async fn work_loop(pcli: PoolClient) {
    let mut try_height: i32 = -1;
    let mut master_url: Option<String> = None;
    loop {
        if try_height < 0 {
            master_url = None;
        }
        let work_url = if let Some(url) = &master_url {
            format!("{}/work_{}.bin", url.as_str(), try_height)
        } else {
            let mc = pcli.write().await.mc.clone();
            if let Some(mc) = mc {
                try_height = mc.current_height - 6; // TODO magic number, parameterize
                master_url = Some(mc.master_url.clone());
            } else {
                debug!("No master conf yet");
                util::sleep_ms(1000).await;
            }
            continue;
        };

        let mut work_bytes = match util::get_url_bin(&work_url).await {
            Err(e) => {
                info!("Error getting {:?} because {:?}", work_url, e);
                util::sleep_ms(1000).await;
                continue;
            }
            Ok(x) => x,
        };
        let mut work = Work::default();
        if let Err(e) = work_decode(&mut work, &mut work_bytes) {
            warn!("Failed to decode work {:?} because {:?}", work_url, e);
            util::sleep_ms(5000).await;
            continue;
        }
        //debug!("Got new work {:?}", work.height);
        {
            let mut pc = pcli.write().await;
            let mc = if let Some(mc) = &pc.mc {
                mc.clone()
            } else {
                error!("MasterConf missing");
                try_height = -1;
                continue;
            };
            pc.work = Some(work.clone());
            if let Err(_) = pc.notify.send(PoolUpdate {
                conf: mc,
                work,
            }) {
                error!("Failed to send work to channel {}", work_url);
            }
        }
        try_height += 1;
    }
}

pub async fn start(pcli: &PoolClient) {
    async_spawn!(pcli, {
        cfg_loop(pcli).await;
    });
    async_spawn!(pcli, {
        work_loop(pcli).await;
    });
}
