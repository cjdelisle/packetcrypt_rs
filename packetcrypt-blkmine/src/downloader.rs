// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Result};
use log::{debug, info};
use packetcrypt_util::protocol::AnnIndex;
use packetcrypt_util::util;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

struct DownloaderM {
    downloading: usize,
    downloaded: usize,
    to_download: VecDeque<String>,
    stop: bool,
}

pub trait OnAnns: Send + Sync {
    fn on_anns(&self, anns: bytes::Bytes, url: &str);
}

pub struct DownloaderS<T: OnAnns> {
    onanns: Arc<T>,
    downloader_count: usize,
    url_base: String,
    m: Mutex<DownloaderM>,
}
pub type Downloader<T> = Arc<DownloaderS<T>>;

struct AhPollWorker<T: OnAnns> {
    url_base: String,
    worker_num: usize,
    ahp: Downloader<T>,
    wakeup: broadcast::Receiver<()>,
}

async fn poll_ann_handler_worker<T: OnAnns>(mut apw: AhPollWorker<T>) {
    let worker_id = format!("Ann dl worker [{} {}]", apw.url_base, apw.worker_num);
    loop {
        let to_dl = if let Some(to_dl) = {
            let mut ahp_l = apw.ahp.m.lock().await;
            if ahp_l.stop {
                info!("{} got stop request", worker_id);
                return;
            }
            ahp_l.to_download.pop_back()
        } {
            to_dl
        } else {
            if let Err(e) = apw.wakeup.recv().await {
                info!("{} error receiving wakeup {}", worker_id, e);
                util::sleep_ms(5_000).await;
            }
            continue;
        };
        let url = format!("{}/anns/{}", apw.url_base, to_dl);
        let bin = match util::get_url_bin(&url).await {
            Ok(x) => x,
            Err(e) => {
                // We will not try to re-download the file because it might be gone
                info!("{} error downloading file {}", worker_id, e);
                continue;
            }
        };
        apw.ahp.onanns.on_anns(bin, &url);
    }
}

async fn poll_ann_handlers<T: OnAnns + 'static>(downloader: &Downloader<T>) {
    let (wakeup_tx, _) = broadcast::channel(32);
    for worker_num in 0..downloader.downloader_count {
        let apw = AhPollWorker {
            url_base: downloader.url_base.clone(),
            worker_num,
            ahp: Arc::clone(downloader),
            wakeup: wakeup_tx.subscribe(),
        };
        tokio::spawn(async move { poll_ann_handler_worker(apw).await });
    }
    let index_url = format!("{}/anns/index.json", downloader.url_base);
    let mut top_file = "".to_owned();
    loop {
        if downloader.m.lock().await.stop {
            info!(
                "Ann index loader [{}] got stop request",
                downloader.url_base
            );
            return;
        }
        debug!("Getting index {}", index_url);
        let text = match util::get_url_text(&index_url).await {
            Ok(res) => res,
            Err(e) => {
                info!("Unable to reach ann index [{}] because [{}]", index_url, e);
                util::sleep_ms(10_000).await;
                continue;
            }
        };
        let mut ai = match serde_json::from_str::<AnnIndex>(text.as_str()) {
            Err(e) => {
                info!("Failed to deserialize ann index {:?} {:?}", text, e);
                util::sleep_ms(10_000).await;
                continue;
            }
            Ok(r) => r,
        };
        {
            let mut ahp_l = downloader.m.lock().await;
            let ltf = top_file.clone();
            let mut new_files = 0;
            for (f, i) in ai.files.drain(..).rev().zip(0..) {
                if i == 0 {
                    top_file = f.clone();
                }
                if ltf == f {
                    break;
                }
                ahp_l.to_download.push_back(f);
                new_files += 1;
            }
            if new_files > 0 {
                debug!("Got {} new files from {}", new_files, downloader.url_base);
                if let Err(e) = wakeup_tx.send(()) {
                    info!("Failed to send to wakeup channel {:?}", e);
                    continue;
                }
            }
        }
        util::sleep_ms(30_000).await;
    }
}

pub async fn new<T: OnAnns + 'static>(
    downloader_count: usize,
    url_base: String,
    onanns: &Arc<T>,
) -> Downloader<T>
where
    T: OnAnns,
{
    Arc::new(DownloaderS {
        downloader_count,
        url_base,
        onanns: Arc::clone(onanns),
        m: Mutex::new(DownloaderM {
            downloading: 0,
            downloaded: 0,
            to_download: VecDeque::new(),
            stop: false,
        }),
    })
}

pub async fn start<T: OnAnns + 'static>(downloader: &Downloader<T>) -> Result<()> {
    if downloader.m.lock().await.stop {
        bail!(
            "Downloader [{}] has already been stopped",
            downloader.url_base
        );
    }
    let dl = Arc::clone(downloader);
    tokio::spawn(async move {
        poll_ann_handlers(&dl).await;
    });
    Ok(())
}

pub async fn stop<T: OnAnns>(downloader: &Downloader<T>) {
    downloader.m.lock().await.stop = true;
}
