// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, format_err, Result};
use log::{debug, info};
use packetcrypt_util::protocol::AnnIndex;
use packetcrypt_util::util;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

// Maximum number of files to queue for download, prevents memory leak if
// the miner cannot keep up with the ann handlers.
const MAX_QUEUE_LENGTH: usize = 5_000;

#[derive(Clone)]
pub struct Stats {
    pub downloading: usize,
    pub downloaded: usize,
    pub queued: usize,
}

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
    onanns: T,
    downloader_count: usize,
    url_base: String,
    handler_pass: Option<String>,
    m: Mutex<DownloaderM>,
}
pub type Downloader<T> = Arc<DownloaderS<T>>;

struct AhPollWorker<T: OnAnns> {
    url_base: String,
    worker_num: usize,
    ahp: Downloader<T>,
    handler_pass: Option<String>,
    wakeup: broadcast::Receiver<()>,
    client: reqwest::Client,
}

async fn done_downloading<T: OnAnns>(apw: &AhPollWorker<T>, success: bool) {
    let mut ahp_l = apw.ahp.m.lock().await;
    ahp_l.downloading -= 1;
    if success {
        ahp_l.downloaded += 1;
    }
}

async fn get_url_bin(
    url: &str,
    ignore_statuses: &[u16],
    client: &reqwest::Client,
    passwd: &Option<String>,
) -> Result<Option<bytes::Bytes>> {
    loop {
        let mut req = client.get(url);
        if let Some(p) = passwd {
            req = req.header("x-pc-passwd", p);
        }
        let res = req.send().await?;
        return match res.status() {
            reqwest::StatusCode::OK => Ok(Some(res.bytes().await?)),
            reqwest::StatusCode::MULTIPLE_CHOICES => {
                continue;
            }
            st => {
                if ignore_statuses.contains(&st.as_u16()) {
                    Ok(None)
                } else {
                    Err(format_err!("Status code was {:?}", st))
                }
            }
        };
    }
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
            let x = ahp_l.to_download.pop_back();
            if x.is_some() {
                ahp_l.downloading += 1;
            }
            x
        } {
            to_dl
        } else {
            let _ = apw.wakeup.recv().await;
            continue;
        };
        let url = format!("{}/anns/{}", apw.url_base, to_dl);
        //debug!("get {} ...", url);
        let bin = match get_url_bin(&url, &[404, 405], &apw.client, &apw.handler_pass).await {
            Ok(x) => x,
            Err(e) => {
                // We will not try to re-download the file because it might be gone
                info!("error downloading {}: {}", url, e);
                done_downloading(&apw, false).await;
                continue;
            }
        };
        done_downloading(&apw, true).await;
        if let Some(bin) = bin {
            //debug!("get {} done (ok)", url);
            apw.ahp.onanns.on_anns(bin, &url);
        } else {
            debug!("get {} done (not found)", url);
        }
    }
}

async fn poll_ann_handlers<T: OnAnns + 'static>(downloader: &Downloader<T>) {
    let (wakeup_tx, _) = broadcast::channel(32);
    for worker_num in 0..downloader.downloader_count {
        let apw = AhPollWorker {
            url_base: downloader.url_base.clone(),
            handler_pass: downloader.handler_pass.clone(),
            worker_num,
            ahp: Arc::clone(downloader),
            wakeup: wakeup_tx.subscribe(),
            client: reqwest::Client::builder().build().unwrap(),
        };
        tokio::spawn(async move { poll_ann_handler_worker(apw).await });
    }
    let index_url = format!("{}/anns/index.json", downloader.url_base);
    let mut top_file: Option<String> = None;
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
            let mut new_files = 0;
            let mut seek_to = if let Some(tf) = &top_file {
                let mut seek_to = None;
                //debug!("Top file was {}", tf);
                for f in ai.files.iter().rev() {
                    if f == tf {
                        //debug!("Found seek_to {}", tf);
                        seek_to = Some(tf.clone());
                        break;
                    }
                }
                seek_to
            } else {
                None
            };
            if let Some(f) = ai.files.last() {
                top_file = Some(f.clone());
                //debug!("Top file is {}, Seeking to {:?}", f, seek_to);
            }
            for f in ai.files.drain(..) {
                if let Some(st) = &seek_to {
                    if st != &f {
                        continue;
                    }
                    seek_to = None;
                }
                ahp_l.to_download.push_back(f);
                new_files += 1;
            }
            loop {
                // Prevent the queue from growing forever
                if ahp_l.to_download.len() < MAX_QUEUE_LENGTH {
                    break;
                }
                ahp_l.to_download.pop_front();
            }
            if new_files > 0 {
                debug!(
                    "Queued {} new files from {}",
                    new_files, downloader.url_base
                );
                if let Err(e) = wakeup_tx.send(()) {
                    info!("Failed to send to wakeup channel {:?}", e);
                    continue;
                }
            }
        }
        util::sleep_ms(5_000).await;
    }
}

pub async fn new<T>(
    downloader_count: usize,
    url_base: String,
    onanns: &T,
    handler_pass: Option<String>,
) -> Downloader<T>
where
    T: OnAnns + 'static + Clone,
{
    Arc::new(DownloaderS {
        downloader_count,
        url_base,
        onanns: onanns.clone(),
        handler_pass,
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

pub async fn stats<T: OnAnns>(downloader: &Downloader<T>, reset_downloade: bool) -> Stats {
    let mut dl_l = downloader.m.lock().await;
    let downloaded = dl_l.downloaded;
    if reset_downloade {
        dl_l.downloaded = 0;
    }
    Stats {
        downloaded,
        downloading: dl_l.downloading,
        queued: dl_l.to_download.len(),
    }
}
