// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::{blkslab, downloader};
use anyhow::{bail, Result};
use log::{debug, info};
use packetcrypt_util::poolclient::{self, PoolClient};
use packetcrypt_util::{hash, util};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

pub struct BlkArgs {
    pub payment_addr: String,
    pub threads: usize,
    pub uploads: usize,
    pub downloader_count: usize,
    pub workdir: String,
    pub pool_master: String,
    pub max_mem: usize,
}

struct FreeItm {
    index: u32,
    length: u32,
}

#[derive(Default)]
struct RevIndex {
    hash: [u8; 32],
    index: u32,
}

pub struct BlkMineS {
    slab: blkslab::BlkSlab,
    free_list: Mutex<VecDeque<FreeItm>>,
    rev_index: Mutex<Vec<RevIndex>>,
    //m: std::sync::Mutex<BlkMineM>,
    pc: PoolClient,
    ba: BlkArgs,
}
pub type BlkMine = Arc<BlkMineS>;

fn get_free_items(bm: &BlkMineS, mut count: u32) -> Result<Vec<FreeItm>> {
    let mut free_l = bm.free_list.lock().unwrap();
    let mut out = Vec::new();
    loop {
        if count == 0 {
            return Ok(out);
        }
        out.push(if let Some(mut fi) = free_l.pop_front() {
            if fi.length > count {
                let remain = fi.length - count;
                fi.length -= remain;
                free_l.push_front(FreeItm {
                    index: fi.index + fi.length,
                    length: remain,
                });
            }
            count -= fi.length;
            fi
        } else {
            bail!("no free items remaining");
        });
    }
}
fn return_free_items(bm: &BlkMineS, fi: impl Iterator<Item = FreeItm>) {
    let mut free_l = bm.free_list.lock().unwrap();
    for x in fi {
        free_l.push_back(x);
    }
}

fn mk_rev_indexes(anns: &bytes::Bytes, free: Vec<FreeItm>) -> Vec<RevIndex> {
    let mut out = Vec::with_capacity(anns.len() / 1024);
    let mut ann_index = 0;
    for mut fi in free {
        loop {
            // Fails if there are more free items than there are anns
            assert!(ann_index + 1024 < anns.len());
            out.push(RevIndex {
                index: fi.index,
                hash: hash::compress32(&anns[ann_index..(ann_index + 1024)]),
            });
            ann_index += 1024;
            fi.index += 1;
            fi.length -= 1;
            if fi.length == 0 {
                break;
            }
        }
    }
    assert!(ann_index == anns.len());
    out
}

impl downloader::OnAnns for BlkMineS {
    fn on_anns(&self, anns: bytes::Bytes, url: &str) {
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
        let free = match get_free_items(self, count) {
            Ok(x) => x,
            Err(e) => {
                info!("Anns [{}] unable to store [{}]", url, e);
                return;
            }
        };
        let revs = mk_rev_indexes(&anns, free);
        let mut ann_index = 0;
        for r in revs {
            blkslab::put_ann(&self.slab, &anns[ann_index..(ann_index + 1024)], r.index);
            ann_index += 1024;
        }
        println!("GOT ANNS!");
        // Check that the anns *can* be used
        // 1. Lock the freelist and get the necessary free items, unlock
        // 2. generate the rev_index entries and enter them directly
        // 3. copy the anns into the memory map
        // 4. lock the aew and apppend entries
    }
}

pub async fn new(ba: BlkArgs) -> Result<BlkMine> {
    let pc = poolclient::new(&ba.pool_master, 32);
    let slab = blkslab::alloc(ba.max_mem)?;
    let rev_index = Mutex::new(Vec::with_capacity(slab.max_anns));
    Ok(Arc::new(BlkMineS {
        slab,
        rev_index,
        free_list: Mutex::new(VecDeque::new()),
        pc,
        ba,
    }))
}

// On download, call add_anns()
// on new height, call on_work()

async fn downloader_loop(bm: &BlkMine) {
    let mut chan = poolclient::update_chan(&bm.pc).await;
    let mut downloaders: Vec<downloader::Downloader<BlkMineS>> = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    loop {
        let upd = match chan.recv().await {
            Ok(x) => x,
            Err(e) => {
                info!("Error recv from pool client channel {}", e);
                util::sleep_ms(5_000);
                continue;
            }
        };
        if upd.conf.download_ann_urls != urls {
            if urls.len() > 0 {
                info!(
                    "Change of ann handler list {:?} -> {:?}",
                    urls, upd.conf.download_ann_urls
                )
            } else {
                info!("Got ann handler list {:?}", upd.conf.download_ann_urls)
            }
            for d in downloaders.drain(..) {
                downloader::stop(&d);
            }
            for url in &upd.conf.download_ann_urls {
                let dl = downloader::new(bm.ba.downloader_count, url.to_owned(), bm).await;
                downloader::start(&dl).await.unwrap();
                downloaders.push(dl);
            }
            urls = upd.conf.download_ann_urls;
        }
    }
}

pub async fn start(bm: &BlkMine) -> Result<()> {
    // 1. connect to annhandlers and begin downloading
    // 2. lock and mine - later: separate the two
    poolclient::start(&bm.pc).await;
    Ok(())
}
