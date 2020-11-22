// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Result};
use log::warn;
use packetcrypt_sys::{BlockMine_Res_t, BlockMine_t};
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::pin::Pin;
use std::sync::Mutex;

#[derive(Default)]
pub struct BlkResult {
    pub high_nonce: u32,
    pub low_nonce: u32,
    pub ann_llocs: [u32; 4],
    pub ann_mlocs: [u32; 4],
}

// This should be small so we don't have tons of (stale) shares piling up
const SHARE_CHAN_SZ: usize = 4;

struct CallbackCtx {
    sender: Mutex<tokio::sync::mpsc::Sender<BlkResult>>,
}

pub unsafe extern "C" fn on_share_found(resp: *mut BlockMine_Res_t, vctx: *mut c_void) {
    let mut res = BlkResult::default();
    res.high_nonce = (*resp).high_nonce;
    res.low_nonce = (*resp).low_nonce;
    for i in 0..4 {
        res.ann_llocs[i] = (*resp).ann_llocs[i];
        res.ann_mlocs[i] = (*resp).ann_mlocs[i];
    }
    let ctx = vctx as *const CallbackCtx;
    if let Err(e) = (*ctx).sender.lock().unwrap().try_send(res) {
        warn!("Unable to send block share to channel because [{}]", e);
    }
}

pub struct BlkMiner {
    _cbc: Pin<Box<CallbackCtx>>,
    miner: *mut BlockMine_t,
    lock: std::sync::Mutex<()>,
    pub receiver: Mutex<Option<tokio::sync::mpsc::Receiver<BlkResult>>>,
    pub max_anns: u32,
}
unsafe impl Send for BlkMiner {}
unsafe impl Sync for BlkMiner {}
impl Drop for BlkMiner {
    fn drop(&mut self) {
        let m = self.miner;
        let _ = self.lock.lock().unwrap();
        unsafe {
            packetcrypt_sys::BlockMine_destroy(m);
        }
    }
}

impl BlkMiner {
    pub fn new(maxmem: u64, threads: u32) -> Result<BlkMiner> {
        let (sender, receiver) = tokio::sync::mpsc::channel(SHARE_CHAN_SZ);
        let mut cbc = Box::pin(CallbackCtx {
            sender: Mutex::new(sender),
        });
        let ptr = (&mut *cbc as *mut CallbackCtx) as *mut c_void;
        let (max_anns, miner) = unsafe {
            let miner = packetcrypt_sys::BlockMine_create(
                maxmem,
                threads as c_int,
                Some(on_share_found),
                ptr,
            );
            if miner.is_null() {
                bail!("Unable to create block miner, probably could not map memory");
            }
            ((*miner).maxAnns, miner)
        };
        Ok(BlkMiner {
            _cbc: cbc,
            miner,
            receiver: Mutex::new(Some(receiver)),
            max_anns,
            lock: Mutex::new(()),
        })
    }
    pub fn get_ann(&self, index: u32, ann_out: &mut [u8]) {
        unsafe {
            packetcrypt_sys::BlockMine_getAnn(self.miner, index, ann_out.as_mut_ptr());
        }
    }
    pub fn put_ann(&self, index: u32, ann: &[u8]) {
        unsafe {
            packetcrypt_sys::BlockMine_updateAnn(self.miner, index, ann.as_ptr());
        }
    }
    pub fn hashes_per_second(&self) -> i64 {
        unsafe { packetcrypt_sys::BlockMine_getHashesPerSecond(self.miner) }
    }
    pub fn mine(&self, block_header: &[u8], ann_indexes: &[u32], target: u32) {
        let _ = self.lock.lock().unwrap();
        unsafe {
            packetcrypt_sys::BlockMine_mine(
                self.miner,
                block_header.as_ptr(),
                ann_indexes.len() as u32,
                ann_indexes.as_ptr(),
                target,
            )
        }
    }
    pub fn stop(&self) {
        let _ = self.lock.lock().unwrap();
        unsafe { packetcrypt_sys::BlockMine_stop(self.miner) }
    }
}
