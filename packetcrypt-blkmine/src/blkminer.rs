// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Result};
use log::warn;
use packetcrypt_sys::{BlockMine_Res_t, BlockMine_t};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::RwLock;

#[derive(Default)]
pub struct BlkResult {
    pub high_nonce: u32,
    pub low_nonce: u32,
    pub ann_llocs: [u32; 4],
    pub ann_mlocs: [u32; 4],
}

// This should be small so we don't have tons of (stale) shares piling up
const SHARE_CHAN_SZ: usize = 16;

struct CallbackCtx {
    sender: Mutex<tokio::sync::mpsc::Sender<BlkResult>>,
}

#[allow(clippy::field_reassign_with_default)]
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
    miner: RwLock<*mut BlockMine_t>,
    pub receiver: Mutex<Option<tokio::sync::mpsc::Receiver<BlkResult>>>,
    pub max_anns: u32,
}
unsafe impl Send for BlkMiner {}
unsafe impl Sync for BlkMiner {}
impl Drop for BlkMiner {
    fn drop(&mut self) {
        let m_l = self.miner.write().unwrap();
        unsafe {
            packetcrypt_sys::BlockMine_destroy(*m_l);
        }
    }
}

unsafe fn mk_str(ptr: *const c_char) -> &'static str {
    if ptr.is_null() {
        "<null>"
    } else {
        CStr::from_ptr(ptr).to_str().unwrap()
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
            let res = packetcrypt_sys::BlockMine_create(
                maxmem,
                threads as c_int,
                Some(on_share_found),
                ptr,
            );
            match res.miner.as_mut() {
                Some(miner) => (miner.maxAnns, miner),
                None => bail!(
                    "Failed to create block miner: During [{}] got [{}]",
                    mk_str(res.stage),
                    mk_str(res.err),
                ),
            }
        };
        Ok(BlkMiner {
            _cbc: cbc,
            miner: RwLock::new(miner),
            receiver: Mutex::new(Some(receiver)),
            max_anns,
        })
    }
    pub fn get_ann(&self, index: u32, ann_out: &mut [u8]) {
        let m_l = self.miner.read().unwrap();
        unsafe {
            packetcrypt_sys::BlockMine_getAnn(*m_l, index, ann_out.as_mut_ptr());
        }
    }
    pub fn put_ann(&self, index: u32, ann: &[u8]) {
        let m_l = self.miner.read().unwrap();
        unsafe {
            packetcrypt_sys::BlockMine_updateAnn(*m_l, index, ann.as_ptr());
        }
    }
    pub fn hashes_per_second(&self) -> i64 {
        let m_l = self.miner.read().unwrap();
        unsafe { packetcrypt_sys::BlockMine_getHashesPerSecond(*m_l) }
    }
    pub fn mine(&self, block_header: &[u8], ann_indexes: &[u32], target: u32) {
        let m_l = self.miner.write().unwrap();
        unsafe {
            packetcrypt_sys::BlockMine_mine(
                *m_l,
                block_header.as_ptr(),
                ann_indexes.len() as u32,
                ann_indexes.as_ptr(),
                target,
            )
        }
    }
    pub fn stop(&self) {
        let m_l = self.miner.write().unwrap();
        unsafe { packetcrypt_sys::BlockMine_stop(*m_l) }
    }
}
