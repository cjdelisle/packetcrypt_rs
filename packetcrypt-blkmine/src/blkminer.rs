// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Result};
use packetcrypt_sys::{BlockMine_Res_t, BlockMine_t};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::pin::Pin;
use std::sync::RwLock;

#[derive(Default)]
pub struct BlkResult {
    pub high_nonce: u32,
    pub low_nonce: u32,
    pub ann_llocs: [u32; 4],
    pub ann_mlocs: [u32; 4],
}

struct CallbackCtx {
    handler: RwLock<Option<Box<dyn OnShare>>>,
}

pub trait OnShare: 'static + Sync + Send {
    fn on_share(&self, res: BlkResult);
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
    if let Some(handler) = &*(*ctx).handler.read().unwrap() {
        handler.on_share(res);
    }
}

pub struct BlkMiner {
    cbc: Pin<Box<CallbackCtx>>,
    miner: *mut BlockMine_t,
    pub max_anns: u32,
}
unsafe impl Send for BlkMiner {}
unsafe impl Sync for BlkMiner {}
impl Drop for BlkMiner {
    fn drop(&mut self) {
        unsafe {
            packetcrypt_sys::BlockMine_destroy(self.miner);
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
        let mut cbc = Box::pin(CallbackCtx {
            handler: RwLock::new(None),
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
            cbc,
            miner,
            max_anns,
        })
    }
    pub fn set_handler(&self, handler: impl OnShare) {
        self.cbc.handler.write().unwrap().replace(Box::new(handler));
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
    pub fn mine(&self, block_header: &[u8], ann_indexes: &[u32], target: u32, job_num: u32) {
        unsafe {
            packetcrypt_sys::BlockMine_mine(
                self.miner,
                block_header.as_ptr(),
                ann_indexes.len() as u32,
                ann_indexes.as_ptr(),
                target,
                job_num,
            )
        }
    }
    pub fn fake_mine(&self, block_header: &[u8], ann_indexes: &[u32]) -> BlkResult {
        let mut res = BlockMine_Res_t {
            ann_llocs: [0_u32; 4],
            ann_mlocs: [0_u32; 4],
            high_nonce: 0,
            low_nonce: 0,
            job_num: 0,
        };
        unsafe {
            packetcrypt_sys::BlockMine_fakeMine(
                self.miner,
                &mut res as *mut BlockMine_Res_t,
                block_header.as_ptr(),
                ann_indexes.len() as u32,
                ann_indexes.as_ptr(),
            );
        };
        BlkResult {
            ann_llocs: res.ann_llocs,
            ann_mlocs: res.ann_mlocs,
            high_nonce: res.high_nonce,
            low_nonce: res.low_nonce,
        }
    }
    pub fn stop(&self) {
        unsafe { packetcrypt_sys::BlockMine_stop(self.miner) }
    }
}
