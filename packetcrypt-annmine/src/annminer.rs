// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::Result;
use bytes::Buf;
use log::warn;
use packetcrypt_sys::PacketCryptAnn;
use packetcrypt_util::{hash, util};
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::sync::atomic::AtomicPtr;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::mpsc::UnboundedReceiver;

pub struct AnnResult {
    pub ann: PacketCryptAnn,
    pub dedup_hash: u64,
}

pub struct CallbackCtx {
    send_ann: tokio::sync::mpsc::UnboundedSender<AnnResult>,
}

pub struct AnnMinerS {
    _cbc: Box<CallbackCtx>,
    miner: Mutex<AtomicPtr<packetcrypt_sys::AnnMiner_t>>,
}
impl Drop for AnnMinerS {
    fn drop(&mut self) {
        unsafe { packetcrypt_sys::AnnMiner_free(*self.miner.lock().unwrap().get_mut()) }
    }
}
pub type AnnMiner = Arc<AnnMinerS>;

pub unsafe extern "C" fn on_ann_found(vctx: *mut c_void, ann: *mut u8) {
    let ann = PacketCryptAnn {
        bytes: util::aligned_bytes(std::slice::from_raw_parts(ann, 1024), 4),
    };
    let dedup_hash = (&hash::compress32(&ann.bytes[..])[..]).get_u64_le();
    let ctx = vctx as *const CallbackCtx;
    if let Err(e) = (*ctx).send_ann.send(AnnResult { ann, dedup_hash }) {
        warn!("Unable to send announcement to channel because [{}]", e);
    }
}

pub fn new(miner_id: u32, workers: usize) -> (AnnMiner, UnboundedReceiver<AnnResult>) {
    let (send_ann, recv_ann) = tokio::sync::mpsc::unbounded_channel();
    let mut cbc = Box::new(CallbackCtx { send_ann });
    let ptr = (&mut *cbc as *mut CallbackCtx) as *mut c_void;
    let miner = unsafe {
        packetcrypt_sys::AnnMiner_create(miner_id, workers as c_int, ptr, Some(on_ann_found))
    };
    (
        Arc::new(AnnMinerS {
            _cbc: cbc,
            miner: Mutex::new(AtomicPtr::new(miner)),
        }),
        recv_ann,
    )
}

const ANN_VERSION: c_int = 1;

pub fn start(
    miner: &AnnMiner,
    parent_block_hash: [u8; 32],
    parent_block_height: i32,
    target: u32,
    signing_key: Option<[u8; 32]>,
) -> Result<()> {
    let mut req = packetcrypt_sys::AnnMiner_Request_t {
        contentLen: 0,
        contentType: 0,
        parentBlockHash: parent_block_hash,
        parentBlockHeight: parent_block_height as u32,
        signingKey: if let Some(x) = signing_key {
            x
        } else {
            [0; 32]
        },
        workTarget: target,
    };
    let ptr = &mut req as *mut packetcrypt_sys::AnnMiner_Request_t;
    unsafe {
        packetcrypt_sys::AnnMiner_start(*miner.miner.lock().unwrap().get_mut(), ptr, ANN_VERSION)
    };
    Ok(())
}

impl AnnMinerS {
    pub fn new(miner_id: u32, workers: usize) -> (AnnMiner, UnboundedReceiver<AnnResult>) {
        new(miner_id, workers)
    }

    pub fn start(
        self: &AnnMiner,
        parent_block_hash: [u8; 32],
        parent_block_height: i32,
        target: u32,
        signing_key: Option<[u8; 32]>,
    ) -> Result<()> {
        start(
            self,
            parent_block_hash,
            parent_block_height,
            target,
            signing_key,
        )
    }

    pub fn hashes_per_second(self: &AnnMiner) -> f64 {
        unsafe { packetcrypt_sys::AnnMiner_hashesPerSecond(*self.miner.lock().unwrap().get_mut()) }
    }
}
