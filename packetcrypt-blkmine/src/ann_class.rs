use crate::ann_buf::{AnnBuf, Hash};
use crate::blkmine::HeightWork;
use crate::prooftree;
use packetcrypt_sys::difficulty::pc_degrade_announcement_target;
use rayon::prelude::*;
use std::mem;
use std::sync::{Arc, Mutex, RwLock};

pub const ANNBUF_SZ: usize = 32 * 1024;
pub type AnnBufSz = AnnBuf<ANNBUF_SZ>;

struct HashTree {
    origin: Arc<Mutex<prooftree::ProofTree>>,
    root_hash: Option<Hash>,
}

impl HashTree {
    fn invalidate(&mut self) {
        if self.root_hash.is_none() {
            return;
        }

        let mut pf = self.origin.lock().unwrap();
        if pf.root_hash.as_ref() == self.root_hash.as_deref() {
            pf.reset();
        }
        self.root_hash = None
    }
}

struct AnnClassMut {
    /// The buffers with the hashes.
    bufs: Vec<Box<AnnBufSz>>,
    topbuf: Box<AnnBufSz>,

    /// Hash trees which contain announcements in this class.
    /// A hash tree will only care to include either all anns in a class or none
    /// so this is not needed per-AnnBuf.
    dependent_trees: Vec<HashTree>,

    /// Are we currently mining?
    mining: bool,
}

/// AnnClass is a "classification" or grouping of announcements which are similar in their
/// properties (same work done on the ann, same block height when mined).
pub struct AnnClass {
    m: RwLock<AnnClassMut>,

    /// The hash of the current block.
    block_hash: Hash,

    // The type of anns in this class.
    block_height: u32,
    min_ann_work: u32,
}

impl AnnClass {
    pub fn with_topbuf(topbuf: Box<AnnBufSz>, hw: &HeightWork) -> Self {
        Self::new(topbuf, vec![], hw)
    }

    pub fn with_bufs(bufs: impl Iterator<Item = Box<AnnBufSz>>, hw: &HeightWork) -> Self {
        // we want topbuf to be the last slice, since it will be the last one to be stolen.
        let mut bufs = bufs.collect::<Vec<_>>();
        let topbuf = bufs.pop().unwrap();
        Self::new(topbuf, bufs, hw)
    }

    fn new(topbuf: Box<AnnBufSz>, bufs: Vec<Box<AnnBufSz>>, hw: &HeightWork) -> Self {
        AnnClass {
            m: RwLock::new(AnnClassMut {
                bufs,
                topbuf,
                dependent_trees: vec![],
                mining: false,
            }),
            block_hash: Default::default(),
            block_height: hw.block_height as u32,
            min_ann_work: hw.work,
        }
    }

    pub fn push_anns(&self, anns: &[&[u8]], indexes: &[u32]) -> usize {
        self.m.read().unwrap().topbuf.push_anns(anns, indexes)
    }

    pub fn add_buf(&self, newbuf: Box<AnnBufSz>) {
        // don't be holding the write mutex while we lock topbuf.
        let mut oldtop = {
            let mut m = self.m.write().unwrap();
            mem::replace(&mut m.topbuf, newbuf)
        };
        // lock the previous top buffer, this will take some time.
        oldtop.lock();
        self.m.write().unwrap().bufs.push(oldtop);
    }

    pub fn steal_buf(&self) -> Result<Option<Box<AnnBufSz>>, ()> {
        let mut m = self.m.write().unwrap();
        if m.mining {
            return Err(());
        }
        if m.bufs.is_empty() {
            return Ok(None);
        }

        m.dependent_trees.iter_mut().for_each(|t| t.invalidate());
        m.dependent_trees.clear();
        Ok(m.bufs.pop())
    }

    pub fn destroy(self) -> Box<AnnBufSz> {
        {
            let m = self.m.write().unwrap();
            assert!(m.bufs.is_empty() && !m.mining);
        }
        self.m.into_inner().unwrap().topbuf
    }

    pub fn ready_anns(&self) -> usize {
        let m = self.m.read().unwrap();
        m.bufs.iter().map(|b| b.next_ann_index()).sum()
    }

    pub fn read_ready_anns(&self, mut out: &mut [prooftree::AnnData]) {
        let m = self.m.read().unwrap();
        // split the out buffer into sub-buffers each of which has enough space to hold
        // enough AnnData for each entry in one buf.
        let mut v = Vec::with_capacity(m.bufs.len());
        for b in &m.bufs {
            let this = b.next_ann_index();
            let (data, excess) = out.split_at_mut(this);
            v.push((b, data));
            out = excess;
        }
        // now that they're split, copy the hashes over in parallel.
        v.into_par_iter().for_each(|(buf, out)| {
            buf.read_ready_anns(out);
        });
    }

    /// Get the effective "value" of these anns, result is a compact int
    /// lower numbers = higher value. Announcements degrade in value with age.
    pub fn ann_effective_work(&self, next_block_height: u32) -> u32 {
        if self.block_height + 3 < next_block_height {
            return self.min_ann_work;
        }
        pc_degrade_announcement_target(self.min_ann_work, next_block_height - self.block_height)
    }
}
