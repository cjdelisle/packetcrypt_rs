use crate::blkminer::BlkMiner;
use crate::prooftree::{self,AnnData};
use rayon::prelude::*;
use sodiumoxide::crypto::generichash;
use std::cell::UnsafeCell;
use std::convert::TryInto;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Default, Copy, Clone)]
pub struct Hash([u8; 32]);

impl Hash {
    fn compute(&mut self, ann: &[u8]) {
        let digest = generichash::hash(ann, Some(32), None).unwrap();
        self.0.copy_from_slice(digest.as_ref())
    }

    fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[..8].try_into().unwrap())
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash {
    fn from(hash: [u8; 32]) -> Self {
        Self(hash)
    }
}

impl Deref for Hash {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The purpose of AnnBuf is to be able to store and account for announcements in memory
/// and efficiently generate sorted lists on demand.
/// Every AnnBuf has a base address (in the big memory storage area).
pub struct AnnBuf<const ANNBUF_SZ: usize> {
    bm: Arc<BlkMiner>,
    base_offset: usize,

    /// The index of the next push.
    /// Allows atomic adds to allocate space for additional anns.
    next_ann_index: AtomicUsize,
    /// The calculated hashes.
    /// Gives interior mutability, so this struct can be shared among threads.
    data: UnsafeCell<[AnnData; ANNBUF_SZ]>,

    locked: bool,
}

unsafe impl<const ANNBUF_SZ: usize> Send for AnnBuf<ANNBUF_SZ> {}
unsafe impl<const ANNBUF_SZ: usize> Sync for AnnBuf<ANNBUF_SZ> {}

impl<const ANNBUF_SZ: usize> AnnBuf<ANNBUF_SZ> {
    pub fn new(bm: Arc<BlkMiner>, base_offset: usize) -> Self {
        Self {
            bm,
            base_offset,
            next_ann_index: AtomicUsize::new(0),
            data: [AnnData::default(); ANNBUF_SZ].into(),
            locked: false.into(),
        }
    }

    /// Push a slice of announcements into this buffer.
    /// Returns the number of actually inserted anns.
    pub fn push_anns(&self, anns: &[&[u8]], mut indexes: &[u32]) -> usize {
        assert!(!self.locked);

        // atomically advance the next_ann_index to "claim" the space.
        let ann_index = self
            .next_ann_index
            .fetch_add(indexes.len(), Ordering::Relaxed);
        if ann_index >= ANNBUF_SZ {
            self.next_ann_index.store(ANNBUF_SZ, Ordering::Relaxed);
            return 0;
        }

        // verify if a partial push is necessary.
        if ann_index + indexes.len() > ANNBUF_SZ {
            indexes = &indexes[..ANNBUF_SZ - ann_index];
            self.next_ann_index.store(ANNBUF_SZ, Ordering::Relaxed);
        }

        let data = self.data.get();
        let mut temp = Hash::default();
        for (i, ann) in (ann_index..).zip(indexes.iter().map(|&ci| anns[ci as usize])) {
            temp.compute(ann);
            let ad = AnnData{
                hash_pfx: temp.to_u64(),
                index: 0,
                mloc: (self.base_offset + i) as u32,
            };
            // SAFETY: the starting index comes from an atomic, and we won't write out of indexes.len() range.
            unsafe { (*data)[i] = ad };

            // actually store ann in miner, with the index offset.
            self.bm.put_ann((self.base_offset + i) as u32, ann, &temp);
        }

        indexes.len()
    }

    /// Locks this AnnBuf once it is full, which sorts the index table by ann hash.
    /// Working with pre-sorted anns is better because they need to be sorted later, and
    /// sorting a bunch of concatenated sorted lists is fast.
    pub fn lock(&mut self) {
        assert!(!self.locked);

        let last = self.next_ann_index();
        // println!(
        //     "*** AnnBuf::lock: base_offset={} size={}",
        //     self.base_offset, last
        // );
        let data = unsafe { &mut *self.data.get() };
        data[..last].par_sort_unstable_by_key(|&i| i.hash_pfx);
        self.locked = true;
    }

    /// Clear the buf for another usage.
    pub fn reset(&mut self) {
        // println!("*** AnnBuf::reset: anns={}", self.next_ann_index());
        self.next_ann_index.store(0, Ordering::Relaxed);
        self.locked = false;
    }

    /// Read out the data from the buf into an array of prooftree::AnnData, which will be used
    /// for building the final proof tree.
    pub fn read_ready_anns(&self, out: &mut [prooftree::AnnData]) {
        assert!(self.locked);
        let last = self.next_ann_index();
        let data = unsafe { &*self.data.get() };
        out.iter_mut().zip(data[..last].iter()).for_each(|(out, inp)| {
            *out = *inp
        });
    }

    pub fn next_ann_index(&self) -> usize {
        self.next_ann_index.load(Ordering::Relaxed)
    }
}
