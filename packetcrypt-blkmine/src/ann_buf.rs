use crate::{blkminer::BlkMiner, prooftree};
use rayon::prelude::*;
use sodiumoxide::crypto::generichash;
use std::cell::UnsafeCell;
use std::convert::TryInto;
use std::ops::Index;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Default, Copy, Clone)]
struct Hash([u8; 32]);

impl Hash {
    fn compute(&mut self, ann: &[u8]) {
        let digest = generichash::hash(ann, Some(32), None).unwrap();
        self.0.copy_from_slice(digest.as_ref())
    }

    fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[24..].try_into().unwrap())
    }
}

/// The purpose of AnnBuf is to be able to store and account for announcements in memory
/// and efficiently generate sorted lists on demand.
/// Every AnnBuf has a base address (in the big memory storage area).
struct AnnBuf<const ANNBUF_SZ: usize> {
    bm: Arc<BlkMiner>,
    base_offset: usize,

    /// allows atomic add to allocate space for additional anns.
    next_ann_index: AtomicUsize,
    /// gives interior mutability, so this struct can be shared among threads.
    hashes: UnsafeCell<[Hash; ANNBUF_SZ]>,

    locked: bool,
    index_table: [u16; ANNBUF_SZ],
}

unsafe impl<const ANNBUF_SZ: usize> Send for AnnBuf<ANNBUF_SZ> {}
unsafe impl<const ANNBUF_SZ: usize> Sync for AnnBuf<ANNBUF_SZ> {}

impl<const ANNBUF_SZ: usize> AnnBuf<ANNBUF_SZ> {
    pub fn new(bm: Arc<BlkMiner>, base_offset: usize) -> Self {
        Self {
            bm,
            base_offset,
            next_ann_index: AtomicUsize::new(0),
            hashes: [Hash::default(); ANNBUF_SZ].into(),
            locked: false.into(),
            index_table: [0; ANNBUF_SZ],
        }
    }

    /// Push a slice of announcements into this buffer.
    /// Returns the number of actually inserted anns.
    pub fn push_anns(&self, mut anns: &[&[u8]]) -> usize {
        // atomically advance the next_ann_index to "claim" the space.
        let ann_index = self.next_ann_index.fetch_add(anns.len(), Ordering::Relaxed);
        if ann_index >= ANNBUF_SZ {
            self.next_ann_index.store(ANNBUF_SZ, Ordering::Relaxed);
            return 0;
        }

        // verify if a partial push is necessary.
        if ann_index + anns.len() > ANNBUF_SZ {
            anns = &anns[..ANNBUF_SZ - ann_index];
            self.next_ann_index.store(ANNBUF_SZ, Ordering::Relaxed);
        }

        let hashes = self.hashes.get();
        let mut temp = Hash::default();
        for (i, &ann) in (ann_index..).zip(anns.iter()) {
            temp.compute(ann);
            unsafe {
                // SAFETY: the starting index comes from an atomic, and we won't write out of anns.len() range.
                (*hashes)[i] = temp;
            }

            // actually store ann in miner, with the index offset.
            self.bm.put_ann((self.base_offset + i) as u32, ann);
        }

        anns.len()
    }

    /// Locks this AnnBuf once it is full, which sorts the index table by ann hash.
    /// Working with pre-sorted anns is better because they need to be sorted later, and
    /// sorting a bunch of concatenated sorted lists is fast.
    pub fn lock(&mut self) {
        assert!(!self.locked);

        let last = self.next_ann_index();
        for i in 0..last {
            self.index_table[i] = i as u16;
        }
        for i in last..ANNBUF_SZ {
            self.index_table[i] = u16::MAX;
        }

        let hashes = unsafe { &*self.hashes.get() };
        self.index_table[..last].par_sort_unstable_by_key(|&i| hashes[i as usize].to_u64());
        self.locked = true
    }

    /// Clear the buf for another usage.
    pub fn reset(&mut self) {
        self.next_ann_index.store(0, Ordering::Relaxed);
        self.locked = false;
    }

    /// Read out the data from the buf into an array of prooftree::AnnData, which will be used
    /// for building the final proof tree.
    pub fn read_ann_data(&self, out: &mut [prooftree::AnnData]) {
        assert!(self.locked);
        let last = self.next_ann_index();
        let hashes = unsafe { &*self.hashes.get() };
        for (i, &idx) in self.index_table[0..last].iter().enumerate() {
            out[i].hash = hashes[idx as usize].0;
            out[i].mloc = (self.base_offset + idx as usize) as u32;
            out[i].index = 0; // used internally for other purposes
        }
    }

    pub fn next_ann_index(&self) -> usize {
        self.next_ann_index.load(Ordering::Relaxed)
    }
}
