use crate::types::Hash;
use crate::blkminer::BlkMiner;
use std::cell::UnsafeCell;
use std::sync::Arc;

pub struct DataBuf {
    hashes: UnsafeCell<Vec<Hash>>,
    bm: Arc<BlkMiner>,
    pub max_anns: usize,
}

impl DataBuf {
    pub fn new(bm: Arc<BlkMiner>) -> Self {
        let max_anns = bm.max_anns as usize;
        Self {
            bm,
            hashes: UnsafeCell::new(unsafe {
                let mut v = Vec::with_capacity(max_anns);
                v.set_len(max_anns);
                v
            }),
            max_anns,
        }
    }
    pub fn get_hash(&self, index: usize) -> Hash {
        unsafe { (*self.hashes.get())[index] }
    }
    pub fn put_ann(&self, index: usize, ann: &[u8], hash: &Hash) {
        self.bm.put_ann(index as u32, ann);
        unsafe { (*self.hashes.get())[index] = *hash }
    }
}