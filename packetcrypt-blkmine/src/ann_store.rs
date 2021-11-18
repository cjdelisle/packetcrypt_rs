#![allow(dead_code)]
use crate::ann_buf::Hash;
use crate::ann_class::{AnnBufSz, AnnClass, ANNBUF_SZ};
use crate::blkmine::{AnnChunk, HeightWork};
use crate::blkminer::BlkMiner;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

struct AnnStoreMut {
    classes: BTreeMap<HeightWork, Box<AnnClass>>,
    recent_blocks: HashMap<i32, Hash>,
}

struct AnnStore {
    m: RwLock<AnnStoreMut>,
    bm: Arc<BlkMiner>,
}

impl AnnStore {
    pub fn new(bm: Arc<BlkMiner>) -> Self {
        // initial buf store, capable of filling the received miner entirely.
        let buf_store = (0..bm.max_anns)
            .step_by(ANNBUF_SZ)
            .map(|i| Box::new(AnnBufSz::new(Arc::clone(&bm), i as usize)));

        let hw_store = HeightWork {
            block_height: 0,
            work: 0xffffffff,
        };
        // bufs will always be stolen from this class until it is used up.
        let class_store = Box::new(AnnClass::with_bufs(buf_store, &hw_store));

        let mut classes = BTreeMap::new();
        classes.insert(hw_store, class_store);
        Self {
            m: RwLock::new(AnnStoreMut {
                classes,
                recent_blocks: HashMap::new(),
            }),
            bm,
        }
    }

    pub fn block(&self, height: i32, hash: Hash) {
        let mut m = self.m.write().unwrap();
        m.recent_blocks.insert(height, hash);
    }

    pub fn push_anns(&self, hw: HeightWork, ac: AnnChunk) {
        let mut m = self.m.write().unwrap();

        // attempt to push the whole chunk, stealing bufs as necessary.
        let (mut indexes, mut next_block_height) = (ac.indexes, None);
        loop {
            // lookup the class matching this HeightWork, if any.
            if let Some(class) = m.classes.get(&hw) {
                let n = class.push_anns(ac.anns, indexes);
                if n == indexes.len() {
                    return;
                }
                indexes = &indexes[n..];
            }

            if let None = next_block_height {
                next_block_height = Some(1 + *m.recent_blocks.keys().max().unwrap() as u32);
            }

            // it didn't fit or there wasn't any suitable class.
            let buf = steal_non_mining_buf(&mut m, next_block_height.unwrap());
            if let Some(class) = m.classes.get(&hw) {
                class.add_buf(buf);
            } else {
                let new_class = Box::new(AnnClass::with_topbuf(buf, &hw));
                assert!(m.classes.insert(hw, new_class).is_none());
            }
        }
    }
}

fn steal_non_mining_buf(m: &mut AnnStoreMut, next_block_height: u32) -> Box<AnnBufSz> {
    let mut mining = vec![];
    loop {
        // find the worst AnnClass to steal a buf from.
        let (&key, worst) = m
            .classes
            .iter()
            .filter(|&(hw, _c)| !mining.contains(hw))
            .max_by_key(|&(_hw, c)| c.ann_effective_work(next_block_height))
            .unwrap();

        match worst.steal_buf() {
            Err(_) => mining.push(key),
            Ok(None) => return m.classes.remove(&key).unwrap().destroy(),
            Ok(Some(buf)) => return buf,
        }
    }
}
