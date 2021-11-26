use crate::ann_buf::Hash;
use crate::ann_class::{AnnBufSz, AnnClass, ANNBUF_SZ};
use crate::blkmine::Time;
use crate::blkmine::{AnnChunk, HeightWork};
use crate::blkminer::BlkMiner;
use crate::prooftree::ProofTree;
use log::{debug, warn};
use packetcrypt_sys::difficulty::pc_degrade_announcement_target;
use rayon::prelude::*;
use std::cell::RefCell;
use std::cmp::max;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct ClassInfo {
    pub hw: HeightWork,
    pub ann_count: usize,
    pub ann_effective_work: u32,
    pub immature: bool,
    pub buf_count: usize,
    pub id: usize,
}
impl ClassInfo {
    pub fn can_mine(&self) -> bool {
        self.ann_effective_work != 0xffffffff && self.ann_count > 0
    }
}

struct AnnStoreMut {
    classes: BTreeMap<HeightWork, Box<AnnClass>>,
    recent_blocks: HashMap<i32, Hash>,
}

pub struct AnnStore {
    m: RwLock<AnnStoreMut>,
    next_class_id: AtomicUsize,
}

thread_local!(static ANN_BUF: RefCell<Option<Box<AnnBufSz>>> = RefCell::new(None));

impl AnnStore {
    pub fn new(bm: Arc<BlkMiner>) -> Self {
        // initial buf store, capable of filling the received miner entirely.
        assert!(bm.max_anns >= ANNBUF_SZ as u32);
        let buf_store = (0..)
            .map(|i| Box::new(AnnBufSz::new(Arc::clone(&bm), i * ANNBUF_SZ)))
            .take(bm.max_anns as usize / ANNBUF_SZ); // this rounds the result down.

        let hw_store = HeightWork {
            block_height: 0,
            work: 0xffffffff,
        };
        // bufs will always be stolen from this class until it is used up.
        let class_store = Box::new(AnnClass::with_bufs(buf_store, &hw_store, 0));

        let mut classes = BTreeMap::new();
        classes.insert(hw_store, class_store);
        Self {
            m: RwLock::new(AnnStoreMut {
                classes,
                recent_blocks: HashMap::new(),
            }),
            next_class_id: AtomicUsize::new(1),
        }
    }

    pub fn block(&self, height: i32, hash: [u8; 32]) {
        let mut m = self.m.write().unwrap();
        m.recent_blocks.insert(height, hash.into());
    }

    pub fn push_anns(&self, hw: HeightWork, ac: &AnnChunk) -> usize {
        ANN_BUF.with(|opt_buf| {
            let ab = if let Some(ab) = opt_buf.borrow_mut().take() {
                ab
            } else {
                let m = self.m.read().unwrap();
                if let Some(ab) = steal_non_mining_buf(&m) {
                    ab
                } else {
                    return 0;
                }
            };
            let (sz, opt_ab) = self.push_anns1(hw, ac, ab);
            *opt_buf.borrow_mut() = opt_ab;
            sz
        })
    }

    fn push_anns1(
        &self,
        hw: HeightWork,
        ac: &AnnChunk,
        buf: Box<AnnBufSz>,
    ) -> (usize, Option<Box<AnnBufSz>>) {
        loop {
            {
                let m = self.m.read().unwrap();
                if let Some(class) = m.classes.get(&hw) {
                    return class.push_anns(ac.anns, ac.indexes, buf);
                }
            }
            {
                let mut m = self.m.write().unwrap();
                let v = m
                    .classes
                    .iter()
                    .filter(|(_, c)| c.is_dead())
                    .map(|(hw, _)| hw)
                    .cloned()
                    .collect::<Vec<_>>();
                for hw in v {
                    m.classes.remove(&hw);
                }
                if m.classes.get(&hw).is_some() {
                    continue;
                }
                let id = self.next_class_id.fetch_add(1, Relaxed);
                let new_class = Box::new(AnnClass::new(None, vec![], &hw, id));
                assert!(m.classes.insert(hw, new_class).is_none());
            }
        }
    }

    /// Return the classes that does have announcements at the moment, already ranked according to
    /// their effective ann work.
    pub fn classes(&self, next_height: i32) -> Vec<ClassInfo> {
        let m = self.m.read().unwrap();
        let mut ready = m
            .classes
            .par_iter()
            .map(|(&hw, ac)| {
                let age = max(0, next_height - hw.block_height) as u32;
                let aew = pc_degrade_announcement_target(hw.work, age);
                (hw, ac, aew, age <= 3)
            })
            .map(|(hw, ac, aew, immature)| {
                let (ann_count, buf_count) = ac.ready_anns_bufs();
                ClassInfo {
                    hw,
                    ann_count,
                    ann_effective_work: aew,
                    buf_count,
                    id: ac.id,
                    immature,
                }
            })
            .collect::<Vec<_>>();

        ready.sort_unstable_by_key(|ci| ci.ann_effective_work);
        ready
    }

    pub fn compute_tree(
        &self,
        set: &[HeightWork],
        pt: &mut ProofTree,
        time: &mut Time,
    ) -> Result<(), &'static str> {
        let m = self.m.read().unwrap();
        let mut set = set
            .into_par_iter() // parallel, since locks must be acquired for all classes.
            .map(|hw| {
                let c = &m.classes[hw]; // will panic if a wrong hw is passed.
                (c, c.ready_anns(), None) // count again, since they may have changed.
            })
            .collect::<Vec<_>>();
        let total_anns = set.iter().map(|(_, r, _)| r).sum();

        // split the out buffer into sub-buffers for each class according to
        // how many anns they had ready, which may be changing as we speak...
        let mut out = &mut pt.ann_data[..];
        for (_, this, dst) in &mut set {
            let (data, excess) = out.split_at_mut(*this);
            *dst = Some(data);
            out = excess;
        }
        debug!("{}", time.next("compute_tree: prepare"));
        // now that they're split, copy the hashes over in parallel.
        set.into_par_iter().for_each(|(c, _, dst)| {
            c.read_ready_anns(dst.unwrap());
        });
        debug!("{}", time.next("compute_tree: read_ready_anns"));
        // compute the tree.
        pt.compute(total_anns, time)
    }
}

fn steal_non_mining_buf<'a>(m: &'a AnnStoreMut) -> Option<Box<AnnBufSz>> {
    struct Class<'a> {
        hw: &'a HeightWork,
        class: &'a Box<AnnClass>,
        effective_work: u32,
    }
    let next_block_height = if let Some(current_height) = m.recent_blocks.keys().max() {
        1 + *current_height
    } else {
        for (hw, cl) in &m.classes {
            if hw.block_height == 0 {
                if let Ok(Some(mut buf)) = cl.steal_buf() {
                    buf.reset();
                    return Some(buf);
                }
            }
        }
        warn!("Cannot steal buffer yet because we have no recent blocks");
        return None;
    };
    let mut classes = m
        .classes
        .iter()
        .map(|(hw, c)| Class {
            hw,
            class: c,
            effective_work: c.ann_effective_work(next_block_height as u32),
        })
        .collect::<Vec<Class<'a>>>();
    classes.sort_unstable_by_key(|a| 0xffffffff - a.effective_work);
    let (mut class_count, mut mining_count, mut empty_count, mut too_new) = (0, 0, 0, 0);
    for cl in classes {
        class_count += 1;
        if next_block_height - cl.hw.block_height <= 3 {
            too_new += 1;
            continue;
        }
        match cl.class.steal_buf() {
            Err(_) => {
                // we're mining with this one, can't take it.
                mining_count += 1;
            }
            Ok(None) => {
                // this one has been completely wiped out.
                empty_count += 1;
            }
            Ok(Some(mut buf)) => {
                buf.reset();
                return Some(buf);
            }
        }
        if let Ok(Some(mut buf)) = cl.class.steal_buf() {
            buf.reset();
            return Some(buf);
        }
    }
    warn!(
        "Unable to get a buffer: classes: [{}], too_new: [{}] mining: [{}], empty: [{}]",
        class_count, too_new, mining_count, empty_count
    );
    None
}
