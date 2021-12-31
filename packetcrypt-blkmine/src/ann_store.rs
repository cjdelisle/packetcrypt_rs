use crate::types::{Hash,AnnData,HeightWork,ClassSet};
use crate::ann_class::{AnnBufSz, AnnClass, ANNBUF_SZ, BUF_RANGES};
use crate::ann_buf::RangeCount;
use crate::blkmine::{AnnChunk, Time};
use crate::databuf::DataBuf;
use crate::prooftree::ProofTree;
use log::{debug, warn, trace};
use packetcrypt_sys::difficulty::pc_degrade_announcement_target;
use rayon::prelude::*;
use std::cell::RefCell;
use std::cmp::max;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
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

#[derive(Default)]
struct ThreadData {
    hashes: Vec<Hash>,
    spare_buf: Option<Box<AnnBufSz>>,
}

thread_local!(static ANN_BUF: RefCell<ThreadData> = RefCell::default());

impl AnnStore {
    pub fn new(db: Arc<DataBuf>) -> Self {
        // initial buf store, capable of filling the received miner entirely.
        assert!(db.max_anns >= ANNBUF_SZ);
        let buf_store = (0..)
            .map(|i| Box::new(AnnBufSz::new(Arc::clone(&db), i * ANNBUF_SZ)))
            .take(db.max_anns / ANNBUF_SZ); // this rounds the result down.

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
        let mut total = 0;
        loop {
            if total == ac.indexes.len() {
                return total;
            }
            let ret = ANN_BUF.with(|thread_data| {
                let mut td = thread_data.borrow_mut();
                let ab = if let Some(ab) = td.spare_buf.take() {
                    ab
                } else {
                    let m = self.m.read().unwrap();
                    if let Some(ab) = steal_non_mining_buf(&m) {
                        ab
                    } else {
                        return Err(());
                    }
                };
                while td.hashes.len() < ac.anns.len() {
                    td.hashes.push(Hash::default());
                }
                for index in ac.indexes[total..].iter().cloned() {
                    td.hashes[index as usize].compute(ac.anns[index as usize]);
                }
                let (sz, opt_ab) = self.push_anns1(hw, ac.anns, &ac.indexes[total..], ab, &td.hashes);
                if let Some(ab) = opt_ab {
                    td.spare_buf.replace(ab);
                }
                Ok(sz)
            });
            match ret {
                Err(_) => return total,
                Ok(sz) => total += sz,
            }
        }
    }

    fn push_anns1(
        &self,
        hw: HeightWork,
        all_anns: &[&[u8]],
        interesting_indexes: &[u32],
        buf: Box<AnnBufSz>,
        hashes: &Vec<Hash>
    ) -> (usize, Option<Box<AnnBufSz>>) {
        loop {
            {
                let m = self.m.read().unwrap();
                if let Some(class) = m.classes.get(&hw) {
                    return class.push_anns(all_anns, interesting_indexes, buf, hashes);
                }
            }
            {
                let mut m = self.m.write().unwrap();
                m.classes.retain(|_hw, c| !c.is_dead());
                if m.classes.contains_key(&hw) {
                    continue;
                }
                let id = self.next_class_id.fetch_add(1, Ordering::Relaxed);
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
            .map(|(hw, ac, ann_effective_work, immature)| {
                let (ann_count, buf_count) = ac.ready_anns_bufs();
                ClassInfo {
                    hw,
                    ann_count,
                    ann_effective_work,
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
        cs: ClassSet,
        pt: &mut ProofTree,
        time: &mut Time,
    ) -> Result<(), &'static str> {
        {
            let m = self.m.read().unwrap();
            let mut set = Vec::new();
            for (hw, c) in m.classes.iter() {
                if cs.best_set.contains(hw) {
                    c.begin_mining();
                    let bufs = c.take_bufs();
                    set.push((c, bufs));
                } else {
                    c.stop_mining();
                }
            }

            debug!("{}", time.next("compute_tree: take bufs"));
            let mut range_total = RangeCount::default();
            for (_, bufs) in &set {
                let v = bufs.par_iter().map(|b|&b.range_counts).fold(
                    ||{Box::new(RangeCount::default())},
                    |mut r1, r2|{
                        r1.add(r2);
                        r1
                    }
                ).collect::<Vec<_>>();
                for r in &v {
                    range_total.add(r);
                }
            }
            debug!("{}", time.next("compute_tree: count ranges"));

            let mut infos: Vec<AnnData> = {
                let total = range_total.0.iter().sum();
                let mut v = Vec::with_capacity(total);
                unsafe { v.set_len(total) };
                v
            };
            let markers = (0..BUF_RANGES).map(|_|AtomicUsize::new(0)).collect::<Vec<_>>();
            let mut offset = 0;
            for (i, r) in range_total.0.iter().enumerate() {
                markers[i].store(offset, Ordering::Relaxed);
                offset += r;
            }
            for (_, bufs) in &set {
                bufs.par_iter().for_each(|b| {
                    let mut boff = 0;
                    for i in 0..BUF_RANGES {
                        let c = b.range_counts.0[i];
                        let idx = markers[i].fetch_add(c, Ordering::Relaxed);
                        unsafe {
                            (*(&infos as *const Vec<AnnData> as *mut Vec<AnnData>))[idx..idx+c].copy_from_slice(
                                b.slice(boff, boff+c)
                            );
                        }
                        boff += c;
                    }
                });
            }
            debug!("{}", time.next("compute_tree: copy infos"));

            let mut infos1 = &mut infos[..];
            let mut info_bufs = Vec::with_capacity(BUF_RANGES);
            for &r in range_total.0.iter() {
                let (buf, rem) = infos1.split_at_mut(r);
                info_bufs.push(buf);
                infos1 = rem;
            }
            info_bufs.into_par_iter().for_each(|buf| {
                buf.sort_unstable_by_key(|a| a.hash_pfx);
            });
            debug!("{}", time.next("compute_tree: sort bufs"));

            let mut last = 0;
            pt.index_table.clear();
            for ad in infos {
                if ad.hash_pfx > last {
                    pt.index_table.push(ad.mloc as u32);
                    last = ad.hash_pfx;
                } else if ad.hash_pfx < last {
                    panic!("hash prefix went backwards!");
                }
            }
            debug!("{}", time.next("compute_tree: make index table"));

            for (c, bufs) in set {
                c.return_bufs(bufs);
            }
            debug!("{}", time.next("compute_tree: return bufs"));
        }
        //debug!("{}", time.next("compute_tree: read_ready_anns"));
        // compute the tree.
        pt.compute(time, cs)
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
    trace!(
        "Unable to get a buffer: classes: [{}], too_new: [{}] mining: [{}], empty: [{}]",
        class_count, too_new, mining_count, empty_count
    );
    None
}
