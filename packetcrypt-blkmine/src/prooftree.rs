// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::blkmine::Time;
use crate::types::AnnData;
use crate::databuf::DataBuf;
use bytes::BufMut;
use log::debug;
use packetcrypt_sys::*;
use rayon::prelude::*;
use std::sync::Arc;

pub struct ProofTree {
    db: Arc<DataBuf>,
    raw: *mut ProofTree_t,
    capacity: u32,
    size: u32,
    pub root_hash: Option<[u8; 32]>,
    pub ann_data: Vec<AnnData>,
    pub index_table: Vec<u32>,
}

unsafe impl Send for ProofTree {}
unsafe impl Sync for ProofTree {}

impl Drop for ProofTree {
    fn drop(&mut self) {
        unsafe {
            ProofTree_destroy(self.raw);
        }
    }
}

static FFF_ENTRY: ProofTree_Entry_t = ProofTree_Entry_t {
    hash: [0xff_u8; 32],
    start: 0xffffffffffffffff,
    end: 0xffffffffffffffff,
};
fn fff_entry() -> *const ProofTree_Entry_t {
    &FFF_ENTRY as *const ProofTree_Entry_t
}

impl ProofTree {
    pub fn new(max_anns: u32, db: Arc<DataBuf>) -> ProofTree {
        ProofTree {
            db,
            raw: unsafe { ProofTree_create(max_anns) },
            size: 0,
            capacity: max_anns,
            root_hash: None,
            ann_data: vec![AnnData::default(); max_anns as usize], // TODO: this is going to take ages
            index_table: Vec::with_capacity(max_anns as usize),
        }
    }

    pub fn reset(&mut self) {
        self.size = 0;
        self.root_hash = None;
    }

    pub fn compute(&mut self, count: usize, time: &mut Time) -> Result<(), &'static str> {
        if self.root_hash.is_some() {
            return Err("tree is in computed state, call reset() first");
        }
        if count == 0 {
            return Err("no anns, cannot compute tree");
        }
        if count > self.capacity as usize {
            return Err("too many anns");
        }

        // Sort the data items
        self.ann_data[..count].par_sort_unstable_by_key(|a| a.hash_pfx);
        debug!("{}", time.next("compute_tree: par_sort_unstable_by_key()"));

        // Truncate the index table
        self.index_table.clear();

        let mut last_pfx = 0;
        self.index_table.extend(self.ann_data[..count].iter().filter_map(|d| {
            if d.hash_pfx == last_pfx {
                //debug!("Drop ann with index {:#x}", pfx);
                None
            } else if d.hash_pfx < last_pfx {
                panic!("list not sorted {:#x} < {:#x}", d.hash_pfx, last_pfx);
            } else {
                last_pfx = d.hash_pfx;
                Some(d.mloc as u32) // TODO: risk
            }
        }));
        debug!("{}", time.next("compute_tree: index_table.extend()"));

        self.index_table.par_iter().enumerate().for_each(|(i, mloc)|{
            let hash = self.db.get_hash(*mloc as usize);
            let pfx_next = if self.index_table.len() > i+1 {
                self.db.get_hash(self.index_table[i+1] as usize).to_u64()
            } else {
                u64::MAX
            };
            let e = ProofTree_Entry_t {
                hash: *hash,
                start: hash.to_u64(),
                end: pfx_next,
            };
            unsafe { ProofTree_putEntry(self.raw, (i + 1) as u32, &e as *const ProofTree_Entry_t) };
        });
        debug!("{}", time.next("compute_tree: putEntry()"));

        let total_anns_zero_included = self.index_table.len() + 1;
        unsafe { ProofTree_prepare2(self.raw, total_anns_zero_included as u64) };
        debug!("{} total {}", time.next("compute_tree: prepare2()"), total_anns_zero_included);

        // Build the merkle tree
        let mut count_this_layer = total_anns_zero_included;
        let mut odx = count_this_layer;
        let mut idx = 0;
        while count_this_layer > 1 {
            if (count_this_layer & 1) != 0 {
                unsafe { ProofTree_putEntry(self.raw, odx as u32, fff_entry()) };
                count_this_layer += 1;
                odx += 1;
            }
            (0..count_this_layer)
                .into_par_iter()
                .step_by(2)
                .for_each(|i| unsafe {
                    ProofTree_hashPair(self.raw, (odx + i / 2) as u64, (idx + i) as u64);
                });
            idx += count_this_layer;
            count_this_layer /= 2;
            odx += count_this_layer;
        }
        assert!(idx + 1 == odx);
        let mut rh = [0u8; 32];
        assert!(odx as u64 == unsafe { ProofTree_complete(self.raw, rh.as_mut_ptr()) });
        debug!("{}", time.next("compute_tree: compute tree"));

        self.root_hash = Some(rh);
        self.size = self.index_table.len() as u32;
        Ok(())
    }

    pub fn get_commit(&self, ann_min_work: u32) -> Result<bytes::BytesMut, &'static str> {
        let hash = if let Some(h) = self.root_hash.as_ref() {
            h
        } else {
            return Err("Not in computed state, call compute() first");
        };
        let mut out = bytes::BytesMut::with_capacity(44);
        out.put(&[0x09, 0xf9, 0x11, 0x02][..]);
        out.put_u32_le(ann_min_work);
        out.put(&hash[..]);
        out.put_u64_le(self.size as u64);
        Ok(out)
    }

    pub fn mk_proof(&mut self, ann_nums: &[u64; 4]) -> Result<bytes::BytesMut, &'static str> {
        if self.root_hash.is_none() {
            return Err("Not in computed state, call compute() first");
        }
        for n in ann_nums {
            if *n >= self.size as u64 {
                return Err("Ann number out of range");
            }
        }
        Ok(unsafe {
            let proof = ProofTree_mkProof(self.raw, ann_nums.as_ptr());
            let mut out = bytes::BytesMut::with_capacity((*proof).size as usize);
            let sl = std::slice::from_raw_parts((*proof).data, (*proof).size as usize);
            out.put(sl);
            ProofTree_destroyProof(proof);
            out
        })
    }
}
