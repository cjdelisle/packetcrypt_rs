// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use bytes::BufMut;
use log::debug;
use packetcrypt_sys::*;
use rayon::prelude::*;
use std::cmp::max;
use std::convert::TryInto;

pub struct AnnData {
    pub hash: [u8; 32],
    pub mloc: u32,
    pub index: u32,
}
impl AnnData {
    fn hash_pfx(&self) -> u64 {
        u64::from_le_bytes(self.hash[0..8].try_into().unwrap())
    }
}

pub struct ProofTree {
    raw: *mut ProofTree_t,
    capacity: u32,
    size: u32,
    highest_mloc: u32,
    root_hash: Option<[u8; 32]>,
    data: Vec<AnnData>,
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
    pub fn new(max_anns: u32) -> ProofTree {
        ProofTree {
            raw: unsafe { ProofTree_create(max_anns) },
            size: 0,
            highest_mloc: 0,
            capacity: max_anns,
            root_hash: None,
            data: Vec::new(),
        }
    }
    pub fn reset(&mut self) {
        self.size = 0;
        self.root_hash = None;
        self.highest_mloc = 0;
    }
    pub fn push(&mut self, hash: &[u8; 32], mloc: u32) -> Result<(), &'static str> {
        if self.root_hash.is_some() {
            return Err("tree is in computed state, call reset() first");
        }
        if self.size >= self.capacity {
            return Err("out of space");
        }
        let pfx = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        if pfx == 0 || pfx == 0xffffffffffffffff {
            // Don't allow these
            return Ok(());
        }
        self.data.push(AnnData {
            hash: *hash,
            mloc,
            index: 0,
        });
        self.size += 1;
        self.highest_mloc = max(self.highest_mloc, mloc);
        Ok(())
    }
    pub fn size(&self) -> u32 {
        self.size
    }
    pub fn old_compute(&mut self) -> Result<Vec<u32>, &'static str> {
        if self.root_hash.is_some() {
            return Err("tree is in computed state, call reset() first");
        }
        if self.size == 0 {
            return Err("no anns, cannot compute tree");
        }
        unsafe {
            ProofTree_clear(self.raw);
        }
        for d in &self.data {
            unsafe { ProofTree_append(self.raw, d.hash.as_ptr(), d.mloc) };
        }
        let mut out = vec![0u32; self.size as usize];
        let mut rh = [0u8; 32];
        let out_p = out.as_mut_ptr();
        let rh_p = rh.as_mut_ptr();
        let count = unsafe { ProofTree_compute(self.raw, rh_p, out_p) };
        out.truncate(count as usize);
        self.root_hash = Some(rh);
        self.size = count;
        for (i, mloc) in (0..).zip(&out) {
            if *mloc > self.highest_mloc {
                panic!(
                    "entry {} of {} has mloc {}, highest possible is {}",
                    i,
                    out.len(),
                    *mloc,
                    self.highest_mloc
                );
            }
        }
        Ok(out)
    }
    pub fn compute(&mut self, data: &mut [AnnData]) -> Result<Vec<u32>, &'static str> {
        if self.root_hash.is_some() {
            return Err("tree is in computed state, call reset() first");
        }
        if self.size == 0 {
            return Err("no anns, cannot compute tree");
        }

        // Sort the data items
        data.par_sort_by(|a, b| a.hash_pfx().cmp(&b.hash_pfx()));

        // Create the index table
        let mut out = Vec::with_capacity(self.size as usize);
        let mut last_pfx = 0;
        for d in data.iter_mut() {
            let pfx = d.hash_pfx();
            // Deduplicate and insert in the index table
            #[allow(clippy::comparison_chain)]
            if pfx > last_pfx {
                out.push(d.mloc);
                // careful to skip entry 0 which is the 0-entry
                d.index = out.len() as u32;
                last_pfx = pfx;
            } else if pfx == last_pfx {
                //debug!("Drop ann with index {:#x}", pfx);
                d.index = 0;
            } else {
                panic!("list not sorted {:#x} < {:#x}", pfx, last_pfx);
            }
        }
        debug!("Loaded {} out of {} anns", out.len(), self.size);

        // Copy the data to the location
        data
            //par_iter()
            .iter()
            .for_each(|d| {
                if d.index == 0 {
                    // Removed in dedupe stage
                    return;
                }
                let e = ProofTree_Entry_t {
                    hash: d.hash,
                    start: d.hash_pfx(),
                    end: 0,
                };
                unsafe { ProofTree_putEntry(self.raw, d.index, &e as *const ProofTree_Entry_t) };
            });

        // Cap off the top with an ffff entry
        let total_anns_zero_included = out.len() + 1;
        let mut rh = [0u8; 32];
        let rh_p = rh.as_mut_ptr();
        unsafe {
            ProofTree_putEntry(self.raw, total_anns_zero_included as u32, fff_entry());
            ProofTree_setTotalAnnsZeroIncluded(self.raw, total_anns_zero_included as u32);
            ProofTree_compute2(self.raw, rh_p);
        }

        self.root_hash = Some(rh);
        self.size = out.len() as u32;
        for (i, mloc) in (0..).zip(&out) {
            if *mloc > self.highest_mloc {
                panic!(
                    "entry {} of {} has mloc {}, highest possible is {}",
                    i,
                    out.len(),
                    *mloc,
                    self.highest_mloc
                );
            }
        }
        Ok(out)

        /*

        // Set the end of each entry to the start of the following entry
        self.data.iter().for_each(|d| unsafe {
            if d.index == 0 {
                // Removed in dedupe stage
                return;
            }
            let e = ProofTree_getEntry(self.raw, d.index);
            let e_n = ProofTree_getEntry(self.raw, d.index + 1);
            (*e).end = (*e_n).start;
            //debug!("{} {:#x} {:#x}", d.index, (*e).start, (*e).end);
            assert!((*e).end > (*e).start);
        });

        // Set the end of the zero entry
        unsafe {
            let e = ProofTree_getEntry(self.raw, 0);
            let e_n = ProofTree_getEntry(self.raw, 1);
            (*e).end = (*e_n).start;
        }

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
                //.into_par_iter()
                .step_by(2)
                .for_each(|i| unsafe {
                    ProofTree_hashPair(self.raw, (odx + i / 2) as u64, (idx + i) as u64);
                });
            idx += count_this_layer;
            count_this_layer >>= 1;
            odx += count_this_layer;
        }
        assert!(idx + 1 == odx);
        let mut rh = [0u8; 32];
        assert!(odx as u64 == unsafe { ProofTree_complete(self.raw, rh.as_mut_ptr()) });

        self.root_hash = Some(rh);
        self.size = out.len() as u32;
        for (i, mloc) in (0..).zip(&out) {
            if *mloc > self.highest_mloc {
                panic!(
                    "entry {} of {} has mloc {}, highest possible is {}",
                    i,
                    out.len(),
                    *mloc,
                    self.highest_mloc
                );
            }
        }

        Ok(out)
        */
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
