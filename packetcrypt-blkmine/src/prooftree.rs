// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use bytes::BufMut;
use log::debug;
use packetcrypt_sys::*;
use rayon::prelude::*;
use std::cmp::max;
use std::convert::TryInto;

struct AnnData {
    hash: [u8; 32],
    mloc: u32,
    index: u32,
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

fn set_fff(e: &mut ProofTree_Entry_t) {
    e.hash = [0xff_u8; 32];
    e.start = 0xffffffffffffffff;
    e.end = 0xffffffffffffffff;
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
        unsafe {
            ProofTree_clear(self.raw);
        }
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
        // unsafe { xxx
        //     ProofTree_append(self.raw, hash.as_ptr(), mloc);
        // }
        self.size += 1;
        self.highest_mloc = max(self.highest_mloc, mloc);
        Ok(())
    }
    pub fn size(&self) -> u32 {
        self.size
    }
    pub fn compute(&mut self) -> Result<Vec<u32>, &'static str> {
        if self.root_hash.is_some() {
            return Err("tree is in computed state, call reset() first");
        }
        if self.size == 0 {
            return Err("no anns, cannot compute tree");
        }

        // Sort the data items
        self.data
            .par_sort_by(|a, b| a.hash_pfx().cmp(&b.hash_pfx()));

        // Create the index table
        let mut out = Vec::with_capacity(self.size as usize);
        let mut last_pfx = 0;
        for d in self.data.iter_mut() {
            let pfx = d.hash_pfx();
            // Deduplicate and insert in the index table
            if pfx > last_pfx {
                out.push(d.mloc);
                d.index = out.len() as u32 + 1;
                last_pfx = pfx;
            } else {
                debug!("Drop ann with index {}", pfx);
                d.index = 0;
            }
        }
        debug!("Loaded {} out of {} anns", out.len(), self.size);

        // Copy the data to the location
        self.data.par_iter().for_each(|d| unsafe {
            if d.index == 0 {
                // Removed in dedupe stage
                return;
            }
            let mut e = *ProofTree_getEntry(self.raw, d.index);
            e.hash.copy_from_slice(&d.hash);
            let pfx = u64::from_le_bytes(d.hash[0..8].try_into().unwrap());
            e.start = pfx;
        });

        // Cap off the top with an ffff entry
        let total_anns_zero_included = out.len() + 1;
        unsafe {
            set_fff(&mut *ProofTree_getEntry(self.raw, self.data.len() as u32));
            ProofTree_setTotalAnnsZeroIncluded(self.raw, total_anns_zero_included as u32);
        }

        // Set the end of each entry to the start of the following entry
        self.data.par_iter().for_each(|d| unsafe {
            let mut e = *ProofTree_getEntry(self.raw, d.index);
            let e_n = *ProofTree_getEntry(self.raw, d.index + 1);
            e.end = e_n.start;
        });

        let mut count_this_layer = total_anns_zero_included;
        let mut odx = count_this_layer;
        let mut idx = 0;
        while count_this_layer > 1 {
            if (count_this_layer & 1) != 0 {
                unsafe { set_fff(&mut *ProofTree_getEntry(self.raw, odx as u32)) };
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
