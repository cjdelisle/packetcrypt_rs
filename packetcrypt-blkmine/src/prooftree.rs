// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use bytes::BufMut;
use packetcrypt_sys::*;
use std::cmp::max;

pub struct ProofTree {
    raw: *mut ProofTree_t,
    capacity: u32,
    size: u32,
    highest_mloc: u32,
    root_hash: Option<[u8; 32]>,
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
impl ProofTree {
    pub fn new(max_anns: u32) -> ProofTree {
        ProofTree {
            raw: unsafe { ProofTree_create(max_anns) },
            size: 0,
            highest_mloc: 0,
            capacity: max_anns,
            root_hash: None,
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
        unsafe {
            ProofTree_append(self.raw, hash.as_ptr(), mloc);
        }
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
