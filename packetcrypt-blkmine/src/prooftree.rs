// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use crate::blkmine::Time;
use crate::databuf::DataBuf;
use bytes::BufMut;
use log::debug;
use packetcrypt_sys::*;
use rayon::prelude::*;
use std::sync::Arc;

pub struct ProofTree {
    db: Arc<DataBuf>,
    tbl: Option<Vec<ProofTree_Entry_t>>,
    size: u32,
    pub root_hash: Option<[u8; 32]>,
    //pub ann_data: Vec<AnnData>,
    pub index_table: Vec<u32>,
}

unsafe impl Send for ProofTree {}
unsafe impl Sync for ProofTree {}

static FFF_ENTRY: ProofTree_Entry_t = ProofTree_Entry_t {
    hash: [0xff_u8; 32],
    start: 0xffffffffffffffff,
    end: 0xffffffffffffffff,
};
static ZERO_ENTRY: ProofTree_Entry_t = ProofTree_Entry_t {
    hash: [0; 32],
    start: 0,
    end: 0,
};

impl ProofTree {
    pub fn new(max_anns: u32, db: Arc<DataBuf>) -> ProofTree {
        //let raw_tree = unsafe { ProofTree_create(max_anns) };
        let tbl_sz = unsafe { PacketCryptProof_entryCount(max_anns as u64) } as usize;
        ProofTree {
            db,
            tbl: Some(unsafe {
                let mut v = Vec::with_capacity(tbl_sz);
                v.set_len(tbl_sz);
                v
            }),
            size: 0,
            root_hash: None,
            // ann_data: unsafe {
            //     let mut v = Vec::with_capacity(max_anns as usize);
            //     v.set_len(max_anns as usize);
            //     v
            // },
            index_table: Vec::with_capacity(max_anns as usize),
        }
    }

    pub fn reset(&mut self) {
        self.size = 0;
        self.root_hash = None;
    }

    pub fn compute(&mut self, time: &mut Time) -> Result<(), &'static str> {
        if self.root_hash.is_some() {
            return Err("tree is in computed state, call reset() first");
        }
        if self.index_table.len() == 0 {
            return Err("no anns, cannot compute tree");
        }

        let mut tbl = self.tbl.take().unwrap();
        //for (i, ent) in tbl[1..self.index_table.len()+1]
        
        const CHUNK_SZ: usize = 256;
        let mut tbl_s = &mut tbl[1..];
        let mut slots = Vec::with_capacity(tbl_s.len() / CHUNK_SZ);
        for i in (0..).step_by(CHUNK_SZ) {
            if (self.index_table.len()+1) <= i + CHUNK_SZ + 3 {
                slots.push(tbl_s);
                break;
            }
            let (data, excess) = tbl_s.split_at_mut(CHUNK_SZ);
            slots.push(data);
            tbl_s = excess;
        }
        let num_slots = slots.len();
        slots.par_iter_mut().enumerate().for_each(|(block_num, chunk)| {
            let i = block_num * CHUNK_SZ;
            if block_num == num_slots - 1 {
                // last chunk, special treatment
                for ((ent, i), mloc) in chunk.iter_mut().zip(i..).zip(self.index_table[i..].iter()) {
                    let mloc = *mloc as usize;
                    let hash = self.db.get_hash(mloc);
                    ent.hash = hash.as_bytes();
                    ent.start = hash.to_u64();
                    ent.end = if i+1 < self.index_table.len() {
                        self.db.get_hash_pfx(self.index_table[i+1] as usize)
                    } else {
                        u64::MAX
                    };
                    if ent.end <= ent.start {
                        panic!("ent.end <= ent.start as mloc: {}\n", mloc);
                    }
                }
                return;
            }
            assert_eq!(chunk.len(), CHUNK_SZ);
            let mut mloc = self.index_table[i] as usize;
            let mut hash = self.db.get_hash(mloc);
            let mut mloc_plus1 = self.index_table[i+1] as usize;
            let mut hash_plus1 = self.db.get_hash(mloc_plus1);
            for (i, (ent, mloc_plus2)) in chunk.iter_mut().zip(self.index_table[i+2..].iter()).enumerate() {
                let mloc_plus2 = *mloc_plus2 as usize;
                self.db.prefetch_hash(mloc_plus2);
                ent.hash = hash.as_bytes();
                ent.start = hash.to_u64();
                ent.end = hash_plus1.to_u64();
                if ent.end <= ent.start {
                    panic!("ent.end {:#x} <= ent.start {:#x} as mloc: {}, mloc+1: {} - {}\n",
                        ent.end, ent.start, mloc, mloc_plus1, i);
                }
                hash = hash_plus1;
                mloc = mloc_plus1;

                mloc_plus1 = mloc_plus2;
                hash_plus1 = self.db.get_hash(mloc_plus2);
            }
        });
        debug!("{}", time.next("compute_tree: putEntry()"));

        let total_anns_zero_included = self.index_table.len() + 1;
        tbl[0] = ZERO_ENTRY;
        tbl[0].end = tbl[1].start;
        assert!(tbl[0].end > tbl[0].start);
        //unsafe { ProofTree_prepare2(self.raw, total_anns_zero_included as u64) };
        //debug!("{} total {}", time.next("compute_tree: prepare2()"), total_anns_zero_included);

        // Build the merkle tree
        let mut count_this_layer = total_anns_zero_included;
        let mut odx = count_this_layer;
        let mut idx = 0;
        while count_this_layer > 1 {
            assert!(tbl[odx-1].end == u64::MAX);
            if (count_this_layer & 1) != 0 {
                tbl[odx] = FFF_ENTRY;
                count_this_layer += 1;
                odx += 1;
            }
            (0..count_this_layer)
                .into_par_iter()
                .step_by(2)
                .for_each(|i| unsafe {
                    ProofTree_hashPair(tbl.as_ptr(), (odx + i / 2) as u64, (idx + i) as u64);
                });
            idx += count_this_layer;
            count_this_layer /= 2;
            odx += count_this_layer;
        }
        assert!(idx + 1 == odx);
        assert!(tbl[idx].start == 0 && tbl[idx].end == u64::MAX);
        let mut rh = [0u8; 32];
        assert!(odx as u64 == unsafe {
            ProofTree_complete2(tbl.as_ptr(), total_anns_zero_included as u64, rh.as_mut_ptr())
        });
        //assert!(odx as u64 == unsafe { ProofTree_complete(self.raw, rh.as_mut_ptr()) });
        debug!("{}", time.next("compute_tree: compute tree"));

        self.tbl = Some(tbl);
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
            let proof = ProofTree_mkProof(self.tbl.as_deref_mut().unwrap().as_ptr(), 
                (self.index_table.len() + 1) as u64,
                self.root_hash.unwrap().as_ptr(),
                ann_nums.as_ptr(),
            );
            let mut out = bytes::BytesMut::with_capacity((*proof).size as usize);
            let sl = std::slice::from_raw_parts((*proof).data, (*proof).size as usize);
            out.put(sl);
            ProofTree_destroyProof(proof);
            out
        })
    }
}
