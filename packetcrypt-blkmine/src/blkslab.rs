// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Result};
use mmap::MapOption::{MapReadable, MapWritable};
use mmap::MemoryMap;
use packetcrypt_util::protocol;

const NUM_MINER_RESULTS: usize = 4;

fn fallback_mmap(max_mem: usize) -> Result<MemoryMap> {
    Ok(mmap::MemoryMap::new(max_mem, &[MapReadable, MapWritable])?)
}

#[cfg(not(target_os = "linux"))]
fn mmap(max_anns: usize) -> Result<MemoryMap> {
    fallback_mmap(max_anns)
}

const MB: usize = 1024 * 1024;
const GB: usize = 1024 * MB;

#[cfg(target_os = "linux")]
fn mmap(max_mem: usize) -> Result<MemoryMap> {
    for (sz, flag, size_s) in [
        (GB, libc::MAP_HUGE_1GB, "GB"),
        (2 * MB, libc::MAP_HUGE_2MB, "2MB"),
    ] {
        if max_mem < sz || max_mem % sz != 0 {
            continue;
        }
        match mmap::MemoryMap::new(
            max_mem,
            &[
                MapReadable,
                MapWritable,
                mmap::MapOption::MapNonStandardFlags(libc::MAP_HUGETLB),
                mmap::MapOption::MapNonStandardFlags(flag),
            ],
        ) {
            Ok(ret) => return Ok(ret),
            Err(e) => {
                info!(
                    "Unable to mmap hugetbl [{}] because [{}] trying fallback",
                    size_s, e
                );
            }
        }
    }
    fallback_mmap(max_anns)
}

pub struct Ann {
    pub data: [u8; 1024],
}

pub struct MineRes {
    pub high_nonce: u32,
    pub low_nonce: u32,
    pub ann_nums: [u32; 4],
}

pub struct WorkInfo {
    pub header: protocol::BlockHeader,
    pub results: [MineRes; NUM_MINER_RESULTS],
}

pub struct BlkSlab {
    annbuf: MemoryMap,
    pub max_anns: usize,
    work_info: &'static mut [WorkInfo],
    anns: &'static mut [Ann],
    index_table: &'static [u32],
}
unsafe impl Sync for BlkSlab {}
unsafe impl Send for BlkSlab {}

fn alloc_slice<'a, T>(ptr: &mut usize, len: &mut usize, count: usize) -> Result<&'a mut [T]> {
    let l = std::mem::size_of::<T>();
    if *len < l {
        bail!("Not enough space, need {} have {}", l, *len);
    }
    let out = std::slice::from_raw_parts_mut(*ptr as *mut T, count);
    *len -= l;
    *ptr += l;
    Ok(out)
}

pub fn put_ann(bs: &BlkSlab, ann: &[u8], index: u32) {}

pub fn alloc(max_mem: usize) -> Result<BlkSlab> {
    let annbuf = mmap(max_mem)?;
    let mut p = annbuf.data() as usize;
    let mut len = annbuf.len() as usize;
    let work_info: &[WorkInfo] = alloc_slice(&mut p, &mut len, 1)?;
    let mut max_anns = len / 1024;
    loop {
        if max_anns * 1024 + max_anns * 4 <= len {
            break;
        }
        max_anns -= 1;
    }
    Ok(BlkSlab {
        max_anns,
        work_info: alloc_slice(&mut p, &mut len, 1)?,
        anns: alloc_slice(&mut p, &mut len, max_anns)?,
        index_table: alloc_slice(&mut p, &mut len, max_anns)?,
        annbuf,
    })
}

// struct FreeList {
//     index: u32,
//     length: u32,
// }

// struct Aew {
//     parent_block_height: i32,
//     ann_min_work: u32,
//     ann_effective_work: u32, // temporary
//     ann_count: u32,
//     index: u32,
// }

// struct RevIndex {
//     hash: [u8; 32],
//     index: u32,
// }

// struct Ann {
//     data: [u128; 64],
// }

// //
// // index_a[n]: u32
// // index_b[n]: u32
// // rev_index[n]: { hash: [u8; 32], location: u32 }
// // aew: Vec<{ parent_block_height: i32, ann_min_work: u32, effective_work: u32, ann_count: u32, index: u32 }>
// // freelist: VecDeque<{ index: u32, length: u32 }>
// // add_anns(ann_set: bytes::Bytes)
// // lock_for_mining()

// fn add_anns(ann_set: bytes::Bytes) {
//     // Check that the anns *can* be used
//     // 1. Lock the freelist and get the necessary free items, unlock
//     // 2. generate the rev_index entries and enter them directly
//     // 3. copy the anns into the memory map
//     // 4. lock the aew and apppend entries
// }

// fn on_work(treenum: u8, next_work: protocol::Work) {
//     // 1. Lock the aew
//     //   1.1 compute effective work
//     //   1.2 sort
//     //   1.3 populate tree
//     // 2. Order tree
//     // 3. build the index before computing tree
//     // 4. Compute tree
//     // 5. send job to mining_loop
//     // 6. Lock the freelist and append the freed anns
// }

// // memory layout
// // header
// // index_table[max_anns]
// // results[threads]
// // anns[max_anns]

// fn mining_loop() {
//     // 1. poll for new work
//     //   * on new work -> stop miners, update job, start miners
//     // 2.
// }

// const NUM_MINER_RESULTS: usize = 4;

// struct MineRes {
//     high_nonce: u32,
//     low_nonce: u32,
//     ann_nums: [u32; 4],
// }

// struct Job {
//     tree: *const c_void,
//     ann_table: Vec<u32>,
// }

// struct BlkMine {
//     //slab: BlkSlab,
//     aew: Vec<Aew>,
//     tree_a: *mut c_void,
//     tree_b: *mut c_void,
//     rev_index: Vec<RevIndex>,
//     freelist: Mutex<VecDeque<FreeList>>,
// }
