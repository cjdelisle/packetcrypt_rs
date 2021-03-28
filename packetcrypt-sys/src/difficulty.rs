use num_bigint::BigUint;
use num_traits::ToPrimitive;
use num_traits::{One, Zero};
use std::cmp::min;

pub fn bn_for_compact(compact: u32) -> BigUint {
    let size = compact >> 24;
    if (compact & 0x00800000) != 0 {
        panic!("Negative bignum not supported");
    }
    let word = compact & 0x007fffff;
    if size <= 3 {
        BigUint::from(word >> (8 * (3 - size)))
    } else {
        BigUint::from(word) << (8 * (size - 3))
    }
}

fn compact_for_bn(bn: BigUint) -> u32 {
    let (compact, size) = {
        let size = {
            let bits = bn.bits() as u32;
            bits / 8 + if bits % 8 == 0 { 0 } else { 1 }
        };
        let compact = if size <= 3 {
            bn.to_u32().unwrap() << (8 * (3 - size))
        } else {
            (bn >> (8 * (size - 3))).to_u32().unwrap()
        };
        if compact & 0x00800000 != 0 {
            (compact >> 8, size + 1)
        } else {
            (compact, size)
        }
    };
    compact | (size << 24)
}

const MAX_COMPACT: u32 = 0x207fffff;

fn is_valid(compact: u32) -> bool {
    compact > 0 && (compact & 0x00800000) == 0 && compact <= MAX_COMPACT
}

fn bn256() -> BigUint {
    BigUint::one() << 256
}

// work = 2**256 / (target + 1)
fn work_for_tar(target: BigUint) -> BigUint {
    bn256() / (target + BigUint::one())
}

// diffOut = (2**256 - work) / work
fn tar_for_work(work: BigUint) -> BigUint {
    if work.is_zero() {
        bn256()
    } else if work.bits() > 256 {
        BigUint::zero()
    } else {
        (bn256() - &work) / work
    }
}

const ANN_WAIT_PERIOD: u32 = 3;

// effective_work = work**3 / 1024 / ann_work / ann_count**2
fn get_effective_work(blk_work: BigUint, ann_work: BigUint, ann_count: u64) -> BigUint {
    if ann_work.is_zero() || ann_count == 0 {
        // This is work *required* so when there is no work and no announcements
        // that work is "infinite".
        return bn256();
    }

    // workOut = workOut**3
    let mut out = blk_work.pow(3);

    // difficulty /= 1024
    out >>= 10;

    // workOut /= annWork
    out /= ann_work;

    // workOut /= annCount
    out /= BigUint::from(ann_count).pow(2);

    out
}

#[no_mangle]
pub fn pc_get_effective_target(block_tar: u32, ann_tar: u32, ann_count: u64) -> u32 {
    let blk_work = work_for_tar(bn_for_compact(block_tar));
    let ann_work = work_for_tar(bn_for_compact(ann_tar));
    let effective_work = get_effective_work(blk_work, ann_work, ann_count);
    let out = compact_for_bn(tar_for_work(effective_work));
    min(out, 0x207fffff)
}

#[no_mangle]
pub fn pc_get_hashrate_multiplier(ann_tar: u32, ann_count: u64) -> u64 {
    let bn_ann_tar = bn_for_compact(ann_tar);
    let bn_ann_work = work_for_tar(bn_ann_tar);
    let bn_ann_count_2 = BigUint::from(ann_count).pow(2);
    let out: BigUint = (bn_ann_work * bn_ann_count_2) >> 10;
    if out.bits() > 64 {
        u64::MAX
    } else {
        out.to_u64().unwrap()
    }
}

#[allow(clippy::if_same_then_else)]
#[no_mangle]
pub fn pc_degrade_announcement_target(ann_tar: u32, ann_age_blocks: u32) -> u32 {
    if ann_age_blocks < ANN_WAIT_PERIOD {
    } else if ann_age_blocks > 256 + ANN_WAIT_PERIOD {
    } else if ann_age_blocks == ANN_WAIT_PERIOD {
        return ann_tar;
    } else {
        let bn_ann_tar = bn_for_compact(ann_tar) << (ann_age_blocks - ANN_WAIT_PERIOD);
        if bn_ann_tar.bits() < 256 {
            let out = compact_for_bn(bn_ann_tar);
            if out <= 0x207fffff {
                return out;
            }
        }
    }
    0xffffffff
}

#[no_mangle]
pub fn pc_is_min_ann_diff_ok(ann_tar: u32) -> bool {
    if is_valid(ann_tar) {
        let tar = bn_for_compact(ann_tar);
        if !tar.is_zero() {
            let work = work_for_tar(tar);
            if !work.is_zero() && work.bits() < 257 {
                return true;
            }
        }
    }
    false
}

pub fn tar_to_diff(ann_tar: u32) -> f64 {
    if is_valid(ann_tar) {
        let tar = bn_for_compact(ann_tar);
        if !tar.is_zero() {
            let work = work_for_tar(tar);
            if !work.is_zero() && work.bits() < 257 {
                return work.to_f64().unwrap_or(0.0);
            }
        }
    }
    0.0
}

#[cfg(all(test, feature = "difficulty-test"))]
mod tests {
    use num_traits::Zero;
    use rand::Rng;
    extern "C" {
        fn DifficultyTest_getEffectiveWork(blockWork: u32, annWork: u32, annCount: u64) -> u32;
        fn DifficultyTest_getEffectiveTarget(blockTar: u32, annTar: u32, annCount: u64) -> u32;
        fn DifficultyTest_degradeAnnouncementTarget(annTar: u32, annAgeBlocks: u32) -> u32;
        fn DifficultyTest_isMinAnnDiffOk(target: u32) -> bool;
        fn DifficultyTest_getHashRateMultiplier(annTar: u32, annCount: u64) -> u64;
        fn DifficultyTest_workForTar(target: u32) -> u32;
        fn DifficultyTest_tarForWork(cwork: u32) -> u32;
    }

    fn rand_compact(rng: &mut impl rand::Rng) -> u32 {
        loop {
            let mut x: u32 = rng.gen();
            if (x >> 24) != 0x20 {
                x >>= 3;
            }
            x &= 0xff7fffff;
            match x >> 24 {
                2 => {
                    if x & 0x00ffff00 == 0 {
                        continue;
                    }
                }
                1 => {
                    if x & 0x00ff0000 == 0 {
                        continue;
                    }
                }
                0 => continue,
                _ => {
                    if x & 0x00ffffff == 0 {
                        continue;
                    }
                }
            };
            return x;
        }
    }

    #[test]
    fn test_tar_for_work() {
        let mut rng = rand::thread_rng();
        let mut i = 0;
        while i < 1000 {
            let work = rand_compact(&mut rng);
            let bn_work = super::bn_for_compact(work);
            if bn_work.is_zero() {
                continue;
            }
            let c_answer = unsafe { DifficultyTest_tarForWork(work) };
            println!("work      {:08x}", work);
            let rs_answer = super::compact_for_bn(super::tar_for_work(bn_work));

            if c_answer != rs_answer {
                println!("work      {:08x}", work);
                println!("c_answer  {}", c_answer);
                println!("rs_answer {}", rs_answer);
                println!("Cycle {}", i);
                panic!("Test failed");
            }
            i += 1;
        }
    }

    #[test]
    fn test_work_for_tar() {
        let mut rng = rand::thread_rng();
        let mut i = 0;
        while i < 1000 {
            let tar = rand_compact(&mut rng);
            let c_answer = unsafe { DifficultyTest_workForTar(tar) };
            let rs_answer = super::compact_for_bn(super::work_for_tar(super::bn_for_compact(tar)));

            if c_answer != rs_answer {
                println!("tar       {:08x}", tar);
                println!("c_answer  {}", c_answer);
                println!("rs_answer {}", rs_answer);
                println!("Cycle {}", i);
                panic!("Test failed");
            }
            i += 1;
        }
    }

    #[test]
    fn test_is_min_ann_diff_ok() {
        let mut rng = rand::thread_rng();
        let mut i = 0;
        while i < 1000 {
            let ann_tar = rand_compact(&mut rng);
            let c_answer = unsafe { DifficultyTest_isMinAnnDiffOk(ann_tar) };
            let rs_answer = super::pc_is_min_ann_diff_ok(ann_tar);

            if c_answer != rs_answer {
                println!("annTar   {:08x}", ann_tar);
                println!("c_answer  {}", c_answer);
                println!("rs_answer {}", rs_answer);
                println!("Cycle {}", i);
                panic!("Test failed");
            }
            if rs_answer {
                i += 1;
            }
        }
    }

    #[test]
    fn test_get_effective_work() {
        let mut rng = rand::thread_rng();
        let mut i = 0;
        let mut ii = 0;
        while i < 1000 {
            let block_work = rand_compact(&mut rng);
            let ann_work = rand_compact(&mut rng);
            let ann_count = rng.gen::<u64>() & 0xffffff;

            let c_answer =
                unsafe { DifficultyTest_getEffectiveWork(block_work, ann_work, ann_count) };

            let bn_blk_work = super::bn_for_compact(block_work);
            let bn_ann_work = super::bn_for_compact(ann_work);
            let bn_effective_work = super::get_effective_work(bn_blk_work, bn_ann_work, ann_count);
            let rs_answer = super::compact_for_bn(bn_effective_work);

            if c_answer != rs_answer {
                println!("block_work {:#08x}", block_work);
                println!("ann_work   {:#08x}", ann_work);
                println!("annCount {}", ann_count);
                println!("c_answer  {:#08x}", c_answer);
                println!("rs_answer {:#08x}", rs_answer);
                println!("Cycle {} ({})", i, ii);
                panic!("Test failed");
            }
            if rs_answer < 0x207fffff && rs_answer > 0 {
                i += 1;
            }
            ii += 1;
        }
    }

    #[test]
    fn test_get_effective_target() {
        let mut rng = rand::thread_rng();
        let mut i = 0;
        let mut ii = 0;
        while i < 1000 {
            let block_tar = rand_compact(&mut rng);
            let ann_tar = rand_compact(&mut rng);
            let ann_count = rng.gen::<u64>();

            let c_answer =
                unsafe { DifficultyTest_getEffectiveTarget(block_tar, ann_tar, ann_count) };
            let rs_answer = super::pc_get_effective_target(block_tar, ann_tar, ann_count);

            if c_answer != rs_answer {
                println!("blockTar {:#08x}", block_tar);
                println!("annTar   {:#08x}", ann_tar);
                println!("annCount {}", ann_count);
                println!("c_answer  {:#08x}", c_answer);
                println!("rs_answer {:#08x}", rs_answer);
                println!("Cycle {} ({})", i, ii);
                panic!("Test failed");
            }
            if rs_answer < 0x207fffff && rs_answer > 0 {
                i += 1;
            }
            ii += 1;
        }
        //println!("Ran in {} cycles", ii);
    }

    #[test]
    fn test_degrade_announcement_target() {
        let mut rng = rand::thread_rng();
        let mut i = 0;
        let mut ii = 0;
        while i < 1000 {
            let ann_tar = rand_compact(&mut rng);
            let age_in_blocks = rng.gen::<u32>() & 0xff;

            let c_answer =
                unsafe { DifficultyTest_degradeAnnouncementTarget(ann_tar, age_in_blocks) };
            let rs_answer = super::pc_degrade_announcement_target(ann_tar, age_in_blocks);

            if c_answer != rs_answer {
                println!("annTar   {:#08x}", ann_tar);
                println!("age_in_blocks {}", age_in_blocks);
                println!("c_answer  {:#08x}", c_answer);
                println!("rs_answer {:#08x}", rs_answer);
                println!("Cycle {} {}", i, ii);
                panic!("Test failed");
            }
            if rs_answer < 0x207fffff && rs_answer > 0 {
                i += 1;
            }
            ii += 1;
        }
    }

    #[test]
    fn test_get_hashrate_multipler() {
        let mut rng = rand::thread_rng();
        let mut i = 0;
        while i < 1000 {
            let ann_tar = rand_compact(&mut rng);
            let ann_count = rng.gen::<u64>();

            let c_answer = unsafe { DifficultyTest_getHashRateMultiplier(ann_tar, ann_count) };
            let rs_answer = super::pc_get_hashrate_multiplier(ann_tar, ann_count);

            if c_answer != rs_answer {
                println!("annTar   {:#08x}", ann_tar);
                println!("ann_counr {}", ann_count);
                println!("c_answer  {:#08x}", c_answer);
                println!("rs_answer {:#08x}", rs_answer);
                println!("Cycle {}", i);
                panic!("Test failed");
            }
            i += 1;
        }
    }
}
