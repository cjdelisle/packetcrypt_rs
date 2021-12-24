use crate::blkminer::BlkMiner;
use anyhow::Result;
use packetcrypt_annmine::annminer::{AnnMiner, AnnMinerS};
use packetcrypt_util::util;
use rand::Rng;
use packetcrypt_sys::sodiumoxide::crypto::stream::chacha20;
use std::fmt::{Display, Formatter};
use std::io::{self, Write};
use std::ops::{AddAssign, Div};
use std::thread;
use std::time::Duration;

pub struct Bencher {
    repeats: u32,
    sampling: Duration,
}

impl Bencher {
    pub fn new(repeats: u32, sampling_ms: u64) -> Self {
        Self {
            repeats,
            sampling: Duration::from_millis(sampling_ms),
        }
    }

    pub fn bench_blk(&self, max_mem: u64, threads: u32) -> Result<()> {
        println!("Starting benchmark");
        println!("mem: {}MB, threads: {}", max_mem / 1024 / 1024, threads);
        let block_miner = start_bench_blk(max_mem, threads)?;

        // we will just call this several times, and return their arithmetic average.
        // there probably are more advanced/accurate algorithms, like discarding the outliers,
        // using other kinds of average, etc., but we'll keep it simple.
        let mut result = BenchBlk::default();
        for i in 1..=self.repeats {
            thread::sleep(self.sampling);
            let partial = BenchBlk {
                hashes_per_second: block_miner.hashes_per_second() as f64,
                // other monitoring points in the future?
            };
            println!("{:2}. result: {}", i, partial);
            result += partial;
        }
        println!("average: {}", result / self.repeats);
        block_miner.request_stop();
        block_miner.await_stop();
        Ok(())
    }

    pub fn bench_ann(&self, threads: usize) -> Result<()> {
        println!("Starting benchmark");
        println!("threads: {}", threads);
        let ann_miner = start_bench_ann(threads)?;

        // waits a bit to let the miner kick in.
        thread::sleep(Duration::from_millis(1000));
        ann_miner.hashes_per_second(); // this resets the inner counter.

        // we will just call this several times, and return their arithmetic average.
        // there probably are more advanced/accurate algorithms, like discarding the outliers,
        // using other kinds of average, etc., but we'll keep it simple.
        let mut result = BenchBlk::default();
        for i in 1..=self.repeats {
            thread::sleep(self.sampling);
            let partial = BenchBlk {
                hashes_per_second: ann_miner.hashes_per_second(),
                // other monitoring points in the future?
            };
            println!("{:2}. result: {}", i, partial);
            result += partial;
        }
        println!("average: {}", result / self.repeats);
        Ok(())
    }
}

/// Assembles all the infrastructure needed to block mining, and starts it.
fn start_bench_blk(max_mem: u64, threads: u32) -> Result<BlkMiner> {
    let block_miner = BlkMiner::new(max_mem, threads)?;
    println!("created miner");

    let key = chacha20::gen_key();
    let mut nonce = chacha20::Nonce::from_slice(&[0; 8]).unwrap();
    let mut ann = chacha20::stream(1024, &nonce, &key);
    let total_entries = block_miner.max_anns;
    for i in 0..total_entries {
        print!(
            "\rinserting announcements... {:.1}%",
            i as f64 / total_entries as f64 * 100.0
        );
        io::stdout().flush().unwrap();

        nonce.increment_le_inplace();
        chacha20::stream_xor_inplace(&mut ann, &nonce, &key);
        block_miner.put_ann(i, &ann);
    }
    println!();

    println!("preparing lookup table...");
    struct Entry {
        index: u32,
        random: u32,
    }
    let mut r = rand::thread_rng();
    let mut lookup = (0..total_entries)
        .map(|index| Entry {
            index,
            random: r.gen(),
        })
        .collect::<Vec<_>>();
    lookup.sort_unstable_by_key(|e| e.random);
    let lookup = lookup.into_iter().map(|e| e.index).collect::<Vec<_>>();

    println!("starting mining");
    block_miner.mine(&[0u8, 80], &lookup, 0x03000001, 0xc001); // 0xc001 is cool :)
    Box::new(lookup).leak();
    Ok(block_miner)
}

/// Assembles all the infrastructure needed to ann mining, and starts it.
fn start_bench_ann(threads: usize) -> Result<AnnMiner> {
    let (ann_miner, _recv) = AnnMinerS::new(123, threads);
    println!("created miner");

    // recv is ignored, which closes the channel, but the target below is impossible, so it won't ever win.

    println!("starting mining");
    ann_miner.start([0u8; 32], 123, 0x03000001, None)?;
    Ok(ann_miner)
}

#[derive(Default)]
struct BenchBlk {
    hashes_per_second: f64,
}

impl AddAssign for BenchBlk {
    fn add_assign(&mut self, rhs: Self) {
        self.hashes_per_second += rhs.hashes_per_second
    }
}

impl Div<u32> for BenchBlk {
    type Output = BenchBlk;

    fn div(self, rhs: u32) -> Self::Output {
        BenchBlk {
            hashes_per_second: self.hashes_per_second / rhs as f64,
        }
    }
}

impl Display for BenchBlk {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}e/s", util::big_number(self.hashes_per_second))
    }
}
