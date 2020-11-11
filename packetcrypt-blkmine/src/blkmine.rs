use anyhow::{bail, Context, Result};
use packetcrypt_util::poolclient::{self, PoolClient};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct BlkArgs {
    pub payment_addr: String,
    pub threads: usize,
    pub uploads: usize,
    pub downloads: usize,
    pub workdir: String,
    pub pool_master: String,
    pub miner_id: u32,
}

#[derive(Debug)]
pub struct BlkMineM {
    unused: i32,
}

pub struct BlkMineS {
    m: RwLock<BlkMineM>,
    pc: PoolClient,
    ba: BlkArgs,
}
pub type BlkMine = Arc<BlkMineS>;

pub async fn new(ba: BlkArgs) -> Result<BlkMine> {
    let pc = poolclient::new(&ba.pool_master, 32);
    Ok(Arc::new(BlkMineS {
        m: RwLock::new(BlkMineM { unused: 0 }),
        pc,
        ba,
    }))
}

// AnnIndex
// put_file(name, height, min_diff, count)
// drain_useless(curr_height) Iterator<&str>
struct AnnEntry {
    file: String,
    height: i32,
    hash: [u8; 32],
    min_diff: u32,
    count: u64,
}
struct AnnIndex {
    entries: Vec<AnnEntry>,
}

pub async fn start(bm: &BlkMine) -> Result<()> {
    // 1. open workdir, scan and build index
    // 2. connect to annhandlers and begin downloading
    // 3. launch deleter
    // 4. lock and mine - later: separate the two
    poolclient::start(&bm.pc).await;
    Ok(())
}
