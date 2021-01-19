// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Context, Result};
use clap::{App, Arg, SubCommand};
use log::warn;
use packetcrypt_annhandler::annhandler;
use packetcrypt_annmine::annmine;
use packetcrypt_blkmine::blkmine;
use packetcrypt_pool::{paymakerclient, poolcfg};
use packetcrypt_util::{poolclient, util};
#[cfg(not(target_os = "windows"))]
use tokio::signal::unix::{signal, SignalKind};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(feature = "leak_detect")]
mod alloc;

#[cfg(feature = "leak_detect")]
async fn leak_detect() -> Result<()> {
    let al = alloc::alloc_init().await?;
    let mut s = signal(SignalKind::user_defined1())?;
    tokio::spawn(async move {
        loop {
            s.recv().await;
            let outfile = format!("packetcrypt_memory_{}.txt", util::now_ms());
            println!("Got SIGUSR1, writing memory trace to: [{}]", outfile);
            if let Err(e) = al.write_mem_allocations(outfile).await {
                println!("Error writing memory trace [{:?}]", e);
            }
        }
    });
    Ok(())
}

#[cfg(not(feature = "leak_detect"))]
async fn leak_detect() -> Result<()> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
async fn exiter() -> Result<()> {
    let mut s = signal(SignalKind::user_defined2())?;
    tokio::spawn(async move {
        s.recv().await;
        println!("Got SIGUSR2, calling process::exit()");
        std::process::exit(252);
    });
    Ok(())
}

#[cfg(target_os = "windows")]
async fn exiter() -> Result<()> {
    Ok(())
}

async fn ah_main(config: &str, handler: &str) -> Result<()> {
    let confb = tokio::fs::read(config)
        .await
        .with_context(|| format!("Failed to read config file [{}]", config))?;
    let mut cfg: poolcfg::Config = toml::de::from_slice(&confb[..])
        .with_context(|| format!("Failed to parse config file [{}]", config))?;

    let hconf = if let Some(x) = cfg.ann_handler.remove(handler) {
        x
    } else {
        bail!("{} is not defined in the config file [{}]", handler, config);
    };
    let ah_workdir = poolcfg::get_ah_workdir(&cfg.root_workdir, &hconf);

    let pc = poolclient::new(&cfg.master_url, 6, 5);

    let pmc = paymakerclient::new(
        &pc,
        paymakerclient::PaymakerClientCfg {
            paylogdir: format!("{}/paylogdir", &ah_workdir),
            password: cfg.paymaker_http_password,
            paylog_submit_every_ms: 60_000,
        },
    )
    .await?;
    paymakerclient::start(&pmc).await;

    let ah = annhandler::new(&pc, &pmc, hconf).await?;
    annhandler::start(&ah).await;

    poolclient::start(&pc).await;

    // All of the threads and jobs are setup, put the main thread to sleep
    util::sleep_forever().await
}

const DEFAULT_ADDR: &str = "pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2";

fn warn_if_addr_default(payment_addr: &str) {
    if payment_addr == DEFAULT_ADDR {
        warn!(
            "--paymentaddr was not specified, coins will be mined for {}",
            DEFAULT_ADDR
        );
    }
}

async fn blk_main(ba: blkmine::BlkArgs) -> Result<()> {
    warn_if_addr_default(&ba.payment_addr);
    let bm = blkmine::new(ba).await?;
    bm.start().await?;
    util::sleep_forever().await
}

async fn ann_main(
    pools: Vec<String>,
    threads: usize,
    payment_addr: &str,
    uploaders: usize,
    upload_timeout: usize,
    mine_old_anns: i32,
) -> Result<()> {
    warn_if_addr_default(payment_addr);
    let am = annmine::new(annmine::AnnMineCfg {
        pools,
        miner_id: util::rand_u32(),
        workers: threads,
        uploaders,
        pay_to: String::from(payment_addr),
        upload_timeout,
        mine_old_anns,
    })
    .await?;
    annmine::start(&am).await?;

    util::sleep_forever().await
}

macro_rules! get_strs {
    ($m:ident, $s:expr) => {
        if let Some(x) = $m.values_of($s) {
            x.map(|x| x.to_string()).collect::<Vec<String>>()
        } else {
            return Ok(());
        }
    };
}
macro_rules! get_str {
    ($m:ident, $s:expr) => {
        if let Some(x) = $m.value_of($s) {
            x
        } else {
            return Ok(());
        }
    };
}
macro_rules! get_usize {
    ($m:ident, $s:expr) => {
        get_num!($m, $s, usize)
    };
}
macro_rules! get_num {
    ($m:ident, $s:expr, $n:ident) => {{
        let s = get_str!($m, $s);
        if let Ok(u) = s.parse::<$n>() {
            u
        } else {
            println!("Unable to parse argument {} as number [{}]", $s, s);
            return Ok(());
        }
    }};
}

#[tokio::main]
async fn main() -> Result<()> {
    leak_detect().await?;
    exiter().await?;
    let cpus_str = format!("{}", num_cpus::get());
    let matches = App::new("packetcrypt")
        .version("0.4.0")
        .author("Caleb James DeLisle <cjd@cjdns.fr>")
        .about("Bandwidth hard proof of work algorithm")
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .arg(
            Arg::with_name("v")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("Verbose logging"),
        )
        .subcommand(
            SubCommand::with_name("ah")
                .about("Run announcement handler")
                .arg(
                    Arg::with_name("config")
                        .short("C")
                        .long("config")
                        .help("Select the config file, default: pool.toml")
                        .default_value("./pool.toml")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("handler")
                        .help("Name of the announcment handler in the config (e.g. ann0)")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("ann")
                .about("Run announcement miner")
                .arg(
                    Arg::with_name("threads")
                        .short("t")
                        .long("threads")
                        .help("Number of threads to mine with")
                        .default_value(&cpus_str)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("uploaders")
                        .short("U")
                        .long("uploaders")
                        .help("Max concurrent uploads (per pool handler)")
                        .default_value("5")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("uploadtimeout")
                        .short("T")
                        .long("uploadtimeout")
                        .help("How long to wait for a reply before aborting an upload")
                        .default_value("30")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("paymentaddr")
                        .short("p")
                        .long("paymentaddr")
                        .help("Address to request payment for mining")
                        .default_value(DEFAULT_ADDR),
                )
                .arg(
                    Arg::with_name("mineold")
                        .short("m")
                        .long("mineold")
                        .help("how many blocks old to mine annoucements, -1 to let the pool decide")
                        .default_value("-1"),
                )
                .arg(
                    Arg::with_name("pools")
                        .help("The pools to mine in")
                        .required(true)
                        .min_values(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("blk")
                .about("Run block miner")
                .arg(
                    Arg::with_name("paymentaddr")
                        .short("p")
                        .long("paymentaddr")
                        .help("Address to request payment for mining")
                        .default_value(DEFAULT_ADDR),
                )
                .arg(
                    Arg::with_name("threads")
                        .short("t")
                        .long("threads")
                        .help("Number of threads to mine with")
                        .default_value(&cpus_str)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("downloaders")
                        .short("d")
                        .long("downloaders")
                        .help("Max concurrent downloads (per handler)")
                        .default_value("30")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("minfree")
                        .short("f")
                        .long("minfree")
                        .help("Minimum fraction of free space to keep in work buffer")
                        .default_value("0.1")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("memorysizemb")
                        .short("m")
                        .long("memorysizemb")
                        .help("Size of memory work buffer in MB")
                        .default_value("4096")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("pool")
                        .help("The pool server to use")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("uploadtimeout")
                        .short("T")
                        .long("uploadtimeout")
                        .help("How long to wait for a reply before aborting an upload")
                        .default_value("30")
                        .takes_value(true),
                ),
        )
        .get_matches();

    util::setup_env(matches.occurrences_of("v")).await?;
    if let Some(ann) = matches.subcommand_matches("ann") {
        // ann miner
        let pools = get_strs!(ann, "pools");
        let payment_addr = get_str!(ann, "paymentaddr");
        let threads = get_usize!(ann, "threads");
        let uploaders = get_usize!(ann, "uploaders");
        let upload_timeout = get_usize!(ann, "uploadtimeout");
        let mine_old_anns = get_num!(ann, "mineold", i32);
        ann_main(
            pools,
            threads,
            payment_addr,
            uploaders,
            upload_timeout,
            mine_old_anns,
        )
        .await?;
    } else if let Some(ah) = matches.subcommand_matches("ah") {
        // ann handler
        let config = get_str!(ah, "config");
        let handler = get_str!(ah, "handler");
        ah_main(config, handler).await?;
    } else if let Some(blk) = matches.subcommand_matches("blk") {
        blk_main(blkmine::BlkArgs {
            max_mem: get_usize!(blk, "memorysizemb") * 1024 * 1024,
            min_free_space: get_num!(blk, "minfree", f64),
            payment_addr: get_str!(blk, "paymentaddr").into(),
            threads: get_usize!(blk, "threads"),
            downloader_count: get_usize!(blk, "downloaders"),
            pool_master: get_str!(blk, "pool").into(),
            upload_timeout: get_usize!(blk, "uploadtimeout"),
        })
        .await?;
    }
    Ok(())
}
