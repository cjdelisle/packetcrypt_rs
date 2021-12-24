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

    let pc = poolclient::new(&cfg.master_url, 6, 5);

    let pmc = paymakerclient::new(
        &pc,
        paymakerclient::PaymakerClientCfg {
            paylogdir: format!("{}/ah/paylogdir", &cfg.root_workdir),
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

async fn sprayer_main(cfg: packetcrypt_sprayer::Config) -> Result<()> {
    packetcrypt_sprayer::Sprayer::new(&cfg)?.start();
    util::sleep_forever().await
}

/// Benchmark hashes per second in block mining.
async fn bench_blk(max_mem: u64, threads: u32) -> Result<()> {
    const REPEAT: u32 = 10;
    const SAMPLING_MS: u64 = 5000;
    let bencher = packetcrypt_blkmine::bench::Bencher::new(REPEAT, SAMPLING_MS);
    tokio::task::spawn_blocking(move || bencher.bench_blk(max_mem, threads))
        .await
        .unwrap()
}

/// Benchmark encryptions per second in ann mining.
async fn bench_ann(threads: usize) -> Result<()> {
    const REPEAT: u32 = 10;
    const SAMPLING_MS: u64 = 5000;
    let bencher = packetcrypt_blkmine::bench::Bencher::new(REPEAT, SAMPLING_MS);
    tokio::task::spawn_blocking(move || bencher.bench_ann(threads))
        .await
        .unwrap()
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

async fn async_main(matches: clap::ArgMatches<'_>) -> Result<()> {
    leak_detect().await?;
    exiter().await?;
    packetcrypt_sys::init();
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
        let spray_cfg = if blk.is_present("subscribe") {
            let passwd: String = get_str!(blk, "handlerpass").into();
            if passwd.is_empty() {
                bail!("When sprayer is enabled, --handlerpass is required");
            }
            let bind: String = get_str!(blk, "bind").into();
            if bind.is_empty() {
                bail!("When sprayer is enabled, --bind is required");
            }
            let subscribe_to = get_strs!(blk, "subscribe");
            let workers = get_usize!(blk, "sprayerthreads");
            let mss = get_usize!(blk, "mss");
            let mcast = if blk.is_present("mcast") {
                get_str!(blk, "mcast")
            } else {
                ""
            }
            .to_owned();
            Some(packetcrypt_sprayer::Config {
                passwd,
                bind,
                workers,
                subscribe_to,
                log_peer_stats: false,
                mss,
                spray_at: Vec::new(),
                mcast,
            })
        } else {
            if blk.is_present("bind") {
                bail!("--bind (bind UDP sprayer socket) is nonsensical without --subscribe");
            }
            None
        };
        blk_main(blkmine::BlkArgs {
            max_mem: get_usize!(blk, "memorysizemb") * 1024 * 1024,
            min_free_space: get_num!(blk, "minfree", f64),
            payment_addr: get_str!(blk, "paymentaddr").into(),
            threads: get_usize!(blk, "threads"),
            downloader_count: get_usize!(blk, "downloaders"),
            pool_master: get_str!(blk, "pool").into(),
            upload_timeout: get_usize!(blk, "uploadtimeout"),
            uploaders: get_usize!(blk, "uploaders"),
            handler_pass: get_str!(blk, "handlerpass").into(),
            spray_cfg,
        })
        .await?;
    } else if let Some(spray) = matches.subcommand_matches("sprayer") {
        let spray_at = if spray.is_present("sprayat") {
            get_strs!(spray, "sprayat")
        } else {
            Vec::new()
        };
        sprayer_main(packetcrypt_sprayer::Config {
            passwd: get_str!(spray, "passwd").into(),
            bind: get_str!(spray, "bind").into(),
            workers: get_usize!(spray, "threads"),
            subscribe_to: get_strs!(spray, "subscribe"),
            log_peer_stats: true,
            mss: get_usize!(spray, "mss"),
            spray_at,
            mcast: "".to_owned(),
        })
        .await?;
    } else if let Some(bench) = matches.subcommand_matches("bench") {
        if let Some(blk) = bench.subcommand_matches("blk") {
            let max_mem = get_num!(blk, "memorysizemb", u64) * 1024 * 1024;
            let threads = get_num!(blk, "threads", u32);
            bench_blk(max_mem, threads).await?;
        } else if let Some(ann) = bench.subcommand_matches("ann") {
            let threads = get_num!(ann, "threads", usize);
            bench_ann(threads).await?;
        }
    }
    Ok(())
}

fn version() -> &'static str {
    let out = git_version::git_version!(
        args = ["--tags", "--dirty=-dirty", "--broken"],
        fallback = "out-of-tree"
    );
    if let Some(v) = out.strip_prefix("packetcrypt-v") {
        &v
    } else {
        &out
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cpus_str = format!("{}", num_cpus::get());
    let matches = App::new("packetcrypt")
        .version(version())
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
                        .default_value("10")
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
                )
                .arg(
                    Arg::with_name("handlerpass")
                        .short("P")
                        .long("handlerpass")
                        .help("Password to use for pulling anns from the handlers")
                        .default_value("")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("subscribe")
                        .short("s")
                        .long("subscribe")
                        .help("Sprayer interface to subscribe to")
                        .takes_value(true)
                        .min_values(1),
                )
                .arg(
                    Arg::with_name("sprayerthreads")
                        .short("S")
                        .long("sprayerthreads")
                        .help("Number of threads to run in the sprayer interface")
                        .default_value("4")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("bind")
                        .short("b")
                        .long("bind")
                        .help("UDP socket to bind to for sprayer interface")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("uploaders")
                        .short("u")
                        .long("uploaders")
                        .help("Number of share-upload threads, be careful not to overload the block handlers")
                        .default_value("4")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("mss")
                        .short("M")
                        .long("maxsegmentsize")
                        .help("Maximum packet size to send when using UDP sprayer, remember IP and UDP overhead")
                        .default_value("1472")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("mcast")
                    .long("mcast")
                    .help("Connect to this multicast group")
                    .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("sprayer")
                .about("Launch ann sprayer daemon")
                .arg(
                    Arg::with_name("threads")
                        .short("t")
                        .long("threads")
                        .help("Number of sprayer threads to run")
                        .default_value("4")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("bind")
                        .short("b")
                        .long("bind")
                        .help("Address to bind to")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("passwd")
                        .short("P")
                        .long("passwd")
                        .help("Password to use for authing with other sprayers")
                        .default_value("")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("subscribe")
                        .short("s")
                        .long("subscribe")
                        .help("Sprayers so subscribe to")
                        .required(true)
                        .min_values(1),
                )
                .arg(
                    Arg::with_name("sprayat")
                        .short("S")
                        .long("sprayat")
                        .help("Always spray at these addresses")
                        .min_values(1),
                )
                .arg(
                    Arg::with_name("mss")
                        .short("M")
                        .long("maxsegmentsize")
                        .help("Maximum packet size to send, remember IP and UDP overhead")
                        .default_value("1472")
                        .takes_value(true)
                ),
        )
        .subcommand(
            SubCommand::with_name("bench")
                .about("Benchmark the performance of mining operations")
                .setting(clap::AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("blk")
                    .about("Benchmark the hashes per second of a block mining")
                    .arg(
                        Arg::with_name("memorysizemb")
                            .short("m")
                            .long("memorysizemb")
                            .help("Size of memory work buffer in MB")
                            .default_value("4096")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::with_name("threads")
                            .short("t")
                            .long("threads")
                            .help("Number of threads to mine with")
                            .default_value(&cpus_str)
                            .takes_value(true),
                    )
                )
                .subcommand(
                    SubCommand::with_name("ann")
                    .about("Benchmark the encryptions per second of an announcement mining")
                    .arg(
                        Arg::with_name("threads")
                            .short("t")
                            .long("threads")
                            .help("Number of threads to mine with")
                            .default_value(&cpus_str)
                            .takes_value(true),
                    )
                )
        )
        .get_matches();

    async_main(matches).await
}
