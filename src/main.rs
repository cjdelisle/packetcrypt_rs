// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{bail, Context, Result};
use clap::{App, Arg, SubCommand};
use log::warn;
use packetcrypt_annhandler::annhandler;
use packetcrypt_annmine::annmine;
use packetcrypt_blkmine::blkmine;
use packetcrypt_pool::{paymakerclient, poolcfg};
use packetcrypt_util::{poolclient, util};
use std::path;
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

fn warn_if_addr_default(payment_addr: &str) -> &str {
    if payment_addr == DEFAULT_ADDR {
        warn!(
            "--paymentaddr was not specified, coins will be mined for {}",
            DEFAULT_ADDR
        );
    }

    payment_addr
}

async fn blk_main(ba: blkmine::BlkArgs) -> Result<()> {
    warn_if_addr_default(&ba.payment_addr);
    let bm = blkmine::new(ba).await?;
    bm.start().await?;
    util::sleep_forever().await
}

async fn ann_load_config(
    pools: Vec<String>,
    threads: usize,
    payment_addr: String,
    uploaders: usize,
    upload_timeout: usize,
    mine_old_anns: i32,
    config_json_path: String
) -> Result<annmine::AnnMineExternalConfig> {
    let defaults = CliParamDefault { ..Default::default() };

    let mut config = annmine::AnnMineExternalConfig {
        pools: Some(pools.clone()),
        threads: Some(threads),
        payment_addr: Some(payment_addr.clone()),
        uploaders: Some(uploaders),
        upload_timeout: Some(upload_timeout),
        mine_old_anns: Some(mine_old_anns),
    };

    if !config_json_path.is_empty() {
        //let cfg: annmine::AnnMineExternalConfig;
        let json: String;

        if config_json_path.contains("http://") || config_json_path.contains("https://") {
            let res = reqwest::get(&config_json_path).await?;
            match res.status() {
                reqwest::StatusCode::OK => {
                    json = res.text().await.ok().expect("Could not read response body");
                },
                st => (panic!("Failed to load config.json. Status code was {:?}", st)),
            };  
        } else {    
            let file = path::Path::new(config_json_path.as_str());
            json = tokio::fs::read_to_string(file).await.ok().expect("Could not read file");
        }

        match serde_json::from_str::<annmine::AnnMineExternalConfig>(json.as_str()){
            Result::Ok(parsed) => {

                if pools.len() == 0 {
                    if let Some(p) = parsed.pools {
                        config.pools = Some(p);
                    }
                }
                if threads == defaults.ann_threads {
                    if let Some(t) = parsed.threads {
                        config.threads = Some(t);
                    }
                }
                if payment_addr == defaults.ann_payment_addr {
                    if let Some(a) = parsed.payment_addr {
                        config.payment_addr = Some(a);
                    } 
                }
                if uploaders == defaults.ann_uploaders {
                    if let Some(u) = parsed.uploaders {
                        config.uploaders = Some(u);
                    }
                }
                if upload_timeout == defaults.ann_upload_timeout {
                    if let Some(ut) = parsed.upload_timeout {
                        config.upload_timeout = Some(ut);
                    } 
                }
                if mine_old_anns == defaults.ann_mine_old {
                    if let Some(m) = parsed.mine_old_anns {
                        config.mine_old_anns = Some(m);
                    }
                }
            },
            Result::Err(err) => {panic!("Unable to parse config.json {}", err)}
        };
    }

    config.print();

    Ok(config)
}

async fn ann_main(
    config: annmine::AnnMineExternalConfig
) -> Result<()> {  
    let am = annmine::new(annmine::AnnMineCfg {
        pools: config.pools.unwrap(),
        miner_id: util::rand_u32(),
        workers: config.threads.unwrap(),
        uploaders: config.uploaders.unwrap(),
        pay_to: config.payment_addr.unwrap(),
        upload_timeout: config.upload_timeout.unwrap(),
        mine_old_anns: config.mine_old_anns.unwrap(),
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
        let pools = if ann.is_present("pools") {
            get_strs!(ann, "pools")
        } else {
            Vec::new()
        }.to_owned();
        let payment_addr = get_str!(ann, "paymentaddr");
        let threads = get_usize!(ann, "threads");
        let uploaders = get_usize!(ann, "uploaders");
        let upload_timeout = get_usize!(ann, "uploadtimeout");
        let mine_old_anns = get_num!(ann, "mineold", i32);
        let config_json_path = if ann.is_present("config") {
            get_str!(ann, "config")
        } else {
            ""
        }.to_owned();

        let mut config = ann_load_config(
            pools,
            threads, 
            payment_addr.to_string(), 
            uploaders, 
            upload_timeout, 
            mine_old_anns, 
            config_json_path
        ).await?;

        // TODO: There has to be a better way to avoid moving `config.payment_addr`
        // when calling `warn_if_addr_default` here...
        config.payment_addr = Some(warn_if_addr_default(&config.payment_addr.unwrap()).to_string());

        ann_main(config)
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

struct CliParamDefault {
    ann_threads: usize,
    ann_uploaders: usize,
    ann_payment_addr: String,
    ann_upload_timeout: usize,
    ann_mine_old: i32,
}
impl Default for CliParamDefault {
    fn default() -> CliParamDefault {
        CliParamDefault {
            ann_threads: num_cpus::get(),
            ann_uploaders: 10,
            ann_payment_addr: String::from(DEFAULT_ADDR),
            ann_upload_timeout: 30,
            ann_mine_old: -1
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let defaults = CliParamDefault { ..Default::default() };
    let cpus_str = defaults.ann_threads.to_string();  //format!("{}", num_cpus::get());
    let ann_uploaders = defaults.ann_uploaders.to_string();
    let ann_upload_timeout = defaults.ann_upload_timeout.to_string();
    let ann_payment_addr = defaults.ann_payment_addr.to_string();
    let ann_mine_old = defaults.ann_mine_old.to_string();

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
                        .default_value(&ann_uploaders)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("uploadtimeout")
                        .short("T")
                        .long("uploadtimeout")
                        .help("How long to wait for a reply before aborting an upload")
                        .default_value(&ann_upload_timeout)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("paymentaddr")
                        .short("p")
                        .long("paymentaddr")
                        .help("Address to request payment for mining")
                        .default_value(&ann_payment_addr),
                )
                .arg(
                    Arg::with_name("mineold")
                        .short("m")
                        .long("mineold")
                        .help("how many blocks old to mine annoucements, -1 to let the pool decide")
                        .default_value(&ann_mine_old),
                )
                .arg(
                    Arg::with_name("pools")
                        .help("The pools to mine in")
                        .required_unless("config")
                        .min_values(1),
                )
                .arg(
                    Arg::with_name("config")
                        .short("c")
                        .long("config")
                        .help("Path to config.json")
                        .takes_value(true),
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
