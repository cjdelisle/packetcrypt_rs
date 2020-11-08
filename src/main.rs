// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
// #![deny(warnings)]
#[macro_use]
mod util;
mod annhandler;
mod annmine;
mod annminer;
mod hash;
mod paymakerclient;
mod poolcfg;
mod poolclient;
mod protocol;
use anyhow::{bail, Context, Result};
use clap::{App, Arg, SubCommand};
use log::warn;
use tokio::signal::unix::{signal, SignalKind};

#[cfg(not(feature = "leak_detect"))]
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
            if let Err(e) = al.write_mem_allocations(&outfile).await {
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

async fn exiter() -> Result<()> {
    let mut s = signal(SignalKind::user_defined2())?;
    tokio::spawn(async move {
        s.recv().await;
        println!("Got SIGUSR2, calling process::exit()");
        std::process::exit(252);
    });
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

    let pc = poolclient::new(&cfg.master_url);
    poolclient::start(&pc).await;

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

    let ah = annhandler::new(&pc, &pmc, ah_workdir, hconf).await?;
    annhandler::start(&ah).await;

    // All of the threads and jobs are setup, put the main thread to sleep
    util::sleep_forever().await
}

const DEFAULT_ADDR: &str = "pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2";

async fn ann_main(
    pool_master: &str,
    threads: usize,
    payment_addr: &str,
    uploads: usize,
    upload_timeout: usize,
) -> Result<()> {
    if payment_addr == DEFAULT_ADDR {
        warn!(
            "--paymentaddr was not specified, coins will be mined for {}",
            DEFAULT_ADDR
        );
    }
    let pc = poolclient::new(pool_master);
    poolclient::start(&pc).await;
    let am = annmine::new(
        &pc,
        annmine::AnnMineCfg {
            miner_id: util::rand_u32(),
            workers: threads,
            uploaders: uploads,
            pay_to: String::from(payment_addr),
            upload_timeout,
        },
    )
    .await?;
    annmine::start(&am).await?;

    util::sleep_forever().await
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
    ($m:ident, $s:expr) => {{
        let s = get_str!($m, $s);
        if let Ok(u) = s.parse::<usize>() {
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
        .version("0.1.1")
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
                    Arg::with_name("uploads")
                        .short("u")
                        .long("uploads")
                        .help("Max concurrent uploads")
                        .default_value("20")
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
                    Arg::with_name("pool")
                        .help("The pool server to use")
                        .required(true)
                        .index(1),
                ),
        )
        .get_matches();

    util::setup_env(matches.occurrences_of("v")).await?;
    if let Some(ann) = matches.subcommand_matches("ann") {
        // ann miner
        let pool_master = get_str!(ann, "pool");
        let payment_addr = get_str!(ann, "paymentaddr");
        let threads = get_usize!(ann, "threads");
        let uploads = get_usize!(ann, "uploads");
        let upload_timeout = get_usize!(ann, "uploadtimeout");
        ann_main(pool_master, threads, payment_addr, uploads, upload_timeout).await?;
    } else if let Some(ah) = matches.subcommand_matches("ah") {
        // ann handler
        let config = get_str!(ah, "config");
        let handler = get_str!(ah, "handler");
        ah_main(config, handler).await?;
    }
    Ok(())
}
