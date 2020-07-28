// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
// #![deny(warnings)]
#[macro_use]
mod util;
mod annhandler;
mod hash;
mod paymakerclient;
mod poolcfg;
mod poolclient;
mod protocol;

#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    util::setup_env().await?;

    let confb = tokio::fs::read("./pool.toml").await?;
    let mut cfg: poolcfg::Config = toml::de::from_slice(&confb[..])?;
    let args: Vec<String> = env::args().collect();
    let arg = if let Some(x) = args.get(1) {
        x
    } else {
        bail!("Usage: miner <instance name>    # run instance, defined in pool.toml");
    };
    let hconf = if let Some(x) = cfg.ann_handler.remove(arg) {
        x
    } else {
        bail!("{} is not defined in the pool.toml", arg);
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
    loop {
        util::sleep_ms(100_000_000).await;
    }
}
