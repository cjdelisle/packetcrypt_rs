// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use std::panic;
use std::process;
use std::path::Path;
use std::time::{Duration, SystemTime};
use anyhow::Result;
use tokio::sync::broadcast::Receiver;
use crossbeam_channel::Sender as SenderCB;
use bytes::buf::BufMut;
use tokio::fs::{File,read_dir};
use regex::Regex;
use tokio::stream::StreamExt;
use tokio::io::AsyncWriteExt;
use log::LevelFilter;

pub async fn sleep_ms(ms: u64) {
    tokio::time::delay_for(Duration::from_millis(ms)).await;
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64
}

pub async fn get_url_bin(url: &str) -> Result<bytes::Bytes> {
    loop {
        let res = reqwest::get(url).await?;
        return match res.status() {
            reqwest::StatusCode::OK => Ok(res.bytes().await?),
            reqwest::StatusCode::MULTIPLE_CHOICES => {
                continue;
            }
            st => Err(format_err!("Status code was {:?}", st)),
        }
    }
}

pub async fn get_url_text(url: &str) -> Result<String> {
    let res = reqwest::get(url).await?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(res.text().await?),
        st => Err(format_err!("Status code was {:?}", st)),
    }
}

#[macro_export]
macro_rules! async_spawn {
    ($arc:ident, $blk:block) => {
        {
            let $arc = Arc::clone($arc);
            tokio::spawn(async move { $blk });
        }
    }
}

pub async fn tokio_bcast_to_crossbeam<T,S>(
    name: S,
    mut tokio_recv: Receiver<T>,
    crossbeam_send: SenderCB<T>,
) where
    T: 'static + Clone + Send,
    S: Into<String>,
{
    let n: String = name.into();
    tokio::spawn(async move {
        loop {
            let mut w = match tokio_recv.recv().await {
                Err(e) => {
                    error!("Error receiving {} from tokio: {:?}", n, e);
                    sleep_ms(5000).await;
                    continue;
                }
                Ok(w) => { w }
            };
            loop {
                w = match crossbeam_send.try_send(w) {
                    Err(e) => {
                        error!("Error sending {} to crossbeam: {:?}", n, e);
                        sleep_ms(3000).await;
                        e.into_inner()
                    }
                    Ok(_) => { break; }
                }
            }
        }
    });
}

pub fn aligned_bytes(from: &[u8], alignment: usize) -> bytes::Bytes {
    let mut b = bytes::BytesMut::with_capacity(from.len() + alignment);
    let mut p = b.as_ptr() as usize;
    let mut i = 0;
    while p % alignment != 0 {
        p += 1;
        b.put_u8(0);
        i += 1;
    }
    b.put(from);
    b.freeze().slice(i..)
}

pub async fn numbered_files(dir: &String, regex: &Regex) -> Result<Vec<(String,usize)>> {
    Ok(read_dir(dir).await?.filter_map(|f_or_err| {
        let f = if let Ok(x) = f_or_err { x } else {
            warn!("Error reading files in dir {}", dir);
            return None;
        };
        let filename = if let Ok(s) = f.file_name().into_string() { s } else { return None; };
        let cap = if let Some(c) = regex.captures(&filename) { c } else { return None; };
        let fileno = if let Some(c) = cap.get(1) { c.as_str() } else {
            // This is a problem with the regex
            error!("filename {:?} does not have a 1st capture group", filename);
            return None;
        };
        let file_int = if let Ok(x) = fileno.parse::<usize>() { x } else {
            warn!("Invalid file {:?}", filename);
            return None;
        };
        Some((filename, file_int))
    }).collect().await)
}

pub async fn highest_num_file(dir: &String, regex: &Regex) -> Result<usize> {
    let mut highest: usize = 0;
    for nf in numbered_files(dir, regex).await? {
        highest = if nf.1 > highest { nf.1 } else { highest };
    }
    Ok(highest)
}

pub async fn write_file(
    name: &String,
    tempdir: &String,
    permdir: &String,
    content: impl Iterator<Item = &bytes::Bytes>,
) -> Result<()> {
    trace!("write_file({})", name);
    let temp = format!("{}/{}", tempdir, name);
    let perm = format!("{}/{}", permdir, name);
    let mut f = File::create(&temp).await?;
    for c in content {
        f.write_all(&c).await?;
    }
    f.shutdown().await?;
    tokio::fs::rename(temp, perm).await?;
    trace!("write_file({}) done", name);
    Ok(())
}

pub async fn ensure_exists_dir(path: &String) -> Result<()> {
    let p = Path::new(path);
    if !p.is_dir() {
        tokio::fs::create_dir_all(&p).await?;
    }
    Ok(())
}

pub async fn setup_env() -> Result<()> {
    // If a thread panics, exit so that the process can be restarted
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        println!("Thread paniced, exiting process");
        process::exit(1);
    }));

    // Filter out some ultra spammy logs
    env_logger::Builder::from_default_env()
        .filter_module("tracing", LevelFilter::Warn)
        .filter_module("hyper", LevelFilter::Info)
        .init();

    Ok(())
}