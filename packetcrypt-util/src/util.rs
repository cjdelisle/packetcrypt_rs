// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{format_err, Result};
use bytes::buf::BufMut;
use crossbeam_channel::Sender as SenderCB;
use log::{error, info, trace, warn, LevelFilter};
use regex::Regex;
use std::env;
use std::io::Write;
use std::panic;
use std::path::Path;
use std::process;
use std::time::{Duration, SystemTime};
use tokio::fs::{read_dir, File};
use tokio::io::AsyncWriteExt;
use tokio::stream::StreamExt;
use tokio::sync::broadcast::Receiver;

pub fn format_kbps(mut kbps: f64) -> String {
    for letter in "KMGTPEZY".chars() {
        if kbps < 1000.0 {
            return format!("{}{}b/s", ((kbps * 100.0) as u32) as f64 / 100.0, letter);
        }
        kbps /= 1024.0;
    }
    String::from("???")
}

pub async fn sleep_ms(ms: u64) {
    tokio::time::delay_for(Duration::from_millis(ms)).await;
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub async fn get_url_bin2(
    url: &str,
    ignore_statuses: &[u16],
    client: &reqwest::Client,
) -> Result<Option<bytes::Bytes>> {
    loop {
        let res = client.get(url).send().await?;
        return match res.status() {
            reqwest::StatusCode::OK => Ok(Some(res.bytes().await?)),
            reqwest::StatusCode::MULTIPLE_CHOICES => {
                continue;
            }
            st => {
                if ignore_statuses.contains(&st.as_u16()) {
                    Ok(None)
                } else {
                    Err(format_err!("Status code was {:?}", st))
                }
            }
        };
    }
}

pub async fn get_url_bin1(url: &str, ignore_statuses: &[u16]) -> Result<Option<bytes::Bytes>> {
    get_url_bin2(url, ignore_statuses, &reqwest::Client::builder().build()?).await
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
        };
    }
}

pub async fn get_url_text(url: &str) -> Result<String> {
    let res = reqwest::get(url).await?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(res.text().await?),
        st => Err(format_err!("Status code was {:?}", st)),
    }
}

pub async fn tokio_bcast_to_crossbeam<T, S>(
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
                    if let tokio::sync::broadcast::RecvError::Lagged(l) = e {
                        info!("Lost {} messages from full queue", l);
                        continue;
                    }
                    error!("Error receiving {} from tokio: {:?}", n, e);
                    sleep_ms(5000).await;
                    continue;
                }
                Ok(w) => w,
            };
            loop {
                w = match crossbeam_send.try_send(w) {
                    Err(e) => {
                        if let crossbeam_channel::TrySendError::Full(w) = e {
                            // We won't even notify about this, just later when
                            // messages are lost on the tokio side.
                            sleep_ms(100).await;
                            w
                        } else {
                            error!("Error sending {} to crossbeam: {:?}", n, e);
                            sleep_ms(3000).await;
                            e.into_inner()
                        }
                    }
                    Ok(_) => {
                        break;
                    }
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

pub async fn numbered_files(dir: &str, regex: &Regex) -> Result<Vec<(String, usize)>> {
    Ok(read_dir(dir)
        .await?
        .filter_map(|f_or_err| {
            let f = if let Ok(x) = f_or_err {
                x
            } else {
                warn!("Error reading files in dir {}", dir);
                return None;
            };
            let filename = if let Ok(s) = f.file_name().into_string() {
                s
            } else {
                return None;
            };
            let cap = if let Some(c) = regex.captures(&filename) {
                c
            } else {
                return None;
            };
            let fileno = if let Some(c) = cap.get(1) {
                c.as_str()
            } else {
                // This is a problem with the regex
                error!("filename {:?} does not have a 1st capture group", filename);
                return None;
            };
            let file_int = if let Ok(x) = fileno.parse::<usize>() {
                x
            } else {
                warn!("Invalid file {:?}", filename);
                return None;
            };
            Some((filename, file_int))
        })
        .collect()
        .await)
}

pub async fn highest_num_file(dir: &str, regex: &Regex) -> Result<usize> {
    let mut highest: usize = 0;
    for nf in numbered_files(dir, regex).await? {
        highest = if nf.1 > highest { nf.1 } else { highest };
    }
    Ok(highest)
}

pub async fn write_file(
    name: &str,
    tempdir: &str,
    permdir: &str,
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

pub async fn ensure_exists_dir(path: &str) -> Result<()> {
    let p = Path::new(path);
    if !p.is_dir() {
        tokio::fs::create_dir_all(&p).await?;
    }
    Ok(())
}

fn now_sec() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn short_file(file: &str) -> &str {
    file.rsplit('/').next().unwrap_or(file)
}

pub async fn setup_env(verbosity: u64) -> Result<()> {
    // If a thread panics, exit so that the process can be restarted
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        println!("Thread paniced, exiting process");
        process::exit(1);
    }));

    let rl = if let Ok(rl) = env::var("RUST_LOG") {
        rl
    } else {
        String::new()
    };

    let mut log = env_logger::Builder::from_default_env();
    log.format(|buf, record| {
        writeln!(
            buf,
            "{} {} {}:{} {}",
            now_sec(),
            record.level(),
            short_file(record.file().unwrap_or("?")),
            record.line().unwrap_or(0),
            record.args()
        )
    });
    if !rl.contains("tracing") {
        log.filter_module("tracing", LevelFilter::Warn);
    }
    if !rl.contains("hyper") {
        log.filter_module("hyper", LevelFilter::Info);
    }
    if !rl.contains("packetcrypt") {
        log.filter_module(
            "packetcrypt",
            if verbosity > 0 {
                LevelFilter::Debug
            } else {
                LevelFilter::Info
            },
        );
    }
    log.init();

    Ok(())
}

pub fn is_zero(s: &[u8]) -> bool {
    s.iter().all(|x| *x == 0)
}

pub async fn sleep_forever() -> ! {
    loop {
        sleep_ms(100_000_000).await;
    }
}

use rand::rngs::OsRng;
use rand::RngCore;

pub fn rand_u32() -> u32 {
    OsRng.next_u32()
}

pub fn big_number(h: f64) -> String {
    let mut h2 = h;
    for t in ["", "K", "M", "G", "T", "P", "E", "Z", "Y"].iter() {
        if h2 < 10000.0 {
            return format!("{} {}", h2 as u32, t);
        }
        h2 /= 1000.0;
    }
    return format!("{}", h);
}

pub fn pad_to(len: usize, mut x: String) -> String {
    while x.len() < len {
        x += " ";
    }
    x
}
