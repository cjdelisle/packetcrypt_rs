extern crate cc;
extern crate pkg_config;
extern crate bindgen;
use walkdir::WalkDir;

use std::path::PathBuf;
use std::iter::Iterator;
use std::{env, fs};

fn bindgen() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindgen::Builder::default()
        .header("packetcrypt/include/packetcrypt/Validate.h")
        .clang_args(&["-I", "packetcrypt/include"])
        .generate_comments(false)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    bindgen();

    let mut cfg = cc::Build::new();
    let target = env::var("TARGET").unwrap();

    let deps = vec!["openssl.pc", "libsodium.pc"];

    if target.contains("apple") {
        let mut path = if let Ok(p) = env::var("PKG_CONFIG_PATH") { p } else { String::new() };
        for maybe_entry in WalkDir::new("/usr/local/Cellar") {
            let e = if let Ok(e) = maybe_entry { e } else { continue; };
            for d in deps.iter() {
                if e.path().ends_with(d) {
                    let dir = e.path().parent().unwrap().to_str().unwrap();
                    println!("Found {} in {}", d, dir);
                    if path.len() > 0 {
                        path = format!("{}:{}", path, dir);
                    } else {
                        path = String::from(dir);
                    }
                }
            }
        }
        println!("PKG_CONFIG_PATH={}", path);
        env::set_var("PKG_CONFIG_PATH", path);
    }
    // /usr/local/Cellar/

    let openssl = pkg_config::Config::new().probe("openssl").unwrap();
    let libsodium = pkg_config::Config::new().probe("libsodium").unwrap();

    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    openssl.include_paths.iter().for_each(|p| { cfg.include(p); });
    libsodium.include_paths.iter().for_each(|p| { cfg.include(p); });
    cfg.static_flag(true);
    println!("cargo:rustc-flags=-lsodium {}",
        openssl.link_paths.iter().chain(libsodium.link_paths.iter()).map(|p|{
            format!(" -L {}", p.to_str().unwrap())
        }).collect::<String>()
    );

    cfg.include("packetcrypt/include")
        .include("packetcrypt/src")
        .file("packetcrypt/src/Validate.c")
        .file("packetcrypt/src/AnnMerkle.c")
        .file("packetcrypt/src/Announce.c")
        .file("packetcrypt/src/CryptoCycle.c")
        .file("packetcrypt/src/Difficulty.c")
        .file("packetcrypt/src/Hash.c")
        .file("packetcrypt/src/PacketCryptProof.c")
        .file("packetcrypt/src/PcCompress.c")
        .file("packetcrypt/src/RandGen.c")
        .file("packetcrypt/src/RandHash_interpreted.c")
        .file("packetcrypt/src/RandHashOps.c")
        .file("packetcrypt/src/Time.c")
        .file("packetcrypt/src/Work.c")
        .out_dir(dst.join("lib"))
        .compile("libpacketcrypt.a");

    let src = env::current_dir().unwrap().join("packetcrypt");
    let include = dst.join("include");
    fs::create_dir_all(&include).unwrap();
    fs::copy(src.join("include/packetcrypt/Validate.h"), dst.join("include/Validate.h")).unwrap();
    fs::copy(src.join("include/packetcrypt/PacketCrypt.h"), dst.join("include/PacketCrypt.h")).unwrap();
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}", dst.join("include").display());
}