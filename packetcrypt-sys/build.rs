extern crate cc;
extern crate pkg_config;
use walkdir::WalkDir;

use std::env;
use std::iter::Iterator;
use std::path::PathBuf;

fn main() {
    #[cfg(feature = "generate-bindings")]
    {
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindgen::Builder::default()
            .header("bindings.h")
            .clang_args(&["-I", "packetcrypt/include"])
            .generate_comments(false)
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }

    let mut cfg = cc::Build::new();
    let target = env::var("TARGET").unwrap();

    if target.contains("apple") {
        let mut path = if let Ok(p) = env::var("PKG_CONFIG_PATH") {
            p
        } else {
            String::new()
        };
        for maybe_entry in WalkDir::new("/usr/local/Cellar") {
            let e = if let Ok(e) = maybe_entry {
                e
            } else {
                continue;
            };
            if e.path().ends_with("libcrypto.pc") {
                let dir = e.path().parent().unwrap().to_str().unwrap();
                println!("Found libcrypto.pc in {}", dir);
                if path.len() > 0 {
                    path = format!("{}:{}", path, dir);
                } else {
                    path = String::from(dir);
                }
            }
        }
        println!("PKG_CONFIG_PATH={}", path);
        env::set_var("PKG_CONFIG_PATH", path);
    }

    let libcrypto = pkg_config::Config::new().probe("libcrypto").unwrap();

    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let mut sodium_found = false;
    for maybe_entry in WalkDir::new(dst.parent().unwrap().parent().unwrap()) {
        let e = if let Ok(e) = maybe_entry {
            e
        } else {
            continue;
        };
        if e.path().ends_with("sodium.h") {
            let dir = e.path().parent().unwrap();
            cfg.include(dir);
            println!("Found sodium.h in {}", dir.to_str().unwrap());
            sodium_found = true;
            break;
        }
    }
    if !sodium_found {
        panic!("Could not find libsodium source code");
    }

    libcrypto.include_paths.iter().for_each(|p| {
        cfg.include(p);
    });
    println!(
        "cargo:rustc-flags={}",
        libcrypto
            .link_paths
            .iter()
            .map(|p| { format!(" -L {}", p.to_str().unwrap()) })
            .collect::<String>()
    );

    cfg.include("packetcrypt/include")
        .include("packetcrypt/src")
        .file("packetcrypt/src/Validate.c")
        .file("packetcrypt/src/AnnMerkle.c")
        .file("packetcrypt/src/AnnMiner.c")
        .file("packetcrypt/src/Announce.c")
        .file("packetcrypt/src/CryptoCycle.c")
        .file("packetcrypt/src/Difficulty.c")
        .file("packetcrypt/src/Hash.c")
        .file("packetcrypt/src/PacketCryptProof.c")
        .file("packetcrypt/src/PcCompress.c")
        .file("packetcrypt/src/RandGen.c")
        .file("packetcrypt/src/RandHash_interpreted.c")
        .file("packetcrypt/src/Time.c")
        .file("packetcrypt/src/Work.c")
        .out_dir(dst.join("lib"))
        .compile("libpacketcrypt.a");

    let src = env::current_dir().unwrap().join("packetcrypt");
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}", dst.join("include").display());
    for f in src.join("src").iter() {
        println!("cargo:rerun-if-changed={}", f.to_string_lossy());
    }
    for f in src.join("include").join("packetcrypt").iter() {
        println!("cargo:rerun-if-changed={}", f.to_string_lossy());
    }
}
