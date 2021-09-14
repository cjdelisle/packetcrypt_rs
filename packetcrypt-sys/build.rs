extern crate cc;
use walkdir::WalkDir;

use std::env;
use std::path::PathBuf;

#[cfg(not(feature = "difficulty-test"))]
fn find_crypto(_cfg: &mut cc::Build) {}

#[cfg(feature = "difficulty-test")]
fn find_crypto(cfg: &mut cc::Build) {
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
    cfg.file("packetcrypt/src/DifficultyTest.c");
}

fn main() {
    #[cfg(feature = "generate-bindings")]
    {
        bindgen::Builder::default()
            .header("bindings.h")
            .clang_args(&["-I", "packetcrypt/include"])
            .generate_comments(false)
            .whitelist_function(".*")
            .whitelist_type("ExportMe")
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file("bindings.rs")
            .expect("Couldn't write bindings!");
    }

    let mut cfg = cc::Build::new();

    find_crypto(&mut cfg);

    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut sodium_found = false;
    let search_path = dst.parent().unwrap().parent().unwrap();
    for _ in 0..600 {
        println!("Looking for libsodium in {}", search_path.to_str().unwrap());
        for maybe_entry in WalkDir::new(search_path) {
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
        if sodium_found {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if !sodium_found {
        panic!("Could not find libsodium source code");
    }

    if cfg.is_flag_supported("-fno-plt").unwrap() {
        cfg.use_plt(false);
    }

    if !cfg!(feature = "portable") {
        cfg.flag_if_supported("-march=native");
        cfg.flag_if_supported("-mtune=native");
        println!("cargo:warning=march=native is enabled, this build is non-portable");
    }

    cfg.include("packetcrypt/include")
        .include("packetcrypt/src")
        .flag("-Wno-implicit-function-declaration")
        .file("packetcrypt/src/Validate.c")
        .file("packetcrypt/src/AnnMerkle.c")
        .file("packetcrypt/src/AnnMiner.c")
        .file("packetcrypt/src/Announce.c")
        .file("packetcrypt/src/CryptoCycle.c")
        .file("packetcrypt/src/Hash.c")
        .file("packetcrypt/src/PacketCryptProof.c")
        .file("packetcrypt/src/PcCompress.c")
        .file("packetcrypt/src/RandGen.c")
        .file("packetcrypt/src/RandHash_interpreted.c")
        .file("packetcrypt/src/PTime.c")
        .file("packetcrypt/src/Work.c")
        .file("packetcrypt/src/ProofTree.c")
        .file("packetcrypt/src/BlockMine.c")
        .file("packetcrypt/src/UdpGso.c")
        .out_dir(dst.join("lib"))
        .flag("-O2")
        .compile("libpacketcrypt.a");

    println!("cargo:root={}", dst.display());
    println!("cargo:include={}", dst.join("include").display());
    println!("cargo:rerun-if-changed={}", env::current_dir().unwrap().to_string_lossy());
}
