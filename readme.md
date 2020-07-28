# packetcrypt_rs
PacketCrypt implementation in Rust

## What exists
PacketCrypt mining is made up of 6 distinct components:
* Master - provides work and 
* Announcement Miner - generates data
* Announcement Handler - consumes data, checks validity and sends to block miner
* Block Miner - consumes data and uses it for mining blocks
* Block Handler - takes mining shares from block miner and validates them
* Paymaker - takes messages from Block Handler and Announcement Handler to
decide which miners the pool should pay

As of now, this codebase only provides the *Announcement Handler* component.
All of the others should be found in
[the original PacketCrypt project](https://github.com/cjdelisle/PacketCrypt).

## How to use

* Compile
* Copy `pool.example.toml` to `pool.toml`
* Edit to match the config for your pool
* run `./target/debug/packetcrypt ann0` to launch the ann handler called ann0 in the config
* set env var: `RUST_LOG=packetcrypt=debug` for better logging
* set env var: `RUST_BACKTRACE=1` for backtraces on errors (including non-critical ones)

## License

LGPL-2.1 or LGPL-3.0, at your option