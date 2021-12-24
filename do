#!/bin/sh

if echo "x$@x" | grep -q '\-\-portable' ; then
    cargo build --release --features portable --features jemalloc
else
    RUSTFLAGS='-C target-cpu=native' cargo build --release --features jemalloc
fi