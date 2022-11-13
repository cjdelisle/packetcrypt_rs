#!/bin/sh

git submodule update --init

if echo "x$@x" | grep -q '\-\-portable' ; then
    cargo build --release --features portable --features jemalloc
elif echo "x$@x" | grep -q '\-\-jit' ; then
    RUSTFLAGS='-C target-cpu=native' cargo build --release --features jemalloc --features jit
else
    RUSTFLAGS='-C target-cpu=native' cargo build --release --features jemalloc
fi