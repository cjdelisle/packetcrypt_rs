#!/bin/bash

function build() {
  cd "${GITHUB_WORKSPACE}" || exit
  cargo build --release --features jemalloc --target=x86_64-unknown-linux-musl

  mkdir "${GITHUB_WORKSPACE}/bin"

  cp "${GITHUB_WORKSPACE}/target/x86_64-unknown-linux-musl/release/packetcrypt" \
    "${GITHUB_WORKSPACE}"'/'"${RELEASE_NAME}"
}
build
