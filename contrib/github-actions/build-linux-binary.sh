#!/bin/bash

function build() {
  cd "${GITHUB_WORKSPACE}" || exit
  PC_CC=clang cargo build --release --features portable --target=x86_64-unknown-linux-musl

  mkdir "${GITHUB_WORKSPACE}/bin"

  cp "${GITHUB_WORKSPACE}/target/x86_64-unknown-linux-musl/release/packetcrypt" \
    "${GITHUB_WORKSPACE}"'/'"${RELEASE_NAME}"
}
build
