#!/bin/bash

function build() {
  cd "${GITHUB_WORKSPACE}" || exit
  cargo build --release --features portable --target x86_64-pc-windows-gnu

  mkdir ./bin

  mv ./target/x86_64-pc-windows-gnu/release/packetcrypt.exe ./bin

  zip -r "./${RELEASE_NAME}-win.zip" ./bin
}
build