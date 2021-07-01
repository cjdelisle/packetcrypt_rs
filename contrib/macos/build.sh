#!/bin/bash

#
# This script should be run from the project root
# e.g. ./contrib/macos/build.sh
#
fpm --prefix /usr/local -n packetcrypt-mac -s dir -t osxpkg -v "$(./target/release/packetcrypt --version | sed -E 's/packetcrypt //' | tr -d '\n')" ./bin