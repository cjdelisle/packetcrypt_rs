#!/bin/bash

#
# This script should be run from the project root
# e.g. ./contrib/deb/build.sh
#
set -e
fpm -n packetcrypt-linux -s dir -t deb -v "$(./target/release/packetcrypt --version | sed -E 's/packetcrypt //' | tr -d '\n')" ./bin