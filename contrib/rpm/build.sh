#!/bin/bash

#
# This script should be run from the project root
# e.g. ./contrib/rpm/build.sh
#
if which fpm; then
	if which rpmbuild; then
		fpm -n packetcrypt-linux -s dir -t rpm -v "$(./target/release/packetcrypt --version | sed -E 's/packetcrypt //' | tr -d '\n')" ./bin
		echo "RPM file built."
	else
		echo "rpmbuild not installed or not reachable"
		exit 1
	fi
else
	echo "fpm not installed or not reachable"
	exit 1
fi
