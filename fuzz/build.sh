#!/usr/bin/env bash

set -e

TARGETS="fuzz_tx_parser fuzz_bip32_path"
SCRIPTDIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd)"
BUILDDIR="$SCRIPTDIR/cmake-build-fuzz"

# Compile fuzzer
rm -rf "$BUILDDIR"
mkdir "$BUILDDIR"
cd "$BUILDDIR"

cmake -DCMAKE_C_COMPILER=clang ..
make clean
make $TARGETS