#!/bin/bash -eu

# build fuzzers
./build.sh
cp cmake-build-fuzz/fuzz_* $OUT