#!/bin/sh
cargo build --release
mkdir tmp 2>/dev/null
sudo mount -t tmpfs tmpfs tmp
sudo ./target/release/deis `pwd`/tmp $1
