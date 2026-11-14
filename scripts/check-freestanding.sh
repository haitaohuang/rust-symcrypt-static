#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
cd "$(dirname "$0")/.."
cargo rustc --locked -p freestanding-smoke --target x86_64-unknown-none --release "$@" -- \
    -C relocation-model=static -C link-arg=-no-pie
binary=target/x86_64-unknown-none/release/freestanding-smoke
if [[ -n "$(nm -u "$binary")" ]]; then
    echo "Unexpected unresolved symbols in the final executable" >&2
    exit 1
fi
if readelf -l "$binary" | grep -Eq 'INTERP|DYNAMIC'; then
    echo "Unexpected dynamic loader or runtime dependency" >&2
    exit 1
fi
timeout 60s "$binary"
