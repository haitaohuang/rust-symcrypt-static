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
timeout 60s "$binary" --entropy-failure
timeout 60s "$binary" --zero-entropy
if timeout 60s "$binary" --stack-failure; then
    echo "Stack-protector failure unexpectedly returned" >&2
    exit 1
else
    status=$?
    if [[ "$status" -ne 71 ]]; then
        echo "Stack-protector failure did not reach the SymCrypt fatal handler: $status" >&2
        exit 1
    fi
fi
