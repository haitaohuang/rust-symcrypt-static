#!/usr/bin/env python3
"""Check selected dependency edges, not optional/cache-only Cargo.lock entries."""

import subprocess
import sys

PACKAGES = (
    "symcrypt-core", "symcrypt-pki", "spdm-crypto-symcrypt", "rustls-symcrypt"
)
FORBIDDEN = {
    "ring", "aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys", "openssl",
    "openssl-sys", "sha2", "sha3", "hmac", "hkdf", "aes", "aes-gcm",
    "chacha20", "chacha20poly1305", "poly1305", "p256", "p384", "rsa",
    "ecdsa", "ed25519", "ed25519-dalek", "curve25519-dalek", "x25519-dalek",
}
REVIEWED = set("""
    async-trait bit_field bitflags bytes cfg-if codec conquer-once conquer-util
    const-oid der der_derive deranged futures futures-channel futures-core
    futures-io futures-sink futures-task futures-util getrandom libc lock_api log
    maybe-async num-conv once_cell pin-project-lite pkcs1 pkcs8 powerfmt proc-macro2
    quote rustls rustls-pki-types rustls-symcrypt rustls-webpki rustversion scopeguard
    sec1 spdm-crypto-symcrypt spdmlib spin spki subtle symcrypt-core symcrypt-pki
    symcrypt-static-sys syn sys_time time time-core unicode-ident untrusted volatile
    x86_64 zeroize zeroize_derive
""".split())

for target in ("x86_64-unknown-linux-gnu", "x86_64-unknown-none"):
    command = [
        "cargo", "tree", "--locked", "--target", target, "--edges", "normal",
        "--prefix", "none", "--format", "{p}",
    ]
    for package in PACKAGES:
        command.extend(("-p", package))
    if target.endswith("-none"):
        command.extend(("--no-default-features", "--features", "symcrypt-core/encoding"))
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    packages = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
    rejected = sorted(packages & FORBIDDEN)
    if rejected:
        sys.exit(f"{target}: unexpected cryptographic implementations: {', '.join(rejected)}")
    unreviewed = sorted(packages - REVIEWED)
    if unreviewed:
        sys.exit(f"{target}: review new normal dependencies before allowing them: {', '.join(unreviewed)}")
    if "symcrypt-static-sys" not in packages:
        sys.exit(f"{target}: native SymCrypt implementation missing")
    print(f"{target}: selected normal dependencies use the SymCrypt backend")
