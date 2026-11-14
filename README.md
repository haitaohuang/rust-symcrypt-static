# Static SymCrypt for Rust

Experimental `no_std` Rust -> narrow C FFI -> statically linked native
[SymCrypt](https://github.com/microsoft/SymCrypt). This is a new embedding
environment, **not a FIPS-validated module or a production-qualified TD backend**.
It does not modify MigTD's shipping configuration or replace Intel QVL/SGXSSL.

## Components

| Crate | Interfaces |
| --- | --- |
| `symcrypt-static-sys` | Opaque native objects, CMake build, custom allocation/CPU/entropy environment |
| `symcrypt-core` | SHA-256/384/512, resumable hashing, HMAC, native HKDF, AES-GCM, ChaCha20-Poly1305, P256/P384 ECDSA/ECDH, RSA PKCS1/PSS, DER key/signature formats |
| `symcrypt-pki` | Classical ECDSA/RSA `rustls-pki-types` verification algorithms |
| `spdm-crypto-symcrypt` | Classical SPDM callbacks, hash/key checkpoints, raw P384 SPKI, certificate verification |
| `rustls-symcrypt` | TLS 1.3 AES-256-GCM/SHA384/P384 provider, ECDSA/RSA signing and verification |

There is no Ed25519, TLS 1.2, QUIC, HPKE, or PQC provider in this implementation.
TLS retains the ECDSA/RSA certificate compatibility matrix, including omitted
RSA signature parameters. Every FIPS-reporting interface returns `false`.

Native SymCrypt is unmodified and pinned to
`286762b7730e2b780678f5ab11fef2b1bad639e0`. SPDM is pinned to
`ccc-spdm-tools/spdm-rs@2ff535b36d583190efc08d030e648b82ca9b839a`;
rustls is pinned to `0.23.45`.

## Build and use

Supported targets: `x86_64-unknown-linux-gnu` and `x86_64-unknown-none`.
Install Clang/Clang++, CMake, Make, and binutils. The core, PKI, and TLS crates
require Rust 1.85; SPDM and the complete workspace require Rust 1.88 because
of upstream `time` dependencies.

```sh
git clone --recurse-submodules https://github.com/haitaohuang/rust-symcrypt-static
cd rust-symcrypt-static
cargo test --locked --workspace
rustup target add x86_64-unknown-none
bash scripts/check-freestanding.sh
```

The default `std` feature supplies a Linux platform using OS entropy. Disable
default features for firmware, install a `symcrypt_core::platform::Platform`
with `initialize_with_platform`, and do so **before any cryptography or
measurement**. The embedding application owns the allocator, panic/fatal
handlers, and initialized stack-protector guard. See that unsafe initializer's
safety contract; the Linux smoke platform is not suitable for a TD.

Use explicit rustls providers, not ambient defaults:

```rust,ignore
let provider = alloc::sync::Arc::new(rustls_symcrypt::provider()?);
let client = rustls::ClientConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_client_auth_cert(certificates, private_key)?;
```

Existing custom certificate/attestation verifiers and certificate resolvers
remain application responsibilities. The provider does not replace trust,
policy, CRL, EKU, or attestation decisions.

For SPDM, call `spdm_crypto_symcrypt::register(clock)` exactly once, before
**any** SPDM crypto API or session. `clock` returns Unix seconds, or `None` when
trusted time is unavailable. Failure to register is fatal to application
startup; upstream registration is not atomic. Its asymmetric registration
callback can report success for a previously installed provider, so the
first-use precondition is mandatory. Do not recover into a mixed backend.

Do **not** enable upstream `spdmlib/std`: its strong optional webpki feature
propagation selects `ring`. This adapter's `std` feature deliberately enables
only the core host environment.

## Platform and secret-handling contracts

- AES-NI, SSSE3, SSE2 and PCLMULQDQ are required for the complete backend.
  AES/RNG reject CPUs missing that acceleration; there is no table-AES or
  software-GHASH fallback.
- AVX/YMM/ZMM dispatch is masked. The embedding ABI and **every interrupt,
  exception, and context-switch path** must preserve XMM state. Native XMM
  save/restore callbacks are no-ops under that contract.
- Each nonempty random request obtains a fresh 48-byte seed: at least 256
  entropy bits plus a fresh 128-bit nonce. It seeds a short-lived native AES
  CTR-DRBG; the seed and state are wiped afterward. Callbacks must not re-enter
  initialization or unwind across C.
- Public random filling reports failure and wipes output. **Entropy failure
  during native key operations invokes the fatal handler** (`0x726e6766`):
  some upstream arithmetic cannot propagate an RNG callback error. Returning
  failure alone is not safe.
- Native owners stay at stable addresses. Allocations, expanded keys, native
  temporaries and owned private encodings are wiped on release. Rustls mutable
  native owners are synchronized; arbitrary SPDM hash handles never become
  pointers.
- Hash checkpoints use a versioned `SCH1` envelope around a native state blob.
  They are not compatible with ring memory dumps. Their checksum is **not
  authentication**. Protect the enclosing migration/checkpoint data.
- ECDHE checkpoints contain private scalars. Upstream SPDM returns a plain
  `Vec`; the application must protect and wipe it. A native private-key owner
  must never be zeroized by overwriting its Rust object representation.
- Nonce uniqueness belongs to the caller. AEAD authentication failure wipes
  candidate plaintext. RSA-PSS requires digest-sized salt and the same hash
  for MGF1; lax salt or no-OID PKCS1 verification is not provided.

SPDM certificate chains are root-first. Chain validation treats the first
certificate as a candidate anchor; authorizing that root remains a separate
application/SPDM responsibility. Raw-SPKI verification is P384/SHA384 only.
Missing trusted time fails certificate verification rather than bypassing it.

## Validation and remaining gates

```sh
python3 -m pip install -r crates/symcrypt-core/tests/requirements.txt
cargo test --locked --workspace --features symcrypt-core/checked -- --include-ignored
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
python3 scripts/check-dependencies.py
bash scripts/check-freestanding.sh
bash scripts/check-freestanding.sh --features checked
```

Tests cover known answers, malformed keys/signatures, checkpoint lifecycles,
RNG failure, AES fallback rejection, independent OpenSSL primitive/certificate
interoperability, mutually authenticated TLS, record fragmentation, and key
updates. TLS interoperates with Python/OpenSSL in both client and server roles.
CI exercises optimized and checked native builds and the declared minimum
toolchains.

The freestanding executable is a real static `x86_64-unknown-none` final link:
no undefined symbols, dynamic loader, or libc. It executes primitives and
SPDM/TLS adapter operations using explicit Linux syscalls as the test driver.
**It is not a TD execution, full SPDM migration, or no_std TLS handshake test.**
Actual TD CPU/XMM/interrupt/entropy qualification, stack/heap/performance
budgets, firmware integration, checkpoint transition handling, policy
regressions, reproducible measurements, and release/pipeline parity remain
integration gates.

The dependency check examines selected normal target edges and requires an
explicit review when new dependency names appear. Optional `ring`
entries can still appear in Cargo.lock and Cargo's cache because of upstream
SPDM manifests; that does not mean they are selected or linked. Parsing-only
RustCrypto-origin `der`, `pkcs1`, `pkcs8`, and `sec1` crates are intentionally
retained; they do not implement the cryptographic operations. The native
`SYMCRYPT_FIPS_BUILD` setting enables upstream checks, not validation of this
custom module.

## License

This wrapper and native SymCrypt are MIT licensed; retain both license
notices. Other dependencies retain their own licenses. The wrapper can be
combined with BSD-2-Clause-Patent MigTD code; MIT does not add an equivalent
express patent grant or constitute cryptographic-policy approval.
