#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod certificates;
pub mod dhe;
pub mod symmetric;
pub mod transcript;

use spdmlib::{
    crypto,
    error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_INVALID_STATE_LOCAL},
    protocol::SpdmBaseHashAlgo,
};
use symcrypt_core::{hash, platform, random};

pub type TimeSource = fn() -> Option<u64>;
static REGISTRATION: spin::Mutex<Option<TimeSource>> = spin::Mutex::new(None);

fn hash_algorithm(algorithm: SpdmBaseHashAlgo) -> Option<hash::Algorithm> {
    match algorithm {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(hash::Algorithm::Sha256),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(hash::Algorithm::Sha384),
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => Some(hash::Algorithm::Sha512),
        _ => None,
    }
}

/// Call once, before *any* spdmlib cryptographic API or session is used.
///
/// spdmlib lazily installs defaults. A failed registration is not recoverable:
/// the embedding application must not start a session with a mixed provider.
/// `clock` returns Unix seconds, or None when authenticated time is unavailable.
pub fn register(clock: TimeSource) -> SpdmResult {
    platform::ensure_initialized().map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    let mut registration = REGISTRATION.lock();
    if registration.is_some() {
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }
    *registration = Some(clock);
    let success = crypto::hash::register(transcript::HASH.clone())
        & crypto::hmac::register(symmetric::HMAC.clone())
        & crypto::hkdf::register(symmetric::HKDF.clone())
        & crypto::aead::register(symmetric::AEAD.clone())
        & crypto::dhe::register(dhe::DHE.clone())
        & crypto::rand::register(RANDOM.clone())
        & crypto::cert_operation::register(certificates::CERTIFICATES.clone())
        & crypto::asym_verify::register(certificates::ASYM_VERIFY.clone());
    if success {
        Ok(())
    } else {
        Err(SPDM_STATUS_INVALID_STATE_LOCAL)
    }
}

pub static RANDOM: crypto::SpdmCryptoRandom = crypto::SpdmCryptoRandom {
    get_random_cb: |output| {
        random::fill(output).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
        Ok(output.len())
    },
};
