#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod cipher;
mod hashing;
mod key_exchange;
mod signing;

pub use cipher::TLS13_AES_256_GCM_SHA384;
pub use key_exchange::SECP384R1;

use alloc::vec;
use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom, WebPkiSupportedAlgorithms};
use rustls::SignatureScheme;
use symcrypt_core::{aead, random};
use symcrypt_pki as pki;

/// Initializes the host backend (or checks the installed no_std platform) before TLS use.
pub fn provider() -> symcrypt_core::Result<CryptoProvider> {
    // Require the accelerated AES backend before constructing infallible rustls primitives.
    aead::Key::new(aead::Algorithm::Aes256Gcm, &[0; 32])?;
    Ok(CryptoProvider {
        cipher_suites: vec![TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![SECP384R1],
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &Random,
        key_provider: &signing::Keys,
    })
}

#[derive(Debug)]
struct Random;

impl SecureRandom for Random {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        random::fill(output).map_err(|_| GetRandomFailed)
    }
}

pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: pki::ALL_ALGORITHMS,
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[&pki::ECDSA_P384_SHA384, &pki::ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[&pki::ECDSA_P256_SHA256, &pki::ECDSA_P384_SHA256],
        ),
        (SignatureScheme::RSA_PSS_SHA512, &[&pki::RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[&pki::RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[&pki::RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[&pki::RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[&pki::RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[&pki::RSA_PKCS1_SHA256]),
    ],
};
