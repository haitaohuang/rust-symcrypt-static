#![no_std]
#![forbid(unsafe_code)]

use rustls_pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};
use symcrypt_core::{ecc, encoding, hash, rsa};

#[derive(Debug)]
enum Kind {
    Ecdsa(ecc::Curve, hash::Algorithm),
    Rsa(hash::Algorithm, rsa::Padding, usize),
}

#[derive(Debug)]
pub struct Algorithm {
    kind: Kind,
    public_key_id: AlgorithmIdentifier,
    signature_id: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for Algorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let verify = || -> symcrypt_core::Result<()> {
            match self.kind {
                Kind::Ecdsa(curve, hash) => {
                    let mut key = ecc::Key::from_sec1_public_key(curve, public_key)?;
                    key.verify(
                        hash,
                        message,
                        &encoding::ecdsa_signature_from_der(curve, signature)?,
                    )
                }
                Kind::Rsa(hash, padding, minimum_bits) => {
                    let mut key = rsa::Key::from_pkcs1_public(public_key)?;
                    let (modulus, _) = key.public_components()?;
                    if modulus.len() * 8 - (modulus[0].leading_zeros() as usize) < minimum_bits {
                        return Err(symcrypt_core::Error::InvalidKey);
                    }
                    key.verify(hash, padding, message, signature)
                }
            }
        };
        verify().map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_id
    }

    fn fips(&self) -> bool {
        false
    }
}

macro_rules! ecdsa_algorithm {
    ($name:ident, $curve:ident, $hash:ident, $public_id:ident, $signature_id:ident) => {
        pub static $name: Algorithm = Algorithm {
            kind: Kind::Ecdsa(ecc::Curve::$curve, hash::Algorithm::$hash),
            public_key_id: alg_id::$public_id,
            signature_id: alg_id::$signature_id,
        };
    };
}

macro_rules! rsa_algorithm {
    ($name:ident, $hash:ident, $padding:ident, $minimum:expr, $signature_id:ident) => {
        pub static $name: Algorithm = Algorithm {
            kind: Kind::Rsa(hash::Algorithm::$hash, rsa::Padding::$padding, $minimum),
            public_key_id: alg_id::RSA_ENCRYPTION,
            signature_id: alg_id::$signature_id,
        };
    };
}

ecdsa_algorithm!(ECDSA_P256_SHA256, P256, Sha256, ECDSA_P256, ECDSA_SHA256);
ecdsa_algorithm!(ECDSA_P256_SHA384, P256, Sha384, ECDSA_P256, ECDSA_SHA384);
ecdsa_algorithm!(ECDSA_P384_SHA256, P384, Sha256, ECDSA_P384, ECDSA_SHA256);
ecdsa_algorithm!(ECDSA_P384_SHA384, P384, Sha384, ECDSA_P384, ECDSA_SHA384);
rsa_algorithm!(RSA_PKCS1_SHA256, Sha256, Pkcs1, 2048, RSA_PKCS1_SHA256);
rsa_algorithm!(RSA_PKCS1_SHA384, Sha384, Pkcs1, 2048, RSA_PKCS1_SHA384);
rsa_algorithm!(RSA_PKCS1_SHA512, Sha512, Pkcs1, 2048, RSA_PKCS1_SHA512);
rsa_algorithm!(RSA_PKCS1_3072_SHA384, Sha384, Pkcs1, 3072, RSA_PKCS1_SHA384);
rsa_algorithm!(RSA_PSS_SHA256, Sha256, Pss, 2048, RSA_PSS_SHA256);
rsa_algorithm!(RSA_PSS_SHA384, Sha384, Pss, 2048, RSA_PSS_SHA384);
rsa_algorithm!(RSA_PSS_SHA512, Sha512, Pss, 2048, RSA_PSS_SHA512);

pub static RSA_PKCS1_SHA256_ABSENT_PARAMS: Algorithm = Algorithm {
    kind: Kind::Rsa(hash::Algorithm::Sha256, rsa::Padding::Pkcs1, 2048),
    public_key_id: alg_id::RSA_ENCRYPTION,
    signature_id: AlgorithmIdentifier::from_slice(&[6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11]),
};
pub static RSA_PKCS1_SHA384_ABSENT_PARAMS: Algorithm = Algorithm {
    kind: Kind::Rsa(hash::Algorithm::Sha384, rsa::Padding::Pkcs1, 2048),
    public_key_id: alg_id::RSA_ENCRYPTION,
    signature_id: AlgorithmIdentifier::from_slice(&[6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 12]),
};
pub static RSA_PKCS1_SHA512_ABSENT_PARAMS: Algorithm = Algorithm {
    kind: Kind::Rsa(hash::Algorithm::Sha512, rsa::Padding::Pkcs1, 2048),
    public_key_id: alg_id::RSA_ENCRYPTION,
    signature_id: AlgorithmIdentifier::from_slice(&[6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 13]),
};

/// Classical schemes supported by this backend. This deliberately excludes Ed25519.
pub static ALL_ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] = &[
    &ECDSA_P256_SHA256,
    &ECDSA_P256_SHA384,
    &ECDSA_P384_SHA256,
    &ECDSA_P384_SHA384,
    &RSA_PKCS1_SHA256,
    &RSA_PKCS1_SHA384,
    &RSA_PKCS1_SHA512,
    &RSA_PKCS1_SHA256_ABSENT_PARAMS,
    &RSA_PKCS1_SHA384_ABSENT_PARAMS,
    &RSA_PKCS1_SHA512_ABSENT_PARAMS,
    &RSA_PSS_SHA256,
    &RSA_PSS_SHA384,
    &RSA_PSS_SHA512,
];
