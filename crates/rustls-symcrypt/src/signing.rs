use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};
use core::fmt;
use rustls::{
    crypto::KeyProvider,
    pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer},
    sign::{Signer, SigningKey},
    Error, SignatureAlgorithm, SignatureScheme,
};
use symcrypt_core::{ecc, encoding, hash::Algorithm, rsa};
use zeroize::Zeroizing;

#[derive(Debug)]
pub(crate) struct Keys;

enum Material {
    Ec(ecc::Key),
    Rsa(rsa::Key),
}

struct Key {
    material: Arc<spin::Mutex<Material>>,
    public: Vec<u8>,
    algorithm: SignatureAlgorithm,
    schemes: &'static [SignatureScheme],
}

struct Signature {
    material: Arc<spin::Mutex<Material>>,
    scheme: SignatureScheme,
}

const RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

impl KeyProvider for Keys {
    fn load_private_key(&self, der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        let der = Zeroizing::new(der);
        let material = match &*der {
            PrivateKeyDer::Pkcs8(bytes) => match ecc::Key::from_pkcs8(bytes.secret_pkcs8_der()) {
                Ok(key) => Material::Ec(key),
                Err(_) => {
                    Material::Rsa(rsa::Key::from_pkcs8(bytes.secret_pkcs8_der()).map_err(error)?)
                }
            },
            PrivateKeyDer::Sec1(bytes) => Material::Ec(
                ecc::Key::from_sec1_der(ecc::Curve::P384, bytes.secret_sec1_der())
                    .or_else(|_| ecc::Key::from_sec1_der(ecc::Curve::P256, bytes.secret_sec1_der()))
                    .map_err(error)?,
            ),
            PrivateKeyDer::Pkcs1(bytes) => Material::Rsa(
                rsa::Key::from_pkcs1_private(bytes.secret_pkcs1_der()).map_err(error)?,
            ),
            _ => return Err(Error::General("Unsupported private key format".into())),
        };
        let (public, algorithm, schemes): (_, _, &'static [SignatureScheme]) = match &material {
            Material::Ec(key) => (
                key.to_spki().map_err(error)?,
                SignatureAlgorithm::ECDSA,
                match key.curve() {
                    ecc::Curve::P256 => &[SignatureScheme::ECDSA_NISTP256_SHA256],
                    ecc::Curve::P384 => &[SignatureScheme::ECDSA_NISTP384_SHA384],
                },
            ),
            Material::Rsa(key) => (
                key.to_spki().map_err(error)?,
                SignatureAlgorithm::RSA,
                RSA_SCHEMES,
            ),
        };
        Ok(Arc::new(Key {
            material: Arc::new(spin::Mutex::new(material)),
            public,
            algorithm,
            schemes,
        }))
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymCryptSigningKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl SigningKey for Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = self
            .schemes
            .iter()
            .find(|scheme| offered.contains(scheme))
            .copied()?;
        Some(Box::new(Signature {
            material: self.material.clone(),
            scheme,
        }))
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.public.as_slice()))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymCryptSigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl Signer for Signature {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        use SignatureScheme as S;
        let (algorithm, padding) = match self.scheme {
            S::ECDSA_NISTP256_SHA256 => (Algorithm::Sha256, rsa::Padding::Pkcs1),
            S::ECDSA_NISTP384_SHA384 => (Algorithm::Sha384, rsa::Padding::Pkcs1),
            S::RSA_PSS_SHA256 => (Algorithm::Sha256, rsa::Padding::Pss),
            S::RSA_PSS_SHA384 => (Algorithm::Sha384, rsa::Padding::Pss),
            S::RSA_PSS_SHA512 => (Algorithm::Sha512, rsa::Padding::Pss),
            S::RSA_PKCS1_SHA256 => (Algorithm::Sha256, rsa::Padding::Pkcs1),
            S::RSA_PKCS1_SHA384 => (Algorithm::Sha384, rsa::Padding::Pkcs1),
            S::RSA_PKCS1_SHA512 => (Algorithm::Sha512, rsa::Padding::Pkcs1),
            _ => return Err(Error::General("Unsupported signature scheme".into())),
        };
        match &mut *self.material.lock() {
            Material::Ec(key) => {
                let signature = key.sign(algorithm, message).map_err(error)?;
                encoding::ecdsa_signature_to_der(key.curve(), &signature).map_err(error)
            }
            Material::Rsa(key) => key.sign(algorithm, padding, message).map_err(error),
        }
    }
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

fn error(error: symcrypt_core::Error) -> Error {
    Error::General(error.to_string())
}
