//! Algorithm-neutral DER encoding. All key validation and cryptography remain native.

use crate::{constant_time_eq, ecc, rsa, Error, Result};
use alloc::{vec, vec::Vec};
use der::{
    asn1::{AnyRef, BitStringRef, ObjectIdentifier, UintRef},
    Decode, Encode, Sequence,
};
use pkcs8::{spki::SubjectPublicKeyInfoRef, AlgorithmIdentifierRef, PrivateKeyInfo};
use zeroize::Zeroizing;

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

impl From<der::Error> for Error {
    fn from(_: der::Error) -> Self {
        Self::InvalidEncoding
    }
}

fn curve_oid(curve: ecc::Curve) -> ObjectIdentifier {
    match curve {
        ecc::Curve::P256 => P256,
        ecc::Curve::P384 => P384,
    }
}

fn parse_curve(algorithm: AlgorithmIdentifierRef<'_>) -> Result<ecc::Curve> {
    if algorithm.oid != EC_PUBLIC_KEY {
        return Err(Error::InvalidKey);
    }
    match algorithm
        .parameters
        .and_then(|value| value.decode_as::<ObjectIdentifier>().ok())
    {
        Some(P256) => Ok(ecc::Curve::P256),
        Some(P384) => Ok(ecc::Curve::P384),
        _ => Err(Error::InvalidKey),
    }
}

fn bounded(input: &[u8], maximum: usize) -> Result<()> {
    if input.len() > maximum {
        Err(Error::InvalidLength)
    } else {
        Ok(())
    }
}

impl ecc::Key {
    pub fn from_pkcs8(input: &[u8]) -> Result<Self> {
        bounded(input, 1024)?;
        let info = PrivateKeyInfo::from_der(input)?;
        let curve = parse_curve(info.algorithm)?;
        let key = Self::from_sec1_der(curve, info.private_key)?;
        if let Some(public) = info.public_key {
            if !constant_time_eq(public, &key.public_key()?) {
                return Err(Error::InvalidKey);
            }
        }
        Ok(key)
    }

    pub fn from_sec1_der(curve: ecc::Curve, input: &[u8]) -> Result<Self> {
        bounded(input, 1024)?;
        let info = sec1::EcPrivateKey::from_der(input)?;
        if info.parameters.is_some_and(|parameters| {
            parameters != sec1::EcParameters::NamedCurve(curve_oid(curve))
        }) {
            return Err(Error::InvalidKey);
        }
        let key = Self::from_private_scalar(curve, info.private_key)?;
        if let Some(public) = info.public_key {
            if !constant_time_eq(public, &key.public_key()?) {
                return Err(Error::InvalidKey);
            }
        }
        Ok(key)
    }

    /// PKCS8 v1, including the inner SEC1 public key. P384 fits MigTD's 185-byte bound.
    pub fn to_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>> {
        let scalar = self.private_scalar()?;
        let public = self.public_key()?;
        let inner = Zeroizing::new(
            sec1::EcPrivateKey {
                private_key: &scalar,
                parameters: None,
                public_key: Some(&public),
            }
            .to_der()?,
        );
        let oid = curve_oid(self.curve());
        let algorithm = AlgorithmIdentifierRef {
            oid: EC_PUBLIC_KEY,
            parameters: Some(AnyRef::from(&oid)),
        };
        Ok(Zeroizing::new(
            PrivateKeyInfo::new(algorithm, &inner).to_der()?,
        ))
    }

    pub fn from_spki(input: &[u8]) -> Result<Self> {
        bounded(input, 1024)?;
        let info = SubjectPublicKeyInfoRef::from_der(input)?;
        Self::from_sec1_public_key(
            parse_curve(info.algorithm)?,
            info.subject_public_key
                .as_bytes()
                .ok_or(Error::InvalidEncoding)?,
        )
    }

    pub fn to_spki(&self) -> Result<Vec<u8>> {
        let public = self.public_key()?;
        let oid = curve_oid(self.curve());
        Ok(SubjectPublicKeyInfoRef {
            algorithm: AlgorithmIdentifierRef {
                oid: EC_PUBLIC_KEY,
                parameters: Some(AnyRef::from(&oid)),
            },
            subject_public_key: BitStringRef::from_bytes(&public)?,
        }
        .to_der()?)
    }
}

#[derive(Sequence)]
struct EcdsaSignature<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

pub fn ecdsa_signature_to_der(curve: ecc::Curve, signature: &[u8]) -> Result<Vec<u8>> {
    let width = curve.scalar_len();
    if signature.len() != 2 * width {
        return Err(Error::InvalidLength);
    }
    Ok(EcdsaSignature {
        r: UintRef::new(&signature[..width])?,
        s: UintRef::new(&signature[width..])?,
    }
    .to_der()?)
}

pub fn ecdsa_signature_from_der(curve: ecc::Curve, signature: &[u8]) -> Result<Vec<u8>> {
    let width = curve.scalar_len();
    bounded(signature, 2 * width + 10)?;
    let parsed = EcdsaSignature::from_der(signature)?;
    let mut output = vec![0; 2 * width];
    for (integer, part) in [parsed.r, parsed.s]
        .iter()
        .zip(output.chunks_exact_mut(width))
    {
        let bytes = integer.as_bytes();
        if bytes.len() > width {
            return Err(Error::InvalidEncoding);
        }
        part[width - bytes.len()..].copy_from_slice(bytes);
    }
    Ok(output)
}

fn check_rsa_algorithm(algorithm: AlgorithmIdentifierRef<'_>) -> Result<()> {
    if algorithm.oid != RSA_ENCRYPTION
        || algorithm
            .parameters
            .is_some_and(|value| value != AnyRef::NULL)
    {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

fn exponent(value: UintRef<'_>) -> Result<u64> {
    let bytes = value.as_bytes();
    if bytes.len() > 8 {
        return Err(Error::InvalidKey);
    }
    let mut buffer = [0; 8];
    buffer[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buffer))
}

impl rsa::Key {
    pub fn from_pkcs1_public(input: &[u8]) -> Result<Self> {
        bounded(input, 2048)?;
        let key = pkcs1::RsaPublicKey::from_der(input)?;
        Self::from_public_components(key.modulus.as_bytes(), exponent(key.public_exponent)?)
    }

    pub fn from_spki(input: &[u8]) -> Result<Self> {
        bounded(input, 2048)?;
        let info = SubjectPublicKeyInfoRef::from_der(input)?;
        check_rsa_algorithm(info.algorithm)?;
        Self::from_pkcs1_public(
            info.subject_public_key
                .as_bytes()
                .ok_or(Error::InvalidEncoding)?,
        )
    }

    pub fn to_pkcs1_public(&self) -> Result<Vec<u8>> {
        let (modulus, exponent) = self.public_components()?;
        Ok(pkcs1::RsaPublicKey {
            modulus: UintRef::new(&modulus)?,
            public_exponent: UintRef::new(&exponent.to_be_bytes())?,
        }
        .to_der()?)
    }

    pub fn to_spki(&self) -> Result<Vec<u8>> {
        let public = self.to_pkcs1_public()?;
        Ok(SubjectPublicKeyInfoRef {
            algorithm: AlgorithmIdentifierRef {
                oid: RSA_ENCRYPTION,
                parameters: Some(AnyRef::NULL),
            },
            subject_public_key: BitStringRef::from_bytes(&public)?,
        }
        .to_der()?)
    }

    pub fn from_pkcs1_private(input: &[u8]) -> Result<Self> {
        bounded(input, 16384)?;
        let parsed = pkcs1::RsaPrivateKey::from_der(input)?;
        if parsed.other_prime_infos.is_some() {
            return Err(Error::InvalidKey);
        }
        let key = Self::from_primes(
            parsed.modulus.as_bytes(),
            exponent(parsed.public_exponent)?,
            parsed.prime1.as_bytes(),
            parsed.prime2.as_bytes(),
        )?;
        let components = key.private_components()?;
        for (supplied, derived) in [
            (parsed.exponent1, &*components.dp),
            (parsed.exponent2, &*components.dq),
            (parsed.coefficient, &*components.coefficient),
        ] {
            if !constant_time_eq(supplied.as_bytes(), UintRef::new(derived)?.as_bytes()) {
                return Err(Error::InvalidKey);
            }
        }
        // Valid private exponents need not use the same representative modulo lambda(n).
        key.check_private_exponent(parsed.private_exponent.as_bytes())?;
        Ok(key)
    }

    pub fn from_pkcs8(input: &[u8]) -> Result<Self> {
        bounded(input, 16384)?;
        let info = PrivateKeyInfo::from_der(input)?;
        check_rsa_algorithm(info.algorithm)?;
        let key = Self::from_pkcs1_private(info.private_key)?;
        if let Some(public) = info.public_key {
            if !constant_time_eq(public, &key.to_pkcs1_public()?) {
                return Err(Error::InvalidKey);
            }
        }
        Ok(key)
    }

    pub fn to_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>> {
        let (modulus, exponent) = self.public_components()?;
        let private = self.private_components()?;
        let inner = Zeroizing::new(
            pkcs1::RsaPrivateKey {
                modulus: UintRef::new(&modulus)?,
                public_exponent: UintRef::new(&exponent.to_be_bytes())?,
                private_exponent: UintRef::new(&private.d)?,
                prime1: UintRef::new(&private.p)?,
                prime2: UintRef::new(&private.q)?,
                exponent1: UintRef::new(&private.dp)?,
                exponent2: UintRef::new(&private.dq)?,
                coefficient: UintRef::new(&private.coefficient)?,
                other_prime_infos: None,
            }
            .to_der()?,
        );
        Ok(Zeroizing::new(
            PrivateKeyInfo::new(
                AlgorithmIdentifierRef {
                    oid: RSA_ENCRYPTION,
                    parameters: Some(AnyRef::NULL),
                },
                &inner,
            )
            .to_der()?,
        ))
    }
}
