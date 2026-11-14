use alloc::{vec, vec::Vec};
use core::time::Duration;
use der::{AnyRef, Decode, Reader, SliceReader, Tag, Tagged};
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use spdmlib::{
    crypto::{self, SpdmAsymVerify, SpdmCertOperation},
    error::{
        SpdmResult, SPDM_STATUS_INVALID_CERT, SPDM_STATUS_INVALID_STATE_LOCAL,
        SPDM_STATUS_VERIF_FAIL,
    },
    protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDer, SpdmSignatureStruct},
};
use symcrypt_core::{ecc, encoding};
use symcrypt_pki as pki;
use webpki::{ExtendedKeyUsageValidator, KeyPurposeId, KeyPurposeIdIter};

const RESPONDER: &[u8] = &[0x2b, 6, 1, 4, 1, 0x83, 0x1c, 0x82, 0x12, 3];
const REQUESTER: &[u8] = &[0x2b, 6, 1, 4, 1, 0x83, 0x1c, 0x82, 0x12, 4];

// Preserve the pinned provider's certificate-signature set, distinct from SPDM message signatures.
static CERT_ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] = &[
    &pki::RSA_PKCS1_SHA256,
    &pki::RSA_PKCS1_SHA384,
    &pki::RSA_PKCS1_SHA512,
    &pki::ECDSA_P256_SHA256,
    &pki::ECDSA_P256_SHA384,
    &pki::ECDSA_P384_SHA256,
    &pki::ECDSA_P384_SHA384,
];

pub static CERTIFICATES: SpdmCertOperation = SpdmCertOperation {
    get_cert_from_cert_chain_cb: certificate_range,
    verify_cert_chain_cb: |chain| {
        let clock = (*crate::REGISTRATION.lock()).ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
        verify_chain_at(chain, clock().ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?)
    },
};

fn ranges(chain: &[u8]) -> SpdmResult<Vec<(usize, usize)>> {
    if chain.is_empty() || chain.len() > spdmlib::config::MAX_SPDM_CERT_CHAIN_DATA_SIZE {
        return Err(SPDM_STATUS_INVALID_CERT);
    }
    let parse = || -> der::Result<Vec<(usize, usize)>> {
        let mut reader = SliceReader::new(chain)?;
        let mut ranges = Vec::new();
        while !reader.is_finished() {
            let start = u32::from(reader.position()) as usize;
            let object = AnyRef::decode(&mut reader)?;
            if object.tag() != Tag::Sequence {
                return Err(Tag::Sequence.value_error());
            }
            ranges.push((start, u32::from(reader.position()) as usize));
        }
        Ok(ranges)
    };
    parse().map_err(|_| SPDM_STATUS_INVALID_CERT)
}

pub fn certificate_range(chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {
    let ranges = ranges(chain)?;
    match index {
        -1 => ranges.last(),
        index if index >= 0 => ranges.get(index as usize),
        _ => None,
    }
    .copied()
    .ok_or(SPDM_STATUS_INVALID_CERT)
}

struct ResponderEku;

impl ExtendedKeyUsageValidator for ResponderEku {
    fn validate(&self, purposes: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        let mut requester = false;
        let mut responder = false;
        for purpose in purposes {
            let purpose = purpose?;
            requester |= purpose == KeyPurposeId::new(REQUESTER);
            responder |= purpose == KeyPurposeId::new(RESPONDER);
        }
        if requester && !responder {
            return Err(webpki::Error::RequiredEkuNotFoundContext(
                webpki::RequiredEkuNotFoundContext {
                    required: webpki::KeyUsage::required(RESPONDER),
                    present: vec![REQUESTER.iter().map(|byte| usize::from(*byte)).collect()],
                },
            ));
        }
        Ok(())
    }
}

/// Validates root-first chain consistency. The SPDM application separately authorizes its root.
pub fn verify_chain_at(chain: &[u8], unix_seconds: u64) -> SpdmResult {
    let ranges = ranges(chain)?;
    let certificates: Vec<_> = ranges
        .iter()
        .map(|&(start, end)| CertificateDer::from(&chain[start..end]))
        .collect();
    let root = certificates.first().ok_or(SPDM_STATUS_INVALID_CERT)?;
    let leaf = certificates.last().ok_or(SPDM_STATUS_INVALID_CERT)?;
    let anchor = webpki::anchor_from_trusted_cert(root).map_err(|_| SPDM_STATUS_INVALID_CERT)?;
    let certificate =
        webpki::EndEntityCert::try_from(leaf).map_err(|_| SPDM_STATUS_INVALID_CERT)?;
    let intermediates = if certificates.len() > 2 {
        &certificates[1..certificates.len() - 1]
    } else {
        &[]
    };
    certificate
        .verify_for_usage(
            CERT_ALGORITHMS,
            &[anchor],
            intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(unix_seconds)),
            ResponderEku,
            None,
            None,
        )
        .map_err(|_| SPDM_STATUS_INVALID_CERT)?;
    Ok(())
}

pub static ASYM_VERIFY: SpdmAsymVerify = SpdmAsymVerify { verify_cb: verify };

fn signature_algorithm(
    hash: SpdmBaseHashAlgo,
    algorithm: SpdmBaseAsymAlgo,
) -> Option<(
    &'static dyn SignatureVerificationAlgorithm,
    usize,
    Option<ecc::Curve>,
)> {
    use SpdmBaseAsymAlgo as A;
    use SpdmBaseHashAlgo as H;
    let curve = match algorithm {
        A::TPM_ALG_ECDSA_ECC_NIST_P256 => Some(ecc::Curve::P256),
        A::TPM_ALG_ECDSA_ECC_NIST_P384 => Some(ecc::Curve::P384),
        _ => None,
    };
    if let Some(curve) = curve {
        let verifier: &dyn SignatureVerificationAlgorithm = match (curve, hash) {
            (ecc::Curve::P256, H::TPM_ALG_SHA_256) => &pki::ECDSA_P256_SHA256,
            (ecc::Curve::P256, H::TPM_ALG_SHA_384) => &pki::ECDSA_P256_SHA384,
            (ecc::Curve::P384, H::TPM_ALG_SHA_256) => &pki::ECDSA_P384_SHA256,
            (ecc::Curve::P384, H::TPM_ALG_SHA_384) => &pki::ECDSA_P384_SHA384,
            _ => return None,
        };
        return Some((verifier, 2 * curve.scalar_len(), Some(curve)));
    }
    let (size, pss) = match algorithm {
        A::TPM_ALG_RSASSA_2048 => (256, false),
        A::TPM_ALG_RSASSA_3072 => (384, false),
        A::TPM_ALG_RSASSA_4096 => (512, false),
        A::TPM_ALG_RSAPSS_2048 => (256, true),
        A::TPM_ALG_RSAPSS_3072 => (384, true),
        A::TPM_ALG_RSAPSS_4096 => (512, true),
        _ => return None,
    };
    let verifier: &dyn SignatureVerificationAlgorithm = match (hash, pss) {
        (H::TPM_ALG_SHA_256, false) => &pki::RSA_PKCS1_SHA256,
        (H::TPM_ALG_SHA_384, false) => &pki::RSA_PKCS1_SHA384,
        (H::TPM_ALG_SHA_512, false) => &pki::RSA_PKCS1_SHA512,
        (H::TPM_ALG_SHA_256, true) => &pki::RSA_PSS_SHA256,
        (H::TPM_ALG_SHA_384, true) => &pki::RSA_PSS_SHA384,
        (H::TPM_ALG_SHA_512, true) => &pki::RSA_PSS_SHA512,
        _ => return None,
    };
    Some((verifier, size, None))
}

fn verify(
    hash: SpdmBaseHashAlgo,
    algorithm: SpdmBaseAsymAlgo,
    der: SpdmDer<'_>,
    message: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    let (verifier, size, curve) =
        signature_algorithm(hash, algorithm).ok_or(SPDM_STATUS_VERIF_FAIL)?;
    if usize::from(signature.data_size) != size {
        return Err(SPDM_STATUS_VERIF_FAIL);
    }
    let signature = signature.data.get(..size).ok_or(SPDM_STATUS_VERIF_FAIL)?;
    match der {
        SpdmDer::SpdmDerPubKeyRfc7250(public) => {
            if curve != Some(ecc::Curve::P384) || hash != SpdmBaseHashAlgo::TPM_ALG_SHA_384 {
                return Err(SPDM_STATUS_VERIF_FAIL);
            }
            let mut key = ecc::Key::from_spki(public).map_err(|_| SPDM_STATUS_VERIF_FAIL)?;
            if key.curve() != ecc::Curve::P384 {
                return Err(SPDM_STATUS_VERIF_FAIL);
            }
            key.verify(symcrypt_core::hash::Algorithm::Sha384, message, signature)
                .map_err(|_| SPDM_STATUS_VERIF_FAIL)
        }
        SpdmDer::SpdmDerCertChain(chain) => {
            let (start, end) = certificate_range(chain, -1)?;
            crypto::check_cert_chain_format(chain, algorithm)?;
            let leaf = CertificateDer::from(&chain[start..end]);
            let certificate =
                webpki::EndEntityCert::try_from(&leaf).map_err(|_| SPDM_STATUS_INVALID_CERT)?;
            let encoded;
            let signature = if let Some(curve) = curve {
                encoded = encoding::ecdsa_signature_to_der(curve, signature)
                    .map_err(|_| SPDM_STATUS_VERIF_FAIL)?;
                &encoded
            } else {
                signature
            };
            certificate
                .verify_signature(verifier, message, signature)
                .map_err(|_| SPDM_STATUS_VERIF_FAIL)
        }
    }
}
