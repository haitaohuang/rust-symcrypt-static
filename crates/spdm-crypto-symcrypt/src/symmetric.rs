use spdmlib::{
    crypto::{SpdmAead, SpdmHkdf, SpdmHmac},
    error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_VERIF_FAIL},
    protocol::*,
};
use symcrypt_core::{aead, hkdf, hmac};
use zeroize::Zeroize;

pub static HMAC: SpdmHmac = SpdmHmac {
    hmac_cb: |algorithm, key, data| {
        let tag = hmac::sign(crate::hash_algorithm(algorithm)?, key, &[data]).ok()?;
        Some(SpdmDigestStruct::from(tag.as_slice()))
    },
    hmac_verify_cb: |algorithm, key, data, tag| {
        let algorithm = crate::hash_algorithm(algorithm).ok_or(SPDM_STATUS_VERIF_FAIL)?;
        let tag = tag
            .data
            .get(..usize::from(tag.data_size))
            .ok_or(SPDM_STATUS_VERIF_FAIL)?;
        hmac::verify(algorithm, key, &[data], tag).map_err(|_| SPDM_STATUS_VERIF_FAIL)
    },
};

pub static HKDF: SpdmHkdf = SpdmHkdf {
    hkdf_extract_cb: extract,
    hkdf_expand_cb: |algorithm, prk, info, length| {
        let algorithm = crate::hash_algorithm(algorithm)?;
        if usize::from(prk.data_size) != algorithm.output_len() {
            return None;
        }
        let prk = prk.data.get(..usize::from(prk.data_size))?;
        let mut output = SpdmHkdfOutputKeyingMaterial::default();
        hkdf::expand(
            algorithm,
            prk,
            info,
            output.data.get_mut(..usize::from(length))?,
        )
        .ok()?;
        output.data_size = length;
        Some(output)
    },
};

fn extract(
    algorithm: SpdmBaseHashAlgo,
    salt: &[u8],
    ikm: &SpdmHkdfInputKeyingMaterial<'_>,
) -> Option<SpdmHkdfPseudoRandomKey> {
    let data = match ikm {
        SpdmHkdfInputKeyingMaterial::SpdmZeroFilled(value) => {
            value.data.get(..usize::from(value.data_size))
        }
        SpdmHkdfInputKeyingMaterial::SpdmSharedSecretFinalKey(value) => {
            value.data.get(..usize::from(value.data_size))
        }
        SpdmHkdfInputKeyingMaterial::SpdmHandshakeSecret(value) => {
            value.data.get(..usize::from(value.data_size))
        }
        SpdmHkdfInputKeyingMaterial::SpdmDirectionHandshakeSecret(value) => {
            value.data.get(..usize::from(value.data_size))
        }
        SpdmHkdfInputKeyingMaterial::SpdmFinishedKey(value) => {
            value.data.get(..usize::from(value.data_size))
        }
        SpdmHkdfInputKeyingMaterial::SpdmDigest(value) => {
            value.data.get(..usize::from(value.data_size))
        }
        SpdmHkdfInputKeyingMaterial::SpdmMasterSecret(value) => {
            value.data.get(..usize::from(value.data_size))
        }
        SpdmHkdfInputKeyingMaterial::SpdmDirectionDataSecret(value) => {
            value.data.get(..usize::from(value.data_size))
        }
    }?;
    let prk = hkdf::extract(crate::hash_algorithm(algorithm)?, salt, data).ok()?;
    Some(SpdmHkdfPseudoRandomKey::from(prk.as_slice()))
}

pub static AEAD: SpdmAead = SpdmAead {
    encrypt_cb: encrypt,
    decrypt_cb: decrypt,
};

fn key_and_nonce<'a>(
    algorithm: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    iv: &'a SpdmAeadIvStruct,
) -> SpdmResult<(aead::Key, &'a [u8; 12])> {
    let algorithm = match algorithm {
        SpdmAeadAlgo::AES_128_GCM => aead::Algorithm::Aes128Gcm,
        SpdmAeadAlgo::AES_256_GCM => aead::Algorithm::Aes256Gcm,
        SpdmAeadAlgo::CHACHA20_POLY1305 => aead::Algorithm::ChaCha20Poly1305,
        _ => return Err(SPDM_STATUS_CRYPTO_ERROR),
    };
    let key = key
        .data
        .get(..usize::from(key.data_size))
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
    let iv = iv
        .data
        .get(..usize::from(iv.data_size))
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
    Ok((
        aead::Key::new(algorithm, key).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?,
        iv.try_into().map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?,
    ))
}

fn encrypt(
    algorithm: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    iv: &SpdmAeadIvStruct,
    aad: &[u8],
    plaintext: &[u8],
    tag: &mut [u8],
    ciphertext: &mut [u8],
) -> SpdmResult<(usize, usize)> {
    let result = (|| {
        let (key, nonce) = key_and_nonce(algorithm, key, iv)?;
        let tag = (&mut *tag)
            .try_into()
            .map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
        key.encrypt(nonce, aad, plaintext, ciphertext, tag)
            .map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
        Ok((plaintext.len(), 16))
    })();
    if result.is_err() {
        tag.zeroize();
        ciphertext.zeroize();
    }
    result
}

fn decrypt(
    algorithm: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    iv: &SpdmAeadIvStruct,
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plaintext: &mut [u8],
) -> SpdmResult<usize> {
    let result = (|| {
        let (key, nonce) = key_and_nonce(algorithm, key, iv)?;
        key.decrypt(
            nonce,
            aad,
            ciphertext,
            plaintext,
            tag.try_into().map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?,
        )
        .map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
        Ok(ciphertext.len())
    })();
    if result.is_err() {
        plaintext.zeroize();
    }
    result
}
