use codec::{Codec, Reader, Writer};
use spdm_crypto_symcrypt::{
    certificates,
    dhe::DHE,
    symmetric::{AEAD, HKDF, HMAC},
    transcript::HASH,
};
use spdmlib::{crypto, protocol::*};
use symcrypt_core::{ecc, hash::Algorithm};

#[test]
fn transcript_handles_are_bounded_and_checkpoints_are_independent() {
    for (algorithm, native) in [
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, Algorithm::Sha256),
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, Algorithm::Sha384),
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, Algorithm::Sha512),
    ] {
        let handle = (HASH.hash_ctx_init_cb)(algorithm).unwrap();
        (HASH.hash_ctx_update_cb)(handle, b"a").unwrap();
        let duplicate = (HASH.hash_ctx_dup_cb)(handle).unwrap();
        let checkpoint = (HASH.hash_ctx_serialize_cb)(handle).unwrap();
        let restored = (HASH.hash_ctx_deserialize_cb)(&checkpoint).unwrap();
        for context in [handle, restored] {
            (HASH.hash_ctx_update_cb)(context, b"bc").unwrap();
            assert_eq!(
                (HASH.hash_ctx_finalize_cb)(context).unwrap().as_ref(),
                native.digest(b"abc").unwrap()
            );
            assert!((HASH.hash_ctx_update_cb)(context, b"invalid").is_err());
            assert!((HASH.hash_ctx_finalize_cb)(context).is_none());
            assert!((HASH.hash_ctx_dup_cb)(context).is_none());
        }
        (HASH.hash_ctx_update_cb)(duplicate, b"d").unwrap();
        assert_eq!(
            (HASH.hash_ctx_finalize_cb)(duplicate).unwrap().as_ref(),
            native.digest(b"ad").unwrap()
        );
        assert!((HASH.hash_ctx_deserialize_cb)(&checkpoint[..checkpoint.len() - 1]).is_none());
    }
    for handle in [0, usize::MAX] {
        assert!((HASH.hash_ctx_update_cb)(handle, b"data").is_err());
        assert!((HASH.hash_ctx_finalize_cb)(handle).is_none());
        assert!((HASH.hash_ctx_serialize_cb)(handle).is_none());
    }
}

#[test]
fn registration_and_actual_spdm_codec_lifecycle() {
    spdm_crypto_symcrypt::register(|| None).unwrap();
    assert!(spdm_crypto_symcrypt::register(|| None).is_err());
    let algorithm = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    let context = crypto::hash::hash_ctx_init(algorithm).unwrap();
    crypto::hash::hash_ctx_update(&context, b"checkpoint").unwrap();
    let mut buffer = [0; 512];
    let mut writer = Writer::init(&mut buffer);
    let length = context.encode(&mut writer).unwrap();
    let restored = crypto::SpdmHashCtx::read(&mut Reader::init(&buffer[..length])).unwrap();
    let fork = context.clone();
    drop(context);
    crypto::hash::hash_ctx_update(&restored, b" restored").unwrap();
    assert_eq!(
        crypto::hash::hash_ctx_finalize(restored).unwrap().as_ref(),
        Algorithm::Sha384.digest(b"checkpoint restored").unwrap()
    );
    assert_eq!(
        crypto::hash::hash_ctx_finalize(fork).unwrap().as_ref(),
        Algorithm::Sha384.digest(b"checkpoint").unwrap()
    );
    assert!(crypto::cert_operation::verify_cert_chain(&[0x30, 0]).is_err());
}

#[test]
fn dhe_round_trip_preserves_resumable_ephemeral_keys() {
    for algorithm in [SpdmDheAlgo::SECP_256_R1, SpdmDheAlgo::SECP_384_R1] {
        let (alice_public, alice) = (DHE.generate_key_pair_cb)(algorithm).unwrap();
        let saved = zeroize::Zeroizing::new(alice.export_private_key().unwrap());
        let imported = (DHE.import_private_key_cb.unwrap())(algorithm, &saved).unwrap();
        let (bob_public, bob) = (DHE.generate_key_pair_cb)(algorithm).unwrap();
        let expected = bob.compute_final_key(&alice_public).unwrap();
        assert_eq!(alice.compute_final_key(&bob_public).unwrap(), expected);
        assert_eq!(imported.compute_final_key(&bob_public).unwrap(), expected);
        assert!((DHE.import_private_key_cb.unwrap())(algorithm, &[0; 1]).is_none());
        let (_, key) = (DHE.generate_key_pair_cb)(algorithm).unwrap();
        let mut invalid = bob_public;
        invalid.data_size = u16::MAX;
        assert!(key.compute_final_key(&invalid).is_none());
    }
}

#[test]
fn kdf_mac_and_aead_enforce_spdm_bounds_and_fail_closed() {
    let algorithm = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    let key = SpdmSharedSecretFinalKeyStruct::from(b"input".as_slice());
    let ikm = SpdmHkdfInputKeyingMaterial::SpdmSharedSecretFinalKey(&key);
    let mut prk = (HKDF.hkdf_extract_cb)(algorithm, b"salt", &ikm).unwrap();
    assert_eq!(
        prk.as_ref(),
        &*symcrypt_core::hkdf::extract(Algorithm::Sha384, b"salt", b"input").unwrap()
    );
    (HKDF.hkdf_expand_cb)(algorithm, &prk, b"info", 0).unwrap();
    (HKDF.hkdf_expand_cb)(algorithm, &prk, b"info", SPDM_MAX_HKDF_OKM_SIZE as u16).unwrap();
    assert!((HKDF.hkdf_expand_cb)(algorithm, &prk, b"info", u16::MAX).is_none());
    prk.data_size -= 1;
    assert!((HKDF.hkdf_expand_cb)(algorithm, &prk, b"info", 32).is_none());
    let mut tag = (HMAC.hmac_cb)(algorithm, b"key", b"data").unwrap();
    (HMAC.hmac_verify_cb)(algorithm, b"key", b"data", &tag).unwrap();
    tag.data_size = u16::MAX;
    assert!((HMAC.hmac_verify_cb)(algorithm, b"key", b"data", &tag).is_err());
    for (algorithm, width) in [
        (SpdmAeadAlgo::AES_128_GCM, 16),
        (SpdmAeadAlgo::AES_256_GCM, 32),
        (SpdmAeadAlgo::CHACHA20_POLY1305, 32),
    ] {
        let mut key = SpdmAeadKeyStruct::from(vec![0; width].as_slice());
        let iv = SpdmAeadIvStruct::from([0; 12].as_slice());
        let mut tag = [0; 16];
        let mut ciphertext = [0; 7];
        (AEAD.encrypt_cb)(
            algorithm,
            &key,
            &iv,
            b"aad",
            b"message",
            &mut tag,
            &mut ciphertext,
        )
        .unwrap();
        let mut plaintext = [0xff; 7];
        (AEAD.decrypt_cb)(
            algorithm,
            &key,
            &iv,
            b"aad",
            &ciphertext,
            &tag,
            &mut plaintext,
        )
        .unwrap();
        assert_eq!(&plaintext, b"message");
        tag[0] ^= 1;
        assert!((AEAD.decrypt_cb)(
            algorithm,
            &key,
            &iv,
            b"aad",
            &ciphertext,
            &tag,
            &mut plaintext
        )
        .is_err());
        assert_eq!(plaintext, [0; 7]);
        key.data_size = u16::MAX;
        plaintext.fill(0xff);
        assert!((AEAD.decrypt_cb)(
            algorithm,
            &key,
            &iv,
            b"aad",
            &ciphertext,
            &tag,
            &mut plaintext
        )
        .is_err());
        assert_eq!(plaintext, [0; 7]);
    }
}

#[test]
fn raw_spki_identity_verification_requires_the_negotiated_curve() {
    let mut key = ecc::Key::generate(ecc::Curve::P384).unwrap();
    let mut signature = SpdmSignatureStruct {
        data_size: 96,
        ..Default::default()
    };
    signature.data[..96].copy_from_slice(&key.sign(Algorithm::Sha384, b"message").unwrap());
    let public = key.to_spki().unwrap();
    let verify = |public: &[u8], message: &[u8], signature: &SpdmSignatureStruct| {
        (certificates::ASYM_VERIFY.verify_cb)(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            SpdmDer::SpdmDerPubKeyRfc7250(public),
            message,
            signature,
        )
    };
    verify(&public, b"message", &signature).unwrap();
    assert!(verify(&public, b"changed", &signature).is_err());
    let wrong_curve = ecc::Key::generate(ecc::Curve::P256)
        .unwrap()
        .to_spki()
        .unwrap();
    assert!(verify(&wrong_curve, b"message", &signature).is_err());
    let mut malformed = public;
    malformed.push(0);
    assert!(verify(&malformed, b"message", &signature).is_err());
    signature.data_size = u16::MAX;
    assert!(verify(&malformed, b"message", &signature).is_err());
}
