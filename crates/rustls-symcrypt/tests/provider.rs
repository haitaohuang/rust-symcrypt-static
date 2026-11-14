use rustls::{
    crypto::cipher::{AeadKey, InboundOpaqueMessage, Iv, OutboundChunks, OutboundPlainMessage},
    crypto::tls13::OkmBlock,
    ContentType, Error, PeerMisbehaved, ProtocolVersion,
};
use rustls_symcrypt::{provider, SECP384R1, TLS13_AES_256_GCM_SHA384};
use symcrypt_core::{hash::Algorithm, hkdf};

#[test]
fn transcript_forks_and_native_hkdf_keep_tls_semantics() {
    provider().unwrap();
    let suite = TLS13_AES_256_GCM_SHA384.tls13().unwrap();
    let hash = suite.common.hash_provider;
    let mut transcript = hash.start();
    transcript.update(b"ab");
    let mut fork = transcript.fork();
    assert_eq!(transcript.fork_finish().as_ref(), hash.hash(b"ab").as_ref());
    transcript.update(b"c");
    fork.update(b"d");
    assert_eq!(transcript.finish().as_ref(), hash.hash(b"abc").as_ref());
    assert_eq!(fork.finish().as_ref(), hash.hash(b"abd").as_ref());

    let kdf = suite.hkdf_provider;
    let expander = kdf.extract_from_secret(Some(b"salt"), b"secret");
    let prk = hkdf::extract(Algorithm::Sha384, b"salt", b"secret").unwrap();
    let mut expected = [0; 97];
    hkdf::expand(Algorithm::Sha384, &prk, b"fragmented info", &mut expected).unwrap();
    let mut actual = [0; 97];
    expander
        .expand_slice(&[b"fragmented", b" ", b"info"], &mut actual)
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        kdf.expander_for_okm(&OkmBlock::new(&prk))
            .expand_block(&[b"fragmented info"])
            .as_ref(),
        &expected[..48],
    );
    assert_eq!(
        kdf.extract_from_zero_ikm(None)
            .expand_block(&[b"label"])
            .as_ref(),
        kdf.extract_from_secret(Some(&[0; 48]), &[0; 48])
            .expand_block(&[b"label"])
            .as_ref(),
    );
    let mut oversized = vec![7; 48 * 255 + 1];
    assert!(expander.expand_slice(&[], &mut oversized).is_err());
    assert!(oversized.iter().all(|byte| *byte == 0));
}

#[test]
fn tls_records_bind_sequence_type_and_tag_and_clear_failed_plaintext() {
    provider().unwrap();
    let algorithm = TLS13_AES_256_GCM_SHA384.tls13().unwrap().aead_alg;
    let mut encrypt = algorithm.encrypter(AeadKey::from([1; 32]), Iv::from([2; 12]));
    let mut decrypt = algorithm.decrypter(AeadKey::from([1; 32]), Iv::from([2; 12]));
    let chunks: &[&[u8]] = &[b"unused", b"record", b" payload", b"unused"];
    let message = OutboundPlainMessage {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_3,
        payload: OutboundChunks::Multiple {
            chunks,
            start: 6,
            end: 20,
        },
    };
    let sealed = encrypt.encrypt(message, 0x123456789a).unwrap();
    let ciphertext = sealed.payload.as_ref().to_vec();
    let mut valid = ciphertext.clone();
    let plaintext = decrypt
        .decrypt(
            InboundOpaqueMessage::new(sealed.typ, sealed.version, &mut valid),
            0x123456789a,
        )
        .unwrap();
    assert_eq!(plaintext.typ, ContentType::Handshake);
    assert_eq!(plaintext.version, ProtocolVersion::TLSv1_3);
    assert_eq!(plaintext.payload, b"record payload");

    for failure in 0..4 {
        let mut altered = ciphertext.clone();
        let mut sequence = 0x123456789a;
        let mut typ = sealed.typ;
        match failure {
            0 => sequence += 1,
            1 => altered[0] ^= 1,
            2 => *altered.last_mut().unwrap() ^= 1,
            _ => typ = ContentType::Alert,
        }
        assert!(matches!(
            decrypt.decrypt(
                InboundOpaqueMessage::new(typ, sealed.version, &mut altered,),
                sequence
            ),
            Err(Error::DecryptError)
        ));
        assert!(altered.iter().all(|byte| *byte == 0));
    }
    for length in 0..17 {
        assert!(decrypt
            .decrypt(
                InboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    &mut vec![0; length],
                ),
                0
            )
            .is_err());
    }
}

#[test]
fn p384_key_exchange_rejects_invalid_and_wrong_curve_points() {
    provider().unwrap();
    let left = SECP384R1.start().unwrap();
    let right = SECP384R1.start().unwrap();
    let left_public = left.pub_key().to_vec();
    let right_public = right.pub_key().to_vec();
    assert_eq!(
        left.complete(&right_public).unwrap().secret_bytes(),
        right.complete(&left_public).unwrap().secret_bytes(),
    );
    let wrong_curve = symcrypt_core::ecc::Key::generate(symcrypt_core::ecc::Curve::P256).unwrap();
    for invalid in [
        vec![],
        vec![0; 97],
        vec![4; 97],
        wrong_curve.public_key().unwrap(),
    ] {
        assert!(matches!(
            SECP384R1.start().unwrap().complete(&invalid),
            Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)),
        ));
    }
}
