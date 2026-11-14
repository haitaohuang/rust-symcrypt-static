use symcrypt_core::{
    aead, ecc,
    hash::{Algorithm, Context},
    hkdf, hmac, random, rsa, Error,
};

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn sha_vectors_and_checkpoints() {
    let vectors = [
        (Algorithm::Sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (Algorithm::Sha384, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
        (Algorithm::Sha512, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    ];
    for (algorithm, expected) in vectors {
        assert_eq!(algorithm.digest(b"abc").unwrap(), hex(expected));
        let mut context = Context::new(algorithm).unwrap();
        context.update(b"a");
        let mut duplicate = context.try_clone().unwrap();
        let mut restored = Context::import(&context.export()).unwrap();
        context.update(b"bc");
        duplicate.update(b"d");
        restored.update(b"bc");
        assert_eq!(context.finish(), hex(expected));
        assert_eq!(restored.finish(), hex(expected));
        assert_eq!(duplicate.finish(), algorithm.digest(b"ad").unwrap());
    }
}

#[test]
fn checkpoint_rejects_invalid_formats() {
    let context = Context::new(Algorithm::Sha384).unwrap();
    let blob = context.export();
    assert!(Context::import(&blob[..blob.len() - 1]).is_err());
    let mut invalid = blob.clone();
    invalid[0] = b'R';
    assert!(Context::import(&invalid).is_err());
    let mut invalid = blob;
    invalid[20] ^= 1;
    assert!(Context::import(&invalid).is_err());
}

#[test]
fn platform_random_produces_independent_output() {
    let mut first = [0u8; 64];
    let mut second = [0u8; 64];
    random::fill(&mut first).unwrap();
    random::fill(&mut second).unwrap();
    assert_ne!(first, second);
    assert_ne!(first, [0; 64]);
}

#[test]
fn hmac_rfc4231_and_fragmented_input() {
    let vectors = [
        (Algorithm::Sha256, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (Algorithm::Sha384, "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),
        (Algorithm::Sha512, "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
    ];
    for (algorithm, expected) in vectors {
        let key = [0x0b; 20];
        let input: &[&[u8]] = &[b"Hi", b"", b" There"];
        let tag = hmac::sign(algorithm, &key, input).unwrap();
        assert_eq!(&*tag, &hex(expected));
        hmac::verify(algorithm, &key, &[b"Hi There"], &tag).unwrap();
        let mut bad = tag.to_vec();
        bad[0] ^= 1;
        assert_eq!(
            hmac::verify(algorithm, &key, input, &bad),
            Err(Error::VerificationFailed)
        );
        assert!(hmac::verify(algorithm, &key, input, &tag[..tag.len() - 1]).is_err());
    }
}

#[test]
fn hkdf_rfc5869_and_output_bounds() {
    let prk = hkdf::extract(
        Algorithm::Sha256,
        &hex("000102030405060708090a0b0c"),
        &[0x0b; 22],
    )
    .unwrap();
    assert_eq!(
        &*prk,
        &hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    );
    let mut output = [0; 42];
    hkdf::expand(
        Algorithm::Sha256,
        &prk,
        &hex("f0f1f2f3f4f5f6f7f8f9"),
        &mut output,
    )
    .unwrap();
    assert_eq!(
        output.as_slice(),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
    for algorithm in [Algorithm::Sha256, Algorithm::Sha384, Algorithm::Sha512] {
        let prk = hkdf::extract(algorithm, b"", b"input").unwrap();
        let mut maximum = vec![0; 255 * algorithm.output_len()];
        hkdf::expand(algorithm, &prk, b"", &mut maximum).unwrap();
        let first_block = hmac::sign(algorithm, &prk, &[&[1]]).unwrap();
        assert_eq!(&maximum[..first_block.len()], &*first_block);
        hkdf::expand(algorithm, &prk, b"", &mut []).unwrap();
        let mut too_long = vec![0xff; maximum.len() + 1];
        assert_eq!(
            hkdf::expand(algorithm, &prk, b"", &mut too_long),
            Err(Error::InvalidLength)
        );
        assert!(too_long.iter().all(|byte| *byte == 0));
        let mut output = [0xff; 16];
        assert_eq!(
            hkdf::expand(algorithm, &prk[..prk.len() - 1], b"", &mut output),
            Err(Error::InvalidLength)
        );
        assert_eq!(output, [0; 16]);
    }
}

#[test]
fn aead_known_answers() {
    for (algorithm, ciphertext, expected_tag) in [
        (
            aead::Algorithm::Aes128Gcm,
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        ),
        (
            aead::Algorithm::Aes256Gcm,
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        ),
    ] {
        let key = aead::Key::new(algorithm, &vec![0; algorithm.key_len()]).unwrap();
        let mut output = [0; 16];
        let mut tag = [0; 16];
        key.encrypt(&[0; 12], b"", &[0; 16], &mut output, &mut tag)
            .unwrap();
        assert_eq!(output.as_slice(), hex(ciphertext));
        assert_eq!(tag.as_slice(), hex(expected_tag));
    }
    let key = aead::Key::new(aead::Algorithm::ChaCha20Poly1305, &[0; 32]).unwrap();
    let tag = key.seal_in_place(&[0; 12], b"", &mut []).unwrap();
    assert_eq!(tag.as_slice(), hex("4eb972c9a8fb3a1b382bb4d36f5ffad1"));
}

#[test]
fn aead_round_trips_and_wipes_unauthenticated_plaintext() {
    for algorithm in [
        aead::Algorithm::Aes128Gcm,
        aead::Algorithm::Aes256Gcm,
        aead::Algorithm::ChaCha20Poly1305,
    ] {
        let key = aead::Key::new(algorithm, &vec![7; algorithm.key_len()]).unwrap();
        let plaintext = b"a non-block-aligned SPDM payload";
        let aad = b"authenticated header";
        let nonce = [3; 12];
        let mut ciphertext = vec![0; plaintext.len()];
        let mut tag = [0; 16];
        key.encrypt(&nonce, aad, plaintext, &mut ciphertext, &mut tag)
            .unwrap();
        let mut output = vec![0xff; plaintext.len()];
        key.decrypt(&nonce, aad, &ciphertext, &mut output, &tag)
            .unwrap();
        assert_eq!(output, plaintext);
        for changed in 0..3 {
            let mut bad_tag = tag;
            let mut bad_ciphertext = ciphertext.clone();
            let bad_aad = if changed == 0 {
                b"wrong".as_slice()
            } else {
                aad
            };
            if changed == 1 {
                bad_tag[0] ^= 1;
            }
            if changed == 2 {
                bad_ciphertext[0] ^= 1;
            }
            output.fill(0xff);
            assert!(key
                .decrypt(&nonce, bad_aad, &bad_ciphertext, &mut output, &bad_tag)
                .is_err());
            assert!(output.iter().all(|byte| *byte == 0));
            assert!(key
                .open_in_place(&nonce, bad_aad, &mut bad_ciphertext, &bad_tag)
                .is_err());
            assert!(bad_ciphertext.iter().all(|byte| *byte == 0));
        }
        let mut in_place = plaintext.to_vec();
        let tag = key.seal_in_place(&[4; 12], aad, &mut in_place).unwrap();
        key.open_in_place(&[4; 12], aad, &mut in_place, &tag)
            .unwrap();
        assert_eq!(in_place, plaintext);
        let mut short = [0xff; 2];
        let mut tag = [0xff; 16];
        assert_eq!(
            key.encrypt(&nonce, aad, plaintext, &mut short, &mut tag),
            Err(Error::InvalidLength)
        );
        assert_eq!(short, [0; 2]);
        assert_eq!(tag, [0; 16]);
        assert!(aead::Key::new(algorithm, &[]).is_err());
    }
}

#[test]
fn ecc_sign_verify_export_import_and_agreement() {
    for (curve, algorithm) in [
        (ecc::Curve::P256, Algorithm::Sha256),
        (ecc::Curve::P384, Algorithm::Sha384),
    ] {
        let mut alice = ecc::Key::generate(curve).unwrap();
        let alice_public = alice.public_key().unwrap();
        let alice_scalar = alice.private_scalar().unwrap();
        let imported = ecc::Key::from_private_scalar(curve, &alice_scalar).unwrap();
        assert_eq!(imported.public_key().unwrap(), alice_public);
        let mut verifier = ecc::Key::from_sec1_public_key(curve, &alice_public).unwrap();
        let signature = alice.sign(algorithm, b"message").unwrap();
        verifier.verify(algorithm, b"message", &signature).unwrap();
        verifier
            .verify_digest(&algorithm.digest(b"message").unwrap(), &signature)
            .unwrap();
        assert!(verifier.verify(algorithm, b"changed", &signature).is_err());
        let mut bad = signature;
        bad[0] ^= 1;
        assert!(verifier.verify(algorithm, b"message", &bad).is_err());
        assert!(verifier.private_scalar().is_err());
        assert!(verifier.sign(algorithm, b"message").is_err());
        let bob = ecc::Key::generate(curve).unwrap();
        let bob_public = bob.public_key().unwrap();
        let expected = bob.agree(&alice_public).unwrap();
        assert_eq!(&*alice.agree(&bob_public).unwrap(), &*expected);
        assert_eq!(&*imported.agree(&bob_public).unwrap(), &*expected);
    }
}

#[test]
fn ecc_rejects_noncanonical_scalars_and_invalid_points() {
    for (curve, order) in [
        (ecc::Curve::P256, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        (ecc::Curve::P384, "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
    ] {
        let width = curve.scalar_len();
        for scalar in [vec![0; width], vec![0xff; width], hex(order), vec![1; width - 1]] {
            assert!(ecc::Key::from_private_scalar(curve, &scalar).is_err());
        }

        let mut scalar = vec![0; width];
        scalar[width - 1] = 1;
        let key = ecc::Key::from_private_scalar(curve, &scalar).unwrap();
        assert_eq!(&*key.private_scalar().unwrap(), &scalar);
        let mut point = key.public_key().unwrap();
        assert!(ecc::Key::from_sec1_public_key(curve, &point[1..]).is_err());
        point[0] = 2;
        assert!(ecc::Key::from_sec1_public_key(curve, &point).is_err());
        point.fill(0);
        point[0] = 4;
        assert!(ecc::Key::from_sec1_public_key(curve, &point).is_err());
    }
}

#[test]
fn rsa_padding_hash_matrix_and_private_import() {
    let mut key = rsa::Key::generate(2048).unwrap();
    let (modulus, exponent) = key.public_components().unwrap();
    let mut public = rsa::Key::from_public_components(&modulus, exponent).unwrap();
    let components = key.private_components().unwrap();
    let mut imported =
        rsa::Key::from_primes(&modulus, exponent, &components.p, &components.q).unwrap();
    for algorithm in [Algorithm::Sha256, Algorithm::Sha384, Algorithm::Sha512] {
        for padding in [rsa::Padding::Pkcs1, rsa::Padding::Pss] {
            let signature = key.sign(algorithm, padding, b"message").unwrap();
            public
                .verify(algorithm, padding, b"message", &signature)
                .unwrap();
            public
                .verify_digest(
                    algorithm,
                    padding,
                    &algorithm.digest(b"message").unwrap(),
                    &signature,
                )
                .unwrap();
            assert!(public
                .verify(algorithm, padding, b"changed", &signature)
                .is_err());
            let other_padding = if padding == rsa::Padding::Pkcs1 {
                rsa::Padding::Pss
            } else {
                rsa::Padding::Pkcs1
            };
            assert!(public
                .verify(algorithm, other_padding, b"message", &signature)
                .is_err());
            assert!(public
                .verify(algorithm, padding, b"message", &signature[1..])
                .is_err());
            let signature = imported.sign(algorithm, padding, b"message").unwrap();
            public
                .verify(algorithm, padding, b"message", &signature)
                .unwrap();
        }
    }
    assert!(public
        .sign(Algorithm::Sha384, rsa::Padding::Pss, b"message")
        .is_err());
    assert!(rsa::Key::from_public_components(&modulus[1..], exponent).is_err());
    assert!(rsa::Key::from_public_components(&modulus, 2).is_err());
    assert!(rsa::Key::generate(1024).is_err());
}
