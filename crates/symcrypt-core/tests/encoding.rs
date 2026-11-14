#![cfg(feature = "encoding")]

use der::{asn1::UintRef, Decode, Encode};
use symcrypt_core::{ecc, encoding, hash::Algorithm, rsa};

#[test]
fn ec_pkcs8_spki_and_signature_round_trips() {
    for (curve, hash) in [
        (ecc::Curve::P256, Algorithm::Sha256),
        (ecc::Curve::P384, Algorithm::Sha384),
    ] {
        let mut key = ecc::Key::generate(curve).unwrap();
        let encoded = key.to_pkcs8().unwrap();
        assert!(encoded.len() <= 185);
        let restored = ecc::Key::from_pkcs8(&encoded).unwrap();
        assert_eq!(restored.public_key().unwrap(), key.public_key().unwrap());
        let spki = key.to_spki().unwrap();
        let mut public = ecc::Key::from_spki(&spki).unwrap();
        let signature = key.sign(hash, b"message").unwrap();
        let der = encoding::ecdsa_signature_to_der(curve, &signature).unwrap();
        let fixed = encoding::ecdsa_signature_from_der(curve, &der).unwrap();
        assert_eq!(signature, fixed);
        public.verify(hash, b"message", &fixed).unwrap();
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(ecc::Key::from_pkcs8(&trailing).is_err());
        assert!(ecc::Key::from_spki(&spki[..spki.len() - 1]).is_err());

        let mut info = pkcs8::PrivateKeyInfo::from_der(&encoded).unwrap();
        let mut inner = sec1::EcPrivateKey::from_der(info.private_key).unwrap();
        let mut wrong_public = key.public_key().unwrap();
        wrong_public[1] ^= 1;
        inner.public_key = Some(&wrong_public);
        let bad_inner = inner.to_der().unwrap();
        info.private_key = &bad_inner;
        assert!(ecc::Key::from_pkcs8(&info.to_der().unwrap()).is_err());
        let mut info = pkcs8::PrivateKeyInfo::from_der(&encoded).unwrap();
        info.public_key = Some(&wrong_public);
        assert!(ecc::Key::from_pkcs8(&info.to_der().unwrap()).is_err());
    }
}

#[test]
fn signature_der_is_canonical_and_bounded() {
    let curve = ecc::Curve::P256;
    let mut fixed = [0; 64];
    fixed[0] = 0x80;
    fixed[63] = 1;
    let der = encoding::ecdsa_signature_to_der(curve, &fixed).unwrap();
    assert_eq!(
        encoding::ecdsa_signature_from_der(curve, &der).unwrap(),
        fixed
    );
    for invalid in [
        vec![0x30, 6, 2, 1, 0x80, 2, 1, 1],
        vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1],
        vec![0x30, 0x80, 2, 1, 1, 2, 1, 1, 0, 0],
        [der.as_slice(), &[0]].concat(),
        der[..der.len() - 1].to_vec(),
    ] {
        assert!(encoding::ecdsa_signature_from_der(curve, &invalid).is_err());
    }
}

#[test]
fn rsa_encoded_keys_round_trip_and_reject_inconsistent_components() {
    let mut key = rsa::Key::generate(2048).unwrap();
    let encoded = key.to_pkcs8().unwrap();
    let mut restored = rsa::Key::from_pkcs8(&encoded).unwrap();
    let mut public = rsa::Key::from_spki(&key.to_spki().unwrap()).unwrap();
    for padding in [rsa::Padding::Pkcs1, rsa::Padding::Pss] {
        let signature = restored
            .sign(Algorithm::Sha384, padding, b"message")
            .unwrap();
        public
            .verify(Algorithm::Sha384, padding, b"message", &signature)
            .unwrap();
        let signature = key.sign(Algorithm::Sha384, padding, b"message").unwrap();
        restored
            .verify(Algorithm::Sha384, padding, b"message", &signature)
            .unwrap();
    }
    let info = pkcs8::PrivateKeyInfo::from_der(&encoded).unwrap();
    for field in 0..2 {
        let mut parsed = pkcs1::RsaPrivateKey::from_der(info.private_key).unwrap();
        let mut altered = if field == 0 {
            parsed.exponent1
        } else {
            parsed.private_exponent
        }
        .as_bytes()
        .to_vec();
        let last = altered.len() - 1;
        altered[last] ^= 2;
        if field == 0 {
            parsed.exponent1 = UintRef::new(&altered).unwrap();
        } else {
            parsed.private_exponent = UintRef::new(&altered).unwrap();
        }
        assert!(rsa::Key::from_pkcs1_private(&parsed.to_der().unwrap()).is_err());
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(rsa::Key::from_pkcs8(&trailing).is_err());
    assert!(ecc::Key::from_pkcs8(&encoded).is_err());
}
