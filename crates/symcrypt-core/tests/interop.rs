#![cfg(feature = "encoding")]

use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Stdio},
};
use symcrypt_core::{aead, ecc, encoding, hash::Algorithm, hkdf, hmac, rsa};

const MESSAGE: &[u8] = b"interop message";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hash(name: &str) -> Algorithm {
    match name {
        "sha256" => Algorithm::Sha256,
        "sha384" => Algorithm::Sha384,
        "sha512" => Algorithm::Sha512,
        _ => panic!("unsupported reference hash"),
    }
}

#[test]
#[ignore = "requires Python 3 and cryptography; exercised explicitly in CI"]
fn openssl_bidirectional_interoperability() {
    let mut cases = Vec::new();
    for (curve, name) in [(ecc::Curve::P256, "sha256"), (ecc::Curve::P384, "sha384")] {
        let mut key = ecc::Key::generate(curve).unwrap();
        let encoded = key.to_pkcs8().unwrap();
        let public = key.to_spki().unwrap();
        let signature =
            encoding::ecdsa_signature_to_der(curve, &key.sign(hash(name), MESSAGE).unwrap())
                .unwrap();
        let peer = ecc::Key::generate(curve).unwrap();
        let secret = key.agree(&peer.public_key().unwrap()).unwrap();
        cases.push(json!({
            "kind": "ec", "hash": name, "private": hex(&encoded), "public": hex(&public),
            "signature": hex(&signature), "peer": hex(&peer.to_spki().unwrap()), "secret": hex(&secret)
        }));
    }
    for bits in [2048, 3072, 4096] {
        let mut key = rsa::Key::generate(bits).unwrap();
        let mut signatures = Vec::new();
        for name in ["sha256", "sha384", "sha512"] {
            for (padding, mode) in [(rsa::Padding::Pkcs1, "pkcs1"), (rsa::Padding::Pss, "pss")] {
                signatures.push(json!({
                    "hash": name, "padding": mode,
                    "signature": hex(&key.sign(hash(name), padding, MESSAGE).unwrap()),
                }));
            }
        }
        cases.push(json!({
            "kind": "rsa", "bits": bits, "private": hex(&key.to_pkcs8().unwrap()),
            "public": hex(&key.to_spki().unwrap()), "signatures": signatures
        }));
    }
    for (algorithm, name) in [
        (aead::Algorithm::Aes128Gcm, "aes128"),
        (aead::Algorithm::Aes256Gcm, "aes256"),
        (aead::Algorithm::ChaCha20Poly1305, "chacha"),
    ] {
        let bytes = vec![7; algorithm.key_len()];
        let key = aead::Key::new(algorithm, &bytes).unwrap();
        let mut ciphertext = MESSAGE.to_vec();
        let tag = key
            .seal_in_place(&[8; 12], b"header", &mut ciphertext)
            .unwrap();
        ciphertext.extend_from_slice(&tag);
        cases.push(json!({"kind": "aead", "algorithm": name, "key": hex(&bytes), "ciphertext": hex(&ciphertext)}));
    }
    for name in ["sha256", "sha384", "sha512"] {
        let algorithm = hash(name);
        let prk = hkdf::extract(algorithm, b"salt", b"input").unwrap();
        let mut expanded = [0; 99];
        hkdf::expand(algorithm, &prk, b"info", &mut expanded).unwrap();
        cases.push(json!({
            "kind": "kdf", "hash": name, "prk": hex(&prk), "expanded": hex(&expanded),
            "hmac": hex(&hmac::sign(algorithm, b"key", &[MESSAGE]).unwrap()),
        }));
    }
    let mut child = Command::new("python3")
        .args(["-c", include_str!("openssl_reference.py")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Python 3 is required for interoperability tests");
    let mut input = child.stdin.take().unwrap();
    input
        .write_all(&serde_json::to_vec(&cases).unwrap())
        .unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "reference failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(responses.len(), cases.len());
    for (case, response) in cases.iter().zip(&responses) {
        match case["kind"].as_str().unwrap() {
            "ec" => {
                let key = ecc::Key::from_pkcs8(&unhex(&response["private"])).unwrap();
                let mut public = ecc::Key::from_spki(&unhex(&response["public"])).unwrap();
                assert_eq!(key.public_key().unwrap(), public.public_key().unwrap());
                let signature =
                    encoding::ecdsa_signature_from_der(key.curve(), &unhex(&response["signature"]))
                        .unwrap();
                public
                    .verify(hash(case["hash"].as_str().unwrap()), MESSAGE, &signature)
                    .unwrap();
                let original = ecc::Key::from_spki(&unhex(&case["public"])).unwrap();
                assert_eq!(
                    &*key.agree(&original.public_key().unwrap()).unwrap(),
                    &unhex(&response["secret"])
                );
            }
            "rsa" => {
                let key = rsa::Key::from_pkcs8(&unhex(&response["private"])).unwrap();
                let mut public = rsa::Key::from_spki(&unhex(&response["public"])).unwrap();
                assert_eq!(
                    key.public_components().unwrap(),
                    public.public_components().unwrap()
                );
                for signature in response["signatures"].as_array().unwrap() {
                    let algorithm = hash(signature["hash"].as_str().unwrap());
                    let padding = if signature["padding"] == "pkcs1" {
                        rsa::Padding::Pkcs1
                    } else {
                        rsa::Padding::Pss
                    };
                    public
                        .verify(algorithm, padding, MESSAGE, &unhex(&signature["signature"]))
                        .unwrap();
                }
                for invalid in response["invalid_pss"].as_array().unwrap() {
                    assert!(public
                        .verify(
                            Algorithm::Sha384,
                            rsa::Padding::Pss,
                            MESSAGE,
                            &unhex(invalid)
                        )
                        .is_err());
                }
                rsa::Key::from_pkcs8(&unhex(&response["equivalent_exponent"])).unwrap();
            }
            "aead" => {
                let algorithm = match case["algorithm"].as_str().unwrap() {
                    "aes128" => aead::Algorithm::Aes128Gcm,
                    "aes256" => aead::Algorithm::Aes256Gcm,
                    _ => aead::Algorithm::ChaCha20Poly1305,
                };
                let key = aead::Key::new(algorithm, &unhex(&case["key"])).unwrap();
                let mut combined = unhex(&response["ciphertext"]);
                let tag: [u8; 16] = combined.split_off(combined.len() - 16).try_into().unwrap();
                key.open_in_place(&[9; 12], b"header", &mut combined, &tag)
                    .unwrap();
                assert_eq!(combined, MESSAGE);
            }
            "kdf" => assert_eq!(response["verified"], true),
            _ => panic!("unexpected reference response"),
        }
    }
}
