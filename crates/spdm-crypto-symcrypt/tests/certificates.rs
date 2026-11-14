use serde_json::Value;
use spdm_crypto_symcrypt::certificates::{certificate_range, verify_chain_at, ASYM_VERIFY};
use spdmlib::protocol::*;
use std::process::Command;

fn unhex(value: &Value) -> Vec<u8> {
    value
        .as_str()
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn chain_parser_rejects_noncanonical_lengths_and_trailing_data() {
    for bytes in [
        vec![],
        vec![0x30],
        vec![0x30, 0x80, 0, 0],
        vec![0x30, 0x81, 1, 0],
        vec![0x30, 0x82, 0xff, 0xff],
        vec![0x30, 0, 0],
        vec![0x04, 0],
    ] {
        assert!(certificate_range(&bytes, -1).is_err());
    }
    assert!(certificate_range(&[0x30, 0], -2).is_err());
    assert!(certificate_range(&[0x30, 0], 1).is_err());
}

#[test]
#[ignore = "requires Python 3 and cryptography; exercised explicitly in CI"]
fn certificate_trust_time_eku_and_signature_contracts() {
    let output = Command::new("python3")
        .args(["-c", include_str!("certificate_reference.py")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixtures: Value = serde_json::from_slice(&output.stdout).unwrap();
    let now = fixtures["now"].as_u64().unwrap();
    for fixture in fixtures["chains"].as_array().unwrap() {
        let chain = unhex(&fixture["chain"]);
        let expected = fixture["valid"].as_bool().unwrap();
        assert_eq!(verify_chain_at(&chain, now).is_ok(), expected);
        assert!(verify_chain_at(&chain, 0).is_err());
        assert!(verify_chain_at(&chain, now + 10 * 366 * 86400).is_err());
        let (first, root_end) = certificate_range(&chain, 0).unwrap();
        let (leaf_start, end) = certificate_range(&chain, -1).unwrap();
        assert_eq!(first, 0);
        assert_eq!(root_end, leaf_start);
        assert_eq!(end, chain.len());
        let mut signature = SpdmSignatureStruct {
            data_size: 96,
            ..Default::default()
        };
        signature.data[..96].copy_from_slice(&unhex(&fixture["signature"]));
        (ASYM_VERIFY.verify_cb)(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            SpdmDer::SpdmDerCertChain(&chain),
            b"message",
            &signature,
        )
        .unwrap();
        signature.data[0] ^= 1;
        assert!((ASYM_VERIFY.verify_cb)(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            SpdmDer::SpdmDerCertChain(&chain),
            b"message",
            &signature,
        )
        .is_err());
        let mut corrupt = chain;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify_chain_at(&corrupt, now).is_err());
    }
}
