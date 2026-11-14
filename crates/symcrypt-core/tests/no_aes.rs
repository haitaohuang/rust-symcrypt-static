use symcrypt_core::{aead, hash, platform, random, Error};

static NO_ACCELERATION: platform::Platform = platform::Platform {
    cpuid: |leaf, subleaf| {
        #[allow(unused_unsafe)]
        let result = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
        let mut registers = [result.eax, result.ebx, result.ecx, result.edx];
        if leaf == 1 {
            let feature = std::env::var("SYMCRYPT_TEST_MISSING_ACCELERATION").unwrap();
            registers[2] &= !(1 << if feature == "AESNI" { 25 } else { 1 });
        }
        registers
    },
    entropy: |_| panic!("AES-dependent RNG must reject the platform before requesting entropy"),
    fatal: |_| std::process::abort(),
};

#[test]
fn aes_never_falls_back_to_table_lookups() {
    if std::env::var("SYMCRYPT_TEST_MISSING_ACCELERATION").is_err() {
        for feature in ["AESNI", "PCLMUL"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "aes_never_falls_back_to_table_lookups",
                    "--nocapture",
                ])
                .env("SYMCRYPT_TEST_MISSING_ACCELERATION", feature)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{feature}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    }
    // SAFETY: CPUID hides acceleration; all advertised features and the host ABI are real.
    unsafe { platform::initialize_with_platform(&NO_ACCELERATION) }.unwrap();
    hash::Algorithm::Sha384
        .digest(b"hashing does not require AES")
        .unwrap();
    assert!(matches!(
        aead::Key::new(aead::Algorithm::Aes256Gcm, &[0; 32]),
        Err(Error::UnsupportedPlatform)
    ));
    let mut output = [0xff; 16];
    assert_eq!(random::fill(&mut output), Err(Error::UnsupportedPlatform));
    assert_eq!(output, [0; 16]);
    aead::Key::new(aead::Algorithm::ChaCha20Poly1305, &[0; 32]).unwrap();
    unsafe { platform::initialize_with_platform(&NO_ACCELERATION) }.unwrap();
}
