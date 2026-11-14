use symcrypt_core::{ecc, platform, random, Error};

static FAILING_ENTROPY: platform::Platform = platform::Platform {
    cpuid: |leaf, subleaf| {
        #[allow(unused_unsafe)]
        let result = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
        [result.eax, result.ebx, result.ecx, result.edx]
    },
    entropy: |output| {
        output.fill(0xa5);
        Err(Error::EntropyUnavailable)
    },
    fatal: |code| std::process::exit(if code == 0x726e6766 { 77 } else { 78 }),
};

#[test]
fn failed_entropy_never_returns_random_bytes_or_a_key() {
    // SAFETY: host CPUID/ABI are unchanged; deliberately unavailable entropy fails closed.
    unsafe { platform::initialize_with_platform(&FAILING_ENTROPY) }.unwrap();
    let mut output = [0xff; 64];
    assert_eq!(random::fill(&mut output), Err(Error::EntropyUnavailable));
    assert_eq!(output, [0; 64]);
    random::fill(&mut []).unwrap();
    if std::env::var_os("SYMCRYPT_ENTROPY_FAILURE_CHILD").is_some() {
        let _ = ecc::Key::generate(ecc::Curve::P384);
        panic!("native generation continued after failed entropy");
    }
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "failed_entropy_never_returns_random_bytes_or_a_key",
        ])
        .env("SYMCRYPT_ENTROPY_FAILURE_CHILD", "1")
        .output()
        .unwrap();
    assert_eq!(child.status.code(), Some(77), "{child:?}");
}
