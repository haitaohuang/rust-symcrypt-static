#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "none"))]
fn main() {
    panic!("Use scripts/check-freestanding.sh; this harness requires x86_64-unknown-none");
}

// Linux syscalls are the explicit test driver, not part of symcrypt-core or a TD adapter.
#[cfg(target_os = "none")]
mod freestanding {
    extern crate alloc;

    use alloc::vec;
    use core::{
        alloc::{GlobalAlloc, Layout},
        arch::{asm, global_asm},
        ptr,
    };
    use symcrypt_core::{aead, ecc, hash, hkdf, hmac, platform, random, rsa, Error, Result};

    global_asm!(
        ".global _start",
        "_start:",
        "xor rbp, rbp",
        "and rsp, -16",
        "call smoke_main",
        "ud2",
    );

    unsafe fn syscall(number: usize, arguments: [usize; 6]) -> isize {
        let result;
        // SAFETY: the caller supplies valid Linux x86_64 syscall arguments and buffers.
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") number => result,
                in("rdi") arguments[0], in("rsi") arguments[1], in("rdx") arguments[2],
                in("r10") arguments[3], in("r8") arguments[4], in("r9") arguments[5],
                lateout("rcx") _, lateout("r11") _,
                options(nostack),
            );
        }
        result
    }

    fn exit(code: usize) -> ! {
        // SAFETY: exit_group has one scalar argument and cannot return successfully.
        unsafe {
            syscall(231, [code, 0, 0, 0, 0, 0]);
        }
        loop {
            core::hint::spin_loop();
        }
    }

    struct MmapAllocator;

    // SAFETY: each allocation has an independent, page-aligned anonymous mapping.
    unsafe impl GlobalAlloc for MmapAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if layout.align() > 4096 {
                return ptr::null_mut();
            }
            // SAFETY: mmap requests private read/write memory, with no fixed address.
            let result = unsafe { syscall(9, [0, layout.size().max(1), 3, 0x22, usize::MAX, 0]) };
            if result < 0 {
                ptr::null_mut()
            } else {
                result as *mut u8
            }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: pointer/layout describe a still-live mapping returned above.
            if unsafe { syscall(11, [pointer as usize, layout.size().max(1), 0, 0, 0, 0]) } != 0 {
                exit(73);
            }
        }
    }

    #[global_allocator]
    static ALLOCATOR: MmapAllocator = MmapAllocator;

    fn entropy(mut output: &mut [u8]) -> Result<()> {
        while !output.is_empty() {
            // SAFETY: getrandom receives an exclusively borrowed writable buffer.
            let result = unsafe {
                syscall(
                    318,
                    [output.as_mut_ptr() as usize, output.len(), 0, 0, 0, 0],
                )
            };
            if result == -4 {
                continue;
            }
            if result <= 0 || result as usize > output.len() {
                return Err(Error::EntropyUnavailable);
            }
            output = &mut output[result as usize..];
        }
        Ok(())
    }

    static PLATFORM: platform::Platform = platform::Platform {
        cpuid: |leaf, subleaf| {
            #[allow(unused_unsafe)]
            let value = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
            [value.eax, value.ebx, value.ecx, value.edx]
        },
        entropy,
        fatal: |_| exit(71),
    };

    #[no_mangle]
    static mut __stack_chk_guard: usize = 0;

    #[no_mangle]
    extern "C" fn __stack_chk_fail() -> ! {
        exit(70)
    }

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
        exit(72)
    }

    fn exercise() -> Result<()> {
        for algorithm in [
            hash::Algorithm::Sha256,
            hash::Algorithm::Sha384,
            hash::Algorithm::Sha512,
        ] {
            let mut state = hash::Context::new(algorithm)?;
            state.update(b"ab");
            let duplicate = state.try_clone()?;
            assert_eq!(duplicate.finish(), algorithm.digest(b"ab")?);
            let mut restored = hash::Context::import(&state.export())?;
            restored.update(b"c");
            assert_eq!(restored.finish(), algorithm.digest(b"abc")?);
            let tag = hmac::sign(algorithm, b"key", &[b"data"])?;
            hmac::verify(algorithm, b"key", &[b"da", b"ta"], &tag)?;
            let prk = hkdf::extract(algorithm, b"salt", b"input")?;
            hkdf::expand(algorithm, &prk, b"info", &mut [0; 80])?;
        }
        let mut random_bytes = [0; 64];
        random::fill(&mut random_bytes)?;
        assert_ne!(random_bytes, [0; 64]);
        for algorithm in [
            aead::Algorithm::Aes128Gcm,
            aead::Algorithm::Aes256Gcm,
            aead::Algorithm::ChaCha20Poly1305,
        ] {
            let key = aead::Key::new(algorithm, &vec![0; algorithm.key_len()])?;
            let mut message = *b"test message";
            let tag = key.seal_in_place(&[0; 12], b"header", &mut message)?;
            key.open_in_place(&[0; 12], b"header", &mut message, &tag)?;
            assert_eq!(&message, b"test message");
        }
        for curve in [ecc::Curve::P256, ecc::Curve::P384] {
            let mut key = ecc::Key::generate(curve)?;
            let private = key.to_pkcs8()?;
            let public = key.to_spki()?;
            let signature = key.sign(hash::Algorithm::Sha384, b"message")?;
            let mut verifier = ecc::Key::from_spki(&public)?;
            verifier.verify(hash::Algorithm::Sha384, b"message", &signature)?;
            let peer = ecc::Key::generate(curve)?;
            let peer_public = peer.public_key()?;
            let secret = peer.agree(&key.public_key()?)?;
            assert_eq!(
                &*secret,
                &*ecc::Key::from_pkcs8(&private)?.agree(&peer_public)?
            );
        }
        let key = rsa::Key::generate(2048)?;
        let mut imported = rsa::Key::from_pkcs8(&key.to_pkcs8()?)?;
        let mut public = rsa::Key::from_spki(&key.to_spki()?)?;
        for padding in [rsa::Padding::Pkcs1, rsa::Padding::Pss] {
            let signature = imported.sign(hash::Algorithm::Sha384, padding, b"message")?;
            public.verify(hash::Algorithm::Sha384, padding, b"message", &signature)?;
        }
        Ok(())
    }

    fn exercise_adapters() {
        use rustls::{
            crypto::cipher::{AeadKey, InboundOpaqueMessage, Iv, OutboundPlainMessage},
            pki_types::PrivatePkcs8KeyDer,
            ContentType, ProtocolVersion, SignatureScheme,
        };
        use spdmlib::{crypto, protocol::*};

        spdm_crypto_symcrypt::register(|| None).unwrap();
        let context = crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384).unwrap();
        crypto::hash::hash_ctx_update(&context, b"transcript").unwrap();
        let checkpoint = context.clone();
        drop(context);
        assert_eq!(
            crypto::hash::hash_ctx_finalize(checkpoint)
                .unwrap()
                .as_ref(),
            hash::Algorithm::Sha384.digest(b"transcript").unwrap(),
        );
        let dhe = &spdm_crypto_symcrypt::dhe::DHE;
        let (public, ephemeral) = (dhe.generate_key_pair_cb)(SpdmDheAlgo::SECP_384_R1).unwrap();
        let saved = zeroize::Zeroizing::new(ephemeral.export_private_key().unwrap());
        let restored =
            (dhe.import_private_key_cb.unwrap())(SpdmDheAlgo::SECP_384_R1, &saved).unwrap();
        let (peer_public, peer) = (dhe.generate_key_pair_cb)(SpdmDheAlgo::SECP_384_R1).unwrap();
        let expected = peer.compute_final_key(&public).unwrap();
        assert_eq!(restored.compute_final_key(&peer_public).unwrap(), expected);
        assert_eq!(ephemeral.compute_final_key(&peer_public).unwrap(), expected);

        let mut identity = ecc::Key::generate(ecc::Curve::P384).unwrap();
        let mut signature = SpdmSignatureStruct {
            data_size: 96,
            ..Default::default()
        };
        signature.data[..96]
            .copy_from_slice(&identity.sign(hash::Algorithm::Sha384, b"identity").unwrap());
        (spdm_crypto_symcrypt::certificates::ASYM_VERIFY.verify_cb)(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            SpdmDer::SpdmDerPubKeyRfc7250(&identity.to_spki().unwrap()),
            b"identity",
            &signature,
        )
        .unwrap();

        let provider = rustls_symcrypt::provider().unwrap();
        let signing_key = provider
            .key_provider
            .load_private_key(
                PrivatePkcs8KeyDer::from(identity.to_pkcs8().unwrap().to_vec()).into(),
            )
            .unwrap();
        let signer = signing_key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
            .unwrap();
        let signature = symcrypt_core::encoding::ecdsa_signature_from_der(
            ecc::Curve::P384,
            &signer.sign(b"TLS identity").unwrap(),
        )
        .unwrap();
        identity
            .verify(hash::Algorithm::Sha384, b"TLS identity", &signature)
            .unwrap();
        let left = provider.kx_groups[0].start().unwrap();
        let right = provider.kx_groups[0].start().unwrap();
        let left_public = left.pub_key().to_vec();
        let right_public = right.pub_key().to_vec();
        assert_eq!(
            left.complete(&right_public).unwrap().secret_bytes(),
            right.complete(&left_public).unwrap().secret_bytes()
        );

        let suite = provider.cipher_suites[0].tls13().unwrap();
        let mut hash = suite.common.hash_provider.start();
        hash.update(b"TLS transcript");
        assert_eq!(hash.fork_finish().as_ref(), hash.finish().as_ref());
        let _key = suite
            .hkdf_provider
            .extract_from_zero_ikm(None)
            .expand_block(&[b"TLS label"]);
        let mut encrypt = suite
            .aead_alg
            .encrypter(AeadKey::from([1; 32]), Iv::from([2; 12]));
        let mut decrypt = suite
            .aead_alg
            .decrypter(AeadKey::from([1; 32]), Iv::from([2; 12]));
        let record = encrypt
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_3,
                    payload: b"TLS record".as_slice().into(),
                },
                10,
            )
            .unwrap();
        let mut payload = record.payload.as_ref().to_vec();
        let plaintext = decrypt
            .decrypt(
                InboundOpaqueMessage::new(record.typ, record.version, &mut payload),
                10,
            )
            .unwrap();
        assert_eq!(plaintext.payload, b"TLS record");
    }

    #[no_mangle]
    extern "C" fn smoke_main() -> ! {
        let mut guard = [0; core::mem::size_of::<usize>()];
        entropy(&mut guard).unwrap();
        // SAFETY: single-threaded startup, before entering any stack-protected native code.
        unsafe {
            __stack_chk_guard = usize::from_ne_bytes(guard);
        }
        // SAFETY: Linux provides the x86_64 ABI/XMM preservation and actual CPUID/OS entropy.
        unsafe { platform::initialize_with_platform(&PLATFORM) }.unwrap();
        exercise().unwrap();
        exercise_adapters();
        let message =
            b"freestanding static-link smoke passed (Linux driver, not TD qualification)\n";
        // SAFETY: write receives the live immutable success-message buffer.
        unsafe {
            syscall(1, [1, message.as_ptr() as usize, message.len(), 0, 0, 0]);
        }
        exit(0)
    }
}
