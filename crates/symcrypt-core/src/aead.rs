use crate::{native_result, platform, Error, Result};
use core::ptr::NonNull;
use symcrypt_static_sys as sys;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Algorithm {
    Aes128Gcm = 128,
    Aes256Gcm = 256,
    ChaCha20Poly1305 = 20,
}

impl Algorithm {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }
}

pub struct Key {
    native: NonNull<sys::Aead>,
}

// SAFETY: expanded keys never move or mutate after creation. Each native one-shot
// operation uses separate local state; concurrent operations may share the key.
unsafe impl Send for Key {}
unsafe impl Sync for Key {}

impl Key {
    pub fn new(algorithm: Algorithm, key: &[u8]) -> Result<Self> {
        if key.len() != algorithm.key_len() {
            return Err(Error::InvalidLength);
        }
        platform::ensure_initialized()?;
        // SAFETY: environment has completed initialization.
        if algorithm != Algorithm::ChaCha20Poly1305 && unsafe { sys::sc_aes_available() } == 0 {
            return Err(Error::UnsupportedPlatform);
        }
        // SAFETY: the algorithm/key length pair is validated and the key is borrowed.
        let native =
            NonNull::new(unsafe { sys::sc_aead_new(algorithm as u32, key.as_ptr(), key.len()) })
                .ok_or(Error::OutOfMemory)?;
        Ok(Self { native })
    }

    /// The caller must never reuse a nonce for encryption with this key.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<()> {
        let result = if input.len() != output.len() {
            Err(Error::InvalidLength)
        } else {
            // SAFETY: fixed nonce/tag sizes, disjoint equal-length buffers; native checks GCM limits.
            native_result(unsafe {
                sys::sc_aead_encrypt(
                    self.native.as_ptr(),
                    nonce.as_ptr(),
                    aad.as_ptr(),
                    aad.len(),
                    input.as_ptr(),
                    output.as_mut_ptr(),
                    input.len(),
                    tag.as_mut_ptr(),
                )
            })
        };
        if result.is_err() {
            output.zeroize();
            tag.zeroize();
        }
        result
    }

    /// No plaintext is returned on authentication failure; the output is wiped.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<()> {
        let result = if input.len() != output.len() {
            Err(Error::InvalidLength)
        } else {
            // SAFETY: exclusive output, disjoint input, and validated fixed-size nonce/tag.
            native_result(unsafe {
                sys::sc_aead_decrypt(
                    self.native.as_ptr(),
                    nonce.as_ptr(),
                    aad.as_ptr(),
                    aad.len(),
                    input.as_ptr(),
                    output.as_mut_ptr(),
                    input.len(),
                    tag.as_ptr(),
                )
            })
        };
        if result.is_err() {
            output.zeroize();
        }
        result
    }

    /// The caller must never reuse a nonce for encryption with this key.
    pub fn seal_in_place(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> Result<[u8; 16]> {
        let mut tag = [0; 16];
        // SAFETY: native AEAD explicitly supports identical input/output buffers.
        let result = native_result(unsafe {
            sys::sc_aead_encrypt(
                self.native.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                tag.as_mut_ptr(),
            )
        });
        if result.is_err() {
            data.zeroize();
            tag.zeroize();
        }
        result.map(|()| tag)
    }

    pub fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<()> {
        // SAFETY: native AEAD supports identical input/output; the mutable slice is exclusive.
        let result = native_result(unsafe {
            sys::sc_aead_decrypt(
                self.native.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                tag.as_ptr(),
            )
        });
        if result.is_err() {
            data.zeroize();
        }
        result
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: unique ownership and no remaining borrows.
        unsafe { sys::sc_aead_free(self.native.as_ptr()) };
    }
}
