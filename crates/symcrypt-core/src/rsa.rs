use crate::{hash::Algorithm, native_result, platform, Error, Result};
use alloc::{vec, vec::Vec};
use core::ptr::{self, NonNull};
use symcrypt_static_sys as sys;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Padding {
    Pkcs1 = 0,
    /// Same digest and MGF1 hash, with exactly one digest-length of salt.
    Pss = 1,
}

pub struct PrivateComponents {
    pub p: Zeroizing<Vec<u8>>,
    pub q: Zeroizing<Vec<u8>>,
    pub d: Zeroizing<Vec<u8>>,
    pub dp: Zeroizing<Vec<u8>>,
    pub dq: Zeroizing<Vec<u8>>,
    pub coefficient: Zeroizing<Vec<u8>>,
}

pub struct Key {
    native: NonNull<sys::Rsa>,
    modulus_len: usize,
    private: bool,
}

// SAFETY: native storage stays fixed; operations affecting validation state take &mut self.
unsafe impl Send for Key {}

impl Key {
    pub fn generate(bits: u32) -> Result<Self> {
        if !matches!(bits, 2048 | 3072 | 4096) {
            return Err(Error::InvalidKey);
        }
        platform::ensure_initialized()?;
        let mut native = ptr::null_mut();
        // SAFETY: supported modulus size and writable output handle.
        native_result(unsafe { sys::sc_rsa_generate(bits, &mut native) })?;
        Ok(Self {
            native: NonNull::new(native).ok_or(Error::OutOfMemory)?,
            modulus_len: bits as usize / 8,
            private: true,
        })
    }

    pub fn from_public_components(modulus: &[u8], exponent: u64) -> Result<Self> {
        Self::import(modulus, exponent, &[], &[])
    }

    /// Imports a two-prime signing key. Components use unsigned big-endian encoding.
    pub fn from_primes(modulus: &[u8], exponent: u64, p: &[u8], q: &[u8]) -> Result<Self> {
        if p.is_empty() || q.is_empty() || p.len() > modulus.len() || q.len() > modulus.len() {
            return Err(Error::InvalidKey);
        }
        Self::import(modulus, exponent, p, q)
    }

    fn import(modulus: &[u8], exponent: u64, p: &[u8], q: &[u8]) -> Result<Self> {
        if !(256..=1024).contains(&modulus.len())
            || modulus[0] == 0
            || modulus[modulus.len() - 1] & 1 == 0
            || exponent < 3
            || exponent & 1 == 0
        {
            return Err(Error::InvalidKey);
        }
        let bits = modulus.len() * 8 - modulus[0].leading_zeros() as usize;
        if bits < 2048 {
            return Err(Error::InvalidKey);
        }
        platform::ensure_initialized()?;
        let mut native = ptr::null_mut();
        // SAFETY: bounded components, matching lengths and writable handle;
        // native import performs key validation without opt-out flags.
        native_result(unsafe {
            sys::sc_rsa_import(
                modulus.as_ptr(),
                modulus.len(),
                exponent,
                p.as_ptr(),
                p.len(),
                q.as_ptr(),
                q.len(),
                &mut native,
            )
        })?;
        Ok(Self {
            native: NonNull::new(native).ok_or(Error::OutOfMemory)?,
            modulus_len: modulus.len(),
            private: !p.is_empty(),
        })
    }

    pub fn modulus_len(&self) -> usize {
        self.modulus_len
    }

    #[cfg(feature = "encoding")]
    pub(crate) fn check_private_exponent(&self, exponent: &[u8]) -> Result<()> {
        if !self.private || exponent.is_empty() || exponent.len() > self.modulus_len {
            return Err(Error::InvalidKey);
        }
        // SAFETY: native validation uses separate temporary integers and a bounded exponent.
        native_result(unsafe {
            sys::sc_rsa_check_private_exponent(
                self.native.as_ptr(),
                exponent.as_ptr(),
                exponent.len(),
            )
        })
    }

    pub fn public_components(&self) -> Result<(Vec<u8>, u64)> {
        let mut modulus = vec![0; self.modulus_len];
        let mut exponent = 0;
        // SAFETY: live key, exact modulus-sized output and one exponent slot.
        native_result(unsafe {
            sys::sc_rsa_export(self.native.as_ptr(), modulus.as_mut_ptr(), &mut exponent)
        })?;
        Ok((modulus, exponent))
    }

    pub fn private_components(&self) -> Result<PrivateComponents> {
        if !self.private {
            return Err(Error::InvalidKey);
        }
        let mut result = PrivateComponents {
            p: Zeroizing::new(vec![0; self.modulus_len]),
            q: Zeroizing::new(vec![0; self.modulus_len]),
            d: Zeroizing::new(vec![0; self.modulus_len]),
            dp: Zeroizing::new(vec![0; self.modulus_len]),
            dq: Zeroizing::new(vec![0; self.modulus_len]),
            coefficient: Zeroizing::new(vec![0; self.modulus_len]),
        };
        // SAFETY: all six outputs are disjoint and large enough for any RSA component.
        native_result(unsafe {
            sys::sc_rsa_export_private(
                self.native.as_ptr(),
                result.p.as_mut_ptr(),
                result.q.as_mut_ptr(),
                result.d.as_mut_ptr(),
                result.dp.as_mut_ptr(),
                result.dq.as_mut_ptr(),
                result.coefficient.as_mut_ptr(),
            )
        })?;
        Ok(result)
    }

    pub fn sign(
        &mut self,
        algorithm: Algorithm,
        padding: Padding,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.sign_digest(algorithm, padding, &algorithm.digest(message)?)
    }

    pub fn sign_digest(
        &mut self,
        algorithm: Algorithm,
        padding: Padding,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.private {
            return Err(Error::InvalidKey);
        }
        if digest.len() != algorithm.output_len() {
            return Err(Error::InvalidLength);
        }
        let mut signature = vec![0; self.modulus_len];
        // SAFETY: exclusive signing key, exact digest and modulus-sized signature.
        native_result(unsafe {
            sys::sc_rsa_sign(
                self.native.as_ptr(),
                algorithm as u32,
                padding as u32,
                digest.as_ptr(),
                digest.len(),
                signature.as_mut_ptr(),
            )
        })?;
        Ok(signature)
    }

    pub fn verify(
        &mut self,
        algorithm: Algorithm,
        padding: Padding,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        self.verify_digest(algorithm, padding, &algorithm.digest(message)?, signature)
    }

    pub fn verify_digest(
        &mut self,
        algorithm: Algorithm,
        padding: Padding,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        if digest.len() != algorithm.output_len() || signature.len() != self.modulus_len {
            return Err(Error::InvalidLength);
        }
        // SAFETY: live exclusive key and exact digest/signature lengths.
        native_result(unsafe {
            sys::sc_rsa_verify(
                self.native.as_ptr(),
                algorithm as u32,
                padding as u32,
                digest.as_ptr(),
                digest.len(),
                signature.as_ptr(),
            )
        })
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: unique owner; native free wipes the complete key allocation.
        unsafe { sys::sc_rsa_free(self.native.as_ptr()) };
    }
}
