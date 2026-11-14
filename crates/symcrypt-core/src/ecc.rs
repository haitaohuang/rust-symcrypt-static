use crate::{hash::Algorithm, native_result, platform, Error, Result};
use alloc::{vec, vec::Vec};
use core::ptr::{self, NonNull};
use symcrypt_static_sys as sys;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Curve {
    P256 = 256,
    P384 = 384,
}

impl Curve {
    pub const fn scalar_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }
}

pub struct Key {
    native: NonNull<sys::Ec>,
    curve: Curve,
    private: bool,
}

// SAFETY: moving the owner leaves the native curve/key addresses unchanged. Operations
// that may update native validation state require exclusive access; Key is not Sync.
unsafe impl Send for Key {}

impl Key {
    pub fn generate(curve: Curve) -> Result<Self> {
        platform::ensure_initialized()?;
        let mut native = ptr::null_mut();
        // SAFETY: valid curve and writable handle slot; native failure frees partial allocations.
        native_result(unsafe { sys::sc_ec_generate(curve as u32, &mut native) })?;
        Ok(Self {
            native: NonNull::new(native).ok_or(Error::OutOfMemory)?,
            curve,
            private: true,
        })
    }

    pub fn from_private_scalar(curve: Curve, scalar: &[u8]) -> Result<Self> {
        if scalar.len() != curve.scalar_len() {
            return Err(Error::InvalidLength);
        }
        Self::import(curve, scalar, true)
    }

    pub fn from_sec1_public_key(curve: Curve, public_key: &[u8]) -> Result<Self> {
        if public_key.len() != 1 + 2 * curve.scalar_len() || public_key[0] != 4 {
            return Err(Error::InvalidEncoding);
        }
        Self::import(curve, &public_key[1..], false)
    }

    fn import(curve: Curve, input: &[u8], private: bool) -> Result<Self> {
        platform::ensure_initialized()?;
        let mut native = ptr::null_mut();
        // SAFETY: input size/format is checked by constructors; native validates keys and
        // the adapter rejects modular reduction of noncanonical private scalars.
        native_result(unsafe {
            sys::sc_ec_import(
                curve as u32,
                input.as_ptr(),
                input.len(),
                private as u32,
                &mut native,
            )
        })?;
        Ok(Self {
            native: NonNull::new(native).ok_or(Error::OutOfMemory)?,
            curve,
            private,
        })
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }

    pub fn private_scalar(&self) -> Result<Zeroizing<Vec<u8>>> {
        if !self.private {
            return Err(Error::InvalidKey);
        }
        let mut output = Zeroizing::new(vec![0; self.curve.scalar_len()]);
        // SAFETY: live private key and exact scalar-sized output.
        native_result(unsafe { sys::sc_ec_export(self.native.as_ptr(), output.as_mut_ptr(), 1) })?;
        Ok(output)
    }

    pub fn public_key(&self) -> Result<Vec<u8>> {
        let mut output = vec![0; 1 + 2 * self.curve.scalar_len()];
        output[0] = 4;
        // SAFETY: native exports X||Y into exactly two field elements after the SEC1 prefix.
        native_result(unsafe {
            sys::sc_ec_export(self.native.as_ptr(), output[1..].as_mut_ptr(), 0)
        })?;
        Ok(output)
    }

    /// Signs a message, hashing it exactly once; returns fixed-width r||s.
    pub fn sign(&mut self, algorithm: Algorithm, message: &[u8]) -> Result<Vec<u8>> {
        let digest = Zeroizing::new(algorithm.digest(message)?);
        self.sign_digest(&digest)
    }

    /// Signs an already computed SHA256/384/512 digest without hashing again.
    pub fn sign_digest(&mut self, digest: &[u8]) -> Result<Vec<u8>> {
        if !self.private {
            return Err(Error::InvalidKey);
        }
        if !matches!(digest.len(), 32 | 48 | 64) {
            return Err(Error::InvalidLength);
        }
        let mut signature = vec![0; 2 * self.curve.scalar_len()];
        // SAFETY: validated digest length, exclusive private key and exact fixed signature size.
        native_result(unsafe {
            sys::sc_ec_sign(
                self.native.as_ptr(),
                digest.as_ptr(),
                digest.len(),
                signature.as_mut_ptr(),
            )
        })?;
        Ok(signature)
    }

    pub fn verify(&mut self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> Result<()> {
        let digest = Zeroizing::new(algorithm.digest(message)?);
        self.verify_digest(&digest, signature)
    }

    pub fn verify_digest(&mut self, digest: &[u8], signature: &[u8]) -> Result<()> {
        if !matches!(digest.len(), 32 | 48 | 64) || signature.len() != 2 * self.curve.scalar_len() {
            return Err(Error::InvalidLength);
        }
        // SAFETY: live exclusive key and validated input lengths; native checks signature values.
        native_result(unsafe {
            sys::sc_ec_verify(
                self.native.as_ptr(),
                digest.as_ptr(),
                digest.len(),
                signature.as_ptr(),
            )
        })
    }

    /// Consumes the ephemeral private key and returns a fixed-width, big-endian shared secret.
    pub fn agree(self, peer_public_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if !self.private {
            return Err(Error::InvalidKey);
        }
        let peer = Self::from_sec1_public_key(self.curve, peer_public_key)?;
        let mut output = Zeroizing::new(vec![0; self.curve.scalar_len()]);
        // SAFETY: validated peer on the same curve, live private key, exact output width.
        native_result(unsafe {
            sys::sc_ec_agree(
                self.native.as_ptr(),
                peer.native.as_ptr(),
                output.as_mut_ptr(),
            )
        })?;
        Ok(output)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: unique owner; native key is freed before its curve.
        unsafe { sys::sc_ec_free(self.native.as_ptr()) };
    }
}
