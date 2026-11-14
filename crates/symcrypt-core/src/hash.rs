use crate::{native_result, platform, Error, Result};
use alloc::{vec, vec::Vec};
use core::ptr::NonNull;
use symcrypt_static_sys as sys;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Algorithm {
    Sha256 = 256,
    Sha384 = 384,
    Sha512 = 512,
}

impl Algorithm {
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn digest(self, input: &[u8]) -> Result<Vec<u8>> {
        let mut output = vec![0; self.output_len()];
        self.digest_into(input, &mut output)?;
        Ok(output)
    }

    pub fn digest_into(self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if output.len() != self.output_len() {
            return Err(Error::InvalidLength);
        }
        platform::ensure_initialized()?;
        // SAFETY: the output matches this algorithm's digest size; input is borrowed.
        native_result(unsafe {
            sys::sc_hash(
                self as u32,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
            )
        })
    }
}

pub struct Context {
    native: NonNull<sys::Hash>,
    algorithm: Algorithm,
}

// SAFETY: ownership moves only the pointer; the native object stays at its stable address.
// Native mutation is exclusive through &mut self, and independent objects are thread-safe.
unsafe impl Send for Context {}

impl Context {
    pub fn new(algorithm: Algorithm) -> Result<Self> {
        platform::ensure_initialized()?;
        // SAFETY: initialized library, valid algorithm, uniquely owned allocation.
        let native = NonNull::new(unsafe { sys::sc_hash_new(algorithm as u32) })
            .ok_or(Error::OutOfMemory)?;
        Ok(Self { native, algorithm })
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn update(&mut self, input: &[u8]) {
        // SAFETY: live native context is exclusively borrowed and input is readable.
        unsafe { sys::sc_hash_update(self.native.as_ptr(), input.as_ptr(), input.len()) };
    }

    pub fn try_clone(&self) -> Result<Self> {
        // SAFETY: native copy creates independent, stable storage; source is not mutated.
        let native = NonNull::new(unsafe { sys::sc_hash_copy(self.native.as_ptr()) })
            .ok_or(Error::OutOfMemory)?;
        Ok(Self {
            native,
            algorithm: self.algorithm,
        })
    }

    pub fn finish(self) -> Vec<u8> {
        let mut output = vec![0; self.algorithm.output_len()];
        // SAFETY: consuming this owner permits mutation; output has the exact digest size.
        unsafe { sys::sc_hash_finish(self.native.as_ptr(), output.as_mut_ptr()) };
        output
    }

    pub fn export(&self) -> Vec<u8> {
        // SAFETY: valid algorithm; the returned size is a public native constant.
        let size = unsafe { sys::sc_hash_export_size(self.algorithm as u32) };
        let mut output = vec![0; size + 8];
        output[..4].copy_from_slice(b"SCH1");
        output[4..8].copy_from_slice(&(self.algorithm as u32).to_be_bytes());
        // SAFETY: exact native export capacity and immutable, live source context.
        unsafe { sys::sc_hash_export(self.native.as_ptr(), output[8..].as_mut_ptr()) };
        output
    }

    pub fn import(input: &[u8]) -> Result<Self> {
        if input.len() < 8 || &input[..4] != b"SCH1" {
            return Err(Error::InvalidEncoding);
        }
        let algorithm = match u32::from_be_bytes([input[4], input[5], input[6], input[7]]) {
            256 => Algorithm::Sha256,
            384 => Algorithm::Sha384,
            512 => Algorithm::Sha512,
            _ => return Err(Error::InvalidEncoding),
        };
        // SAFETY: valid algorithm; exported lengths are independent of initialization.
        let size = unsafe { sys::sc_hash_export_size(algorithm as u32) };
        if input.len() != size + 8 {
            return Err(Error::InvalidLength);
        }
        let context = Self::new(algorithm)?;
        // SAFETY: exact validated blob length and exclusive context; native import validates contents.
        native_result(unsafe {
            sys::sc_hash_import(context.native.as_ptr(), input[8..].as_ptr())
        })?;
        Ok(context)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: this is the unique owner and all borrows have ended.
        unsafe { sys::sc_hash_free(self.native.as_ptr()) };
    }
}
