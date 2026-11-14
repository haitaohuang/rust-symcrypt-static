use crate::{constant_time_eq, hash::Algorithm, platform, Error, Result};
use alloc::{vec, vec::Vec};
use core::ptr::NonNull;
use symcrypt_static_sys as sys;
use zeroize::Zeroizing;

pub struct Context {
    native: NonNull<sys::Hmac>,
    algorithm: Algorithm,
}

// SAFETY: the key and state remain in their native allocation; mutation requires &mut self.
unsafe impl Send for Context {}

impl Context {
    pub fn new(algorithm: Algorithm, key: &[u8]) -> Result<Self> {
        platform::ensure_initialized()?;
        // SAFETY: valid algorithm and readable key; native HMAC accepts all key lengths.
        let native =
            NonNull::new(unsafe { sys::sc_hmac_new(algorithm as u32, key.as_ptr(), key.len()) })
                .ok_or(Error::OutOfMemory)?;
        Ok(Self { native, algorithm })
    }

    pub fn update(&mut self, input: &[u8]) {
        // SAFETY: exclusive live context and readable input.
        unsafe { sys::sc_hmac_update(self.native.as_ptr(), input.as_ptr(), input.len()) };
    }

    pub fn finish(self) -> Zeroizing<Vec<u8>> {
        let mut output = Zeroizing::new(vec![0; self.algorithm.output_len()]);
        // SAFETY: consuming context and exact output size.
        unsafe { sys::sc_hmac_finish(self.native.as_ptr(), output.as_mut_ptr()) };
        output
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: unique owner, native key/state are wiped before the allocation is freed.
        unsafe { sys::sc_hmac_free(self.native.as_ptr()) };
    }
}

pub fn sign(algorithm: Algorithm, key: &[u8], input: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>> {
    let mut context = Context::new(algorithm, key)?;
    for part in input {
        context.update(part);
    }
    Ok(context.finish())
}

pub fn verify(algorithm: Algorithm, key: &[u8], input: &[&[u8]], tag: &[u8]) -> Result<()> {
    let expected = sign(algorithm, key, input)?;
    if constant_time_eq(&expected, tag) {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}
