use crate::{hash::Algorithm, native_result, platform, Error, Result};
use alloc::{vec, vec::Vec};
use symcrypt_static_sys as sys;
use zeroize::{Zeroize, Zeroizing};

pub fn extract(algorithm: Algorithm, salt: &[u8], input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    platform::ensure_initialized()?;
    let mut output = Zeroizing::new(vec![0; algorithm.output_len()]);
    // SAFETY: readable inputs and a digest-sized output.
    native_result(unsafe {
        sys::sc_hkdf_extract(
            algorithm as u32,
            salt.as_ptr(),
            salt.len(),
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    })?;
    Ok(output)
}

pub fn expand(algorithm: Algorithm, prk: &[u8], info: &[u8], output: &mut [u8]) -> Result<()> {
    let result = (|| {
        if prk.len() < algorithm.output_len() || output.len() > 255 * algorithm.output_len() {
            return Err(Error::InvalidLength);
        }
        platform::ensure_initialized()?;
        // SAFETY: RFC 5869 PRK/output bounds are checked; each pointer matches its slice length.
        native_result(unsafe {
            sys::sc_hkdf_expand(
                algorithm as u32,
                prk.as_ptr(),
                prk.len(),
                info.as_ptr(),
                info.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        })
    })();
    if result.is_err() {
        output.zeroize();
    }
    result
}
