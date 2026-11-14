use crate::{native_result, platform, Error, Result};
use symcrypt_static_sys as sys;
use zeroize::{Zeroize, Zeroizing};

/// Fills output using a freshly seeded native AES-CTR-DRBG.
///
/// A fresh 48-byte platform entropy request is used per call, avoiding shared DRBG
/// state, lock re-entry from native key generation, and inherited state after fork.
/// This construction is not a claim of FIPS module validation.
pub fn fill(output: &mut [u8]) -> Result<()> {
    if output.is_empty() {
        return Ok(());
    }
    let result = (|| {
        platform::ensure_initialized()?;
        // SAFETY: initialized environment; only public CPU dispatch flags are queried.
        if unsafe { sys::sc_aes_available() } == 0 {
            return Err(Error::UnsupportedPlatform);
        }
        let mut seed = Zeroizing::new([0u8; 48]);
        (platform::get()?.entropy)(&mut seed[..])?;
        // SAFETY: seed is exactly 48 bytes; output is exclusively borrowed.
        native_result(unsafe { sys::sc_random(seed.as_ptr(), output.as_mut_ptr(), output.len()) })
    })();
    if result.is_err() {
        output.zeroize();
    }
    result
}
