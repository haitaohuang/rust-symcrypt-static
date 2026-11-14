#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod aead;
pub mod ecc;
#[cfg(feature = "encoding")]
pub mod encoding;
pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod platform;
pub mod random;
pub mod rsa;

use core::fmt;
use symcrypt_static_sys as sys;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLength,
    InvalidEncoding,
    InvalidKey,
    VerificationFailed,
    UnsupportedPlatform,
    OutOfMemory,
    EntropyUnavailable,
    NotInitialized,
    AlreadyInitialized,
    Native(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymCrypt error: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

fn native_result(status: u32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Native(status))
    }
}

/// Compares equal-length byte strings without data-dependent early returns.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        // SAFETY: both buffers contain left.len() readable bytes; no initialization is required.
        && unsafe { sys::sc_equal(left.as_ptr(), right.as_ptr(), left.len()) != 0 }
}
