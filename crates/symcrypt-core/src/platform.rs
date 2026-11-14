use crate::{Error, Result};
use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use core::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicPtr, AtomicU8, Ordering},
};
use symcrypt_static_sys as sys;

pub struct Platform {
    pub cpuid: fn(u32, u32) -> [u32; 4],
    pub entropy: fn(&mut [u8]) -> Result<()>,
    /// Also called with 0x726e6766 when native key operations cannot obtain randomness.
    pub fatal: fn(u32) -> !,
}

static PLATFORM: AtomicPtr<Platform> = AtomicPtr::new(ptr::null_mut());
static INITIALIZED: AtomicU8 = AtomicU8::new(0);

/// Installs the embedding environment once. Reinstalling the same instance is idempotent.
///
/// # Safety
/// CPUID must faithfully describe the execution environment. SSE/SSSE3 and XMM state
/// must be enabled and preserved by the ABI and every interrupt/exception handler.
/// The entropy callback must provide fresh cryptographically strong bytes (at least
/// 256 bits of entropy plus a fresh 128-bit nonce per 48-byte request). Callbacks
/// must not re-enter initialization and no callback may unwind through C.
/// Entropy failure inside native key operations invokes `fatal`, because some
/// native arithmetic paths cannot propagate RNG errors.
pub unsafe fn initialize_with_platform(platform: &'static Platform) -> Result<()> {
    let pointer = ptr::from_ref(platform).cast_mut();
    match PLATFORM.compare_exchange(
        ptr::null_mut(),
        pointer,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {}
        Err(existing) if existing == pointer => {}
        Err(_) => return Err(Error::AlreadyInitialized),
    }
    ensure_initialized()
}

pub(crate) fn get() -> Result<&'static Platform> {
    let pointer = PLATFORM.load(Ordering::Acquire);
    // SAFETY: only initialize_with_platform installs a pointer, from a static reference.
    unsafe { pointer.as_ref() }.ok_or(Error::NotInitialized)
}

pub fn ensure_initialized() -> Result<()> {
    if INITIALIZED.load(Ordering::Acquire) == 2 {
        return Ok(());
    }
    #[cfg(feature = "std")]
    {
        let _ = PLATFORM.compare_exchange(
            ptr::null_mut(),
            ptr::from_ref(&HOST).cast_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    let platform = get()?;
    loop {
        match INITIALIZED.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                let features = (platform.cpuid)(1, 0);
                if features[2] & (1 << 9) == 0 || features[3] & (1 << 26) == 0 {
                    INITIALIZED.store(3, Ordering::Release);
                    return Err(Error::UnsupportedPlatform);
                }
                // SAFETY: platform is installed, CPU prerequisites checked, and this is
                // the sole initializer. Hash self-tests do not call the entropy callback.
                unsafe { sys::sc_init() };
                INITIALIZED.store(2, Ordering::Release);
                return Ok(());
            }
            Err(2) => return Ok(()),
            Err(3) => return Err(Error::UnsupportedPlatform),
            Err(_) => core::hint::spin_loop(),
        }
    }
}

#[cfg(feature = "std")]
static HOST: Platform = Platform {
    cpuid: |leaf, subleaf| {
        // SAFETY: CPUID is available on every supported x86_64 Linux host.
        #[allow(unused_unsafe)] // The intrinsic was unsafe at the declared MSRV.
        let result = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
        [result.eax, result.ebx, result.ecx, result.edx]
    },
    entropy: |output| getrandom::getrandom(output).map_err(|_| Error::EntropyUnavailable),
    fatal: |code| {
        std::eprintln!(
            "SymCrypt fatal {code:#010x}\n{}",
            std::backtrace::Backtrace::capture()
        );
        std::process::abort()
    },
};

#[repr(C)]
struct Allocation {
    base: *mut u8,
    size: usize,
    alignment: usize,
}

#[no_mangle]
unsafe extern "C" fn symcrypt_rs_alloc(size: usize, alignment: usize) -> *mut c_void {
    let alignment = alignment.max(core::mem::align_of::<Allocation>());
    let Some(header) = core::mem::size_of::<Allocation>()
        .checked_add(alignment.wrapping_sub(1))
        .map(|size| size & !alignment.wrapping_sub(1))
    else {
        return ptr::null_mut();
    };
    let Some(total) = header.checked_add(size) else {
        return ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, alignment) else {
        return ptr::null_mut();
    };
    // SAFETY: validated nonzero layout, null is propagated to the native caller.
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: header and payload lie within layout, with suitable metadata alignment.
    unsafe {
        let payload = base.add(header);
        payload.cast::<Allocation>().sub(1).write(Allocation {
            base,
            size: total,
            alignment,
        });
        payload.cast()
    }
}

#[no_mangle]
unsafe extern "C" fn symcrypt_rs_free(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: native callbacks free only pointers returned by symcrypt_rs_alloc, once.
    unsafe {
        let allocation = pointer.cast::<Allocation>().sub(1).read();
        let layout = Layout::from_size_align_unchecked(allocation.size, allocation.alignment);
        sys::sc_wipe(allocation.base, allocation.size);
        dealloc(allocation.base, layout);
    }
}

#[no_mangle]
unsafe extern "C" fn symcrypt_rs_cpuid(leaf: u32, subleaf: u32, output: *mut u32) {
    if let Ok(platform) = get() {
        let result = (platform.cpuid)(leaf, subleaf);
        // SAFETY: the environment adapter supplies an array of four writable u32 values.
        unsafe { ptr::copy_nonoverlapping(result.as_ptr(), output, 4) };
    }
}

#[no_mangle]
extern "C" fn symcrypt_rs_fatal(code: u32) -> ! {
    if let Ok(platform) = get() {
        (platform.fatal)(code);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
unsafe extern "C" fn symcrypt_rs_random(output: *mut u8, length: usize) -> core::ffi::c_int {
    if length == 0 {
        return 0;
    }
    // SAFETY: SymCrypt supplies a writable, exclusive buffer of length bytes.
    let output = unsafe { core::slice::from_raw_parts_mut(output, length) };
    if crate::random::fill(output).is_ok() {
        0
    } else {
        use zeroize::Zeroize;
        output.zeroize();
        -1
    }
}
