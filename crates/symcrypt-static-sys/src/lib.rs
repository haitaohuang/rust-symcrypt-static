#![no_std]

#[repr(C)]
pub struct Hash {
    _private: [u8; 0],
}

#[repr(C)]
pub struct Hmac {
    _private: [u8; 0],
}

#[repr(C)]
pub struct Aead {
    _private: [u8; 0],
}

#[repr(C)]
pub struct Ec {
    _private: [u8; 0],
}

#[repr(C)]
pub struct Rsa {
    _private: [u8; 0],
}

extern "C" {
    pub fn sc_init();
    pub fn sc_aes_available() -> core::ffi::c_int;
    pub fn sc_wipe(data: *mut u8, length: usize);
    pub fn sc_equal(left: *const u8, right: *const u8, length: usize) -> core::ffi::c_int;
    pub fn sc_hash(algorithm: u32, data: *const u8, length: usize, output: *mut u8) -> u32;
    pub fn sc_hash_new(algorithm: u32) -> *mut Hash;
    pub fn sc_hash_free(context: *mut Hash);
    pub fn sc_hash_update(context: *mut Hash, data: *const u8, length: usize);
    pub fn sc_hash_finish(context: *mut Hash, output: *mut u8);
    pub fn sc_hash_copy(context: *const Hash) -> *mut Hash;
    pub fn sc_hash_export_size(algorithm: u32) -> usize;
    pub fn sc_hash_export(context: *const Hash, output: *mut u8);
    pub fn sc_hash_import(context: *mut Hash, input: *const u8) -> u32;
    pub fn sc_random(seed: *const u8, output: *mut u8, length: usize) -> u32;
    pub fn sc_hmac_new(algorithm: u32, key: *const u8, length: usize) -> *mut Hmac;
    pub fn sc_hmac_update(context: *mut Hmac, data: *const u8, length: usize);
    pub fn sc_hmac_finish(context: *mut Hmac, output: *mut u8);
    pub fn sc_hmac_free(context: *mut Hmac);
    pub fn sc_hkdf_extract(
        algorithm: u32,
        salt: *const u8,
        salt_length: usize,
        input: *const u8,
        input_length: usize,
        output: *mut u8,
        output_length: usize,
    ) -> u32;
    pub fn sc_hkdf_expand(
        algorithm: u32,
        prk: *const u8,
        prk_length: usize,
        info: *const u8,
        info_length: usize,
        output: *mut u8,
        output_length: usize,
    ) -> u32;
    pub fn sc_aead_new(algorithm: u32, key: *const u8, length: usize) -> *mut Aead;
    pub fn sc_aead_free(context: *mut Aead);
    pub fn sc_aead_encrypt(
        key: *const Aead,
        nonce: *const u8,
        aad: *const u8,
        aad_length: usize,
        input: *const u8,
        output: *mut u8,
        length: usize,
        tag: *mut u8,
    ) -> u32;
    pub fn sc_aead_decrypt(
        key: *const Aead,
        nonce: *const u8,
        aad: *const u8,
        aad_length: usize,
        input: *const u8,
        output: *mut u8,
        length: usize,
        tag: *const u8,
    ) -> u32;
    pub fn sc_ec_generate(curve: u32, output: *mut *mut Ec) -> u32;
    pub fn sc_ec_free(key: *mut Ec);
    pub fn sc_ec_import(
        curve: u32,
        input: *const u8,
        length: usize,
        private_key: u32,
        output: *mut *mut Ec,
    ) -> u32;
    pub fn sc_ec_export(key: *const Ec, output: *mut u8, private_key: u32) -> u32;
    pub fn sc_ec_sign(key: *const Ec, digest: *const u8, length: usize, signature: *mut u8) -> u32;
    pub fn sc_ec_verify(
        key: *const Ec,
        digest: *const u8,
        length: usize,
        signature: *const u8,
    ) -> u32;
    pub fn sc_ec_agree(key: *const Ec, peer: *const Ec, output: *mut u8) -> u32;
    pub fn sc_rsa_generate(bits: u32, output: *mut *mut Rsa) -> u32;
    pub fn sc_rsa_free(key: *mut Rsa);
    pub fn sc_rsa_check_private_exponent(key: *const Rsa, d: *const u8, length: usize) -> u32;
    pub fn sc_rsa_import(
        modulus: *const u8,
        modulus_length: usize,
        exponent: u64,
        p: *const u8,
        p_length: usize,
        q: *const u8,
        q_length: usize,
        output: *mut *mut Rsa,
    ) -> u32;
    pub fn sc_rsa_export(key: *const Rsa, modulus: *mut u8, exponent: *mut u64) -> u32;
    pub fn sc_rsa_export_private(
        key: *const Rsa,
        p: *mut u8,
        q: *mut u8,
        d: *mut u8,
        dp: *mut u8,
        dq: *mut u8,
        coefficient: *mut u8,
    ) -> u32;
    pub fn sc_rsa_sign(
        key: *const Rsa,
        algorithm: u32,
        pss: u32,
        digest: *const u8,
        digest_length: usize,
        signature: *mut u8,
    ) -> u32;
    pub fn sc_rsa_verify(
        key: *const Rsa,
        algorithm: u32,
        pss: u32,
        digest: *const u8,
        digest_length: usize,
        signature: *const u8,
    ) -> u32;
}
