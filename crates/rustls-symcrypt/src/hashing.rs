use alloc::{boxed::Box, vec::Vec};
use rustls::crypto::{
    hash::{self, HashAlgorithm, Output},
    hmac::Tag,
    tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError},
};
use symcrypt_core::{
    hash::{Algorithm, Context},
    hkdf, hmac,
};
use zeroize::Zeroizing;

pub(crate) struct Sha384;
struct HashContext(spin::Mutex<Context>);

impl hash::Hash for Sha384 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(spin::Mutex::new(
            Context::new(Algorithm::Sha384).expect("SymCrypt hash initialization failed"),
        )))
    }

    fn hash(&self, input: &[u8]) -> Output {
        Output::new(
            &Algorithm::Sha384
                .digest(input)
                .expect("SymCrypt hash failed"),
        )
    }

    fn output_len(&self) -> usize {
        48
    }
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }
}

impl hash::Context for HashContext {
    fn fork_finish(&self) -> Output {
        let copy = self
            .0
            .lock()
            .try_clone()
            .expect("SymCrypt hash copy failed");
        Output::new(&copy.finish())
    }
    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(spin::Mutex::new(
            self.0
                .lock()
                .try_clone()
                .expect("SymCrypt hash copy failed"),
        )))
    }
    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.into_inner().finish())
    }
    fn update(&mut self, input: &[u8]) {
        self.0.get_mut().update(input);
    }
}

pub(crate) struct Kdf;
struct Expander(Zeroizing<Vec<u8>>);

impl Hkdf for Kdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        self.extract_from_secret(salt, &[0; 48])
    }
    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        Box::new(Expander(
            hkdf::extract(Algorithm::Sha384, salt.unwrap_or(&[0; 48]), secret)
                .expect("SymCrypt HKDF extract failed"),
        ))
    }
    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(Expander(Zeroizing::new(okm.as_ref().to_vec())))
    }
    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        Tag::new(
            &hmac::sign(Algorithm::Sha384, key.as_ref(), &[message]).expect("SymCrypt HMAC failed"),
        )
    }
}

impl HkdfExpander for Expander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        hkdf::expand(Algorithm::Sha384, &self.0, &info.concat(), output)
            .map_err(|_| OutputLengthError)
    }
    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut output = Zeroizing::new([0; 48]);
        self.expand_slice(info, &mut output[..])
            .expect("SymCrypt HKDF expand failed");
        OkmBlock::new(output.as_slice())
    }
    fn hash_len(&self) -> usize {
        48
    }
}
