use alloc::{boxed::Box, vec, vec::Vec};
use spdmlib::{
    crypto::{SpdmDhe, SpdmDheKeyExchange},
    protocol::{SpdmDheAlgo, SpdmDheExchangeStruct, SpdmSharedSecretFinalKeyStruct},
};
use symcrypt_core::ecc;

fn curve(algorithm: SpdmDheAlgo) -> Option<ecc::Curve> {
    match algorithm {
        SpdmDheAlgo::SECP_256_R1 => Some(ecc::Curve::P256),
        SpdmDheAlgo::SECP_384_R1 => Some(ecc::Curve::P384),
        _ => None,
    }
}

struct Exchange(ecc::Key);

impl SpdmDheKeyExchange for Exchange {
    fn compute_final_key(
        self: Box<Self>,
        peer: &SpdmDheExchangeStruct,
    ) -> Option<SpdmSharedSecretFinalKeyStruct> {
        if usize::from(peer.data_size) != 2 * self.0.curve().scalar_len() {
            return None;
        }
        let mut public = vec![4];
        public.extend_from_slice(peer.data.get(..usize::from(peer.data_size))?);
        let secret = self.0.agree(&public).ok()?;
        Some(SpdmSharedSecretFinalKeyStruct::from(secret.as_slice()))
    }

    fn export_private_key(&self) -> Option<Vec<u8>> {
        // The upstream trait returns Vec; the checkpoint owner must wipe this exported secret.
        Some(self.0.private_scalar().ok()?.to_vec())
    }
}

pub static DHE: SpdmDhe = SpdmDhe {
    generate_key_pair_cb: |algorithm| {
        let key = ecc::Key::generate(curve(algorithm)?).ok()?;
        let public = key.public_key().ok()?;
        let mut exchange = SpdmDheExchangeStruct {
            data_size: (public.len() - 1) as u16,
            ..Default::default()
        };
        exchange
            .data
            .get_mut(..public.len() - 1)?
            .copy_from_slice(&public[1..]);
        Some((exchange, Box::new(Exchange(key))))
    },
    import_private_key_cb: Some(|algorithm, bytes| {
        Some(Box::new(Exchange(
            ecc::Key::from_private_scalar(curve(algorithm)?, bytes).ok()?,
        )))
    }),
};
