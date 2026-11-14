use alloc::{boxed::Box, string::ToString, vec::Vec};
use rustls::{
    crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    ffdhe_groups::FfdheGroup,
    Error, NamedGroup, PeerMisbehaved, ProtocolVersion,
};
use symcrypt_core::ecc;

pub static SECP384R1: &dyn SupportedKxGroup = &P384;

#[derive(Debug)]
struct P384;

struct Exchange {
    key: spin::Mutex<ecc::Key>,
    public: Vec<u8>,
}

impl SupportedKxGroup for P384 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let key = ecc::Key::generate(ecc::Curve::P384).map_err(error)?;
        let public = key.public_key().map_err(error)?;
        Ok(Box::new(Exchange {
            key: spin::Mutex::new(key),
            public,
        }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

impl ActiveKeyExchange for Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let secret = self
            .key
            .into_inner()
            .agree(peer)
            .map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        Ok(SharedSecret::from(secret.as_slice()))
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

fn error(error: symcrypt_core::Error) -> Error {
    Error::General(error.to_string())
}
