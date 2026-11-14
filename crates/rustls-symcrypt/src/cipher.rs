use alloc::boxed::Box;
use rustls::{
    crypto::cipher::{
        make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
        MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
        Tls13AeadAlgorithm, UnsupportedOperationError,
    },
    CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion,
    SupportedCipherSuite, Tls13CipherSuite,
};
use symcrypt_core::aead;
use zeroize::Zeroize;

pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &crate::hashing::Sha384,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &crate::hashing::Kdf,
        aead_alg: &Aes256Gcm,
        quic: None,
    });

struct Aes256Gcm;
struct RecordKey {
    key: aead::Key,
    iv: Iv,
}

impl RecordKey {
    fn new(key: AeadKey, iv: Iv) -> Self {
        Self {
            key: aead::Key::new(aead::Algorithm::Aes256Gcm, key.as_ref())
                .expect("SymCrypt AEAD key creation failed"),
            iv,
        }
    }
}

impl Tls13AeadAlgorithm for Aes256Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(RecordKey::new(key, iv))
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(RecordKey::new(key, iv))
    }
    fn key_len(&self) -> usize {
        32
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }
}

impl MessageEncrypter for RecordKey {
    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        sequence: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        if message.payload.len() > 16384 {
            return Err(Error::EncryptError);
        }
        let length = self.encrypted_payload_len(message.payload.len());
        let mut payload = PrefixedPayload::with_capacity(length);
        payload.extend_from_chunks(&message.payload);
        payload.extend_from_slice(&[u8::from(message.typ)]);
        let tag = self
            .key
            .seal_in_place(
                &Nonce::new(&self.iv, sequence).0,
                &make_tls13_aad(length),
                payload.as_mut(),
            )
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, length: usize) -> usize {
        length.saturating_add(17)
    }
}

impl MessageDecrypter for RecordKey {
    fn decrypt<'a>(
        &mut self,
        mut message: InboundOpaqueMessage<'a>,
        sequence: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        if message.typ != ContentType::ApplicationData
            || message.version != ProtocolVersion::TLSv1_2
            || message.payload.len() < 17
        {
            message.payload.zeroize();
            return Err(Error::DecryptError);
        }
        let length = message.payload.len();
        let plaintext_length = length - 16;
        let tag: [u8; 16] = message.payload[plaintext_length..]
            .try_into()
            .map_err(|_| Error::DecryptError)?;
        if self
            .key
            .open_in_place(
                &Nonce::new(&self.iv, sequence).0,
                &make_tls13_aad(length),
                &mut message.payload[..plaintext_length],
                &tag,
            )
            .is_err()
        {
            message.payload.zeroize();
            return Err(Error::DecryptError);
        }
        message.payload.truncate(plaintext_length);
        message.into_tls13_unpadded_message()
    }
}
