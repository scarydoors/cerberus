use std::marker::PhantomData;
use rand::rngs::OsRng;
use thiserror::Error;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use chacha20poly1305::{aead::Aead, AeadCore, KeyInit, XChaCha20Poly1305};

use cerberus_secret::{ExposeSecret, SecretSlice};
use cerberus_serde::base64_expose_secret;

use crate::{kdf::DeriveKey, Cipher, EncryptedData, KeyIdentifier, KeyMismatchError, NewKey, Nonce};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymmetricKey {
    #[serde(with = "base64_expose_secret")]
    key: SecretSlice<u8>,
    id: KeyIdentifier,
}

impl SymmetricKey {
    pub fn id(&self) -> &KeyIdentifier {
        &self.id
    }
}

impl NewKey for SymmetricKey {
    const KEY_SIZE: usize = 32;

    fn new_unchecked(key: SecretSlice<u8>, id: KeyIdentifier) -> Self {
        Self { key, id }
    }
}

impl DeriveKey for SymmetricKey {
    const MAC_INFO_SUFFIX: &'static str = "_symmmetric_key";
}

impl Cipher for SymmetricKey {
    type Error = SymmetricKeyError;

    fn encrypt<T: Serialize>(&self, data: &T) -> Result<EncryptedData<T>, Self::Error> {
        let data = serde_json::to_string(&data).map_err(|_| SymmetricKeyError::SerializationError);

        let cipher = XChaCha20Poly1305::new(self.key.expose_secret().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted_data = cipher.encrypt(&nonce, data.as_bytes())?;

        Ok(EncryptedData {
            encrypted_data,
            key_id: self.id.clone(),
            nonce: Nonce(nonce.into()),
            _phantom: PhantomData,
        })
    }

    fn decrypt<T: DeserializeOwned>(&self, encrypted_data: &EncryptedData<T>) -> Result<T, Self::Error> {
        let cipher = XChaCha20Poly1305::new(self.key.expose_secret().into());
        let decrypted_data = cipher.decrypt(
            &encrypted_data.nonce.0.into(),
            encrypted_data.encrypted_data.as_slice(),
        )?;

        let data = serde_json::from_slice(&decrypted_data).map_err(|_| SymmetricKeyError::SerializationError);
        Ok(data)
    }
}

#[derive(Error, Debug)]
pub enum SymmetricKeyError {
    #[error(transparent)]
    KeyMismatch(#[from] KeyMismatchError),
    // below type is opaque because the serialization covers the sensitive data
    // and it is not desirable to reveal information about it in logs and such
    // through a potential error
    #[error("unable to serialize/deserialize sensitive data")]
    SerializationError,

    #[error("failed symmetric key operation")]
    CipherError
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    data: EncryptedData<T>,
    dek: EncryptedData<SymmetricKey>,
}

impl<T> Envelope<T>
where
    T: Serialize + DeserializeOwned,
{
    pub fn seal(kek: &impl Cipher, data: &T) -> Result<Self> {
        let dek = SymmetricKey::generate(&mut OsRng, KeyIdentifier::local());
        let data = dek.encrypt(data)?;
        let dek_encrypted = kek.encrypt(&dek)?;

        Ok(Self {
            data,
            dek: dek_encrypted,
        })
    }

    pub fn open(&self, kek: &impl Cipher) -> Result<T> {
        let dek: SymmetricKey = kek.decrypt(&self.dek)?;
        let data = dek.decrypt(&self.data)?;

        Ok(data)
    }
}
