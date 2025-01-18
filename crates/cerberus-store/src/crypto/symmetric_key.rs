use super::{Cipher, EncryptedData, EncryptedKey};
use crate::{hash_password, Error};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub(crate) struct SymmetricKey {
    id: Option<i64>,
    key: Vec<u8>,
}

impl SymmetricKey {
    pub(crate) fn new(key: &[u8], id: Option<i64>) -> Self {
        Self {
            id,
            key: key.to_vec(),
        }
    }

    pub(crate) fn generate(rng: impl CryptoRng + RngCore) -> Self {
        let key = XChaCha20Poly1305::generate_key(rng);

        Self {
            id: None,
            key: key.to_vec(),
        }
    }

    pub(crate) fn from_password(password: &[u8], salt: &str) -> Self {
        let key = hash_password(password, salt);

        Self { id: None, key }
    }

    pub(crate) fn into_encrypted_key<K: Cipher>(self, parent_key: &K) -> EncryptedKey {
        let encrypted_key = parent_key.encrypt(&self.key).unwrap();

        EncryptedKey::new(self.id, encrypted_key)
    }

    pub(crate) fn can_decrypt<T: Serialize + DeserializeOwned>(
        &self,
        data: &EncryptedData<T>,
    ) -> bool {
        self.id == data.key_id
    }

    pub(crate) fn id(&self) -> Option<i64> {
        self.id
    }
}

impl Cipher for SymmetricKey {
    fn encrypt<T: Serialize + DeserializeOwned>(
        &self,
        data: &T,
    ) -> Result<EncryptedData<T>, Error> {
        let data = serde_json::to_string(&data)?;

        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted_data = cipher.encrypt(&nonce.into(), data.as_bytes())?;

        Ok(EncryptedData {
            enc_data: encrypted_data,
            nonce: nonce.into(),
            key_id: self.id,
            _phantom: PhantomData,
        })
    }

    fn decrypt<T: Serialize + DeserializeOwned>(
        &self,
        data: &EncryptedData<T>,
    ) -> Result<T, Error> {
        if !self.can_decrypt(data) {
            return Err(Error::IncorrectKey);
        }

        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let decrypted_data = cipher.decrypt(&data.nonce.into(), data.enc_data.as_slice())?;

        let data = serde_json::from_slice(&decrypted_data)?;
        Ok(data)
    }
}
