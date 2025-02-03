use crate::Error;
use rand::rngs::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use std::marker::PhantomData;

mod encrypted_key;
mod secure_key;
mod symmetric_key;

pub(crate) use encrypted_key::EncryptedKey;
pub(crate) use secure_key::{SecureKey, SecureKeyState};
pub(crate) use symmetric_key::SymmetricKey;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EncryptedData<T: Serialize + DeserializeOwned> {
    enc_data: Vec<u8>,
    nonce: [u8; 24],
    key_id: Option<i64>,
    _phantom: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> Clone for EncryptedData<T> {
    fn clone(&self) -> Self {
        Self {
            enc_data: self.enc_data.clone(),
            nonce: self.nonce,
            key_id: self.key_id,
            _phantom: PhantomData
        }
    }
}

impl<T: Serialize + DeserializeOwned> EncryptedData<T> {
    pub(crate) fn key_id(&self) -> Option<i64> {
        self.key_id
    }
}

pub(crate) trait Cipher {
    fn encrypt<T: Serialize + DeserializeOwned>(&self, data: &T)
        -> Result<EncryptedData<T>, Error>;

    fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>)
        -> Result<T, Error>;
}

pub(crate) struct EncryptedDataKeyPair<T: Serialize + DeserializeOwned> {
    encrypted_data: EncryptedData<T>,
    encrypted_key: EncryptedKey,
}

impl<T: Serialize + DeserializeOwned> EncryptedDataKeyPair<T> {
    pub(crate) fn new(encrypted_data: EncryptedData<T>, encrypted_key: EncryptedKey) -> Self {
        Self { encrypted_data, encrypted_key }
    }

    pub(crate) fn encrypt_with_random_key(data: T, parent_key: &SymmetricKey) -> Result<Self, Error> {
        let key = SymmetricKey::generate(&mut OsRng);
        let encrypted_data = key.encrypt(&data).unwrap();
        let encrypted_key = key.into_encrypted_key(parent_key);

        Ok(Self::new(encrypted_data, encrypted_key))
    }

    pub(crate) fn encrypt_and_replace<K: Cipher>(&mut self, parent_key: &K, new_data: &T) -> Result<(), Error> {
        let key = self.get_encryption_key(parent_key)?;
        let new_data_enc = key.encrypt(new_data)?;

        self.encrypted_data = new_data_enc;
        Ok(())
    }

    pub(crate) fn decrypt<K: Cipher>(&self, parent_key: &K) -> Result<T, Error> {
        let key = self.get_encryption_key(parent_key)?;
        let data = key.decrypt(&self.encrypted_data)?;

        Ok(data)
    }

    pub(crate) fn encrypted_key(&self) -> &EncryptedKey {
        &self.encrypted_key
    }

    pub(crate) fn encrypted_data(&self) -> &EncryptedData<T> {
        &self.encrypted_data
    }

    fn get_encryption_key<K: Cipher>(&self, parent_key: &K) -> Result<SymmetricKey, Error> {
        let symmetric_key = self.encrypted_key.try_to_symmetric_key(parent_key)?;
        Ok(symmetric_key)
    }
}
