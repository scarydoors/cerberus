use crate::{database::{Database, record_types::EncryptedKeyRecord, Repository}, hash_password, nonce_counter::NonceCounter};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit},
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::Error;

use std::marker::PhantomData;

#[derive(Debug)]
pub(crate) struct EncryptedKey {
    id: Option<i64>,
    key_encrypted_data: EncryptedData<Vec<u8>>,
}

impl EncryptedKey {
    pub(crate) fn new(id: Option<i64>, key_encrypted_data: EncryptedData<Vec<u8>>) -> Self {
        Self {
            id,
            key_encrypted_data,
        }
    }

    pub(crate) fn try_to_symmetric_key(&self, parent_key: &SymmetricKey) -> Result<SymmetricKey, Error> {
        let decrypted_key = parent_key.decrypt(&self.key_encrypted_data)?;
        Ok(SymmetricKey::new(&decrypted_key, self.id))
    }

    pub(crate) async fn store<R: Repository>(&mut self, repo: &mut R) -> Result<(), Error> {
        let key_record = repo
            .store_key(&self.key_encrypted_data)
            .await?;

        self.id = Some(key_record.id);

        Ok(())
    }

    pub(crate) fn id(&self) -> Option<i64> {
        self.id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EncryptedData<T: Serialize + DeserializeOwned> {
    enc_data: Vec<u8>,
    nonce: [u8; 24],
    key_id: Option<i64>,
    _phantom: PhantomData<T>
}

impl<T: Serialize + DeserializeOwned> EncryptedData<T> {
    pub(crate) fn key_id(&self) -> Option<i64> {
        self.key_id
    }
}

trait Cipher {
    fn encrypt<T: Serialize + DeserializeOwned>(&self, data: &T) -> Result<EncryptedData<T>, Error>;

    fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T, Error>;
}

#[derive(Debug)]
pub struct SecureKey {
    decrypted_key: Option<SymmetricKey>,
    encrypted_key: EncryptedKey,
}

impl SecureKey {
    pub fn new(encrypted_key: EncryptedKey) -> Self {
        Self {
            encrypted_key,
            decrypted_key: None
        }
    }

    pub fn unlock(&mut self, parent_key: &SymmetricKey) -> Result<(), Error> {
        let symmetric_key = self.encrypted_key.try_to_symmetric_key(parent_key)?;

        self.decrypted_key = Some(symmetric_key);

        Ok(())
    }

    pub fn lock(&mut self) {
        self.decrypted_key = None;
    }

    pub fn is_locked(&self) -> bool {
        self.decrypted_key.is_none()
    }
}

impl Cipher for SecureKey {
    fn encrypt<T: Serialize + DeserializeOwned>(&self, data: &T) -> Result<EncryptedData<T>, Error> {
        self.decrypted_key.as_ref().ok_or_else(|| Error::Locked)?.encrypt(data)
    }

    fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T, Error> {
        self.decrypted_key.as_ref().ok_or_else(|| Error::Locked)?.decrypt(data)
    }
}

#[derive(Debug)]
pub(crate) struct SymmetricKey {
    id: Option<i64>,
    key: Vec<u8>,
}

impl SymmetricKey {
    pub fn new(key: &[u8], id: Option<i64>) -> Self {
        Self {
            id,
            key: key.to_vec(),
        }
    }

    pub fn generate(rng: impl CryptoRng + RngCore) -> Self {
        let key = XChaCha20Poly1305::generate_key(rng);

        Self {
            id: None,
            key: key.to_vec(),
        }
    }

    pub fn from_password(password: &[u8], salt: &str) -> Self {
        let key = hash_password(password, salt);

        Self {
            id: None,
            key,
        }
    }

    pub fn into_encrypted_key<K: Cipher>(self, parent_key: &K) -> EncryptedKey {
        let encrypted_key = parent_key.encrypt(&self.key).unwrap();

        EncryptedKey::new(self.id, encrypted_key)
    }

    pub(crate) fn can_decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> bool {
        self.id == data.key_id
    }

    pub(crate) fn id(&self) -> Option<i64> {
        self.id
    }

}

impl Cipher for SymmetricKey {
    fn encrypt<T: Serialize + DeserializeOwned>(&self, data: &T) -> Result<EncryptedData<T>, Error> {
        let data = serde_json::to_string(&data)?;

        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted_data = cipher.encrypt(&nonce.into(), data.as_bytes())?;

        Ok(EncryptedData {
            enc_data: encrypted_data,
            nonce: nonce.into(),
            key_id: self.id,
            _phantom: PhantomData
        })
    }

    fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T, Error> {
        if !self.can_decrypt(data) {
            return Err(Error::IncorrectKey)
        }

        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let decrypted_data = cipher.decrypt(&data.nonce.into(), data.enc_data.as_slice())?;

        let data = serde_json::from_slice(&decrypted_data)?;
        Ok(data)
    }
}
