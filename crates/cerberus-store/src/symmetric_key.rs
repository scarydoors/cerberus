use crate::{database::{Database, record_types::EncryptedKeyRecord, Repository}, hash_password, nonce_counter::NonceCounter};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit},
};
use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::Error;

use std::marker::PhantomData;

impl EncryptedKeyRecord {
    pub(crate) fn into_encrypted_key(self) -> EncryptedKey {
        EncryptedKey::new(
            self.id,
            self.key_encrypted_data.0,
            self.next_nonce.try_into().expect("nonce is 24 bytes long")
        )
    }
}

pub(crate) struct EncryptedKey {
    id: i64,
    key_encrypted_data: EncryptedData<Vec<u8>>,
    next_nonce: [u8; 24]
}

impl EncryptedKey {
    pub(crate) fn new(id: i64, key_encrypted_data: EncryptedData<Vec<u8>>, next_nonce: [u8; 24]) -> Self {
        Self {
            id,
            key_encrypted_data,
            next_nonce
        }
    }

    pub(crate) fn try_to_symmetric_key(&self, parent_key: &SymmetricKey) -> Result<SymmetricKey, Error> {
        let decrypted_key = parent_key.decrypt(&self.key_encrypted_data)?;
        Ok(SymmetricKey::new(&decrypted_key, Some(&self.next_nonce), Some(self.id))?)
    }
}

impl EncryptedKeyRecord {
    pub(crate) fn try_to_symmetric_key(&self, parent_key: &SymmetricKey) -> Result<SymmetricKey, Error> {
        let decrypted_key = parent_key.decrypt(&self.key_encrypted_data)?;

        Ok(SymmetricKey::new(&decrypted_key, Some(&self.next_nonce), Some(self.id))?)
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

trait DatabaseBackedCipher {
    async fn encrypt<T: Serialize + DeserializeOwned, R: Repository>(&mut self, data: &T, repo: Option<&mut R>) -> Result<EncryptedData<T>, Error>;

    fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T, Error>;
}

#[derive(Debug)]
pub struct SecureKey {
    decrypted_key: Option<SymmetricKey>,
    encrypted_key: EncryptedKeyRecord,
}

impl SecureKey {
    pub fn new(encrypted_key: EncryptedKeyRecord) -> Self {
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

impl DatabaseBackedCipher for SecureKey {
    async fn encrypt<T: Serialize + DeserializeOwned, R: Repository>(&mut self, data: &T, repo: Option<&mut R>) -> Result<EncryptedData<T>, Error> {
        self.decrypted_key.as_mut().ok_or_else(|| Error::Locked)?.encrypt(data, repo).await
    }

    fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T, Error> {
        self.decrypted_key.as_ref().ok_or_else(|| Error::Locked)?.decrypt(data)
    }
}

#[derive(Debug)]
pub(crate) struct SymmetricKey {
    id: Option<i64>,
    key: Vec<u8>,
    next_nonce: NonceCounter,
}

impl SymmetricKey {
    pub fn new(key: &[u8], next_nonce: Option<&[u8]>, id: Option<i64>) -> Result<Self, Error> {
        let nonce_counter = match next_nonce {
            Some(next_nonce) => NonceCounter::new(next_nonce)?,
            None => NonceCounter::default()
        };

        Ok(Self {
            id,
            key: key.to_vec(),
            next_nonce: nonce_counter,
        })
    }

    pub fn generate(rng: impl CryptoRng + RngCore) -> Self {
        let key = XChaCha20Poly1305::generate_key(rng);

        Self {
            id: None,
            key: key.to_vec(),
            next_nonce: NonceCounter::default(),
        }
    }

    pub fn from_password(password: &[u8], salt: &str) -> Self {
        let key = hash_password(password, salt);

        Self {
            id: None,
            key,
            next_nonce: NonceCounter::default(),
        }
    }

    pub(crate) fn can_decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> bool {
        self.id == data.key_id
    }

    pub(crate) fn id(&self) -> Option<i64> {
        self.id
    }

    pub(crate) async fn store<K: DatabaseBackedCipher, R: Repository>(&mut self, parent_key: &mut K, repo: &mut R) -> Result<(), Error> {
        let encrypted_key = parent_key.encrypt(&self.key, Some(repo)).await?;

        let key_record = repo
            .store_key(&encrypted_key, &self.next_nonce.get_value())
            .await?;

        self.id = Some(key_record.id);

        Ok(())
    }

    async fn maybe_update_next_nonce<R: Repository>(&mut self, repo: Option<&mut R>) -> Result<(), Error> {
        if let Some(id) = self.id {
            let repo = repo.expect("repo is present because the key has state in the database which must be updated");
            repo.update_key_next_nonce(id, &self.next_nonce.get_value()).await?;
        }

        Ok(())
    }
}

impl DatabaseBackedCipher for SymmetricKey {
    async fn encrypt<T: Serialize + DeserializeOwned, R: Repository>(&mut self, data: &T, repo: Option<&mut R>) -> Result<EncryptedData<T>, Error> {
        let data = serde_json::to_string(&data)?;

        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let nonce = self.next_nonce.get_value();
        let encrypted_data = cipher.encrypt(&nonce.into(), data.as_bytes())?;

        self.next_nonce.increment()?;
        self.maybe_update_next_nonce(repo).await?;

        Ok(EncryptedData {
            enc_data: encrypted_data,
            nonce,
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

#[cfg(test)]
mod test {
    use super::*;

    use rand::rngs::OsRng;
    use sqlx::SqlitePool;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct TestStruct(i64);

    #[tokio::test]
    async fn can_encrypt_and_decrypt_data() {
        let mut symmetric_key = SymmetricKey::generate(&mut OsRng, 0, None);

        let plain_data = TestStruct(500000000);

        let nonce_before_encrypting = symmetric_key.next_nonce.get_value();
        let encrypted_data = symmetric_key.encrypt(&plain_data).await.unwrap();

        let decrypted_data = symmetric_key.decrypt(&encrypted_data).unwrap();

        assert_ne!(nonce_before_encrypting, symmetric_key.next_nonce.get_value());
        assert_eq!(decrypted_data, plain_data);
    }

    // todo: write test which tests whether nonce is reflected in database
}
