use crate::{database::{Database, EncryptedKeyRecord}, hash_password, nonce_counter::NonceCounter};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit},
};
use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::Error;

use std::marker::PhantomData;

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

#[derive(Debug)]
pub struct SecureKey {
    symmetric_key: Option<SymmetricKey>,
    encrypted_key: EncryptedKeyRecord,
}

impl SecureKey {
    pub fn new(encrypted_key: EncryptedKeyRecord) -> Self {
        Self {
            encrypted_key,
            symmetric_key: None
        }
    }

    pub fn unlock(&mut self, parent_key: &SymmetricKey, database: Option<Database>) -> Result<(), Error> {
        let symmetric_key = self.encrypted_key.try_to_symmetric_key(parent_key, database)?;

        self.symmetric_key = Some(symmetric_key);

        Ok(())
    }

    pub fn lock(&mut self) -> Result<(), Error> {
        self.symmetric_key = None;

        Ok(())
    }

    pub fn decrypt<T: DeserializeOwned + Serialize>(&self, data: EncryptedData<T>) -> Result<T, Error> {
        self.symmetric_key.as_ref().ok_or_else(|| Error::Locked)?.decrypt(&data)
    }

    pub async fn encrypt<T: DeserializeOwned + Serialize>(&mut self, data: T) -> Result<EncryptedData<T>, Error> {
        self.symmetric_key.as_mut().ok_or_else(|| Error::Locked)?.encrypt(&data).await
    }
}

#[derive(Debug)]
pub(crate) struct SymmetricKey {
    id: Option<i64>,
    key: Vec<u8>,
    next_nonce: NonceCounter,
    database: Option<Database>
}

impl SymmetricKey {
    pub fn new(key: &[u8], next_nonce: Option<&[u8]>, id: Option<i64>, database: Option<Database>) -> Result<Self, Error> {
        let nonce_counter = match next_nonce {
            Some(next_nonce) => NonceCounter::new(next_nonce)?,
            None => NonceCounter::default()
        };

        Ok(Self {
            id,
            key: key.to_vec(),
            next_nonce: nonce_counter,
            database
        })
    }

    pub fn generate(rng: impl CryptoRng + RngCore, database: Option<Database>) -> Self {
        let key = XChaCha20Poly1305::generate_key(rng);

        Self {
            id: None,
            key: key.to_vec(),
            next_nonce: NonceCounter::default(),
            database
        }
    }

    pub fn from_password(password: &str, salt: &str) -> Self {
        let key = hash_password(password.as_bytes(), salt);

        Self {
            id: None,
            key,
            next_nonce: NonceCounter::default(),
            database: None
        }
    }

    pub async fn encrypt<T: Serialize + DeserializeOwned>(&mut self, data: &T) -> Result<EncryptedData<T>, Error> {
        let data = serde_json::to_string(&data)?;

        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let nonce = self.next_nonce.get_value();
        let encrypted_data = cipher.encrypt(&nonce.into(), data.as_bytes())?;

        self.next_nonce.increment()?;
        self.maybe_update_next_nonce().await?;

        Ok(EncryptedData {
            enc_data: encrypted_data,
            nonce,
            key_id: self.id,
            _phantom: PhantomData
        })
    }

    pub fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T, Error> {
        if !self.can_decrypt(data) {
            return Err(Error::IncorrectKey)
        }

        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let decrypted_data = cipher.decrypt(&data.nonce.into(), data.enc_data.as_slice())?;

        let data = serde_json::from_slice(&decrypted_data)?;
        Ok(data)
    }

    pub(crate) fn can_decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> bool {
        self.id == data.key_id
    }

    pub(crate) fn id(&self) -> Option<i64> {
        self.id
    }

    pub(crate) async fn store(&mut self, parent_key: &mut SymmetricKey) -> Result<(), Error> {
        let encrypted_key = parent_key.encrypt(&self.key).await?;

        let key_record = self.database
            .as_ref()
            .expect("store can only be called when the key has access to the database")
            .store_key(&encrypted_key, &self.next_nonce.get_value())
            .await?;

        self.id = Some(key_record.id);

        Ok(())
    }

    async fn maybe_update_next_nonce(&self) -> Result<(), Error> {
        if let (Some(database), Some(id)) = (self.database.as_ref(), self.id) {
            database.update_key_next_nonce(id, &self.next_nonce.get_value()).await?;
        }

        Ok(())
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
