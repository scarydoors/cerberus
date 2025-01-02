use crate::nonce_counter::NonceCounter;
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

pub(crate) struct KeyRecord {
    id: Option<i64>,
    key_encrypted_data: EncryptedData<Vec<u8>>,
    next_nonce: [u8; 24],
    vault_id: i64
}

impl KeyRecord {
    pub(crate) fn to_symmetric_key(&self, parent_key: &SymmetricKey) -> Result<SymmetricKey, Error> {
        let decrypted_key = parent_key.decrypt(&self.key_encrypted_data)?;

        Ok(SymmetricKey::new(&decrypted_key, Some(&self.next_nonce), Some(self.id), self.vault_id))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SymmetricKey {
    id: Option<i64>,
    key: Vec<u8>,
    next_nonce: NonceCounter,
    vault_id: i64,
}

impl SymmetricKey {
    pub fn new(key: &[u8], next_nonce: Option<&[u8]>, id: Option<i64>, vault_id: i64) -> Self {
        let nonce_counter = match next_nonce {
            Some(next_nonce) => NonceCounter::new(next_nonce),
            None => NonceCounter::default()
        };

        Self {
            id,
            key: key.to_vec(),
            next_nonce: nonce_counter,
            vault_id
        }
    }

    pub fn new_with_rng(mut rng: impl CryptoRng + RngCore, id: Option<i64>, vault_id: i64) -> Self {
        let key = XChaCha20Poly1305::generate_key(rng);

        Self {
            id,
            key: key.to_vec(),
            next_nonce: NonceCounter::default(),
            vault_id,
        }
    }

    pub fn encrypt<T: Serialize + DeserializeOwned>(&mut self, data: &T) -> Result<EncryptedData<T>, Error> {
        let data = serde_json::to_string(&data)?;

        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let nonce = self.next_nonce.get_value();
        let encrypted_data = cipher.encrypt(&nonce.into(), data.as_bytes())?;
        self.next_nonce.increment()?;

        Ok(EncryptedData {
            enc_data: encrypted_data,
            nonce,
            key_id: self.id,
            _phantom: PhantomData
        })
    }

    pub fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T, Error> {
        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let decrypted_data = cipher.decrypt(&data.nonce.into(), data.enc_data.as_slice())?;

        let data = serde_json::from_slice(&decrypted_data)?;
        Ok(data)
    }

    pub(crate) fn to_key_record(&self, parent_key: &mut SymmetricKey) -> Result<KeyRecord, Error> {
        let encrypted_key = parent_key.encrypt(&self.key)?;

        Ok(KeyRecord {
            id: self.id,
            next_nonce: self.next_nonce.get_value(),
            key_encrypted_data: encrypted_key,
            vault_id: self.vault_id
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::rngs::OsRng;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct TestStruct(i64);

    #[test]
    fn can_encrypt_and_decrypt_data() {
        let mut symmetric_key = SymmetricKey::new_with_rng(&mut OsRng, None, 0);

        let plain_data = TestStruct(500000000);

        let nonce_before_encrypting = symmetric_key.next_nonce.get_value();
        let encrypted_data = symmetric_key.encrypt(&plain_data).unwrap();

        let decrypted_data = symmetric_key.decrypt(&encrypted_data).unwrap();

        assert_eq!(decrypted_data, plain_data);
    }
}
