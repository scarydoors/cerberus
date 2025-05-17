use std::marker::PhantomData;

use argon2::{
    password_hash::{PasswordHasher, Salt, SaltString},
    Argon2,
};
use chacha20poly1305::{aead::Aead, AeadCore, KeyInit, XChaCha20Poly1305};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod secret;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("encryption failed: {0}")]
    Encryption(#[from] chacha20poly1305::Error),

    #[error("hashing failed: {0}")]
    Hashing(#[from] argon2::password_hash::Error),
}

pub trait Cipher {
    fn encrypt<T: Serialize + DeserializeOwned>(&self, data: &T) -> Result<EncryptedData<T>>;
    fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T>;
}

type Nonce = [u8; 24];

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedData<T: Serialize + DeserializeOwned> {
    data: Vec<u8>,
    nonce: Nonce,
    _phantom: PhantomData<T>,
}

pub struct SymmetricKey {
    key: Vec<u8>,
}

impl SymmetricKey {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
        }
    }

    pub fn generate(rng: impl CryptoRng + RngCore) -> Self {
        let key = XChaCha20Poly1305::generate_key(rng);
        Self {
            key: key.to_vec(),
        }
    }

    pub fn from_password(password: &[u8], salt: &str) -> Self {
        Self {
            key: hash_password(password, salt)
        }
    }
}

impl Cipher for SymmetricKey {
    fn encrypt<T: Serialize + DeserializeOwned>(
        &self,
        data: &T,
    ) -> Result<EncryptedData<T>> {
        let data = serde_json::to_string(&data)?;

        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted_data = cipher.encrypt(&nonce.into(), data.as_bytes())?;

        Ok(EncryptedData {
            data: encrypted_data,
            nonce: nonce.into(),
            _phantom: PhantomData,
        })
    }

    fn decrypt<T: Serialize + DeserializeOwned>(
        &self,
        encrypted_data: &EncryptedData<T>,
    ) -> Result<T> {
        let cipher = XChaCha20Poly1305::new(self.key.as_slice().into());
        let decrypted_data = cipher.decrypt(&encrypted_data.nonce.into(), encrypted_data.data.as_slice())?;

        let data = serde_json::from_slice(&decrypted_data)?;
        Ok(data)
    }
}

pub fn generate_salt() -> String {
    SaltString::generate(&mut OsRng).to_string()
}

pub fn hash_password(password: &[u8], salt: &str) -> Vec<u8> {
    let salt = Salt::from_b64(salt).expect("salt is the correct format");
    let password_hash_data = Argon2::default().hash_password(password, salt).unwrap();

    let key = password_hash_data
        .hash
        .expect("hash_password was successful");

    key.as_bytes().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
