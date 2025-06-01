use std::marker::PhantomData;

use argon2::{
    password_hash::{PasswordHasher, Salt, SaltString},
    Argon2,
};
use chacha20poly1305::{aead::Aead, AeadCore, KeyInit, XChaCha20Poly1305};
use mac::HmacSha256;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use cerberus_secret::{SecretSlice, ExposeSecret};
use cerberus_serde::{base64, base64_expose_secret};

pub mod mac;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("encryption failed: {0}")]
    Encryption(#[from] chacha20poly1305::Error),

    #[error("hashing failed: {0}")]
    Hashing(#[from] argon2::password_hash::Error),

    #[error("hmac error: {0}")]
    Hmac(#[from] hmac::digest::MacError),
}

pub trait Cipher {
    fn encrypt<T: Serialize>(&self, data: &T) -> Result<EncryptedData<T>>;
    fn decrypt<T: DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct Nonce(
    #[serde(with="base64")]
    [u8; 24]
);

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData<T> {
    #[serde(with="base64")]
    encrypted_data: Vec<u8>,
    key_id: KeyIdentifier,
    nonce: Nonce,
    #[serde(skip)]
    _phantom: PhantomData<T>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
#[serde(rename_all = "snake_case")]
pub enum KeyIdentifier {
    Local,
    Uuid(Uuid),
    Derived(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymmetricKey {
    #[serde(with = "base64_expose_secret")]
    key: SecretSlice<u8>,
    id: KeyIdentifier,
}

impl SymmetricKey {
    pub fn new(key: Vec<u8>, id: KeyIdentifier) -> Self {
        Self {
            key: key.into(),
            id
        }
    }

    pub fn generate(rng: impl CryptoRng + RngCore, id: KeyIdentifier) -> Self {
        let key = XChaCha20Poly1305::generate_key(rng);
        Self {
            key: key.to_vec().into(),
            id
        }
    }
}

impl Cipher for SymmetricKey {
    fn encrypt<T: Serialize>(
        &self,
        data: &T,
    ) -> Result<EncryptedData<T>> {
        let data = serde_json::to_string(&data)?;

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

    fn decrypt<T: DeserializeOwned>(
        &self,
        encrypted_data: &EncryptedData<T>,
    ) -> Result<T> {
        let cipher = XChaCha20Poly1305::new(self.key.expose_secret().into());
        let decrypted_data = cipher.decrypt(&encrypted_data.nonce.0.into(), encrypted_data.encrypted_data.as_slice())?;

        let data = serde_json::from_slice(&decrypted_data)?;
        Ok(data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    data: EncryptedData<T>,
    dek: EncryptedData<SymmetricKey>
}

impl<T> Envelope<T>
where T: Serialize + DeserializeOwned {
    pub fn seal(kek: &impl Cipher, data: &T) -> Result<Self> {
        let dek = SymmetricKey::generate(&mut OsRng, KeyIdentifier::Local);
        let data = dek.encrypt(data)?;
        let dek_encrypted = kek.encrypt(&dek)?;

        Ok(Self {
            data,
            dek: dek_encrypted
        })
    }

    pub fn open(&self, kek: &impl Cipher) -> Result<T> {
        let dek: SymmetricKey = kek.decrypt(&self.dek)?;
        let data = dek.decrypt(&self.data)?;

        Ok(data)
    }
}


pub fn generate_salt() -> String {
    SaltString::generate(&mut OsRng).to_string()
}

pub fn hash_password(password: &[u8], salt: &str) -> SecretSlice<u8> {
    let salt = Salt::from_b64(salt).expect("salt is the correct format");
    let password_hash_data = Argon2::default().hash_password(password, salt).unwrap();

    let key = password_hash_data
        .hash
        .expect("hash_password was successful");

    key.as_bytes().to_owned().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct SecretOwned {
        data: String
    }

    #[test]
    fn it_works() {
        let master_key = SymmetricKey::generate(&mut OsRng, KeyIdentifier::Derived("coolkey".into()));

        let envelope = Envelope::seal(&master_key, &SecretOwned { data: String::from("what") }).unwrap();

        let decrypted = envelope.open(&master_key).unwrap();
    }
}
