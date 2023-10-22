use super::encrypted_key::EncryptedKey;
use super::key::{CipherError, Key};
use super::key_pair::KeyPair;
use super::types::{Cipher, Mac};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct EncryptedKeyPair {
    cipher_key: EncryptedKey<Cipher>,
    mac_key: EncryptedKey<Mac>,
}

type Result<T> = std::result::Result<T, CipherError>;

impl EncryptedKeyPair {
    pub fn new(cipher_key: EncryptedKey<Cipher>, mac_key: EncryptedKey<Mac>) -> Self {
        Self {
            cipher_key,
            mac_key,
        }
    }

    pub fn new_random(cipher_key: &Key<Cipher>) -> Result<Self> {
        Ok(Self::new(
            EncryptedKey::new_random(&cipher_key)?,
            EncryptedKey::new_random(&cipher_key)?,
        ))
    }

    pub fn try_to_key_pair(&self, cipher_key: &Key<Cipher>) -> Result<KeyPair> {
        Ok(KeyPair::new(
            &self.cipher_key.try_to_key(cipher_key)?,
            &self.mac_key.try_to_key(cipher_key)?,
        ))
    }
}
