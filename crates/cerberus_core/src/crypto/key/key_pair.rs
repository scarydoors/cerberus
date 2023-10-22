use argon2::Argon2;
use hkdf::Hkdf;
use zeroize::Zeroizing;
use sha2::Sha256;
use thiserror::Error;

use crate::crypto::key::types::{Cipher, Mac};
use crate::crypto::key::Key;

pub struct KeyPair {
    cipher_key: Key<Cipher>,
    mac_key: Key<Mac>,
}

#[derive(Error, Debug)]
pub enum KeyPairError {
    #[error("error while hashing password: {0}")]
    HashError(#[from] argon2::Error),

    #[error("error while deriving keys: {0}")]
    DeriveError(#[from] hkdf::InvalidLength),
}

type Result<T> = std::result::Result<T, KeyPairError>;

impl KeyPair {
    const ENCRYPTION_KEY_INFO: &[u8] = b"encryption_key";
    const MAC_KEY_INFO: &[u8] = b"mac_key";

    pub fn new(cipher_key: &[u8], mac_key: &[u8]) -> Self {
        Self {
            cipher_key: Key::new(cipher_key),
            mac_key: Key::new(mac_key),
        }
    }

    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self> {
        let argon2 = Argon2::default();
        let mut ikm = Zeroizing::new(Vec::with_capacity(32));
        argon2.hash_password_into(password.as_bytes(), salt, ikm.as_mut_slice())?;
        Self::from_ikm(&ikm[..])
    }

    pub fn from_ikm(ikm: &[u8]) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(None, ikm);

        let mut keys = Zeroizing::new(Vec::with_capacity(64));
        let (encryption_key, mac_key) = keys.split_at_mut(32);

        hkdf.expand(&Self::ENCRYPTION_KEY_INFO, encryption_key)?;
        hkdf.expand(&Self::MAC_KEY_INFO, mac_key)?;

        Ok(Self::new(encryption_key, mac_key))
    }

    pub fn mac_key(&self) -> &Key<Mac> {
        &self.mac_key
    }

    pub fn cipher_key(&self) -> &Key<Cipher> {
        &self.cipher_key
    }
}
