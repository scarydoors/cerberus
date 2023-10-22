use argon2::Argon2;
use hkdf::Hkdf;
use zeroize::Zeroizing;
use sha2::Sha256;

use super::types::{Cipher, Mac};
use super::key::Key;
use super::KeyError;

pub struct KeyPair {
    cipher_key: Key<Cipher>,
    mac_key: Key<Mac>,
}

type Result<T> = std::result::Result<T, KeyError>;

impl KeyPair {
    const ENCRYPTION_KEY_INFO: &[u8] = b"encryption_key";
    const MAC_KEY_INFO: &[u8] = b"mac_key";

    pub fn new(cipher_key: &[u8], mac_key: &[u8]) -> Result<Self> {
        Ok(Self {
            cipher_key: Key::new(cipher_key)?,
            mac_key: Key::new(mac_key)?,
        })
    }

    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self> {
        let argon2 = Argon2::default();
        let mut ikm = Zeroizing::new(vec![0u8; 32]);
        argon2.hash_password_into(password.as_bytes(), salt, ikm.as_mut_slice())?;
        Self::from_ikm(&ikm[..])
    }

    pub fn from_ikm(ikm: &[u8]) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(None, ikm);

        let mut keys = Zeroizing::new(vec![0u8; 64]);
        let (encryption_key, mac_key) = keys.split_at_mut(32);

        hkdf.expand(Self::ENCRYPTION_KEY_INFO, encryption_key)?;
        hkdf.expand(Self::MAC_KEY_INFO, mac_key)?;

        Ok(Self::new(encryption_key, mac_key)?)
    }

    pub fn mac_key(&self) -> &Key<Mac> {
        &self.mac_key
    }

    pub fn cipher_key(&self) -> &Key<Cipher> {
        &self.cipher_key
    }
}
