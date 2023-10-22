use zeroize::Zeroizing;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::key::Key;
use super::types::{Cipher, KeyState};
use super::KeyError;

#[derive(Deserialize, Serialize, Debug)]
pub struct EncryptedKey<T: KeyState> {
    key: Box<[u8]>,
    nonce: Box<[u8]>,
    _kind: PhantomData<T>,
}

type Result<T> = std::result::Result<T, KeyError>;

impl<T: KeyState> EncryptedKey<T> {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            key: key.into(),
            nonce: nonce.into(),
            _kind: PhantomData,
        }
    }

    pub fn new_random(cipher_key: &Key<Cipher>) -> Result<Self> {
        let key = Key::new_random()?;
        Ok(key.try_to_encrypted_key(cipher_key)?)
    }

    pub fn try_to_key(&self, cipher_key: &Key<Cipher>) -> Result<Key<T>> {
        let decrypted_key = Zeroizing::new(cipher_key.decrypt(&self.nonce, &self.key)?);
        Ok(Key::new(decrypted_key.as_slice())?)
    }
}
