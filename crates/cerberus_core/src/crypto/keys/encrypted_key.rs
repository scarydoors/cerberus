use zeroize::Zeroizing;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::key::{CipherError, Key};
use super::types::{Cipher, KeyState};

#[derive(Deserialize, Serialize, Debug)]
pub struct EncryptedKey<T: KeyState> {
    key: Vec<u8>,
    nonce: Vec<u8>,
    _kind: PhantomData<T>,
}

impl<T: KeyState> EncryptedKey<T> {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            key: key.into(),
            nonce: nonce.into(),
            _kind: PhantomData,
        }
    }

    pub fn new_random(cipher_key: &Key<Cipher>) -> Result<Self, CipherError> {
        let key = Key::new_random();
        key.try_to_encrypted_key(cipher_key)
    }

    pub fn try_to_key(&self, cipher_key: &Key<Cipher>) -> Result<Key<T>, CipherError> {
        let decrypted_key = Zeroizing::new(cipher_key.decrypt(&self.nonce, &self.key)?);
        Ok(Key::new(decrypted_key.as_slice()))
    }
}
