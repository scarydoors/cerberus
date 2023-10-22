use std::ops::Deref;

use crate::crypto::random_bytes;
use chacha20poly1305::aead::Aead;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use super::{
    encrypted_key::EncryptedKey,
    types::{Cipher, KeyState},
};

pub struct Key<State: KeyState> {
    key: Zeroizing<Box<[u8]>>,
    state: State,
}

pub type CipherError = chacha20poly1305::Error;
type Result<T> = std::result::Result<T, CipherError>;

impl<State: KeyState> Key<State> {
    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() == State::KEY_SIZE);
        let key = Zeroizing::new(Vec::from(key).into_boxed_slice());

        Self {
            // key will also be zeroized here
            state: State::with_key(&key),
            key,
        }
    }

    pub fn new_random() -> Self {
        let key =
            Zeroizing::new(Vec::from(random_bytes(&mut OsRng, State::KEY_SIZE)).into_boxed_slice());

        Self {
            state: State::with_key(&key),
            key,
        }
    }

    pub fn try_to_encrypted_key(&self, cipher_key: &Key<Cipher>) -> Result<EncryptedKey<State>> {
        let nonce = random_bytes(&mut OsRng, 24);

        Ok(EncryptedKey::new(
            &cipher_key.encrypt(&self.key, &nonce)?,
            &nonce,
        ))
    }
}

impl<T: KeyState> Deref for Key<T> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl Key<Cipher> {
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = &self.state.0;
        Ok(cipher.encrypt(nonce.into(), plaintext)?)
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = &self.state.0;
        Ok(cipher.decrypt(nonce.into(), ciphertext)?)
    }
}
