use std::ops::Deref;
use chacha20poly1305::aead::Aead;
use hmac::{Hmac, Mac as HmacMac};
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::random_bytes;
use super::KeyError;

use super::types::Mac;
use super::{
    encrypted_key::EncryptedKey,
    types::{Cipher, KeyState},
};

pub struct Key<State: KeyState> {
    key: Zeroizing<Box<[u8]>>,
    state: State,
}

type Result<T> = std::result::Result<T, KeyError>;

impl<State: KeyState> Key<State> {
    pub fn new(key: &[u8]) -> Result<Self> {
        assert!(key.len() == State::KEY_SIZE);
        let key = Zeroizing::new(Vec::from(key).into_boxed_slice());

        Ok(Self {
            // key will also be zeroized here
            state: State::with_key(&key)?,
            key,
        })
    }

    pub fn new_random() -> Result<Self> {
        let key =
            Zeroizing::new(random_bytes(&mut OsRng, State::KEY_SIZE).into_boxed_slice());

        Ok(Self {
            state: State::with_key(&key)?,
            key,
        })
    }

    pub fn try_to_encrypted_key(&self, cipher_key: &Key<Cipher>) -> Result<EncryptedKey<State>> {
        let nonce = random_bytes(&mut OsRng, 24);

        Ok(EncryptedKey::new(
            &cipher_key.encrypt(&nonce, &self.key)?,
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

impl Key<Mac> {
    pub fn new_hmac(&self) -> Hmac<Sha256> {
        Hmac::new_from_slice(&self.key).expect("hmac key is correct length")
    }
}

// TODO: ADD MAC CONVENIENCE METHODS TOMORROW !!!!111!!1!
