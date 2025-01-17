use crate::{database::{Database, record_types::EncryptedKeyRecord, Repository}, hash_password, nonce_counter::NonceCounter};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit},
};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::Error;

use std::marker::PhantomData;

mod symmetric_key;
mod encrypted_key;
mod secure_key;

pub(crate) use symmetric_key::SymmetricKey;
pub(crate) use encrypted_key::EncryptedKey;
pub(crate) use secure_key::SecureKey;

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

trait Cipher {
    fn encrypt<T: Serialize + DeserializeOwned>(&self, data: &T) -> Result<EncryptedData<T>, Error>;

    fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T, Error>;
}
