use std::marker::PhantomData;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, Salt, SaltString},
};
use cerberus_secret::{ExposeSecret, SecretSlice};
use cerberus_serde::base64;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use chacha20poly1305::KeyInit;

use uuid::Uuid;

pub mod kdf;
pub mod mac;
pub mod symmetric;

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
    fn encrypt<T: Serialize>(&self, data: &T) -> Result<EncryptedData<T>, CipherError>;
    fn decrypt<T: DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T, CipherError>;
}

#[derive(Error, Debug)]
pub enum CipherError {
    #[error(transparent)]
    KeyMismatch(#[from] KeyMismatchError),
    // below type is opaque because the serialization covers the sensitive data
    // and it is not desirable to reveal information about it in logs and such
    // through a potential error
    #[error("unable to serialize/deserialize sensitive data")]
    SerializationError,

    #[error("failed cipher operation")]
    OperationFailed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct Nonce(#[serde(with = "base64")] [u8; 24]);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData<T> {
    #[serde(with = "base64")]
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
    #[serde(serialize_with = "forbid_derived_serialization")]
    Derived {
        context: String,
        derived_from: Option<Box<KeyIdentifier>>,
    },
}

impl KeyIdentifier {
    pub fn local() -> Self {
        KeyIdentifier::Local
    }

    pub fn uuid() -> Self {
        KeyIdentifier::Uuid(Uuid::new_v4())
    }

    pub fn derived(context: String, derived_from: Option<KeyIdentifier>) -> Self {
        KeyIdentifier::Derived {
            context,
            derived_from: derived_from.map(Box::new),
        }
    }

    pub fn verify_identifier(&self, other_key_id: &KeyIdentifier) -> Result<(), KeyMismatchError> {
        if self == other_key_id {
            Ok(())
        } else {
            Err(KeyMismatchError {
                left: self.clone(),
                right: other_key_id.clone()
            })
        }
    }
}

#[derive(Error, Debug)]
#[error("key identifier mismatch, left: {left:?}, right: {right:?}")]
pub struct KeyMismatchError {
    left: KeyIdentifier,
    right: KeyIdentifier
}

fn forbid_derived_serialization<S: serde::Serializer>(
    _: &str,
    _: &Option<Box<KeyIdentifier>>,
    _serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    Err(serde::ser::Error::custom(SerializeDeriveKeyError))
}

#[derive(Error, Debug)]
#[error("derived keys must not be serialized")]
pub struct SerializeDeriveKeyError;

pub trait NewKey: Sized {
    const KEY_SIZE: usize;

    fn new_unchecked(key: SecretSlice<u8>, id: KeyIdentifier) -> Self;

    fn new(key: SecretSlice<u8>, id: KeyIdentifier) -> Result<Self, InvalidKeySizeError> {
        let key_len = key.expose_secret().len();
        if key_len == Self::KEY_SIZE {
            Ok(Self::new_unchecked(key, id))
        } else {
            Err(InvalidKeySizeError {
                actual: key_len,
                expected: Self::KEY_SIZE,
            })
        }
    }

    fn generate(mut rng: impl CryptoRng + RngCore, id: KeyIdentifier) -> Self {
        let mut key = vec![0u8; Self::KEY_SIZE];

        rng.fill_bytes(&mut key);

        Self::new_unchecked(key.into(), id)
    }
}

#[derive(thiserror::Error, Debug)]
#[error("invalid key length, expected: {expected}, actual: {actual}")]
pub struct InvalidKeySizeError {
    expected: usize,
    actual: usize
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
