use std::marker::PhantomData;

use crate::{
    primitive::Cipher,
    secret::{ExposeSecret, Secret},
};
use rand::{CryptoRng, RngCore};
use argon2::{Argon2, PasswordHasher};
use hkdf::{Hkdf, InvalidLength};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use chacha20poly1305::aead;

pub type SecretBox = Secret<Box<[u8]>>;

pub struct Keychain {
    mac_key: SecretBox,
    cipher_key: SecretBox,
}

impl Keychain {
    const MAC_INFO: &[u8] = b"mac_key_info";
    const CIPHER_INFO: &[u8] = b"cipher_key_info";

    pub fn new(key: &[u8]) -> Self {
        Self {
            mac_key: hkdf(Self::MAC_INFO, key, None).unwrap(),
            cipher_key: hkdf(Self::CIPHER_INFO, key, None).unwrap(),
        }
    }

    pub fn expose_mac_key(&self) -> &[u8] {
        self.mac_key.expose_secret()
    }

    pub fn expose_cipher_key(&self) -> &[u8] {
        self.cipher_key.expose_secret()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData<T: Serialize + DeserializeOwned> {
    ciphertext: Vec<u8>,
    data_len: usize,
    _kind: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> EncryptedData<T> {
    pub fn new(value: T, cipher: &mut Cipher) -> Result<Self, aead::Error> {
        let data = bincode::serialize(&value).unwrap();
        let ciphertext = cipher.encrypt(&data)?;
        Ok(Self {
            ciphertext,
            data_len: data.len(),
            _kind: PhantomData
        })
    }

    pub fn decrypt(&self, cipher: &Cipher) -> Result<T, aead::Error> {
        let data = cipher.decrypt(&self.ciphertext, self.data_len)?;
        let value = bincode::deserialize(&data.expose_secret()).unwrap();
        Ok(value)
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedKey(Vec<u8>);
impl EncryptedKey {
    const KEY_SIZE: usize = 32;
    pub fn new(key: &[u8], cipher: &mut Cipher) -> Result<Self, aead::Error> {
        Ok(Self(cipher.encrypt(key)?))
    }

    pub fn decrypt(&self, cipher: &Cipher) -> Result<SecretBox, aead::Error> {
        Ok(cipher.decrypt(&self.0, Self::KEY_SIZE)?)
    }
}

pub fn hkdf(info: &[u8], ikm: &[u8], salt: Option<&[u8]>) -> Result<SecretBox, InvalidLength> {
    let hkdf = Hkdf::<Sha256>::new(salt, &ikm);
    let mut key = vec![0u8, 32];
    hkdf.expand(info, &mut key)?;
    Ok(key.into_boxed_slice().into())
}

pub fn argon2(password: &[u8], salt: &[u8]) -> SecretBox {
    let argon2 = Argon2::default();
    let mut key = vec![0u8, 32];
    argon2.hash_password_into(password, salt, &mut key).unwrap();
    key.into_boxed_slice().into()
}

pub fn random_bytes(mut rng: impl CryptoRng + RngCore, length: usize) -> SecretBox {
    let mut result = vec![0u8; length];
    rng.fill_bytes(&mut result);
    result.into_boxed_slice().into()
}
