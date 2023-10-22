use thiserror::Error;
use super::random_bytes;
use rand::rngs::OsRng;

pub mod encrypted_key;
pub mod encrypted_key_pair;
pub mod key;
pub mod key_pair;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("error using cipher: {0}")]
    CipherError(#[from] chacha20poly1305::Error),
    #[error("error when initializing hmac instance: {0}")]
    HmacError(#[from] hmac::digest::InvalidLength),
    #[error("error when hashing password: {0}")]
    HashError(#[from] argon2::Error),
    #[error("error when deriving secret keys from password: {0}")]
    DeriveError(#[from] hkdf::InvalidLength),
}

pub fn generate_nonce() -> Vec<u8> {
    random_bytes(&mut OsRng, 24)
}

pub mod types {
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
    use hmac::Hmac;
    use sha2::Sha256;
    use super::KeyError;
    
    pub struct Mac(pub(crate) Hmac<Sha256>);

    pub struct Cipher(pub(crate) XChaCha20Poly1305);

    pub trait KeyState: Sized {
        const KEY_SIZE: usize;
        fn with_key(key: &[u8]) -> Result<Self, KeyError>;
    }
    
    type HmacSha256 = Hmac<Sha256>;
    impl KeyState for Mac {
        const KEY_SIZE: usize = 32;

        fn with_key(key: &[u8]) -> Result<Self, KeyError> {
            Ok(Self(HmacSha256::new_from_slice(key)?))
        }
    }
    impl KeyState for Cipher {
        const KEY_SIZE: usize = 32;
        fn with_key(key: &[u8]) -> Result<Self, KeyError> {
            Ok(Self(XChaCha20Poly1305::new(key.into())))
        }
    }
}

pub use encrypted_key::*;
pub use encrypted_key_pair::*;
pub use key::*;
pub use key_pair::*;
