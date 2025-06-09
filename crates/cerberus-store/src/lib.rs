use argon2::{
    Argon2,
    password_hash::{PasswordHasher, Salt, SaltString},
};
use rand::rngs::OsRng;

pub mod item;
pub mod store;
pub mod vault;

mod crypto;
mod database;

pub use store::*;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unable to create database: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("unable to hash password")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("unable to encrypt data")]
    EncryptionFailed(#[from] chacha20poly1305::Error),

    #[error("malformed data in store")]
    DeserializationError(#[from] serde_json::Error),

    #[error("incorrect symmetric key used for decryption")]
    IncorrectKey,

    #[error("key does not exist in database")]
    KeyDoesNotExist,

    #[error("cannot update key in store")]
    CannotUpdateKey,

    #[error("the store is locked")]
    Locked,

    #[error("the profile already exists")]
    ProfileAlreadyExists,

    #[error("store needs to be initialized using the initialize_profile method")]
    StoreNotInitialized,

    #[error("store already unlocked")]
    StoreAlreadyUnlocked,

    #[error("incorrect password")]
    IncorrectPassword,
}

fn generate_salt() -> String {
    SaltString::generate(&mut OsRng).to_string()
}

fn hash_password(password: &[u8], salt: &str) -> Vec<u8> {
    let salt = Salt::from_b64(salt).expect("salt is the correct format");
    let password_hash_data = Argon2::default().hash_password(password, salt).unwrap();

    let key = password_hash_data
        .hash
        .expect("hash_password was successful");

    key.as_bytes().to_owned()
}
