use std::path::Path;

use argon2::{
    password_hash::{PasswordHasher, Salt, SaltString},
    Argon2,
};
use rand::rngs::OsRng;

use chacha20poly1305::aead::KeyInit;

use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};

pub mod item;
pub mod store;
pub mod vault;

mod crypto;
mod database;
mod nonce_counter;

pub use store::*;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unable to create database: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("unable to hash password")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("unable to encrypt data")]
    EncryptionFailed(#[from] chacha20poly1305::Error),

    #[error("unable to increment nonce")]
    NonceError(#[from] nonce_counter::NonceError),

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

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub async fn create_database(filename: impl AsRef<Path>) -> Result<(), Error> {
    let options = SqliteConnectOptions::new()
        .filename(filename)
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(options).await?;

    MIGRATOR
        .run(&pool)
        .await
        .map_err(|err| sqlx::Error::from(err).into())
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

//pub async fn create_master_encryption_key(pool: &SqlitePool, password: &[u8]) -> Result<(), Error> {
//    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
//
//    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
//    let master_key = XChaCha20Poly1305::generate_key(&mut OsRng);
//
//
//    let master_key_enc = cipher.encrypt(&nonce, master_key.as_slice())?;
//    let nonce_slice = nonce.as_slice();
//
//    sqlx::query!(
//        "INSERT INTO keys (encrypted_key, nonce) VALUES (?, ?)",
//        master_key_enc,
//        nonce_slice
//    )
//        .fetch_all(pool)
//        .await?;
//
//    Ok(())
//}
