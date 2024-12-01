use std::path::Path;

use rand::rngs::OsRng;
use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2,
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305, XNonce
};

use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};

mod store;
mod nonce_counter;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unable to create database: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("unable to hash password")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("unable to encrypt data")]
    EncryptionFailed(#[from] chacha20poly1305::Error)
}

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub async fn create_database(filename: impl AsRef<Path>) -> Result<(), Error> {
    let options = SqliteConnectOptions::new()
        .filename(filename)
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(options).await?;

    MIGRATOR
        .run(&pool)
        .await.map_err(|err| sqlx::Error::from(err).into())
}

pub async fn create_master_encryption_key(pool: &SqlitePool, password: &[u8]) -> Result<(), Error> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash_data = Argon2::default().hash_password(password, &salt).unwrap();

    let key = password_hash_data.hash.unwrap();

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let master_key = XChaCha20Poly1305::generate_key(&mut OsRng);


    let master_key_enc = cipher.encrypt(&nonce, master_key.as_slice())?;
    let nonce_slice = nonce.as_slice();

    sqlx::query!(
        "INSERT INTO keys (encrypted_key, nonce) VALUES (?, ?)",
        master_key_enc,
        nonce_slice
    )
        .fetch_all(pool)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn can_create_master_encryption_key_in_database(pool: SqlitePool) {
        let password = b"what the hell man";

        create_master_encryption_key(&pool, password).await.unwrap();
    }
}
