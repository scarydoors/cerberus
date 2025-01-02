use std::path::Path;

use chrono::NaiveDateTime;
use sqlx::{sqlite::SqliteConnectOptions, types::Json, SqlitePool};

use crate::{
    symmetric_key::{EncryptedData, SymmetricKey}, vault::Vault, Error
};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Default)]
pub(crate) struct VaultRecord {
    id: i64,
    name: String,
    salt: String,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl VaultRecord {
    pub fn to_vault(&self, database: Database) -> Vault {
        Vault::new(
            self.id,
            &self.name,
            &self.salt,
            self.created_at.and_utc(),
            self.updated_at.and_utc(),
            database
        )
    }
}

pub(crate) struct KeyRecord {
    pub(crate) id: i64,
    key_encrypted_data: Json<EncryptedData<Vec<u8>>>,
    next_nonce: Vec<u8>,
    vault_id: i64
}

impl KeyRecord {
    pub(crate) fn try_to_symmetric_key(&self, parent_key: &SymmetricKey, database: Option<Database>) -> Result<SymmetricKey, Error> {
        let decrypted_key = parent_key.decrypt(&self.key_encrypted_data)?;

        Ok(SymmetricKey::new(&decrypted_key, Some(&self.next_nonce), Some(self.id), self.vault_id, database)?)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Database {
    pool: SqlitePool
}

impl Database {
    pub(crate) async fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);

        let pool = SqlitePool::connect_with(options).await?;

        MIGRATOR
            .run(&pool)
            .await.map_err(|err| sqlx::Error::from(err))?;

        Ok(Self {
            pool
        })
    }

    pub(crate) fn from_pool(pool: SqlitePool) -> Self {
        Self {
            pool
        }
    }

    pub(crate) async fn store_vault(&self, name: &str, salt: &str) -> Result<VaultRecord, Error> {
        let vault_record = sqlx::query_as!(
            VaultRecord,
            "INSERT INTO vaults(name, salt) VALUES (?, ?) RETURNING *",
            name,
            salt
        )
            .fetch_one(&self.pool)
            .await?;

        Ok(vault_record)
    }

    pub(crate) async fn store_key(&self, key: &EncryptedData<Vec<u8>>, next_nonce: &[u8], vault_id: i64) -> Result<KeyRecord, Error> {
        let serialized_key = serde_json::to_string(key)?;
        let key_record = sqlx::query_as!(
            KeyRecord,
            "INSERT INTO keys(key_encrypted_data, next_nonce, vault_id)
            VALUES (?, ?, ?)
            RETURNING id, key_encrypted_data as 'key_encrypted_data: Json<EncryptedData<Vec<u8>>>', next_nonce, vault_id",
            serialized_key,
            next_nonce,
            vault_id
        )
            .fetch_one(&self.pool)
            .await?;

        Ok(key_record)
    }

    pub(crate) async fn update_key_next_nonce(&self, key_id: i64, next_nonce: &[u8]) -> Result<bool, Error> {
        let res = sqlx::query!(
            "UPDATE keys SET next_nonce = ? WHERE id = ?",
            next_nonce,
            key_id
        )
            .execute(&self.pool)
            .await?;

        Ok(res.rows_affected() > 0)
    }

    pub(crate) async fn find_vault_key(&self, vault_id: i64) -> Result<Option<KeyRecord>, Error> {
        let key_record = sqlx::query_as!(
            KeyRecord,
            "SELECT id, key_encrypted_data as 'key_encrypted_data: Json<EncryptedData<Vec<u8>>>', next_nonce, vault_id
            FROM keys
            WHERE vault_id = ? AND key_encrypted_data->>'key_id' IS NULL",
            vault_id
        )
            .fetch_optional(&self.pool)
            .await?;

        Ok(key_record)
    }
}
