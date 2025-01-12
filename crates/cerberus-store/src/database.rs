use std::pin::Pin;
use std::{cell::RefCell, future::Future, path::Path};

use chrono::NaiveDateTime;
use sqlx::{sqlite::SqliteConnectOptions, types::Json, Executor, Sqlite, SqlitePool, Transaction};
use sqlx::Error as SqlxError;

use crate::{
    symmetric_key::{EncryptedData, SymmetricKey}, vault::Vault, Error
};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub(crate) struct Profile {
    id: i64,
    name: String,
    salt: String,
    key_id: i64,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

#[derive(Default)]
pub(crate) struct VaultRecord {
    id: i64,
    name: String,
    key_id: i64,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl VaultRecord {
    pub fn to_vault(&self, database: Database) -> Vault {
        Vault::new(
            self.id,
            &self.name,
            self.key_id,
            self.created_at.and_utc(),
            self.updated_at.and_utc(),
            database
        )
    }
}

#[derive(Debug)]
pub(crate) struct EncryptedKeyRecord {
    pub(crate) id: i64,
    key_encrypted_data: Json<EncryptedData<Vec<u8>>>,
    next_nonce: Vec<u8>,
}

impl EncryptedKeyRecord {
    pub(crate) fn try_to_symmetric_key(&self, parent_key: &SymmetricKey, database: Option<Database>) -> Result<SymmetricKey, Error> {
        let decrypted_key = parent_key.decrypt(&self.key_encrypted_data)?;

        Ok(SymmetricKey::new(&decrypted_key, Some(&self.next_nonce), Some(self.id), database)?)
    }
}

pub(crate) trait Repository {
    async fn store_vault(&mut self, name: &str, key_id: i64) -> Result<VaultRecord, Error> {
        let vault_record = sqlx::query_as!(
            VaultRecord,
            "INSERT INTO vaults(name, key_id) VALUES (?, ?) RETURNING *",
            name,
            key_id
        )
            .fetch_one(self.get_executor())
            .await?;

        Ok(vault_record)
    }

    async fn store_key(&mut self, key: &EncryptedData<Vec<u8>>, next_nonce: &[u8]) -> Result<EncryptedKeyRecord, Error> {
        let serialized_key = serde_json::to_string(key)?;
        let key_record = sqlx::query_as!(
            EncryptedKeyRecord,
            "INSERT INTO keys(key_encrypted_data, next_nonce)
            VALUES (?, ?)
            RETURNING id, key_encrypted_data as 'key_encrypted_data: Json<EncryptedData<Vec<u8>>>', next_nonce",
            serialized_key,
            next_nonce,
        )
            .fetch_one(self.get_executor())
            .await?;

        Ok(key_record)
    }

    async fn update_key_next_nonce(&mut self, key_id: i64, next_nonce: &[u8]) -> Result<bool, Error> {
        let res = sqlx::query!(
            "UPDATE keys SET next_nonce = ? WHERE id = ?",
            next_nonce,
            key_id
        )
            .execute(self.get_executor())
            .await?;

        Ok(res.rows_affected() > 0)
    }

    async fn get_profile(&mut self) -> Result<Option<Profile>, Error> {
        let profile = sqlx::query_as!(
            Profile,
            "SELECT id, name, salt, key_id, created_at, updated_at FROM profiles WHERE id = 1"
        )
            .fetch_optional(self.get_executor())
            .await?;

        Ok(profile)
    }

    async fn store_profile(&mut self, name: &str, salt: &str, key_id: i64) -> Result<Profile, Error> {
        let profile = sqlx::query_as!(
            Profile,
            "INSERT INTO profiles(name, salt, key_id)
            VALUES (?, ?, ?)
            RETURNING id, name, salt, key_id, created_at, updated_at",
            name,
            salt,
            key_id
        )
            .fetch_one(self.get_executor())
            .await?;

        Ok(profile)
    }

    async fn find_key(&mut self, key_id: i64) -> Result<Option<EncryptedKeyRecord>, Error> {
        let key_record = sqlx::query_as!(
            EncryptedKeyRecord,
            "SELECT id, key_encrypted_data as 'key_encrypted_data: Json<EncryptedData<Vec<u8>>>', next_nonce
            FROM keys
            WHERE id = ?",
            key_id
        )
            .fetch_optional(self.get_executor())
            .await?;

        Ok(key_record)
    }

    fn get_executor(&mut self) -> impl Executor<'_, Database = Sqlite>;
}

#[derive(Debug, Clone)]
pub(crate) struct Database {
    pool: SqlitePool,
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

    pub(crate) async fn transaction<F, O, E>(&self, func: F) -> Result<O, E>
    where for<'a>
        F: FnOnce(&'a mut DatabaseTransaction<'_>) -> Pin<Box<dyn Future<Output = Result<O, E>> + Send + 'a>>,
        O: Send,
        E: From<SqlxError> + Send
    {
        let mut transaction = DatabaseTransaction { transaction: self.pool.begin().await? };
        let result = func(&mut transaction).await;
        match result {
            Ok(ret) => {
                transaction.into_inner().commit().await?;

                Ok(ret)
            },
            Err(err) => {
                transaction.into_inner().rollback().await?;

                Err(err)
            }
        }
    }
}

impl Repository for Database {
    fn get_executor(&mut self) -> impl Executor<'_, Database = Sqlite> {
        &self.pool
    }
}

pub(crate) struct DatabaseTransaction<'a> {
    transaction: Transaction<'a, Sqlite>
}

impl<'a> DatabaseTransaction<'a> {
    pub(crate) fn get_inner(&self) -> &Transaction<'a, Sqlite> {
        &self.transaction
    }

    pub(crate) fn get_inner_mut(&'a mut self) -> &'a mut Transaction<'a, Sqlite> {
        &mut self.transaction
    }

    pub(crate) fn into_inner(self) -> Transaction<'a, Sqlite> {
        self.transaction
    }
}

impl<'a> Repository for DatabaseTransaction<'a> {
    fn get_executor(&mut self) -> impl Executor<'_, Database = Sqlite> {
        &mut *self.transaction
    }
}

impl<'a> Repository for &mut DatabaseTransaction<'a> {
    fn get_executor(&mut self) -> impl Executor<'_, Database = Sqlite> {
        (**self).get_executor()
    }
}
