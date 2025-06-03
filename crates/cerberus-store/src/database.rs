use std::pin::Pin;
use std::{future::Future, path::Path};

use sqlx::Error as SqlxError;
use sqlx::{sqlite::SqliteConnectOptions, types::Json, Executor, Sqlite, SqlitePool, Transaction};

use crate::item::{ItemData, ItemOverview};
use crate::{crypto::EncryptedData, Error};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub mod record_types;

use record_types::{
    EncryptedKeyRecord, ItemPreviewRecord, ItemRecord, ItemRecordWithKeys, ProfileRecord,
    VaultPreviewRecord, VaultRecord,
};

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

    async fn find_vault(&mut self, id: i64) -> Result<Option<VaultRecord>, Error> {
        let vault_record = sqlx::query_as!(VaultRecord, "SELECT * FROM vaults WHERE id = ?", id)
            .fetch_optional(self.get_executor())
            .await?;

        Ok(vault_record)
    }

    async fn store_key(
        &mut self,
        key: &EncryptedData<Vec<u8>>,
    ) -> Result<EncryptedKeyRecord, Error> {
        let serialized_key = serde_json::to_string(key)?;
        let key_record = sqlx::query_as!(
            EncryptedKeyRecord,
            "INSERT INTO keys(key_encrypted_data)
             VALUES (?)
             RETURNING id, key_encrypted_data as 'key_encrypted_data: Json<EncryptedData<Vec<u8>>>'",
            serialized_key,
        )
        .fetch_one(self.get_executor())
        .await?;

        Ok(key_record)
    }

    async fn find_key(&mut self, key_id: i64) -> Result<Option<EncryptedKeyRecord>, Error> {
        let key_record = sqlx::query_as!(
            EncryptedKeyRecord,
            "SELECT id, key_encrypted_data as 'key_encrypted_data: Json<EncryptedData<Vec<u8>>>'
             FROM keys
             WHERE id = ?",
            key_id
        )
        .fetch_optional(self.get_executor())
        .await?;

        Ok(key_record)
    }

    async fn get_profile(&mut self) -> Result<Option<ProfileRecord>, Error> {
        let profile = sqlx::query_as!(
            ProfileRecord,
            "SELECT id, name, salt, key_id, created_at, updated_at FROM profiles WHERE id = 1"
        )
        .fetch_optional(self.get_executor())
        .await?;

        Ok(profile)
    }

    async fn store_profile(
        &mut self,
        name: &str,
        salt: &str,
        key_id: i64,
    ) -> Result<ProfileRecord, Error> {
        let profile = sqlx::query_as!(
            ProfileRecord,
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

    async fn list_vault_previews(&mut self) -> Result<Vec<VaultPreviewRecord>, Error> {
        let vault_overview_records =
            sqlx::query_as!(VaultPreviewRecord, "SELECT id, name FROM vaults")
                .fetch_all(self.get_executor())
                .await?;

        Ok(vault_overview_records)
    }

    async fn store_item(
        &mut self,
        vault_id: i64,
        enc_item_overview: &EncryptedData<ItemOverview>,
        item_overview_key_id: i64,
        enc_item_data: &EncryptedData<ItemData>,
        item_data_key_id: i64,
    ) -> Result<ItemRecord, Error> {
        let serialized_item_overview = serde_json::to_string(enc_item_overview)?;
        let serialized_item_data = serde_json::to_string(enc_item_data)?;
        let item_record = sqlx::query_as!(
            ItemRecord,
            "INSERT INTO items(
                 vault_id,
                 overview_encrypted_data,
                 overview_key_id,
                 item_encrypted_data,
                 item_key_id
             )
             VALUES (?, ?, ?, ?, ?)
             RETURNING
                 id,
                 vault_id,
                 overview_encrypted_data as 'overview_encrypted_data: Json<EncryptedData<ItemOverview>>',
                 overview_key_id,
                 item_encrypted_data as 'item_encrypted_data: Json<EncryptedData<ItemData>>',
                 item_key_id,
                 created_at,
                 updated_at",
            vault_id,
            serialized_item_overview,
            item_overview_key_id,
            serialized_item_data,
            item_data_key_id,
        )
            .fetch_one(self.get_executor())
            .await?;

        Ok(item_record)
    }

    async fn find_item(&mut self, id: i64) -> Result<ItemRecordWithKeys, Error> {
        let record = sqlx::query!(
            "SELECT
                 items.id,
                 items.vault_id,
                 items.overview_encrypted_data as 'overview_encrypted_data: Json<EncryptedData<ItemOverview>>',
                 items.item_encrypted_data as 'item_encrypted_data: Json<EncryptedData<ItemData>>',
                 items.created_at,
                 items.updated_at,
                 overview_keys.id as 'overview_key_id',
                 overview_keys.key_encrypted_data as 'overview_key_encrypted_data: Json<EncryptedData<Vec<u8>>>',
                 data_keys.id as 'item_key_id',
                 data_keys.key_encrypted_data as 'data_key_encrypted_data: Json<EncryptedData<Vec<u8>>>'
             FROM items
             INNER JOIN keys AS overview_keys ON overview_keys.id = items.overview_key_id
             INNER JOIN keys AS data_keys ON data_keys.id = items.item_key_id
             WHERE items.id = ?",
            id
        )
            .fetch_one(self.get_executor())
            .await?;

        let item_record_with_keys = ItemRecordWithKeys {
            item_record: ItemRecord {
                id: record.id,
                vault_id: record.vault_id,
                overview_encrypted_data: record.overview_encrypted_data,
                overview_key_id: record.overview_key_id,
                item_encrypted_data: record.item_encrypted_data,
                item_key_id: record.item_key_id,
                created_at: record.created_at,
                updated_at: record.updated_at,
            },
            overview_key: record.overview_key_encrypted_data,
            data_key: record.data_key_encrypted_data,
        };

        Ok(item_record_with_keys)
    }

    async fn list_item_previews(
        &mut self,
        vault_id: Option<i64>,
    ) -> Result<Vec<ItemPreviewRecord>, Error> {
        let vault_id = vault_id.unwrap();
        let item_preview_records = sqlx::query_as!(
            ItemPreviewRecord,
            "SELECT
                 items.id,
                 items.vault_id,
                 items.overview_encrypted_data as 'overview_encrypted_data: Json<EncryptedData<ItemOverview>>',
                 items.created_at,
                 items.updated_at,
                 keys.id as 'overview_key_id',
                 keys.key_encrypted_data as 'overview_key_encrypted_data: Json<EncryptedData<Vec<u8>>>'
             FROM items
             INNER JOIN (SELECT id, key_encrypted_data  FROM keys) AS keys ON keys.id = items.overview_key_id
             WHERE items.vault_id = ?
             GROUP BY items.id",
            vault_id
        )
            .fetch_all(self.get_executor())
            .await?;

        Ok(item_preview_records)
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
            .await
            .map_err(sqlx::Error::from)?;

        Ok(Self { pool })
    }

    pub(crate) fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub(crate) async fn transaction<F, O, E>(&self, func: F) -> Result<O, E>
    where
        for<'a> F: FnOnce(
            &'a mut DatabaseTransaction<'_>,
        ) -> Pin<Box<dyn Future<Output = Result<O, E>> + Send + 'a>>,
        O: Send,
        E: From<SqlxError> + Send,
    {
        let mut transaction = DatabaseTransaction {
            transaction: self.pool.begin().await?,
        };
        let result = func(&mut transaction).await;
        match result {
            Ok(ret) => {
                transaction.into_inner().commit().await?;

                Ok(ret)
            }
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
    transaction: Transaction<'a, Sqlite>,
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

impl Repository for DatabaseTransaction<'_> {
    fn get_executor(&mut self) -> impl Executor<'_, Database = Sqlite> {
        &mut *self.transaction
    }
}

impl Repository for &mut DatabaseTransaction<'_> {
    fn get_executor(&mut self) -> impl Executor<'_, Database = Sqlite> {
        (**self).get_executor()
    }
}
