use chrono::{NaiveDateTime};
use rand::rngs::OsRng;
use sqlx::{
    sqlite::SqliteConnectOptions,
    SqlitePool,
};
use std::path::Path;
use crate::hash_password;
use crate::symmetric_key::SymmetricKey;
use crate::Error;
use crate::generate_salt;
use crate::vault::{Vault, VaultRecord};

#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
}

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

impl Store {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);

        let pool = SqlitePool::connect_with(options).await?;

        MIGRATOR
            .run(&pool)
            .await.map_err(|err| sqlx::Error::from(err))?;

        Ok(Store {
            pool
        })
    }

    pub fn from_pool(pool: SqlitePool) -> Self {
        Store {
            pool
        }
    }

    pub async fn create_vault(&self, name: &str, password: &str) -> Result<Vault, Error> {
        let salt = generate_salt();
        let vault_record = sqlx::query_as!(VaultRecord,
            "INSERT INTO vaults(name, salt) VALUES (?, ?) RETURNING *", name, salt
        )
            .fetch_one(&self.pool)
            .await?;

        let master_encryption_key = SymmetricKey::new(&hash_password(password.as_bytes(), &salt), None, None, vault_record.id);

        let vault = Vault::new(vault_record, self.clone());
        unimplemented!();
    }

    pub async fn create_key(&self, key_record: KeyRecord) {
        let key_record = sqlx
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn can_create_vault(pool: SqlitePool) {
        let store = Store::from_pool(pool);

        store.create_vault("new vault", "password").await.unwrap();
    }
}
