use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use std::path::Path;
use crate::Error;

struct Store {
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
}

struct EncryptedData {
    data: Vec<u8>,
}
