use sqlx::{
    sqlite::SqliteConnectOptions,
    SqlitePool,
};
use std::path::Path;
use crate::Error;
use crate::generate_salt;

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

    pub async fn create_vault(&self, name: &str, password: &str) -> Result<(), Error> {
        let salt = generate_salt();
        sqlx::query(
            "INSERT INTO vaults(name, salt) VALUES (?, ?)"
        )
            .bind(name)
            .bind(salt)
            .fetch_all(&self.pool)
            .await?;

        Ok(())
    }
}
