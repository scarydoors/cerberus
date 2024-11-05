use std::path::Path;

use sqlx::{migrate::MigrateError, sqlite::SqliteConnectOptions, Error, SqlitePool};

pub async fn create_database(filename: impl AsRef<Path>) -> Result<(), MigrateError> {
    let options = SqliteConnectOptions::new()
        .filename(filename)
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(options).await.unwrap();

    sqlx::migrate!()
        .run(&pool)
        .await
}
