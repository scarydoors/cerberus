use std::path::Path;

use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unable to create database: {0}")]
    DatabaseCreationFailed(#[from] sqlx::Error),
}

pub async fn create_database(filename: impl AsRef<Path>) -> Result<(), Error> {
    let options = SqliteConnectOptions::new()
        .filename(filename)
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(options).await?;

    sqlx::migrate!()
        .run(&pool)
        .await.map_err(|err| sqlx::Error::from(err).into())
}
