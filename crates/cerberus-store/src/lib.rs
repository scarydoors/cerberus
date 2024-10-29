use std::{future::Future, path::Path};

use sqlx::{sqlite::SqliteConnectOptions, Error, SqlitePool};


pub fn create_database(filename: impl AsRef<Path>) -> impl Future< Output = Result<SqlitePool, Error>> {
    let options = SqliteConnectOptions::new()
        .filename(filename)
        .create_if_missing(true);

    SqlitePool::connect_with(options)
}
