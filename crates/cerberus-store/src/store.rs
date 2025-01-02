use chrono::{NaiveDateTime};
use rand::rngs::OsRng;
use std::path::Path;
use crate::database::Database;
use crate::hash_password;
use crate::symmetric_key::SymmetricKey;
use crate::Error;
use crate::generate_salt;
use crate::vault::Vault;

#[derive(Debug, Clone)]
pub struct Store {
    database: Database
}

impl Store {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(Store {
            database: Database::new(path).await?
        })
    }

    pub async fn create_vault(&self, name: &str, password: &str) -> Result<Vault, Error> {
        let salt = generate_salt();

        let vault_record = self.database.store_vault(name, &salt).await?;
        let mut vault = vault_record.to_vault(self.database.clone());

        vault.initialize_vault_key(password.as_bytes()).await?;

        Ok(vault)
    }
}
