use chrono::{NaiveDateTime};
use rand::rngs::OsRng;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use crate::database::Database;
use crate::hash_password;
use crate::symmetric_key::SecureKey;
use crate::symmetric_key::SymmetricKey;
use crate::Error;
use crate::generate_salt;
use crate::vault::Vault;

#[derive(Debug)]
pub struct Store {
    database: Database,
    master_key: Option<Arc<Mutex<SecureKey>>>,
}

impl Store {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(Store {
            database: Database::new(path).await?,
            master_key: None,
        })
    }

    pub async fn unlock(&self, password: &str) -> Result<(), Error> {

        unimplemented!()
    }

    pub async fn initialize_profile(&self, name: &str, password: &str) -> Result<(), Error> {
        self.database.get_profile().await?.map_or(Ok(()), |_| Err(Error::ProfileAlreadyExists))?;

        let salt = generate_salt();

    }

    pub async fn create_vault(&self, name: &str, password: &str) -> Result<Vault, Error> {
        unimplemented!()
        let salt = generate_salt();

        let vault_record = self.database.store_vault(name).await?;
        let mut vault = vault_record.to_vault(self.database.clone());

        vault.initialize_vault_key(password.as_bytes()).await?;

        Ok(vault)
    }
}
