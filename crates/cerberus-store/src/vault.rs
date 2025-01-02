use chrono::{DateTime, Utc};
use rand::rngs::OsRng;

use crate::{database::{Database, VaultRecord}, hash_password, symmetric_key::SymmetricKey, Error};

pub struct Vault {
    id: i64,
    name: String,
    salt: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    database: Database,
    vault_key: Option<SymmetricKey>,
}

impl Vault {
    pub(crate) fn new(id: i64, name: &str, salt: &str, created_at: DateTime<Utc>, updated_at: DateTime<Utc>, database: Database) -> Self {
        Self {
            id,
            name: name.to_string(),
            salt: salt.to_string(),
            created_at,
            updated_at,
            database,
            vault_key: None
        }
    }

    pub async fn unlock(&mut self, password: &str) -> Result<(), Error> {
        let encrypted_vault_key = self.database.find_vault_key(self.id).await?.expect("database has a vault key for this vault");

        let master_key = self.get_master_symmetric_key(password.as_bytes())?;
        let vault_key = encrypted_vault_key.try_to_symmetric_key(&master_key, Some(self.database.clone()))?;

        self.vault_key = Some(vault_key);
        Ok(())
    }

    fn is_vault_locked(&self) -> bool {
        self.vault_key.is_none()
    }

    pub(crate) async fn initialize_vault_key(&mut self, password: &[u8]) -> Result<(), Error> {
        debug_assert!(self.database.find_vault_key(self.id).await?.is_none());

        let mut master_key = self.get_master_symmetric_key(password)?;
        let mut vault_key = SymmetricKey::generate(&mut OsRng, self.id, Some(self.database.clone()));

        vault_key.store(&mut master_key).await?;

        self.vault_key = Some(vault_key);

        Ok(())
    }

    fn get_master_symmetric_key(&self, password: &[u8]) -> Result<SymmetricKey, Error> {
        let hash = hash_password(password, &self.salt);

        Ok(SymmetricKey::new(&hash, None, None, self.id, None)?)
    }
}
