use chrono::{DateTime, Utc};
use rand::rngs::OsRng;

use crate::{database::{Database, EncryptedKeyRecord}, hash_password, symmetric_key::SymmetricKey, Error};

pub struct Vault {
    id: i64,
    name: String,
    key_id: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    database: Database,
    vault_key: Option<SymmetricKey>,
    enc_vault_key: Option<EncryptedKeyRecord>,
}

impl Vault {
    pub(crate) fn new(id: i64, name: &str, key_id: i64, created_at: DateTime<Utc>, updated_at: DateTime<Utc>, database: Database) -> Self {
        Self {
            id,
            name: name.to_string(),
            key_id,
            created_at,
            updated_at,
            database,
            vault_key: None,
            enc_vault_key: None,
        }
    }

    pub async fn unlock(&mut self, password: &str) -> Result<(), Error> {
        unimplemented!();
        self.ensure_enc_vault_key_retrieved().await?;
        let encrypted_vault_key = self.enc_vault_key.as_ref().unwrap();

        let master_key = self.get_master_symmetric_key(password.as_bytes())?;
        let vault_key = encrypted_vault_key.try_to_symmetric_key(&master_key, Some(self.database.clone()))?;

        self.vault_key = Some(vault_key);
        Ok(())
    }

    pub fn is_vault_locked(&self) -> bool {
        self.vault_key.is_none()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    //async fn ensure_enc_vault_key_retrieved(&mut self) -> Result<(), Error> {
    //    if self.enc_vault_key.is_none() {
    //        self.enc_vault_key = Some(self.database.find_vault_key(self.id).await?.expect("database has a vault key for this vault"));
    //    }

    //    Ok(())
    //}

    //pub(crate) async fn initialize_vault_key(&mut self, password: &[u8]) -> Result<(), Error> {
    //    debug_assert!(self.database.find_vault_key(self.id).await?.is_none());

    //    let mut master_key = self.get_master_symmetric_key(password)?;
    //    let mut vault_key = SymmetricKey::generate(&mut OsRng, self.id, Some(self.database.clone()));

    //    vault_key.store(&mut master_key).await?;

    //    self.vault_key = Some(vault_key);

    //    Ok(())
    //}
}
