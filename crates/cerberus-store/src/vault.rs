use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rand::rngs::OsRng;

use crate::{database::{record_types::VaultRecord, Database}, hash_password, symmetric_key::{EncryptedKey, SecureKey, SymmetricKey}, Error};

pub struct VaultKey {
    master_key: Arc<Mutex<SecureKey>>,
    vault_key: EncryptedKey,
}

impl VaultRecord {
    pub(crate) fn into_vault(self, vault_key: VaultKey, database: Database) -> Vault {
        Vault {
            id: self.id,
            name: self.name,
            created_at: self.created_at.and_utc(),
            updated_at: self.updated_at.and_utc(),
            database,
            vault_key
        }
    }
}

pub struct Vault {
    id: i64,
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    database: Database,
    vault_key: VaultKey
}

impl Vault {
    pub(crate) fn new(id: i64, name: &str, created_at: DateTime<Utc>, updated_at: DateTime<Utc>, database: Database, vault_key: VaultKey) -> Self {
        Self {
            id,
            name: name.to_string(),
            created_at,
            updated_at,
            database,
            vault_key,
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
}
