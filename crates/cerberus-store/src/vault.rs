use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rand::rngs::OsRng;

use crate::{database::{record_types::VaultRecord, Database}, hash_password, symmetric_key::{EncryptedKey, SecureKey, SymmetricKey}, Error};

pub(crate) struct VaultKey {
    master_key: Arc<Mutex<SecureKey>>,
    vault_key: EncryptedKey,
}

impl VaultKey {
    pub(crate) fn new(master_key: Arc<Mutex<SecureKey>>, vault_key: EncryptedKey) -> Self {
        Self {
            master_key,
            vault_key,
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
    pub(crate) fn new(id: i64, name: String, created_at: DateTime<Utc>, updated_at: DateTime<Utc>, database: Database, vault_key: VaultKey) -> Self {
        Self {
            id,
            name,
            created_at,
            updated_at,
            database,
            vault_key,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}
