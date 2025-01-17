use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use crate::{
    crypto::{EncryptedKey, SecureKey},
    database::Database,
};

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
    vault_overview: VaultOverview,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    database: Database,
    vault_key: VaultKey,
}

impl Vault {
    pub(crate) fn new(
        vault_overview: VaultOverview,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        database: Database,
        vault_key: VaultKey,
    ) -> Self {
        Self {
            vault_overview,
            created_at,
            updated_at,
            database,
            vault_key,
        }
    }

    pub fn overview(&self) -> &VaultOverview {
        &self.vault_overview
    }
}

pub struct VaultOverview {
    id: i64,
    name: String,
}

impl VaultOverview {
    pub(crate) fn new(id: i64, name: String) -> Self {
        Self { id, name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> i64 {
        self.id
    }
}
