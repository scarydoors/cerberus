use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use crate::{
    crypto::{EncryptedKey, SecureKey},
    database::Database,
    item::{ItemData, ItemOverview},
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
    id: i64,
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    database: Database,
    vault_key: VaultKey,
}

impl Vault {
    pub(crate) fn new(
        id: i64,
        name: String,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        database: Database,
        vault_key: VaultKey,
    ) -> Self {
        Self {
            id,
            name,
            created_at,
            updated_at,
            database,
            vault_key,
        }
    }

    pub fn create_item(&self, item_overview: ItemOverview, item_data: ItemData) {

    }
}

pub struct VaultPreview {
    id: i64,
    name: String,
}

impl VaultPreview {
    pub(crate) fn new(id: i64, name: String) -> Self {
        Self {
            id,
            name,
        }
    }
}
