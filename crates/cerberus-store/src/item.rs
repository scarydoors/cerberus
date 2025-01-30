use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{crypto::EncryptedDataKeyPair, database::Database, vault::VaultKey};

pub struct Item {
    enc_overview: EncryptedDataKeyPair<ItemOverview>,
    enc_data: EncryptedDataKeyPair<ItemData>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    vault_key: VaultKey,
    database: Database,
}

#[derive(Serialize, Deserialize)]
pub struct ItemOverview {
    name: String,
    site: String
}

impl ItemOverview {
    pub fn new(name: String, site: String) -> Self {
        Self {
            name,
            site
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ItemData {
    secret: String
}

impl ItemData {
    pub fn new(secret: String) -> Self {
        Self {
            secret
        }
    }
}

impl Item {
    pub(crate) fn new(
        id: i64,
        enc_overview: EncryptedDataKeyPair<ItemOverview>,
        enc_data: EncryptedDataKeyPair<ItemOverview>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        vault_key: VaultKey,
        database: Database,
    ) {
        Self {
            id,
            enc_overview,
            enc_data,
            created_at,
            updated_at,
            vault_key,
            database,
        }
    }
}
