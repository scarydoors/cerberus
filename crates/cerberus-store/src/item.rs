use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{crypto::EncryptedDataKeyPair, database::Database, vault::VaultKey, Error};

pub struct Item {
    id: i64,
    enc_overview: EncryptedDataKeyPair<ItemOverview>,
    enc_data: EncryptedDataKeyPair<ItemData>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    vault_key: VaultKey,
    database: Database,
}

pub struct ItemPreview {
    id: i64,
    overview: ItemOverview
}

impl ItemPreview {
    pub fn new(id: i64, overview: ItemOverview) -> Self {
        Self { id, overview }
    }

    pub fn id(&self) -> i64 {
        self.id
    }

    pub fn overview(&self) -> &ItemOverview {
        &self.overview
    }
}

#[derive(Debug, Serialize, Deserialize)]
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

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn site(&self) -> &str {
        &self.site
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ItemData {
    secret: String
}

impl ItemData {
    pub fn new(secret: String) -> Self {
        Self {
            secret
        }
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl Item {
    pub(crate) fn new(
        id: i64,
        enc_overview: EncryptedDataKeyPair<ItemOverview>,
        enc_data: EncryptedDataKeyPair<ItemData>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        vault_key: VaultKey,
        database: Database,
    ) -> Item {
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

    pub fn overview(&self) -> Result<ItemOverview, Error> {
        Ok(self.enc_overview.decrypt(&self.vault_key)?)
    }

    pub fn data(&self) -> Result<ItemData, Error> {
        Ok(self.enc_data.decrypt(&self.vault_key)?)
    }
}
