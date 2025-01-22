use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    crypto::{Cipher, EncryptedData, EncryptedKey, SecureKey, SymmetricKey},
    database::Database, Error,
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

    pub(crate) fn get_symmetric_key(&self) -> Result<SymmetricKey, Error> {
        let master_key = self.master_key.lock().unwrap();
        let vault_key = self.vault_key.try_to_symmetric_key(&*master_key)?;

        Ok(vault_key)
    }
}

impl Cipher for VaultKey {
    fn encrypt<T: Serialize + DeserializeOwned>(&self, data: &T) -> Result<EncryptedData<T>, Error> {
        let key = self.get_symmetric_key()?;

        Ok(key.encrypt(data)?)
    }

    fn decrypt<T: Serialize + DeserializeOwned>(&self, data: &EncryptedData<T>) -> Result<T, Error> {
        let key = self.get_symmetric_key()?;

        Ok(key.decrypt(data)?)
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
