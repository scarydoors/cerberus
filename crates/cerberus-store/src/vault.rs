use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    crypto::{Cipher, EncryptedData, EncryptedKey, SecureKey, SymmetricKey}, database::Database, item::{Item, ItemData, ItemOverview}, Error
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

    pub fn create_item(&self, item_overview: ItemOverview, item_data: ItemData) -> Result<Item, Error> {


        todo!()
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
