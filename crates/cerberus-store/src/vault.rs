use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    crypto::{Cipher, EncryptedData, EncryptedKey, SecureKey, SymmetricKey}, database::{self, Database, Repository}, item::{Item, ItemData, ItemOverview, ItemPreview}, Error
};

#[derive(Debug, Clone)]
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

    pub async fn create_item(&self, item_overview: ItemOverview, item_data: ItemData) -> Result<Item, Error> {
        let overview_key = SymmetricKey::generate(&mut OsRng);
        let data_key = SymmetricKey::generate(&mut OsRng);

        let enc_item_overview = overview_key.encrypt(&item_overview)?;
        let enc_item_data = data_key.encrypt(&item_data)?;

        let id = self.id;
        let vault_key = self.vault_key.clone();
        let database = self.database.clone();

        let item = self.database.transaction(|mut transaction| {
            Box::pin(async move {
                let mut enc_overview_key = overview_key.into_encrypted_key(&vault_key);
                enc_overview_key.store(&mut transaction).await?;
                let mut enc_data_key = data_key.into_encrypted_key(&vault_key);
                enc_data_key.store(&mut transaction).await?;

                let item_record = transaction.store_item(
                    id,
                    &enc_item_overview,
                    enc_overview_key.id().unwrap(),
                    &enc_item_data,
                    enc_data_key.id().unwrap()
                ).await?;

                Ok::<_, Error>(item_record.into_item(enc_overview_key, enc_data_key, vault_key, database))
            })
        }).await?;

        Ok(item)
    }

    pub async fn list_items(&mut self) -> Result<Vec<ItemPreview>, Error> {
        let vault_key = self.vault_key.get_symmetric_key()?;

        let item_previews = self.database.list_item_previews(Some(self.id))
            .await?
            .into_iter()
            .map(|record| record.try_into_item_preview(&vault_key))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(item_previews)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
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
