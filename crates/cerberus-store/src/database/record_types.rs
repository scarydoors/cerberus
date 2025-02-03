use chrono::{NaiveDateTime};
use sqlx::{database, types::Json};

use crate::{
    crypto::{Cipher, EncryptedData, EncryptedDataKeyPair, EncryptedKey}, item::{Item, ItemData, ItemOverview, ItemPreview}, store::Profile, vault::{self, Vault, VaultKey, VaultPreview}, Error
};

use super::Database;

#[derive(Debug)]
pub(crate) struct ProfileRecord {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) salt: String,
    pub(crate) key_id: i64,
    pub(crate) created_at: NaiveDateTime,
    pub(crate) updated_at: NaiveDateTime,
}

impl ProfileRecord {
    pub(crate) fn into_profile(self) -> Profile {
        Profile::new(
            self.id,
            self.name,
            self.salt,
            self.key_id,
            self.created_at.and_utc(),
            self.updated_at.and_utc(),
        )
    }
}

impl From<ProfileRecord> for Profile {
    fn from(record: ProfileRecord) -> Self {
        record.into_profile()
    }
}

#[derive(Debug)]
pub(crate) struct VaultRecord {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) key_id: i64,
    pub(crate) created_at: NaiveDateTime,
    pub(crate) updated_at: NaiveDateTime,
}

impl VaultRecord {
    pub(crate) fn into_vault(self, vault_key: VaultKey, database: Database) -> Vault {
        Vault::new(
            self.id,
            self.name,
            self.created_at.and_utc(),
            self.updated_at.and_utc(),
            database,
            vault_key,
        )
    }
}

pub(crate) struct VaultPreviewRecord {
    pub(crate) id: i64,
    pub(crate) name: String,
}

impl VaultPreviewRecord {
    pub(crate) fn into_vault_preview(self) -> VaultPreview {
        VaultPreview::new(self.id, self.name)
    }
}

#[derive(Debug)]
pub(crate) struct EncryptedKeyRecord {
    pub(crate) id: i64,
    pub(crate) key_encrypted_data: Json<EncryptedData<Vec<u8>>>,
}

impl EncryptedKeyRecord {
    pub(crate) fn into_encrypted_key(self) -> EncryptedKey {
        EncryptedKey::new(Some(self.id), self.key_encrypted_data.0)
    }
&}

impl From<EncryptedKeyRecord> for EncryptedKey {
    fn from(record: EncryptedKeyRecord) -> Self {
        record.into_encrypted_key()
    }
}

#[derive(Debug)]
pub(crate) struct ItemPreviewRecord {
    pub(crate) id: i64,
    pub(crate) vault_id: i64,
    pub(crate) overview_encrypted_data: Json<EncryptedData<ItemOverview>>,
    pub(crate) overview_key_id: i64,
    pub(crate) overview_key_encrypted_data: Json<EncryptedData<Vec<u8>>>,
    pub(crate) created_at: NaiveDateTime,
    pub(crate) updated_at: NaiveDateTime,
}

impl ItemPreviewRecord {
    pub(crate) fn try_into_item_preview<K: Cipher>(self, parent_key: &K) -> Result<ItemPreview, Error> {
        let enc_overview_key = EncryptedKey::new(Some(self.overview_key_id), self.overview_key_encrypted_data.0);
        let overview_key = enc_overview_key.try_to_symmetric_key(parent_key)?;

        let overview_data = overview_key.decrypt(&self.overview_encrypted_data.0)?;

        let preview = ItemPreview::new(self.id, overview_data);
        Ok(preview)
    }
}

#[derive(Debug)]
pub(crate) struct ItemRecord {
    pub(crate) id: i64,
    pub(crate) vault_id: i64,
    pub(crate) overview_encrypted_data: Json<EncryptedData<ItemOverview>>,
    pub(crate) overview_key_id: i64,
    pub(crate) item_encrypted_data: Json<EncryptedData<ItemData>>,
    pub(crate) item_key_id: i64,
    pub(crate) created_at: NaiveDateTime,
    pub(crate) updated_at: NaiveDateTime,
}

impl ItemRecord {
    pub(crate) fn into_item(self, overview_key: EncryptedKey, data_key: EncryptedKey, vault_key: VaultKey, database: Database) -> Item {
        Item::new(
            self.id,
            EncryptedDataKeyPair::new(self.overview_encrypted_data.0, overview_key),
            EncryptedDataKeyPair::new(self.item_encrypted_data.0, data_key),
            self.created_at.and_utc(),
            self.updated_at.and_utc(),
            vault_key,
            database
        )
    }
}

pub(crate) struct ItemRecordWithKeys {
    pub(crate) item_record: ItemRecord,
    pub(crate) overview_key: Json<EncryptedData<Vec<u8>>>,
    pub(crate) data_key: Json<EncryptedData<Vec<u8>>>,
}

impl ItemRecordWithKeys {
    pub(crate) fn into_item(self, vault_key: VaultKey, database: Database) -> Item {
        let overview_key = EncryptedKey::new(Some(self.item_record.overview_key_id), self.overview_key.0);
        let data_key = EncryptedKey::new(Some(self.item_record.item_key_id), self.data_key.0);

        self.item_record.into_item(overview_key, data_key, vault_key, database)
    }
}
