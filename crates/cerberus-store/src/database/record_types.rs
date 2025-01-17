use chrono::NaiveDateTime;
use sqlx::types::Json;

use crate::{store::Profile, symmetric_key::{EncryptedData, EncryptedKey}, vault::{Vault, VaultKey}};

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
        Profile::new(self.id, self.name, self.salt, self.key_id, self.created_at.and_utc(), self.updated_at.and_utc())
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
        Vault::new(self.id, self.name, self.created_at.and_utc(), self.updated_at.and_utc(), database, vault_key)
    }
}

pub(crate) struct VaultOverviewRecord {
    pub(crate) id: i64,
    pub(crate) name: String
}

#[derive(Debug)]
pub(crate) struct EncryptedKeyRecord {
    pub(crate) id: i64,
    pub(crate) key_encrypted_data: Json<EncryptedData<Vec<u8>>>,
}

impl EncryptedKeyRecord {
    pub(crate) fn into_encrypted_key(self) -> EncryptedKey {
        EncryptedKey::new(
            Some(self.id),
            self.key_encrypted_data.0,
        )
    }
}

impl From<EncryptedKeyRecord> for EncryptedKey {
    fn from(record: EncryptedKeyRecord) -> Self {
        record.into_encrypted_key()
    }
}
