use chrono::NaiveDateTime;
use sqlx::types::Json;

use crate::{symmetric_key::{EncryptedData, EncryptedKey}, vault::Vault};

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

#[derive(Debug)]
pub(crate) struct VaultRecord {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) key_id: i64,
    pub(crate) created_at: NaiveDateTime,
    pub(crate) updated_at: NaiveDateTime,
}

#[derive(Debug)]
pub(crate) struct EncryptedKeyRecord {
    pub(crate) id: i64,
    pub(crate) key_encrypted_data: Json<EncryptedData<Vec<u8>>>,
    pub(crate) next_nonce: Vec<u8>,
}
