use chrono::{NaiveDateTime, DateTime, Utc};
use rand::rngs::OsRng;

use crate::{store::Store, symmetric_key::SymmetricKey, Error};

#[derive(Debug)]
pub struct VaultRecord {
    id: i64,
    name: String,
    salt: String,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

pub struct Vault {
    id: i64,
    name: String,
    salt: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    store: Store,
    master_encryption_key: Option<SymmetricKey>
}

impl Vault {
    pub fn new(record: VaultRecord, store: Store) -> Self {
        Self {
            id: record.id,
            name: record.name,
            salt: record.salt,
            created_at: record.created_at.and_utc(),
            updated_at: record.updated_at.and_utc(),
            store,
            master_encryption_key: None
        }
    }

    pub fn unlock(password: &[u8]) -> Result<(), Error> {

    }

    pub(crate) fn new_symmetric_key(&mut self, parent_key: &mut SymmetricKey) -> Result<SymmetricKey, Error> {
        let symmetric_key = SymmetricKey::new_with_rng(&mut OsRng, None, self.id);
        let key_record = symmetric_key.to_key_record(parent_key)?;



        Ok(symmetric_key)
    }
}
