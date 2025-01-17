use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{crypto::EncryptedData, database::record_types::EncryptedKeyRecord};

#[derive(Serialize, Deserialize)]
struct ItemOverview {
    name: String,
}

#[derive(Serialize, Deserialize)]
struct ItemData {
    secret: String,
}

pub struct Item {
    id: i64,
    enc_overview: EncryptedData<ItemOverview>,
    enc_data: EncryptedData<ItemData>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    enc_overview_key: EncryptedKeyRecord,
    enc_data_key: EncryptedKeyRecord,
}

impl Item {
    pub(crate) fn new(
        id: i64,
        enc_overview: EncryptedData<ItemOverview>,
        enc_data: EncryptedData<ItemOverview>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) {
    }
}
