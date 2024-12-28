use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EncryptedData {
    data: Vec<u8>,
    nonce: [u8; 24],
    key_id: usize
}
