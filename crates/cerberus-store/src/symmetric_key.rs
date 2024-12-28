use crate::nonce_counter::NonceCounter;

struct SymmetricKey {
    key: Vec<u8>,
    nonce: NonceCounter
}

impl SymmetricKey {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            nonce: NonceCounter::new(nonce)
        }
    }

    pub fn from_encrypted_key(encrypted_key: &[u8], nonce: &[u8], symmetric_key: &SymmetricKey) -> Self {

    }
}
