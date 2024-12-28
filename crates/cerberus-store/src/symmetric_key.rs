use crate::nonce_counter::NonceCounter;

struct SymmetricKey {
    key: Vec<u8>,
    nonce_counter: NonceCounter
}

impl SymmetricKey {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            nonce_counter: NonceCounter::new(nonce)
        }
    }

    pub fn from_encrypted_key(encrypted_key: &[u8], nonce: &[u8], symmetric_key: &SymmetricKey) -> Self {

    }
}
