use crate::nonce_counter::NonceCounter;

struct SymmetricKey {
    key: Vec<u8>,
    nonce_counter: NonceCounter
}

impl SymmetricKey {
    pub fn new(key: &[u8], next_nonce: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            nonce_counter: NonceCounter::new(next_nonce)
        }
    }
}
