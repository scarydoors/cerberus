use chacha20poly1305::{
    aead::{self, generic_array::typenum::Unsigned, Aead, AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use serde::{Deserialize, Serialize};
use crate::secret::Secret;

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct NonceCounter(u128);

impl NonceCounter {
    pub fn with_initial(initial_value: u128) -> Self {
        Self(initial_value)
    }
    
    /// Advances the nonce counter, panics if nonce overflows 12 bytes.
    pub fn advance(&mut self) {
        self.0 += 1;
        if self.0 >> (8 * 12) != 0 {
            panic!("Nonce has overflowed!");
        }
    }

    pub fn as_bytes(self) -> [u8; 12] {
        self.0.to_be_bytes()[4..]
            .try_into()
            .expect("slice is correct length")
    }
}

pub struct Cipher<'a> {
    aead: ChaCha20Poly1305,
    counter: &'a mut NonceCounter,
}

impl<'a> Cipher<'a> {
    pub fn new(cipher_key: &[u8], counter: &'a mut NonceCounter) -> Self {
        Self {
            aead: ChaCha20Poly1305::new_from_slice(cipher_key)
                .expect("cipher key is correct length"),
            counter,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let capacity = plaintext.len() + <ChaCha20Poly1305 as AeadCore>::TagSize::to_usize() + 12;
        let mut result = Vec::with_capacity(capacity);

        let nonce = self.counter.as_bytes();
        let ciphertext = self.aead.encrypt(&nonce.into(), plaintext)?;
        self.counter.advance();

        result.extend(nonce.into_iter());
        result.extend(ciphertext.into_iter());

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8], expected_size: usize) -> Result<SecretData, aead::Error> {
        if ciphertext.len()
            != expected_size + <ChaCha20Poly1305 as AeadCore>::TagSize::to_usize() + 12
        {
            return Err(aead::Error);
        }

        let (nonce, ciphertext) = ciphertext.split_at(12);
        Ok(self.aead.decrypt(nonce.into(), ciphertext)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::NonceCounter;

    #[test]
    fn increment_nonce_counter() {
        let mut nonce = NonceCounter::default();
        assert_eq!(nonce.as_bytes(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        nonce.advance();
        assert_eq!(nonce.as_bytes(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }
}
