use rand::{CryptoRng, RngCore};

pub mod keys;
pub mod hmac;

pub fn random_bytes(mut rng: impl CryptoRng + RngCore, length: usize) -> Vec<u8> {
    let mut result = vec![0u8; length];
    rng.fill_bytes(&mut result);
    result
}
