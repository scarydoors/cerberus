use chacha20poly1305::KeyInit;
use hmac::{digest::CtOutput, Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use crate::{secret::{ExposeSecret, SecretSlice}, Result};

pub use cerberus_macros::VerifyHmac;

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub trait VerifyHmac<M: Mac + KeyInit = HmacSha256> {
    fn update_hmac(&self, hmac: &mut impl Mac);

    fn compute_tag<K: AsRef<[u8]>>(&self, key: K) -> CtOutput<M> {
        let mut mac = <M as KeyInit>::new_from_slice(key.as_ref()).expect("HMAC should accept keys of any size");
        self.update_hmac(&mut mac);
        mac.finalize()
    }

    fn verify_tag<K: AsRef<[u8]>>(&self, key: K, tag: &[u8]) -> Result<()> {
        let mut mac = <M as KeyInit>::new_from_slice(key.as_ref()).expect("HMAC should accept keys of any size");
        self.update_hmac(&mut mac);
        Ok(mac.verify(tag.into())?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacKey {
    key: SecretSlice<u8>
}

impl HmacKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key: key.into()
        }
    }
}
