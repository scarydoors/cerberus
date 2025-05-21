use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use crate::Result;

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub trait VerifyHmac: Sized {
    fn update_hmac(&self, hmac: &mut HmacSha256);
    fn verify_hmac(&self, hmac_key: &HmacKey, tag: &[u8]) -> Result<()> {
        hmac_key.verify(self, tag)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacKey {
    #[serde(with="crate::base64")]
    key: Vec<u8>
}

impl HmacKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key
        }
    }

    pub fn verify<T: VerifyHmac>(&self, data: &T, tag: &[u8]) -> Result<()> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac key can be any size");
        data.update_hmac(&mut mac);
        Ok(mac.verify_slice(tag)?)
    }
}
