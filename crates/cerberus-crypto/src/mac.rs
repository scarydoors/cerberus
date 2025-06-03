use hmac::{digest::CtOutput, Hmac, Mac};
use sha2::Sha256;
use cerberus_secret::{ExposeSecret, SecretSlice};
use crate::Result;

pub use cerberus_macros::UpdateHmac;

use crate::KeyIdentifier;

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub trait UpdateHmac<M: Mac = HmacSha256> {
    fn update_hmac(&self, hmac: &mut impl Mac);

}

//
//    fn verify_tag<K: AsRef<[u8]>>(&self, key: K, tag: &[u8]) -> Result<()> {
//        let mut mac = <M as KeyInit>::new_from_slice(key.as_ref()).expect("HMAC should accept keys of any size");
//        self.update_hmac(&mut mac);
//        Ok(mac.verify(tag.into())?)
//    }
//    fn compute_tag<K: AsRef<[u8]>>(&self, key: K) -> CtOutput<M> {
//        let mut mac = <M as KeyInit>::new_from_slice(key.as_ref()).expect("HMAC should accept keys of any size");
//        self.update_hmac(&mut mac);
//        mac.finalize()
//    }

#[derive(Debug, Clone)]
pub struct HmacKey {
    key: SecretSlice<u8>,
    id: KeyIdentifier,
}

impl HmacKey {
    pub const KEY_SIZE: usize = 32;

    pub fn new(key: SecretSlice<u8>, id: KeyIdentifier) -> Self {
        Self {
            key,
            id
        }
    }

    pub fn verify_tag(&self, data: impl UpdateHmac, tag: &[u8]) -> Result<()> {
        let mut mac = self.init_hmac();
        data.update_hmac(&mut mac);
        Ok(mac.verify(tag.into())?)
    }

    pub fn compute_tag(&self, data: impl UpdateHmac) -> CtOutput<HmacSha256> {
        let mut mac = self.init_hmac();
        data.update_hmac(&mut mac);
        mac.finalize()
    }

    fn init_hmac(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(self.key.expose_secret()).expect("HMAC should accept keys of any size")
    }
}
