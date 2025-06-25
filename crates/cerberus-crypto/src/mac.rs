use crate::{kdf::DeriveKey, NewKey};
use cerberus_secret::{ExposeSecret, SecretSlice};
use hmac::{digest::CtOutput, Hmac, Mac};
use sha2::Sha256;

pub use cerberus_macros::UpdateHmac;
use thiserror::Error;

use crate::KeyIdentifier;

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub trait UpdateHmac<M: Mac = HmacSha256> {
    fn update_hmac(&self, hmac: &mut impl Mac);
}

#[derive(Debug, Clone)]
pub struct HmacKey {
    key: SecretSlice<u8>,
    id: KeyIdentifier,
}

impl HmacKey {
    pub const KEY_SIZE: usize = 32;

    pub fn id(&self) -> &KeyIdentifier {
        &self.id
    }

    pub fn verify_tag(&self, data: impl UpdateHmac, tag: &[u8]) -> Result<(), InvalidMacError> {
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
        HmacSha256::new_from_slice(self.key.expose_secret())
            .expect("HMAC should accept keys of any size")
    }
}

#[derive(Debug, Error)]
#[error("mac mismatch")]
pub struct InvalidMacError;

impl NewKey for HmacKey {
    const KEY_SIZE: usize = 32;

    fn new_unchecked(key: SecretSlice<u8>, id: KeyIdentifier) -> Self {
        Self { key, id }
    }
}

impl DeriveKey for HmacKey {
    const MAC_INFO_SUFFIX: &'static str = "_hmac_key";
}
