use cerberus_secret::{SecretSlice, ExposeSecret};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};

use crate::{mac::HmacKey, KeyIdentifier, NewKey, SymmetricKey};

pub(crate) type HkdfSha256 = Hkdf<sha2::Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationMaterial {
    key: SecretSlice<u8>,
    id: KeyIdentifier,
}

pub fn derive_key(ikm: &[u8], label: &str, len: usize) -> SecretSlice<u8> {
    let hkdf = HkdfSha256::new(None, ikm);
    let mut okm = vec![0u8; len];
    hkdf.expand(label.as_bytes(), &mut okm).expect("HKDF expand should not fail");

    SecretSlice::from(okm)
}

fn build_info(label: &str, suffix: &str) -> String {
    format!("{}{}", label, suffix)
}

trait DeriveKey: NewKey {
    const MAC_INFO_SUFFIX: &'static str;
}

impl DerivationMaterial {
    const SYMMETRIC_SUFFIX: &'static str = "_symmetric_key";
    const HMAC_SUFFIX: &'static str = "_hmac_key";

    pub fn new(key: SecretSlice<u8>, id: KeyIdentifier) -> Self {
        Self {
            key,
            id
        }
    }

    pub fn derive_symmetric_key(&self, label: &str) -> SymmetricKey {
        let kdf_info = build_info(label, Self::SYMMETRIC_SUFFIX);
        let key = derive_key(self.key.expose_secret(), &kdf_info, SymmetricKey::KEY_SIZE);
        let id = KeyIdentifier::derived(kdf_info, Some(self.id.clone()));

        SymmetricKey::new_unchecked(key, id)
    }

    pub fn derive_hmac_key(&self, label: &str) -> HmacKey {
        let kdf_info = build_info(label, Self::HMAC_SUFFIX);
        let key = derive_key(self.key.expose_secret(), &kdf_info, HmacKey::KEY_SIZE);
        let id = KeyIdentifier::derived(kdf_info, Some(self.id.clone()));

        HmacKey::new_unchecked(key, id)
    }
}
