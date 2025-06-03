use cerberus_secret::{ExposeSecret, SecretSlice};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};

use crate::{KeyIdentifier, NewKey};

pub(crate) type HkdfSha256 = Hkdf<sha2::Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationMaterial {
    key: SecretSlice<u8>,
    id: KeyIdentifier,
}

fn hkdf_extract(ikm: &[u8], label: &str, len: usize) -> SecretSlice<u8> {
    let hkdf = HkdfSha256::new(None, ikm);
    let mut okm = vec![0u8; len];
    hkdf.expand(label.as_bytes(), &mut okm)
        .expect("HKDF expand should not fail");

    SecretSlice::from(okm)
}

fn build_info(label: &str, suffix: &str) -> String {
    format!("{}{}", label, suffix)
}

pub trait DeriveKey: NewKey {
    const MAC_INFO_SUFFIX: &'static str;
}

impl DerivationMaterial {
    pub fn new(key: SecretSlice<u8>, id: KeyIdentifier) -> Self {
        Self { key, id }
    }

    pub fn derive_key<T: DeriveKey>(&self, label: &str) -> T {
        let kdf_info = build_info(label, T::MAC_INFO_SUFFIX);
        let key = hkdf_extract(self.key.expose_secret(), &kdf_info, T::KEY_SIZE);
        let id = KeyIdentifier::derived(kdf_info, Some(self.id.clone()));

        T::new_unchecked(key, id)
    }
}
