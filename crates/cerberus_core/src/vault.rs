use std::collections::BTreeMap;

use serde::{Serialize, Deserialize};
use time::OffsetDateTime;

use crate::crypto::{SecretBox, EncryptedData, argon2, Keychain, EncryptedKey, random_bytes};
use chacha20poly1305::aead::{self, OsRng};
use crate::primitive::{NonceCounter, Cipher};
use crate::secret::ExposeSecret;

pub struct Locked;
pub struct Unlocked {
    keychain: Keychain
}

trait State : private::Sealed {}
impl private::Sealed for Locked {}
impl private::Sealed for Unlocked {}
impl State for Locked {}
impl State for Unlocked {}

#[derive(Serialize, Deserialize)]
pub struct Vault<State = Locked> {
    name: String,
    counter: NonceCounter,
    items: Vec<Item>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    state: State,
}

impl Vault<Locked> {
    pub fn new(name: &str) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            name: name.to_owned(),
            counter: NonceCounter::default(),
            items: Vec::new(),
            created_at: now,
            updated_at: now,
            state: Locked,
        }
    }

    pub fn unlock(self, password: &[u8]) -> Vault<Unlocked> {
        let derived_key = argon2(password, b"whatwhatwhatwhat");
        Vault {
            name: self.name,
            counter: self.counter,
            items: self.items,
            created_at: self.created_at,
            updated_at: self.updated_at,
            state: Unlocked {
                keychain: Keychain::new(derived_key.expose_secret()),
            },
        }
    }
}

impl Vault<Unlocked> {
    pub fn add_item(&mut self, item: Item) {
        self.items.push(item);
    }

    pub fn keychain(&self) -> &Keychain {
        &self.state.keychain
    }
}

#[derive(Serialize, Deserialize)]
pub struct Item {
    overview: EncryptedData<ItemOverview>,
    overview_key: EncryptedKey,
    details: EncryptedData<ItemDetails>,
    detail_key: EncryptedKey,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Item {
    pub fn new(name: &str, site: &str, password: &str, keychain: &Keychain) -> Self {
        let cipher = Cipher::new()
        let now = OffsetDateTime::now_utc();
        let overview_key = random_bytes(&mut OsRng, 32);
        let overview = EncryptedData::new(
            ItemOverview {
                name: name.to_owned(),
                site: site.to_owned(),
            },
            cipher
        ).unwrap();

        let detail_key = random_bytes(&mut OsRng, 32);
        let details = EncryptedData::new(
            ItemDetails {
                password: password.to_owned(),
            },
            cipher
        ).unwrap();

        Self {
            overview,
            overview_key: EncryptedKey::new(overview_key.expose_secret(), cipher).unwrap(),
            details,
            detail_key: EncryptedKey::new(detail_key.expose_secret(), cipher).unwrap(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ItemOverview {
    name: String,
    site: String,
}

#[derive(Serialize, Deserialize)]
struct ItemDetails {
    password: String
}

mod private {
    pub trait Sealed {}
}
