use super::{Cipher, EncryptedData, EncryptedKey, SymmetricKey};
use crate::Error;
use serde::{Serialize, de::DeserializeOwned};

pub(crate) enum SecureKeyState {
    Locked,
    Unlocked,
}

#[derive(Debug)]
pub(crate) struct SecureKey {
    decrypted_key: Option<SymmetricKey>,
    encrypted_key: EncryptedKey,
}

impl SecureKey {
    pub(crate) fn new(encrypted_key: EncryptedKey) -> Self {
        Self {
            encrypted_key,
            decrypted_key: None,
        }
    }

    pub(crate) fn new_unlocked(encrypted_key: EncryptedKey, decrypted_key: SymmetricKey) -> Self {
        Self {
            decrypted_key: Some(decrypted_key),
            encrypted_key,
        }
    }

    pub(crate) fn unlock(&mut self, parent_key: &SymmetricKey) -> Result<(), Error> {
        let symmetric_key = self.encrypted_key.try_to_symmetric_key(parent_key)?;

        self.decrypted_key = Some(symmetric_key);

        Ok(())
    }

    pub(crate) fn lock(&mut self) {
        self.decrypted_key = None;
    }

    pub(crate) fn get_state(&self) -> SecureKeyState {
        if self.is_locked() {
            SecureKeyState::Locked
        } else {
            SecureKeyState::Unlocked
        }
    }

    pub(crate) fn is_locked(&self) -> bool {
        self.decrypted_key.is_none()
    }

    fn get_decrypted_key(&self) -> Result<&SymmetricKey, Error> {
        self.decrypted_key.as_ref().ok_or(Error::Locked)
    }
}

impl Cipher for SecureKey {
    fn encrypt<T: Serialize + DeserializeOwned>(
        &self,
        data: &T,
    ) -> Result<EncryptedData<T>, Error> {
        self.get_decrypted_key()?.encrypt(data)
    }

    fn decrypt<T: Serialize + DeserializeOwned>(
        &self,
        data: &EncryptedData<T>,
    ) -> Result<T, Error> {
        self.get_decrypted_key()?.decrypt(data)
    }
}
