use super::{Cipher, EncryptedData, SymmetricKey};
use crate::database::Repository;
use crate::Error;

#[derive(Debug)]
pub(crate) struct EncryptedKey {
    id: Option<i64>,
    key_encrypted_data: EncryptedData<Vec<u8>>,
}

impl EncryptedKey {
    pub(crate) fn new(id: Option<i64>, key_encrypted_data: EncryptedData<Vec<u8>>) -> Self {
        Self {
            id,
            key_encrypted_data,
        }
    }

    pub(crate) fn try_to_symmetric_key<K: Cipher>(
        &self,
        parent_key: &K,
    ) -> Result<SymmetricKey, Error> {
        let decrypted_key = parent_key.decrypt(&self.key_encrypted_data)?;
        Ok(SymmetricKey::new(&decrypted_key, self.id))
    }

    pub(crate) async fn store<R: Repository>(&mut self, repo: &mut R) -> Result<(), Error> {
        let key_record = repo.store_key(&self.key_encrypted_data).await?;

        self.id = Some(key_record.id);

        Ok(())
    }

    pub(crate) fn id(&self) -> Option<i64> {
        self.id
    }
}
