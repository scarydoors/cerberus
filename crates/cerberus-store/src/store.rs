use argon2::password_hash::Output;
use chrono::{NaiveDateTime};
use rand::rngs::OsRng;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use crate::database::Database;
use crate::database::DatabaseTransaction;
use crate::database::Profile;
use crate::database::Repository;
use crate::hash_password;
use crate::symmetric_key::SecureKey;
use crate::symmetric_key::SymmetricKey;
use crate::Error;
use crate::generate_salt;
use crate::vault::Vault;

#[derive(Debug)]
pub struct Store {
    database: Database,
    master_key: Option<Arc<Mutex<SecureKey>>>,
    profile: Option<Profile>
}

impl Store {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(Store {
            database: Database::new(path).await?,
            master_key: None,
            profile: None
        })
    }

    pub async fn unlock(&mut self, password: &str) -> Result<(), Error> {
        self.ensure_profile_retrieved().await?;
        self.ensure_master_key_retrieved().await?;

        let profile = self.profile.as_ref().unwrap();
        let master_key = self.master_key.as_ref().unwrap();

        let mut master_key = master_key.lock().unwrap();

        if !master_key.is_locked() {
            Err(Error::StoreAlreadyUnlocked)
        } else {
            let derived_key = SymmetricKey::from_password(password.as_bytes(), &profile.salt);
            master_key.unlock(&derived_key)?;

            Ok(())
        }
    }

    pub async fn lock(&mut self) -> Result<(), Error> {
        if let None = self.master_key {
            return Err(Error::Locked);
        };

        let master_key = self.master_key.as_ref().unwrap();

        let mut master_key = master_key.lock().unwrap();

        if master_key.is_locked() {
            Err(Error::Locked)
        } else {
            master_key.lock();
            Ok(())
        }
    }

    async fn ensure_profile_retrieved(&mut self) -> Result<(), Error> {
        if let None = self.profile {
            self.profile = Some(self.database.get_profile().await?.ok_or(Error::StoreNotInitialized)?);
        }

        Ok(())
    }

    async fn ensure_master_key_retrieved(&mut self) -> Result<(), Error> {
        if let None = self.master_key {
            let profile = self.profile.as_ref().expect("profile has been initialized and fetched");
            let enc_master_key = self.database.find_key(profile.key_id).await?.expect("key exists because profile exists");

            self.master_key = Some(Arc::new(Mutex::new(SecureKey::new(enc_master_key))));
        }

        Ok(())
    }

    pub async fn initialize_profile(&mut self, name: &str, password: &str) -> Result<(), Error> {
        self.database.get_profile().await?.map_or(Ok(()), |_| Err(Error::ProfileAlreadyExists))?;

        let salt = generate_salt();
        let mut derived_key = SymmetricKey::from_password(password.as_bytes(), &salt);
        let mut master_key = SymmetricKey::generate(&mut OsRng);

        let name_owned = name.to_owned();

        self.profile = Some(self.database.transaction(|mut transaction| {
            Box::pin(async move {
                master_key.store(&mut derived_key, &mut transaction).await?;
                let profile = transaction.store_profile(&name_owned, &salt, master_key.id().unwrap()).await?;

                Ok::<_, Error>(profile)
            })
        }).await?);

        Ok(())
    }

    pub async fn create_vault(&self, name: &str, password: &str) -> Result<Vault, Error> {

        self.database.transaction(|transaction| {
            Box::pin(async move {

                Ok::<_, Error>(())
            })
        }).await?;

        let vault_record = self.database.store_vault(name).await?;

        let mut vault = vault_record.to_vault(self.database.clone());

        vault.initialize_vault_key(password.as_bytes()).await?;

        Ok(vault)
    }

}
