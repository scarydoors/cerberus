use argon2::password_hash::Output;
use chrono::Utc;
use chrono::{NaiveDateTime, DateTime};
use rand::rngs::OsRng;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use crate::database::Database;
use crate::database::DatabaseTransaction;
use crate::database::record_types::{Profile, ProfileRecord};
use crate::database::Repository;
use crate::hash_password;
use crate::symmetric_key::SecureKey;
use crate::symmetric_key::SymmetricKey;
use crate::Error;
use crate::generate_salt;
use crate::vault::Vault;


#[derive(Debug)]
pub struct Profile {
    id: i64,
    name: String,
    salt: String,
    key_id: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl ProfileRecord {
    pub(crate) fn into_profile(self) -> Profile {
        Profile {
            id: self.id,
            name: self.name,
            salt: self.salt,
            key_id: self.key_id,
            created_at: self.created_at.and_utc(),
            updated_at: self.updated_at.and_utc(),
        }
    }
}

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
                let profile_record = transaction.store_profile(&name_owned, &salt, master_key.id().unwrap()).await?;

                Ok::<_, Error>(profile_record.into_profile())
            })
        }).await?);

        Ok(())
    }

    pub async fn create_vault(&self, name: &str) -> Result<Vault, Error> {
        let mut master_key = self.master_key.as_ref().ok_or(Error::Locked)?.lock().unwrap();
        let mut vault_key = SymmetricKey::generate(&mut OsRng);

        let vault = self.database.transaction(|transaction| {
            Box::pin(async move {
                vault_key.store(&mut *master_key, transaction).await?;
                let vault_record = transaction.store_vault(name, vault_key.id().unwrap()).await?;

                Ok::<_, Error>(vault_record.into_vault())
            })
        }).await?;

        let vault_record = self.database.store_vault(name).await?;

        let mut vault = vault_record.to_vault(self.database.clone());

        vault.initialize_vault_key(password.as_bytes()).await?;

        Ok(vault)
    }

}
