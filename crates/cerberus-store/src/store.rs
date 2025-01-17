use chrono::Utc;
use chrono::DateTime;
use rand::rngs::OsRng;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use crate::database::Database;
use crate::database::Repository;
use crate::crypto::{SecureKey, SymmetricKey};
use crate::Error;
use crate::generate_salt;
use crate::vault::{Vault, VaultKey};

#[derive(Debug)]
pub struct Profile {
    id: i64,
    name: String,
    salt: String,
    key_id: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Profile {
    pub(crate) fn new(id: i64, name: String, salt: String, key_id: i64, created_at: DateTime<Utc>, updated_at: DateTime<Utc>) -> Self {
        Self {
            id,
            name,
            salt,
            key_id,
            created_at,
            updated_at,
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
            self.profile = Some(self.database.get_profile().await?.ok_or(Error::StoreNotInitialized)?.into_profile());
        }

        Ok(())
    }

    async fn ensure_master_key_retrieved(&mut self) -> Result<(), Error> {
        if let None = self.master_key {
            let profile = self.profile.as_ref().expect("profile has been initialized and fetched");
            let enc_master_key = self.database.find_key(profile.key_id).await?.expect("key exists because profile exists").into_encrypted_key();

            self.master_key = Some(Arc::new(Mutex::new(SecureKey::new(enc_master_key))));
        }

        Ok(())
    }

    pub async fn initialize_profile(&mut self, name: String, password: &str) -> Result<(), Error> {
        self.database.get_profile().await?.map_or(Ok(()), |_| Err(Error::ProfileAlreadyExists))?;

        let salt = generate_salt();
        let mut derived_key = SymmetricKey::from_password(password.as_bytes(), &salt);
        let master_key = SymmetricKey::generate(&mut OsRng);

        self.profile = Some(self.database.transaction(|mut transaction| {
            Box::pin(async move {
                let mut encrypted_master_key = master_key.into_encrypted_key(&mut derived_key);
                encrypted_master_key.store(&mut transaction).await?;
                let profile_record = transaction.store_profile(&name, &salt, encrypted_master_key.id().unwrap()).await?;

                Ok::<_, Error>(profile_record.into_profile())
            })
        }).await?);

        Ok(())
    }

    pub async fn create_vault(&self, name: String) -> Result<Vault, Error> {
        let master_key = self.master_key.as_ref().ok_or(Error::Locked)?.lock().unwrap();
        let vault_key = SymmetricKey::generate(&mut OsRng);
        let mut encrypted_vault_key = vault_key.into_encrypted_key(&*master_key);

        let (vault_record, encrypted_vault_key) = self.database.transaction(|transaction| {
            Box::pin(async move {
                encrypted_vault_key.store(transaction).await?;
                let vault_record = transaction.store_vault(&name, encrypted_vault_key.id().unwrap()).await?;

                Ok::<_, Error>((vault_record, encrypted_vault_key))
            })
        }).await?;

        let arc_master_key = self.master_key.as_ref().unwrap().clone();
        let database = self.database.clone();
        let vault_key = VaultKey::new(arc_master_key, encrypted_vault_key);

        Ok(vault_record.into_vault(vault_key, database))
    }
}
