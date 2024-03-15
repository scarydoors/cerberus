use std::ops::Deref;

use thiserror::Error;
use serde::{Deserialize, Serialize};
use super::keys::{Key, types::Mac};
use hmac::{Mac as HmacMac, digest::{FixedOutput, MacError}};

#[derive(Deserialize, Serialize, Clone)]
pub struct Signed<T: Serialize>
{
    #[serde(flatten)]
    inner: T,
    mac: Box<[u8]>,
}

#[derive(Error, Debug)]
pub enum SignedError {
    #[error("error while calculating mac: {0}")]
    MacCalculationError(#[from] bincode::Error),
    #[error("mac is invalid or empty: {0}")]
    MacVerifyError(#[from] MacError),
}

impl<T: Serialize> Signed<T> {
    pub fn new(value: T, mac_key: &Key<Mac>) -> Result<Self, SignedError> {
        let value_as_bytes = bincode::serialize(&value)?;
        let mut mac = mac_key.new_hmac();
        mac.update(&value_as_bytes);
        
        Ok(Self {
            inner: value,
            mac: Vec::from(mac.finalize_fixed().as_slice()).into_boxed_slice()
        })
    }

    pub fn into_inner(&self, mac_key: &Key<Mac>) -> Result<&T, SignedError> {
        let value_as_bytes = bincode::serialize(&self.inner)?;
        let mut mac = mac_key.new_hmac();
        println!("{:?}", mac_key.deref());
        mac.update(&value_as_bytes);
        println!("{:?}", mac.finalize_fixed());

        Ok(&self.inner)
    }
}
