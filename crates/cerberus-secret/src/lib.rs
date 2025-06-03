use serde::{
    de::{self},
    Deserialize, Serialize, Serializer,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBox<T: Zeroize + ?Sized> {
    inner_secret: Box<T>,
}

impl<T: Zeroize + ?Sized> From<Box<T>> for SecretBox<T> {
    fn from(value: Box<T>) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize + ?Sized> SecretBox<T> {
    pub fn new(boxed_secret: Box<T>) -> Self {
        Self {
            inner_secret: boxed_secret,
        }
    }
}

impl<T: Zeroize + Clone> Clone for SecretBox<T> {
    fn clone(&self) -> Self {
        Self {
            inner_secret: self.inner_secret.clone(),
        }
    }
}

pub type SecretSlice<S> = SecretBox<[S]>;

impl<S> Clone for SecretSlice<S>
where
    S: Clone + Zeroize,
    [S]: Zeroize,
{
    fn clone(&self) -> Self {
        Self {
            inner_secret: self.inner_secret.clone(),
        }
    }
}

impl<S> From<Vec<S>> for SecretSlice<S>
where
    S: Zeroize,
    [S]: Zeroize,
{
    fn from(value: Vec<S>) -> Self {
        Self::from(value.into_boxed_slice())
    }
}

impl<T: Zeroize + ?Sized> std::fmt::Debug for SecretBox<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBox")
            .field("inner_secret", &"REDACTED")
            .finish()
    }
}

pub trait ExposeSecret<T: Zeroize + ?Sized> {
    fn expose_secret(&self) -> &T;
}

pub trait ExposeSecretMut<T: Zeroize + ?Sized> {
    fn expose_secret_mut(&mut self) -> &mut T;
}

impl<T: Zeroize + ?Sized> ExposeSecret<T> for SecretBox<T> {
    fn expose_secret(&self) -> &T {
        &self.inner_secret
    }
}

impl<T: Zeroize + ?Sized> ExposeSecretMut<T> for SecretBox<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.inner_secret
    }
}

impl<T: Zeroize + ?Sized + Serialize> Serialize for SecretBox<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.expose_secret().serialize(serializer)
    }
}

impl<'de, T: Zeroize + de::DeserializeOwned + Clone> Deserialize<'de> for SecretBox<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut data = T::deserialize(deserializer)?;
        let secret_box = Self::from(Box::new(data.clone()));
        data.zeroize();
        Ok(secret_box)
    }
}

impl<'de, S> Deserialize<'de> for SecretSlice<S>
where
    S: Zeroize + de::DeserializeOwned,
    [S]: Zeroize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let data = Vec::deserialize(deserializer)?;
        let secret_box = Self::from(data.into_boxed_slice());
        Ok(secret_box)
    }
}
