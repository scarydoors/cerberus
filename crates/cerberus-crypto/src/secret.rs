use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBox<T: Zeroize + ?Sized> {
    inner_secret: Box<T>
}

impl<T: Zeroize + ?Sized> SecretBox<T> {
    pub fn new(boxed_secret: Box<T>) -> Self {
        Self {
            inner_secret: boxed_secret
        }
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

impl<T: Zeroize + ?Sized> From<Box<T>> for SecretBox<T> {
    fn from(boxed_secret: Box<T>) -> Self {
        Self::new(boxed_secret)
    }
}
