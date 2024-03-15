//! [`Secret`] utility type handling sensitive data.
//! Based on the `secrecy` crate.

use zeroize::Zeroize;

pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }
}

pub trait ExposeSecret<T> {
    fn expose_secret(&self) -> &T;
}

impl<T: Zeroize> ExposeSecret<T> for Secret<T> {
    fn expose_secret(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}
