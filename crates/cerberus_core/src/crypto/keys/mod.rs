pub mod encrypted_key;
pub mod encrypted_key_pair;
pub mod key;
pub mod key_pair;

pub mod types {
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

    // TODO: implement Mac
    pub struct Mac {}

    pub struct Cipher(pub(crate) XChaCha20Poly1305);

    pub trait KeyState {
        const KEY_SIZE: usize;
        fn with_key(key: &[u8]) -> Self;
    }

    impl KeyState for Mac {
        const KEY_SIZE: usize = 32;
        fn with_key(_key: &[u8]) -> Self {
            unimplemented!();
        }
    }
    impl KeyState for Cipher {
        const KEY_SIZE: usize = 32;
        fn with_key(key: &[u8]) -> Self {
            Self(XChaCha20Poly1305::new(key.into()))
        }
    }
}

pub use encrypted_key::*;
pub use encrypted_key_pair::*;
pub use key::*;
pub use key_pair::*;
