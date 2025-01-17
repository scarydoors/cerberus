use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug)]
pub enum NonceError {
    #[error("cannot create nonce counter, the slice used to initialize the nonce counter must be 24 bytes long")]
    IncorrectNonceLength,
    #[error("cannot increment the nonce anymore")]
    NonceExhausted,
}

#[derive(Default, Debug, Copy, Clone, Serialize, Deserialize)]
pub(crate) struct NonceCounter {
    inner: [u8; 24],
}

impl NonceCounter {
    pub fn new(value: &[u8]) -> Result<Self, NonceError> {
        Ok(Self {
            inner: value
                .try_into()
                .map_err(|_| NonceError::IncorrectNonceLength)?,
        })
    }

    pub fn get_value(&self) -> [u8; 24] {
        self.inner
    }

    pub fn increment(&mut self) -> Result<(), NonceError> {
        for (idx, byte) in self.inner.iter_mut().enumerate() {
            if *byte == 0b11111111 && idx == 23 {
                return Err(NonceError::NonceExhausted);
            } else if *byte == 0b11111111 {
                continue;
            }

            *byte += 1;
            break;
        }

        Ok(())
    }
}

impl From<[u8; 24]> for NonceCounter {
    fn from(value: [u8; 24]) -> Self {
        NonceCounter { inner: value }
    }
}

impl TryFrom<&[u8]> for NonceCounter {
    type Error = NonceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_increment_nonce_counter() {
        let mut nonce_counter = NonceCounter::default();

        assert_eq!(nonce_counter.get_value(), [0; 24]);

        nonce_counter
            .increment()
            .expect("haven't iterated enough times to exhaust the counter");
        assert_eq!(nonce_counter.get_value()[0], 0b00000001);
        assert_eq!(&nonce_counter.get_value()[1..], [0; 23]);
    }

    #[test]
    fn can_exhaust_nonce_counter() {
        let mut nonce_counter = NonceCounter::default();

        for _ in 0..24 {
            for _ in 0..255 {
                nonce_counter
                    .increment()
                    .expect("haven't iterated enough times to exhaust the counter");
            }
        }

        let result = nonce_counter.increment();
        assert!(matches!(result, Err(NonceError::NonceExhausted)));
    }
}
