#[derive(thiserror::Error, Debug)]
enum NonceError {
    #[error("cannot increment the nonce anymore")]
    NonceExhausted
}

#[derive(Default, Debug, Copy, Clone)]
struct NonceCounter {
    inner: [u8; 24]
}

impl NonceCounter {
    pub fn new(value: &[u8]) -> Self {
        Self {
            inner: value.try_into().unwrap()
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_increment_nonce_counter() {
        let mut nonce_counter = NonceCounter::default();

        assert_eq!(nonce_counter.get_value(), [0; 24]);

        nonce_counter.increment();
        assert_eq!(nonce_counter.get_value()[0], 0b00000001);
        assert_eq!(&nonce_counter.get_value()[1..], [0; 23]);
    }

    #[test]
    fn can_exhaust_nonce_counter() {
        let mut nonce_counter = NonceCounter::default();

        for _ in 0..24 {
            for _ in 0..255 {
                nonce_counter.increment().expect("haven't iterated enough times to exceed the counter");
            }
        }

        let result = nonce_counter.increment();
        assert!(matches!(result, Err(NonceError::NonceExhausted)));
    }
}
