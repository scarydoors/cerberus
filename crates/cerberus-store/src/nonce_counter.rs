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

    pub fn increment(&mut self) {
        for byte in self.inner.iter_mut() {
            if *byte == 0b11111111 {
                continue;
            }

            *byte += 1;
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_increment_nonce_counter() {
        let mut nonce_counter = NonceCounter::default();
        nonce_counter.increment();
        nonce_counter.increment();
        nonce_counter.increment();
        panic!("{:?}", nonce_counter);
    }
}
