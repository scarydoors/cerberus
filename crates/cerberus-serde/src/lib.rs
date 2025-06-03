pub mod base64 {
    use base64::{engine, Engine};
    use serde::{
        de::{Deserializer, Visitor},
        Serialize, Serializer,
    };
    use std::marker::PhantomData;

    const ENGINE: engine::GeneralPurpose = ::base64::engine::general_purpose::STANDARD_NO_PAD;

    pub fn serialize<T: AsRef<[u8]>, S: Serializer>(
        source: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ENGINE.encode(source).serialize(serializer)
    }

    pub fn deserialize<'de, S: TryFrom<Vec<u8>>, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<S, D::Error> {
        struct Vis<T>(std::marker::PhantomData<T>);
        impl<T> Visitor<'_> for Vis<T>
        where
            T: TryFrom<Vec<u8>>,
        {
            type Value = T;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a base64 string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ENGINE
                    .decode(v)
                    .map_err(E::custom)?
                    .try_into()
                    .map_err(|_| {
                        E::custom(format!(
                            "Failed to convert base64 decoded data to target type"
                        ))
                    })
            }
        }

        deserializer.deserialize_str(Vis::<S>(PhantomData))
    }
}

pub mod base64_expose_secret {
    use cerberus_secret::{ExposeSecret, SecretBox};
    use serde::Serializer;
    use zeroize::Zeroize;

    pub use super::base64::deserialize;

    pub fn serialize<T: AsRef<[u8]> + ?Sized + Zeroize, S: Serializer>(
        source: &SecretBox<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::base64::serialize(&source.expose_secret(), serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::base64;

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "base64")]
        data: Vec<u8>,
    }

    #[test]
    fn test_serialization() {
        let original = TestStruct {
            data: b"hello world".to_vec(),
        };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();

        assert_eq!(original.data, deserialized.data);
    }
}
