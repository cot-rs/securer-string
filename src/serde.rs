use core::fmt;
use std::borrow::Borrow;
use std::marker::PhantomData;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{SecureArray, SecureVec};

struct BytesVisitor<Value> {
    phandom_data: PhantomData<Value>,
}

impl<Value> Default for BytesVisitor<Value> {
    fn default() -> Self {
        Self {
            phandom_data: Default::default(),
        }
    }
}

impl<'de, SecureValue: TryFrom<Vec<u8>>> Visitor<'de> for BytesVisitor<SecureValue>
where
    SecureValue::Error: std::fmt::Display,
{
    type Value = SecureValue;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array or a sequence of bytes")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Self::Value::try_from(value.to_vec()).map_err(|error| {
            serde::de::Error::custom(format!(
                "cannot construct secure value from byte slice: {error}"
            ))
        })
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Self::Value::try_from(value).map_err(|error| {
            serde::de::Error::custom(format!(
                "cannot construct secure value from byte vector: {error}"
            ))
        })
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut value: Vec<u8> = Vec::with_capacity(seq.size_hint().unwrap_or(0));

        while let Some(element) = seq.next_element()? {
            value.push(element);
        }

        Self::Value::try_from(value).map_err(|error| {
            serde::de::Error::custom(format!(
                "cannot construct secure value from byte sequence: {error}"
            ))
        })
    }
}

impl<'de> Deserialize<'de> for SecureVec<u8> {
    fn deserialize<D>(deserializer: D) -> Result<SecureVec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(BytesVisitor::default())
    }
}

impl Serialize for SecureVec<u8> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.content.borrow())
    }
}

impl<'de, const LENGTH: usize> Deserialize<'de> for SecureArray<u8, LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(BytesVisitor::default())
    }
}

impl<const LENGTH: usize> Serialize for SecureArray<u8, LENGTH> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.content.borrow())
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::{SecureArray, SecureVec};

    #[test]
    fn test_serde_json() {
        let secure_bytes = SecureVec::from("abc".as_bytes());

        let json = serde_json::to_string_pretty(secure_bytes.unsecure()).unwrap();
        println!("json = {json}");

        let secure_bytes_serde: SecureVec<u8> = serde_json::from_str(&json).unwrap();

        assert_eq!(secure_bytes, secure_bytes_serde);
    }

    #[test]
    fn test_serde_visit_bytes() {
        let de = serde::de::value::BytesDeserializer::<serde::de::value::Error>::new(b"abc");
        let result = SecureVec::<u8>::deserialize(de).unwrap();
        assert_eq!(result.unsecure(), b"abc");
    }

    #[test]
    fn test_serde_array() {
        let data: SecureArray<u8, 3> = SecureArray::from(*b"abc");
        let json = serde_json::to_string(&data).unwrap();
        let result: SecureArray<u8, 3> = serde_json::from_str(&json).unwrap();
        assert_eq!(data, result);
    }
}
