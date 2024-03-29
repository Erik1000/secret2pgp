use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{de::Error, Deserialize, Deserializer, Serialize};

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Base64UrlBytes(pub Vec<u8>);

impl Serialize for Base64UrlBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = Base64UrlUnpadded::encode_string(&self.0);
        encoded.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64UrlBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;

        let decoded = Base64UrlUnpadded::decode_vec(&encoded)
            .map_err(|_| D::Error::custom("encountered invalid Base64Url string"))?;

        Ok(Self(decoded))
    }
}
