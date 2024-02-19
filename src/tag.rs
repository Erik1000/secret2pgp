use std::{io::Write, ops::Deref, time::SystemTime};

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use sequoia_openpgp::{
    cert::SubkeyBuilder,
    packet::{
        key::{Key4, SecretParts, UnspecifiedRole},
        signature::SignatureBuilder,
        Key, UserID,
    },
    parse::{
        stream::{VerificationHelper, VerifierBuilder},
        Parse,
    },
    policy::StandardPolicy,
    serialize::{
        stream::{LiteralWriter, Message, Signer},
        MarshalInto,
    },
    types::{Features, HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm},
    Cert, Fingerprint, Packet,
};
use serde::{de::Error as _, ser::Error as _, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

use crate::{rng::SecretSeededHkdfRng, Base64UrlBytes};

pub const DOMAIN_SEPARATION: &str = "tag.erik-tesar.com";
pub const PRIMARY_KEY_INFO: &[u8] = b"/tag/openpgp/primary-key";
pub const SIGNING_SUBKEY_INFO: &[u8] = b"/tag/openpgp/subkey/sig/0";
pub const AUTHENTICATION_SUBKEY_INFO: &[u8] = b"/tag/openpgp/subkey/aut/0";
pub const ENCRYPTION_SUBKEY_INFO: &[u8] = b"/tag/openpgp/subkey/enc/0";

/// Uid cascade levels as per 6.4.4 ISO-14443-3
///
/// <http://www.emutag.com/iso/14443-3.pdf>
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum Uid {
    Level1([u8; 4]),
    Level2([u8; 7]),
    Level3([u8; 10]),
}

impl Uid {
    #[allow(unused)]
    pub fn from_base64urlsafe(uid: &str) -> anyhow::Result<Self> {
        let v = Base64UrlUnpadded::decode_vec(uid)?;
        Self::try_from(v)
    }

    pub fn from_hex(uid: &str) -> anyhow::Result<Self> {
        let v = hex::decode(uid)?;
        Self::try_from(v)
    }
}

impl TryFrom<Vec<u8>> for Uid {
    type Error = anyhow::Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(match value.len() {
            4 => Self::Level1(value.try_into().unwrap()),
            7 => Self::Level2(value.try_into().unwrap()),
            10 => Self::Level3(value.try_into().unwrap()),
            _ => return Err(anyhow!("Invalid data length")),
        })
    }
}

impl Deref for Uid {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Level1(x) => &x[..],
            Self::Level2(x) => &x[..],
            Uid::Level3(x) => &x[..],
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct PrivateTag {
    /// Unique identifier of the NFC tag
    uid: Uid,
    /// A 256bit pseudorandom key of which the sha256 hash is stored in the server
    identity_key: [u8; 32],
    /// A 256bit pseudorandom key which is never seen by the server party and
    /// shall only be used on-device to derive cryptographic keys (e.g. OpenPGP keys).
    /// The server knowns the public openpgp key derived from this secret.
    secret_key: [u8; 32],
    /// Date this tag was created. This is not the manufacture date but choosen by you. The date does not matter but is needed for the pgp certificate and is part of the tag identity.
    creation_date: DateTime<Utc>,
}

impl PrivateTag {
    pub fn from_encoded(
        uid: Uid,
        identity_key: &str,
        secret_key: &str,
        creation_date: &str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            uid,
            identity_key: decode_b64urlsafe(identity_key)?,
            secret_key: decode_b64urlsafe(secret_key)?,
            creation_date: DateTime::parse_from_rfc3339(creation_date)?.to_utc(),
        })
    }

    pub fn generate(uid: Uid, creation_date: DateTime<Utc>) -> (Self, String) {
        let mut identity_key = [0; 32];
        OsRng.fill_bytes(&mut identity_key);
        let mut secret_key = [0; 32];
        OsRng.fill_bytes(&mut secret_key);

        let encoded_identity = Base64UrlUnpadded::encode_string(&identity_key);
        let encoded_secret = Base64UrlUnpadded::encode_string(&secret_key);
        (
            Self {
                uid,
                identity_key,
                secret_key,
                creation_date,
            },
            // i is sent to the server by the browser
            // everything after `#` is not sent to the server
            format!(
                "https://{DOMAIN_SEPARATION}/v1/t/open?i={encoded_identity}#s={encoded_secret}"
            ),
        )
    }
    pub fn derive_pgp_certificate(&self) -> anyhow::Result<Cert> {
        let uid = &self.uid;
        let secret = self.secret_key;
        let creation_time: SystemTime = self.creation_date.into();
        let expiration_time: Option<SystemTime> = None;
        let policy_reference_time = None;
        let primary_key_info: Vec<u8> = DOMAIN_SEPARATION
            .as_bytes()
            .iter()
            .chain(PRIMARY_KEY_INFO)
            .cloned()
            .collect();
        let signing_key_info: Vec<u8> = DOMAIN_SEPARATION
            .as_bytes()
            .iter()
            .chain(SIGNING_SUBKEY_INFO)
            .cloned()
            .collect();
        let authentication_subkey_info: Vec<u8> = DOMAIN_SEPARATION
            .as_bytes()
            .iter()
            .chain(AUTHENTICATION_SUBKEY_INFO)
            .cloned()
            .collect();
        let encryption_subkey_info: Vec<u8> = DOMAIN_SEPARATION
            .as_bytes()
            .iter()
            .chain(ENCRYPTION_SUBKEY_INFO)
            .cloned()
            .collect();

        // generate keys
        let primary_key =
            generate_ed25519_key(&secret, &primary_key_info, creation_time)?.role_into_primary();
        let mut primary_keypair = primary_key.clone().into_keypair()?;

        let signing_subkey = generate_ed25519_key(&secret, &signing_key_info, creation_time)?
            .role_into_subordinate();

        let authentication_subkey =
            generate_ed25519_key(&secret, &authentication_subkey_info, creation_time)?
                .role_into_subordinate();

        let encryption_subkey =
            generate_x25519_key(&secret, &encryption_subkey_info, creation_time)?
                .role_into_subordinate();

        let primary_key_binding_builder = SignatureBuilder::new(SignatureType::DirectKey)
            .set_signature_creation_time(creation_time)?
            .set_key_expiration_time(&primary_key, None)?
            .set_key_flags(KeyFlags::empty().set_certification())?
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
            .set_features(Features::empty().set_seipdv1())?;

        let primary_key_binding =
            primary_key_binding_builder.sign_direct_key(&mut primary_keypair, None)?;

        // create certificate containing only the primary key
        let cert =
            Cert::from_packets([primary_key.into(), primary_key_binding.into()].into_iter())?;

        let policy = StandardPolicy::default();

        let valid_cert = cert.with_policy(&policy, policy_reference_time)?;
        // new cert with primary key and signing subkey
        let cert = SubkeyBuilder::new(valid_cert, signing_subkey, KeyFlags::empty().set_signing())?
            .set_signature_creation_time(creation_time)?
            .set_key_expiration_time(expiration_time)?
            .attach_cert()?;

        let valid_cert = cert.with_policy(&policy, policy_reference_time)?;
        // new cert with primary, signing and authentication keys
        let cert = SubkeyBuilder::new(
            valid_cert,
            authentication_subkey,
            KeyFlags::empty().set_authentication(),
        )?
        .set_signature_creation_time(creation_time)?
        .set_key_expiration_time(expiration_time)?
        .attach_cert()?;

        let valid_cert = cert.with_policy(&policy, policy_reference_time)?;
        // new cert with primary, signing, authentication and encryption keys
        let cert = SubkeyBuilder::new(
            valid_cert,
            encryption_subkey,
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
        )?
        .set_signature_creation_time(creation_time)?
        .set_key_expiration_time(expiration_time)?
        .attach_cert()?;

        // add an userid because GnuPG does not import the key otherwise
        let user_id = userid_from_uid(uid)?;
        let user_id_binding_builder = SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
            .set_features(Features::empty().set_seipdv1())?
            // primary since it's the only...
            .set_primary_userid(true)?
            .set_key_flags(KeyFlags::empty().set_certification())?
            .set_signature_creation_time(creation_time)?;
        let user_id_binding = user_id.bind(&mut primary_keypair, &cert, user_id_binding_builder)?;

        let (cert, changed) =
            cert.insert_packets2::<[Packet; 2]>([user_id.into(), user_id_binding.into()])?;
        assert!(changed, "UserID should have changed the certificate");

        Ok(cert)
    }
}

#[derive(Debug)]
pub struct TagIdentity {
    /// Unique identifier of the NFC tag
    pub uid: Uid,
    /// Datetime at which this NFC tag identity was created
    pub creation_time: DateTime<Utc>,
    /// Sha256 hash of the identity_key. Basically a password used for server side authentication
    pub identity_hash: [u8; 32],
    /// Fingerprint of the derived openpgp identity
    pub pgp_fingerprint: Fingerprint,
}

impl TryFrom<PrivateTag> for TagIdentity {
    type Error = anyhow::Error;
    fn try_from(value: PrivateTag) -> Result<Self, Self::Error> {
        let pgp_fingerprint = value.derive_pgp_certificate()?.fingerprint();
        let mut hasher = Sha256::new();
        hasher.update(value.identity_key);
        let identity_hash = hasher.finalize().into();
        Ok(Self {
            uid: value.uid,
            creation_time: value.creation_date,
            identity_hash,
            pgp_fingerprint,
        })
    }
}

impl<'de> Deserialize<'de> for TagIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            uid: Base64UrlBytes,
            creation_time: String,
            identity_hash: Base64UrlBytes,
            pgp_fingerprint: String,
        }

        let repr = Repr::deserialize(deserializer)?;
        Ok(Self {
            uid: Uid::try_from(repr.uid.0).map_err(D::Error::custom)?,
            creation_time: DateTime::parse_from_rfc3339(&repr.creation_time)
                .map_err(D::Error::custom)?
                .to_utc(),
            identity_hash: repr
                .identity_hash
                .0
                .try_into()
                .map_err(|_| D::Error::custom("Identiy hash length invalid"))?,
            pgp_fingerprint: Fingerprint::from_hex(&repr.pgp_fingerprint)
                .map_err(D::Error::custom)?,
        })
    }
}

impl Serialize for TagIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Repr {
            uid: Base64UrlBytes,
            creation_time: String,
            identity_hash: Base64UrlBytes,
            pgp_fingerprint: String,
        }
        let repr = Repr {
            uid: Base64UrlBytes((*self.uid).into()),
            creation_time: self.creation_time.to_rfc3339(),
            identity_hash: Base64UrlBytes(self.identity_hash.into()),
            pgp_fingerprint: self.pgp_fingerprint.to_hex(),
        };
        repr.serialize(serializer)
    }
}

pub struct StoredTag {
    pub identity: TagIdentity,
    pub pgp_certificate: Cert,
    /// pgp signature over `identity` made by the signing key of the derived pgp cert
    ///
    /// Contains multiple pgp packets
    pub pgp_identity_self_signature: Vec<u8>,
}

impl StoredTag {
    /// Create a stored tag discarding secret parts of [`PrivateTag`] afterwards
    pub fn create(private: PrivateTag) -> anyhow::Result<Self> {
        let policy = StandardPolicy::at(private.creation_date);
        let cert = private.derive_pgp_certificate()?;
        let valid_cert = cert.with_policy(&policy, Some(private.creation_date.into()))?;
        let keypair = valid_cert
            .keys()
            .secret()
            .find(|k| k.for_signing())
            .ok_or(anyhow!("pgp certificate does not have signing key"))?
            .key()
            .clone()
            .into_keypair()?;

        let tag_identity: TagIdentity = private.clone().try_into()?;
        let serialized = serde_json::to_string(&tag_identity)?;

        let mut sink = Vec::new();
        {
            let message = Message::new(&mut sink);

            let sig_builder = SignatureBuilder::new(SignatureType::Binary);

            let message = Signer::with_template(message, keypair, sig_builder)
                .hash_algo(HashAlgorithm::SHA256)?
                .creation_time(private.creation_date)
                .build()?;

            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(serialized.as_bytes())?;
            message.finalize()?;
        }
        Ok(Self {
            identity: private.try_into()?,
            pgp_certificate: cert,
            pgp_identity_self_signature: sink,
        })
    }
}

impl VerificationHelper for StoredTag {
    fn get_certs(
        &mut self,
        ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
        if self
            .pgp_certificate
            .keys()
            .any(|k| ids.contains(&k.key_handle()))
        {
            Ok(vec![self.pgp_certificate.clone()])
        } else {
            Err(anyhow!("no certificate found"))
        }
    }
    fn check(
        &mut self,
        _structure: sequoia_openpgp::parse::stream::MessageStructure,
    ) -> sequoia_openpgp::Result<()> {
        Ok(())
    }
}

impl<'de> Deserialize<'de> for StoredTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            identity: TagIdentity,
            pgp_certificate: Base64UrlBytes,
            pgp_identity_self_signature: Base64UrlBytes,
        }
        let repr = Repr::deserialize(deserializer)?;

        let identity = repr.identity;
        let pgp_certificate = Cert::from_bytes(&repr.pgp_certificate.0)
            .map_err(|e| D::Error::custom(anyhow!("Cannot deserialize pgp certificate: {e}")))?;

        let stored_tag = Self {
            identity,
            pgp_certificate,
            pgp_identity_self_signature: repr.pgp_identity_self_signature.0.clone(),
        };

        // verify self signature
        let self_sig = VerifierBuilder::from_bytes(&repr.pgp_identity_self_signature.0)
            .map_err(|e| D::Error::custom(anyhow!("Cannot deserialize pgp self signature: {e}")))?;
        let policy = StandardPolicy::default();
        let self_sig = self_sig
            .with_policy(&policy, None, stored_tag)
            .map_err(|e| D::Error::custom(anyhow!("Cannot verify self signature: {e}")))?;

        if !self_sig.message_processed() {
            return Err(D::Error::custom(anyhow!("Failed to verify self signature")));
        }

        let stored_tag = self_sig.into_helper();
        Ok(stored_tag)
    }
}

impl Serialize for StoredTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Repr<'a> {
            identity: &'a TagIdentity,
            pgp_certificate: Base64UrlBytes,
            pgp_identity_self_signature: Base64UrlBytes,
        }

        let repr = Repr {
            identity: &self.identity,
            pgp_certificate: Base64UrlBytes(
                self.pgp_certificate
                    .export_to_vec()
                    .map_err(S::Error::custom)?,
            ),
            pgp_identity_self_signature: Base64UrlBytes(self.pgp_identity_self_signature.clone()),
        };
        repr.serialize(serializer)
    }
}

fn generate_ed25519_key(
    secret: &[u8],
    info: &[u8],
    creation_time: SystemTime,
) -> anyhow::Result<Key<SecretParts, UnspecifiedRole>> {
    let mut rng = SecretSeededHkdfRng::new(None, secret, info);

    let key: SigningKey = SigningKey::generate(&mut rng);
    let key = Key4::import_secret_ed25519(key.as_bytes(), creation_time)?;
    Ok(Key::from(key))
}

fn generate_x25519_key(
    secret: &[u8],
    info: &[u8],
    creation_time: SystemTime,
) -> anyhow::Result<Key<SecretParts, UnspecifiedRole>> {
    let rng = SecretSeededHkdfRng::new(None, secret, info);

    let mut private = StaticSecret::random_from_rng(rng).to_bytes();

    // x25519-dalek weird behavior: https://gitlab.com/sequoia-pgp/sequoia/-/issues/1087
    // TODO: probably fixed in >1.18
    private[0] &= 0b1111_1000;
    private[31] &= !0b1000_0000;
    private[31] |= 0b0100_0000;

    let key = Key4::import_secret_cv25519(
        &private,
        HashAlgorithm::SHA256,
        SymmetricAlgorithm::AES128,
        creation_time,
    )?;
    Ok(Key::from(key))
}

fn userid_from_uid(uid: &[u8]) -> anyhow::Result<UserID> {
    let encoded = Base64UrlUnpadded::encode_string(uid);
    UserID::from_address(None, None, format!("{encoded}@{DOMAIN_SEPARATION}"))
}

fn decode_b64urlsafe<const N: usize>(input: &str) -> anyhow::Result<[u8; N]> {
    // must use Vec otherwise inputs that are too short are not detected
    let decoded = Base64UrlUnpadded::decode_vec(input)?;
    <[u8; N]>::try_from(decoded).map_err(|_| anyhow!("invalid length for input data"))
}
