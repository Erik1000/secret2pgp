use std::{io::Write, time::SystemTime};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use clap::Parser;

mod rng;

use ed25519_dalek::SigningKey;
use rng::SecretSeededHkdfRng;
use sequoia_openpgp::{
    cert::SubkeyBuilder,
    crypto::KeyPair,
    packet::{
        key::{Key4, PrimaryRole, SubordinateRole},
        signature::SignatureBuilder,
        Key, UserID,
    },
    policy::StandardPolicy,
    serialize::Serialize,
    types::{Features, HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm},
    Cert, Packet,
};
use x25519_dalek::StaticSecret;

#[derive(Debug, Parser)]
struct Args {
    /// your base64 urlsafe no pad encoded 256bit secret
    #[arg(short, long)]
    seed: String,
    /// tag uid in the format like 04:89:94:5A:E1:71:80
    #[arg(short, long)]
    tag_uid: String,
    /// unix timestamp for key creation. This is part of the key identifier and should be a known value.
    #[arg(short, long)]
    creation_time: Option<i64>,
    /// Optional salt
    #[arg(long)]
    salt: Option<String>,
    /// Expiration time of the keys
    #[arg(long)]
    expiration_time: Option<i64>,
    /// Whether or not to export the secret material of the derived pgp key
    #[arg(long, default_value = "false")]
    export_secret: bool,
}
fn main() -> anyhow::Result<()> {
    let args = Args::try_parse()?;
    let tag_uid =
        base64ct::Base64UrlUnpadded::encode_string(&hex::decode(args.tag_uid.replace(':', ""))?);
    // if the userid is not an email address, some implementations complain..
    // this encodes the unique tag identifier base64 urlsafe no pad
    let tag_uid = format!("{tag_uid}@tag.erik-tesar.com");
    let salt = args.salt.map(|s| s.into_bytes());
    let seed = Base64UrlUnpadded::decode_vec(&args.seed)?;
    let c_time: DateTime<Utc> = DateTime::from_timestamp(args.creation_time.unwrap_or(0), 0)
        .ok_or(anyhow::anyhow!("invalid creation time"))?;

    let e_time = args
        .expiration_time
        .map(|t| DateTime::from_timestamp(t, 0).ok_or(anyhow::anyhow!("invalid expiration time")))
        .transpose()?;
    let e_time: Option<SystemTime> = e_time.map(SystemTime::from);

    // info to derive the key for the primary key
    let mut rng = SecretSeededHkdfRng::new(
        salt.as_deref(),
        &seed,
        b"erik-tesar.com/tag/openpgp/primary-key",
    );

    let policy = StandardPolicy::default();

    let primary_key: SigningKey = SigningKey::generate(&mut rng);

    let primary_key: Key4<_, PrimaryRole> =
        Key4::import_secret_ed25519(&primary_key.to_bytes(), Some(c_time.into()))?;
    let primary_key: Key<_, _> = Key::from(primary_key);
    let mut primary_keypair: KeyPair = primary_key.clone().into_keypair()?;

    // use the primary key only for certification
    let primary_key_flags = KeyFlags::empty()
        .set_certification()
        .set_authentication()
        .set_signing();
    // build the direct key signature for the primary key
    let primary_key_binding_builder = SignatureBuilder::new(SignatureType::DirectKey)
        .set_key_flags(primary_key_flags)?
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])?
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
        .set_features(Features::empty().set_seipdv1())?
        .set_key_expiration_time(&primary_key, e_time)?;
    let primary_key_direct_key_sig =
        primary_key_binding_builder.sign_direct_key(&mut primary_keypair, None)?;

    let packets: [Packet; 2] = [primary_key.into(), primary_key_direct_key_sig.into()];

    // A cert with only the primary key
    let cert = Cert::from_packets(packets.into_iter())?;
    let valid_cert = cert.with_policy(&policy, None)?;

    // info to derive (the first and probably only) encryption subkey
    rng.update_info_reset(b"erik-tesar.com/tag/openpgp/subkey/enc/0");
    let mut private = StaticSecret::random_from_rng(&mut rng).to_bytes();

    // x25519-dalek weird behavior: https://gitlab.com/sequoia-pgp/sequoia/-/issues/1087
    private[0] &= 0b1111_1000;
    private[31] &= !0b1000_0000;
    private[31] |= 0b0100_0000;

    let enc_key = private;
    let enc_key: Key4<_, SubordinateRole> = Key4::import_secret_cv25519(
        &enc_key,
        HashAlgorithm::SHA256,
        SymmetricAlgorithm::AES128,
        Some(c_time.into()),
    )?;
    let enc_key: Key<_, _> = Key::from(enc_key);

    // use the same key for storage and transport encryption (GnuPG does not even differentiate)
    let enc_key_flags = KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption();

    let cert = SubkeyBuilder::new(valid_cert, enc_key, enc_key_flags)?
        //.set_primary_key_signer(primary_keypair.clone())
        .attach_cert()?;

    // finally add a userid does GnuPG does not complain
    let user_id = UserID::from_address(None, None, tag_uid)?;

    let user_id_binding_builder = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])?
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
        .set_features(Features::empty().set_seipdv1())?
        // primary since it's the only...
        .set_primary_userid(true)?
        .set_key_flags(KeyFlags::empty().set_certification())?;
    let user_id_binding = user_id.bind(&mut primary_keypair, &cert, user_id_binding_builder)?;

    let packets: [Packet; 2] = [user_id.into(), user_id_binding.into()];
    let cert = cert.insert_packets(packets)?;

    let valid_cert = cert.with_policy(&policy, None)?;

    let mut stdout: Box<dyn Write> = Box::new(std::io::stdout());
    match args.export_secret {
        true => valid_cert.as_tsk().armored().serialize(&mut stdout)?,
        false => valid_cert.armored().serialize(&mut stdout)?,
    }
    Ok(())
}
