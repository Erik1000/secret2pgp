use std::{fs::read_to_string, path::PathBuf};

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};

mod base64;
mod rng;
mod tag;

pub use base64::Base64UrlBytes;

use sequoia_openpgp::{
    parse::Parse,
    serialize::{
        stream::{Armorer, Message},
        Serialize, SerializeInto,
    },
    PacketPile,
};
use sha2::{Digest, Sha256};
use tag::{PrivateTag, StoredTag, Uid};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new, random NFC tag identity with the given tag uid
    Generate {
        #[arg(value_parser = |s: &'_ str| Uid::from_hex(s))]
        uid: Uid,
        #[arg(long, default_value_t = false)]
        no_output_link: bool,
        #[arg(long, default_value_t = false)]
        no_output_tag: bool,
    },
    /// Inspect a tag identity with or without secret
    Inspect {
        /// The file containing the JSON serialized tag identity
        filename: PathBuf,
    },
    /// Verify a tag identity
    Verify {
        /// The identity provided which should be checked against the identity file
        provieded_identity: String,
        /// The file containing the JSON serialized tag identity
        #[arg(long, group = "identity")]
        filename: Option<PathBuf>,
        #[arg(group = "identity")]
        identity_hash: Option<String>,
    },
    /// Derive an OpenPGP identity from the secret part of a tag identity
    Derive {
        /// Uid of the tag
        #[arg(long, group = "identity", value_parser = |s: &'_ str| Uid::from_hex(s))]
        uid: Option<Uid>,
        /// The identity_key of this tag
        #[arg(long)]
        identity_key: String,
        /// Filename containing the stored tag information
        #[arg(long, group = "identity")]
        filename: Option<PathBuf>,
        /// The secret key of this tag
        secret_key: String,
        #[arg(long, group = "identity")]
        creation_date: Option<DateTime<Utc>>,
        /// Whether or not the output secret key material
        #[arg(long, default_value_t = false)]
        output_secret: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::try_parse()?;

    match cli.command {
        Commands::Generate {
            uid,
            no_output_link,
            no_output_tag,
        } => {
            let (tag, link) = PrivateTag::generate(uid);
            if !no_output_link {
                eprintln!("{link}");
            }

            let tag = StoredTag::create(tag)?;
            if !no_output_tag {
                println!("{}", serde_json::to_string(&tag)?);
            }
        }
        Commands::Derive {
            uid,
            identity_key,
            filename,
            secret_key,
            creation_date,
            output_secret,
        } => {
            let (uid, creation_date) = filename
                .map(|path| {
                    read_to_string(path)
                        .map_err(|e| anyhow!("Error reading file: {e}"))
                        .and_then(|s| {
                            serde_json::from_str::<StoredTag>(&s)
                                .map_err(|e| anyhow!("Cannot deserialize tag: {e}"))
                        })
                        .map(|s| (s.identity.uid, s.identity.creation_time))
                })
                .unwrap_or_else(|| {
                    uid.ok_or(anyhow!("uid must be provided")).and_then(|uid| {
                        creation_date
                            .ok_or(anyhow!("creation date must be provided"))
                            .map(move |c| (uid, c))
                    })
                })?;

            let tag = PrivateTag::from_encoded(
                uid,
                &identity_key,
                &secret_key,
                // yes, parsing this twice is dumb but i dont care to change the methods arguments
                &creation_date.to_rfc3339(),
            )?;
            let derive = tag.derive_pgp_certificate()?;
            let mut writer = std::io::stdout();
            if output_secret {
                derive.as_tsk().export(&mut writer)?;
            } else {
                derive.export(&mut writer)?;
            }
        }
        Commands::Verify {
            filename,
            identity_hash,
            provieded_identity,
        } => {
            let expected_hash: [u8; 32] = {
                match identity_hash {
                    Some(hash) => Base64UrlUnpadded::decode_vec(&hash)?
                        .try_into()
                        .map_err(|v: Vec<u8>| anyhow!("Invalid hash length: {}", v.len()))?,
                    None => {
                        filename
                            .map(|file| {
                                let s = read_to_string(file)?;
                                let tag: StoredTag = serde_json::from_str(&s)?;
                                Ok::<_, anyhow::Error>(tag)
                            })
                            .transpose()?
                            .ok_or(anyhow!("no identity hash provided"))?
                            .identity
                            .identity_hash
                    }
                }
            };
            let decoded: [u8; 32] = Base64UrlUnpadded::decode_vec(&provieded_identity)?
                .try_into()
                .map_err(|v: Vec<u8>| anyhow!("Invalid identity length: {}", v.len()))?;
            let mut hasher = Sha256::new();
            hasher.update(decoded);
            let actual_hash: [u8; 32] = hasher.finalize().into();
            if expected_hash == actual_hash {
                return Ok(());
            } else {
                return Err(anyhow!("Identity verification failed."));
            }
        }
        Commands::Inspect { filename } => {
            let s = read_to_string(filename)?;
            let tag: StoredTag =
                serde_json::from_str(&s).map_err(|e| anyhow!("Invalid tag: {e}"))?;

            let uid = hex::encode(&*tag.identity.uid);
            let identity_hash = hex::encode(tag.identity.identity_hash);

            let armor_cert = String::from_utf8(tag.pgp_certificate.armored().to_vec()?)?;

            let sig = PacketPile::from_bytes(&tag.pgp_identity_self_signature)?;
            let mut sink = Vec::new();
            {
                let message = Message::new(&mut sink);
                let mut armorer = Armorer::new(message)
                    .kind(sequoia_openpgp::armor::Kind::Signature)
                    .build()?;
                sig.export(&mut armorer)?;
                armorer.finalize()?;
            }
            let armor_sig = String::from_utf8(sink)?;
            println!(
                include_str!("inspect.txt"),
                &uid,
                tag.identity.creation_time,
                &identity_hash,
                tag.identity.pgp_fingerprint.to_hex(),
                armor_cert,
                armor_sig,
            );
        }
    }

    Ok(())
}
