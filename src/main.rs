use std::{fs::read_to_string, path::PathBuf};

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};

mod base64;
mod rng;
mod tag;

pub use base64::Base64UrlBytes;

use sequoia_openpgp::serialize::Serialize;
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
        #[arg(long, default_value_t = true)]
        output_link: bool,
        #[arg(long, default_value_t = true)]
        output_tag: bool,
    },
    /// Inspect a tag identity with or without secret
    Inspect {
        /// The file containing the JSON serialized tag identity
        filename: Option<PathBuf>,
    },
    /// Verify a tag identity
    Verify {
        /// The file containing the JSON serialized tag identity
        filename: Option<PathBuf>,
        /// The identity provided which should be checked against the identity file
        identity: String,
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
            output_link,
            output_tag,
        } => {
            let (tag, link) = PrivateTag::generate(uid);
            if output_link {
                eprintln!("{link}");
            }

            let tag = StoredTag::create(tag)?;
            if output_tag {
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
        _ => unimplemented!(),
    }

    Ok(())
}
