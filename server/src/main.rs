use eyre::eyre;
use libsecret2pgp::tag::Uid;
use log::info;
use rocket::{
    http::{uri::Reference, Status},
    request::{FromRequest, Outcome},
    response::{status::BadRequest, Redirect, Responder},
    Request, Response, Rocket, State,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DisplayFromStr;
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::PgPoolOptions,
    types::chrono::{FixedOffset, NaiveTime},
    PgPool,
};
use std::{borrow::Cow, collections::HashSet, io, net::IpAddr};

#[allow(clippy::declare_interior_mutable_const)]
pub const FORBIDDEN_REDIRECT: Reference<'static> =
    uri!("https://www.youtube.com/watch?v=JaotiOp45dg#s=");

#[allow(clippy::declare_interior_mutable_const)]
pub const DEFAULT_REDIRECT: Reference<'static> =
    uri!("https://www.youtube.com/watch?v=qGyPuey-1Jw#s=");
#[macro_use]
extern crate rocket;

#[main]
async fn main() -> eyre::Result<()> {
    pretty_env_logger::init();
    let rocket = Rocket::build();

    let figment = rocket.figment();

    let config: Config = figment.extract()?;

    let pool = PgPoolOptions::new().connect(&config.database_url).await?;

    sqlx::migrate!("../migrations/").run(&pool).await?;

    rocket
        .mount("/v1/t/", routes![open])
        .manage(pool)
        .launch()
        .await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct Config {
    database_url: String,
}

type Result<T, E = rocket::response::Debug<eyre::Error>> = std::result::Result<T, E>;

pub struct UserAgent<'r>(&'r str);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserAgent<'r> {
    type Error = eyre::Error;
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match req.headers().get_one("User-Agent") {
            Some(user_agent) => Outcome::Success(Self(user_agent)),
            None => Outcome::Error((Status::BadRequest, eyre!("User-Agent header not set"))),
        }
    }
}

#[get("/open?<i>")]
async fn open(
    ip_addr: IpAddr,
    user_agent: Option<UserAgent<'_>>,
    i: &str,
    pool: &State<PgPool>,
) -> Result<Result<Redirect, BadRequest<&'static str>>> {
    use base64ct::Encoding;

    let user_agent = user_agent.map(|inner| inner.0);
    let mut identity_key = [0u8; 32];
    match base64ct::Base64UrlUnpadded::decode(i, &mut identity_key) {
        Ok(written) => {
            if written.len() != 32 {
                return Ok(Err(BadRequest(
                    "identity_key has invalid length. Expected 32 byte",
                )));
            }
        }

        Err(_) => {
            return Ok(Err(BadRequest("invalid base64 urlsafe encoding")));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(identity_key);
    let identity_hash = hasher.finalize();

    sqlx::query!(
        r#"INSERT INTO access_log (address, user_agent, identity_hash)
        VALUES ($1, $2, $3)
    "#,
        ip_addr as _,
        user_agent,
        &*identity_hash as _
    )
    .execute(pool.inner())
    .await
    .map_err(|e| eyre!(e))?;

    // search if there is an expected hash stored from some known tag
    let uid: Option<Uid> = sqlx::query!(
        r#"SELECT "uid" FROM tags WHERE identity_hash = $1"#,
        &*identity_hash,
    )
    .try_map(|r| Uid::try_from(r.uid).map_err(|e| sqlx::Error::Decode(e.into())))
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| eyre!(e))?;

    match uid {
        Some(uid) => {
            info!("Successfully authenticated tag with uid `{:?}`", uid);
            let (action, _requirements) = sqlx::query!(r#"SELECT actions.action_id AS "action_id!", actions.action AS "action!", actions.requirements AS "requirements!" FROM active_actions
            INNER JOIN actions ON active_actions.action_id = actions.action_id
            WHERE active_actions.tag_uid = $1"#, &*uid).try_map(|record| {
                info!("{record:#?}");
                let action: ActionRepr = serde_json::from_value(record.action).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                let action = Action::Redirect(match action {
                    ActionRepr::Redirect { to } => Redirect::to(to.to_string())
                });

                let requirements: HashSet<Requirement> = serde_json::from_value(record.requirements).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                Ok((action, requirements))
                // TODO: fetch multiple actions and check requirements and warn if there are multiple actions that would match
            }).fetch_optional(pool.inner()).await.map_err(|e| eyre!(e))?.unzip();

            let action = action.unwrap_or(Action::Redirect(Redirect::to(DEFAULT_REDIRECT)));
            let Action::Redirect(redirect) = action;

            Ok(Ok(redirect))
        }
        None => {
            info!(
                "Failed to authenticate tag with identity_hash `{:x}`",
                identity_hash
            );
            Ok(Ok(Redirect::to(FORBIDDEN_REDIRECT)))
        }
    }
}

#[derive(Debug, Responder)]
pub enum Action {
    Redirect(Redirect),
}

#[derive(Deserialize, Serialize)]
enum ActionRepr<'a> {
    Redirect { to: Cow<'a, str> },
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match ActionRepr::deserialize(deserializer)? {
            ActionRepr::Redirect { to } => Self::Redirect(Redirect::to(to.to_string())),
        })
    }
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum Requirement {
    // from <= now <= to
    BetweenTimeOfDay {
        #[serde_as(as = "DisplayFromStr")]
        timezone: FixedOffset,
        #[serde_as(as = "DisplayFromStr")]
        from: NaiveTime,
        #[serde_as(as = "DisplayFromStr")]
        to: NaiveTime,
    },
    UserAgent {
        contains: Option<String>,
        name: Option<String>,
        os: Option<String>,
        os_version: Option<String>,
    },
}
