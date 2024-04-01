use base64ct::{Base64UrlUnpadded, Encoding};
use eyre::{eyre, Context};
use libsecret2pgp::{
    tag::{StoredTag, Uid},
    Base64UrlBytes,
};

use log::warn;
use rocket::{
    http::{uri::Reference, Status},
    outcome::{try_outcome, IntoOutcome},
    request::{FromRequest, Outcome},
    response::{status::BadRequest, Redirect, Responder},
    serde::json::Json,
    Request, Rocket, State,
};
use sequoia_openpgp::serialize::SerializeInto;
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
use url::Url;

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
        .mount(
            "/v1/t/",
            routes![open_tag, add_tag, list_tags, set_redirect, delete_tag],
        )
        .manage(pool)
        .manage(config)
        .launch()
        .await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct Config {
    database_url: String,
    authorization_token_hash: Base64UrlBytes,
}

type Result<T, E = rocket::response::Debug<eyre::Error>> = std::result::Result<T, E>;

pub struct UserAgent<'r>(&'r str);

pub struct Authenticator;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authenticator {
    type Error = eyre::Error;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let header = try_outcome!(req
            .headers()
            .get_one("Authorization")
            .ok_or(eyre!("missing `Authorization` header"))
            .or_error(Status::Unauthorized));

        let token = try_outcome!(header
            .split_once("Bearer")
            .ok_or(eyre!("invalid `Authorization` header, expected `Bearer`"))
            .or_error(Status::Unauthorized))
        .1
        .trim();

        let token = try_outcome!(Base64UrlUnpadded::decode_vec(token)
            .map_err(|e| eyre!("invalid `Authorization` token: {e}"))
            .or_error(Status::Unauthorized));

        let mut hasher = Sha256::new();
        hasher.update(token);
        let hash = hasher.finalize();

        let config = try_outcome!(req
            .rocket()
            .state::<Config>()
            .ok_or(eyre!("missing `Config` state"))
            .or_error(Status::InternalServerError));

        match *hash == config.authorization_token_hash.0 {
            true => Outcome::Success(Self),
            false => Outcome::Error((Status::Unauthorized, eyre!("invalid `Authorization` token"))),
        }
    }
}

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
async fn open_tag(
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

#[post("/add", data = "<tag>")]
async fn add_tag(
    _auth: Authenticator,
    pool: &State<PgPool>,
    tag: Json<StoredTag>,
) -> Result<(Status, &'static str)> {
    let tag = &*tag;
    let cert = tag.pgp_certificate.export_to_vec().map_err(|e| eyre!(e))?;
    match sqlx::query!(
        "INSERT INTO tags (
        uid, 
        creation_time, 
        identity_hash, 
        pgp_fingerprint, 
        pgp_certificate, 
        pgp_identity_self_signature) 
        VALUES ($1::bytea, $2, $3::bytea, $4::bytea, $5, $6)",
        &*tag.identity.uid,
        tag.identity.creation_time,
        &tag.identity.identity_hash,
        tag.identity.pgp_fingerprint.as_bytes(),
        &cert,
        tag.pgp_identity_self_signature,
    )
    .execute(pool.inner())
    .await
    {
        Ok(_) => Ok((Status::Ok, "tag created")),
        Err(e) => match e.as_database_error() {
            Some(e) if e.is_unique_violation() => Ok((Status::Conflict, "this tag already exists")),
            _ => Err(eyre!("insert tag failed: {e}").into()),
        },
    }
}

#[derive(Deserialize)]
struct DeleteTag {
    tag_uid: Uid,
}

#[post("/delete", data = "<tag>")]
async fn delete_tag(
    _auth: Authenticator,
    pool: &State<PgPool>,
    tag: Json<DeleteTag>,
) -> Result<(Status, &'static str)> {
    sqlx::query!(
        "DELETE FROM active_actions WHERE tag_uid = $1",
        &*tag.tag_uid
    )
    .execute(pool.inner())
    .await
    .context("failed to delete active actions for tag")?;
    let deleted = sqlx::query!(
        r#"
    DELETE FROM tags WHERE uid = $1;
    "#,
        &*tag.tag_uid
    )
    .execute(pool.inner())
    .await
    .context("failed to delete tag")?
    .rows_affected()
        == 1;
    Ok(match deleted {
        true => (Status::Ok, "tag deleted"),
        false => (Status::NotFound, "tag not found"),
    })
}

#[get("/list")]
async fn list_tags(_auth: Authenticator, pool: &State<PgPool>) -> Result<Json<Vec<StoredTag>>> {
    // sadly, query_as! does not use FromRow
    // see <https://github.com/launchbadge/sqlx/issues/514>
    // because of that, use the function instead of macro
    let tags: Vec<StoredTag> = sqlx::query_as(
        "SELECT 
    uid, 
    creation_time, 
    identity_hash, 
    pgp_fingerprint, 
    pgp_certificate, 
    pgp_identity_self_signature 
    FROM tags 
    -- there should never be more than 1000 tags
    LIMIT 1000",
    )
    .fetch_all(pool.inner())
    .await
    .map_err(|e| eyre!("cannot fetch tags: {e}"))?;
    Ok(Json(tags))
}

#[derive(Deserialize)]
struct RedirectLink {
    /// The link the server should redirect to
    link: Url,
    /// Uid of the tag (can be fetched from /list)
    tag_uid: Uid,
    #[serde(default)]
    keep_secret_key: bool,
}
#[post("/set/redirect", data = "<data>")]
async fn set_redirect(
    _auth: Authenticator,
    pool: &State<PgPool>,
    data: Json<RedirectLink>,
) -> Result<&'static str> {
    let mut link = data.link.clone();
    // overwrite fragment if the link itself does not contain one by itself
    if link.fragment().is_none() && !data.keep_secret_key {
        // the browser will keep the url fragment unless we explicitly set one
        link.set_fragment(Some("s="));
    }

    let link = link.to_string();

    // ensure the link is valid for Reference, because the `url` and rocket seems to differ in validation...
    if let Err(e) = Reference::parse(&link) {
        warn!("a link was parsed successful by the `url` crate but not rocket: `{link}`");
        return Err(eyre!("invalid link: {e}").into());
    }

    let action = ActionRepr::Redirect {
        to: Cow::Borrowed(&link),
    };
    let action = serde_json::to_value(action).map_err(|e| eyre!("cannot serialize action: {e}"))?;

    let action_id = sqlx::query!(
        "INSERT INTO actions(action)
    VALUES ($1)
    RETURNING action_id",
        action
    )
    .fetch_one(pool.inner())
    .await
    .map_err(|e| eyre!("failed to insert action: {e}"))?
    .action_id;

    // simply overwrite active action since currently only one active action is supported
    let overwritten = sqlx::query!(
        "DELETE FROM active_actions WHERE tag_uid = $1",
        &*data.tag_uid
    )
    .execute(pool.inner())
    .await
    .map_err(|e| eyre!(e))?
    .rows_affected()
        == 1;

    sqlx::query!(
        "INSERT INTO active_actions (
        tag_uid, 
        action_id
    ) VALUES ($1::bytea, $2)",
        &*data.tag_uid,
        action_id
    )
    .execute(pool.inner())
    .await
    .map_err(|e| eyre!("cannot update active action: {e}"))?;

    match overwritten {
        true => Ok("updated active action"),
        false => Ok("installed first active action"),
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
