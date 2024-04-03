use std::net::IpAddr;

use reqwest::{Client, StatusCode};
use rocket::tokio::sync::mpsc::Receiver;
use serde_json::json;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum TagEvent {
    OpenSuccess(UserAgentMeta),
    OpenFailed(UserAgentMeta),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct UserAgentMeta {
    pub ip_addr: IpAddr,
    pub user_agent: Option<String>,
}

pub async fn listen_for_events(
    client: Client,
    mut recv: Receiver<TagEvent>,
    user: String,
    device: String,
    token: String,
) -> eyre::Result<()> {
    log::debug!("listening...");
    while let Some(event) = recv.recv().await {
        let (title, message) = match event {
            TagEvent::OpenSuccess(meta) => (
                "Tag successfully opened",
                format!(
                    "Opened from `{}` on `{}`",
                    meta.ip_addr,
                    meta.user_agent.unwrap_or("unknown".into()),
                ),
            ),
            TagEvent::OpenFailed(meta) => (
                "Tag denied",
                format!(
                    "`{}` on `{}` tried to open a tag.",
                    meta.ip_addr,
                    meta.user_agent.unwrap_or("unknown".into()),
                ),
            ),
        };

        let req = json!({
            "token": token,
            "user": user,
            "device": device,
            "title": title,
            "message": message,
        });

        match client
            .post(" https://api.pushover.net/1/messages.json ")
            .json(&req)
            .send()
            .await
        {
            Ok(res) => {
                if res.status() != StatusCode::OK {
                    log::error!(
                        "pushover api returned non-200 code: {}:\n{}",
                        res.status(),
                        res.text().await?
                    );
                }
            }
            Err(e) => {
                log::error!("failed to send push message: {e}");
            }
        }
    }

    Ok(())
}
