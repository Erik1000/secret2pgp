use libsecret2pgp::tag::{PrivateTag, Uid};
use log::info;
use url::Url;

fn start() {
    let url = web_sys::window().unwrap().location().href().unwrap();
    let url: Url = url.parse().unwrap();
    let identity_key = url
        .query_pairs()
        .find(|(name, _)| name == "i")
        .map(|(_, k)| k)
        .unwrap();
    let secret_key = url.fragment().unwrap().trim_start_matches("s=");
    let dummy_uid = Uid::Level1([0, 0, 0, 0]);
    let creation_date = "2024-01-01T00:00:00+00:00";
    info!("{}", url);
    let tag =
        PrivateTag::from_encoded(dummy_uid, &identity_key, secret_key, creation_date).unwrap();
    info!("{:#?}", tag);
}

fn main() {
    console_error_panic_hook::set_once();
    console_log::init().unwrap();
    start();
}
