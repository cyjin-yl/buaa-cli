//! Astronautics college: exact HTTP directory identity, separate HTTPS observation.
use super::{college_directory_attribution, describe_college_surface, unavailable};
use crate::net::{ArchiveClient, CacheMode, Error, SA_ROOT_URL};
use serde_json::Value;
use url::Url;

const LISTED_ROOT_URL: &str = "http://www.sa.buaa.edu.cn/";

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let mut attribution =
        college_directory_attribution(&directory, "宇航学院", LISTED_ROOT_URL, LISTED_ROOT_URL)?;
    attribution["selected_https_root"] = SA_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_sa(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    if page != "root" {
        return Err(Error::new("invalid_input", "unknown college surface page"));
    }
    let (client, attribution) = bound_client(mode)?;
    let target = Url::parse(SA_ROOT_URL).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "sa", attribution)
        })
}
