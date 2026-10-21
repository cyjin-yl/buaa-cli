//! Mechanical Engineering and Automation college source boundary.
//!
//! The official directory preserves an HTTP member at
//! `http://www.me.buaa.edu.cn/`.  Public reconnaissance found the reviewed
//! `xyxw.htm` (学院新闻) and `xszx.htm` (学术资讯) boards and their
//! `/info/1126/` and `/info/1128/` article namespaces, but the HTTPS endpoint
//! cannot currently be admitted: `www.me.buaa.edu.cn` presents a certificate
//! whose names do not match the requested host and the canonical host's TLS
//! handshake ends without a response.  Plain HTTP is never used as a
//! fallback.  Keep this adapter surface-only until a validated HTTPS source
//! is available; no listing/article bytes are asserted from the HTTP probe.

use super::{ListQuery, invalid_article, invalid_list, parse_iso_date};
use crate::net::{CacheMode, Error};
use serde_json::Value;
use url::Url;

const TLS_BLOCKER: &str = "mechanical-engineering source is surface-only: HTTPS certificate names do not match www.me.buaa.edu.cn and canonical me.buaa.edu.cn TLS ended unexpectedly; plaintext HTTP fallback is disabled";

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    if !matches!(page, "root" | "notices") {
        return Err(Error::new("invalid_input", "unknown college surface page"));
    }
    let _ = (mode, page);
    Err(Error::new("unsupported", TLS_BLOCKER))
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    if query
        .category
        .as_deref()
        .is_some_and(|category| !matches!(category, "xyxw" | "xszx"))
        || query.page == Some(0)
    {
        return Err(invalid_list());
    }
    query
        .since
        .as_deref()
        .map(|raw| parse_iso_date(raw).ok_or_else(invalid_list))
        .transpose()?;
    query
        .until
        .as_deref()
        .map(|raw| parse_iso_date(raw).ok_or_else(invalid_list))
        .transpose()?;
    let _ = mode;
    Err(Error::new("unsupported", TLS_BLOCKER))
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let url = Url::parse(raw).map_err(|_| invalid_article())?;
    let allowed = url.scheme() == "https"
        && url.host_str() == Some("www.me.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && raw == url.as_str()
        && source_page > 0
        && article_namespace(url.path());
    if !allowed {
        return Err(invalid_article());
    }
    let _ = mode;
    Err(Error::new("unsupported", TLS_BLOCKER))
}

fn article_namespace(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/info/") else {
        return false;
    };
    let Some((category, id)) = rest
        .strip_suffix(".htm")
        .and_then(|value| value.split_once('/'))
    else {
        return false;
    };
    matches!(category, "1126" | "1128")
        && !id.is_empty()
        && id.len() <= 10
        && id.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_stops_before_unverified_tls_transport() {
        let error = surface(CacheMode::Offline, "root").unwrap_err();
        assert_eq!(error.code, "unsupported");
        assert!(
            error
                .message
                .contains("plaintext HTTP fallback is disabled")
        );
    }

    #[test]
    fn article_namespace_is_bounded_to_reviewed_categories() {
        assert!(article_namespace("/info/1126/9340.htm"));
        assert!(article_namespace("/info/1128/9011.htm"));
        assert!(!article_namespace("/info/1131/9388.htm"));
        assert!(!article_namespace("/info/1126/not-a-number.htm"));
        assert!(!article_namespace("/info/1126/42.htm?x=1"));
    }

    #[test]
    fn list_and_article_stop_before_transport() {
        let error = list(CacheMode::Offline, &ListQuery::default()).unwrap_err();
        assert_eq!(error.code, "unsupported");
        assert!(
            error
                .message
                .contains("plaintext HTTP fallback is disabled")
        );
        let error = article(
            CacheMode::Offline,
            "https://www.me.buaa.edu.cn/info/1126/9340.htm",
            1,
        )
        .unwrap_err();
        assert_eq!(error.code, "unsupported");
        let error = article(
            CacheMode::Offline,
            "https://www.me.buaa.edu.cn/info/1126/9340.htm?query=foreign",
            1,
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_input");
    }
}
