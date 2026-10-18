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

use super::{ListQuery, college_directory_attribution, invalid_article, invalid_list, parse_iso_date};
use crate::net::{CacheMode, Error, ME_NOTICES_URL, ME_ROOT_URL};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://www.me.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学机械工程及自动化学院";
const TLS_BLOCKER: &str = "mechanical-engineering source is surface-only: HTTPS certificate names do not match www.me.buaa.edu.cn and canonical me.buaa.edu.cn TLS ended unexpectedly; plaintext HTTP fallback is disabled";

fn source_mode(mode: CacheMode) -> CacheMode {
    if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    }
}

fn attribution(mode: CacheMode) -> Result<Value, Error> {
    let directory = crate::organizations::list(source_mode(mode))?;
    let mut value = college_directory_attribution(
        &directory,
        "机械工程及自动化学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    value["selected_https_root"] = ME_ROOT_URL.into();
    value["selection_relation"] =
        "deliberate HTTPS candidate; TLS host validation is currently blocked, so the literal HTTP directory identity is not upgraded or used as a source".into();
    Ok(value)
}

fn blocked_surface(page: &str, attribution: Value) -> Value {
    let selected_url = if page == "notices" {
        ME_NOTICES_URL
    } else {
        ME_ROOT_URL
    };
    json!({
        "schema_version": 1,
        "type": "college_source_surface",
        "result": "surface_blocked",
        "publisher": PUBLISHER,
        "college": "me",
        "page": page,
        "selected_url": selected_url,
        "directory_attribution": attribution,
        "fallback_reason": {
            "code": "tls_transport_blocked",
            "message": TLS_BLOCKER,
            "raw_html": null,
            "plaintext_fallback": "disabled"
        },
        "source_contract": {
            "discovered_boards": [
                {"path":"/xyxw.htm","label":"学院新闻","article_namespace":"/info/1126/","selectors":"div.news_l > div.news_l_con > ul > li; div.news_r > div.news_r_tit; div.news_r > p.news_r_tit2; div.news_r > div#vsb_content > div.v_news_content"},
                {"path":"/xszx.htm","label":"学术资讯","article_namespace":"/info/1128/","selectors":"div.noticer > dl; div.news_r > div.news_r_tit; div.news_r > p.news_r_tit2; div.news_r > div#vsb_content > div.v_news_content"}
            ],
            "pagination": "source-advertised links only; no inferred page URLs",
            "article_declarations": "listing-declared canonical links only",
            "verified": false
        },
        "completeness": {
            "scope": "single_explicit_public_page",
            "announcement_adapter_verified": false,
            "links_followed": false,
            "publication_date": "unknown",
            "list_and_article": "blocked_before_transport_by_tls"
        }
    })
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    if !matches!(page, "root" | "notices") {
        return Err(Error::new("invalid_input", "unknown college surface page"));
    }
    Ok(blocked_surface(page, attribution(mode)?))
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
    let Some((category, id)) = rest.strip_suffix(".htm").and_then(|value| value.split_once('/'))
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
    fn surface_preserves_http_directory_identity_and_tls_blocker() {
        let value = blocked_surface("root", json!({"member":{"listed_href":LISTED_ROOT_URL}}));
        assert_eq!(value["result"], "surface_blocked");
        assert_eq!(value["selected_url"], ME_ROOT_URL);
        assert_eq!(value["directory_attribution"]["member"]["listed_href"], LISTED_ROOT_URL);
        assert_eq!(value["fallback_reason"]["code"], "tls_transport_blocked");
        assert_eq!(value["fallback_reason"]["plaintext_fallback"], "disabled");
        assert!(!value["fallback_reason"]["message"]
            .as_str()
            .unwrap()
            .contains("http://www.me.buaa.edu.cn/xyxw.htm"));
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
        assert!(error.message.contains("plaintext HTTP fallback is disabled"));
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
