//! Official-directory-bound Physics college notices.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url, article_body, article_output, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, html_fallback, invalid_article, invalid_list,
    is_admitted_html, is_http, is_safe_public_fallback, parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, PHYSICS_NOTICES_URL, PHYSICS_ROOT_URL, Response,
    physics_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://physics.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学物理学院";

fn source_mode(mode: CacheMode) -> CacheMode {
    if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    }
}

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("physics.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && physics_path_allowed(url.path())
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let source_mode = source_mode(mode);
    let directory = crate::organizations::list(source_mode)?;
    let mut attribution =
        college_directory_attribution(&directory, "物理学院", LISTED_ROOT_URL, LISTED_ROOT_URL)?;
    attribution["selected_https_root"] = PHYSICS_ROOT_URL.into();
    attribution["selection_relation"] =
        "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_physics(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => PHYSICS_ROOT_URL,
        "notices" => PHYSICS_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(
            &client,
            PHYSICS_ROOT_URL,
            PHYSICS_NOTICES_URL,
            &mut attribution,
        )?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            if !is_admitted_html(response) {
                return Err(unavailable());
            }
            match describe_college_surface(response, "physics", attribution.clone()) {
                Ok(value) => Ok(value),
                Err(_) if is_safe_public_fallback(response) => Ok(html_fallback(
                    response,
                    "college_source_surface",
                    "physics",
                    "physics_surface_selector_contract",
                )),
                Err(error) => Err(error),
            }
        })
}

fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(element_text)
        .unwrap_or_default();
    if title.len() > MAX_TEXT {
        return Err(unavailable());
    }
    let lists = Selector::parse("ul.news-ul").map_err(|_| unavailable())?;
    let mut lists = document.select(&lists);
    let list = lists.next().ok_or_else(|| {
        failed_contract(
            "Physics notice listing requires one news-ul view",
            file!(),
            line!(),
        )
    })?;
    if lists.next().is_some() {
        return Err(unavailable());
    }
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a[href]").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in list.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut row_anchors = row.select(&anchors);
        let anchor = row_anchors
            .next()
            .filter(|_| row_anchors.next().is_none())
            .ok_or_else(|| {
                failed_contract(
                    "Physics notice row requires one direct anchor",
                    file!(),
                    line!(),
                )
            })?;
        let title = element_text(anchor);
        if title.is_empty() || title.len() > MAX_TEXT {
            return Err(failed_contract(
                "Physics notice row requires a bounded nonempty title",
                file!(),
                line!(),
            ));
        }
        let listed_href = anchor.value().attr("href");
        if listed_href
            .is_some_and(|href| href.len() > MAX_HREF || href.chars().any(char::is_control))
        {
            return Err(unavailable());
        }
        let mut row_dates = row.select(&dates);
        let date = row_dates
            .next()
            .filter(|_| row_dates.next().is_none())
            .and_then(|node| parse_iso_date(element_text(node).trim()));
        let (resolved_http_url, link_kind) = match listed_href {
            None => (None, "missing"),
            Some(raw) => match base.join(raw) {
                Ok(url) if is_http(&url) => (Some(url.to_string()), "http"),
                Ok(_) => (None, "non_http"),
                Err(_) => (None, "invalid"),
            },
        };
        entries.push(ListingEntry {
            source_order: entries.len() + 1,
            title,
            date,
            category_label: Some("通知公告".into()),
            summary: None,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "Physics notice listing has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(PHYSICS_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        college_html(response)?;
        advertised_page_url(
            &response.body,
            &latest,
            page,
            "div.pb_sys_common span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/index/tzgg/"),
        )
    })
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    if query
        .category
        .as_deref()
        .is_some_and(|category| category != "tzgg")
    {
        return Err(invalid_list());
    }
    let page = query.page.unwrap_or(1);
    if page == 0 {
        return Err(invalid_list());
    }
    let since = query
        .since
        .as_deref()
        .map(|raw| parse_iso_date(raw).ok_or_else(invalid_list))
        .transpose()?;
    let until = query
        .until
        .as_deref()
        .map(|raw| parse_iso_date(raw).ok_or_else(invalid_list))
        .transpose()?;
    let (client, mut attribution) = bound_client(mode)?;
    bind_college_board(
        &client,
        PHYSICS_ROOT_URL,
        PHYSICS_NOTICES_URL,
        &mut attribution,
    )?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = match college_html(response).and_then(|html| parse_listing(&html, &target)) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                let mut value = html_fallback(
                    response,
                    "announcements_list",
                    "physics",
                    "physics_listing_selector_contract",
                );
                value["category"] = json!("tzgg");
                value["page"] = json!(page);
                return Ok(value);
            }
            Err(error) => return Err(error),
        };
        let entries: Vec<&ListingEntry> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
            .collect();
        Ok(json!({
            "schema_version": 1,
            "type": "announcements_list",
            "result": "listing_snapshot",
            "publisher": PUBLISHER,
            "college": "physics",
            "category": "tzgg",
            "listing_label": "通知公告",
            "page": page,
            "document_title": document.title,
            "filters": {"since": since, "until": until, "match": query.r#match},
            "entries": entries,
            "entry_count": entries.len(),
            "directory_attribution": attribution,
            "completeness": {
                "scope": "single_college_selected_page",
                "pagination": "source_advertised_ordinal_only; no automatic traversal",
                "other_colleges": "not_covered",
                "dates": "source ISO YYYY-MM-DD; missing or invalid stays null",
                "summaries": "physics board has no source excerpt; original article text is separate"
            },
            "retrieval": retrieval(response)
        }))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1252/")
        || source_page == 0
    {
        return Err(invalid_article());
    }
    let (client, attribution) = bound_client(mode)?;
    article_with_client(client, mode, &target, source_page, attribution)
}

pub(crate) fn article_with_client(
    client: ArchiveClient,
    mode: CacheMode,
    target: &Url,
    source_page: u32,
    mut attribution: Value,
) -> Result<Value, Error> {
    bind_college_board(
        &client,
        PHYSICS_ROOT_URL,
        PHYSICS_NOTICES_URL,
        &mut attribution,
    )?;
    let source = listing_url(&client, source_page)?;
    let listing = client.get(&source, false, |response| {
        let document = match college_html(response).and_then(|html| parse_listing(&html, &source)) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_list",
                    "physics",
                    "physics_listing_selector_contract",
                ));
            }
            Err(error) => return Err(error),
        };
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Err(Error::new(
                "unsupported",
                "retained Physics notice page does not declare the selected article",
            ));
        }
        Ok(retrieval(response))
    })?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained Physics listing could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client.with_cache_mode(mode).get(target, false, |response| {
        let document = match college_html(response) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_article",
                    "physics",
                    "physics_article_selector_contract",
                ));
            }
            Err(error) => return Err(error),
        };
        let mut output = match normalize(response, &document) {
            Ok(output) => output,
            Err(_) if is_safe_public_fallback(response) => html_fallback(
                response,
                "announcements_article",
                "physics",
                "physics_article_selector_contract",
            ),
            Err(error) => return Err(error),
        };
        Ok({
            output["publisher"] = json!(PUBLISHER);
            output["college"] = json!("physics");
            output["directory_attribution"] = attribution.clone();
            output["source_listing"] = listing.clone();
            output
        })
    })
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let titles = Selector::parse("div.article-tt").map_err(|_| unavailable())?;
    let mut titles = document.select(&titles);
    let title = titles
        .next()
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_HREF)
        .ok_or_else(|| {
            failed_contract(
                "Physics article requires one article-tt heading",
                file!(),
                line!(),
            )
        })?;
    if titles.next().is_some() {
        return Err(unavailable());
    }
    let metadata_selector = Selector::parse("div.article-sm").map_err(|_| unavailable())?;
    let mut metadata_nodes = document.select(&metadata_selector);
    let metadata = metadata_nodes.next().ok_or_else(|| {
        failed_contract(
            "Physics article requires one article-sm publication header",
            file!(),
            line!(),
        )
    })?;
    if metadata_nodes.next().is_some() {
        return Err(unavailable());
    }
    let metadata_text = element_text(metadata);
    let mut publication_tokens = metadata_text
        .split_whitespace()
        .filter_map(|token| token.strip_prefix("发布时间："));
    let published_at = publication_tokens
        .next()
        .and_then(|raw| parse_iso_date(raw.trim()));
    if publication_tokens.next().is_some() {
        return Err(unavailable());
    }
    let bodies =
        Selector::parse("div.article-txt div.v_news_content").map_err(|_| unavailable())?;
    let mut bodies = document.select(&bodies);
    let body = bodies.next().ok_or_else(|| {
        failed_contract(
            "Physics article requires one article-txt source body",
            file!(),
            line!(),
        )
    })?;
    if bodies.next().is_some() {
        return Err(unavailable());
    }
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, false)?;
    let article = ArticleDocument {
        title,
        category: Some("1252".into()),
        published_at,
        paragraphs,
        attachment_hints,
        attachments_found,
    };
    let mut output = article_output(response, article);
    output["completeness"]["body_source"] = json!("div.article-txt div.v_news_content p");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(url: &str, body: &str) -> Response {
        Response {
            url: url.into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            body: body.as_bytes().to_vec(),
            sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn listing_preserves_source_order_and_iso_dates() {
        let source = response(
            PHYSICS_NOTICES_URL,
            r#"<title>Fixture notices</title><ul class="news-ul"><li><a href="../info/1252/42.htm">First policy</a><span>2026-10-16 </span></li><li><a href="../info/1252/43.htm">Unknown date</a><span>not-a-date</span></li></ul>"#,
        );
        let document = parse_listing(
            &college_html(&source).unwrap(),
            &Url::parse(PHYSICS_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(document.entries[0].source_order, 1);
        assert_eq!(document.entries[0].date.as_deref(), Some("2026-10-16"));
        assert_eq!(document.entries[1].date, None);
        let filtered: Vec<_> = document
            .entries
            .iter()
            .filter(|entry| {
                entry_in_scope(
                    entry,
                    &Some("2026-10-01".into()),
                    &Some("2026-10-16".into()),
                    &None,
                )
            })
            .map(|entry| entry.title.as_str())
            .collect();
        assert_eq!(filtered, ["First policy"]);
    }

    #[test]
    fn pagination_requires_advertised_physics_destination() {
        let base = Url::parse(PHYSICS_NOTICES_URL).unwrap();
        let source = br#"<template><div class="pb_sys_common"><span class="p_no"><a href="https://foreign.example/index/tzgg/1.htm">2</a></span></div></template><div class="pb_sys_common"><span class="p_no"><a href="tzgg/1.htm">2</a></span></div>"#;
        let selected = advertised_page_url(
            source,
            &base,
            2,
            "div.pb_sys_common span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/index/tzgg/"),
        )
        .unwrap();
        assert_eq!(selected.path(), "/index/tzgg/1.htm");
        let foreign = br#"<div class="pb_sys_common"><span class="p_no"><a href="https://foreign.example/index/tzgg/1.htm">2</a></span></div>"#;
        assert_eq!(
            advertised_page_url(
                foreign,
                &base,
                2,
                "div.pb_sys_common span.p_no a[href]",
                |url| plain_url(url) && url.path().starts_with("/index/tzgg/"),
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
    }

    #[test]
    fn article_uses_publication_header_and_unique_source_body() {
        let source = response(
            "https://physics.buaa.edu.cn/info/1252/42.htm",
            r#"<div class="article-tt">Fixture policy</div><div class="article-sm">发布时间：2026-09-22　作者：<script>click()</script></div><div class="article-txt"><div class="v_news_content"><p>Source paragraph.</p><p><script>not prose</script></p></div></div>"#,
        );
        let output = normalize(&source, &college_html(&source).unwrap()).unwrap();
        assert_eq!(output["title"], "Fixture policy");
        assert_eq!(output["published_at"], "2026-09-22");
        assert_eq!(output["body_paragraphs"], json!(["Source paragraph."]));
        assert_eq!(output["category"], "1252");
    }

    #[test]
    fn ambiguous_article_bodies_fail_closed() {
        let source = response(
            "https://physics.buaa.edu.cn/info/1252/42.htm",
            r#"<div class="article-tt">Fixture policy</div><div class="article-sm">发布时间：2026-09-22</div><div class="article-txt"><div class="v_news_content"><p>Desktop.</p></div><div class="v_news_content"><p>Duplicate.</p></div></div>"#,
        );
        assert_eq!(
            normalize(&source, &college_html(&source).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn url_admission_rejects_queries_and_foreign_paths() {
        assert!(plain_url(
            &Url::parse("https://physics.buaa.edu.cn/").unwrap()
        ));
        assert!(plain_url(
            &Url::parse("https://physics.buaa.edu.cn/info/1252/42.htm").unwrap()
        ));
        assert!(!plain_url(
            &Url::parse("https://physics.buaa.edu.cn/info/1252/42.htm?x=1").unwrap()
        ));
        assert!(!plain_url(
            &Url::parse("https://physics.buaa.edu.cn/info/9999/42.htm").unwrap()
        ));
    }
}
