//! Directory-bound integrated-circuit college notices; no inferred routes.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url, article_body, article_output, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, invalid_article, invalid_list, is_http, parse_iso_date,
    retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, IC_NOTICES_URL, IC_ROOT_URL, Response, ic_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学集成电路科学与工程学院";

fn source_mode(mode: CacheMode) -> CacheMode {
    if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    }
}

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("ic.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && ic_path_allowed(url.path())
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let directory = crate::organizations::list(source_mode(mode))?;
    let attribution =
        college_directory_attribution(&directory, "集成电路科学与工程学院", IC_ROOT_URL)?;
    Ok((ArchiveClient::open_ic(source_mode(mode))?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => IC_ROOT_URL,
        "notices" => IC_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, IC_ROOT_URL, IC_NOTICES_URL, &mut attribution)?;
    }
    let url = Url::parse(raw).map_err(|_| unavailable())?;
    client.with_cache_mode(mode).get(&url, false, |response| {
        describe_college_surface(response, "ic", attribution)
    })
}

fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(element_text)
        .unwrap_or_default();
    let rows = Selector::parse("div.fl1 ul.lt18 > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse("a.a[href]").map_err(|_| unavailable())?;
    let heading = Selector::parse("h4").map_err(|_| unavailable())?;
    let day_selector = Selector::parse("div.time big").map_err(|_| unavailable())?;
    let year_selector = Selector::parse("div.time small").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in document.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let title = row
            .select(&heading)
            .next()
            .map(element_text)
            .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
            .ok_or_else(|| {
                failed_contract(
                    "IC notice row requires nonempty h4 source title",
                    file!(),
                    line!(),
                )
            })?;
        let listed_href = row
            .select(&anchors)
            .next()
            .and_then(|node| node.value().attr("href"));
        if listed_href
            .is_some_and(|href| href.len() > MAX_HREF || href.chars().any(char::is_control))
        {
            return Err(unavailable());
        }
        let date = row
            .select(&day_selector)
            .next()
            .zip(row.select(&year_selector).next())
            .and_then(|(day, year)| {
                let year = element_text(year);
                let year = year.strip_prefix('/')?.trim();
                parse_iso_date(&format!("{year}-{}", element_text(day)))
            });
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
            "IC notice listing requires fl1/lt18 source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(IC_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        college_html(response)?;
        advertised_page_url(&response.body, &latest, page, |url| {
            plain_url(url) && url.path().starts_with("/tzgg/")
        })
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
    bind_college_board(&client, IC_ROOT_URL, IC_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target,false,|response| {
        let document = parse_listing(&college_html(response)?,&target)?;
        let entries:Vec<&ListingEntry> = document.entries.iter().filter(|entry| entry_in_scope(entry,&since,&until,&query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"ic","category":"tzgg","listing_label":"通知公告","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"source_year_and_month_day; missing stays null"},
            "retrieval":retrieval(response)}))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1042/")
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
    bind_college_board(&client, IC_ROOT_URL, IC_NOTICES_URL, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing = client.get(&source, false, |response| {
        let document = parse_listing(&college_html(response)?, &source)?;
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Err(Error::new(
                "unsupported",
                "retained notice page does not declare the selected IC article",
            ));
        }
        Ok(retrieval(response))
    })?;
    // Retain validated original HTML even if its content layout has drifted.
    // A parser error remains an error, not an empty/full-text success; this
    // allows an offline source correction without another remote observation.
    client
        .with_cache_mode(mode)
        .get(target, false, |response| {
            let document = college_html(response)?;
            Ok(normalize(response, &document).map(|mut value| {
                value["publisher"] = json!(PUBLISHER);
                value["college"] = json!("ic");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let title_selector = Selector::parse("div.ar_tit h3").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_HREF)
        .ok_or_else(|| {
            failed_contract(
                "IC article requires its ar_tit/h3 source heading",
                file!(),
                line!(),
            )
        })?;
    let date_selector = Selector::parse("div.ar_tit div.con p").map_err(|_| unavailable())?;
    let published_at = document
        .select(&date_selector)
        .filter_map(|node| {
            let text = element_text(node);
            parse_iso_date(text.strip_prefix("发布日期：")?.trim())
        })
        .next();
    let bodies = Selector::parse("div.v_news_content").map_err(|_| unavailable())?;
    let mut bodies = document.select(&bodies);
    let body = bodies.next().ok_or_else(|| {
        failed_contract(
            "IC article requires its source body container",
            file!(),
            line!(),
        )
    })?;
    if bodies.next().is_some() {
        return Err(unavailable());
    }
    let (paragraphs, attachment_hints, attachments_found) = article_body(body)?;
    let article = ArticleDocument {
        title,
        category: Some("1042".into()),
        published_at,
        paragraphs,
        attachment_hints,
        attachments_found,
    };
    Ok(article_output(response, article))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://ic.buaa.edu.cn/info/1042/42.htm".into(),
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
    fn article_uses_publication_header_not_sidebar_heading() {
        let source = response(
            r#"<h2>通知公告</h2><div class="ar_tit"><h3>Fixture published policy</h3><div class="con"><p>发布日期：2026-09-29</p></div></div><div class="v_news_content"><p>Source policy paragraph.</p><p><script>not prose</script></p></div>"#,
        );
        let value = normalize(&source, &college_html(&source).unwrap()).unwrap();
        assert_eq!(value["title"], "Fixture published policy");
        assert_eq!(value["published_at"], "2026-09-29");
        assert_eq!(
            value["body_paragraphs"],
            json!(["Source policy paragraph."])
        );
    }

    #[test]
    fn ambiguous_article_bodies_do_not_become_combined_prose() {
        let source = response(
            r#"<div class="ar_tit"><h3>Fixture policy</h3></div><div class="v_news_content"><p>Desktop paragraph.</p></div><div class="mbody ph"><div class="v_news_content"><p>Mobile duplicate.</p></div></div>"#,
        );
        assert_eq!(
            normalize(&source, &college_html(&source).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn listing_dates_are_source_dates_and_missing_dates_stay_missing() {
        let source = response(
            r#"<title>Fixture notices</title><div class="fl1"><ul class="lt18"><li><a class="a" href="info/1042/42.htm"><div class="time"><big>09-29</big><small>/ 2026</small></div><h4>Fixture policy</h4></a></li><li><a class="a" href="info/1042/43.htm"><div class="time"><big>02-29</big><small>/ 2026</small></div><h4>Unknown date policy</h4></a></li></ul></div>"#,
        );
        let document = parse_listing(
            &college_html(&source).unwrap(),
            &Url::parse(IC_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(document.entries[0].date.as_deref(), Some("2026-09-29"));
        assert_eq!(document.entries[1].date, None);
        let dated: Vec<_> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &Some("2026-09-01".into()), &None, &None))
            .map(|entry| entry.title.as_str())
            .collect();
        assert_eq!(dated, ["Fixture policy"]);
    }

    #[test]
    fn inert_pagination_cannot_override_the_advertised_board() {
        let base = Url::parse(IC_NOTICES_URL).unwrap();
        let source = br#"<template><div class="pb_sys_common"><span class="p_no"><a href="tzgg/999.htm">2</a></span></div></template><div class="pb_sys_common"><span class="p_no"><a href="tzgg/22.htm">2</a></span></div>"#;
        let selected = advertised_page_url(source, &base, 2, |url| {
            plain_url(url) && url.path().starts_with("/tzgg/")
        })
        .unwrap();
        assert_eq!(selected.path(), "/tzgg/22.htm");
        let foreign = br#"<div class="pb_sys_common"><span class="p_no"><a href="https://foreign.example/tzgg/22.htm">2</a></span></div>"#;
        assert_eq!(
            advertised_page_url(foreign, &base, 2, plain_url)
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn untyped_html_or_active_base_cannot_authorize_a_source() {
        let mut untyped = response("<title>Fixture</title>");
        untyped.headers.clear();
        assert_eq!(college_html(&untyped).unwrap_err().code, "unavailable");
        let mut prefix = response("<title>Fixture</title>");
        prefix
            .headers
            .insert("content-type".into(), "text/html-unknown".into());
        assert_eq!(college_html(&prefix).unwrap_err().code, "unavailable");
        let base = response(r#"<base href="https://foreign.example/"><title>Fixture</title>"#);
        assert_eq!(college_html(&base).unwrap_err().code, "unavailable");
    }

    #[test]
    fn hidden_or_ambiguous_directory_members_do_not_grant_egress() {
        let member = json!({"name":"集成电路科学与工程学院","resolved_http_url":IC_ROOT_URL,"hidden_in_source":false});
        let mut hidden = member.clone();
        hidden["hidden_in_source"] = json!(true);
        for entries in [json!([hidden]), json!([member.clone(), member])] {
            assert_eq!(
                college_directory_attribution(
                    &json!({"entries":entries}),
                    "集成电路科学与工程学院",
                    IC_ROOT_URL
                )
                .unwrap_err()
                .code,
                "unavailable"
            );
        }
    }
}
