//! Official-directory-bound Sino-French Aviation college source observations.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url, article_body, article_output, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, invalid_article, invalid_list, is_http, parse_iso_date,
    retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, ZFAI_NOTICES_URL, ZFAI_ROOT_URL, zfai_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学中法航空学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("zfai.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && zfai_path_allowed(url.path())
}

fn source_date(monthday: &str, year: &str) -> Option<String> {
    let monthday: &[u8; 5] = monthday.trim().as_bytes().try_into().ok()?;
    let year: &[u8; 4] = year.trim().as_bytes().try_into().ok()?;
    let mut date = [0; 10];
    date[..4].copy_from_slice(year);
    date[4] = b'-';
    date[5..].copy_from_slice(monthday);
    parse_iso_date(std::str::from_utf8(&date).ok()?)
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let attribution =
        college_directory_attribution(&directory, "中法航空学院", ZFAI_ROOT_URL, ZFAI_ROOT_URL)?;
    Ok((ArchiveClient::open_zfai(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => ZFAI_ROOT_URL,
        "notices" => ZFAI_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, ZFAI_ROOT_URL, ZFAI_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "zfai", attribution)
        })
}

fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let titles = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&titles)
        .next()
        .map(element_text)
        .unwrap_or_default();
    if title.len() > MAX_TEXT {
        return Err(unavailable());
    }
    let containers =
        Selector::parse("div.news div.fl1 > div.wp > ul.list11.flex").map_err(|_| unavailable())?;
    let mut containers = document.select(&containers);
    let primary = containers
        .next()
        .filter(|_| containers.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Zfai information listing requires one fl1/list11 view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a.a").map_err(|_| unavailable())?;
    let headings = Selector::parse(":scope > div.rr > h4.h4s2").map_err(|_| unavailable())?;
    let summaries = Selector::parse(":scope > div.rr > p.ps3").map_err(|_| unavailable())?;
    let monthdays = Selector::parse(":scope > div.time > h3").map_err(|_| unavailable())?;
    let years = Selector::parse(":scope > div.time > h6").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in primary.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut links = row.select(&anchors);
        let anchor = links
            .next()
            .filter(|_| links.next().is_none())
            .ok_or_else(|| {
                failed_contract(
                    "Zfai information row requires one direct a link",
                    file!(),
                    line!(),
                )
            })?;
        let mut row_headings = anchor.select(&headings);
        let title = row_headings
            .next()
            .filter(|_| row_headings.next().is_none())
            .map(element_text)
            .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
            .ok_or_else(|| {
                failed_contract(
                    "Zfai information row requires one rr/h4s2 heading",
                    file!(),
                    line!(),
                )
            })?;
        let listed_href = anchor.value().attr("href");
        if listed_href
            .is_some_and(|href| href.len() > MAX_HREF || href.chars().any(char::is_control))
        {
            return Err(unavailable());
        }
        let mut row_summaries = anchor.select(&summaries);
        let summary = row_summaries
            .next()
            .map(element_text)
            .filter(|text| !text.is_empty());
        if row_summaries.next().is_some()
            || summary.as_ref().is_some_and(|text| text.len() > MAX_TEXT)
        {
            return Err(unavailable());
        }
        let mut row_monthdays = anchor.select(&monthdays);
        let monthday = row_monthdays
            .next()
            .filter(|_| row_monthdays.next().is_none());
        let mut row_years = anchor.select(&years);
        let year = row_years.next().filter(|_| row_years.next().is_none());
        let date = monthday
            .zip(year)
            .and_then(|(monthday, year)| source_date(&element_text(monthday), &element_text(year)));
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
            category_label: Some("信息公告".into()),
            summary,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "Zfai information listing has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(ZFAI_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        college_html(response)?;
        advertised_page_url(
            &response.body,
            &latest,
            page,
            "div.pagebar span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/xxgg1/"),
        )
    })
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    if query
        .category
        .as_deref()
        .is_some_and(|category| category != "xxgg1")
        || query.page == Some(0)
    {
        return Err(invalid_list());
    }
    let page = query.page.unwrap_or(1);
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
    bind_college_board(&client, ZFAI_ROOT_URL, ZFAI_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = parse_listing(&college_html(response)?, &target)?;
        let entries: Vec<&ListingEntry> = document.entries.iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"zfai","category":"xxgg1","listing_label":"信息公告","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"source MM-DD and YYYY; missing or invalid stays null","summaries":"source rr/p.ps3 excerpt; not original full text"},
            "retrieval":retrieval(response)}))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1196/")
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
    bind_college_board(&client, ZFAI_ROOT_URL, ZFAI_NOTICES_URL, &mut attribution)?;
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
                "retained information board does not declare the selected Zfai article",
            ));
        }
        Ok(retrieval(response))
    })?;
    client
        .with_cache_mode(mode)
        .get(target, false, |response| {
            let document = college_html(response)?;
            Ok(normalize(response, &document).map(|mut value| {
                value["publisher"] = json!(PUBLISHER);
                value["college"] = json!("zfai");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
}

fn normalize(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    let forms = Selector::parse("div.detail div.fl1 > div.wp.flex > div.left > form")
        .map_err(|_| unavailable())?;
    let mut forms = document.select(&forms);
    let main = forms
        .next()
        .filter(|_| forms.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Zfai article requires one direct detail/left source form",
                file!(),
                line!(),
            )
        })?;
    let headers = Selector::parse(":scope > div.ar_tit").map_err(|_| unavailable())?;
    let mut headers = main.select(&headers);
    let header = headers
        .next()
        .filter(|_| headers.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Zfai article requires one direct ar_tit header",
                file!(),
                line!(),
            )
        })?;
    let mut titles = header
        .children()
        .filter_map(ElementRef::wrap)
        .filter(|node| node.value().name() == "h3")
        .map(element_text)
        .filter(|title| !title.is_empty());
    let title = titles
        .next()
        .filter(|title| title.len() <= MAX_HREF)
        .ok_or_else(|| {
            failed_contract(
                "Zfai article requires one nonempty direct ar_tit/h3 heading",
                file!(),
                line!(),
            )
        })?;
    if titles.next().is_some() {
        return Err(unavailable());
    }
    let mut dates = header
        .children()
        .filter_map(ElementRef::wrap)
        .filter(|node| node.value().name() == "h6");
    let published_at = dates.next().and_then(|date| {
        date.children()
            .filter_map(ElementRef::wrap)
            .filter(|node| node.value().name() == "span")
            .nth(1)
            .and_then(|node| {
                element_text(node)
                    .strip_prefix("时间：")
                    .and_then(|raw| parse_iso_date(raw.trim()))
            })
    });
    if dates.next().is_some() {
        return Err(unavailable());
    }
    let bodies =
        Selector::parse(":scope > div.ar_article > div#vsb_content_1001 > div.v_news_content")
            .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Zfai article requires one direct vsb_content_1001/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, false)?;
    Ok(article_output(
        response,
        ArticleDocument {
            title,
            category: Some("1196".into()),
            published_at,
            paragraphs,
            attachment_hints,
            attachments_found,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CacheStatus, Response};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://zfai.buaa.edu.cn/info/1196/42.htm".into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            body: body.as_bytes().to_vec(),
            sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            fetched_at_unix_ms: 7,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    fn article_html(header: &str, body: &str) -> String {
        format!(
            r#"<h3>Sidebar heading</h3><div class="detail"><div class="fl1"><div class="wp flex"><div class="left"><form><div class="ar_tit"><h3>Original source heading</h3>{header}</div><div class="ar_article"><div id="vsb_content_1001"><div class="v_news_content">{body}</div></div></div></form></div></div></div></div>"#
        )
    }

    #[test]
    fn ambiguous_date_slots_stay_unknown_and_cannot_satisfy_date_filters() {
        let html = r#"<div class="news"><div class="fl1"><div class="wp"><ul class="list11 flex">
<li><a class="a" href="info/1196/42.htm"><div class="time"><h3>09-14</h3><h3>09-15</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Ambiguous monthday</h4></div></a></li>
<li><a class="a" href="info/1196/43.htm"><div class="time"><h3>09-14</h3><h6>2026</h6><h6>2025</h6></div><div class="rr"><h4 class="h4s2">Ambiguous year</h4></div></a></li>
<li><a class="a" href="info/1196/44.htm"><div class="time"><h3>09-14</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Unambiguous source date</h4></div></a></li>
</ul></div></div></div>"#;
        let parsed = parse_listing(
            &Html::parse_document(html),
            &Url::parse(ZFAI_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(
            parsed
                .entries
                .iter()
                .map(|entry| entry.date.as_deref())
                .collect::<Vec<_>>(),
            vec![None, None, Some("2026-09-14")]
        );
        let since = Some("2026-09-14".into());
        let until = Some("2026-09-14".into());
        let filtered: Vec<_> = parsed
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &None))
            .map(|entry| entry.title.as_str())
            .collect();
        assert_eq!(filtered, vec!["Unambiguous source date"]);
    }

    #[test]
    fn listing_preserves_source_titles_excerpts_order_and_unknown_dates() {
        let html = r#"<title>Information fixture</title><div class="news"><div class="fl1"><div class="wp"><ul class="list11 flex">
<li><a class="a" href="info/1196/42.htm"><div class="time"><h3>06-05</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Earlier source heading</h4><p class="ps3">Distinct excerpt only</p></div></a></li>
<li><a class="a" href="info/1196/43.htm"><div class="time"><h3>09-14</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Later source heading</h4><p class="ps3">Second source excerpt</p></div></a></li>
<li><a class="a" href="info/1196/44.htm"><div class="time"><h3>02-29</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Unknown date heading</h4></div></a></li>
</ul></div></div></div><ul><li><a href="info/1196/99.htm">Unrelated sidebar row</a></li></ul>"#;
        let parsed = parse_listing(
            &Html::parse_document(html),
            &Url::parse(ZFAI_NOTICES_URL).unwrap(),
        )
        .unwrap();
        let rows: Vec<_> = parsed
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.title.as_str(),
                    entry.date.as_deref(),
                    entry.summary.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                (
                    "Earlier source heading",
                    Some("2026-06-05"),
                    Some("Distinct excerpt only")
                ),
                (
                    "Later source heading",
                    Some("2026-09-14"),
                    Some("Second source excerpt")
                ),
                ("Unknown date heading", None, None),
            ]
        );
        let since = Some("2026-09-14".into());
        let until = Some("2026-09-14".into());
        let filtered: Vec<_> = parsed
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &None))
            .map(|entry| entry.title.as_str())
            .collect();
        assert_eq!(filtered, vec!["Later source heading"]);
        assert!(!parsed.entries.iter().any(|entry| entry_in_scope(
            entry,
            &None,
            &None,
            &Some("excerpt only".into())
        )));
    }

    #[test]
    fn pagebar_selects_active_ordinals_without_legacy_container_or_filename_inference() {
        let base = Url::parse(ZFAI_NOTICES_URL).unwrap();
        let source = br#"<div class="pb_sys_common"><span class="p_no"><a href="xxgg1/99.htm">2</a></span></div><template><div class="pagebar"><span class="p_no"><a href="xxgg1/98.htm">2</a></span></div></template><div class="pagebar"><span class="p_no"><a href="xxgg1/8.htm">2</a></span><span class="p_no"><a href="xxgg1/1.htm">3</a></span></div>"#;
        let selected =
            advertised_page_url(source, &base, 2, "div.pagebar span.p_no a[href]", plain_url)
                .unwrap();
        assert_eq!(selected.path(), "/xxgg1/8.htm");
        assert_eq!(
            advertised_page_url(source, &base, 3, "div.pagebar span.p_no a[href]", plain_url)
                .unwrap()
                .path(),
            "/xxgg1/1.htm"
        );
        assert_eq!(
            advertised_page_url(source, &base, 8, "div.pagebar span.p_no a[href]", plain_url)
                .unwrap_err()
                .code,
            "unavailable"
        );
        let foreign = br#"<div class="pagebar"><span class="p_no"><a href="https://foreign.example/xxgg1/8.htm">2</a></span></div>"#;
        assert_eq!(
            advertised_page_url(
                foreign,
                &base,
                2,
                "div.pagebar span.p_no a[href]",
                plain_url
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
    }

    #[test]
    fn article_owns_original_header_table_order_and_second_publication_slot() {
        let body = "<p>Body date 2030-01-01</p><table><tr><td><p>First source cell</p></td><td><p>Second source cell</p></td></tr></table>";
        let source = response(&article_html(
            "<h6><span>时间：2020-01-01<script>counter()</script></span><span>时间：2026-09-14</span><span>时间：2040-01-01</span></h6>",
            body,
        ));
        let parsed = normalize(&source, &college_html(&source).unwrap()).unwrap();
        assert_eq!(parsed["title"], "Original source heading");
        assert_eq!(parsed["published_at"], "2026-09-14");
        assert_eq!(
            parsed["body_paragraphs"],
            json!([
                "Body date 2030-01-01",
                "First source cell",
                "Second source cell"
            ])
        );
        let missing = response(&article_html(
            "<h6><span>时间：2020-01-01</span><span>Invalid publication slot</span><span>时间：2040-01-01</span></h6>",
            body,
        ));
        assert!(
            normalize(&missing, &college_html(&missing).unwrap()).unwrap()["published_at"]
                .is_null()
        );
    }

    #[test]
    fn article_refuses_ambiguous_source_headings_and_bodies() {
        let source = article_html(
            "<h6><span>Count</span><span>时间：2026-09-14</span></h6>",
            "<p>Source policy.</p>",
        );
        let ambiguous_heading = response(&source.replace(
            "<h3>Original source heading</h3>",
            "<h3>Original source heading</h3><h3>Other source heading</h3>",
        ));
        assert_eq!(
            normalize(
                &ambiguous_heading,
                &college_html(&ambiguous_heading).unwrap()
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
        let ambiguous_body = response(&source.replace("<div class=\"v_news_content\"><p>Source policy.</p></div>", "<div class=\"v_news_content\"><p>Source policy.</p></div><div class=\"v_news_content\"><p>Other policy.</p></div>"));
        assert_eq!(
            normalize(&ambiguous_body, &college_html(&ambiguous_body).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }
}
