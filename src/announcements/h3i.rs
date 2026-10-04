//! Official-directory-bound International Innovation college observations.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    article_body, article_output, bind_college_board, college_directory_attribution, college_html,
    describe_college_surface, element_text, entry_in_scope, failed_contract, invalid_article,
    invalid_list, is_http, parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, H3I_NOTICES_URL, H3I_ROOT_URL, Response, h3i_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学国际创新学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("h3i.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && h3i_path_allowed(url.path())
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
        college_directory_attribution(&directory, "国际创新学院", H3I_ROOT_URL, H3I_ROOT_URL)?;
    Ok((ArchiveClient::open_h3i(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => H3I_ROOT_URL,
        "notices" => H3I_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, H3I_ROOT_URL, H3I_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "h3i", attribution)
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
                "H3i recruitment listing requires one fl1/list11 view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a.a[href]").map_err(|_| unavailable())?;
    let headings = Selector::parse("a.a > div.rr > h4.h4s2").map_err(|_| unavailable())?;
    let monthdays = Selector::parse("a.a > div.time > h3").map_err(|_| unavailable())?;
    let years = Selector::parse("a.a > div.time > h6").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in primary.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let title = row
            .select(&headings)
            .next()
            .map(element_text)
            .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
            .ok_or_else(|| {
                failed_contract(
                    "H3i recruitment row requires its rr/h4s2 heading",
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
            .select(&monthdays)
            .next()
            .zip(row.select(&years).next())
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
            category_label: Some("招聘公告".into()),
            summary: None,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "H3i recruitment listing has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    if query
        .category
        .as_deref()
        .is_some_and(|category| category != "cpgg")
        || query.page == Some(0)
    {
        return Err(invalid_list());
    }
    let page = query.page.unwrap_or(1);
    if page != 1 {
        return Err(Error::new(
            "unavailable",
            "H3i recruitment board has no reviewed later-page declaration",
        ));
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
    bind_college_board(&client, H3I_ROOT_URL, H3I_NOTICES_URL, &mut attribution)?;
    let target = Url::parse(H3I_NOTICES_URL).map_err(|_| unavailable())?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = parse_listing(&college_html(response)?, &target)?;
        let entries: Vec<&ListingEntry> = document.entries.iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"h3i","category":"cpgg","listing_label":"招聘公告","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"no reviewed later-page declaration; no traversal","other_colleges":"not_covered","dates":"source MM-DD and YYYY; source order retained; missing or invalid stays null"},
            "retrieval":retrieval(response)}))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1141/")
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
    if source_page != 1 {
        return Err(Error::new(
            "unavailable",
            "H3i recruitment board has no reviewed later-page declaration",
        ));
    }
    bind_college_board(&client, H3I_ROOT_URL, H3I_NOTICES_URL, &mut attribution)?;
    let source = Url::parse(H3I_NOTICES_URL).map_err(|_| unavailable())?;
    let listing = client.get(&source, false, |response| {
        let document = parse_listing(&college_html(response)?, &source)?;
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Err(Error::new(
                "unsupported",
                "retained recruitment page does not declare the selected H3i article",
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
                value["college"] = json!("h3i");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let forms = Selector::parse("div.detail div.fl1 > div.wp.flex > div.left > div > form")
        .map_err(|_| unavailable())?;
    let mut forms = document.select(&forms);
    let main = forms
        .next()
        .filter(|_| forms.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "H3i article requires one detail/left source form",
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
                "H3i article requires one direct ar_tit header",
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
                "H3i article requires one nonempty direct ar_tit/h3 heading",
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
        Selector::parse(":scope > div.ar_article > div#vsb_content_1043 > div.v_news_content")
            .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "H3i article requires one direct vsb_content_1043/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, false)?;
    Ok(article_output(
        response,
        ArticleDocument {
            title,
            category: Some("1141".into()),
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
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://h3i.buaa.edu.cn/info/1141/42.htm".into(),
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
            r#"<h3>Sidebar heading</h3><div class="detail"><div class="fl1"><div class="wp flex"><div class="left"><div><form><div class="ar_tit"><h3>Original source heading</h3>{header}</div><div class="ar_article"><div id="vsb_content_1043"><div class="v_news_content">{body}</div></div></div></form></div></div></div></div></div>"#
        )
    }

    #[test]
    fn listing_preserves_source_order_and_heading_with_real_monthday_dates() {
        let html = r#"<title>Recruitment fixture</title><div class="news"><div class="fl1"><div class="wp"><ul class="list11 flex">
<li><a class="a" href="../info/1141/42.htm"><div class="time"><h3>04-19</h3><h6>2024</h6></div><div class="rr"><h4 class="h4s2">Earlier source row</h4><p>Private summary marker</p></div></a></li>
<li><a class="a" href="../info/1141/43.htm"><div class="time"><h3>03-06</h3><h6>2025</h6></div><div class="rr"><h4 class="h4s2">Later source row</h4></div></a></li>
<li><a class="a" href="../info/1141/44.htm"><div class="time"><h3>02-30</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Unknown date row</h4></div></a></li>
</ul></div></div></div><ul><li><a href="../info/1141/99.htm">Unrelated sidebar row</a></li></ul>"#;
        let parsed = parse_listing(
            &Html::parse_document(html),
            &Url::parse(H3I_NOTICES_URL).unwrap(),
        )
        .unwrap();
        let rows: Vec<_> = parsed
            .entries
            .iter()
            .map(|entry| (entry.title.as_str(), entry.date.as_deref()))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("Earlier source row", Some("2024-04-19")),
                ("Later source row", Some("2025-03-06")),
                ("Unknown date row", None)
            ]
        );
        assert!(
            !serde_json::to_string(&parsed)
                .unwrap()
                .contains("Private summary marker")
        );
        let since = Some("2025-01-01".into());
        let filtered: Vec<_> = parsed
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &None, &None))
            .map(|entry| entry.title.as_str())
            .collect();
        assert_eq!(filtered, vec!["Later source row"]);
    }

    #[test]
    fn article_owns_header_tables_and_second_publication_slot_not_body_dates() {
        let body = "<p>Body date 2030-01-01</p><table><tr><td><p>First source cell</p></td><td><p>Second source cell</p></td></tr></table>";
        let header = "<h6><span>时间：2020-01-01<script>counter()</script></span><span>时间：2026-10-01</span><span>时间：2040-01-01</span></h6>";
        let original = response(&article_html(header, body));
        let parsed = normalize(&original, &college_html(&original).unwrap()).unwrap();
        assert_eq!(parsed["title"], "Original source heading");
        assert_eq!(parsed["published_at"], "2026-10-01");
        assert_eq!(
            parsed["body_paragraphs"],
            json!([
                "Body date 2030-01-01",
                "First source cell",
                "Second source cell"
            ])
        );
        let missing = response(&article_html(
            "<h6><span>时间：2020-01-01</span><span>No publication slot</span><span>时间：2040-01-01</span></h6>",
            body,
        ));
        assert!(
            normalize(&missing, &college_html(&missing).unwrap()).unwrap()["published_at"]
                .is_null()
        );
    }

    #[test]
    fn article_refuses_ambiguous_source_headings_and_bodies() {
        let header = "<h6><span>Count</span><span>时间：2026-10-01</span></h6>";
        let source = article_html(header, "<p>Source policy.</p>");
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
