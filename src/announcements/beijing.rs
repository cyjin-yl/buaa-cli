//! Official-directory-bound Beijing college source observations.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url, article_body, article_output, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, invalid_article, invalid_list, is_http, parse_iso_date,
    retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, BEIJING_NOTICES_URL, BEIJING_ROOT_URL, CacheMode, Error, Response,
    beijing_path_allowed,
};
use chrono::NaiveDate;
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学北京学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("beijing.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && beijing_path_allowed(url.path())
}

fn source_date(raw: &str) -> Option<String> {
    let mut bytes: [u8; 10] = raw.trim().as_bytes().try_into().ok()?;
    if bytes[4] != b'.' || bytes[7] != b'.' {
        return None;
    }
    bytes[4] = b'-';
    bytes[7] = b'-';
    parse_iso_date(std::str::from_utf8(&bytes).ok()?)
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let attribution = college_directory_attribution(&directory, "北京学院", BEIJING_ROOT_URL)?;
    Ok((ArchiveClient::open_beijing(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => BEIJING_ROOT_URL,
        "notices" => BEIJING_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(
            &client,
            BEIJING_ROOT_URL,
            BEIJING_NOTICES_URL,
            &mut attribution,
        )?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "beijing", attribution)
        })
}

fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let titles = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&titles)
        .next()
        .map(element_text)
        .unwrap_or_default();
    let rows = Selector::parse("div.ny-right div.notice-list > div > ul > li")
        .map_err(|_| unavailable())?;
    let headings = Selector::parse("a > h3").map_err(|_| unavailable())?;
    let anchors = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let dates = Selector::parse("a > span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in document.select(&rows) {
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
                    "Beijing notice row requires its a/h3 source heading",
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
            .select(&dates)
            .next()
            .and_then(|node| source_date(&element_text(node)));
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
            "Beijing listing requires its ny-right/notice-list source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(BEIJING_NOTICES_URL).map_err(|_| unavailable())?;
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
            |url| plain_url(url) && url.path().starts_with("/xwdt/gggs/"),
        )
    })
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    if query
        .category
        .as_deref()
        .is_some_and(|category| category != "gggs")
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
        BEIJING_ROOT_URL,
        BEIJING_NOTICES_URL,
        &mut attribution,
    )?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target,false,|response| {
        let document = parse_listing(&college_html(response)?, &target)?;
        let entries:Vec<&ListingEntry> = document.entries.iter().filter(|entry| entry_in_scope(entry,&since,&until,&query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"beijing","category":"gggs","listing_label":"通知公告","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"source_YYYY.MM.DD; missing or invalid stays null"},"retrieval":retrieval(response)}))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1014/")
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
        BEIJING_ROOT_URL,
        BEIJING_NOTICES_URL,
        &mut attribution,
    )?;
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
                "retained notice page does not declare the selected Beijing article",
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
                value["college"] = json!("beijing");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
}

fn publication_date(raw: &str) -> Option<String> {
    let raw = raw.strip_prefix("日期：")?.trim().strip_suffix('日')?;
    let (year, tail) = raw.split_once('年')?;
    let (month, day) = tail.split_once('月')?;
    if year.len() != 4
        || !(1..=2).contains(&month.len())
        || !(1..=2).contains(&day.len())
        || ![year, month, day]
            .into_iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(year.parse().ok()?, month.parse().ok()?, day.parse().ok()?)?;
    Some(date.format("%Y-%m-%d").to_string())
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let mains = Selector::parse("div.ny-right form > div.art-main").map_err(|_| unavailable())?;
    let mut mains = document.select(&mains);
    let main = mains.next().ok_or_else(|| {
        failed_contract(
            "Beijing article requires its ny-right form/art-main source container",
            file!(),
            line!(),
        )
    })?;
    if mains.next().is_some() {
        return Err(unavailable());
    }
    let headings = Selector::parse("div.art-tit > h3").map_err(|_| unavailable())?;
    let mut headings = main.select(&headings).filter(|node| {
        node.parent()
            .and_then(|parent| parent.parent())
            .is_some_and(|parent| parent.id() == main.id())
    });
    let title = headings
        .next()
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_HREF)
        .ok_or_else(|| {
            failed_contract(
                "Beijing article requires its direct art-tit/h3 source heading",
                file!(),
                line!(),
            )
        })?;
    if headings.next().is_some() {
        return Err(unavailable());
    }
    let dates = Selector::parse("div.art-tit > p > span.date").map_err(|_| unavailable())?;
    let published_at = main
        .select(&dates)
        .filter(|node| {
            node.parent()
                .and_then(|parent| parent.parent())
                .and_then(|parent| parent.parent())
                .is_some_and(|parent| parent.id() == main.id())
        })
        .filter_map(|node| publication_date(&element_text(node)))
        .next();
    let bodies = Selector::parse("div.art-body-box div#vsb_content div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies.next().ok_or_else(|| {
        failed_contract(
            "Beijing article requires its source vsb_content/v_news_content body",
            file!(),
            line!(),
        )
    })?;
    if bodies.next().is_some() {
        return Err(unavailable());
    }
    let (paragraphs, attachment_hints, attachments_found) = article_body(body)?;
    let mut value = article_output(
        response,
        ArticleDocument {
            title,
            category: Some("1014".into()),
            published_at,
            paragraphs,
            attachment_hints,
            attachments_found,
        },
    );
    value["completeness"]["body_source"] = json!(
        "unique art-main art-body-box/vsb_content/v_news_content; source table-cell paragraphs retained in document order"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://beijing.buaa.edu.cn/info/1014/42.htm".into(),
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
    fn listing_uses_source_heading_and_real_dot_dates() {
        let html = r#"<title>Fixture notices</title><div><a href="info/1014/99.htm"><h3>Sidebar noise</h3></a></div><div class="ny-right"><div class="notice-list"><div><ul>
            <li><a href="../info/1014/42.htm"><span>2026.09.22</span><h3>Fixture policy</h3><p>Not title/date metadata.</p></a></li>
            <li><a href="../info/1014/43.htm"><span>2026.02.30</span><h3>Invalid date</h3></a></li>
            <li><a href="../info/1014/44.htm"><h3>Missing date</h3><p>2026.09.22 is not a header.</p></a></li>
        </ul></div></div></div>"#;
        let document = parse_listing(
            &Html::parse_document(html),
            &Url::parse(BEIJING_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(
            document
                .entries
                .iter()
                .map(|entry| entry.title.as_str())
                .collect::<Vec<_>>(),
            vec!["Fixture policy", "Invalid date", "Missing date"]
        );
        assert_eq!(
            document
                .entries
                .iter()
                .map(|entry| entry.date.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("2026-09-22"), None, None]
        );
        let since = Some("2026-09-22".into());
        assert_eq!(
            document
                .entries
                .iter()
                .filter(|entry| entry_in_scope(entry, &since, &since, &None))
                .map(|entry| entry.title.as_str())
                .collect::<Vec<_>>(),
            vec!["Fixture policy"]
        );
    }

    #[test]
    fn article_uses_source_header_and_scoped_body_without_promoting_body_dates() {
        let source = response(
            r#"<h2>Sidebar heading</h2><div class="ny-right"><form><div class="art-main"><div class="art-tit"><h3>Fixture policy</h3><p><span class="date">日期：2026年9月22日</span></p></div><div class="art-body-box"><div id="vsb_content"><div class="v_news_content"><p>Source paragraph.</p><table><tr><td><p>Table cell.</p></td></tr></table><p><script>not prose</script></p></div></div></div></div></form></div><div class="v_news_content"><p>Unrelated prose.</p></div>"#,
        );
        let output = normalize(&source, &college_html(&source).unwrap()).unwrap();
        assert_eq!(output["title"], "Fixture policy");
        assert_eq!(output["published_at"], "2026-09-22");
        assert_eq!(
            output["body_paragraphs"],
            json!(["Source paragraph.", "Table cell."])
        );
        let missing_header = response(
            r#"<div class="ny-right"><form><div class="art-main"><div class="art-tit"><h3>Fixture policy</h3></div><div class="art-body-box"><div id="vsb_content"><div class="v_news_content"><div class="art-tit"><p><span class="date">日期：2026年9月22日</span></p></div><p>Source paragraph.</p></div></div></div></div></form></div>"#,
        );
        assert_eq!(
            normalize(&missing_header, &college_html(&missing_header).unwrap()).unwrap()["published_at"],
            Value::Null
        );
        let ambiguous = response(
            r#"<div class="ny-right"><form><div class="art-main"><div class="art-tit"><h3>Fixture policy</h3></div><div class="art-body-box"><div id="vsb_content"><div class="v_news_content"><p>First body.</p></div><div class="v_news_content"><p>Second body.</p></div></div></div></div></form></div>"#,
        );
        assert_eq!(
            normalize(&ambiguous, &college_html(&ambiguous).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn large_table_notice_retains_all_paragraphs_and_rejects_overflow() {
        let make_source = |count: usize| {
            let cells = (0..count)
                .map(|index| format!("<tr><td><p>Synthetic cell {index}</p></td></tr>"))
                .collect::<String>();
            response(&format!(
                "<div class=\"ny-right\"><form><div class=\"art-main\"><div class=\"art-tit\"><h3>Fixture table notice</h3></div><div class=\"art-body-box\"><div id=\"vsb_content\"><div class=\"v_news_content\"><table>{cells}</table></div></div></div></div></form></div>"
            ))
        };
        let source = make_source(1024);
        let output = normalize(&source, &college_html(&source).unwrap()).unwrap();
        assert_eq!(
            output["body_paragraphs"],
            json!(
                (0..1024)
                    .map(|index| format!("Synthetic cell {index}"))
                    .collect::<Vec<_>>()
            )
        );
        let overflow = make_source(1025);
        assert_eq!(
            normalize(&overflow, &college_html(&overflow).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }
}
