//! Official-directory-bound Medical Science and Engineering college notices.
//!
//! The YGY site is a Visual SiteBuilder board whose selected announcement
//! listing uses `ul.list1` rows.  Rows expose month/day only, so canonical
//! dates remain unknown rather than inferring a year from the current clock.
//! Article pages use the source-owned `div.content`/`h1`/`div.time` and
//! `v_news_content` layout.  Attachments and non-paragraph content remain
//! source-declared hints; no asset is downloaded.

use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF,
    MAX_PARAGRAPH, MAX_TEXT, article_category_from_url, article_output, article_paragraphs,
    bind_college_board, college_directory_attribution, college_html, declared_jsp_attachment_hints,
    describe_college_surface, element_text, entry_in_scope, failed_contract, html_fallback,
    inert_element, invalid_article, invalid_list, is_admitted_html, is_http,
    is_safe_public_fallback, parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, Response, YGY_NOTICES_URL, YGY_ROOT_URL, ygy_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://ygy.buaa.edu.cn";
const PUBLISHER: &str = "北京航空航天大学医学科学与工程学院";
const CATEGORY: &str = "yggg";
const LISTING_LABEL: &str = "医工公告";
const MAX_PAGE_HOPS: u32 = 16;

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("ygy.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && ygy_path_allowed(url.path())
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let mut attribution = college_directory_attribution(
        &directory,
        "医学科学与工程学院",
        LISTED_ROOT_URL,
        "http://ygy.buaa.edu.cn/",
    )?;
    attribution["selected_https_root"] = YGY_ROOT_URL.into();
    attribution["selection_relation"] =
        "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_ygy(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => YGY_ROOT_URL,
        "notices" => YGY_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, YGY_ROOT_URL, YGY_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            if !is_admitted_html(response) {
                return Err(unavailable());
            }
            match describe_college_surface(response, "ygy", attribution.clone()) {
                Ok(value) => Ok(value),
                Err(_) if is_safe_public_fallback(response) => Ok(html_fallback(
                    response,
                    "college_source_surface",
                    "ygy",
                    "ygy_surface_selector_contract",
                )),
                Err(error) => Err(error),
            }
        })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(YGY_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    if page > MAX_PAGE_HOPS {
        return Err(Error::new(
            "unavailable",
            "requested YGY page exceeds the reviewed advertised-page hop bound",
        ));
    }
    let mut current = latest;
    for _ in 1..page {
        let next = current.clone();
        current = client.get(&next, false, |response| {
            college_html(response)?;
            advertised_next_page_url(&response.body, &next)
        })?;
    }
    Ok(current)
}

fn advertised_next_page_url(bytes: &[u8], base: &Url) -> Result<Url, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(text);
    let links = Selector::parse("div.page a.Next[href]").map_err(|_| unavailable())?;
    let mut selected = None;
    for link in document.select(&links) {
        if element_text(link) != "下页" {
            continue;
        }
        let raw = link.value().attr("href").ok_or_else(unavailable)?;
        if raw.len() > MAX_HREF || raw.chars().any(char::is_control) {
            return Err(unavailable());
        }
        let url = base.join(raw).map_err(|_| unavailable())?;
        if !plain_url(&url) || !url.path().starts_with("/tzgg/yggg/") {
            return Err(failed_contract(
                "YGY next-page link must remain in the selected board",
                file!(),
                line!(),
            ));
        }
        match selected.as_ref() {
            Some(previous) if previous != &url => {
                return Err(Error::new(
                    "unavailable",
                    "YGY next-page declarations conflict; no URL was selected",
                ));
            }
            None => selected = Some(url),
            _ => {}
        }
    }
    selected.ok_or_else(|| {
        Error::new(
            "unavailable",
            "requested YGY page is not advertised by the retained board",
        )
    })
}

fn source_month_day(month: &str, day: &str) -> bool {
    let valid_part = |raw: &str| raw.len() == 2 && raw.bytes().all(|byte| byte.is_ascii_digit());
    if !valid_part(day) || !valid_part(month) {
        return false;
    }
    let month: u32 = month.parse().unwrap_or_default();
    let day: u32 = day.parse().unwrap_or_default();
    (1..=12).contains(&month) && (1..=31).contains(&day)
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

    let lists = Selector::parse("ul.list1").map_err(|_| unavailable())?;
    let mut lists = document.select(&lists).filter(|node| !inert_element(*node));
    let primary = lists
        .next()
        .filter(|_| lists.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "YGY notice listing requires one active list1 view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > div.li-r > a[href]").map_err(|_| unavailable())?;
    let summaries = Selector::parse(":scope > div.li-r > p").map_err(|_| unavailable())?;
    let months = Selector::parse(":scope > div.li-l > p.p1").map_err(|_| unavailable())?;
    let days = Selector::parse(":scope > div.li-l > p.p2").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in primary.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(failed_contract(
                "YGY notice listing exceeds the reviewed entry budget",
                file!(),
                line!(),
            ));
        }
        let mut row_anchors = row.select(&anchors);
        let anchor = row_anchors
            .next()
            .filter(|_| row_anchors.next().is_none())
            .ok_or_else(|| {
                failed_contract(
                    "YGY notice row requires one direct li-r anchor",
                    file!(),
                    line!(),
                )
            })?;
        let title = element_text(anchor);
        if title.is_empty() || title.len() > MAX_TEXT {
            return Err(failed_contract(
                "YGY notice row requires a bounded non-empty title",
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
        let mut row_summaries = row.select(&summaries);
        let summary = row_summaries
            .next()
            .map(element_text)
            .filter(|text| !text.is_empty());
        if row_summaries.next().is_some()
            || summary
                .as_ref()
                .is_some_and(|text| text.len() > MAX_PARAGRAPH)
        {
            return Err(failed_contract(
                "YGY notice row requires at most one bounded summary",
                file!(),
                line!(),
            ));
        }
        let mut row_days = row.select(&days);
        let day = row_days.next().map(element_text);
        if row_days.next().is_some() {
            return Err(failed_contract(
                "YGY notice row requires one source day",
                file!(),
                line!(),
            ));
        }
        let mut row_months = row.select(&months);
        let month = row_months.next().map(element_text);
        if row_months.next().is_some() {
            return Err(failed_contract(
                "YGY notice row requires one source month",
                file!(),
                line!(),
            ));
        }
        // The source exposes only MM-DD.  Validate its shape, but do not
        // invent a year from the current date or from an article identifier.
        let _source_date_is_valid = day
            .as_deref()
            .zip(month.as_deref())
            .is_some_and(|(day, month)| source_month_day(month.trim(), day.trim()));
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
            date: None,
            category_label: Some(LISTING_LABEL.into()),
            summary,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "YGY notice listing has no source rows",
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
        .is_some_and(|category| category != CATEGORY)
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
    bind_college_board(&client, YGY_ROOT_URL, YGY_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = match college_html(response).and_then(|html| parse_listing(&html, &target)) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                let mut value = html_fallback(
                    response,
                    "announcements_list",
                    "ygy",
                    "ygy_listing_selector_contract",
                );
                value["category"] = json!(CATEGORY);
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
            "college": "ygy",
            "category": CATEGORY,
            "listing_label": LISTING_LABEL,
            "page": page,
            "document_title": document.title,
            "filters": {"since": since, "until": until, "match": query.r#match},
            "entries": entries,
            "entry_count": entries.len(),
            "directory_attribution": attribution,
            "completeness": {
                "scope": "single_college_selected_board_page",
                "pagination": "source_advertised_next_links_only; bounded traversal to selected ordinal",
                "other_colleges": "not_covered",
                "dates": "source MM-DD has no year; canonical dates remain null rather than inferred",
                "summaries": "source direct li-r paragraph excerpt; not original full text"
            },
            "retrieval": retrieval(response)
        }))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || source_page == 0
        || !target.path().starts_with("/info/1004/")
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
    bind_college_board(&client, YGY_ROOT_URL, YGY_NOTICES_URL, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing = client.get(&source, false, |response| {
        let document = match college_html(response).and_then(|html| parse_listing(&html, &source)) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_list",
                    "ygy",
                    "ygy_listing_selector_contract",
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
                "retained YGY notice page does not declare the selected article",
            ));
        }
        Ok(retrieval(response))
    })?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained YGY listing could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client.with_cache_mode(mode).get(target, false, |response| {
        let document = match college_html(response) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_article",
                    "ygy",
                    "ygy_article_selector_contract",
                ));
            }
            Err(error) => return Err(error),
        };
        let mut value = match normalize(response, &document) {
            Ok(value) => value,
            Err(_) if is_safe_public_fallback(response) => html_fallback(
                response,
                "announcements_article",
                "ygy",
                "ygy_article_selector_contract",
            ),
            Err(error) => return Err(error),
        };
        Ok({
            value["publisher"] = json!(PUBLISHER);
            value["college"] = json!("ygy");
            value["directory_attribution"] = attribution.clone();
            value["source_listing"] = listing.clone();
            value
        })
    })
}

fn publication_date(raw: &str) -> Option<String> {
    raw.strip_prefix("发布时间：")
        .and_then(|value| value.split_whitespace().next())
        .and_then(parse_iso_date)
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let containers = Selector::parse("div.content").map_err(|_| unavailable())?;
    let mut containers = document
        .select(&containers)
        .filter(|node| !inert_element(*node));
    let content = containers
        .next()
        .filter(|_| containers.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "YGY article requires one active content container",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > h1").map_err(|_| unavailable())?;
    let mut headings = content.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "YGY article requires one direct content h1 heading",
                file!(),
                line!(),
            )
        })?;
    let dates = Selector::parse(":scope > div.time").map_err(|_| unavailable())?;
    let mut dates = content.select(&dates);
    let published_at = dates
        .next()
        .filter(|_| dates.next().is_none())
        .and_then(|node| publication_date(&element_text(node)));
    let bodies = Selector::parse(":scope > div.content-detail > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = content.select(&bodies).filter(|node| !inert_element(*node));
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "YGY article requires one scoped content-detail/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let paragraphs = article_paragraphs(body, false)?;
    let (attachment_hints, hints_truncated) = declared_jsp_attachment_hints(content)?;
    let attachments_found = !attachment_hints.is_empty() || hints_truncated;
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let tables = Selector::parse("table").map_err(|_| unavailable())?;
    let has_images = body.select(&images).any(|node| !inert_element(node));
    let table_count = body
        .select(&tables)
        .filter(|node| !inert_element(*node))
        .count();
    let mut output = article_output(
        response,
        ArticleDocument {
            title,
            category: Url::parse(&response.url)
                .ok()
                .as_ref()
                .and_then(article_category_from_url),
            published_at,
            paragraphs,
            attachment_hints,
            attachments_found,
        },
    );
    output["attachments"]["hints_truncated"] = json!(hints_truncated);
    output["completeness"]["body_source"] = json!(
        "unique content/content-detail/v_news_content paragraphs; executable and fallback text excluded"
    );
    output["completeness"]["attachment_source"] = json!(
        "active source-declared JSP file links within content, including siblings outside the text body; hints only, never fetched"
    );
    output["completeness"]["image_content_present"] = json!(has_images);
    output["completeness"]["unextracted_table_count"] = json!(table_count);
    if attachments_found || has_images || table_count != 0 {
        output["result"] = json!("partial_text");
        output["completeness"]["missing_nonparagraph_content"] = json!(
            "attachment bytes, image text and nonparagraph table content are not reconstructed or downloaded"
        );
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(html: &str) -> Response {
        Response {
            url: "https://ygy.buaa.edu.cn/info/1004/42.htm".into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            sha256: format!("{:x}", Sha256::digest(html.as_bytes())),
            body: html.as_bytes().to_vec(),
            fetched_at_unix_ms: 1,
            cache_status: crate::net::CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn listing_binds_list1_rows_and_keeps_yearless_dates_unknown() {
        let html = r#"<title>医工公告</title><ul class="list1">
            <li><div class="li-l"><p class="p1">09</p><p class="p2">10</p></div><div class="li-r"><a href="../info/1004/42.htm">First notice</a><p>First summary.</p></div></li>
            <li><div class="li-l"><p class="p1">02</p><p class="p2">29</p></div><div class="li-r"><a href="../info/1004/43.htm">Second notice</a></div></li>
        </ul>"#;
        let document = parse_listing(
            &Html::parse_document(html),
            &Url::parse(YGY_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(document.title, "医工公告");
        assert_eq!(document.entries.len(), 2);
        assert_eq!(document.entries[0].source_order, 1);
        assert_eq!(document.entries[0].date, None);
        assert_eq!(
            document.entries[0].resolved_http_url.as_deref(),
            Some("https://ygy.buaa.edu.cn/info/1004/42.htm")
        );
        assert_eq!(document.entries[1].summary, None);
    }

    #[test]
    fn article_scopes_original_body_and_declared_attachment() {
        let response = response(
            r#"<div class="content"><h1>Original heading</h1><div class="time">发布时间：2026-09-10 18:05&nbsp;&nbsp;点击次数：<script>ignored</script></div>
            <div class="content-detail"><div class="v_news_content"><p>First <em>inline</em> paragraph.</p><template><p>inactive</p></template><img src="poster.png"><table><tr><td>not reconstructed</td></tr></table></div></div>
            <p><a href="/system/_content/download.jsp?wbfileid=42">Schedule.pdf</a></p></div>"#,
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["title"], "Original heading");
        assert_eq!(output["published_at"], "2026-09-10");
        assert_eq!(
            output["body_paragraphs"],
            json!(["First inline paragraph."])
        );
        assert_eq!(output["result"], "partial_text");
        assert_eq!(output["attachments"]["found"], true);
        assert_eq!(
            output["attachments"]["hints"],
            json!([{"href":"/system/_content/download.jsp?wbfileid=42","text":"Schedule.pdf","fetched":false}])
        );
    }

    #[test]
    fn next_page_selector_requires_the_active_source_declaration() {
        let html = r#"<div class="page"><a class="Next" href="yggg/2.htm">下页</a><a class="Next" href="yggg/1.htm">尾页</a></div>
            <div class="page"><a class="Next" href="yggg/2.htm">下页</a></div>"#;
        assert_eq!(
            advertised_next_page_url(html.as_bytes(), &Url::parse(YGY_NOTICES_URL).unwrap())
                .unwrap()
                .as_str(),
            "https://ygy.buaa.edu.cn/tzgg/yggg/2.htm"
        );
        let conflicting = html.replacen("yggg/2.htm", "yggg/3.htm", 1);
        assert_eq!(
            advertised_next_page_url(
                conflicting.as_bytes(),
                &Url::parse(YGY_NOTICES_URL).unwrap()
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
    }

    #[test]
    fn article_rejects_ambiguous_content_contract() {
        let response = response(
            r#"<div class="content"><h1>One</h1><div class="time">发布时间：2026-09-10</div><div class="content-detail"><div class="v_news_content"><p>Body</p></div></div></div><div class="content"><h1>Two</h1></div>"#,
        );
        assert_eq!(
            normalize(&response, &college_html(&response).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }
}
