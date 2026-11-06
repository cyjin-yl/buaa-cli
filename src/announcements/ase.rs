//! Directory-bound Aviation Science and Engineering college announcements.
//!
//! The reviewed HTTPS source is the canonical `ase.buaa.edu.cn` host.  The
//! official directory advertises the distinct literal HTTP `www.ase` root;
//! that source identity is retained in attribution and is not silently
//! upgraded or treated as a protocol alias.

use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF,
    MAX_PARAGRAPH, MAX_TEXT, advertised_page_url_document, article_body, article_category_from_url,
    article_output, bind_college_board, college_directory_attribution, college_html,
    describe_college_surface, element_text, entry_in_scope, failed_contract, html_fallback,
    inert_element, invalid_article, invalid_list, is_safe_public_fallback,
    is_safe_public_fallback_document, parse_iso_date, retrieval, unavailable,
};
use crate::html::visit_active_text;
use crate::net::{
    ASE_NOTICES_URL, ASE_ROOT_URL, ArchiveClient, CacheMode, Error, ase_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://www.ase.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学航空科学与工程学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("ase.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && ase_path_allowed(url.path())
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
        "航空科学与工程学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = ASE_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_ase(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => ASE_ROOT_URL,
        "notices" => ASE_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, ASE_ROOT_URL, ASE_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "ase", attribution)
        })
}

fn parse_date(node: ElementRef<'_>) -> Option<String> {
    let spans = Selector::parse(":scope > span").ok()?;
    let mut spans = node.select(&spans);
    let month_day = spans.next().map(element_text)?;
    if spans.next().is_some() {
        return None;
    }
    // Inert script/style/template/noscript payload text is not source prose:
    // only active text nodes count toward the split month-day plus year form.
    let mut parts = Vec::new();
    let _ = visit_active_text(
        node,
        |_| false,
        |text| {
            let part = text.trim();
            if !part.is_empty() {
                parts.push(part.to_owned());
            }
            parts.len() > 2
        },
    );
    if parts.len() != 2 || parts[0] != month_day.as_str() {
        return None;
    }
    let (month, day) = month_day.split_once('-')?;
    parse_iso_date(&format!("{}-{month}-{day}", parts[1]))
}

fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(element_text)
        .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT)
        .ok_or_else(|| failed_contract("ASE listing requires a bounded title", file!(), line!()))?;
    let lists =
        Selector::parse("div.nycontent > div.wp > div.txtList > ul").map_err(|_| unavailable())?;
    let mut lists = document.select(&lists).filter(|node| !inert_element(*node));
    let list = lists
        .next()
        .filter(|_| lists.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "ASE notices require one active txtList view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a[href]").map_err(|_| unavailable())?;
    let headings = Selector::parse(":scope > a > div.txt > div.h4").map_err(|_| unavailable())?;
    let summaries =
        Selector::parse(":scope > a > div.txt > div.desc").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > a > div.time").map_err(|_| unavailable())?;
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
                    "ASE notice row requires one direct article anchor",
                    file!(),
                    line!(),
                )
            })?;
        let mut row_headings = row.select(&headings);
        let title = row_headings
            .next()
            .filter(|_| row_headings.next().is_none())
            .map(element_text)
            .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT)
            .ok_or_else(|| {
                failed_contract(
                    "ASE notice row requires one bounded h4 title",
                    file!(),
                    line!(),
                )
            })?;
        let listed_href = anchor.value().attr("href");
        if listed_href.is_some_and(|href| {
            href.is_empty() || href.len() > MAX_HREF || href.chars().any(char::is_control)
        }) {
            return Err(unavailable());
        }
        let mut row_summaries = row.select(&summaries);
        let summary = row_summaries
            .next()
            .map(element_text)
            .filter(|value| !value.is_empty());
        if row_summaries.next().is_some()
            || summary
                .as_ref()
                .is_some_and(|value| value.len() > MAX_PARAGRAPH)
        {
            return Err(unavailable());
        }
        let mut row_dates = row.select(&dates);
        let date = row_dates
            .next()
            .filter(|_| row_dates.next().is_none())
            .and_then(parse_date);
        let (resolved_http_url, link_kind) = match listed_href {
            None => (None, "missing"),
            Some(raw) => match base.join(raw) {
                Ok(url) if matches!(url.scheme(), "http" | "https") => {
                    let kind = if url.scheme() == "https" {
                        "https"
                    } else {
                        "http"
                    };
                    (Some(url.to_string()), kind)
                }
                Ok(_) => (None, "non_http"),
                Err(_) => (None, "invalid"),
            },
        };
        entries.push(ListingEntry {
            source_order: entries.len() + 1,
            title,
            date,
            category_label: Some("通知公告".into()),
            summary,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "ASE notice view requires at least one source row",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(ASE_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    let result: Result<Url, Error> = client.get(&latest, false, |response| {
        let document = college_html(response)?;
        let selected = advertised_page_url_document(
            &document,
            &latest,
            page,
            "div.pb_sys_common span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/zhxw/tzgg/"),
        );
        if selected.is_err() && !is_safe_public_fallback_document(response, &document) {
            return Err(unavailable());
        }
        Ok(selected)
    })?;
    result
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    if query
        .category
        .as_deref()
        .is_some_and(|category| category != "tzgg")
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
    bind_college_board(&client, ASE_ROOT_URL, ASE_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            let html = college_html(response)?;
            let document = match parse_listing(&html, &target) {
                Ok(document) => document,
                Err(_) if is_safe_public_fallback_document(response, &html) => {
                    let mut value = html_fallback(
                        response,
                        "announcements_list",
                        "ase",
                        "ase_listing_selector_contract",
                    );
                    value["category"] = json!("tzgg");
                    value["page"] = json!(page);
                    return Ok(value);
                }
                Err(error) => return Err(error),
            };
            let entries: Vec<_> = document
                .entries
                .iter()
                .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
                .collect();
            Ok(json!({
                "schema_version": 1,
                "type": "announcements_list",
                "result": "listing_snapshot",
                "publisher": PUBLISHER,
                "college": "ase",
                "category": "tzgg",
                "listing_label": "通知公告",
                "page": page,
                "document_title": document.title,
                "filters": {"since": since, "until": until, "match": query.r#match},
                "entries": entries,
                "entry_count": entries.len(),
                "directory_attribution": attribution,
                "completeness": {
                    "scope": "single_college_selected_notice_page",
                    "pagination": "source_advertised_ordinal_only; no automatic traversal",
                    "other_colleges": "not_covered",
                    "dates": "source MM-DD plus year; missing or malformed stays null",
                    "summaries": "source direct excerpt; not original full text",
                },
                "retrieval": retrieval(response),
            }))
        })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || source_page == 0
        || !target.path().starts_with("/info/")
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
    bind_college_board(&client, ASE_ROOT_URL, ASE_NOTICES_URL, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing_result: Result<Value, Error> = client.get(&source, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &source) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback_document(response, &html) => {
                return Ok(Ok(html_fallback(
                    response,
                    "announcements_list",
                    "ase",
                    "ase_listing_selector_contract",
                )));
            }
            Err(error) => return Err(error),
        };
        super::refuse_unsafe_listing(response, &html)?;
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Ok(Err(Error::new(
                "unsupported",
                "retained ASE notice page does not declare the selected article",
            )));
        }
        Ok(Ok(retrieval(response)))
    })?;
    let listing = listing_result?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained ASE notice page could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client
        .with_cache_mode(mode)
        .get(target, false, |response| {
            let document = match college_html(response) {
                Ok(document) => document,
                Err(_) if is_safe_public_fallback(response) => {
                    return Ok(Ok(html_fallback(
                        response,
                        "announcements_article",
                        "ase",
                        "ase_article_selector_contract",
                    )));
                }
                Err(error) => return Err(error),
            };
            Ok(normalize(response, &document).map(|mut value| {
                value["publisher"] = json!(PUBLISHER);
                value["college"] = json!("ase");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
}

fn normalize(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    // Unsafe article pages are never retained, whether or not their layout
    // still matches the reviewed selectors: refuse before parsing or exposing
    // any of their bytes.
    if !is_safe_public_fallback_document(response, document) {
        return Err(unavailable());
    }
    // A safe public page whose layout drifted away from the reviewed contract
    // degrades into retained original evidence for offline repair instead of
    // an outer error that discards the admitted bytes.
    normalize_article(response, document).or_else(|_| {
        Ok(html_fallback(
            response,
            "announcements_article",
            "ase",
            "ase_article_selector_contract",
        ))
    })
}

fn normalize_article(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    let forms = Selector::parse(
        "div.nycontent > div.wp > div.nyArc > form[name=\"_newscontent_fromname\"]",
    )
    .map_err(|_| unavailable())?;
    let mut forms = document.select(&forms).filter(|node| !inert_element(*node));
    let form = forms
        .next()
        .filter(|_| forms.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "ASE article requires one direct nyArc content form",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > div.arc-tit > h1").map_err(|_| unavailable())?;
    let mut headings = form.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "ASE article requires one direct arc-tit/h1 heading",
                file!(),
                line!(),
            )
        })?;
    let spans = Selector::parse(":scope > div.arc-info > div > span").map_err(|_| unavailable())?;
    let mut dates = form
        .select(&spans)
        .filter(|node| element_text(*node).starts_with("发布时间"));
    let published_at = dates
        .next()
        .filter(|_| dates.next().is_none())
        .and_then(|node| {
            let raw = element_text(node);
            raw.strip_prefix("发布时间：")
                .or_else(|| raw.strip_prefix("发布时间:"))
                .and_then(parse_iso_date)
        });
    let bodies = Selector::parse(":scope > div.arc-con > div#vsb_content_2 > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = form.select(&bodies).filter(|node| !inert_element(*node));
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "ASE article requires one scoped vsb_content_2/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, false)?;
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
    output["completeness"]["body_source"] = json!(
        "unique nyArc/form/arc-con/#vsb_content_2/v_news_content paragraphs; executable and fallback text excluded"
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
    use crate::net::{CacheStatus, Response};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(url: &str, html: &str) -> Response {
        Response {
            url: url.into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html; charset=utf-8".into())]),
            sha256: format!("{:x}", Sha256::digest(html.as_bytes())),
            body: html.as_bytes().to_vec(),
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    const LISTING_BOARD: &str = r#"<title>通知公告-航空科学与工程学院</title>
        <div class="nycontent"><div class="wp"><div class="txtList"><ul>
        <li><a href="../info/1052/42.htm"><div class="time ddjb"><span>06-03</span>2026</div><div class="txt"><div class="h4 eclips">First title</div><div class="desc line2">First excerpt</div></div></a></li>
        <li><a href="../info/1285/43.htm"><div class="time ddjb"><span>10-11</span>2026</div><div class="txt"><div class="h4 eclips">Second title</div><div class="desc line2">Second excerpt</div></div></a></li>
        </ul></div></div></div>"#;

    #[test]
    fn ase_listing_preserves_source_order_and_split_dates() {
        let base = Url::parse(ASE_NOTICES_URL).unwrap();
        let document = Html::parse_document(LISTING_BOARD);
        let listing = parse_listing(&document, &base).unwrap();
        assert_eq!(listing.entries.len(), 2);
        assert_eq!(listing.entries[0].source_order, 1);
        assert_eq!(listing.entries[0].date.as_deref(), Some("2026-06-03"));
        assert_eq!(
            listing.entries[1].resolved_http_url.as_deref(),
            Some("https://ase.buaa.edu.cn/info/1285/43.htm")
        );
    }

    #[test]
    fn review_regression_security_marked_listing_is_refused_before_output_or_cache() {
        // A board that still parses while carrying a security marker is
        // unsafe: the real list callback must refuse it before serializing
        // entries and before ArchiveClient::get may persist the response
        // (save happens only after the callback returns Ok), and no fallback
        // export may carry the unsafe bytes.
        let base = Url::parse(ASE_NOTICES_URL).unwrap();
        let link_response = response(
            ASE_NOTICES_URL,
            &LISTING_BOARD.replace(
                "href=\"../info/1052/42.htm\"",
                "href=\"../info/1052/42.htm?csrf_token=synthetic\"",
            ),
        );
        let html = college_html(&link_response).unwrap();
        let listing = parse_listing(&html, &base).unwrap();
        assert!(
            serde_json::to_string(&listing)
                .unwrap()
                .contains("csrf_token"),
            "the declared marker link would otherwise reach serialized output"
        );
        assert_eq!(
            crate::announcements::refuse_unsafe_listing(&link_response, &html)
                .unwrap_err()
                .code,
            "unavailable"
        );
        assert!(!is_safe_public_fallback_document(&link_response, &html));

        let control_response = response(
            ASE_NOTICES_URL,
            &format!(
                "{LISTING_BOARD}<form><input type=\"hidden\" name=\"csrf_token\" value=\"synthetic\"></form>"
            ),
        );
        let html = college_html(&control_response).unwrap();
        let listing = parse_listing(&html, &base).unwrap();
        assert_eq!(listing.entries.len(), 2);
        assert_eq!(
            crate::announcements::refuse_unsafe_listing(&control_response, &html)
                .unwrap_err()
                .code,
            "unavailable"
        );
        assert!(!is_safe_public_fallback_document(&control_response, &html));

        // The ordinary public board stays admissible end to end.
        let response = response(ASE_NOTICES_URL, LISTING_BOARD);
        let html = college_html(&response).unwrap();
        assert!(parse_listing(&html, &base).is_ok());
        assert!(crate::announcements::refuse_unsafe_listing(&response, &html).is_ok());
        assert!(is_safe_public_fallback_document(&response, &html));
    }

    #[test]
    fn ase_article_scopes_header_and_body_and_marks_nonparagraph_content() {
        let html = r#"<div class="nycontent"><div class="wp"><div class="nyArc"><form name="_newscontent_fromname">
            <div class="arc-tit"><h1>Original article</h1></div>
            <div class="arc-info"><div><span>发布时间：2026-06-03</span><span>浏览次数：<script>1</script>次</span></div></div>
            <div class="arc-con"><div id="vsb_content_2"><div class="v_news_content"><p>Body paragraph.</p><img src="poster.png" alt="not transcribed"><table><tr><td>Cell</td></tr></table></div></div></div>
        </form></div></div></div>"#;
        let response = response("https://ase.buaa.edu.cn/info/1052/42.htm", html);
        let document = college_html(&response).unwrap();
        let output = normalize(&response, &document).unwrap();
        assert_eq!(output["title"], "Original article");
        assert_eq!(output["published_at"], "2026-06-03");
        assert_eq!(output["body_paragraphs"], json!(["Body paragraph."]));
        assert_eq!(output["result"], "partial_text");
        assert_eq!(output["completeness"]["image_content_present"], true);
        assert_eq!(output["completeness"]["unextracted_table_count"], 1);
    }

    #[test]
    fn ase_ambiguous_publication_spans_stay_unknown() {
        let html = r#"<div class="nycontent"><div class="wp"><div class="nyArc"><form name="_newscontent_fromname">
            <div class="arc-tit"><h1>Original article</h1></div>
            <div class="arc-info"><div><span>发布时间：2026-06-03</span><span>发布时间：2026-06-04</span></div></div>
            <div class="arc-con"><div id="vsb_content_2"><div class="v_news_content"><p>Body paragraph.</p></div></div></div>
        </form></div></div></div>"#;
        let response = response("https://ase.buaa.edu.cn/info/1052/42.htm", html);
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["published_at"], Value::Null);
    }

    #[test]
    fn review_regression_ase_safe_article_drift_returns_preserved_evidence() {
        // A public article page whose layout drifted away from the reviewed
        // selectors must degrade into retained original evidence for offline
        // repair, not an unavailable error that discards the admitted bytes.
        const BODY: &[u8] = br#"<html><head><title>ASE article drift</title></head><body><div class="migrated-layout"><h2>Drifted article</h2><p>Selector contract broken.</p></div></body></html>"#;
        let source = response(
            "https://ase.buaa.edu.cn/info/1052/42.htm",
            std::str::from_utf8(BODY).unwrap(),
        );
        let document = college_html(&source).unwrap();
        assert!(is_safe_public_fallback_document(&source, &document));
        let output = normalize(&source, &document).unwrap();
        assert_eq!(output["type"], "announcements_article");
        assert_eq!(output["result"], "fallback");
        assert_eq!(output["college"], "ase");
        assert_eq!(
            STANDARD
                .decode(output["raw_html"].as_str().unwrap())
                .unwrap()
                .as_slice(),
            BODY
        );
        assert_eq!(output["raw_html_sha256"], format!("{:x}", Sha256::digest(BODY)));
        assert_eq!(output["body_byte_length"], BODY.len() as u64);
    }

    #[test]
    fn review_regression_ase_unsafe_article_drift_is_refused() {
        // The degraded-evidence contract never applies to a page carrying an
        // active authentication surface: its bytes are withheld entirely.
        let html = r#"<html><body><form><input type="password" name="password"></form><div class="migrated-layout"><p>Drifted article.</p></div></body></html>"#;
        let source = response("https://ase.buaa.edu.cn/info/1052/42.htm", html);
        let document = college_html(&source).unwrap();
        assert!(!is_safe_public_fallback_document(&source, &document));
        assert!(normalize(&source, &document).is_err());
    }

    #[test]
    fn review_regression_ase_inert_markup_in_date_keeps_real_date() {
        // An inert script/style payload inside the date node is not source
        // text: the surrounding MM-DD span plus year still resolves, while
        // genuinely ambiguous date nodes stay null.
        let html = r#"<title>通知公告-航空科学与工程学院</title>
            <div class="nycontent"><div class="wp"><div class="txtList"><ul>
            <li><a href="../info/1052/42.htm"><div class="time ddjb"><span>06-03</span><script>_click_add_(1)</script>2026</div><div class="txt"><div class="h4 eclips">Script date</div><div class="desc line2">Excerpt</div></div></a></li>
            <li><a href="../info/1052/43.htm"><div class="time ddjb"><script>window.counter()</script><span>06-04</span>2026<style>.x{opacity:0}</style></div><div class="txt"><div class="h4 eclips">Style date</div><div class="desc line2">Excerpt</div></div></a></li>
            <li><a href="../info/1052/44.htm"><div class="time ddjb"><span>06-05</span>2025 2026</div><div class="txt"><div class="h4 eclips">Two years</div><div class="desc line2">Excerpt</div></div></a></li>
            <li><a href="../info/1052/45.htm"><div class="time ddjb"><span>06-06</span><span>2026</span></div><div class="txt"><div class="h4 eclips">Two spans</div><div class="desc line2">Excerpt</div></div></a></li>
            <li><a href="../info/1052/46.htm"><div class="time ddjb"><span>06-07</span>twenty-six</div><div class="txt"><div class="h4 eclips">Word year</div><div class="desc line2">Excerpt</div></div></a></li>
            </ul></div></div></div>"#;
        let base = Url::parse(ASE_NOTICES_URL).unwrap();
        let document = Html::parse_document(html);
        let listing = parse_listing(&document, &base).unwrap();
        let dates: Vec<Option<&str>> = listing
            .entries
            .iter()
            .map(|entry| entry.date.as_deref())
            .collect();
        assert_eq!(
            dates,
            vec![
                Some("2026-06-03"),
                Some("2026-06-04"),
                None,
                None,
                None,
            ]
        );
    }
}
