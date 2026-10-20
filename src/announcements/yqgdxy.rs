//! Directory-bound 仪器科学与光电工程学院 notices.
//!
//! The directory records the literal HTTP root, while the reviewed public
//! pages are selected HTTPS observations.  The adapter never upgrades the
//! directory value, follows only the root-declared `/tzgg.htm` board, and
//! resolves later pages from the board's own pagination links.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url_document, article_body, bind_college_board, college_directory_attribution,
    college_html, describe_college_surface, element_text, entry_in_scope, failed_contract,
    html_fallback, inert_element, invalid_article, invalid_list, is_http,
    is_safe_public_fallback_document, parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, YQGDXY_NOTICES_URL, YQGDXY_ROOT_URL, yqgdxy_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://yqgdxy.buaa.edu.cn/";
pub(super) const PUBLISHER: &str = "北京航空航天大学仪器科学与光电工程学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("yqgdxy.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && yqgdxy_path_allowed(url.path())
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    // Directory authority is cache-first even for a selected page refresh;
    // the selected source itself receives the caller's requested mode.
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let mut attribution = college_directory_attribution(
        &directory,
        "仪器科学与光电工程学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = YQGDXY_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_yqgdxy(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => YQGDXY_ROOT_URL,
        "notices" => YQGDXY_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(
            &client,
            YQGDXY_ROOT_URL,
            YQGDXY_NOTICES_URL,
            &mut attribution,
        )?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "yqgdxy", attribution)
        })
}

/// Parse the source-ordered `nymain/ny-right/text-list` view.
pub(super) fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let titles = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&titles)
        .next()
        .map(element_text)
        .unwrap_or_default();
    if title.len() > MAX_TEXT {
        return Err(unavailable());
    }
    let views = Selector::parse("div.nymain > div.ny-right > div.text-list > ul")
        .map_err(|_| unavailable())?;
    let mut views = document.select(&views).filter(|node| !inert_element(*node));
    let primary = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Yqgdxy notices require one nymain/text-list view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in primary.select(&rows).filter(|node| !inert_element(*node)) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut links = row.select(&anchors).filter(|node| !inert_element(*node));
        let anchor = links
            .next()
            .filter(|_| links.next().is_none())
            .ok_or_else(|| {
                failed_contract(
                    "Yqgdxy notice row requires one direct title link",
                    file!(),
                    line!(),
                )
            })?;
        let title = element_text(anchor);
        if title.is_empty() || title.len() > MAX_TEXT {
            return Err(failed_contract(
                "Yqgdxy notice link requires source text",
                file!(),
                line!(),
            ));
        }
        let listed_href = anchor.value().attr("href");
        if listed_href.is_some_and(|raw| raw.len() > MAX_HREF || raw.chars().any(char::is_control))
        {
            return Err(unavailable());
        }
        let mut row_dates = row.select(&dates).filter(|node| !inert_element(*node));
        let date = row_dates
            .next()
            .filter(|_| row_dates.next().is_none())
            .and_then(|node| parse_iso_date(&element_text(node)));
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
            "Yqgdxy notice view has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(YQGDXY_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    let result: Result<Url, Error> = client.get(&latest, false, |response| {
        let document = college_html(response)?;
        let selected = advertised_page_url_document(
            &document,
            &latest,
            page,
            "div.nymain > div.ny-right > div.text-list > div.pagination span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/tzgg/"),
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
    bind_college_board(
        &client,
        YQGDXY_ROOT_URL,
        YQGDXY_NOTICES_URL,
        &mut attribution,
    )?;
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
                        "yqgdxy",
                        "yqgdxy_listing_selector_contract",
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
                "schema_version":1,
                "type":"announcements_list",
                "result":"listing_snapshot",
                "publisher":PUBLISHER,
                "college":"yqgdxy",
                "category":"tzgg",
                "listing_label":"通知公告",
                "page":page,
                "document_title":document.title,
                "filters":{"since":since,"until":until,"match":query.r#match},
                "entries":entries,
                "entry_count":entries.len(),
                "directory_attribution":attribution,
                "completeness":{
                    "scope":"single_college_selected_page",
                    "pagination":"source_advertised_ordinal_only; no automatic traversal",
                    "other_colleges":"not_covered",
                    "dates":"source YYYY-MM-DD; missing, invalid or ambiguous stays null",
                    "summaries":"not supplied by this source view; not reconstructed",
                    "external_links":"retained listing references only; never fetched"
                },
                "retrieval":retrieval(response)
            }))
        })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1053/")
        || source_page == 0
    {
        return Err(invalid_article());
    }
    let (client, attribution) = bound_client(mode)?;
    article_with_client(client, mode, &target, source_page, attribution)
}

/// Shared with the isolated transport regression and keeps declaration checks
/// ahead of the selected article GET.
pub(crate) fn article_with_client(
    client: ArchiveClient,
    mode: CacheMode,
    target: &Url,
    source_page: u32,
    mut attribution: Value,
) -> Result<Value, Error> {
    bind_college_board(
        &client,
        YQGDXY_ROOT_URL,
        YQGDXY_NOTICES_URL,
        &mut attribution,
    )?;
    let source = listing_url(&client, source_page)?;
    let listing_result: Result<Value, Error> = client.get(&source, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &source) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback_document(response, &html) => {
                return Ok(Ok(html_fallback(
                    response,
                    "announcements_list",
                    "yqgdxy",
                    "yqgdxy_listing_selector_contract",
                )));
            }
            Err(error) => return Err(error),
        };
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Ok(Err(Error::new(
                "unsupported",
                "retained notice page does not declare the selected Yqgdxy article",
            )));
        }
        Ok(Ok(retrieval(response)))
    })?;
    let listing = listing_result?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained Yqgdxy notice page could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client.with_cache_mode(mode).get(target, false, |response| {
        let html = college_html(response)?;
        let mut output = match normalize(response, &html) {
            Ok(value) => value,
            Err(_) if is_safe_public_fallback_document(response, &html) => html_fallback(
                response,
                "announcements_article",
                "yqgdxy",
                "yqgdxy_article_selector_contract",
            ),
            Err(error) => return Err(error),
        };
        output["publisher"] = json!(PUBLISHER);
        output["college"] = json!("yqgdxy");
        output["directory_attribution"] = attribution;
        output["source_listing"] = listing;
        Ok(output)
    })
}

fn normalize(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    let (article, has_images, table_count) = parse_article_with_completeness(document)?;
    let attachments_found = article.attachments_found;
    let mut output = super::article_output(response, article);
    output["completeness"]["body_source"] = json!(
        "unique nymain/art-main form; owned art-tit h3 and unique leaf 日期： ISO date; scoped art-body/v_news_content paragraphs; code and fallback payloads excluded"
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

fn parse_article_with_completeness(
    document: &Html,
) -> Result<(ArticleDocument, bool, usize), Error> {
    let views = Selector::parse("div.nymain > div.ny-right > div.art-main > form")
        .map_err(|_| unavailable())?;
    let mut views = document.select(&views).filter(|node| !inert_element(*node));
    let primary = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Yqgdxy article requires one nymain/art-main form",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > div.art-tit > h3").map_err(|_| unavailable())?;
    let mut headings = primary
        .select(&headings)
        .filter(|node| !inert_element(*node));
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "Yqgdxy article requires one original art-tit heading",
                file!(),
                line!(),
            )
        })?;
    let dates = Selector::parse(":scope > div.art-tit > p > span").map_err(|_| unavailable())?;
    let mut dates = primary
        .select(&dates)
        .filter(|node| !inert_element(*node))
        .map(|node| (node, element_text(node)))
        .filter(|(_, text)| text.starts_with("日期："));
    let published_at = dates
        .next()
        .filter(|_| dates.next().is_none())
        .filter(|(node, _)| {
            node.children()
                .all(|child| child.value().as_element().is_none())
        })
        .and_then(|(_, text)| {
            text.strip_prefix("日期：")
                .and_then(|date| parse_iso_date(date.trim()))
        });
    let bodies = Selector::parse(":scope > div.art-body > div > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = primary.select(&bodies).filter(|node| !inert_element(*node));
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Yqgdxy article requires one owned art-body/v_news_content",
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
    Ok((
        ArticleDocument {
            title,
            category: Some("1053".into()),
            published_at,
            paragraphs,
            attachment_hints,
            attachments_found,
        },
        has_images,
        table_count,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CacheStatus, Response};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn article_html(dates: &str, body: &str) -> String {
        format!(
            r#"<h3>Outside heading</h3><div class="nymain"><div class="ny-right"><div class="art-main"><form><div class="art-tit"><h3>Original <em>inline</em> heading</h3><p>{dates}<span>Outside date field</span></p></div><div class="art-body"><div><div class="v_news_content">{body}</div></div></div><p>Outside form prose</p></form></div></div></div>"#
        )
    }

    fn article_html_with_unowned_sibling(dates: &str, body: &str) -> String {
        format!(
            r#"<h3>Outside heading</h3><div class="nymain"><div class="ny-right"><div class="art-main"><form><div class="art-tit"><h3>Original <em>inline</em> heading</h3><p>{dates}<span>Outside date field</span></p></div><div class="art-body"><div><div class="v_news_content">{body}</div><div class="other"><div class="v_news_content"><p>Unowned sibling paragraph.</p><a href="/unowned.pdf">Unowned attachment</a></div></div></div></div><p>Outside form prose</p></form></div></div></div>"#
        )
    }

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

    #[test]
    fn listing_preserves_order_and_keeps_ambiguous_dates_unknown() {
        let html = r#"<div class="nymain"><div class="ny-right"><div class="text-list"><ul>
          <li><a href="info/1053/42.htm">Original <em>inline</em><script>inert</script> heading</a><span>2024-02-29</span></li>
          <template><li><a href="info/1053/99.htm">Inert row</a></li></template>
          <li><a href="https://external.example/notice">External reference</a><span>2026-09-01</span><span>2026-09-02</span></li>
          <li><a href="info/1053/43.htm">Older source record</a><span>2023-02-29</span></li>
        </ul></div></div></div>"#;
        let output = parse_listing(
            &Html::parse_document(html),
            &Url::parse(YQGDXY_NOTICES_URL).unwrap(),
        )
        .unwrap();
        let observed: Vec<_> = output
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.source_order,
                    entry.title.as_str(),
                    entry.date.as_deref(),
                    entry.resolved_http_url.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            observed,
            vec![
                (
                    1,
                    "Original inline heading",
                    Some("2024-02-29"),
                    Some("https://yqgdxy.buaa.edu.cn/info/1053/42.htm")
                ),
                (
                    2,
                    "External reference",
                    None,
                    Some("https://external.example/notice")
                ),
                (
                    3,
                    "Older source record",
                    None,
                    Some("https://yqgdxy.buaa.edu.cn/info/1053/43.htm")
                ),
            ]
        );
    }

    #[test]
    fn article_owns_header_body_and_publication_date() {
        let body = "<p>Source <em>inline</em> paragraph.</p><p>2001-01-01</p>";
        let (document, _, _) = parse_article_with_completeness(&Html::parse_document(
            &article_html("<span>日期：2024-02-29</span>", body),
        ))
        .unwrap();
        assert_eq!(document.title, "Original inline heading");
        assert_eq!(document.published_at.as_deref(), Some("2024-02-29"));
        assert_eq!(
            document.paragraphs,
            vec![
                "Source inline paragraph.".to_string(),
                "2001-01-01".to_string()
            ]
        );
        for dates in [
            "",
            "<span>日期：2023-02-29</span>",
            "<span>日期：2024-02-29</span><span>日期：2025-01-01</span>",
        ] {
            let (document, _, _) =
                parse_article_with_completeness(&Html::parse_document(&article_html(dates, body)))
                    .unwrap();
            assert_eq!(document.published_at, None);
            assert_eq!(
                document.paragraphs,
                vec![
                    "Source inline paragraph.".to_string(),
                    "2001-01-01".to_string()
                ]
            );
        }
        let duplicate = format!("{html}{html}", html = article_html("", body));
        assert!(parse_article_with_completeness(&Html::parse_document(&duplicate)).is_err());
    }

    #[test]
    fn review_regression_yqgdxy_article_body_excludes_unowned_siblings_and_links() {
        let html = article_html_with_unowned_sibling(
            "<span>日期：2024-02-29</span>",
            r#"<p>Owned source paragraph.</p><a href="/owned.pdf">Owned attachment</a>"#,
        );
        let (document, _, _) =
            parse_article_with_completeness(&Html::parse_document(&html)).unwrap();
        assert_eq!(
            document.paragraphs,
            vec!["Owned source paragraph.".to_string()]
        );
        assert_eq!(document.attachment_hints.len(), 1);
        assert_eq!(document.attachment_hints[0]["text"], "Owned attachment");
        assert!(document.attachments_found);
    }

    #[test]
    fn review_regression_yqgdxy_empty_owned_body_does_not_borrow_sibling_text() {
        let html = article_html_with_unowned_sibling("<span>日期：2024-02-29</span>", "");
        assert_eq!(
            parse_article_with_completeness(&Html::parse_document(&html))
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn review_regression_yqgdxy_nonparagraph_content_is_not_reported_as_full_text() {
        let body = r#"<p>Introduction.</p><img src="poster.png" alt="not transcribed"><table><tr><td>Required table content.</td></tr></table>"#;
        let source = response(
            "https://yqgdxy.buaa.edu.cn/info/1053/42.htm",
            &article_html("", body),
        );
        let document = college_html(&source).unwrap();
        let output = normalize(&source, &document).unwrap();
        assert_eq!(output["body_paragraphs"], json!(["Introduction."]));
        assert_eq!(output["result"], "partial_text");
        assert_eq!(output["completeness"]["image_content_present"], true);
        assert_eq!(output["completeness"]["unextracted_table_count"], 1);
    }

    #[test]
    fn source_profile_rejects_foreign_query_and_http_aliases() {
        for path in [
            "/",
            "/robots.txt",
            "/tzgg.htm",
            "/tzgg/7.htm",
            "/info/1053/7292.htm",
        ] {
            assert!(crate::net::yqgdxy_path_allowed(path));
        }
        for path in [
            "/tzgg/not-a-page.htm",
            "/info/1052/7292.htm",
            "/info/1053/7292.pdf",
            "/other.htm",
        ] {
            assert!(!crate::net::yqgdxy_path_allowed(path));
        }
        assert!(!plain_url(
            &Url::parse("http://yqgdxy.buaa.edu.cn/info/1053/1.htm").unwrap()
        ));
        assert!(!plain_url(
            &Url::parse("https://yqgdxy.buaa.edu.cn/info/1053/1.htm?x=1").unwrap()
        ));
        assert!(!plain_url(
            &Url::parse("https://other.example/info/1053/1.htm").unwrap()
        ));
    }
}
