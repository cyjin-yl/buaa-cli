//! Space and Earth sciences college announcements.
//!
//! The retained directory member is the literal HTTP root
//! `http://sse.buaa.edu.cn/`; the live source is deliberately selected as the
//! separate HTTPS root.  The current root declares the `公告公示`/`通知公告`
//! board at `xwdt/gsgg/tzgg.htm`.  Its rows use the common
//! `nymain/notice-list` layout, while article pages use the common direct
//! `art-main`/`cont-tit`/`vsb_content` layout.  No protocol equivalence is
//! inferred from the two roots.

use super::{
    ArticleDocument, ListQuery, MAX_TEXT, article_category_from_url, article_output,
    article_paragraphs, bind_college_board, college_directory_attribution, college_html,
    declared_jsp_attachment_hints, describe_college_surface, entry_in_scope, failed_contract,
    html_fallback, inert_element, invalid_article, invalid_list, is_admitted_html,
    is_safe_public_fallback, parse_chinese_publication_date, parse_iso_date, parse_notice_list,
    retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, SSE_NOTICES_URL, SSE_ROOT_URL, sse_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://sse.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学空间与地球科学学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("sse.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && sse_path_allowed(url.path())
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
        "空间与地球科学学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = SSE_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_sse(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => SSE_ROOT_URL,
        "notices" => SSE_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, SSE_ROOT_URL, SSE_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            if !is_admitted_html(response) {
                return Err(unavailable());
            }
            match describe_college_surface(response, "sse", attribution.clone()) {
                Ok(value) => Ok(value),
                Err(_) if is_safe_public_fallback(response) => Ok(html_fallback(
                    response,
                    "college_source_surface",
                    "sse",
                    "sse_surface_selector_contract",
                )),
                Err(error) => Err(error),
            }
        })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(SSE_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        let document = college_html(response)?;
        let selected = super::advertised_page_url_document(
            &document,
            &latest,
            page,
            "div.nymain div.ny-right div.notice-list > div > div.pagestyle span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/xwdt/gsgg/tzgg/"),
        );
        if selected.is_err() && !super::is_safe_public_fallback_document(response, &document) {
            return Err(unavailable());
        }
        Ok(selected)
    })?
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
    bind_college_board(&client, SSE_ROOT_URL, SSE_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            let document =
                match college_html(response).and_then(|html| parse_notice_list(&html, &target)) {
                    Ok(document) => document,
                    Err(_) if is_safe_public_fallback(response) => {
                        let mut value = html_fallback(
                            response,
                            "announcements_list",
                            "sse",
                            "sse_listing_selector_contract",
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
                "college":"sse",
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
                    "dates":"source YYYY.MM.DD; missing, invalid or ambiguous stays null",
                    "summaries":"source direct a/p excerpt; not original full text"
                },
                "retrieval":retrieval(response)
            }))
        })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || source_page == 0
        || !target.path().starts_with("/info/1078/")
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
    bind_college_board(&client, SSE_ROOT_URL, SSE_NOTICES_URL, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing = client.get(&source, false, |response| {
        let document =
            match college_html(response).and_then(|html| parse_notice_list(&html, &source)) {
                Ok(document) => document,
                Err(_) if is_safe_public_fallback(response) => {
                    return Ok(html_fallback(
                        response,
                        "announcements_list",
                        "sse",
                        "sse_listing_selector_contract",
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
                "retained notice page does not declare the selected Sse article",
            ));
        }
        Ok(retrieval(response))
    })?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained SSE listing could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client.with_cache_mode(mode).get(target, false, |response| {
        let document = match college_html(response) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_article",
                    "sse",
                    "sse_article_selector_contract",
                ));
            }
            Err(error) => return Err(error),
        };
        let mut value = match normalize(response, &document) {
            Ok(value) => value,
            Err(_) if is_safe_public_fallback(response) => html_fallback(
                response,
                "announcements_article",
                "sse",
                "sse_article_selector_contract",
            ),
            Err(error) => return Err(error),
        };
        Ok({
            value["publisher"] = json!(PUBLISHER);
            value["college"] = json!("sse");
            value["directory_attribution"] = attribution.clone();
            value["source_listing"] = listing.clone();
            value
        })
    })
}

fn normalize(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    let mains = Selector::parse("div.nymain > div.w16 > div.ny-right > form > div.art-main")
        .map_err(|_| unavailable())?;
    let mut mains = document.select(&mains).filter(|node| !inert_element(*node));
    let main = mains
        .next()
        .filter(|_| mains.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Sse article requires one direct nymain/art-main container",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > div.art-tit > h3").map_err(|_| unavailable())?;
    let mut headings = main.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(super::element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "Sse article requires one direct art-tit/h3 heading",
                file!(),
                line!(),
            )
        })?;
    let dates =
        Selector::parse(":scope > div.art-tit > p > span.date").map_err(|_| unavailable())?;
    let mut dates = main.select(&dates);
    let published_at = dates
        .next()
        .filter(|_| dates.next().is_none())
        .and_then(|node| parse_chinese_publication_date(&super::element_text(node)));
    let bodies = Selector::parse(
        ":scope > div.art-body-box > div.art-body > div#vsb_content > div.v_news_content",
    )
    .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Sse article requires one scoped vsb_content/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let paragraphs = article_paragraphs(body, false)?;
    let (attachment_hints, hints_truncated) = declared_jsp_attachment_hints(main)?;
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
        "unique art-main/art-body-box/art-body/#vsb_content/v_news_content paragraphs; executable and fallback text excluded"
    );
    output["completeness"]["attachment_source"] = json!(
        "active source-declared JSP file links within art-main, including siblings outside the text body; hints only, never fetched"
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
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://sse.buaa.edu.cn/info/1078/42.htm".into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            body: body.as_bytes().to_vec(),
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn sse_listing_preserves_rows_dates_excerpts_and_order() {
        let body = r#"<html><head><title>通知公告-空间与地球科学学院</title></head><body>
            <div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-list"><div><ul>
            <li><a href="../../info/1078/42.htm"><span>2026.10.10</span><h3>First source heading</h3><p>First source excerpt.</p></a></li>
            <li><a href="../../info/1078/41.htm"><span>2026.09.01</span><h3>Earlier source heading</h3><p>Earlier source excerpt.</p></a></li>
            </ul></div></div></div></div></div></body></html>"#;
        let parsed = parse_notice_list(
            &Html::parse_document(body),
            &Url::parse(SSE_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].source_order, 1);
        assert_eq!(parsed.entries[0].title, "First source heading");
        assert_eq!(parsed.entries[0].date.as_deref(), Some("2026-10-10"));
        assert_eq!(
            parsed.entries[0].summary.as_deref(),
            Some("First source excerpt.")
        );
        assert_eq!(parsed.entries[1].date.as_deref(), Some("2026-09-01"));
        assert_eq!(
            parsed.entries[0].resolved_http_url.as_deref(),
            Some("https://sse.buaa.edu.cn/info/1078/42.htm")
        );
    }

    #[test]
    fn sse_article_scopes_header_body_and_unfetched_attachment() {
        let body = r#"<html><head><title>Fixture</title></head><body>
            <div class="nymain"><div class="w16"><div class="ny-right"><form><div class="art-main">
              <div class="art-tit"><h3>Source article heading</h3><p><span class="date">日期：2026年10月10日</span></p></div>
              <div class="art-body-box"><div class="art-body"><div id="vsb_content"><div class="v_news_content">
                <p>First source paragraph.</p><p>Second source paragraph.</p><img src="poster.png"><a href="/system/_content/download.jsp?wbfileid=fixture">Source.pdf</a>
              </div></div></div></div>
            </div><p><a href="/system/_content/download.jsp?wbfileid=outside">Outside.pdf</a></p></form></div></div></div></body></html>"#;
        let response = response(body);
        let parsed = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(parsed["title"], "Source article heading");
        assert_eq!(parsed["published_at"], "2026-10-10");
        assert_eq!(
            parsed["body_paragraphs"],
            json!(["First source paragraph.", "Second source paragraph."])
        );
        assert_eq!(
            parsed["attachments"]["hints"],
            json!([{
                "href": "/system/_content/download.jsp?wbfileid=fixture",
                "text": "Source.pdf",
                "fetched": false
            }])
        );
        assert_eq!(parsed["result"], "partial_text");
        assert_eq!(parsed["completeness"]["image_content_present"], true);
    }

    #[test]
    fn sse_urls_remain_directory_bound_and_canonical() {
        for raw in [
            "http://sse.buaa.edu.cn/info/1078/42.htm",
            "https://sse.buaa.edu.cn/info/1078/42.htm?x=1",
            "https://sse.buaa.edu.cn/info/9999/42.htm",
            "https://foreign.example/info/1078/42.htm",
            "https://sse.buaa.edu.cn/xwdt/gsgg/tzgg.htm?x=1",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(!plain_url(&url));
        }
        assert!(plain_url(
            &Url::parse("https://sse.buaa.edu.cn/info/1078/42.htm").unwrap()
        ));
    }
}
