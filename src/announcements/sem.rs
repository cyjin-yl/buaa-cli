//! Economics and management college notices: exact directory identity,
//! separately selected HTTPS observation, and the reviewed `tzgg` board.
//!
//! The board uses the college site's desktop `ul.d-newsU5` rows rather than
//! the `nymain/notice-list` layout used by several other college sources.
//! Each row has one `a.inner`, an `h4.tit` heading, and a split month/day plus
//! year date.  Article pages keep their heading/date/body under one
//! `d-detail1` form.  External links (including WeChat announcements) remain
//! listing metadata and are never followed by this adapter.

use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url, article_category_from_url, article_output, article_paragraphs,
    bind_college_board, college_directory_attribution, college_html, declared_jsp_attachment_hints,
    describe_college_surface, element_text, entry_in_scope, failed_contract, html_fallback,
    inert_element, invalid_article, invalid_list, is_admitted_html, is_http,
    is_safe_public_fallback, parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, Response, SEM_NOTICES_URL, SEM_ROOT_URL, sem_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://sem.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学经济管理学院";
const CATEGORY: &str = "tzgg";
const CATEGORY_LABEL: &str = "通知公告";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("sem.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && sem_path_allowed(url.path())
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
        "经济管理学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = SEM_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_sem(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => SEM_ROOT_URL,
        "notices" => SEM_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, SEM_ROOT_URL, SEM_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            if !is_admitted_html(response) {
                return Err(unavailable());
            }
            match describe_college_surface(response, "sem", attribution.clone()) {
                Ok(value) => Ok(value),
                Err(_) if is_safe_public_fallback(response) => Ok(html_fallback(
                    response,
                    "college_source_surface",
                    "sem",
                    "sem_surface_selector_contract",
                )),
                Err(error) => Err(error),
            }
        })
}

fn parse_sem_date(row: ElementRef<'_>) -> Option<String> {
    let dates = Selector::parse(":scope > a.inner > div.date").ok()?;
    let mut dates = row.select(&dates);
    let date = dates.next()?;
    if dates.next().is_some() {
        return None;
    }
    let day_selector = Selector::parse(":scope > div.t1").ok()?;
    let year_selector = Selector::parse(":scope > div.t2").ok()?;
    let mut days = date.select(&day_selector);
    let day = days.next().map(element_text)?;
    if days.next().is_some() {
        return None;
    }
    let mut years = date.select(&year_selector);
    let year = years.next().map(element_text)?;
    if years.next().is_some() {
        return None;
    }
    let year = year.trim().strip_prefix('/')?.trim();
    let (month, day) = day.trim().split_once('-')?;
    if month.is_empty() || day.is_empty() || month.contains('-') || day.contains('-') {
        return None;
    }
    parse_iso_date(&format!("{year}-{month}-{day}"))
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

    let board_selector = Selector::parse("ul.d-newsU5").map_err(|_| unavailable())?;
    let mut boards = document
        .select(&board_selector)
        .filter(|node| !inert_element(*node));
    let board = boards
        .next()
        .filter(|_| boards.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "SEM notices require one active d-newsU5 board",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a.inner[href]").map_err(|_| unavailable())?;
    let headings = Selector::parse(":scope > div.text > h4.tit").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in board.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut row_anchors = row.select(&anchors);
        let anchor = row_anchors
            .next()
            .filter(|_| row_anchors.next().is_none())
            .ok_or_else(|| {
                failed_contract(
                    "SEM notice row requires one direct inner anchor",
                    file!(),
                    line!(),
                )
            })?;
        let mut row_headings = anchor.select(&headings);
        let title = row_headings
            .next()
            .filter(|_| row_headings.next().is_none())
            .map(element_text)
            .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT)
            .ok_or_else(|| {
                failed_contract(
                    "SEM notice row requires one direct text/h4 heading",
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
            date: parse_sem_date(row),
            category_label: Some(CATEGORY_LABEL.into()),
            summary: None,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "SEM notice board has no active source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(SEM_NOTICES_URL).map_err(|_| unavailable())?;
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
            |url| plain_url(url) && url.path().starts_with("/xwdt/tzgg/"),
        )
    })
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
    bind_college_board(&client, SEM_ROOT_URL, SEM_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            let document =
                match college_html(response).and_then(|html| parse_listing(&html, &target)) {
                    Ok(document) => document,
                    Err(_) if is_safe_public_fallback(response) => {
                        let mut value = html_fallback(
                            response,
                            "announcements_list",
                            "sem",
                            "sem_listing_selector_contract",
                        );
                        value["category"] = json!(CATEGORY);
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
                "college":"sem",
                "category":CATEGORY,
                "listing_label":CATEGORY_LABEL,
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
                    "dates":"source split month-day/year; missing, invalid or ambiguous stays null",
                    "summaries":"source has no reviewed row summary; not reconstructed",
                    "external_links":"retained as source hints; never fetched"
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
        || !target.path().starts_with("/info/1024/")
    {
        return Err(invalid_article());
    }
    let (client, attribution) = bound_client(mode)?;
    article_with_client(client, mode, &target, source_page, attribution)
}

fn article_with_client(
    client: ArchiveClient,
    mode: CacheMode,
    target: &Url,
    source_page: u32,
    mut attribution: Value,
) -> Result<Value, Error> {
    bind_college_board(&client, SEM_ROOT_URL, SEM_NOTICES_URL, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing = client.get(&source, false, |response| {
        let document = match college_html(response).and_then(|html| parse_listing(&html, &source)) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_list",
                    "sem",
                    "sem_listing_selector_contract",
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
                "retained SEM notice page does not declare the selected article",
            ));
        }
        Ok(retrieval(response))
    })?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained SEM listing could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client.with_cache_mode(mode).get(target, false, |response| {
        let document = match college_html(response) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_article",
                    "sem",
                    "sem_article_selector_contract",
                ));
            }
            Err(error) => return Err(error),
        };
        let mut value = match normalize(response, &document) {
            Ok(value) => value,
            Err(_) if is_safe_public_fallback(response) => html_fallback(
                response,
                "announcements_article",
                "sem",
                "sem_article_selector_contract",
            ),
            Err(error) => return Err(error),
        };
        Ok({
            value["publisher"] = json!(PUBLISHER);
            value["college"] = json!("sem");
            value["directory_attribution"] = attribution.clone();
            value["source_listing"] = listing.clone();
            value
        })
    })
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let details = Selector::parse("div.d-detail1").map_err(|_| unavailable())?;
    let mut details = document
        .select(&details)
        .filter(|node| !inert_element(*node));
    let detail = details
        .next()
        .filter(|_| details.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "SEM article requires one active d-detail1 container",
                file!(),
                line!(),
            )
        })?;
    let forms = Selector::parse(":scope > form[name=\"_newscontent_fromname\"]")
        .map_err(|_| unavailable())?;
    let mut forms = detail.select(&forms);
    let form = forms
        .next()
        .filter(|_| forms.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "SEM article requires one direct news-content form",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > div.hd > h1.tit").map_err(|_| unavailable())?;
    let mut headings = form.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "SEM article requires one direct hd/h1 title",
                file!(),
                line!(),
            )
        })?;
    let info = Selector::parse(":scope > div.hd > div.info > span").map_err(|_| unavailable())?;
    let publication_values: Vec<String> = form
        .select(&info)
        .map(element_text)
        .filter(|value| value.contains("发布时间"))
        .collect();
    let published_at_raw = if publication_values.len() == 1 {
        publication_values.into_iter().next()
    } else {
        None
    };
    let published_at = published_at_raw.as_deref().and_then(|raw| {
        let value = raw.split_once('：')?.1.trim();
        parse_iso_date(value)
    });
    let bodies = Selector::parse(":scope > div#vsb_content > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = form.select(&bodies).filter(|node| !inert_element(*node));
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "SEM article requires one direct vsb_content/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let paragraphs = article_paragraphs(body, true)?;
    let (attachment_hints, hints_truncated) = declared_jsp_attachment_hints(form)?;
    let attachments_found = !attachment_hints.is_empty() || hints_truncated;
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let scripts = Selector::parse("script").map_err(|_| unavailable())?;
    let tables = Selector::parse("table").map_err(|_| unavailable())?;
    let has_images = body.select(&images).any(|node| !inert_element(node));
    let has_embedded_viewer = body.select(&scripts).any(|script| {
        !inert_element(script) && script.text().any(|text| text.contains("showVsbpdfIframe"))
    });
    let table_count = body
        .select(&tables)
        .filter(|node| !inert_element(*node))
        .count();
    if paragraphs.is_empty()
        && !attachments_found
        && !has_images
        && !has_embedded_viewer
        && table_count == 0
    {
        return Err(failed_contract(
            "SEM article requires text or declared nonparagraph source content",
            file!(),
            line!(),
        ));
    }
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
    output["published_at_raw"] = published_at_raw.map(Value::String).unwrap_or(Value::Null);
    output["attachments"]["hints_truncated"] = json!(hints_truncated);
    output["completeness"]["body_source"] = json!(
        "unique d-detail1/news-content form/vsb_content/v_news_content paragraphs; executable and fallback text excluded"
    );
    output["completeness"]["image_content_present"] = json!(has_images);
    output["completeness"]["embedded_viewer_present"] = json!(has_embedded_viewer);
    output["completeness"]["unextracted_table_count"] = json!(table_count);
    if attachments_found || has_images || has_embedded_viewer || table_count != 0 {
        output["result"] = if output["body_paragraph_count"] == json!(0) {
            json!("attachment_only")
        } else {
            json!("partial_text")
        };
        output["completeness"]["missing_nonparagraph_content"] = json!(
            "attachment bytes, embedded document text, image text and nonparagraph table content are not reconstructed or downloaded"
        );
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str, url: &str) -> Response {
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
    fn listing_preserves_external_links_and_split_dates() {
        let source = r#"
            <title>通知公告-经济管理学院</title>
            <ul class="d-newsU5">
              <li><a class="inner" href="../info/1024/42.htm"><div class="date"><div class="t1">09-08</div><div class="t2">/ 2026</div></div><div class="text"><h4 class="tit">Policy notice</h4></div></a></li>
              <li><a class="inner" href="https://mp.weixin.qq.com/s/example"><div class="date"><div class="t1">bad</div><div class="t2">/ 2026</div></div><div class="text"><h4 class="tit">External notice</h4></div></a></li>
            </ul>
        "#;
        let base = Url::parse(SEM_NOTICES_URL).unwrap();
        let listing = parse_listing(&Html::parse_document(source), &base).unwrap();
        assert_eq!(listing.entries.len(), 2);
        assert_eq!(listing.entries[0].date.as_deref(), Some("2026-09-08"));
        assert_eq!(
            listing.entries[0].resolved_http_url.as_deref(),
            Some("https://sem.buaa.edu.cn/info/1024/42.htm")
        );
        assert_eq!(listing.entries[1].date, None);
        assert_eq!(
            listing.entries[1].resolved_http_url.as_deref(),
            Some("https://mp.weixin.qq.com/s/example")
        );
    }

    #[test]
    fn listing_rejects_multiple_active_boards() {
        let source = r#"<title>Fixture</title><ul class="d-newsU5"><li><a class="inner"><div class="text"><h4 class="tit">One</h4></div></a></li></ul><ul class="d-newsU5"><li><a class="inner"><div class="text"><h4 class="tit">Two</h4></div></a></li></ul>"#;
        assert!(
            parse_listing(
                &Html::parse_document(source),
                &Url::parse(SEM_NOTICES_URL).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn article_reads_scoped_header_body_and_attachment_hints() {
        let source = r#"
          <div class="d-detail1"><form name="_newscontent_fromname">
            <div class="hd"><h1 class="tit">Policy article</h1><div class="info"><span>来源：</span><span>发布时间：2026-09-08</span></div></div>
            <div id="vsb_content"><div class="v_news_content"><p>First paragraph.</p><p>Second paragraph.</p></div></div>
            <p><a href="/system/_content/download.jsp?owner=1&wbfileid=x">Policy.pdf</a></p>
          </form></div>
        "#;
        let response = response(source, "https://sem.buaa.edu.cn/info/1024/42.htm");
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["title"], "Policy article");
        assert_eq!(output["published_at"], "2026-09-08");
        assert_eq!(
            output["body_paragraphs"],
            json!(["First paragraph.", "Second paragraph."])
        );
        assert_eq!(output["attachments"]["hints"][0]["text"], "Policy.pdf");
        assert_eq!(output["result"], "partial_text");
    }

    #[test]
    fn article_allows_declared_viewer_without_inventing_text() {
        let source = r#"
          <div class="d-detail1"><form name="_newscontent_fromname">
            <div class="hd"><h1 class="tit">PDF notice</h1><div class="info"><span>发布时间：2026-09-08</span></div></div>
            <div id="vsb_content"><div class="v_news_content"><p><script>showVsbpdfIframe("/__local/original.pdf");</script></p></div></div>
            <p><a href="/system/_content/download.jsp?owner=1&wbfileid=x">Application.docx</a></p>
          </form></div>
        "#;
        let response = response(source, "https://sem.buaa.edu.cn/info/1024/42.htm");
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["body_paragraphs"], json!([]));
        assert_eq!(output["result"], "attachment_only");
        assert_eq!(output["completeness"]["embedded_viewer_present"], true);
    }

    #[test]
    fn sem_url_admission_rejects_query_and_foreign_paths() {
        assert!(plain_url(&Url::parse(SEM_NOTICES_URL).unwrap()));
        assert!(!plain_url(
            &Url::parse("https://sem.buaa.edu.cn/xwdt/tzgg.htm?x=1").unwrap()
        ));
        assert!(!plain_url(
            &Url::parse("https://sem.buaa.edu.cn/info/1020/42.htm").unwrap()
        ));
        assert!(!plain_url(
            &Url::parse("https://other.buaa.edu.cn/info/1024/42.htm").unwrap()
        ));
    }
}
