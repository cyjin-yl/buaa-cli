//! Computer-college CMS contract, observed independently of the news center.
//! Lists use p.bt and a split year/month-day; articles use div.d1 and may carry
//! document previews instead of text. Never executes scripts or fetches hints.

use super::{
    ListQuery, ListingDocument, ListingEntry, MAX_ATTACHMENT_HINTS, MAX_BODY_PARAGRAPHS,
    MAX_ENTRIES, MAX_HREF, MAX_HTML, MAX_PARAGRAPH, MAX_TEXT, advertised_page_url, element_text,
    entry_in_scope, failed_contract, invalid_article, invalid_list, is_document_href, is_http,
    parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, Response, SCSE_NOTICES_URL, scse_document_path_allowed,
    scse_path_allowed,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::NaiveDateTime;
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

pub(super) const PUBLISHER: &str = "北京航空航天大学计算机学院";

mod viewer;

fn plain_url(url: &Url, allow_http: bool) -> bool {
    (url.scheme() == "https" || (allow_http && url.scheme() == "http"))
        && url.host_str() == Some("scse.buaa.edu.cn")
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
}

fn list_path(path: &str) -> bool {
    path == "/xwgg/gggs.htm" || (path.starts_with("/xwgg/gggs/") && scse_path_allowed(path))
}

pub(super) fn is_history_source(raw: &str) -> bool {
    Url::parse(raw).is_ok_and(|url| plain_url(&url, true) && list_path(url.path()))
}

fn html(bytes: &[u8]) -> Result<Html, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    Ok(Html::parse_document(
        std::str::from_utf8(bytes).map_err(|_| unavailable())?,
    ))
}

pub(super) fn parse_listing(bytes: &[u8], base: &Url) -> Result<ListingDocument, Error> {
    let document = html(bytes)?;
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(element_text)
        .unwrap_or_default();
    let rows = Selector::parse("div.ej_nr div.list > ul > li").map_err(|_| unavailable())?;
    let anchor = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let heading = Selector::parse("p.bt").map_err(|_| unavailable())?;
    let month_day = Selector::parse("div.sj p").map_err(|_| unavailable())?;
    let year = Selector::parse("div.sj span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in document.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(failed_contract(
                "college listing exceeds the reviewed row budget",
                file!(),
                line!(),
            ));
        }
        let title = row
            .select(&heading)
            .next()
            .map(element_text)
            .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
            .ok_or_else(|| {
                failed_contract("SCSE listing row requires p.bt text", file!(), line!())
            })?;
        let listed_href = row
            .select(&anchor)
            .next()
            .and_then(|node| node.value().attr("href"));
        if listed_href.is_some_and(|href| href.len() > MAX_HREF) {
            return Err(failed_contract(
                "college href exceeds the reviewed byte budget",
                file!(),
                line!(),
            ));
        }
        let listed_href = listed_href
            .filter(|href| !href.is_empty())
            .map(str::to_owned);
        let date = row
            .select(&year)
            .next()
            .zip(row.select(&month_day).next())
            .and_then(|(year, day)| {
                parse_iso_date(&format!("{}-{}", element_text(year), element_text(day)))
            });
        let (resolved_http_url, link_kind) = match listed_href.as_deref() {
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
            category_label: Some("公告公示".into()),
            summary: None,
            listed_href,
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "SCSE listing requires ej_nr/list rows",
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
        .map(|value| parse_iso_date(value).ok_or_else(invalid_list))
        .transpose()?;
    let until = query
        .until
        .as_deref()
        .map(|value| parse_iso_date(value).ok_or_else(invalid_list))
        .transpose()?;
    let latest = Url::parse(SCSE_NOTICES_URL).map_err(|_| unavailable())?;
    let discovery_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let client = ArchiveClient::open_scse(discovery_mode)?;
    let target = if page == 1 {
        latest
    } else {
        client.get(&latest, false, |response| {
            advertised_page_url(&response.body, &latest, page, |url| {
                plain_url(url, false)
                    && url.path().starts_with("/xwgg/gggs/")
                    && list_path(url.path())
            })
        })?
    };
    client.with_cache_mode(mode).get(&target, false, |response| {
        let base = Url::parse(&response.url).map_err(|_| unavailable())?;
        let document = parse_listing(&response.body, &base)?;
        let entries: Vec<&ListingEntry> = document.entries.iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
        Ok(json!({
            "schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"scse","category":"gggs","listing_label":"公告公示","page":page,
            "filters":{"since":since,"until":until,"match":query.r#match},
            "document_title":document.title,"entries":entries,"entry_count":entries.len(),
            "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"source_year_and_month_day; missing stays null"},
            "retrieval":retrieval(response),
        }))
    })
}

fn resolve_article(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|_| invalid_article())?;
    if !plain_url(&url, false)
        || !url.path().starts_with("/info/")
        || !scse_path_allowed(url.path())
    {
        return Err(invalid_article());
    }
    Ok(url)
}

pub(super) fn article(mode: CacheMode, raw: &str) -> Result<Value, Error> {
    let url = resolve_article(raw)?;
    let client = ArchiveClient::open_scse(mode)?;
    client.get(&url, false, normalize_article)
}

fn declared_pdf(document: &Html, article: &Url) -> Result<Option<Url>, Error> {
    let scripts = Selector::parse("div.v_news_content script").map_err(|_| unavailable())?;
    let mut selected: Option<Url> = None;
    for node in document.select(&scripts) {
        if node.value().attr("src").is_some() {
            continue;
        }
        let explicit_type = node.value().attr("type");
        if explicit_type.is_none()
            && node.value().attr("language").is_some_and(|language| {
                !language.is_empty() && !language.eq_ignore_ascii_case("javascript")
            })
        {
            continue; // unreviewed legacy language-derived data block
        }
        let kind = explicit_type
            .unwrap_or_default()
            .trim_matches(|ch| matches!(ch, '\t' | '\n' | '\u{000c}' | '\r' | ' '));
        if kind.eq_ignore_ascii_case("module") {
            if node.text().any(|text| text.contains("showVsbpdfIframe")) {
                return Err(unavailable());
            }
            continue;
        }
        if !kind.is_empty()
            && ![
                "text/javascript",
                "application/javascript",
                "text/ecmascript",
                "application/ecmascript",
                "application/x-javascript",
            ]
            .iter()
            .any(|allowed| kind.eq_ignore_ascii_case(allowed))
        {
            continue;
        }
        for text in node.text() {
            for path in viewer::declarations(text)? {
                if path.len() > MAX_HREF {
                    return Err(unavailable());
                }
                let url = article.join(&path).map_err(|_| unavailable())?;
                if !plain_url(&url, false) || !scse_document_path_allowed(url.path()) {
                    return Err(failed_contract(
                        "source-declared PDF must use the reviewed college document namespace",
                        file!(),
                        line!(),
                    ));
                }
                if selected.as_ref().is_some_and(|previous| previous != &url) {
                    return Err(failed_contract(
                        "article declares ambiguous original PDF documents",
                        file!(),
                        line!(),
                    ));
                }
                selected = Some(url);
            }
        }
    }
    Ok(selected)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentInput {
    article_url: String,
}

pub(super) fn document(mode: CacheMode, input: &str) -> Result<Value, Error> {
    if input.len() > 32 * 1024 {
        return Err(invalid_article());
    }
    let input: DocumentInput = serde_json::from_str(input).map_err(|_| invalid_article())?;
    let article = resolve_article(&input.article_url)?;
    // Resolve against the retained article snapshot. An operator may refresh
    // that article separately; document --refresh revalidates only its PDF.
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let client = ArchiveClient::open_scse(source_mode)?;
    let (document_url, source) = client.get(&article, false, |response| {
        let declared = declared_pdf(&html(&response.body)?, &article)?.ok_or_else(|| {
            failed_contract(
                "article has no supported source-declared original PDF",
                file!(),
                line!(),
            )
        })?;
        Ok((declared, retrieval(response)))
    })?;
    client.with_cache_mode(mode).get(&document_url, true, |response| {
        validate_pdf(response)?;
        Ok(json!({
            "schema_version":1,"type":"announcement_document","result":"source_document_bytes",
            "publisher":PUBLISHER,"college":"scse","source_article":source,
            "reference_policy":"retained_article_snapshot; refresh the article separately to discover a changed document declaration",
            "relationship":"original PDF declared by the source viewer; not a derived preview image",
            "document":{"media_type":"application/pdf","byte_length":response.body.len(),"sha256":response.sha256,"content_base64":STANDARD.encode(&response.body)},
            "retrieval":retrieval(response),
            "verification":{"hash_scope":"retrieved_document_bytes","pdf_framing_checked":true,"external_published_checksum_verified":false,"publisher_signature_verified":false,"document_safety_scan_performed":false},
            "completeness":{"scope":"single_source_declared_pdf","other_attachments_fetched":false,"preview_images_fetched":false,"text_extracted":false,"ocr_performed":false},
        }))
    })
}

fn validate_pdf(response: &Response) -> Result<(), Error> {
    let tail = &response.body[response.body.len().saturating_sub(1024)..];
    let mime_ok = response.headers.get("content-type").is_none_or(|value| {
        let media = value.split(';').next().unwrap_or_default().trim();
        media.eq_ignore_ascii_case("application/pdf")
            || media.eq_ignore_ascii_case("application/octet-stream")
    });
    if !mime_ok
        || !response.body.starts_with(b"%PDF-")
        || !tail.windows(5).any(|window| window == b"%%EOF")
    {
        return Err(failed_contract(
            "source document lacks reviewed PDF MIME/framing; bytes are not cached as a PDF",
            file!(),
            line!(),
        ));
    }
    Ok(())
}

fn preview_paths(document: &Html) -> Result<(bool, Vec<String>), Error> {
    let selector = Selector::parse("div.v_news_content script").map_err(|_| unavailable())?;
    for node in document.select(&selector) {
        // Inspect a bounded JSON string array declared by this observed CMS;
        // never evaluate the script or treat its contents as article prose.
        for text in node.text() {
            let Some(marker) = text.find("vsb_pdf_image_data") else {
                continue;
            };
            let Some(tail) = text[marker..]
                .split_once('=')
                .map(|(_, tail)| tail.trim_start())
            else {
                continue;
            };
            if !tail.starts_with('[') {
                continue;
            }
            let Some(end) = tail.find(']') else {
                continue;
            };
            if end + 1 > 64 * 1024 {
                return Err(unavailable());
            }
            let paths: Vec<String> =
                serde_json::from_str(&tail[..=end]).map_err(|_| unavailable())?;
            if paths.len() > 128
                || paths.iter().any(|path| {
                    path.len() > MAX_HREF
                        || !path.starts_with("/__local/")
                        || path.chars().any(char::is_control)
                })
            {
                return Err(unavailable());
            }
            return Ok((true, paths));
        }
    }
    Ok((false, Vec::new()))
}

fn normalize_article(response: &Response) -> Result<Value, Error> {
    let document = html(&response.body)?;
    let title_selector = Selector::parse("div.d1 p.bt").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(element_text)
        .filter(|text| !text.is_empty() && text.len() <= MAX_HREF)
        .ok_or_else(|| {
            failed_contract("SCSE article requires d1/p.bt heading", file!(), line!())
        })?;
    let date_selector = Selector::parse("div.d1 p.xx span").map_err(|_| unavailable())?;
    let published_at_raw = document.select(&date_selector).next().map(element_text);
    let published_at = published_at_raw.as_deref().and_then(|raw| {
        NaiveDateTime::parse_from_str(raw, "%b %e, %Y %I:%M %p")
            .ok()
            .map(|date| date.date().format("%Y-%m-%d").to_string())
    });
    let paragraph_selector = Selector::parse("div.v_news_content p").map_err(|_| unavailable())?;
    let mut paragraphs = Vec::new();
    for paragraph in document.select(&paragraph_selector) {
        let text = element_text(paragraph);
        if text.is_empty() {
            continue;
        }
        if text.len() > MAX_PARAGRAPH || paragraphs.len() == MAX_BODY_PARAGRAPHS {
            return Err(unavailable());
        }
        paragraphs.push(text);
    }
    let (has_previews, previews) = preview_paths(&document)?;
    let original_pdf = declared_pdf(
        &document,
        &Url::parse(&response.url).map_err(|_| unavailable())?,
    )?;
    let has_document = has_previews || original_pdf.is_some();
    let attachment_selector = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let mut hints = Vec::new();
    let mut hints_truncated = false;
    for anchor in document.select(&attachment_selector) {
        let href = anchor.value().attr("href").unwrap_or_default();
        let name = element_text(anchor);
        if !href.starts_with("/system/_content/download.jsp?") || !is_document_href(&name) {
            continue;
        }
        if href.len() > MAX_HREF || name.len() > MAX_TEXT {
            return Err(unavailable());
        }
        if hints.len() == MAX_ATTACHMENT_HINTS {
            hints_truncated = true;
            break;
        }
        hints.push(json!({"href":href,"text":name,"fetched":false}));
    }
    if paragraphs.is_empty() && !has_document && hints.is_empty() {
        return Err(failed_contract(
            "SCSE article requires text or declared document/attachment content",
            file!(),
            line!(),
        ));
    }
    let result = if has_document {
        if paragraphs.is_empty() {
            "embedded_document"
        } else {
            "partial_text"
        }
    } else if paragraphs.is_empty() {
        "attachment_only"
    } else {
        "full_text"
    };
    Ok(json!({
        "schema_version":1,"type":"announcements_article","result":result,"publisher":PUBLISHER,"college":"scse",
        "title":title,"published_at":published_at,"published_at_raw":published_at_raw,
        "body_paragraph_count":paragraphs.len(),"body_paragraphs":paragraphs,
        "embedded_document":{"present":has_document,"original_pdf_url":original_pdf.as_ref().map(Url::as_str),"preview_paths":previews,"preview_kind":"source_declared_derived_images","assets_fetched":false,"ocr_performed":false,"original_document_verified":false},
        "attachments":{"found":!hints.is_empty(),"hints":hints,"hints_truncated":hints_truncated,"note":"source-declared links only; never fetched"},
        "completeness":{"scope":"single_college_article_page","body_source":"v_news_content paragraphs excluding executable/fallback markup","missing_document_text":"not_reconstructed"},
        "retrieval":retrieval(response),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://scse.buaa.edu.cn/info/1099/42.htm".into(),
            status: 200,
            headers: BTreeMap::new(),
            body: body.as_bytes().to_vec(),
            sha256: "a".repeat(64),
            fetched_at_unix_ms: 0,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn split_dates_and_http_history_preserve_original_source_scope() {
        let body = br#"<title>Fixture notices</title><div class="ej_nr"><div class="list"><ul><li><a href="../../info/1099/42.htm"><div class="sj"><p>09-07</p><span>2026</span></div><p class="bt">Fixture notice</p></a></li><li><p class="bt">Unknown date and link</p></li></ul></div></div>"#;
        let base = Url::parse("http://scse.buaa.edu.cn/xwgg/gggs/1.htm").unwrap();
        let document = parse_listing(body, &base).unwrap();
        assert_eq!(document.entries[0].date.as_deref(), Some("2026-09-07"));
        assert_eq!(
            document.entries[0].resolved_http_url.as_deref(),
            Some("http://scse.buaa.edu.cn/info/1099/42.htm")
        );
        assert!(document.entries[1].date.is_none());
        assert_eq!(document.entries[1].link_kind, "missing");
        let since = Some("2026-09-01".into());
        assert!(!entry_in_scope(&document.entries[1], &since, &None, &None));
    }

    #[test]
    fn preview_scripts_are_not_policy_text_and_jsp_attachments_survive() {
        let body = r#"<h2>Wrong sidebar heading</h2><div class="d1"><p class="bt">Fixture policy</p><p class="xx"><span>Sep 7, 2026 06:30 PM</span></p></div><div class="v_news_content"><p><script>var vsb_pdf_image_data = ["/__local/fixture.jpg"];</script></p></div><ul><li><a href="/system/_content/download.jsp?urltype=news.DownloadAttachUrl&amp;owner=1&amp;wbfileid=fixture">Form.pdf</a></li></ul>"#;
        let out = normalize_article(&response(body)).unwrap();
        assert_eq!(out["title"], "Fixture policy");
        assert_eq!(out["published_at"], "2026-09-07");
        assert_eq!(out["result"], "embedded_document");
        assert_eq!(out["body_paragraph_count"], 0);
        assert_eq!(out["attachments"]["hints"][0]["text"], "Form.pdf");
        assert_eq!(
            out["embedded_document"]["original_document_verified"],
            false
        );
    }

    #[test]
    fn college_pager_cannot_escape_its_advertised_board() {
        let base = Url::parse(SCSE_NOTICES_URL).unwrap();
        let allowed = |url: &Url| {
            plain_url(url, false) && url.path().starts_with("/xwgg/gggs/") && list_path(url.path())
        };
        let body = br#"<div class="pb_sys_common"><span class="p_no"><a href="gggs/1.htm">2</a></span></div>"#;
        assert_eq!(
            advertised_page_url(body, &base, 2, allowed).unwrap().path(),
            "/xwgg/gggs/1.htm"
        );
        let wrong_board = br#"<div class="pb_sys_common"><span class="p_no"><a href="xydt/1.htm">2</a></span></div>"#;
        assert_eq!(
            advertised_page_url(wrong_board, &base, 2, allowed)
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn notice_article_scope_rejects_other_categories_and_credential_routes() {
        for url in [
            "https://scse.buaa.edu.cn/info/1002/42.htm",
            "https://news.buaa.edu.cn/info/1099/42.htm",
            "https://operator:secret@scse.buaa.edu.cn/info/1099/42.htm",
            "https://scse.buaa.edu.cn/info/1099/42.htm?session=fixture",
            "https://scse.buaa.edu.cn/info/1099/42.htm#fragment",
        ] {
            assert_eq!(resolve_article(url).unwrap_err().code, "invalid_input");
        }
    }

    #[test]
    fn original_pdf_is_declared_by_viewer_not_inferred_from_preview_names() {
        let article = Url::parse("https://scse.buaa.edu.cn/info/1099/42.htm").unwrap();
        let path = "/__local/C/C7/70/AAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBB_123.pdf";
        let body = format!(
            r#"<div class="v_news_content"><script>var vsb_pdf_image_data=["/__local/preview.jpg"];showVsbpdfIframe("{path}","100%");</script></div>"#
        );
        assert_eq!(
            declared_pdf(&html(body.as_bytes()).unwrap(), &article)
                .unwrap()
                .unwrap()
                .path(),
            path
        );
        let preview_only = br#"<div class="v_news_content"><script>var vsb_pdf_image_data=["/__local/preview.jpg"];</script></div>"#;
        assert!(
            declared_pdf(&html(preview_only).unwrap(), &article)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn viewer_expressions_and_foreign_document_routes_are_not_followed() {
        let article = Url::parse("https://scse.buaa.edu.cn/info/1099/42.htm").unwrap();
        for argument in [
            r#""https://evil.example/file.pdf""#,
            r#""/__local/C/C7/70/AAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBB_123.pdf?session=fixture""#,
            r#""/__local/C/C7/70/AAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBB_123.pdf"+suffix"#,
        ] {
            let body = format!(
                "<div class=\"v_news_content\"><script>showVsbpdfIframe({argument},\"100%\");</script></div>"
            );
            assert_eq!(
                declared_pdf(&html(body.as_bytes()).unwrap(), &article)
                    .unwrap_err()
                    .code,
                "unavailable"
            );
        }
    }

    #[test]
    fn login_html_and_truncated_pdf_are_not_retained_as_documents() {
        for body in ["<html>Not a document</html>", "%PDF-1.7\ntruncated"] {
            assert_eq!(
                validate_pdf(&response(body)).unwrap_err().code,
                "unavailable"
            );
        }
    }

    #[test]
    fn inactive_viewer_text_cannot_declare_an_original_pdf() {
        let article = Url::parse("https://scse.buaa.edu.cn/info/1099/42.htm").unwrap();
        let path = "/__local/C/C7/70/AAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBB_123.pdf";
        let scripts = [
            format!("// showVsbpdfIframe(\"{path}\",\"100%\");"),
            format!("/* showVsbpdfIframe(\"{path}\",\"100%\"); */"),
            format!("var inert = 'showVsbpdfIframe(\"{path}\",\"100%\");';"),
            format!("<!-- ;showVsbpdfIframe(\"{path}\");\n"),
        ];
        for script in scripts {
            let source = format!("<div class=\"v_news_content\"><script>{script}</script></div>");
            assert!(
                declared_pdf(&html(source.as_bytes()).unwrap(), &article)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn viewer_calls_require_executable_classic_script_content() {
        let article = Url::parse("https://scse.buaa.edu.cn/info/1099/42.htm").unwrap();
        let path = "/__local/C/C7/70/AAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBB_123.pdf";
        for attributes in [
            "type=\"text/plain\"",
            "type=\"application/json\"",
            "src=\"/external.js\"",
            "language=\"vbscript\"",
            "type=\"\u{00a0}text/javascript\"",
        ] {
            let source = format!(
                "<div class=\"v_news_content\"><script {attributes}>showVsbpdfIframe(\"{path}\");</script></div>"
            );
            assert!(
                declared_pdf(&html(source.as_bytes()).unwrap(), &article)
                    .unwrap()
                    .is_none()
            );
        }
        let source = format!(
            "<div class=\"v_news_content\"><script>// comment\rshowVsbpdfIframe(\"{path}\");</script></div>"
        );
        assert_eq!(
            declared_pdf(&html(source.as_bytes()).unwrap(), &article)
                .unwrap()
                .unwrap()
                .path(),
            path
        );
        let interpolation = format!(
            "<div class=\"v_news_content\"><script>var unsupported = `x${{showVsbpdfIframe(\"{path}\")}}`;</script></div>"
        );
        assert!(declared_pdf(&html(interpolation.as_bytes()).unwrap(), &article).is_err());
    }

    #[test]
    fn original_pdf_without_previews_is_not_mislabeled_full_text() {
        let path = "/__local/C/C7/70/AAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBB_123.pdf";
        let header = "<div class=\"d1\"><p class=\"bt\">Fixture document</p></div>";
        let viewer = format!(
            "<div class=\"v_news_content\"><p><script>showVsbpdfIframe(\"{path}\",\"100%\");</script></p></div>"
        );
        let source = format!("{header}{viewer}");
        let out = normalize_article(&response(&source)).unwrap();
        assert_eq!(out["result"], "embedded_document");
        assert_eq!(out["embedded_document"]["present"], true);
        let intro = format!(
            "{header}<div class=\"v_news_content\"><p>Introductory text</p><script>showVsbpdfIframe(\"{path}\",\"100%\");</script></div>"
        );
        assert_eq!(
            normalize_article(&response(&intro)).unwrap()["result"],
            "partial_text"
        );
    }
}
