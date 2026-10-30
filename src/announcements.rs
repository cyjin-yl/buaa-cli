//! Official BUAA news-center (`news.buaa.edu.cn`) announcements and news, parsed
//! over a cache-first snapshot shared with the official-directory governor policy.
//!
//! The retired `www.buaa.edu.cn/xwzx.htm` listing now 404s; the live news center
//! is `news.buaa.edu.cn`. Category listings (`tzgg.htm`, `zhxw.htm`, ...) expose
//! one `.tlist li` row per item: an `a[href]` anchor, a `.pub_date` day + month,
//! and a `.pub_info` category label / `h3` title / summary `p`. Article pages
//! (`/info/<category>/<id>.htm`) carry the title in `h2`, the publish date in
//! `.cont-tit`, and the body in `.v_news_content`. Rows missing a title are
//! rejected rather than reconstructed; missing dates stay `null`. Attachment
//! links are surfaced as hints and never downloaded. Historical bytes remain
//! operator-asserted provenance, bound by SHA-256.

use crate::html::{active_element_text, element_text, inert_element};
use crate::net::{ArchiveClient, CacheMode, Error, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{NaiveDate, NaiveDateTime};
use scraper::{ElementRef, Html, Node, Selector};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

pub(crate) mod ase;
pub(crate) mod aviation;
pub(crate) mod beijing;
pub(crate) mod bme;
pub(crate) mod cst;
pub(crate) mod dept3;
pub(crate) mod ee;
pub(crate) mod fld;
pub(crate) mod h3i;
pub(crate) mod hss;
pub(crate) mod iai;
pub(crate) mod ic;
pub(crate) mod iiif;
pub(crate) mod math;
pub(crate) mod me;
pub(crate) mod mse;
pub(crate) mod physics;
pub(crate) mod rse;
pub(crate) mod sa;
pub(crate) mod sce;
mod scse;
#[cfg(feature = "viewer-admission-proof")]
pub fn proof_scse_article(response: &Response) -> Result<Value, Error> {
    scse::normalize_article(response)
}
pub(crate) mod sem;
pub(crate) mod sepe;
pub(crate) mod shenyuan;
pub(crate) mod soft;
pub(crate) mod sse;
pub(crate) mod transportation;
pub(crate) mod viewer;
pub(crate) mod wrj;
pub(crate) mod ygy;
pub(crate) mod yqgdxy;
pub(crate) mod zfai;

const NEWS_BASE: &str = "https://news.buaa.edu.cn";
const MAX_HTML: usize = 2 * 1024 * 1024;
const MAX_HISTORY_METADATA: usize = 8 * 1024;
const MAX_ENTRIES: usize = 256;
const MAX_TEXT: usize = 512;
const MAX_HREF: usize = 4096;
const MAX_BODY_PARAGRAPHS: usize = 1024;
const MAX_PARAGRAPH: usize = 8 * 1024;
const MAX_ATTACHMENT_HINTS: usize = 32;
const DEFAULT_CATEGORY: &str = "tzgg";

/// Reviewed news-center category listings as `(slug, label)` pairs.
const CATEGORIES: &[(&str, &str)] = &[
    ("tzgg", "通知公告"),
    ("zhxw", "综合新闻"),
    ("ztxw", "专题新闻"),
    ("bhrw", "北航人物"),
    ("xyfc_new", "校园风采"),
    ("kjzx_new", "科教在线"),
    ("mtbh_new", "媒体北航"),
    ("gybh_new", "光影北航"),
    ("spxw1", "视频新闻"),
    ("wyyd_new", "文艺园地"),
];

/// File extensions treated as downloadable attachments (surfaced as hints only).
const DOCUMENT_EXTENSIONS: &[&str] = &[
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".txt", ".wps",
    ".ofd",
];

#[derive(Debug, serde::Serialize)]
pub struct ListingEntry {
    pub source_order: usize,
    pub title: String,
    pub date: Option<String>,
    pub category_label: Option<String>,
    pub summary: Option<String>,
    pub listed_href: Option<String>,
    pub resolved_http_url: Option<String>,
    pub link_kind: &'static str,
}

#[derive(Debug, serde::Serialize)]
pub struct ListingDocument {
    pub title: String,
    pub entries: Vec<ListingEntry>,
}

#[derive(Debug)]
struct ArticleDocument {
    title: String,
    category: Option<String>,
    published_at: Option<String>,
    paragraphs: Vec<String>,
    attachment_hints: Vec<Value>,
    attachments_found: bool,
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    college: Option<String>,
    category: Option<String>,
    page: Option<u32>,
    since: Option<String>,
    until: Option<String>,
    #[serde(rename = "match")]
    r#match: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ArticleQuery {
    url: Option<String>,
    source_page: Option<u32>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryInput {
    html: String,
    provenance: HistoryProvenance,
    #[serde(default, deserialize_with = "deserialize_history_kind")]
    kind: Option<Option<String>>,
    #[serde(default)]
    encoding: HistoryEncoding,
    root_view: Option<HistoryRootView>,
}

// Preserve the pre-existing optional kind behavior outside legacy MSE, while
// distinguishing omitted from explicit null for the newly admitted root.
fn deserialize_history_kind<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <Option<String> as serde::Deserialize>::deserialize(deserializer).map(Some)
}

#[derive(Default, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum HistoryEncoding {
    #[default]
    Utf8,
    Gb2312,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoryRootView {
    News,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryProvenance {
    source_url: String,
    #[serde(default)]
    capture_timestamp: Option<String>,
    #[serde(default)]
    asserted_by: Option<String>,
}

fn unavailable() -> Error {
    Error::new(
        "unavailable",
        "official news-center document could not be interpreted safely; file an issue at https://github.com/cyjin-yl/buaa-cli/issues/new with this CLI version and URL",
    )
}

fn invalid_list() -> Error {
    Error::new(
        "invalid_input",
        "announcements list input is malformed; expected a JSON object with optional college, category, page, since, until, match",
    )
}

fn invalid_article() -> Error {
    Error::new(
        "invalid_input",
        "announcements article input is malformed; expected a reviewed source-declared HTTPS article URL and a source-supported source_page",
    )
}

fn invalid_document() -> Error {
    Error::new(
        "invalid_input",
        "announcements document input is malformed; expected a JSON object with article_url naming a reviewed source-declared HTTPS SCSE or Chemistry (sce) article URL",
    )
}

fn invalid_history() -> Error {
    Error::new(
        "invalid_input",
        "announcements history input is malformed; original bytes, explicit encoding and provenance must match an admitted offline source contract",
    )
}

/// Emit a rejected-parse error anchored to a declared invariant, so an
/// operator-agent can file a GitHub issue or debug-and-patch the listed
/// invariant and open a PR.
fn failed_contract(invariant: &'static str, file: &'static str, line: u32) -> Error {
    Error::with_source(
        "unavailable",
        "official news-center document contract violated; the public page layout likely changed. File an issue at https://github.com/cyjin-yl/buaa-cli/issues/new or debug the reported invariant yourself and open a PR",
        file,
        line,
        invariant,
    )
}

fn normalized_text<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    parts
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

fn category_label(slug: &str) -> Option<&'static str> {
    CATEGORIES
        .iter()
        .find(|(entry_slug, _)| *entry_slug == slug)
        .map(|(_, label)| *label)
}

fn is_http(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

/// Only the latest listing has a stable URL. Numbered pages must be selected
/// from the source's advertised links, not guessed from an ordinal.
fn latest_listing_url(category: &str) -> Result<Url, Error> {
    if category_label(category).is_none() {
        return Err(Error::new(
            "invalid_input",
            "unknown announcements category; expected one of: tzgg, zhxw, ztxw, bhrw, xyfc_new, kjzx_new, mtbh_new, gybh_new, spxw1, wyyd_new",
        ));
    }
    Url::parse(&format!("{NEWS_BASE}/{category}.htm")).map_err(|_| unavailable())
}

fn advertised_page_url(
    bytes: &[u8],
    base: &Url,
    page: u32,
    ordinal_links: &str,
    allowed_page: impl Fn(&Url) -> bool,
) -> Result<Url, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(text);
    advertised_page_url_document(&document, base, page, ordinal_links, allowed_page)
}

fn advertised_page_url_document(
    document: &Html,
    base: &Url,
    page: u32,
    ordinal_links: &str,
    allowed_page: impl Fn(&Url) -> bool,
) -> Result<Url, Error> {
    let selector = Selector::parse(ordinal_links).map_err(|_| unavailable())?;
    let mut selected = None;
    for link in document.select(&selector) {
        if element_text(link).parse::<u32>().ok() != Some(page) {
            continue;
        }
        let url = base
            .join(link.value().attr("href").ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
        if !allowed_page(&url) {
            return Err(failed_contract(
                "advertised listing page must remain in the selected category",
                file!(),
                line!(),
            ));
        }
        match selected.as_ref() {
            Some(previous) if previous != &url => {
                return Err(Error::new(
                    "unavailable",
                    "requested page has conflicting advertised destinations; no URL was selected",
                ));
            }
            None => selected = Some(url),
            _ => {}
        }
    }
    selected.ok_or_else(|| {
        Error::new(
            "unavailable",
            "requested page is not advertised by the latest listing; no URL was inferred",
        )
    })
}

/// True when an operator-asserted history `source_url` is a news-center listing.
fn is_list_source_url(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if url.scheme() != "https"
        || url.host_str() != Some("news.buaa.edu.cn")
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return false;
    }
    let path = url.path();
    CATEGORIES.iter().any(|(slug, _)| {
        path == format!("/{slug}.htm")
            || path
                .strip_prefix(&format!("/{slug}/"))
                .and_then(|tail| tail.strip_suffix(".htm"))
                .is_some_and(|page| !page.is_empty() && page.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Compact listing date `<b>DD</b><span>YYYY.MM</span>` → canonical `YYYY-MM-DD`.
fn parse_compact_date(day_raw: &str, yearmonth_raw: &str) -> Option<String> {
    let day_raw = day_raw.trim();
    let ym = yearmonth_raw.trim();
    if day_raw.is_empty() || day_raw.len() > 2 || day_raw.bytes().any(|b| !b.is_ascii_digit()) {
        return None;
    }
    if ym.len() != 7 || !ym.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    let year: i32 = ym[0..4].parse().ok()?;
    if ym.as_bytes()[4] != b'.' {
        return None;
    }
    let month: u32 = ym[5..7].parse().ok()?;
    let day: u32 = day_raw.parse().ok()?;
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    Some(date.format("%Y-%m-%d").to_string())
}

/// Canonical ISO date filter value (`YYYY-MM-DD`), validated as a real date.
fn parse_iso_date(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.len() != 10 {
        return None;
    }
    let b = raw.as_bytes();
    if b[4] != b'-'
        || b[7] != b'-'
        || !b[0..4].iter().all(|c| c.is_ascii_digit())
        || !b[5..7].iter().all(|c| c.is_ascii_digit())
        || !b[8..10].iter().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let year: i32 = raw[0..4].parse().ok()?;
    let month: u32 = raw[5..7].parse().ok()?;
    let day: u32 = raw[8..10].parse().ok()?;
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    Some(date.format("%Y-%m-%d").to_string())
}

fn parse_chinese_publication_date(raw: &str) -> Option<String> {
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

/// Parse one news-center category listing. Public for offline evidence
/// validation; performs no network or cache access.
pub fn parse_listing(bytes: &[u8], base: &Url) -> Result<ListingDocument, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(text);
    let title = document
        .select(&Selector::parse("title").map_err(|_| unavailable())?)
        .next()
        .map(|node| normalized_text(node.text()))
        .unwrap_or_default();

    let row_selector = Selector::parse("div.tlist li").map_err(|_| unavailable())?;
    let anchor_selector = Selector::parse("a").map_err(|_| unavailable())?;
    let row_title_selector = Selector::parse("div.pub_info h3").map_err(|_| unavailable())?;
    let label_selector = Selector::parse("div.pub_info span").map_err(|_| unavailable())?;
    let summary_selector = Selector::parse("div.pub_info p").map_err(|_| unavailable())?;
    let day_selector = Selector::parse("div.pub_date b").map_err(|_| unavailable())?;
    let month_selector = Selector::parse("div.pub_date span").map_err(|_| unavailable())?;

    let mut entries: Vec<ListingEntry> = Vec::new();
    for row in document.select(&row_selector) {
        if entries.len() >= MAX_ENTRIES {
            return Err(failed_contract(
                "listing exceeds the reviewed entry budget",
                file!(),
                line!(),
            ));
        }
        let listed_href = row
            .select(&anchor_selector)
            .next()
            .and_then(|anchor| anchor.value().attr("href"));
        if listed_href.is_some_and(|href| href.len() > MAX_HREF) {
            return Err(failed_contract(
                "listing href exceeds the reviewed byte budget",
                file!(),
                line!(),
            ));
        }
        let listed_href = listed_href
            .filter(|href| !href.is_empty())
            .map(str::to_owned);

        let title = row
            .select(&row_title_selector)
            .next()
            .map(|node| normalized_text(node.text()))
            .filter(|t| !t.is_empty() && t.len() <= MAX_TEXT);
        let title = match title {
            Some(title) => title,
            None => {
                return Err(failed_contract(
                    "listing row must contain a non-empty pub_info h3 title",
                    file!(),
                    line!(),
                ));
            }
        };

        let category_label = row
            .select(&label_selector)
            .next()
            .map(|node| normalized_text(node.text()))
            .filter(|t| !t.is_empty() && t.len() <= MAX_TEXT);

        let summary = row
            .select(&summary_selector)
            .next()
            .map(|node| normalized_text(node.text()))
            .filter(|t| !t.is_empty())
            .map(|t| t.chars().take(MAX_TEXT).collect());

        let date = row.select(&day_selector).next().and_then(|node| {
            let day = normalized_text(node.text());
            let month = row
                .select(&month_selector)
                .next()
                .map(|node| normalized_text(node.text()))?;
            parse_compact_date(&day, &month)
        });

        let (resolved_http_url, link_kind) = match listed_href.as_deref() {
            None => (None, "missing"),
            Some(raw) => match base.join(raw) {
                Ok(resolved) if is_http(&resolved) => (Some(resolved.to_string()), "http"),
                Ok(_) => (None, "non_http"),
                Err(_) => (None, "invalid"),
            },
        };

        entries.push(ListingEntry {
            source_order: entries.len() + 1,
            title,
            date,
            category_label,
            summary,
            listed_href,
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "listing must contain at least one div.tlist li row",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn parse_article(bytes: &[u8], url: &Url) -> Result<ArticleDocument, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(text);

    let title = document
        .select(&Selector::parse("h2").map_err(|_| unavailable())?)
        .next()
        .map(|node| normalized_text(node.text()))
        .filter(|t| !t.is_empty() && t.len() <= MAX_HREF);
    let title = match title {
        Some(title) => title,
        None => {
            return Err(failed_contract(
                "article must contain a non-empty h2 title",
                file!(),
                line!(),
            ));
        }
    };

    let published_at = document
        .select(&Selector::parse("div.cont-tit p").map_err(|_| unavailable())?)
        .next()
        .and_then(|node| {
            let text = normalized_text(node.text());
            let tokens: Vec<&str> = text.split_whitespace().collect();
            tokens
                .iter()
                .position(|token| token.contains("发布时间"))
                .and_then(|index| tokens.get(index + 1))
                .map(|token| token.to_string())
        })
        .and_then(|raw| parse_iso_date(&raw));

    let (paragraphs, attachment_hints, attachments_found) =
        article_body(document.root_element(), false)?;
    Ok(ArticleDocument {
        title,
        category: article_category_from_url(url),
        published_at,
        paragraphs,
        attachment_hints,
        attachments_found,
    })
}

fn article_body(
    document: ElementRef<'_>,
    has_other_source_text: bool,
) -> Result<(Vec<String>, Vec<Value>, bool), Error> {
    let paragraphs = article_paragraphs(document, has_other_source_text)?;
    let link_selector = Selector::parse("div.v_news_content a[href]").map_err(|_| unavailable())?;
    let mut attachment_hints: Vec<Value> = Vec::new();
    let mut attachments_found = false;
    for anchor in document.select(&link_selector) {
        if inert_element(anchor) {
            continue;
        }
        let Some(href) = anchor.value().attr("href") else {
            continue;
        };
        if !is_document_href(href) {
            continue;
        }
        attachments_found = true;
        if attachment_hints.len() < MAX_ATTACHMENT_HINTS {
            attachment_hints.push(json!({
                "href": href,
                "text": active_element_text(anchor),
            }));
        }
    }
    Ok((paragraphs, attachment_hints, attachments_found))
}

fn article_paragraphs(
    document: ElementRef<'_>,
    has_other_source_text: bool,
) -> Result<Vec<String>, Error> {
    let body_selector = Selector::parse("div.v_news_content p").map_err(|_| unavailable())?;
    let mut paragraphs: Vec<String> = Vec::new();
    for paragraph in document.select(&body_selector) {
        let text = element_text(paragraph);
        if text.is_empty() {
            continue;
        }
        if paragraphs.len() >= MAX_BODY_PARAGRAPHS {
            return Err(failed_contract(
                "article body exceeds the reviewed paragraph budget",
                file!(),
                line!(),
            ));
        }
        if text.len() > MAX_PARAGRAPH {
            return Err(failed_contract(
                "article paragraph exceeds the reviewed byte budget",
                file!(),
                line!(),
            ));
        }
        paragraphs.push(text);
    }
    if paragraphs.is_empty() && !has_other_source_text {
        return Err(failed_contract(
            "article must contain at least one v_news_content paragraph",
            file!(),
            line!(),
        ));
    }

    Ok(paragraphs)
}

fn declared_jsp_attachment_hints(scope: ElementRef<'_>) -> Result<(Vec<Value>, bool), Error> {
    let links = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let mut hints = Vec::new();
    let mut hints_truncated = false;
    for anchor in scope.select(&links) {
        if inert_element(anchor) {
            continue;
        }
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
    Ok((hints, hints_truncated))
}

fn article_category_from_url(url: &Url) -> Option<String> {
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.first() == Some(&"info") && segments.len() == 3 {
        Some(segments[1].to_string())
    } else {
        None
    }
}

fn is_document_href(href: &str) -> bool {
    let path = href.split(['?', '#']).next().unwrap_or(href);
    let lower = path.to_ascii_lowercase();
    DOCUMENT_EXTENSIONS
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn retrieval(response: &Response) -> Value {
    json!({
        "source_url": response.url,
        "fetched_at_unix_ms": response.fetched_at_unix_ms,
        "cache_status": response.cache_status,
        "response_body_sha256": response.sha256,
        "response_body_byte_length": response.body.len(),
        "revalidated_at_unix_ms": response.revalidated_at_unix_ms,
        "revalidation_status": response.revalidation_status,
        "http": {"status": response.status, "headers": response.headers},
    })
}

pub(crate) fn is_admitted_html(response: &Response) -> bool {
    response.status == 200
        && !response.body.is_empty()
        && response.body.len() <= MAX_HTML
        && response_content_type(response).is_some_and(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("text/html")
        })
}

fn response_content_type(response: &Response) -> Option<&str> {
    response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str())
}

pub(crate) fn is_safe_public_fallback(response: &Response) -> bool {
    if !is_admitted_html(response) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&response.body) else {
        return false;
    };
    let document = Html::parse_document(text);
    is_safe_public_fallback_document(response, &document)
}

fn is_safe_public_fallback_document(response: &Response, document: &Html) -> bool {
    let Ok(bases) = Selector::parse("base[href]") else {
        return false;
    };
    if document.select(&bases).any(|base| !inert_element(base)) {
        return false;
    }
    if response
        .headers
        .iter()
        .any(|(name, value)| crate::net::challenge_header(name.trim(), value.as_bytes()))
    {
        return false;
    }
    let Ok(elements) = Selector::parse("*") else {
        return false;
    };
    !document
        .select(&elements)
        .filter(|element| !inert_element(*element))
        .any(public_security_element)
}

/// Refuse an unsafe admitted listing outright.
///
/// A response that carries authentication, password, CSRF, CAPTCHA or
/// challenge semantics must never be retained in the public cache, not even
/// when its selectors happen to match a listing view. A safe admitted
/// response keeps its original bytes so it can still be repaired offline.
pub(crate) fn refuse_unsafe_listing(response: &Response, document: &Html) -> Result<(), Error> {
    if is_safe_public_fallback_document(response, document) {
        Ok(())
    } else {
        Err(unavailable())
    }
}

fn compact_security_token(value: &str) -> String {
    value
        .trim()
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

pub(crate) fn security_token(value: &str) -> bool {
    let token = compact_security_token(value);
    token == "password"
        || token == "passwd"
        || token == "passphrase"
        || token == "csrf"
        || token == "csrftoken"
        || token == "xsrf"
        || token == "xsrftoken"
        || token == "requestverificationtoken"
        || token == "verificationtoken"
        || token == "authenticitytoken"
        || token == "antiforgerytoken"
        || token == "captcha"
        || token == "recaptcha"
        || token == "hcaptcha"
        || token == "turnstile"
        || token == "challenge"
        || token == "challengeform"
        || token == "challengeplatform"
        || token == "auth"
        || token == "authpage"
        || token == "login"
        || token == "signin"
        || token == "signinform"
        || token == "authenticate"
        || token == "authentication"
        || token == "authform"
        || token == "oauth"
        || token == "authorize"
        || token == "cas"
        || token == "saml"
        || token == "sso"
        || token.contains("password")
        || token.contains("captcha")
        || token.contains("turnstile")
        || token.contains("csrf")
        || token.contains("xsrf")
        || token.contains("requestverificationtoken")
        || token.contains("challenge")
        || token.contains("login")
        || token.contains("signin")
        || token.contains("authentication")
        || token.contains("authorize")
        || token.contains("oauth")
        || token.starts_with("cfchl")
}

fn public_security_element(element: ElementRef<'_>) -> bool {
    let tag = element.value().name();
    element.value().attrs().any(|(name, value)| {
        let name = name.to_ascii_lowercase();
        if security_token(&name) {
            return true;
        }
        if tag == "input" && name == "type" && value.trim().eq_ignore_ascii_case("password") {
            return true;
        }
        if !matches!(
            name.as_str(),
            "action"
                | "aria-label"
                | "autocomplete"
                | "class"
                | "content"
                | "href"
                | "id"
                | "label"
                | "name"
                | "placeholder"
                | "src"
                | "title"
                | "type"
        ) && !name.starts_with("data-")
        {
            return false;
        }
        security_token(value)
    })
}

pub(crate) fn html_fallback(
    response: &Response,
    output_type: &str,
    college: &str,
    reason: &str,
) -> Value {
    json!({
        "schema_version": 1,
        "type": output_type,
        "result": "fallback",
        "college": college,
        "raw_html": STANDARD.encode(&response.body),
        "raw_html_sha256": response.sha256,
        "content_type": response_content_type(response).unwrap_or_default(),
        "body_byte_length": response.body.len(),
        "fallback_reason": reason,
        "retrieval": retrieval(response),
    })
}

fn entry_in_scope(
    entry: &ListingEntry,
    since: &Option<String>,
    until: &Option<String>,
    match_substring: &Option<String>,
) -> bool {
    if match_substring
        .as_deref()
        .is_some_and(|pattern| !pattern.is_empty() && !entry.title.contains(pattern))
    {
        return false;
    }
    if let Some(since) = since {
        match &entry.date {
            Some(date) if date.as_str() >= since.as_str() => {}
            _ => return false,
        }
    }
    if let Some(until) = until {
        match &entry.date {
            Some(date) if date.as_str() <= until.as_str() => {}
            _ => return false,
        }
    }
    true
}

fn normalize_listing(
    response: &Response,
    category: &str,
    page: u32,
    since: &Option<String>,
    until: &Option<String>,
    match_substring: &Option<String>,
) -> Result<Value, Error> {
    let url = Url::parse(&response.url).map_err(|_| unavailable())?;
    let document = parse_listing(&response.body, &url)?;
    let entries: Vec<&ListingEntry> = document
        .entries
        .iter()
        .filter(|entry| entry_in_scope(entry, since, until, match_substring))
        .collect();
    let listing_label = category_label(category).unwrap_or_default();
    Ok(json!({
        "schema_version": 1,
        "type": "announcements_list",
        "result": "listing_snapshot",
        "publisher": "北京航空航天大学",
        "listing_label": listing_label,
        "category": category,
        "page": page,
        "filters": {
            "since": since,
            "until": until,
            "match": match_substring,
        },
        "document_title": document.title,
        "entry_count": entries.len(),
        "entries": entries,
        "completeness": {
            "scope": format!("category_{category}_page_{page}"),
            "pagination": "explicit_page_selected_from_advertised_links; no automatic traversal",
            "date_filter_semantics": "entries without a parseable date are dropped when since or until is set",
            "historical_content": "use_buaa_archive",
        },
        "retrieval": retrieval(response),
    }))
}

fn normalize_article(response: &Response) -> Result<Value, Error> {
    let url = Url::parse(&response.url).map_err(|_| unavailable())?;
    let document = parse_article(&response.body, &url)?;
    Ok(article_output(response, document))
}

fn article_output(response: &Response, document: ArticleDocument) -> Value {
    let mut output = json!({
        "schema_version": 1,
        "type": "announcements_article",
        "result": "full_text",
        "publisher": "北京航空航天大学",
        "body_paragraph_count": document.paragraphs.len(),
        "attachments": {
            "found": document.attachments_found,
            "note": "attachment links are surfaced as hints and are never downloaded by this command",
        },
        "completeness": {
            "scope": "single_article_page",
            "body_source": "div.v_news_content p",
        },
        "retrieval": retrieval(response),
    });
    output["title"] = Value::String(document.title);
    output["category"] = document.category.map(Value::String).unwrap_or(Value::Null);
    output["published_at"] = document
        .published_at
        .map(Value::String)
        .unwrap_or(Value::Null);
    output["body_paragraphs"] =
        Value::Array(document.paragraphs.into_iter().map(Value::String).collect());
    output["attachments"]["hints"] = Value::Array(document.attachment_hints);
    output
}

fn article_content(document: ArticleDocument) -> Value {
    let mut output = json!({
        "schema_version": 1,
        "type": "announcements_article",
        "result": "full_text",
        "publisher": "北京航空航天大学",
        "body_paragraph_count": document.paragraphs.len(),
        "attachments": {
            "found": document.attachments_found,
            "note": "attachment links are surfaced as hints and are never downloaded by this command",
        },
        "completeness": {
            "scope": "single_article_page",
            "body_source": "div.v_news_content p",
        },
    });
    output["title"] = Value::String(document.title);
    output["category"] = document.category.map(Value::String).unwrap_or(Value::Null);
    output["published_at"] = document
        .published_at
        .map(Value::String)
        .unwrap_or(Value::Null);
    output["body_paragraphs"] =
        Value::Array(document.paragraphs.into_iter().map(Value::String).collect());
    output["attachments"]["hints"] = Value::Array(document.attachment_hints);
    output
}

struct SourceTables {
    values: Vec<Value>,
    row_count: usize,
    cell_count: usize,
    has_text: bool,
}

fn source_tables(body: ElementRef<'_>) -> Result<SourceTables, Error> {
    let tables = Selector::parse("table").map_err(|_| unavailable())?;
    let rows = Selector::parse("tr").map_err(|_| unavailable())?;
    let cells = Selector::parse(":scope > th, :scope > td").map_err(|_| unavailable())?;
    let captions = Selector::parse(":scope > caption").map_err(|_| unavailable())?;
    let mut result = SourceTables {
        values: Vec::new(),
        row_count: 0,
        cell_count: 0,
        has_text: false,
    };
    for table in body.select(&tables).filter(|node| !inert_element(*node)) {
        if result.values.len() == MAX_ENTRIES
            || table.select(&tables).any(|node| !inert_element(node))
            || table.descendants().any(|node| {
                matches!(node.value(), Node::Text(text) if !text.trim().is_empty())
                    && !node.ancestors().any(|ancestor| {
                        ancestor.value().as_element().is_some_and(|element| {
                            matches!(
                                element.name(),
                                "td" | "th"
                                    | "caption"
                                    | "script"
                                    | "style"
                                    | "template"
                                    | "noscript"
                            )
                        })
                    })
            })
        {
            return Err(failed_contract(
                "source tables require bounded flat rows and cell-owned text",
                file!(),
                line!(),
            ));
        }
        let mut caption_nodes = table.select(&captions).filter(|node| !inert_element(*node));
        let caption = caption_nodes.next().map(element_text);
        if caption_nodes.next().is_some()
            || caption
                .as_ref()
                .is_some_and(|text| text.len() > MAX_PARAGRAPH)
        {
            return Err(failed_contract(
                "table caption is ambiguous or over budget",
                file!(),
                line!(),
            ));
        }
        result.has_text |= caption.as_ref().is_some_and(|text| !text.is_empty());
        let mut source_rows = Vec::new();
        for row in table.select(&rows).filter(|node| !inert_element(*node)) {
            if result.row_count == MAX_BODY_PARAGRAPHS {
                return Err(failed_contract(
                    "table rows exceed the reviewed text budget",
                    file!(),
                    line!(),
                ));
            }
            let mut source_cells = Vec::new();
            let mut row_bytes = 0usize;
            for cell in row.select(&cells).filter(|node| !inert_element(*node)) {
                if source_cells.len() == MAX_ENTRIES {
                    return Err(failed_contract(
                        "table row exceeds the reviewed cell budget",
                        file!(),
                        line!(),
                    ));
                }
                let text = element_text(cell);
                row_bytes += text.len();
                if row_bytes > MAX_PARAGRAPH {
                    return Err(failed_contract(
                        "table row text exceeds the reviewed byte budget",
                        file!(),
                        line!(),
                    ));
                }
                result.has_text |= !text.is_empty();
                let mut value = json!({"header":cell.value().name() == "th"});
                value["text"] = Value::String(text);
                for span in ["rowspan", "colspan"] {
                    if let Some(raw) = cell.value().attr(span) {
                        if raw.len() > MAX_TEXT {
                            return Err(failed_contract(
                                "table span attribute exceeds the reviewed text budget",
                                file!(),
                                line!(),
                            ));
                        }
                        value[span] = Value::String(raw.to_owned());
                    }
                }
                source_cells.push(value);
            }
            result.row_count += 1;
            result.cell_count += source_cells.len();
            let mut value = json!({});
            value["cells"] = Value::Array(source_cells);
            source_rows.push(value);
        }
        let mut value = json!({"source_order":result.values.len() + 1});
        value["caption"] = caption.map(Value::String).unwrap_or(Value::Null);
        value["rows"] = Value::Array(source_rows);
        result.values.push(value);
    }
    Ok(result)
}

fn table_article_output(
    body: ElementRef<'_>,
    title: String,
    category: Option<String>,
    published_at: Option<String>,
    body_source: &str,
) -> Result<Value, Error> {
    let tables = source_tables(body)?;
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, tables.has_text)?;
    if paragraphs.len() + tables.row_count > MAX_BODY_PARAGRAPHS {
        return Err(failed_contract(
            "paragraphs and table rows exceed the reviewed text budget",
            file!(),
            line!(),
        ));
    }
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let has_images = body.select(&images).any(|image| !inert_element(image));
    let mut output = article_content(ArticleDocument {
        title,
        category,
        published_at,
        paragraphs,
        attachment_hints,
        attachments_found,
    });
    output["body_table_count"] = json!(tables.values.len());
    output["body_table_row_count"] = json!(tables.row_count);
    output["body_table_cell_count"] = json!(tables.cell_count);
    output["body_tables"] = Value::Array(tables.values);
    output["completeness"]["body_source"] = json!(body_source);
    output["completeness"]["table_representation"] = json!(
        "normalized source cell text and explicitly present span attributes; no inferred cells, span expansion or visual-layout reconstruction; paragraph-wrapped cells remain in body_paragraphs as well"
    );
    output["completeness"]["unextracted_table_count"] = json!(0);
    output["completeness"]["image_content_present"] = json!(has_images);
    if has_images || attachments_found {
        output["result"] = json!("partial_text");
        output["completeness"]["missing_nonparagraph_content"] =
            json!("image text and attachment contents are not reconstructed or downloaded");
    }
    Ok(output)
}

fn parse_list_query(input: Option<&str>) -> Result<ListQuery, Error> {
    match input {
        None => Ok(ListQuery::default()),
        Some(raw) if raw.trim().is_empty() => Ok(ListQuery::default()),
        Some(raw) => serde_json::from_str::<Option<ListQuery>>(raw)
            .map(Option::unwrap_or_default)
            .map_err(|_| invalid_list()),
    }
}

pub fn list(mode: CacheMode, input: Option<&str>) -> Result<Value, Error> {
    let query = parse_list_query(input)?;
    match query.college.as_deref() {
        Some("scse") => return scse::list(mode, &query),
        Some("ic") => return ic::list(mode, &query),
        Some("aviation") => return aviation::list(mode, &query),
        Some("beijing") => return beijing::list(mode, &query),
        Some("shenyuan") => return shenyuan::list(mode, &query),
        Some("h3i") => return h3i::list(mode, &query),
        Some("iai") => return iai::list(mode, &query),
        Some("zfai") => return zfai::list(mode, &query),
        Some("iiif") => return iiif::list(mode, &query),
        Some("math") => return math::list(mode, &query),
        Some("mse") => return mse::list(mode, &query),
        Some("sepe") => return sepe::list(mode, &query),
        Some("soft") => return soft::list(mode, &query),
        Some("transportation") => return transportation::list(mode, &query),
        Some("physics") => return physics::list(mode, &query),
        Some("sce") => return sce::list(mode, &query),
        Some("sse") => return sse::list(mode, &query),
        Some("sem") => return sem::list(mode, &query),
        Some("fld") => return fld::list(mode, &query),
        Some("me") => return me::list(mode, &query),
        Some("wrj") => return wrj::list(mode, &query),
        Some("yqgdxy") => return yqgdxy::list(mode, &query),
        Some("ase") => return ase::list(mode, &query),
        Some("hss") => return hss::list(mode, &query),
        Some("bme") => return bme::list(mode, &query),
        Some("ygy") => return ygy::list(mode, &query),
        Some("cst") => return cst::list(mode, &query),
        Some("dept3") => return dept3::list(mode, &query),
        Some("ee") => return ee::list(mode, &query),
        Some(_) => return Err(invalid_list()),
        None => {}
    }
    let category = query.category.as_deref().unwrap_or(DEFAULT_CATEGORY);
    let page = query.page.unwrap_or(1);
    if page < 1 {
        return Err(invalid_list());
    }
    let since = match query.since.as_deref() {
        Some(raw) => Some(parse_iso_date(raw).ok_or_else(invalid_list)?),
        None => None,
    };
    let until = match query.until.as_deref() {
        Some(raw) => Some(parse_iso_date(raw).ok_or_else(invalid_list)?),
        None => None,
    };
    let latest = latest_listing_url(category)?;
    // Page discovery is always cache-first; --refresh applies to the selected
    // page, not to the latest-listing snapshot used for ordinal resolution.
    let discovery_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let discovery_client = ArchiveClient::open_announcements(discovery_mode)?;
    let url = if page == 1 {
        latest
    } else {
        let prefix = format!("/{category}/");
        discovery_client.get(&latest, false, |response| {
            advertised_page_url(
                &response.body,
                &latest,
                page,
                "div.pb_sys_common span.p_no a[href]",
                |url| is_list_source_url(url.as_str()) && url.path().starts_with(&prefix),
            )
        })?
    };
    let client = discovery_client.with_cache_mode(mode);
    client.get(&url, false, move |response| {
        normalize_listing(response, category, page, &since, &until, &query.r#match)
    })
}

fn resolve_article_url(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|_| invalid_article())?;
    if url.scheme() != "https"
        || url.host_str() != Some("news.buaa.edu.cn")
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return Err(invalid_article());
    }
    let segments = url
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .unwrap_or_default();
    let valid = segments.len() == 3
        && segments[0] == "info"
        && !segments[1].is_empty()
        && segments[1].len() <= 10
        && segments[1].bytes().all(|b| b.is_ascii_digit())
        && segments[2].strip_suffix(".htm").is_some_and(|stem| {
            !stem.is_empty() && stem.len() <= 10 && stem.bytes().all(|b| b.is_ascii_digit())
        });
    if !valid {
        return Err(invalid_article());
    }
    Ok(url)
}

pub fn article(mode: CacheMode, input: &str) -> Result<Value, Error> {
    let query: ArticleQuery = serde_json::from_str(input).map_err(|_| invalid_article())?;
    let raw_url = query
        .url
        .as_deref()
        .filter(|url| !url.trim().is_empty())
        .ok_or_else(invalid_article)?;
    let parsed = Url::parse(raw_url).map_err(|_| invalid_article())?;
    match parsed.host_str() {
        Some("ic.buaa.edu.cn") => {
            return ic::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("aviation.buaa.edu.cn") => {
            return aviation::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("beijing.buaa.edu.cn") => {
            return beijing::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("hc.buaa.edu.cn") => {
            return shenyuan::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("h3i.buaa.edu.cn") => {
            return h3i::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("iai.buaa.edu.cn") => {
            return iai::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("zfai.buaa.edu.cn") => {
            return zfai::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("iiif.buaa.edu.cn") => {
            return iiif::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("math.buaa.edu.cn") => {
            return math::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("mse.buaa.edu.cn") => {
            return mse::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("sepe.buaa.edu.cn") => {
            return sepe::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("soft.buaa.edu.cn") => {
            return soft::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("transportation.buaa.edu.cn") => {
            return transportation::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("physics.buaa.edu.cn") => {
            return physics::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("sce.buaa.edu.cn") => {
            return sce::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("sse.buaa.edu.cn") => {
            return sse::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("sem.buaa.edu.cn") => {
            return sem::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("fld.buaa.edu.cn") => {
            return fld::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("www.me.buaa.edu.cn") => {
            return me::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("wrj.buaa.edu.cn") => {
            return wrj::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("yqgdxy.buaa.edu.cn") => {
            return yqgdxy::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("ase.buaa.edu.cn") => {
            return ase::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("www.hss.buaa.edu.cn") => {
            return hss::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("bme.buaa.edu.cn") => {
            return bme::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("ygy.buaa.edu.cn") => {
            return ygy::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("cst.buaa.edu.cn") => {
            return cst::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("dept3.buaa.edu.cn") => {
            return dept3::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        Some("www.ee.buaa.edu.cn") => {
            return ee::article(mode, raw_url, query.source_page.unwrap_or(1));
        }
        _ => {}
    }
    if query.source_page.is_some() {
        return Err(invalid_article());
    }
    if parsed.host_str() == Some("scse.buaa.edu.cn") {
        return scse::article(mode, raw_url);
    }
    let url = resolve_article_url(raw_url)?;
    let client = ArchiveClient::open_announcements(mode)?;
    client.get(&url, false, normalize_article)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentInput {
    article_url: String,
    #[serde(default, deserialize_with = "document_selector")]
    source_page: Option<u32>,
}

fn document_selector<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // A present null must not erase a selector and relax the input contract.
    <u32 as serde::Deserialize<'de>>::deserialize(deserializer).map(Some)
}

/// Retrieve one supported original explicitly declared by a retained article.
/// Does not infer a document from preview names or automatically follow hints.
pub fn document(mode: CacheMode, input: &str) -> Result<Value, Error> {
    if input.len() > 32 * 1024 {
        return Err(invalid_document());
    }
    let input: DocumentInput = serde_json::from_str(input).map_err(|_| invalid_document())?;
    let article = Url::parse(&input.article_url).map_err(|_| invalid_document())?;
    match article.host_str() {
        Some("sce.buaa.edu.cn") => sce::document(mode, &input),
        Some("scse.buaa.edu.cn") if input.source_page.is_none() => {
            scse::document(mode, &input.article_url)
        }
        _ => Err(invalid_document()),
    }
}

/// Fixed public college pages, not a unified college crawler or a verified
/// announcement parser. Never follows the returned hints.
pub fn college_surface(mode: CacheMode, college: &str, page: &str) -> Result<Value, Error> {
    if college == "ic" {
        return ic::surface(mode, page);
    }
    if college == "aviation" {
        return aviation::surface(mode, page);
    }
    if college == "beijing" {
        return beijing::surface(mode, page);
    }
    if college == "shenyuan" {
        return shenyuan::surface(mode, page);
    }
    if college == "h3i" {
        return h3i::surface(mode, page);
    }
    if college == "iai" {
        return iai::surface(mode, page);
    }
    if college == "zfai" {
        return zfai::surface(mode, page);
    }
    if college == "iiif" {
        return iiif::surface(mode, page);
    }
    if college == "math" {
        return math::surface(mode, page);
    }
    if college == "mse" {
        return mse::surface(mode, page);
    }
    if college == "rse" {
        return rse::surface(mode, page);
    }
    if college == "sepe" {
        return sepe::surface(mode, page);
    }
    if college == "soft" {
        return soft::surface(mode, page);
    }
    if college == "transportation" {
        return transportation::surface(mode, page);
    }
    if college == "physics" {
        return physics::surface(mode, page);
    }
    if college == "sse" {
        return sse::surface(mode, page);
    }
    if college == "sem" {
        return sem::surface(mode, page);
    }
    if college == "fld" {
        return fld::surface(mode, page);
    }
    if college == "me" {
        return me::surface(mode, page);
    }
    if college == "wrj" {
        return wrj::surface(mode, page);
    }
    if college == "yqgdxy" {
        return yqgdxy::surface(mode, page);
    }
    if college == "ase" {
        return ase::surface(mode, page);
    }
    if college == "hss" {
        return hss::surface(mode, page);
    }
    if college == "bme" {
        return bme::surface(mode, page);
    }
    if college == "ygy" {
        return ygy::surface(mode, page);
    }
    if college == "cst" {
        return cst::surface(mode, page);
    }
    if college == "dept3" {
        return dept3::surface(mode, page);
    }
    if college == "ee" {
        return ee::surface(mode, page);
    }
    if college == "sa" {
        return sa::surface(mode, page);
    }
    if college == "scse" {
        return scse::surface(mode, page);
    }
    if college == "sce" {
        return sce::surface(mode, page);
    }
    Err(Error::new("invalid_input", "unknown college surface page"))
}

fn college_html(response: &Response) -> Result<Html, Error> {
    if response.status != 200
        || response.body.is_empty()
        || response.body.len() > MAX_HTML
        || !response_content_type(response).is_some_and(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("text/html")
        })
    {
        return Err(unavailable());
    }
    college_text_document(std::str::from_utf8(&response.body).map_err(|_| unavailable())?)
}

/// Shared source-text admission for fetched UTF-8 and explicitly decoded archives.
pub(crate) fn college_text_document(text: &str) -> Result<Html, Error> {
    if text.is_empty() || text.len() > MAX_HTML {
        return Err(unavailable());
    }
    let document = Html::parse_document(text);
    let bases = Selector::parse("base[href]").map_err(|_| unavailable())?;
    if document.select(&bases).any(|base| {
        !base.ancestors().any(|node| {
            node.value()
                .as_element()
                .is_some_and(|node| matches!(node.name(), "template" | "noscript"))
        })
    }) {
        return Err(failed_contract(
            "college source has unreviewed HTML base semantics",
            file!(),
            line!(),
        ));
    }
    Ok(document)
}

/// Offline-bytes equivalent of college_html for supplied college documents.
fn college_document(bytes: &[u8]) -> Result<Html, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    college_text_document(std::str::from_utf8(bytes).map_err(|_| unavailable())?)
}

fn college_directory_attribution(
    directory: &Value,
    name: &str,
    listed_root: &str,
    resolved_root: &str,
) -> Result<Value, Error> {
    let mut members = directory["entries"]
        .as_array()
        .ok_or_else(unavailable)?
        .iter()
        .filter(|member| {
            member["name"] == name
                && member["resolved_http_url"] == resolved_root
                && member["hidden_in_source"] == false
        });
    let member = members.next().ok_or_else(unavailable)?;
    if members.next().is_some() || member["listed_href"] != listed_root {
        return Err(unavailable());
    }
    Ok(
        json!({"member":member,"directory_retrieval":directory["retrieval"],"reference_policy":"retained_authoritative_directory; refresh organizations list separately"}),
    )
}

#[cfg(feature = "directory-admission-proof")]
pub(crate) fn college_directory_attribution_for_proof(
    directory: &Value,
    name: &str,
    listed_root: &str,
    resolved_root: &str,
) -> Result<Value, Error> {
    college_directory_attribution(directory, name, listed_root, resolved_root)
}

fn describe_college_surface(
    response: &Response,
    college: &str,
    attribution: Value,
) -> Result<Value, Error> {
    if response.status != 200 || response.body.len() > MAX_HTML {
        return Err(unavailable());
    }
    let document = if matches!(
        college,
        "computer_science"
            | "ic"
            | "aviation"
            | "beijing"
            | "shenyuan"
            | "h3i"
            | "iai"
            | "zfai"
            | "iiif"
            | "mse"
            | "rse"
            | "sepe"
            | "soft"
            | "physics"
            | "sce"
            | "sse"
            | "fld"
            | "sem"
            | "me"
            | "wrj"
            | "yqgdxy"
            | "ase"
            | "hss"
            | "bme"
            | "ygy"
            | "cst"
            | "dept3"
            | "ee"
            | "sa"
    ) {
        college_html(response)?
    } else {
        Html::parse_document(std::str::from_utf8(&response.body).map_err(|_| unavailable())?)
    };
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(|node| normalized_text(node.text()))
        .filter(|title| !title.is_empty());
    if title.as_ref().is_some_and(|title| title.len() > MAX_TEXT) {
        return Err(unavailable());
    }
    let anchor_selector = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let base = Url::parse(&response.url).map_err(|_| unavailable())?;
    let mut hints = Vec::new();
    let mut hints_truncated = false;
    for node in document.select(&anchor_selector) {
        let raw = node.value().attr("href").unwrap_or_default();
        if raw.len() > MAX_HREF {
            continue;
        }
        let Ok(url) = base.join(raw) else {
            continue;
        };
        if !is_http(&url)
            || url.host_str() != base.host_str()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
        {
            continue;
        }
        let label = element_text(node);
        if label.is_empty() || label.len() > MAX_TEXT {
            continue;
        }
        if hints.len() == 64 {
            hints_truncated = true;
            break;
        }
        hints.push(json!({"path":url.path(),"listed_scheme":url.scheme(),"label":label}));
    }
    let mut output = json!({
        "schema_version":1,"type":"college_source_surface","result":"surface_snapshot",
        "college":college,
        "document_title":title,"same_host_path_hints":hints,"hints_truncated":hints_truncated,
        "completeness":{"scope":"single_explicit_public_page","announcement_adapter_verified":false,"links_followed":false,"publication_date":"unknown"},
        "retrieval":retrieval(response),
    });
    output["directory_attribution"] = attribution;
    Ok(output)
}

fn bind_college_board(
    client: &ArchiveClient,
    root: &str,
    board: &str,
    attribution: &mut Value,
) -> Result<(), Error> {
    let root = Url::parse(root).map_err(|_| unavailable())?;
    let board = Url::parse(board).map_err(|_| unavailable())?;
    let root_source = client.get(&root, false, |response| {
        let document = college_html(response)?;
        let links = Selector::parse("a[href]").map_err(|_| unavailable())?;
        if !document.select(&links).any(|node| {
            !element_text(node).is_empty()
                && node.value().attr("href").is_some_and(|raw| {
                    raw.len() <= MAX_HREF
                        && !raw.chars().any(char::is_control)
                        && !raw.contains(['%', '\\'])
                        && root.join(raw).is_ok_and(|url| url == board)
                })
        }) {
            return Err(Error::new(
                "unsupported",
                "retained college root does not declare the reviewed notice board",
            ));
        }
        Ok(retrieval(response))
    })?;
    attribution["root_retrieval"] = root_source;
    Ok(())
}

/// Source-ordered `nymain/notice-list` layout observed at Mse and Sepe.
fn parse_notice_list(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let titles = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&titles)
        .next()
        .map(element_text)
        .unwrap_or_default();
    if title.len() > MAX_TEXT {
        return Err(unavailable());
    }
    let views = Selector::parse("div.nymain > div.w16 > div.ny-right > div.notice-list > div > ul")
        .map_err(|_| unavailable())?;
    let mut views = document.select(&views).filter(|node| !inert_element(*node));
    let primary = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "college notices require one nymain/notice-list view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a").map_err(|_| unavailable())?;
    let headings = Selector::parse(":scope > h3").map_err(|_| unavailable())?;
    let summaries = Selector::parse(":scope > p").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > span").map_err(|_| unavailable())?;
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
                    "college notice row requires one direct a link",
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
                    "college notice row requires one direct h3 heading",
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
            || summary
                .as_ref()
                .is_some_and(|text| text.len() > MAX_PARAGRAPH)
        {
            return Err(unavailable());
        }
        let mut row_dates = anchor.select(&dates);
        let date = row_dates
            .next()
            .filter(|_| row_dates.next().is_none())
            .and_then(|node| {
                let raw = element_text(node);
                let mut bytes: [u8; 10] = raw.trim().as_bytes().try_into().ok()?;
                if bytes[4] != b'.' || bytes[7] != b'.' {
                    return None;
                }
                bytes[4] = b'-';
                bytes[7] = b'-';
                parse_iso_date(std::str::from_utf8(&bytes).ok()?)
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
            category_label: Some("公告公示".into()),
            summary,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "college notice view has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn is_dept3_article_history_source(raw: &str, url: &Url) -> bool {
    raw == url.as_str()
        && url.scheme() == "http"
        && url.host_str() == Some("dept3.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.path().starts_with("/info/1093/") || url.path().starts_with("/info/1014/"))
        && crate::net::dept3_path_allowed(url.path())
}

pub fn history(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_HTML.div_ceil(3) * 4 + MAX_HISTORY_METADATA {
        return Err(invalid_history());
    }
    let query: HistoryInput = serde_json::from_str(input).map_err(|_| invalid_history())?;
    let college_snapshot = scse::is_history_source(&query.provenance.source_url);
    let base = Url::parse(&query.provenance.source_url).map_err(|_| invalid_history())?;
    let kind = query.kind.as_ref().and_then(Option::as_deref);
    let dept3_article = kind == Some("article")
        && is_dept3_article_history_source(&query.provenance.source_url, &base);
    let math_root = kind.is_none_or(|kind| kind == "listing")
        && math::root_listing_source(&query.provenance.source_url);
    let legacy_listing_mse = (query.kind.is_none() || kind == Some("listing"))
        && mse::legacy_listing_source(&query.provenance.source_url);
    let legacy_article_mse = kind == Some("article")
        && mse::legacy_history_source(&query.provenance.source_url);
    let legacy_mse = legacy_listing_mse || legacy_article_mse;
    if (query.root_view.is_some()
        && !(math_root && matches!(query.root_view, Some(HistoryRootView::News))))
        || (!college_snapshot
            && !dept3_article
            && !math_root
            && !legacy_mse
            && !is_list_source_url(&query.provenance.source_url))
        || (legacy_mse && query.encoding != HistoryEncoding::Gb2312)
        || (!legacy_mse && query.encoding != HistoryEncoding::Utf8)
        || query.html.len() > MAX_HTML.div_ceil(3) * 4
    {
        return Err(invalid_history());
    }
    let timestamp = match &query.provenance.capture_timestamp {
        Some(value) => Some(
            capture_timestamp(value)
                .map(|time| time.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .map_err(|_| invalid_history()),
        )
        .transpose()?,
        None => None,
    };
    let bytes = STANDARD
        .decode(query.html.as_bytes())
        .map_err(|_| invalid_history())?;
    if bytes.len() > MAX_HTML {
        return Err(invalid_history());
    }
    let hash = format!("{:x}", Sha256::digest(&bytes));
    // Legacy Materials PHP originals are the only admitted non-UTF-8 sources:
    // explicit gb2312 on the exact literal HTTP root or call_board_detail URL.
    let legacy_text = if legacy_mse {
        Some(
            encoding_rs::GBK
                .decode_without_bom_handling_and_without_replacement(&bytes)
                .ok_or_else(invalid_history)?,
        )
    } else {
        None
    };
    if legacy_mse {
        let source = college_text_document(legacy_text.as_ref().ok_or_else(invalid_history)?)
            .map_err(|_| invalid_history())?;
        let mut output = if legacy_listing_mse {
            mse::parse_legacy_listing(&source, &base).map_err(|_| invalid_history())?
        } else {
            let mut output =
                mse::parse_legacy_article(&source).map_err(|_| invalid_history())?;
            output["type"] = json!("announcements_history");
            output["publisher"] = Value::Null;
            output["college"] = json!("mse");
            output["completeness"]["scope"] = json!("single_supplied_archive_article");
            output["completeness"]["freshness"] = json!("archived_bytes");
            output["completeness"]["source_layout"] = json!(
                "observed source-specific article header/body/table contract; historical era applicability is operator_asserted, not verified"
            );
            output
        };
        output["completeness"]["source_identity"] = json!(
            "operator_asserted source URL only; historical directory/root/list attribution and archive response headers are not verified"
        );
        let text = legacy_text.ok_or_else(invalid_history)?;
        output["interpretation"] = json!({
            "source_encoding":"gb2312",
            "encoding_status":"source_declared_only",
            "decoder":"WHATWG GBK (GB2312 web label), no replacement or BOM sniffing",
            "derived_utf8_sha256":format!("{:x}", Sha256::digest(text.as_bytes())),
            "derived_utf8_bytes":text.len(),
            "note":"decoded UTF-8 is derived content; retrieval binds the original supplied bytes",
        });
        output["provenance"] = json!({
            "status": "operator_asserted",
            "source_url": query.provenance.source_url,
            "capture_timestamp": timestamp,
            "asserted_by": query.provenance.asserted_by,
            "verification": "asserted_only; archive response headers were not supplied with the bytes",
        });
        output["retrieval"] = json!({
            "sha256": hash,
            "supplied_bytes": bytes.len(),
            "provenance_status": "operator_asserted",
        });
        return Ok(output);
    }
    if dept3_article {
        let document =
            Html::parse_document(std::str::from_utf8(&bytes).map_err(|_| invalid_history())?);
        let mut output = dept3::parse_article(&document).map_err(|_| invalid_history())?;
        output["type"] = json!("announcements_history");
        output["result"] = json!("article_snapshot");
        output["provenance"] = json!({
            "status": "operator_asserted",
            "source_url": query.provenance.source_url,
            "capture_timestamp": timestamp,
            "asserted_by": query.provenance.asserted_by,
        });
        output["retrieval"] = json!({
            "sha256": hash,
            "supplied_bytes": bytes.len(),
            "provenance_status": "operator_asserted",
        });
        return Ok(output);
    }
    if math_root {
        let source = college_document(&bytes).map_err(|_| invalid_history())?;
        let mut output = if matches!(query.root_view, Some(HistoryRootView::News)) {
            math::parse_root_news_listing(&source, &base)
        } else {
            math::parse_root_listing(&source, &base)
        }
        .map_err(|_| invalid_history())?;
        output["completeness"]["source_identity"] = json!(
            "operator_asserted source URL only; historical directory/root/list attribution and archive response headers are not verified"
        );
        output["provenance"] = json!({
            "status": "operator_asserted",
            "source_url": query.provenance.source_url,
            "capture_timestamp": timestamp,
            "asserted_by": query.provenance.asserted_by,
            "verification": "asserted_only; archive response headers were not supplied with the bytes",
        });
        output["retrieval"] = json!({
            "sha256": hash,
            "supplied_bytes": bytes.len(),
            "provenance_status": "operator_asserted",
        });
        return Ok(output);
    }
    let document = if college_snapshot {
        scse::parse_listing(&bytes, &base)
    } else {
        parse_listing(&bytes, &base)
    }
    .map_err(|_| invalid_history())?;
    Ok(json!({
        "schema_version": 1,
        "type": "announcements_history",
        "result": "listing_snapshot",
        "publisher": if college_snapshot {scse::PUBLISHER} else {"北京航空航天大学"},
        "college": if college_snapshot {Some("scse")} else {None},
        "listing_label": if college_snapshot {"公告公示（历史快照）"} else {"新闻中心（历史快照）"},
        "document_title": document.title,
        "entries": document.entries,
        "provenance": {
            "status": "operator_asserted",
            "source_url": query.provenance.source_url,
            "capture_timestamp": timestamp,
            "asserted_by": query.provenance.asserted_by,
            "verification": "asserted_only; archive response headers were not supplied with the bytes",
        },
        "completeness": {
            "scope": "single_supplied_archive_snapshot",
            "pagination": "not_applicable",
            "freshness": "archived_bytes",
        },
        "retrieval": {
            "sha256": hash,
            "supplied_bytes": bytes.len(),
            "provenance_status": "operator_asserted",
        },
    }))
}

fn capture_timestamp(value: &str) -> Result<NaiveDateTime, ()> {
    if value.len() != 14 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let part =
        |range: std::ops::Range<usize>| -> Result<u32, ()> { value[range].parse().map_err(|_| ()) };
    let year = part(0..4)? as i32;
    let date = NaiveDate::from_ymd_opt(year, part(4..6)?, part(6..8)?).ok_or(())?;
    date.and_hms_opt(part(8..10)?, part(10..12)?, part(12..14)?)
        .ok_or(())
}

pub fn schema() -> Value {
    let news_categories: Vec<Value> = CATEGORIES
        .iter()
        .map(|(slug, _)| json!(slug))
        .chain(std::iter::once(Value::Null))
        .collect();
    let mut output = json!({
        "document": {
            "input":{
                "type":"object","additionalProperties":false,"required":["article_url"],
                "properties":{
                    "article_url":{"type":"string","pattern":"^https://(?:scse|sce)\\.buaa\\.edu\\.cn/","description":"Reviewed HTTPS SCSE or Chemistry(sce) article declaring one active original PDF. Chemistry additionally binds its exact directory member, retained root and selected 学院新闻 listing, with canonical /info/1013 articles only."},
                    "attachment_ordinal":{"type":"integer","minimum":1,"maximum":MAX_ATTACHMENT_HINTS,"description":"Reserved for attachment-hint colleges; this slice rejects the field for both SCSE and Chemistry."},
                    "source_page":{"type":"integer","minimum":1,"maximum":u32::MAX,"description":"Chemistry source listing ordinal, default 1; later ordinals must be advertised by the retained latest listing. Omit for SCSE; explicit null is not accepted."}
                },
                "allOf":[
                    {"not":{"required":["attachment_ordinal"]}},
                    {"if":{"properties":{"article_url":{"pattern":"^https://scse\\.buaa\\.edu\\.cn/"}}},"then":{"not":{"required":["source_page"]}}},
                    {"if":{"properties":{"article_url":{"pattern":"^https://sce\\.buaa\\.edu\\.cn/"}}},"then":{"properties":{"article_url":{"pattern":"^https://sce[.]buaa[.]edu[.]cn/info/1013/[0-9]{1,10}[.]htm$"}}}}
                ]
            },
            "output":{"type":"object","description":"One source-declared original PDF as base64, byte length, SHA-256 and separate article/document retrieval facts. PDF header/EOF framing only; not a package/signature/safety certificate. Immutable byte cache; fresh PDF MIME admission precedes equality. The existing PDF missing-MIME allowance is retained. Discovery stays cache-first; document --refresh revalidates only the selected document. No OCR, text extraction, implicit article refresh, preview-image or other-attachment download."}
        },
        "college_source": {
            "input":{"description":"Fixed directory-bound college-source pages for scse, ic, aviation, beijing, shenyuan, h3i, iai, zfai, iiif, mse, rse, sepe, math, soft, transportation, physics, sce, sse, sem, fld, me, wrj, yqgdxy, ase, sa, hss, bme, ygy, cst, dept3 and ee. Select root or a reviewed notices board; aviation also supports public-notices. Rse and Sa support root only. ME and EE remain explicit transport blockers, not successful snapshots. Preserve literal directory URLs separately from deliberate HTTPS observations; bind boards through source declarations, follow no returned hints, and never infer missing routes or claim complete coverage."},
            "output":{"type":"object","description":"Source metadata with retrieval provenance or an explicit unsupported/transport error; safe admitted selector drift may carry original raw_html and fallback_reason. No authentication or challenge body is exposed."}
        },
        "list": {
            "input": {
                "type": ["object", "null"],
                "description": "Optional JSON object. Without college, select the university news center (default category tzgg). Selected college categories and page limits are constrained below. Preserve source row order, original titles/dates, separate excerpts, and exact directory/root/list binding. since/until are inclusive ISO dates; match is a title substring. Later pages require explicit source-advertised ordinals; no automatic crawl or guessed URLs. ME/EE listing requests remain explicit TLS blockers.",
                "additionalProperties": false,
                "properties": {
                    "college": {"enum": ["scse","ic","aviation","beijing","shenyuan","h3i","iai","zfai","iiif","mse","sepe","math","soft","transportation","physics","sce","sse","sem","fld","me","wrj","yqgdxy","ase","hss","bme","ygy","cst","dept3","ee",null]},
                    "category": {"type": ["string","null"]},
                    "page": {"type": ["integer","null"], "minimum": 1,"maximum":u32::MAX},
                    "since": {"type": ["string","null"], "pattern": "^\\d{4}-\\d{2}-\\d{2}$"},
                    "until": {"type": ["string","null"], "pattern": "^\\d{4}-\\d{2}-\\d{2}$"},
                    "match": {"type": ["string","null"]}
                },
                "allOf":[{"if":{"required":["college"],"properties":{"college":{"enum":["scse","beijing","mse","sepe","transportation"]}}},
                    "then":{"properties":{"category":{"enum":["gggs",null]}}},
                },
                    {"if":{"properties":{"college":{"type":"null"}}},"then":{"properties":{"category":{"enum":news_categories}}}},
                    {"if":{"required":["college"],"properties":{"college":{"const":"aviation"}}},"then":{"properties":{"category":{"enum":["tzgg","gkgs",null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"const":"h3i"}}},"then":{"properties":{"category":{"enum":["cpgg",null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"const":"zfai"}}},"then":{"properties":{"category":{"enum":["xxgg1",null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"const":"sce"}}},"then":{"properties":{"category":{"enum":["xyxw",null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"const":"fld"}}},"then":{"properties":{"category":{"enum":["zxtz",null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"const":"me"}}},"then":{"properties":{"category":{"enum":["xyxw","xszx",null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"const":"bme"}}},"then":{"properties":{"category":{"enum":["information",null]},"page":{"enum":[1,null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"const":"ygy"}}},"then":{"properties":{"category":{"enum":["yggg",null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"enum":["ic","shenyuan","iiif","iai","soft","physics","sem","sse","wrj","yqgdxy","ase","hss","cst","dept3","ee"]}}},"then":{"properties":{"category":{"enum":["tzgg",null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"const":"dept3"}}},"then":{"properties":{"page":{"enum":[1,null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"const":"math"}}},"then":{"properties":{"category":{"enum":["xygg",null]},"page":{"enum":[1,null]}}}},
                    {"if":{"required":["college"],"properties":{"college":{"enum":["h3i","iai"]}}},"then":{"properties":{"page":{"enum":[1,null]}}}}]
            },
            "output": {
                "type": "object",
                "description": "Selected-source listing snapshot with title/date/link entries, explicit college scope when selected, filters and retrieval provenance. No all-college coverage claim.",
            }
        },
        "article": {
            "input": {
                "type": "object",
                "description": "JSON object with a reviewed source article URL. Source-page-capable college readers require retained directory/root/list declarations before requesting an article. source_page defaults to 1; later ordinals must be source-advertised. H3i, IAI, Math, Dept3 and BME support page 1 only. SCSE and readers without source-page support reject a non-null selector. Keep original headings/publication facts distinct from excerpts and body dates; explicitly report unfetched image/table/viewer/attachment content. BME accepts only its exact reviewed ASP.NET query shape. ME/EE remain transport blockers. No arbitrary URL, credentials, custom port, fragment, automatic asset download or inferred route." ,
                "additionalProperties":false,"required":["url"],
                "me_article_contract":{"description":"ME article URLs are limited to HTTPS www.me.buaa.edu.cn/info/1126 or /info/1128 paths and must be declared by a discovered xyxw or xszx board; the adapter currently returns a TLS transport blocker before any request."},
                "properties": {"url": {"type": "string"},"source_page":{"type":["integer","null"],"minimum":1,"maximum":u32::MAX}},
                "allOf":[{"if":{"required":["source_page"],"properties":{"source_page":{"type":"integer"}}},"then":{"properties":{"url":{"pattern":"^https://((ic[.]buaa[.]edu[.]cn/info/1042|aviation[.]buaa[.]edu[.]cn/info/1061|beijing[.]buaa[.]edu[.]cn/info/1014|hc[.]buaa[.]edu[.]cn/info/1083|h3i[.]buaa[.]edu[.]cn/info/1141|iai[.]buaa[.]edu[.]cn/info/1024|zfai[.]buaa[.]edu[.]cn/info/1196|iiif[.]buaa[.]edu[.]cn/info/1186|mse[.]buaa[.]edu[.]cn/info/(1061|1058)|sepe[.]buaa[.]edu[.]cn/info/(1078|1093|1080)|math[.]buaa[.]edu[.]cn/info/1294|soft[.]buaa[.]edu[.]cn/info/1095|transportation[.]buaa[.]edu[.]cn/info/1058|physics[.]buaa[.]edu[.]cn/info/1252|sce[.]buaa[.]edu[.]cn/info/1013|sse[.]buaa[.]edu[.]cn/info/1078|sem[.]buaa[.]edu[.]cn/info/1024|fld[.]buaa[.]edu[.]cn/info/1011|www[.]me[.]buaa[.]edu[.]cn/info/(1126|1128)|wrj[.]buaa[.]edu[.]cn/info/1008|yqgdxy[.]buaa[.]edu[.]cn/info/1053|ase[.]buaa[.]edu[.]cn/info/(1052|1285)|www[.]hss[.]buaa[.]edu[.]cn/info/1103|ygy[.]buaa[.]edu[.]cn/info/1004|cst[.]buaa[.]edu[.]cn/info/1102|dept3[.]buaa[.]edu[.]cn/info/(1093|1014)|www[.]ee[.]buaa[.]edu[.]cn/info/1062)/[0-9]{1,10}[.]htm|bme[.]buaa[.]edu[.]cn/newsInfo[.]aspx[?]catID=13&subcatID=[0-9]{1,10}&curID=[0-9]{1,10})$"}}}},
                    {"if":{"required":["url"],"properties":{"url":{"pattern":"^https://(h3i|iai|math|dept3|bme)[.]buaa[.]edu[.]cn/"}}},"then":{"properties":{"source_page":{"enum":[1,null]}}}}]
            },
            "output": {
                "type": "object",
                "description": "Source paragraph text excluding code/fallback markup, publication facts and attachment hints. Text reads retain at most 1024 nonempty source paragraphs, at most 8 KiB each, from a document bounded to 2 MiB; overflow is an error, never silent truncation. Mse additionally returns separate source-ordered flat-table captions, rows and cells with explicitly present span attributes, without expanding spans or inventing grid positions. Mse counts paragraphs plus table rows under the same 1024 text-block budget, at most 256 tables/cells per row and 8 KiB of normalized text per row. Its ordinary table-only text is readable; empty/nontext bodies remain unavailable, unsupported nested/unowned table layouts fail closed, and unfetched image/attachment content stays partial. Sepe retains active source-declared JSP file hints within art-main, including siblings outside its text body; the observed55-paragraph original has three unfetched file hints and remains partial_text. Other college table/PDF/image limits remain source-specific. Preview/attachment bytes are never fetched and OCR is not performed.",
            }
        },
        "history": {
            "input": {
                "type": "object",
                "additionalProperties": false,
                "required": ["html", "provenance"],
                "properties": {
                    "kind": {"type":["string","null"],"description":"For legacy Materials, omit or use listing for the root, or use article for the PHP original; explicit null does not admit its root. Math root accepts an omitted/null kind or listing."},
                    "encoding": {"type":"string","enum":["utf8","gb2312"],"default":"utf8","description":"UTF-8 for existing sources. Explicit gb2312 is available only for the admitted offline Materials HTTP root listing or PHP article, with one matching source charset declaration. WHATWG GBK decoding uses no replacement or BOM sniffing; no guessing or fallback."},
                    "root_view": {"type":["string","null"],"enum":["news",null],"description":"Math literal HTTP root only: news selects its separate source-declared news view; omission/null selects notices. No recruitment or board-body admission."},
                    "html": {"type":"string","maxLength":MAX_HTML.div_ceil(3) * 4,"description":"Base64 original bytes, at most 2 MiB raw and 2 MiB decoded UTF-8 HTML. The serialized input allows an additional 8 KiB for metadata, not more source bytes."},
                    "provenance": {
                        "type":"object","additionalProperties":false,"required":["source_url"],
                        "properties": {
                            "source_url":{"type":"string","description":"Exact admitted source assertion, not fetch permission or verified attribution. UTF-8 sources are reviewed news-center/college listings, an explicitly typed Dept3 article, or literal http://math.buaa.edu.cn/ as a root listing. The GBK legacy leg admits only literal http://mse.buaa.edu.cn/ or http://mse.buaa.edu.cn:80/ as a listing and call_board_detail.php?call_board_id=<1-10 digits> as an article; no protocol, port, case or path alias."},
                            "capture_timestamp":{"type":["string","null"],"pattern":"^[0-9]{14}$","description":"Optional asserted YYYYMMDDhhmmss UTC capture; not publication time or verified archive attribution."},
                            "asserted_by":{"type":["string","null"],"description":"Optional operator assertion, not an authenticated identity."}
                        }
                    }
                },
                "allOf":[
                    {"if":{"required":["root_view"],"properties":{"root_view":{"type":"string"}}},"then":{"properties":{"provenance":{"properties":{"source_url":{"const":"http://math.buaa.edu.cn/"}}}}}},
                    {"if":{"required":["encoding"],"properties":{"encoding":{"const":"gb2312"}}},"then":{"properties":{"provenance":{"properties":{"source_url":{"pattern":"^http://mse[.]buaa[.]edu[.]cn(:80)?/(call_board_detail[.]php[?]call_board_id=[0-9]{1,10})?$"}}}}}},
                    {"if":{"properties":{"provenance":{"properties":{"source_url":{"pattern":"^http://mse[.]buaa[.]edu[.]cn(:80)?/call_board_detail[.]php[?]call_board_id=[0-9]{1,10}$"}}}}},"then":{"required":["kind","encoding"],"properties":{"kind":{"const":"article"},"encoding":{"const":"gb2312"}}}},
                    {"if":{"properties":{"provenance":{"properties":{"source_url":{"pattern":"^http://mse[.]buaa[.]edu[.]cn(:80)?/$"}}}}},"then":{"required":["encoding"],"properties":{"kind":{"const":"listing"},"encoding":{"const":"gb2312"}}}}
                ],
                "description": "Offline operator-asserted snapshot: base64 html, explicit encoding and provenance.source_url matching an admitted offline source contract (reviewed news-center/college listing, kind:'article' Dept3 article, literal http://math.buaa.edu.cn/ root with optional root_view 'news', or the GBK Materials legacy root/PHP article), optional capture_timestamp and asserted_by. Math defaults to the separate notices view; no protocol/port/path alias or board/article admission. No request or archive-attribution verification occurs.",
            },
            "output": {
                "type": "object",
                "description": "Parsed snapshot with asserted provenance and SHA-256 byte binding.",
            }
        },
    });

    output["article"]["output"]["properties"] = json!({
        "body_tables": {
            "type":"array","maxItems":MAX_ENTRIES,
            "description":"Mse source tables only; normalized text is derived from original HTML whose retrieval hash remains unchanged. Arrays preserve table/row/cell source order. Span attributes are DOM-decoded source strings and omitted when absent, not inferred defaults.",
            "items": {
                "type":"object","additionalProperties":false,"required":["source_order","caption","rows"],
                "properties": {
                    "source_order":{"type":"integer","minimum":1,"maximum":MAX_ENTRIES},
                    "caption":{"type":["string","null"],"maxLength":MAX_PARAGRAPH},
                    "rows":{"type":"array","maxItems":MAX_BODY_PARAGRAPHS,"items":{
                        "type":"object","additionalProperties":false,"required":["cells"],
                        "properties":{"cells":{"type":"array","maxItems":MAX_ENTRIES,"items":{
                            "type":"object","additionalProperties":false,"required":["header","text"],
                            "properties":{"header":{"type":"boolean","description":"True only for an original th cell."},"text":{"type":"string","maxLength":MAX_PARAGRAPH},"rowspan":{"type":"string","maxLength":MAX_TEXT},"colspan":{"type":"string","maxLength":MAX_TEXT}}
                        }}}
                    }}
                }
            }
        },
        "body_table_count":{"type":"integer","minimum":0,"maximum":MAX_ENTRIES},
        "body_table_row_count":{"type":"integer","minimum":0,"maximum":MAX_BODY_PARAGRAPHS},
        "body_table_cell_count":{"type":"integer","minimum":0,"maximum":MAX_BODY_PARAGRAPHS * MAX_ENTRIES}
    });

    output["history"]["output"]["properties"]["entries"] = json!({
        "type":"array","maxItems":MAX_ENTRIES,
        "items":{"type":"object","properties":{
            "source_order":{"type":"integer","minimum":1,"description":"Legacy Materials root uses active-anchor DOM order; not a school code."},
            "declared_popup_target":{"type":"string","maxLength":MAX_TEXT,"description":"Legacy root only: original unescaped relative PHP notice literal, separate from href:# and the normalized resolved URL."}
        }}
    });
    output["history"]["output"]["properties"]["body_text"] = json!({
        "type":"string","maxLength":MAX_PARAGRAPH,
        "description":"Legacy Materials body only: derived normalized text in active DOM order, not a fabricated paragraph or table cell."
    });
    output["history"]["output"]["properties"]["source_footer_text"] =
        json!({"type":"string","maxLength":MAX_TEXT});
    output["history"]["output"]["properties"]["source_footer_date"] = json!({
        "type":["string","null"],"description":"Standalone parseable footer date only. Unverified role, explicitly not published_at or archive capture time."
    });
    output["history"]["output"]["properties"]["interpretation"] = json!({
        "type":"object","additionalProperties":false,
        "required":["source_encoding","encoding_status","decoder","derived_utf8_sha256","derived_utf8_bytes","note"],
        "properties":{
            "source_encoding":{"const":"gb2312"},
            "encoding_status":{"const":"source_declared_only"},
            "decoder":{"type":"string"},
            "derived_utf8_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "derived_utf8_bytes":{"type":"integer","minimum":1,"maximum":MAX_HTML},
            "note":{"type":"string"}
        }
    });

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_identity_preserves_distinct_declared_literal_and_resolved_root() {
        let mut directory = json!({"entries":[{
            "name":"Fixture Reliability Institute",
            "listed_href":"http://rse.buaa.edu.cn",
            "resolved_http_url":"http://rse.buaa.edu.cn/",
            "hidden_in_source":false
        }]});
        let attribution = college_directory_attribution(
            &directory,
            "Fixture Reliability Institute",
            "http://rse.buaa.edu.cn",
            "http://rse.buaa.edu.cn/",
        )
        .unwrap();
        assert_eq!(
            attribution["member"]["listed_href"],
            "http://rse.buaa.edu.cn"
        );
        directory["entries"][0]["listed_href"] = "http://rse.buaa.edu.cn/".into();
        assert_eq!(
            college_directory_attribution(
                &directory,
                "Fixture Reliability Institute",
                "http://rse.buaa.edu.cn",
                "http://rse.buaa.edu.cn/",
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
    }

    fn listing_html() -> String {
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>通知公告-新闻网</title></head><body>
<div class="tlist"><ul>
<li><a href="info/1010/69802.htm"><div class="pub_date"><div><b>15</b><span>2026.09</span></div></div>
<div class="pub_info"><span>通知公告</span><h3>关于启动交换项目的通知</h3><p>第一段摘要</p></div></a></li>
<li><a href="info/1010/69801.htm"><div class="pub_date"><div><b>01</b><span>2026.09</span></div></div>
<div class="pub_info"><span>通知公告</span><h3>另一条通知</h3><p>第二段摘要</p></div></a></li>
<li><a href="info/1010/69700.htm"><div class="pub_date"><div><b>26</b><span>2026.08</span></div></div>
<div class="pub_info"><span>通知公告</span><h3>更早的通知</h3><p>第三段摘要</p></div></a></li>
</ul></div></body></html>"#
            .to_string()
    }

    fn base_url() -> Url {
        Url::parse("https://news.buaa.edu.cn/tzgg.htm").unwrap()
    }

    fn fallback_response(body: &[u8]) -> Response {
        Response {
            url: base_url().to_string(),
            status: 200,
            headers: std::collections::BTreeMap::from([(
                "content-type".to_string(),
                "text/html; charset=utf-8".to_string(),
            )]),
            body: body.to_vec(),
            sha256: format!("{:x}", Sha256::digest(body)),
            fetched_at_unix_ms: 1,
            cache_status: crate::net::CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn public_fallback_admission_uses_structural_security_attributes() {
        let ordinary = fallback_response(
            br#"<html><body><p>Public source bytes mention password, captcha and challenge as prose.</p></body></html>"#,
        );
        assert!(is_safe_public_fallback(&ordinary));

        let password = fallback_response(
            br#"<form action = "/session"><input class = "field" type = " password " name = "p&#97;ssword"></form>"#,
        );
        assert!(!is_safe_public_fallback(&password));

        let security_form = fallback_response(
            br#"<form id="sign-in"><input type="hidden" name="__RequestVerificationToken"><input name="g-recaptcha-response"></form>"#,
        );
        assert!(!is_safe_public_fallback(&security_form));

        let challenge = fallback_response(
            br#"<div id="cf-chl-widget"><iframe src="/cdn-cgi/challenge-platform"></iframe></div>"#,
        );
        assert!(!is_safe_public_fallback(&challenge));

        let active_base = fallback_response(
            br#"<base href="https://foreign.example/"><p>Public source bytes.</p>"#,
        );
        assert!(!is_safe_public_fallback(&active_base));

        let mut wrong_status = ordinary.clone();
        wrong_status.status = 403;
        assert!(!is_safe_public_fallback(&wrong_status));
        let mut wrong_mime = ordinary.clone();
        wrong_mime
            .headers
            .insert("content-type".into(), "application/json".into());
        assert!(!is_safe_public_fallback(&wrong_mime));
        let mut header_case = ordinary.clone();
        header_case.headers.remove("content-type");
        header_case
            .headers
            .insert("Content-Type".into(), "text/html".into());
        assert!(is_safe_public_fallback(&header_case));
        let oversized = fallback_response(&vec![b'x'; MAX_HTML + 1]);
        assert!(!is_safe_public_fallback(&oversized));

        let invalid_utf8 = fallback_response(&[b'<', b'p', b'>', 0xff, b'<', b'/', b'p', b'>']);
        assert!(!is_safe_public_fallback(&invalid_utf8));
    }

    #[test]
    fn parse_listing_reads_tlist_rows() {
        let document = parse_listing(listing_html().as_bytes(), &base_url()).unwrap();
        assert_eq!(document.title, "通知公告-新闻网");
        assert_eq!(document.entries.len(), 3);
        let first = &document.entries[0];
        assert_eq!(first.title, "关于启动交换项目的通知");
        assert_eq!(first.date.as_deref(), Some("2026-09-15"));
        assert_eq!(first.category_label.as_deref(), Some("通知公告"));
        assert_eq!(first.summary.as_deref(), Some("第一段摘要"));
        assert_eq!(first.link_kind, "http");
        assert_eq!(
            first.resolved_http_url.as_deref(),
            Some("https://news.buaa.edu.cn/info/1010/69802.htm")
        );
        assert_eq!(document.entries[2].date.as_deref(), Some("2026-08-26"));
    }

    #[test]
    fn review_regression_notice_list_without_nymain_ownership_is_refused() {
        let document = Html::parse_document(
            r#"<title>Unowned notices</title><div class="notice-list"><div><ul>
            <li><a href="../../info/1078/42.htm"><span>2026.10.10</span><h3>Unowned heading</h3><p>Unowned excerpt.</p></a></li>
            </ul></div></div>"#,
        );
        let base = Url::parse(crate::net::SSE_NOTICES_URL).unwrap();
        assert_eq!(
            parse_notice_list(&document, &base).unwrap_err().code,
            "unavailable"
        );
    }

    #[test]
    fn review_regression_notice_list_keeps_owned_rows_despite_unowned_sidebar() {
        let document = Html::parse_document(
            r#"<title>Source notices</title>
            <div class="notice-list"><div><ul><li><a href="../../info/1078/99.htm"><span>2026.10.11</span><h3>Unowned sidebar</h3><p>Unowned excerpt.</p></a></li></ul></div></div>
            <div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-list"><div><ul>
            <li><a href="../../info/1078/42.htm"><span>2026.10.10</span><h3>First source heading</h3><p>First source excerpt.</p></a></li>
            <li><a href="../../info/1078/41.htm"><span>2026.09.01</span><h3>Earlier source heading</h3><p>Earlier source excerpt.</p></a></li>
            </ul></div></div></div></div></div>"#,
        );
        let base = Url::parse(crate::net::SSE_NOTICES_URL).unwrap();
        let parsed = parse_notice_list(&document, &base).unwrap();
        let rows: Vec<_> = parsed
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.source_order,
                    entry.title.as_str(),
                    entry.date.as_deref(),
                    entry.summary.as_deref(),
                    entry.resolved_http_url.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                (
                    1,
                    "First source heading",
                    Some("2026-10-10"),
                    Some("First source excerpt."),
                    Some("https://sse.buaa.edu.cn/info/1078/42.htm")
                ),
                (
                    2,
                    "Earlier source heading",
                    Some("2026-09-01"),
                    Some("Earlier source excerpt."),
                    Some("https://sse.buaa.edu.cn/info/1078/41.htm")
                ),
            ]
        );
    }

    #[test]
    fn parse_listing_reports_missing_link_kind() {
        let html = r#"<!DOCTYPE html><html><head><title>t</title></head><body>
<div class="tlist"><ul><li><div class="pub_date"><div><b>01</b><span>2026.09</span></div></div>
<div class="pub_info"><span>通知公告</span><h3>无链接</h3><p>摘要</p></div></li></ul></div></body></html>"#;
        let document = parse_listing(html.as_bytes(), &base_url()).unwrap();
        assert_eq!(document.entries[0].link_kind, "missing");
        assert!(document.entries[0].listed_href.is_none());
    }

    #[test]
    fn parse_listing_rejects_row_without_title() {
        let html = r#"<!DOCTYPE html><html><head><title>t</title></head><body>
<div class="tlist"><ul><li><a href="info/1010/1.htm"><div class="pub_info"><span>通知公告</span><p>无标题</p></div></a></li></ul></div></body></html>"#;
        let err = parse_listing(html.as_bytes(), &base_url()).unwrap_err();
        assert_eq!(err.code, "unavailable");
        let src = err.source.expect("parse rejections must carry file/line");
        assert_eq!(src.file, "src/announcements.rs");
    }

    #[test]
    fn parse_listing_rejects_empty_list() {
        let html = r#"<!DOCTYPE html><html><head><title>t</title></head><body><div class="tlist"><ul></ul></div></body></html>"#;
        assert!(parse_listing(html.as_bytes(), &base_url()).is_err());
    }

    #[test]
    fn present_over_budget_links_are_rejected_not_reported_missing() {
        let body = listing_html().replace("info/1010/69802.htm", &"x".repeat(MAX_HREF + 1));
        assert_eq!(
            parse_listing(body.as_bytes(), &base_url())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn iso_filter_rejects_signed_years_instead_of_widening_query_scope() {
        assert_eq!(parse_iso_date("-001-01-01"), None);
    }

    #[test]
    fn compact_date_is_normalized_and_validated() {
        assert_eq!(
            parse_compact_date("15", "2026.09"),
            Some("2026-09-15".to_string())
        );
        assert_eq!(parse_compact_date("15", "2026.9"), None);
        assert_eq!(parse_compact_date("32", "2026.09"), None);
        assert_eq!(parse_compact_date("15", "2026.13"), None);
        assert_eq!(parse_compact_date("", "2026.09"), None);
    }

    #[test]
    fn iso_date_filter_is_validated() {
        assert_eq!(parse_iso_date("2026-09-15"), Some("2026-09-15".to_string()));
        assert_eq!(parse_iso_date("2026-13-01"), None);
        assert_eq!(parse_iso_date("2026-09-32"), None);
        assert_eq!(parse_iso_date("2026/09/15"), None);
    }

    #[test]
    fn pagination_uses_advertised_ordinals_not_filename_numbers() {
        let html = br#"<div class="pb_sys_common"><span class="p_no"><a href="tzgg/252.htm">2</a></span><span class="p_no"><a href="tzgg/1.htm">253</a></span><span class="p_no"><a href="tzgg/252.htm">2</a></span></div>"#;
        let base = latest_listing_url("tzgg").unwrap();
        let allowed =
            |url: &Url| is_list_source_url(url.as_str()) && url.path().starts_with("/tzgg/");
        assert_eq!(
            advertised_page_url(
                html,
                &base,
                2,
                "div.pb_sys_common span.p_no a[href]",
                allowed
            )
            .unwrap()
            .path(),
            "/tzgg/252.htm"
        );
        assert_eq!(
            advertised_page_url(
                html,
                &base,
                253,
                "div.pb_sys_common span.p_no a[href]",
                allowed
            )
            .unwrap()
            .path(),
            "/tzgg/1.htm"
        );
        assert_eq!(
            advertised_page_url(
                html,
                &base,
                6,
                "div.pb_sys_common span.p_no a[href]",
                allowed
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
        let foreign = br#"<div class="pb_sys_common"><span class="p_no"><a href="https://evil.example/tzgg/252.htm">2</a></span></div>"#;
        assert_eq!(
            advertised_page_url(
                foreign,
                &base,
                2,
                "div.pb_sys_common span.p_no a[href]",
                allowed
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
    }

    #[test]
    fn pagination_rejects_conflicting_ordinal_destinations() {
        let html = br#"<div class="pb_sys_common"><span class="p_no"><a href="tzgg/252.htm">2</a></span><span class="p_no"><a href="tzgg/251.htm">2</a></span></div>"#;
        let base = latest_listing_url("tzgg").unwrap();
        assert_eq!(
            advertised_page_url(
                html,
                &base,
                2,
                "div.pb_sys_common span.p_no a[href]",
                |url| is_list_source_url(url.as_str()) && url.path().starts_with("/tzgg/")
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
    }

    #[test]
    fn entry_scope_applies_filters() {
        let document = parse_listing(listing_html().as_bytes(), &base_url()).unwrap();
        let since = Some("2026-09-01".to_string());
        let none = None;
        let in_scope: Vec<&ListingEntry> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &none, &none))
            .collect();
        assert_eq!(in_scope.len(), 2);
        let match_sub = Some("交换".to_string());
        let matched: Vec<&ListingEntry> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &none, &none, &match_sub))
            .collect();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].title, "关于启动交换项目的通知");
    }

    #[test]
    fn parse_article_extracts_body_date_and_attachments() {
        let html = r#"<!DOCTYPE html><html><head><title>关于启动交换项目的通知</title></head><body>
<h2>关于启动交换项目的通知</h2>
<div class="cont-tit"><p>发布时间: 2026-09-15 / 点击数: 100</p></div>
<div class="v_news_content">
<p>第一段正文。</p>
<p>第二段正文。</p>
<p><a href="files/报名须知.pdf">报名须知</a></p>
</div></body></html>"#;
        let url = Url::parse("https://news.buaa.edu.cn/info/1010/69802.htm").unwrap();
        let document = parse_article(html.as_bytes(), &url).unwrap();
        assert_eq!(document.title, "关于启动交换项目的通知");
        assert_eq!(document.category.as_deref(), Some("1010"));
        assert_eq!(document.published_at.as_deref(), Some("2026-09-15"));
        assert_eq!(document.paragraphs.len(), 3);
        assert!(document.attachments_found);
        assert_eq!(document.attachment_hints.len(), 1);
        assert_eq!(document.attachment_hints[0]["href"], "files/报名须知.pdf");
    }

    #[test]
    fn parse_article_rejects_missing_body() {
        let html = r#"<!DOCTYPE html><html><head><title>t</title></head><body><h2>标题</h2><div class="v_news_content"></div></body></html>"#;
        let url = Url::parse("https://news.buaa.edu.cn/info/1010/1.htm").unwrap();
        assert!(parse_article(html.as_bytes(), &url).is_err());
    }

    #[test]
    fn executable_or_fallback_markup_is_not_article_text() {
        let html = r#"<title>Fixture</title><h2>Fixture title</h2><div class="v_news_content"><p><script>var embedded_document = ["not policy text"];</script><style>.hidden { display:none }</style><noscript>Enable JavaScript</noscript></p></div>"#;
        let url = Url::parse("https://news.buaa.edu.cn/info/1010/1.htm").unwrap();
        assert_eq!(
            parse_article(html.as_bytes(), &url).unwrap_err().code,
            "unavailable"
        );
    }

    #[test]
    fn inert_attachment_links_and_code_labels_are_not_source_hints() {
        let input = r#"<h2>Fixture article</h2><div class="v_news_content"><p>Source paragraph.</p><template><a href="/inactive.pdf">Inactive label</a></template><noscript><a href="/fallback.pdf">Fallback label</a></noscript><a href="/active.pdf">Visible label<script>private-code-marker</script><style>private-style-marker</style></a><a href="/image-only.pdf"><img src="/fixture.png"></a></div>"#;
        let url = Url::parse("https://news.buaa.edu.cn/info/1010/42.htm").unwrap();
        let response = Response {
            url: url.to_string(),
            status: 200,
            headers: std::collections::BTreeMap::new(),
            body: input.as_bytes().to_vec(),
            sha256: format!("{:x}", Sha256::digest(input.as_bytes())),
            fetched_at_unix_ms: 1,
            cache_status: crate::net::CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        };
        let output = article_output(&response, parse_article(&response.body, &url).unwrap());
        assert_eq!(
            output["attachments"]["hints"],
            json!([
                {"href":"/active.pdf","text":"Visible label"},
                {"href":"/image-only.pdf","text":""}
            ])
        );
        assert_eq!(output["attachments"]["found"], true);
        assert!(!output.to_string().contains("private-code-marker"));
        let inactive_only = r#"<h2>Fixture article</h2><div class="v_news_content"><p>Source paragraph.</p><template><a href="/inactive.pdf">Inactive label</a></template></div>"#;
        let document = parse_article(inactive_only.as_bytes(), &url).unwrap();
        assert!(!document.attachments_found);
        assert!(document.attachment_hints.is_empty());
    }

    #[test]
    fn resolve_article_url_rejects_foreign_paths() {
        assert!(resolve_article_url("https://news.buaa.edu.cn/info/1010/69802.htm").is_ok());
        assert!(resolve_article_url("https://evil.example/info/1010/1.htm").is_err());
        assert!(resolve_article_url("https://news.buaa.edu.cn/info/1010/1.htm?x=1").is_err());
        assert!(resolve_article_url("https://news.buaa.edu.cn/xwzx.htm").is_err());
        assert!(resolve_article_url("https://news.buaa.edu.cn/info/abc/1.htm").is_err());
    }

    #[test]
    fn history_requires_operator_asserted_provenance() {
        let html = listing_html();
        let encoded = STANDARD.encode(html.as_bytes());
        let input = json!({
            "html": encoded,
            "provenance": {
                "source_url": "https://news.buaa.edu.cn/tzgg.htm",
                "capture_timestamp": "20260920120000"
            }
        })
        .to_string();
        let output = history(&input).unwrap();
        assert_eq!(output["provenance"]["status"], "operator_asserted");
        assert_eq!(
            output["provenance"]["source_url"],
            "https://news.buaa.edu.cn/tzgg.htm"
        );
        assert_eq!(
            output["provenance"]["capture_timestamp"],
            "2026-09-20T12:00:00Z"
        );
        assert_eq!(output["entries"].as_array().unwrap().len(), 3);
        assert_eq!(output["retrieval"]["sha256"].as_str().unwrap().len(), 64);

        let foreign = json!({
            "html": encoded,
            "provenance": {"source_url": "https://www.buaa.edu.cn/xwzx.htm"}
        })
        .to_string();
        let err = history(&foreign).unwrap_err();
        assert_eq!(err.code, "invalid_input");

        let article_url = json!({
            "html": encoded,
            "provenance": {"source_url": "https://news.buaa.edu.cn/info/1010/1.htm"}
        })
        .to_string();
        assert!(history(&article_url).is_err());
    }

    #[test]
    fn college_history_keeps_the_notice_board_identity() {
        let body = "<title>Fixture notices</title><div class=\"ej_nr\"><div class=\"list\"><ul><li><p class=\"bt\">Synthetic notice</p></li></ul></div></div>";
        let input = json!({"html":STANDARD.encode(body),"provenance":{"source_url":"http://scse.buaa.edu.cn/xwgg/gggs.htm"}});
        let out = history(&input.to_string()).unwrap();
        assert_eq!(out["college"], "scse");
        assert_eq!(out["listing_label"], "公告公示（历史快照）");
        assert_eq!(
            out["provenance"]["source_url"],
            "http://scse.buaa.edu.cn/xwgg/gggs.htm"
        );
    }

    #[test]
    fn history_accepts_paged_sources_without_relaxing_provenance_scope() {
        let mut input = json!({
            "html": STANDARD.encode(listing_html().replace("href=\"info/", "href=\"../info/")),
            "provenance": {
                "source_url": "https://news.buaa.edu.cn/tzgg/252.htm",
                "asserted_by": "fixture-operator"
            }
        });
        let result = history(&input.to_string()).unwrap();
        assert_eq!(
            result["provenance"]["source_url"],
            input["provenance"]["source_url"]
        );
        assert_eq!(result["provenance"]["asserted_by"], "fixture-operator");
        assert_eq!(result["provenance"]["status"], "operator_asserted");
        assert_eq!(
            result["entries"][0]["resolved_http_url"],
            "https://news.buaa.edu.cn/info/1010/69802.htm"
        );
        for source in [
            "https://news.buaa.edu.cn/tzgg/.htm",
            "https://news.buaa.edu.cn/tzgg/2.52.htm",
            "https://news.buaa.edu.cn/tzgg/252.htm#fragment",
            "https://operator:secret@news.buaa.edu.cn/tzgg.htm",
            "https://news.buaa.edu.cn:8443/tzgg.htm",
        ] {
            input["provenance"]["source_url"] = json!(source);
            assert_eq!(
                history(&input.to_string()).unwrap_err().code,
                "invalid_input"
            );
        }
    }

    use std::sync::atomic::{AtomicU64, Ordering};

    static OFFLINE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn document_null_selector_cannot_disappear_from_input_contract() {
        for field in ["attachment_ordinal", "source_page"] {
            let input = format!(
                r#"{{"article_url":"https://scse.buaa.edu.cn/info/1099/42.htm","{field}":null}}"#
            );
            assert!(
                serde_json::from_str::<DocumentInput>(&input).is_err(),
                "null {field} must stay a contract violation"
            );
        }
        let input = r#"{"article_url":"https://sce.buaa.edu.cn/info/1013/42.htm","source_page":null}"#;
        assert!(serde_json::from_str::<DocumentInput>(input).is_err());
    }

    #[test]
    fn document_dispatch_rejects_unsupported_hosts_and_selectors_before_reads() {
        for raw in [
            r#"{"article_url":"https://math.buaa.edu.cn/info/1294/42.htm"}"#,
            r#"{"article_url":"https://sepe.buaa.edu.cn/info/1078/42.htm"}"#,
            r#"{"article_url":"https://scse.buaa.edu.cn/info/1099/42.htm","source_page":1}"#,
            r#"{"article_url":"https://scse.buaa.edu.cn/info/1099/42.htm","attachment_ordinal":1}"#,
            r#"{"article_url":"https://sce.buaa.edu.cn/info/1013/42.htm","attachment_ordinal":1}"#,
            r#"{"article_url":"https://sce.buaa.edu.cn/info/1013/42.htm","source_page":0}"#,
            r#"{"article_url":"https://scse.buaa.edu.cn/info/1099/42.htm","unknown":1}"#,
            r#"not json"#,
            r#"{"article_url":42}"#,
        ] {
            assert_eq!(
                document(CacheMode::Offline, raw).unwrap_err().code,
                "invalid_input",
                "input {raw}"
            );
        }
    }

    /// Hermetic offline contract: an empty cache directory must yield
    /// `offline_miss` for both listing and article URLs, without touching the
    /// operator's real cache, governor, or network.
    #[test]
    fn offline_lookup_with_empty_cache_reports_unavailable() {
        let root = std::env::temp_dir().join(format!(
            "buaa-announcements-offline-{}-{}",
            std::process::id(),
            OFFLINE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let client =
            ArchiveClient::open_announcements_offline_for_test(&root.join("cache")).unwrap();
        let listing = client
            .get(&latest_listing_url("tzgg").unwrap(), false, |_| Ok(()))
            .unwrap_err();
        assert_eq!(listing.code, "offline_miss");
        let article = client
            .get(
                &resolve_article_url("https://news.buaa.edu.cn/info/1010/1.htm").unwrap(),
                false,
                |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(article.code, "offline_miss");
        assert!(!root.join("cache/governor").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn history_legacy_html(body: &str) -> String {
        format!(
            r#"<html><head><meta http-equiv="Content-Type" content="text/html; charset=gb2312"><title>Not the article heading</title></head><body><table><tr><td><div>Banner, not prose</div></td></tr><tr><td><div><table class="underline"><tr><td class="p20blue"><div>Synthetic <strong>notice</strong></div></td></tr></table><table><tr><td class="p20blue"><table><tr><td></td></tr></table>{body}</td></tr></table></div></td></tr><tr><td><div>2004-03-23</div></td></tr></table></body></html>"#
        )
    }

    fn history_legacy_input(html: &str) -> Value {
        let (bytes, _, had_errors) = encoding_rs::GBK.encode(html);
        assert!(
            !had_errors,
            "synthetic legacy fixture must encode without replacement"
        );
        json!({"kind":"article","encoding":"gb2312","html":STANDARD.encode(bytes),
            "provenance":{"source_url":"http://mse.buaa.edu.cn:80/call_board_detail.php?call_board_id=42",
                "capture_timestamp":"20040409111518"}})
    }

    const LEGACY_ROOT_HELPER: &str = "function MM_openBrWindow(target, name, features) { // source helper\nwindow.open(target, name, features); }";

    fn history_legacy_root_input(script: &str, anchors: &str) -> Value {
        let html = format!(
            r#"<html><head><meta charset="gb2312"><title>Synthetic legacy home</title><script>{script}</script></head><body>{anchors}</body></html>"#
        );
        let mut input = history_legacy_input(&html);
        input["kind"] = json!("listing");
        input["provenance"]["source_url"] = json!("http://mse.buaa.edu.cn:80/");
        input["provenance"]["capture_timestamp"] = json!("20040326165604");
        input
    }

    fn history_legacy_root_anchor(target: &str, title: &str) -> String {
        format!(
            r##"<a href="#" onclick="MM_openBrWindow('{target}', '', 'width=400')">{title}</a>"##
        )
    }

    #[test]
    fn history_legacy_root_keeps_all_notice_declarations_not_other_popups() {
        let script = format!(
            "function reload(init) {{ if (init) {{ window.size = 1; }} }} reload(true);\n{LEGACY_ROOT_HELPER}"
        );
        let anchors = format!(
            "<a href='/'>Navigation</a>{}<template>{}</template>{}{}{}",
            history_legacy_root_anchor("other_page.php", "<img src='not-a-title.png'>"),
            history_legacy_root_anchor("call_board_detail.php?call_board_id=99", "Inert"),
            history_legacy_root_anchor(
                "call_board_detail.php?call_board_id=42",
                "前文<em>中间</em>后文"
            ),
            history_legacy_root_anchor(
                "call_board_detail.php?call_board_id=7",
                "Second 2004-05-15"
            ),
            history_legacy_root_anchor("call_board_detail.php?call_board_id=1234567890", "Third")
        );
        let output = history(&history_legacy_root_input(&script, &anchors).to_string()).unwrap();
        let entries = output["entries"].as_array().unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry["source_order"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry["title"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["前文 中间 后文", "Second 2004-05-15", "Third"]
        );
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry["declared_popup_target"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "call_board_detail.php?call_board_id=42",
                "call_board_detail.php?call_board_id=7",
                "call_board_detail.php?call_board_id=1234567890"
            ]
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry["listed_href"] == "#" && entry["date"].is_null())
        );
        assert_eq!(
            entries[0]["resolved_http_url"],
            "http://mse.buaa.edu.cn/call_board_detail.php?call_board_id=42"
        );
        assert!(output["publisher"].is_null());
        assert_eq!(
            output["provenance"]["capture_timestamp"],
            "2004-03-26T16:56:04Z"
        );
        assert_eq!(output["completeness"]["complete_history"], false);
    }

    #[test]
    fn history_legacy_root_rejects_ambiguous_nested_and_changed_bindings() {
        let anchor = history_legacy_root_anchor("call_board_detail.php?call_board_id=42", "Notice");
        for script in [
            format!("{LEGACY_ROOT_HELPER}\n{LEGACY_ROOT_HELPER}"),
            format!("function outer() {{ {LEGACY_ROOT_HELPER} }}"),
            format!("/* {LEGACY_ROOT_HELPER} */"),
            format!("{LEGACY_ROOT_HELPER}; MM_openBrWindow = another;"),
            LEGACY_ROOT_HELPER.replace(
                "window.open(target, name, features)",
                "window.open(name, target, features)",
            ),
            LEGACY_ROOT_HELPER.replace("target", "window"),
        ] {
            assert_eq!(
                history(&history_legacy_root_input(&script, &anchor).to_string())
                    .unwrap_err()
                    .code,
                "invalid_input"
            );
        }
    }

    #[test]
    fn history_legacy_root_requires_an_active_inline_classic_helper() {
        let anchor = history_legacy_root_anchor("call_board_detail.php?call_board_id=42", "Notice");
        let input = history_legacy_root_input(LEGACY_ROOT_HELPER, &anchor);
        let original = STANDARD.decode(input["html"].as_str().unwrap()).unwrap();
        let html = encoding_rs::GBK
            .decode_without_bom_handling_and_without_replacement(&original)
            .unwrap();
        for rejected in [
            html.replace("<script>", "<script type='module'>"),
            html.replace("<script>", "<script src='unfetched.js'>"),
            html.replace("<script>", "<script type='application/json'>"),
            html.replace("<script>", "<template><script>")
                .replace("</script>", "</script></template>"),
        ] {
            let mut rejected = history_legacy_input(&rejected);
            rejected["kind"] = json!("listing");
            rejected["provenance"]["source_url"] = json!("http://mse.buaa.edu.cn/");
            assert_eq!(
                history(&rejected.to_string()).unwrap_err().code,
                "invalid_input"
            );
        }
    }

    #[test]
    fn history_legacy_root_refuses_dynamic_escaped_and_foreign_notice_targets() {
        for target in [
            "call_board_detail.php?call_board_id=42&extra=1",
            "call_board_detail.php?call_board_id=%34%32",
            "call_board_detail.php?call_board_id=42#fragment",
            "http://foreign.example/call_board_detail.php?call_board_id=42",
            "/call_board_detail.php?call_board_id=42",
            "call_board_detail.php?call_board_id=\\x34\\x32",
        ] {
            let input = history_legacy_root_input(
                LEGACY_ROOT_HELPER,
                &history_legacy_root_anchor(target, "Notice"),
            );
            assert_eq!(
                history(&input.to_string()).unwrap_err().code,
                "invalid_input"
            );
        }
        let anchor = history_legacy_root_anchor("call_board_detail.php?call_board_id=42", "Notice")
            .replace(
                "'call_board_detail.php?call_board_id=42'",
                "'call_board_detail.php?call_board_id=' + selectedId",
            );
        assert_eq!(
            history(&history_legacy_root_input(LEGACY_ROOT_HELPER, &anchor).to_string())
                .unwrap_err()
                .code,
            "invalid_input"
        );
    }

    #[test]
    fn history_legacy_root_requires_exact_offline_root_and_explicit_encoding() {
        let mut input = history_legacy_root_input(
            LEGACY_ROOT_HELPER,
            &history_legacy_root_anchor("call_board_detail.php?call_board_id=42", "Notice"),
        );
        for source in [
            "https://mse.buaa.edu.cn/",
            "http://mse.buaa.edu.cn:81/",
            "http://mse.buaa.edu.cn/?query=1",
            "http://mse.buaa.edu.cn/xwdt/gggs.htm",
            "http://mse.buaa.edu.cn",
            "http://MSE.buaa.edu.cn/",
        ] {
            input["provenance"]["source_url"] = json!(source);
            assert_eq!(
                history(&input.to_string()).unwrap_err().code,
                "invalid_input"
            );
        }
        input["provenance"]["source_url"] = json!("http://mse.buaa.edu.cn/");
        input.as_object_mut().unwrap().remove("encoding");
        assert_eq!(
            history(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
        input["encoding"] = json!("gb2312");
        input["kind"] = json!("article");
        assert_eq!(
            history(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
        input["kind"] = Value::Null;
        assert_eq!(
            history(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
        input["kind"] = json!("other");
        assert_eq!(
            history(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
        input.as_object_mut().unwrap().remove("kind");
        assert_eq!(
            history(&input.to_string()).unwrap()["entries"][0]["title"],
            "Notice"
        );
    }

    #[test]
    fn history_legacy_root_rejects_missing_titles_and_entry_overflow() {
        let anchor = history_legacy_root_anchor("call_board_detail.php?call_board_id=42", "Notice");
        let boundary = history_legacy_root_input(LEGACY_ROOT_HELPER, &anchor.repeat(MAX_ENTRIES));
        assert_eq!(
            history(&boundary.to_string()).unwrap()["entries"]
                .as_array()
                .unwrap()
                .len(),
            MAX_ENTRIES
        );
        for anchors in [
            anchor.repeat(MAX_ENTRIES + 1),
            history_legacy_root_anchor(
                "call_board_detail.php?call_board_id=42",
                "<img src='not-transcribed.png'>",
            ),
            history_legacy_root_anchor(
                "call_board_detail.php?call_board_id=42",
                &"x".repeat(MAX_TEXT + 1),
            ),
        ] {
            assert_eq!(
                history(&history_legacy_root_input(LEGACY_ROOT_HELPER, &anchors).to_string())
                    .unwrap_err()
                    .code,
                "invalid_input"
            );
        }
    }

    #[test]
    fn history_legacy_mse_separates_original_decoding_and_date_roles() {
        let html =
            history_legacy_html("前文<em>中间</em>后文 2004-05-15.<script>not prose</script>");
        let input = history_legacy_input(&html);
        let raw = STANDARD.decode(input["html"].as_str().unwrap()).unwrap();
        let output = history(&input.to_string()).unwrap();
        assert_eq!(output["title"], "Synthetic notice");
        assert!(output["publisher"].is_null());
        assert_eq!(output["body_text"], "前文 中间 后文 2004-05-15.");
        assert_eq!(output["source_footer_text"], "2004-03-23");
        assert_eq!(output["source_footer_date"], "2004-03-23");
        assert!(output["published_at"].is_null());
        assert_eq!(
            output["provenance"]["capture_timestamp"],
            "2004-04-09T11:15:18Z"
        );
        assert_eq!(
            output["provenance"]["source_url"],
            "http://mse.buaa.edu.cn:80/call_board_detail.php?call_board_id=42"
        );
        assert_eq!(
            output["retrieval"],
            json!({
            "sha256":format!("{:x}", Sha256::digest(&raw)),
            "supplied_bytes":raw.len(),"provenance_status":"operator_asserted"})
        );
        assert_eq!(
            output["interpretation"]["derived_utf8_sha256"],
            format!("{:x}", Sha256::digest(html.as_bytes()))
        );
        assert_eq!(output["interpretation"]["derived_utf8_bytes"], html.len());
        assert_ne!(
            output["retrieval"]["sha256"],
            output["interpretation"]["derived_utf8_sha256"]
        );
        assert_eq!(output["body_paragraphs"], json!([]));
        assert!(output.get("body_tables").is_none());
        assert!(output.get("directory_attribution").is_none());
        assert!(output.get("source_listing").is_none());
        let unknown =
            history(&history_legacy_input(&html.replace("2004-03-23", "2004-02-30")).to_string())
                .unwrap();
        assert_eq!(unknown["source_footer_text"], "2004-02-30");
        assert!(unknown["source_footer_date"].is_null());
        assert!(unknown["published_at"].is_null());
    }

    #[test]
    fn history_legacy_mse_requires_explicit_encoding_and_exact_offline_uri() {
        let mut input = history_legacy_input(&history_legacy_html("Source body."));
        input["provenance"]["source_url"] =
            json!("http://mse.buaa.edu.cn/call_board_detail.php?call_board_id=1234567890");
        assert_eq!(
            history(&input.to_string()).unwrap()["body_text"],
            "Source body."
        );
        for source in [
            "https://mse.buaa.edu.cn/call_board_detail.php?call_board_id=42",
            "http://operator:fixture@mse.buaa.edu.cn/call_board_detail.php?call_board_id=42",
            "http://mse.buaa.edu.cn:81/call_board_detail.php?call_board_id=42",
            "http://MSE.buaa.edu.cn/call_board_detail.php?call_board_id=42",
            "http://mse.buaa.edu.cn/call_board_detail.php?call_board_id=42&other=1",
            "http://mse.buaa.edu.cn/call_board_detail.php?call_board_id=42&call_board_id=43",
            "http://mse.buaa.edu.cn/call_board_detail.php?call_board_id=%34%32",
            "http://mse.buaa.edu.cn/call_board_detail.php?call_board_id=12345678901",
            "http://mse.buaa.edu.cn/call_board_detail.php?call_board_id=42#fragment",
            "http://mse.buaa.edu.cn/other.php?call_board_id=42",
        ] {
            input["provenance"]["source_url"] = json!(source);
            assert_eq!(
                history(&input.to_string()).unwrap_err().code,
                "invalid_input"
            );
        }
        input["provenance"]["source_url"] =
            json!("http://mse.buaa.edu.cn:80/call_board_detail.php?call_board_id=42");
        input.as_object_mut().unwrap().remove("encoding");
        assert_eq!(
            history(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
        input["encoding"] = json!("gb2312");
        input.as_object_mut().unwrap().remove("kind");
        assert_eq!(
            history(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
    }

    #[test]
    fn history_legacy_mse_rejects_malformed_or_unmatched_charset() {
        let html = history_legacy_html("合成内容");
        for rejected in [
            html.replace("charset=gb2312", "charset=utf-8"),
            html.replace(
                "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\">",
                "",
            ),
            html.replace("<title>", "<meta charset='gb2312'><title>"),
            html.replace(
                "text/html; charset=gb2312",
                "text/html; charset=gb2312; charset=utf-8",
            ),
        ] {
            assert_eq!(
                history(&history_legacy_input(&rejected).to_string())
                    .unwrap_err()
                    .code,
                "invalid_input"
            );
        }
        let mut input = history_legacy_input(&html);
        let mut bytes = STANDARD.decode(input["html"].as_str().unwrap()).unwrap();
        bytes.push(0xff);
        input["html"] = json!(STANDARD.encode(bytes));
        assert_eq!(
            history(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
        input = history_legacy_input(&html);
        input["encoding"] = json!("gbk");
        assert_eq!(
            history(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
        input["encoding"] = json!("gb2312");
        input["provenance"]["source_url"] = json!("http://mse.buaa.edu.cn/info/1061/42.htm");
        assert_eq!(
            history(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
    }

    #[test]
    fn history_legacy_mse_rejects_unowned_or_ambiguous_layout_text() {
        let html = history_legacy_html("Ordered body.");
        for rejected in [
            html.replace(
                "<table class=\"underline\">",
                "Unowned text<table class=\"underline\">",
            ),
            html.replace(
                "<table class=\"underline\">",
                "<svg><noscript><foreignObject>Unowned source prose</foreignObject></noscript></svg><table class=\"underline\">",
            ),
            html.replace(
                "Synthetic <strong>notice</strong>",
                "Synthetic notice</div><div>Other heading",
            ),
            html.replace("<td></td>", "<td>Nested source data</td>"),
            html.replace(
                "<td></td>",
                "<td><svg><noscript><foreignObject>Nested source data</foreignObject></noscript></svg></td>",
            ),
            html.replace("Ordered body.", ""),
        ] {
            assert_eq!(
                history(&history_legacy_input(&rejected).to_string())
                    .unwrap_err()
                    .code,
                "invalid_input"
            );
        }
        let inert = html.replace("Ordered body.", "Before<template><table><tr><td>Not source data</td></tr></table></template><noscript>Fallback</noscript><style>css</style><script>js</script>After");
        assert_eq!(
            history(&history_legacy_input(&inert).to_string()).unwrap()["body_text"],
            "Before After"
        );
        let base = html.replace("<title>", "<base href='http://different.test/'><title>");
        assert_eq!(
            history(&history_legacy_input(&base).to_string())
                .unwrap_err()
                .code,
            "invalid_input"
        );
    }

    #[test]
    fn history_legacy_mse_unfetched_media_and_files_keep_text_partial() {
        let html = history_legacy_html(
            "Before<img src='original.png'><a href='original.pdf'>Source <strong>file</strong></a><template><a href='inactive.doc'>Not a hint</a></template>After",
        );
        let output = history(&history_legacy_input(&html).to_string()).unwrap();
        assert_eq!(output["result"], "partial_text");
        assert_eq!(output["body_text"], "Before Source file After");
        assert_eq!(
            output["attachments"]["hints"],
            json!([{"href":"original.pdf","text":"Source file"}])
        );
        assert_eq!(output["body_paragraphs"], json!([]));
        assert!(output["published_at"].is_null());
    }

    #[test]
    fn history_legacy_mse_bounds_raw_html_decoded_html_and_body_text() {
        let body_at_limit = history_legacy_html(&"x".repeat(MAX_PARAGRAPH));
        assert_eq!(
            history(&history_legacy_input(&body_at_limit).to_string()).unwrap()["body_text"],
            "x".repeat(MAX_PARAGRAPH)
        );
        let body_over_limit = history_legacy_html(&"x".repeat(MAX_PARAGRAPH + 1));
        assert_eq!(
            history(&history_legacy_input(&body_over_limit).to_string())
                .unwrap_err()
                .code,
            "invalid_input"
        );
        let html = history_legacy_html("Bounded body.");
        let filler = "x".repeat(MAX_HTML - html.len() - "<!---->".len());
        let mut at_limit =
            history_legacy_input(&html.replace("<head>", &format!("<head><!--{filler}-->")));
        at_limit["provenance"]["asserted_by"] = json!("Synthetic operator assertion".repeat(20));
        assert_eq!(
            history(&at_limit.to_string()).unwrap()["body_text"],
            "Bounded body."
        );
        let mut raw = STANDARD.decode(at_limit["html"].as_str().unwrap()).unwrap();
        raw.push(b' ');
        at_limit["html"] = json!(STANDARD.encode(raw));
        assert_eq!(
            history(&at_limit.to_string()).unwrap_err().code,
            "invalid_input"
        );
        let expanded = html.replace(
            "<head>",
            &format!("<head><!--{}-->", "中".repeat(MAX_HTML / 2 - 1024)),
        );
        assert_eq!(
            history(&history_legacy_input(&expanded).to_string())
                .unwrap_err()
                .code,
            "invalid_input"
        );
    }


}
