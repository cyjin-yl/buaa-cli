//! Official-directory-bound Humanities and Social Sciences college notices.
//!
//! The directory advertises this source as literal HTTP metadata. The adapter
//! uses only a separate HTTPS candidate for transport, binds the
//! source-declared notice board, and only follows article URLs present in the
//! selected board snapshot.
use super::scse::viewer;
use super::{
    ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT, article_body,
    bind_college_board, college_directory_attribution, college_html, declared_jsp_attachment_hints,
    describe_college_surface, element_text, entry_in_scope, failed_contract, html_fallback,
    invalid_article, invalid_list, is_http, is_safe_public_fallback, parse_iso_date, retrieval,
    unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, HSS_NOTICES_URL, HSS_ROOT_URL, Response, hss_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学人文社会科学学院";
const LISTED_ROOT_URL: &str = "http://www.hss.buaa.edu.cn/";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("www.hss.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && hss_path_allowed(url.path())
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
        "人文社会科学学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = HSS_ROOT_URL.into();
    attribution["selection_relation"] =
        "deliberate HTTPS candidate; the exact literal HTTP directory identity is retained as metadata and is never used for transport".into();
    Ok((ArchiveClient::open_hss(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => HSS_ROOT_URL,
        "notices" => HSS_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, HSS_ROOT_URL, HSS_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            let _document = college_html(response)?;
            match describe_college_surface(response, "hss", attribution.clone()) {
                Ok(value) => Ok(value),
                Err(_) if is_safe_public_fallback(response) => Ok(html_fallback(
                    response,
                    "college_source_surface",
                    "hss",
                    "hss_surface_selector_contract",
                )),
                Err(error) => Err(error),
            }
        })
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
    let lists = Selector::parse("div.n_right > ul.list").map_err(|_| unavailable())?;
    let mut lists = document.select(&lists);
    let list = lists
        .next()
        .filter(|_| lists.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "HSS notice listing requires one n_right/list view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a[href]").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > a[href] > span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in list.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut row_anchors = row.select(&anchors);
        let anchor = row_anchors.next().ok_or_else(|| {
            failed_contract(
                "HSS notice row requires one direct anchor",
                file!(),
                line!(),
            )
        })?;
        if row_anchors.next().is_some() {
            return Err(failed_contract(
                "HSS notice row requires one direct anchor",
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
        let date_text = {
            let mut row_dates = row.select(&dates);
            let first = row_dates.next().map(element_text);
            if row_dates.next().is_some() {
                None
            } else {
                first
            }
        };
        let date = date_text.as_deref().and_then(parse_iso_date);
        let anchor_text = element_text(anchor);
        let title = date_text
            .as_deref()
            .and_then(|date| anchor_text.strip_prefix(date))
            .map(str::trim)
            .unwrap_or(anchor_text.as_str())
            .to_owned();
        if title.is_empty() || title.len() > MAX_TEXT {
            return Err(failed_contract(
                "HSS notice row requires a nonempty source title",
                file!(),
                line!(),
            ));
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
            "HSS notice listing has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn explicit_page_indicator(text: &str) -> Option<(u32, u32)> {
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if !chars[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let mut current = 0u32;
        while index < chars.len() && chars[index].is_ascii_digit() {
            current = current
                .checked_mul(10)?
                .checked_add(chars[index].to_digit(10)?)?;
            index += 1;
        }
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if chars.get(index) != Some(&'/') {
            continue;
        }
        index += 1;
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if !chars
            .get(index)
            .is_some_and(|character| character.is_ascii_digit())
        {
            continue;
        }
        let mut total = 0u32;
        while index < chars.len() && chars[index].is_ascii_digit() {
            total = total
                .checked_mul(10)?
                .checked_add(chars[index].to_digit(10)?)?;
            index += 1;
        }
        if current != 0 && total >= current {
            return Some((current, total));
        }
    }
    None
}

fn explicit_link_page(text: &str) -> Option<u32> {
    let trimmed = text.trim();
    (!trimmed.is_empty() && trimmed.chars().all(|character| character.is_ascii_digit()))
        .then(|| trimmed.parse().ok())
        .flatten()
}

fn select_advertised_page_url(document: &Html, latest: &Url, page: u32) -> Result<Url, Error> {
    let pages = Selector::parse("div.pages").map_err(|_| unavailable())?;
    let mut page_blocks = document
        .select(&pages)
        .filter(|node| !super::inert_element(*node));
    let page_block = page_blocks.next().ok_or_else(|| {
        Error::new(
            "unavailable",
            "HSS notice listing has no explicit page ordinal declaration",
        )
    })?;
    if page_blocks.next().is_some() {
        return Err(Error::new(
            "unavailable",
            "HSS notice listing has conflicting page ordinal declarations",
        ));
    }
    let (current, total) = explicit_page_indicator(&element_text(page_block)).ok_or_else(|| {
        Error::new(
            "unavailable",
            "HSS notice listing has no explicit page ordinal declaration",
        )
    })?;
    if page < 1 || page > total {
        return Err(Error::new(
            "unavailable",
            "requested HSS page is outside the explicitly advertised ordinal range",
        ));
    }
    if page == current {
        return Ok(latest.clone());
    }
    let links = Selector::parse("div.pages a[href]").map_err(|_| unavailable())?;
    let mut selected = None;
    for link in document
        .select(&links)
        .filter(|node| !super::inert_element(*node))
    {
        let raw = link.value().attr("href").ok_or_else(unavailable)?;
        let url = latest.join(raw).map_err(|_| unavailable())?;
        if !plain_url(&url) || !url.path().starts_with("/xwzx1/tzgg/") {
            continue;
        }
        let Some(stem) = url
            .path()
            .strip_prefix("/xwzx1/tzgg/")
            .and_then(|path| path.strip_suffix(".htm"))
        else {
            continue;
        };
        if stem.parse::<u32>().is_err() {
            continue;
        }
        let label = element_text(link);
        let declared_page = explicit_link_page(&label).or_else(|| {
            if label.contains("下页") || label.contains("下一页") {
                current.checked_add(1)
            } else if label.contains("尾页") || label.contains("末页") {
                Some(total)
            } else {
                None
            }
        });
        if declared_page != Some(page) {
            continue;
        }
        match selected.as_ref() {
            Some(previous) if previous != &url => {
                return Err(Error::new(
                    "unavailable",
                    "requested HSS page has conflicting advertised destinations; no URL was selected",
                ));
            }
            None => selected = Some(url),
            _ => {}
        }
    }
    selected.ok_or_else(|| {
        Error::new(
            "unavailable",
            "requested HSS page is not explicitly advertised by the retained notice listing; no URL was inferred",
        )
    })
}

fn listing_url_response(
    response: &Response,
    latest: &Url,
    page: u32,
) -> Result<Result<Url, Error>, Error> {
    let document = college_html(response)?;
    let selected = select_advertised_page_url(&document, latest, page);
    if selected.is_err() && !is_safe_public_fallback(response) {
        return Err(unavailable());
    }
    Ok(selected)
}

/// HSS's legacy pagination labels are “下页/尾页”, not numeric anchors.  The
/// source's explicit page indicator and link label, rather than a zero-based
/// filename convention, determine the requested ordinal.
fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(HSS_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    let result: Result<Url, Error> = client.get(&latest, false, |response| {
        listing_url_response(response, &latest, page)
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
    bind_college_board(&client, HSS_ROOT_URL, HSS_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    let result: Result<Value, Error> = client.with_cache_mode(mode).get(&target, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &target) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                let mut value = html_fallback(
                    response,
                    "announcements_list",
                    "hss",
                    "hss_listing_selector_contract",
                );
                value["category"] = json!("tzgg");
                value["page"] = json!(page);
                return Ok(Ok(value));
            }
            Err(error) => return Err(error),
        };
        let entries: Vec<&ListingEntry> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
            .collect();
        Ok(Ok(json!({
            "schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"hss","category":"tzgg","listing_label":"通知公告","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source-advertised ordinal only; no automatic traversal","other_colleges":"not_covered","dates":"source ISO dates; source order retained; missing or invalid stays null","summaries":"source titles only; no excerpt promotion"},
            "retrieval":retrieval(response)
        })))
    })?;
    result
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1103/")
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
    bind_college_board(&client, HSS_ROOT_URL, HSS_NOTICES_URL, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing_result: Result<Value, Error> = client.get(&source, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &source) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(Ok(html_fallback(
                    response,
                    "announcements_list",
                    "hss",
                    "hss_listing_selector_contract",
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
                "retained HSS notice page does not declare the selected article",
            )));
        }
        Ok(Ok(retrieval(response)))
    })?;
    let listing = listing_result?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained HSS notice page could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client.with_cache_mode(mode).get(target, false, |response| {
        let document = match college_html(response) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_article",
                    "hss",
                    "hss_article_selector_contract",
                ));
            }
            Err(error) => return Err(error),
        };
        let mut value = match normalize(response, &document) {
            Ok(value) => value,
            Err(_) if is_safe_public_fallback(response) => html_fallback(
                response,
                "announcements_article",
                "hss",
                "hss_article_selector_contract",
            ),
            Err(error) => return Err(error),
        };
        value["publisher"] = json!(PUBLISHER);
        value["college"] = json!("hss");
        value["directory_attribution"] = attribution.clone();
        value["source_listing"] = listing.clone();
        Ok(value)
    })
}

fn local_asset_url(base: &Url, raw: &str, suffix: &str) -> Result<String, Error> {
    if raw.len() > MAX_HREF
        || raw.chars().any(char::is_control)
        || !raw.starts_with("/__local/")
        || !raw.to_ascii_lowercase().ends_with(suffix)
    {
        return Err(unavailable());
    }
    let url = base.join(raw).map_err(|_| unavailable())?;
    if url.scheme() != base.scheme()
        || url.host_str() != base.host_str()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(unavailable());
    }
    Ok(url.to_string())
}

const MAX_DECLARATION_SCRIPT: usize = 64 * 1024;
const MAX_PREVIEW_PATHS: usize = 128;

fn skip_script_string(script: &str, offset: &mut usize, quote: u8) -> Result<(), Error> {
    let bytes = script.as_bytes();
    *offset += 1;
    while let Some(byte) = bytes.get(*offset).copied() {
        *offset += 1;
        if byte == b'\\' {
            if *offset == bytes.len() {
                return Err(unavailable());
            }
            *offset += 1;
        } else if byte == quote {
            return Ok(());
        }
    }
    Err(unavailable())
}

fn skip_script_comment(script: &str, offset: &mut usize) -> Result<bool, Error> {
    let bytes = script.as_bytes();
    if bytes.get(*offset..*offset + 2) == Some(b"//")
        || bytes.get(*offset..*offset + 4) == Some(b"<!--")
    {
        while *offset < bytes.len() && !matches!(bytes[*offset], b'\r' | b'\n') {
            *offset += 1;
        }
        return Ok(true);
    }
    if bytes.get(*offset..*offset + 2) == Some(b"/*") {
        *offset += 2;
        while bytes.get(*offset..*offset + 2) != Some(b"*/") {
            if *offset >= bytes.len() {
                return Err(unavailable());
            }
            *offset += 1;
        }
        *offset += 2;
        return Ok(true);
    }
    Ok(false)
}

fn skip_script_trivia(script: &str, offset: &mut usize) -> Result<(), Error> {
    loop {
        while script
            .as_bytes()
            .get(*offset)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            *offset += 1;
        }
        if !skip_script_comment(script, offset)? {
            return Ok(());
        }
    }
}

#[derive(Clone, Copy)]
enum PreviewToken<'a> {
    Identifier(&'a str),
    Punctuation(u8),
    Other,
}

fn simple_preview_prefix(tokens: &[PreviewToken<'_>]) -> bool {
    matches!(
        tokens,
        [] | [PreviewToken::Identifier("var")]
            | [PreviewToken::Identifier("let")]
            | [PreviewToken::Identifier("const")]
            | [
                PreviewToken::Identifier("window"),
                PreviewToken::Punctuation(b'.')
            ]
    )
}

pub(super) fn declared_preview_paths(script: &str) -> Result<Vec<String>, Error> {
    if !script.contains("vsb_pdf_image_data") {
        return Ok(Vec::new());
    }
    if script.len() > MAX_DECLARATION_SCRIPT {
        return Err(unavailable());
    }
    let bytes = script.as_bytes();
    let marker = "vsb_pdf_image_data";
    let mut offset = 0;
    let mut brace_depth = 0usize;
    let mut statement = Vec::new();
    let mut previews = Vec::new();
    while offset < bytes.len() {
        skip_script_trivia(script, &mut offset)?;
        let Some(byte) = bytes.get(offset).copied() else {
            break;
        };
        if matches!(byte, b'\'' | b'"' | b'`') {
            skip_script_string(script, &mut offset, byte)?;
            statement.push(PreviewToken::Other);
            continue;
        }
        if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') {
            let start = offset;
            offset += 1;
            while bytes
                .get(offset)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
            {
                offset += 1;
            }
            let identifier = &script[start..offset];
            if identifier != marker {
                statement.push(PreviewToken::Identifier(identifier));
                continue;
            }
            if brace_depth != 0 || !simple_preview_prefix(&statement) {
                return Err(unavailable());
            }
            skip_script_trivia(script, &mut offset)?;
            if bytes.get(offset) != Some(&b'=') {
                return Err(unavailable());
            }
            offset += 1;
            skip_script_trivia(script, &mut offset)?;
            if bytes.get(offset) != Some(&b'[') {
                return Err(unavailable());
            }
            let array_start = offset;
            let mut stream = serde_json::Deserializer::from_str(&script[array_start..])
                .into_iter::<Vec<String>>();
            let paths = stream
                .next()
                .ok_or_else(unavailable)?
                .map_err(|_| unavailable())?;
            if paths.len() > MAX_PREVIEW_PATHS {
                return Err(unavailable());
            }
            offset = array_start + stream.byte_offset();
            previews.extend(paths);
            statement.push(PreviewToken::Punctuation(b'='));
            skip_script_trivia(script, &mut offset)?;
            if bytes.get(offset) == Some(&b';') {
                offset += 1;
                statement.clear();
            } else if offset != bytes.len() {
                statement.push(PreviewToken::Other);
            }
            continue;
        }
        offset += 1;
        match byte {
            b';' => statement.clear(),
            b'{' => {
                brace_depth = brace_depth.checked_add(1).ok_or_else(unavailable)?;
                statement.push(PreviewToken::Punctuation(byte));
            }
            b'}' => {
                brace_depth = brace_depth.checked_sub(1).ok_or_else(unavailable)?;
                statement.push(PreviewToken::Punctuation(byte));
            }
            _ => statement.push(PreviewToken::Punctuation(byte)),
        }
    }
    if brace_depth != 0 {
        return Err(unavailable());
    }
    Ok(previews)
}

fn declared_document(
    body: ElementRef<'_>,
    base: &Url,
) -> Result<(bool, Option<String>, Vec<String>), Error> {
    let scripts = Selector::parse("script").map_err(|_| unavailable())?;
    let mut original_pdf = None;
    let mut previews = Vec::new();
    for script in body.select(&scripts) {
        if script.value().attr("src").is_some() || crate::html::inert_element(script) {
            continue;
        }
        let Some(kind) = crate::html::script_kind(script) else {
            continue;
        };
        if kind == crate::html::ScriptKind::Module {
            if script.text().any(|text| text.contains("showVsbpdfIframe")) {
                return Err(unavailable());
            }
            continue;
        }
        for text in script.text() {
            for path in viewer::declarations(text)? {
                let url = local_asset_url(base, &path, ".pdf")?;
                if original_pdf
                    .as_ref()
                    .is_some_and(|previous| previous != &url)
                {
                    return Err(failed_contract(
                        "HSS article declares ambiguous original PDF documents",
                        file!(),
                        line!(),
                    ));
                }
                original_pdf = Some(url);
            }
            for path in declared_preview_paths(text)? {
                if previews.len() == MAX_PREVIEW_PATHS {
                    return Err(unavailable());
                }
                previews.push(local_asset_url(base, &path, ".jpg")?);
            }
        }
    }
    Ok((original_pdf.is_some(), original_pdf, previews))
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let mains =
        Selector::parse("div.n_con > form[name=\"_newscontent_fromname\"] > div.contain_con")
            .map_err(|_| unavailable())?;
    let mut mains = document.select(&mains);
    let main = mains
        .next()
        .filter(|_| mains.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "HSS article requires one n_con/newscontent contain_con container",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > h2").map_err(|_| unavailable())?;
    let mut headings = main.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "HSS article requires one direct nonempty h2 heading",
                file!(),
                line!(),
            )
        })?;
    let date_selector =
        Selector::parse(":scope > p[style*=\"text-align:center\"]").map_err(|_| unavailable())?;
    let mut date_nodes = main.select(&date_selector);
    let published_at = date_nodes.next().map(element_text).and_then(|raw| {
        raw.split_once("发布日期：")
            .and_then(|(_, tail)| tail.split_whitespace().next().and_then(parse_iso_date))
    });
    if date_nodes.next().is_some() {
        return Err(unavailable());
    }
    let bodies = Selector::parse(":scope > div#vsb_content > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "HSS article requires one direct vsb_content/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let (paragraphs, mut attachment_hints, mut attachments_found) = article_body(body, true)?;
    let (declared_hints, hints_truncated) = declared_jsp_attachment_hints(main)?;
    attachments_found |= !declared_hints.is_empty();
    attachment_hints.extend(declared_hints);
    let base = Url::parse(&response.url).map_err(|_| unavailable())?;
    let (has_document, original_pdf, previews) = declared_document(body, &base)?;
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let has_images = body
        .select(&images)
        .any(|node| !crate::html::inert_element(node));
    let tables = Selector::parse("table").map_err(|_| unavailable())?;
    let table_count = body
        .select(&tables)
        .filter(|node| !crate::html::inert_element(*node))
        .count();
    if paragraphs.is_empty() && !has_document && attachment_hints.is_empty() {
        return Err(failed_contract(
            "HSS article requires text or source-declared document/attachment content",
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
    } else if has_images || table_count != 0 {
        "partial_text"
    } else {
        "full_text"
    };
    let mut output = json!({
        "schema_version":1,"type":"announcements_article","result":result,"publisher":PUBLISHER,"college":"hss",
        "title":title,"category":"1103","published_at":published_at,
        "body_paragraph_count":paragraphs.len(),"body_paragraphs":paragraphs,
        "embedded_document":{"present":has_document,"original_pdf_url":original_pdf,"preview_paths":previews,"preview_kind":"source_declared_derived_images","assets_fetched":false,"ocr_performed":false,"original_document_verified":false},
        "attachments":{"found":attachments_found,"hints":attachment_hints,"hints_truncated":hints_truncated,"note":"source-declared links only; never fetched"},
        "completeness":{"scope":"single_college_article_page","body_source":"v_news_content paragraphs excluding executable/fallback markup","missing_document_text":"not_reconstructed","image_content_present":has_images,"unextracted_table_count":table_count,"missing_nonparagraph_content":if has_images || table_count != 0 {json!("image text and table contents are not reconstructed or downloaded")} else {Value::Null}},
        "retrieval":retrieval(response)
    });
    output["attachments"]["hints_truncated"] = json!(hints_truncated);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(url: &str, body: &str) -> Response {
        Response {
            url: url.into(),
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

    #[test]
    fn listing_uses_direct_rows_and_source_dates_without_promoting_date_text() {
        let html = r#"<title>通知公告-人文社会科学学院</title><div class="n_right"><ul class="list">
            <li><a href="../info/1103/42.htm"><span>2026-10-15</span>First source notice</a></li>
            <li><a href="../info/1103/43.htm"><span>2026-02-30</span>Unknown date notice</a></li>
        </ul></div><ul class="list"><li>unrelated</li></ul>"#;
        let parsed = parse_listing(
            &Html::parse_document(html),
            &Url::parse(HSS_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.entries[0].title, "First source notice");
        assert_eq!(parsed.entries[0].date.as_deref(), Some("2026-10-15"));
        assert_eq!(parsed.entries[1].date, None);
        let since = Some("2026-10-01".to_owned());
        assert_eq!(
            parsed
                .entries
                .iter()
                .filter(|entry| entry_in_scope(entry, &since, &None, &None))
                .map(|entry| entry.title.as_str())
                .collect::<Vec<_>>(),
            vec!["First source notice"]
        );
    }

    #[test]
    fn image_pdf_article_is_embedded_document_with_sibling_attachment_hints() {
        let html = r#"<div class="n_con"><form name="_newscontent_fromname"><div class="contain_con">
            <h2>Source article heading</h2><p style="text-align:center;background:#f5f5f5">【 发布日期：2026-10-15 】</p>
            <div id="vsb_content"><div class="v_news_content"><p><script>var vsb_pdf_image_data=["/__local/1/AA/BB/CC/preview.jpg"];showVsbpdfIframe("/__local/1/AA/BB/CC/original.pdf","100%","600");</script></p></div></div>
            <p><ul><li>附件<a href="/system/_content/download.jsp?file=1">附件：Form.pdf</a></li></ul></p>
        </div></form></div>"#;
        let response = response("https://www.hss.buaa.edu.cn/info/1103/42.htm", html);
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["result"], "embedded_document");
        assert_eq!(output["published_at"], "2026-10-15");
        assert_eq!(output["body_paragraph_count"], 0);
        assert_eq!(output["embedded_document"]["present"], true);
        assert_eq!(output["attachments"]["hints"][0]["text"], "附件：Form.pdf");
    }

    #[test]
    fn inactive_preview_payloads_cannot_authorize_an_embedded_document() {
        for script in [
            r#"/* var vsb_pdf_image_data=["/__local/1/AA/BB/CC/preview.jpg"]; */"#,
            r#"const text = "vsb_pdf_image_data=[\"/__local/1/AA/BB/CC/preview.jpg\"]";"#,
            r#"/* showVsbpdfIframe("/__local/1/AA/BB/CC/original.pdf"); */"#,
            r#"const text = "showVsbpdfIframe(\"/__local/1/AA/BB/CC/original.pdf\")";"#,
        ] {
            let html = format!(
                r#"<div class="n_con"><form name="_newscontent_fromname"><div class="contain_con">
                <h2>Source article heading</h2><div id="vsb_content"><div class="v_news_content"><p><script>{script}</script></p></div></div>
            </div></form></div>"#
            );
            let response = response("https://www.hss.buaa.edu.cn/info/1103/42.htm", &html);
            assert_eq!(
                normalize(&response, &college_html(&response).unwrap())
                    .unwrap_err()
                    .code,
                "unavailable"
            );
        }

        let active_preview_only = r#"<div class="n_con"><form name="_newscontent_fromname"><div class="contain_con">
            <h2>Source article heading</h2><div id="vsb_content"><div class="v_news_content"><p><script>var vsb_pdf_image_data=["/__local/1/AA/BB/CC/preview.jpg"];</script></p></div></div>
        </div></form></div>"#;
        let response = response(
            "https://www.hss.buaa.edu.cn/info/1103/42.htm",
            active_preview_only,
        );
        assert_eq!(
            normalize(&response, &college_html(&response).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn review_regression_security_discovery_refusal_stays_outer_error() {
        for body in [
            r#"<form><input type="password"><input name="csrf_token" value="private-token"></form>"#,
            r#"<div id="cf-chl-widget"><iframe src="/cdn-cgi/challenge-platform"></iframe></div>"#,
        ] {
            let response = response(HSS_NOTICES_URL, body);
            let latest = Url::parse(HSS_NOTICES_URL).unwrap();
            let processed = listing_url_response(&response, &latest, 2);
            assert_eq!(processed.unwrap_err().code, "unavailable");
        }
    }

    #[test]
    fn review_regression_inert_hss_scripts_cannot_authorize_an_embedded_document() {
        for container in ["template", "noscript"] {
            let html = format!(
                r#"<div class="n_con"><form name="_newscontent_fromname"><div class="contain_con">
                <h2>Source article heading</h2><div id="vsb_content"><div class="v_news_content"><p><{container}><script>showVsbpdfIframe("/__local/1/AA/BB/CC/original.pdf","100%","600");</script></{container}></p></div></div>
            </div></form></div>"#
            );
            let response = response("https://www.hss.buaa.edu.cn/info/1103/42.htm", &html);
            assert_eq!(
                normalize(&response, &college_html(&response).unwrap())
                    .unwrap_err()
                    .code,
                "unavailable"
            );
        }
    }

    #[test]
    fn conflicting_active_original_documents_are_rejected() {
        let html = r#"<div class="n_con"><form name="_newscontent_fromname"><div class="contain_con">
            <h2>Source article heading</h2><div id="vsb_content"><div class="v_news_content"><p><script>showVsbpdfIframe("/__local/1/AA/BB/CC/first.pdf");showVsbpdfIframe("/__local/1/AA/BB/CC/second.pdf");</script></p></div></div>
        </div></form></div>"#;
        let response = response("https://www.hss.buaa.edu.cn/info/1103/42.htm", html);
        assert_eq!(
            normalize(&response, &college_html(&response).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn page_two_requires_explicit_ordinal_and_link() {
        let html = r#"<div class="pages"><span>1 / 2</span><span class="PrevDisabled">上页</span><a href="tzgg/1.htm">下页</a><a href="tzgg/1.htm">尾页</a></div>"#;
        let document = Html::parse_document(html);
        let base = Url::parse(HSS_NOTICES_URL).unwrap();
        let target = select_advertised_page_url(&document, &base, 2).unwrap();
        assert_eq!(
            target,
            Url::parse("https://www.hss.buaa.edu.cn/xwzx1/tzgg/1.htm").unwrap()
        );
        assert!(plain_url(&target));
        let without_indicator =
            Html::parse_document(r#"<div class="pages"><a href="tzgg/1.htm">下页</a></div>"#);
        assert!(select_advertised_page_url(&without_indicator, &base, 2).is_err());
        let conflicting = Html::parse_document(
            r#"<div class="pages"><span>1/2</span><a href="tzgg/1.htm">下页</a><a href="tzgg/2.htm">下页</a></div>"#,
        );
        assert!(select_advertised_page_url(&conflicting, &base, 2).is_err());
    }

    #[test]
    fn hss_ordinal_failure_is_inner_after_source_admission() {
        let html = r#"<div class="pages"><span>1/2</span><a href="tzgg/1.htm">下页</a></div>"#;
        let admitted = response(HSS_NOTICES_URL, html);
        let latest = Url::parse(HSS_NOTICES_URL).unwrap();
        let processed = listing_url_response(&admitted, &latest, 3).unwrap();
        assert_eq!(processed.unwrap_err().code, "unavailable");

        let conflicting = response(
            HSS_NOTICES_URL,
            r#"<div class="pages"><span>1/2</span><a href="tzgg/1.htm">下页</a><a href="tzgg/2.htm">下页</a></div>"#,
        );
        let processed = listing_url_response(&conflicting, &latest, 2).unwrap();
        assert_eq!(processed.unwrap_err().code, "unavailable");
    }
}
