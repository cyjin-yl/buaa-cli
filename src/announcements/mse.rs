//! Materials college: exact HTTP directory identity, separate HTTPS observation.
use super::{
    ArticleDocument, ListQuery, MAX_ATTACHMENT_HINTS, MAX_BODY_PARAGRAPHS, MAX_ENTRIES,
    MAX_PARAGRAPH, MAX_TEXT, advertised_page_url, article_body, article_category_from_url,
    article_content, article_output, bind_college_board, college_directory_attribution,
    college_html, describe_college_surface, element_text, entry_in_scope, failed_contract,
    inert_element, invalid_article, invalid_list, is_document_href,
    parse_chinese_publication_date, parse_iso_date, parse_notice_list, retrieval, unavailable,
};
use crate::html::{
    MAX_SCRIPT_BYTES, MAX_SCRIPT_DEPTH, ScriptKind, script_kind, script_quoted_end, script_trivia,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, MSE_NOTICES_URL, MSE_ROOT_URL, mse_path_allowed,
};
use scraper::{ElementRef, Html, Node, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://mse.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学材料科学与工程学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("mse.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && mse_path_allowed(url.path())
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
        "材料科学与工程学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = MSE_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_mse(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => MSE_ROOT_URL,
        "notices" => MSE_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, MSE_ROOT_URL, MSE_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "mse", attribution)
        })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(MSE_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        college_html(response)?;
        advertised_page_url(
            &response.body,
            &latest,
            page,
            "div.nymain div.ny-right div.notice-list > div > div.pagestyle span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/xwdt/gggs/"),
        )
    })
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    if query
        .category
        .as_deref()
        .is_some_and(|category| category != "gggs")
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
    bind_college_board(&client, MSE_ROOT_URL, MSE_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = parse_notice_list(&college_html(response)?, &target)?;
        let entries: Vec<_> = document.entries.iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"mse","category":"gggs","listing_label":"公告公示","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"source YYYY.MM.DD; missing, invalid or ambiguous stays null","summaries":"source direct a/p excerpt; not original full text"},
            "retrieval":retrieval(response)}))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || source_page == 0
        || !(target.path().starts_with("/info/1061/") || target.path().starts_with("/info/1058/"))
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
    bind_college_board(&client, MSE_ROOT_URL, MSE_NOTICES_URL, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing = client.get(&source, false, |response| {
        let document = parse_notice_list(&college_html(response)?, &source)?;
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Err(Error::new(
                "unsupported",
                "retained notice page does not declare the selected Mse article",
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
                value["college"] = json!("mse");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
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
                "Mse source tables require bounded flat rows and cell-owned text",
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
                "Mse table caption is ambiguous or over budget",
                file!(),
                line!(),
            ));
        }
        result.has_text |= caption.as_ref().is_some_and(|text| !text.is_empty());
        let mut source_rows = Vec::new();
        for row in table.select(&rows).filter(|node| !inert_element(*node)) {
            if result.row_count == MAX_BODY_PARAGRAPHS {
                return Err(failed_contract(
                    "Mse table rows exceed the reviewed text budget",
                    file!(),
                    line!(),
                ));
            }
            let mut source_cells = Vec::new();
            let mut row_bytes = 0usize;
            for cell in row.select(&cells).filter(|node| !inert_element(*node)) {
                if source_cells.len() == MAX_ENTRIES {
                    return Err(failed_contract(
                        "Mse table row exceeds the reviewed cell budget",
                        file!(),
                        line!(),
                    ));
                }
                let text = element_text(cell);
                row_bytes += text.len();
                if row_bytes > MAX_PARAGRAPH {
                    return Err(failed_contract(
                        "Mse table row text exceeds the reviewed byte budget",
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
                                "Mse table span attribute exceeds the reviewed text budget",
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

fn normalize(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    let mains = Selector::parse("div.nymain > div.w16 > div.ny-right > form > div.art-main")
        .map_err(|_| unavailable())?;
    let mut mains = document.select(&mains).filter(|node| !inert_element(*node));
    let main = mains
        .next()
        .filter(|_| mains.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Mse article requires one direct nymain/art-main container",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > div.art-tit > h3").map_err(|_| unavailable())?;
    let mut headings = main.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "Mse article requires one direct art-tit/h3 original heading",
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
        .and_then(|node| parse_chinese_publication_date(&element_text(node)));
    let bodies = Selector::parse(":scope > div.art-body-box > div.art-body > div#vsb_content.ar_article > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Mse article requires one scoped ar_article/vsb_content source body",
                file!(),
                line!(),
            )
        })?;
    let tables = source_tables(body)?;
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, tables.has_text)?;
    if paragraphs.len() + tables.row_count > MAX_BODY_PARAGRAPHS {
        return Err(failed_contract(
            "Mse paragraphs and table rows exceed the reviewed text budget",
            file!(),
            line!(),
        ));
    }
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let has_images = body.select(&images).any(|image| !inert_element(image));
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
    output["body_table_count"] = json!(tables.values.len());
    output["body_table_row_count"] = json!(tables.row_count);
    output["body_table_cell_count"] = json!(tables.cell_count);
    output["body_tables"] = Value::Array(tables.values);
    output["completeness"]["body_source"] = json!(
        "unique art-main/art-body-box/art-body/ar_article#vsb_content/v_news_content; source paragraphs and separate ordered flat-table captions/rows/cells; code and fallback payloads excluded"
    );
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

/// Offline identity only. The archived declaration includes the explicit default
/// port, which Url normalizes away; preserve that literal spelling in provenance.
pub(super) fn legacy_history_source(raw: &str) -> bool {
    let Some(path) = raw
        .strip_prefix("http://mse.buaa.edu.cn/")
        .or_else(|| raw.strip_prefix("http://mse.buaa.edu.cn:80/"))
    else {
        return false;
    };
    legacy_notice_path(path)
}

fn legacy_notice_path(path: &str) -> bool {
    path.strip_prefix("call_board_detail.php?call_board_id=")
        .is_some_and(|id| (1..=10).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit()))
}

pub(super) fn legacy_listing_source(raw: &str) -> bool {
    matches!(
        raw,
        "http://mse.buaa.edu.cn/" | "http://mse.buaa.edu.cn:80/"
    )
}

fn legacy_charset_declared(document: &Html) -> Result<(), Error> {
    let metas = Selector::parse("meta[charset], meta[http-equiv]").map_err(|_| unavailable())?;
    let mut declarations = 0;
    for meta in document.select(&metas).filter(|node| !inert_element(*node)) {
        let charset = meta.value().attr("charset");
        let content_type = meta
            .value()
            .attr("http-equiv")
            .is_some_and(|value| value.eq_ignore_ascii_case("content-type"));
        let label = if let Some(label) = charset {
            if content_type {
                return Err(unavailable());
            }
            label
        } else if content_type {
            let (mime, parameter) = meta
                .value()
                .attr("content")
                .and_then(|value| value.split_once(';'))
                .ok_or_else(unavailable)?;
            let (name, label) = parameter.trim().split_once('=').ok_or_else(unavailable)?;
            if !mime.trim().eq_ignore_ascii_case("text/html")
                || !name.trim().eq_ignore_ascii_case("charset")
            {
                return Err(unavailable());
            }
            label
        } else {
            continue;
        };
        declarations += 1;
        if !label.trim().eq_ignore_ascii_case("gb2312") || declarations != 1 {
            return Err(unavailable());
        }
    }
    if declarations != 1 {
        return Err(unavailable());
    }
    Ok(())
}

fn legacy_token(script: &str, offset: &mut usize, token: &str) -> Option<()> {
    script_trivia(script.as_bytes(), offset)?;
    if !script.get(*offset..)?.starts_with(token) {
        return None;
    }
    *offset += token.len();
    if token
        .as_bytes()
        .last()
        .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$'))
        && script
            .as_bytes()
            .get(*offset)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$'))
    {
        return None;
    }
    Some(())
}

fn legacy_identifier<'a>(script: &'a str, offset: &mut usize) -> Option<&'a str> {
    script_trivia(script.as_bytes(), offset)?;
    if !script
        .as_bytes()
        .get(*offset)
        .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'$'))
    {
        return None;
    }
    let start = *offset;
    while script
        .as_bytes()
        .get(*offset)
        .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$'))
    {
        *offset += 1;
    }
    let identifier = &script[start..*offset];
    (identifier.len() <= MAX_TEXT).then_some(identifier)
}

/// Only the complete observed helper shape: three distinct arguments forwarded
/// unchanged to window.open. No execution, scope inference or general JS parser.
fn legacy_helper_declaration(script: &str, offset: &mut usize) -> Option<()> {
    legacy_token(script, offset, "function")?;
    legacy_token(script, offset, "MM_openBrWindow")?;
    legacy_token(script, offset, "(")?;
    let url = legacy_identifier(script, offset)?;
    legacy_token(script, offset, ",")?;
    let name = legacy_identifier(script, offset)?;
    legacy_token(script, offset, ",")?;
    let features = legacy_identifier(script, offset)?;
    if url == name
        || url == features
        || name == features
        || [url, name, features].contains(&"window")
    {
        return None;
    }
    legacy_token(script, offset, ")")?;
    legacy_token(script, offset, "{")?;
    legacy_token(script, offset, "window")?;
    legacy_token(script, offset, ".")?;
    legacy_token(script, offset, "open")?;
    legacy_token(script, offset, "(")?;
    if legacy_identifier(script, offset)? != url {
        return None;
    }
    legacy_token(script, offset, ",")?;
    if legacy_identifier(script, offset)? != name {
        return None;
    }
    legacy_token(script, offset, ",")?;
    if legacy_identifier(script, offset)? != features {
        return None;
    }
    legacy_token(script, offset, ")")?;
    legacy_token(script, offset, ";")?;
    legacy_token(script, offset, "}")
}

/// The retained script also contains a separate reload helper/call. Scan bounded
/// top-level declarations, not a substring or a whole-script singleton. Quoted,
/// commented and nested helper names cannot establish this binding; reassignment
/// or an unreviewed reference rejects rather than guessing execution semantics.
fn legacy_popup_helpers(script: &str) -> Option<usize> {
    if script.len() > MAX_SCRIPT_BYTES {
        return None;
    }
    let bytes = script.as_bytes();
    let mut offset = 0;
    let mut stack = Vec::new();
    let mut statement_start = true;
    let mut helpers = 0;
    loop {
        script_trivia(bytes, &mut offset)?;
        let Some(byte) = bytes.get(offset).copied() else {
            break;
        };
        match byte {
            b'"' | b'\'' | b'`' => {
                script_quoted_end(bytes, &mut offset)?;
                statement_start = false;
            }
            b'(' | b'[' | b'{' => {
                if stack.len() == MAX_SCRIPT_DEPTH {
                    return None;
                }
                stack.push(byte);
                offset += 1;
                statement_start = false;
            }
            b')' | b']' | b'}' => {
                let expected = match byte {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                if stack.pop() != Some(expected) {
                    return None;
                }
                offset += 1;
                statement_start = false;
            }
            b';' => {
                offset += 1;
                statement_start = stack.is_empty();
            }
            b'/' => return None,
            _ if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') => {
                let start = offset;
                let identifier = legacy_identifier(script, &mut offset)?;
                if identifier == "function" && stack.is_empty() && statement_start {
                    let mut name_offset = offset;
                    if legacy_identifier(script, &mut name_offset)? == "MM_openBrWindow" {
                        offset = start;
                        legacy_helper_declaration(script, &mut offset)?;
                        helpers += 1;
                        if helpers > 1 {
                            return None;
                        }
                        statement_start = true;
                        continue;
                    }
                }
                if identifier == "MM_openBrWindow" {
                    return None;
                }
                statement_start = false;
            }
            _ => {
                offset += 1;
                statement_start = false;
            }
        }
    }
    stack.is_empty().then_some(helpers)
}

fn legacy_literal<'a>(script: &'a str, offset: &mut usize) -> Option<&'a str> {
    script_trivia(script.as_bytes(), offset)?;
    if !matches!(script.as_bytes().get(*offset), Some(b'\'' | b'"')) {
        return None;
    }
    let start = *offset + 1;
    script_quoted_end(script.as_bytes(), offset)?;
    let literal = &script[start..*offset - 1];
    if literal.len() > MAX_TEXT
        || literal.contains('\\')
        || literal
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}'))
    {
        return None;
    }
    Some(literal)
}

fn legacy_popup_target(handler: &str) -> Option<&str> {
    if handler.len() > MAX_PARAGRAPH {
        return None;
    }
    let mut offset = 0;
    legacy_token(handler, &mut offset, "MM_openBrWindow")?;
    legacy_token(handler, &mut offset, "(")?;
    let target = legacy_literal(handler, &mut offset)?;
    legacy_token(handler, &mut offset, ",")?;
    legacy_literal(handler, &mut offset)?;
    legacy_token(handler, &mut offset, ",")?;
    legacy_literal(handler, &mut offset)?;
    legacy_token(handler, &mut offset, ")")?;
    script_trivia(handler.as_bytes(), &mut offset)?;
    if handler.as_bytes().get(offset) == Some(&b';') {
        offset += 1;
        script_trivia(handler.as_bytes(), &mut offset)?;
    }
    (offset == handler.len()).then_some(target)
}

pub(super) fn parse_legacy_listing(document: &Html, base: &Url) -> Result<Value, Error> {
    legacy_charset_declared(document)?;
    let titles = Selector::parse("head > title").map_err(|_| unavailable())?;
    let mut titles = document
        .select(&titles)
        .filter(|node| !inert_element(*node));
    let title = titles
        .next()
        .filter(|_| titles.next().is_none())
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
        .ok_or_else(unavailable)?;
    let scripts = Selector::parse("script").map_err(|_| unavailable())?;
    let mut helpers = 0;
    for script in document
        .select(&scripts)
        .filter(|node| !inert_element(*node))
    {
        if script_kind(script) != Some(ScriptKind::Classic) {
            continue;
        }
        let mut text = script.text();
        let source = text.next().unwrap_or_default();
        if !source.contains("MM_openBrWindow") {
            continue;
        }
        if script.value().attr("src").is_some() || text.next().is_some() {
            return Err(unavailable());
        }
        helpers += legacy_popup_helpers(source).ok_or_else(unavailable)?;
        if helpers > 1 {
            return Err(unavailable());
        }
    }
    if helpers != 1 {
        return Err(unavailable());
    }
    let anchors = Selector::parse("a").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for (index, anchor) in document
        .select(&anchors)
        .filter(|node| !inert_element(*node))
        .enumerate()
    {
        let Some(handler) = anchor
            .value()
            .attr("onclick")
            .filter(|handler| handler.contains("MM_openBrWindow"))
        else {
            continue;
        };
        let target = legacy_popup_target(handler).ok_or_else(unavailable)?;
        // This root also opens non-notice pages with the same helper. Only the
        // declared PHP notice namespace establishes a notice row, not the popup
        // function name, title, position, or a guessed source date.
        if target
            .split(['?', '#'])
            .next()
            .and_then(|path| path.rsplit('/').next())
            != Some("call_board_detail.php")
        {
            continue;
        }
        if !legacy_notice_path(target)
            || anchor.value().attr("href") != Some("#")
            || entries.len() == MAX_ENTRIES
        {
            return Err(unavailable());
        }
        let resolved = base.join(target).map_err(|_| unavailable())?;
        if !legacy_history_source(resolved.as_str()) {
            return Err(unavailable());
        }
        let text = element_text(anchor);
        if text.is_empty() || text.len() > MAX_TEXT {
            return Err(unavailable());
        }
        entries.push(json!({
            "source_order":index + 1,"title":text,"date":null,"category_label":null,"summary":null,
            "listed_href":"#","declared_popup_target":target,"resolved_http_url":resolved.as_str(),
            "link_kind":"source_declared_popup",
        }));
    }
    if entries.is_empty() {
        return Err(unavailable());
    }
    Ok(json!({
        "schema_version":1,"type":"announcements_history","result":"listing_snapshot",
        "publisher":null,"college":"mse","listing_label":"legacy root source-declared popup notices",
        "document_title":title,"entries":entries,
        "completeness":{
            "scope":"single_supplied_archive_snapshot","pagination":"not_applicable","freshness":"archived_bytes",
            "complete_history":false,
            "source_layout":"observed root PHP-notice anchors and one complete inline three-argument popup helper; other popup namespaces are not notices; historical applicability is operator_asserted, not verified",
            "link_interpretation":"literal source declaration only; helper not executed and runtime navigation not verified",
        },
    }))
}

/// As in shared table admission, reject active text outside its retained owner;
/// inert payloads do not establish source prose or an alternate content scope.
fn legacy_unowned_text(scope: ElementRef<'_>, owners: &[ElementRef<'_>]) -> bool {
    scope.descendants().any(|node| {
        matches!(node.value(), Node::Text(text) if !text.trim().is_empty())
            && !node.ancestors().any(|ancestor| {
                owners.iter().any(|owner| owner.id() == ancestor.id())
                    || ElementRef::wrap(ancestor).is_some_and(crate::html::is_inert_context)
            })
    })
}

/// Observed PHP notice template: layout tables, not source data tables. The
/// unlabelled footer date is retained separately and never becomes publication.
pub(super) fn parse_legacy_article(document: &Html) -> Result<Value, Error> {
    legacy_charset_declared(document)?;
    let shells = Selector::parse("body > table > tbody").map_err(|_| unavailable())?;
    let mut shells = document
        .select(&shells)
        .filter(|node| !inert_element(*node));
    let shell = shells
        .next()
        .filter(|_| shells.next().is_none())
        .ok_or_else(unavailable)?;
    let rows = Selector::parse(":scope > tr").map_err(|_| unavailable())?;
    let mut rows = shell.select(&rows);
    let _banner = rows.next().ok_or_else(unavailable)?;
    let main = rows.next().ok_or_else(unavailable)?;
    let footer = rows
        .next()
        .filter(|_| rows.next().is_none())
        .ok_or_else(unavailable)?;
    let containers = Selector::parse(":scope > td > div").map_err(|_| unavailable())?;
    let mut containers = main.select(&containers);
    let container = containers
        .next()
        .filter(|_| containers.next().is_none())
        .ok_or_else(unavailable)?;
    let tables = Selector::parse(":scope > table").map_err(|_| unavailable())?;
    let mut tables = container.select(&tables);
    let header = tables
        .next()
        .filter(|table| {
            table
                .value()
                .has_class("underline", scraper::CaseSensitivity::CaseSensitive)
        })
        .ok_or_else(unavailable)?;
    let body_table = tables
        .next()
        .filter(|_| tables.next().is_none())
        .ok_or_else(unavailable)?;
    let titles =
        Selector::parse(":scope > tbody > tr > td.p20blue > div").map_err(|_| unavailable())?;
    let mut titles = header.select(&titles);
    let heading = titles
        .next()
        .filter(|_| titles.next().is_none())
        .ok_or_else(unavailable)?;
    let bodies = Selector::parse(":scope > tbody > tr > td.p20blue").map_err(|_| unavailable())?;
    let mut bodies = body_table.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(unavailable)?;
    if legacy_unowned_text(main, &[header, body_table])
        || legacy_unowned_text(header, &[heading])
        || legacy_unowned_text(body_table, &[body])
    {
        return Err(unavailable());
    }
    let nested_tables = Selector::parse("table").map_err(|_| unavailable())?;
    if body
        .select(&nested_tables)
        .filter(|node| !inert_element(*node))
        .any(|table| legacy_unowned_text(table, &[]))
    {
        return Err(failed_contract(
            "legacy notice contains an unreviewed nonempty nested table",
            file!(),
            line!(),
        ));
    }
    let title = element_text(heading);
    let body_text = element_text(body);
    let footer_text = element_text(footer);
    if title.is_empty()
        || title.len() > MAX_TEXT
        || body_text.is_empty()
        || body_text.len() > MAX_PARAGRAPH
        || footer_text.len() > MAX_TEXT
    {
        return Err(unavailable());
    }
    let links = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let mut attachment_hints = Vec::new();
    let mut attachments_found = false;
    for link in body.select(&links).filter(|node| !inert_element(*node)) {
        let href = link.value().attr("href").ok_or_else(unavailable)?;
        if is_document_href(href) {
            attachments_found = true;
            if attachment_hints.len() < MAX_ATTACHMENT_HINTS {
                attachment_hints.push(json!({"href":href,"text":element_text(link)}));
            }
        }
    }
    let media = Selector::parse("img, iframe, object, embed, audio, video, svg, canvas")
        .map_err(|_| unavailable())?;
    let nontext_present = body.select(&media).any(|node| !inert_element(node));
    let mut output = article_content(ArticleDocument {
        title,
        category: None,
        published_at: None,
        paragraphs: Vec::new(),
        attachment_hints,
        attachments_found,
    });
    output["body_text"] = Value::String(body_text);
    output["source_footer_date"] = json!(parse_iso_date(&footer_text));
    output["source_footer_text"] = Value::String(footer_text);
    output["completeness"]["body_source"] = json!(
        "legacy PHP notice: second outer layout row, direct header table.underline and separate td.p20blue body; source-ordered active text, no invented paragraphs or data-table grid"
    );
    output["completeness"]["footer_date_role"] =
        json!("unverified; source footer has no publication label and is not published_at");
    output["completeness"]["nontext_content_present"] = json!(nontext_present);
    if nontext_present || attachments_found {
        output["result"] = json!("partial_text");
        output["completeness"]["missing_nonparagraph_content"] =
            json!("image/embedded content and attachment bytes are not transcribed or fetched");
    }
    Ok(output)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CacheStatus, Response};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn listing(rows: &str) -> Html {
        Html::parse_document(&format!(
            "<div class=\"nymain\"><div class=\"w16\"><div class=\"ny-right\"><div class=\"notice-list\"><div><ul>{rows}</ul></div></div></div></div></div>"
        ))
    }

    fn source(header: &str, body: &str) -> Response {
        let html = format!(
            "<h3>Sidebar heading</h3><div class=\"nymain\"><div class=\"w16\"><div class=\"ny-right\"><form><div class=\"art-main\"><div class=\"art-tit cont-tit d\">{header}</div><div class=\"art-body-box\"><div class=\"art-body d\"><div class=\"ar_article\" id=\"vsb_content\"><div class=\"v_news_content\">{body}</div></div></div></div></div></form></div></div></div><div class=\"v_news_content\"><p>Unrelated paragraph.</p></div>"
        );
        Response {
            url: "https://mse.buaa.edu.cn/info/1058/42.htm".into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            sha256: format!("{:x}", Sha256::digest(html.as_bytes())),
            body: html.into_bytes(),
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn mse_listing_preserves_order_and_excludes_ambiguous_date_from_filter() {
        let document = listing(
            r#"<li><a href="../info/1061/42.htm" title="Not the visible heading"><span>2026.09.09</span><h3>Earlier visible heading<script>not source text</script></h3><p>Excerpt 2040-01-01 is not publication.</p></a></li>
            <li><a href="../info/1058/43.htm"><span>2026.09.15</span><span>2026.09.16</span><h3>Ambiguous publication</h3></a></li>
            <li><a href="../info/1058/44.htm"><span>2026.09.21</span><h3>Later visible heading</h3></a></li>"#,
        );
        let parsed = parse_notice_list(&document, &Url::parse(MSE_NOTICES_URL).unwrap()).unwrap();
        assert_eq!(
            parsed
                .entries
                .iter()
                .map(|row| row.title.as_str())
                .collect::<Vec<_>>(),
            vec![
                "Earlier visible heading",
                "Ambiguous publication",
                "Later visible heading"
            ]
        );
        assert_eq!(
            parsed.entries[0].summary.as_deref(),
            Some("Excerpt 2040-01-01 is not publication.")
        );
        assert_eq!(parsed.entries[1].date, None);
        let filtered = parsed
            .entries
            .iter()
            .filter(|row| {
                entry_in_scope(
                    row,
                    &Some("2026-09-15".into()),
                    &Some("2026-09-21".into()),
                    &None,
                )
            })
            .map(|row| row.title.as_str())
            .collect::<Vec<_>>();
        assert_eq!(filtered, vec!["Later visible heading"]);
    }

    #[test]
    fn mse_listing_refuses_duplicate_primary_views_and_original_headings() {
        let one = "<li><a href=\"../info/1061/42.htm\"><h3>Source heading</h3></a></li>";
        let original = listing(one);
        let duplicate = Html::parse_document(&format!("{}{}", original.html(), original.html()));
        let base = Url::parse(MSE_NOTICES_URL).unwrap();
        assert_eq!(
            parse_notice_list(&duplicate, &base).unwrap_err().code,
            "unavailable"
        );
        let duplicate_headings = listing(
            "<li><a href=\"../info/1061/42.htm\"><h3>First heading</h3><h3>Second heading</h3></a></li>",
        );
        assert_eq!(
            parse_notice_list(&duplicate_headings, &base)
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn mse_article_original_header_and_nonparagraph_table_content_stay_distinct() {
        let response = source(
            "<h3>Original article heading</h3><p><span class=\"date\">日期：2026年09月21日</span></p>",
            "<table><tr><td><span>Unextracted source cell.</span></td></tr></table><p>Original paragraph dated 2040-01-01.</p>",
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["title"], "Original article heading");
        assert_eq!(output["published_at"], "2026-09-21");
        assert_eq!(
            output["body_paragraphs"],
            json!(["Original paragraph dated 2040-01-01."])
        );
        assert_eq!(output["result"], "full_text");
        assert_eq!(
            output["body_tables"],
            json!([{"source_order":1,"caption":null,"rows":[{"cells":[{"header":false,"text":"Unextracted source cell."}]}]}])
        );

        let wrapped = source(
            "<h3>Original article heading</h3><p><span class=\"date\">日期：2026年09月21日</span><span class=\"date\">日期：2026年09月22日</span></p>",
            "<table><tr><td><p>Retained source cell.</p><script>inactive table data</script></td></tr></table><p>Final source paragraph.</p>",
        );
        let output = normalize(&wrapped, &college_html(&wrapped).unwrap()).unwrap();
        assert_eq!(output["published_at"], Value::Null);
        assert_eq!(
            output["body_paragraphs"],
            json!(["Retained source cell.", "Final source paragraph."])
        );
        assert_eq!(output["result"], "full_text");
        assert_eq!(output["completeness"]["unextracted_table_count"], 0);

        let table_only = source(
            "<h3>Original article heading</h3>",
            "<table><tr><td>Unextracted only.</td></tr></table>",
        );
        let output = normalize(&table_only, &college_html(&table_only).unwrap()).unwrap();
        assert_eq!(output["result"], "full_text");
        assert_eq!(output["body_paragraphs"], json!([]));
        assert_eq!(
            output["body_tables"][0]["rows"][0]["cells"],
            json!([{"header":false,"text":"Unextracted only."}])
        );
    }

    #[test]
    fn mse_tables_preserve_inline_order_declared_spans_and_active_scope() {
        let response = source(
            "<h3>Original table heading</h3>",
            "<template><table><tr><td>Inactive table.</td></tr></table></template><table><caption>Source caption</caption><tr><th colspan=\"2\">Heading</th></tr><tr><td rowspan=\"0\">Before <b>middle</b> after<script>inactive cell code</script></td><td>Tail</td></tr></table>",
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["body_paragraphs"], json!([]));
        assert_eq!(output["result"], "full_text");
        assert_eq!(
            output["body_tables"],
            json!([{
                "source_order":1,
                "caption":"Source caption",
                "rows":[
                    {"cells":[{"header":true,"text":"Heading","colspan":"2"}]},
                    {"cells":[{"header":false,"text":"Before middle after","rowspan":"0"},{"header":false,"text":"Tail"}]}
                ]
            }])
        );
    }

    #[test]
    fn mse_tables_preserve_decoded_span_strings_without_numeric_interpretation() {
        let response = source(
            "<h3>Original table heading</h3>",
            "<table><tr><td rowspan=\"&#10;2\" colspan=\"&#9;3\">Source cell.</td></tr></table>",
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(
            output["body_tables"][0]["rows"][0]["cells"],
            json!([{"header":false,"text":"Source cell.","rowspan":"\n2","colspan":"\t3"}])
        );
    }

    #[test]
    fn mse_table_row_budget_rejects_overflow_without_partial_success() {
        let bounded = source(
            "<h3>Original table heading</h3>",
            &format!(
                "<table>{}</table>",
                "<tr><td>Source cell.</td></tr>".repeat(MAX_BODY_PARAGRAPHS)
            ),
        );
        let output = normalize(&bounded, &college_html(&bounded).unwrap()).unwrap();
        assert_eq!(
            output["body_tables"][0]["rows"].as_array().unwrap().len(),
            MAX_BODY_PARAGRAPHS
        );
        assert_eq!(
            output["body_tables"][0]["rows"][MAX_BODY_PARAGRAPHS - 1]["cells"][0]["text"],
            "Source cell."
        );
        let overflow = source(
            "<h3>Original table heading</h3>",
            &format!(
                "<table>{}</table>",
                "<tr><td>Source cell.</td></tr>".repeat(MAX_BODY_PARAGRAPHS + 1)
            ),
        );
        assert_eq!(
            normalize(&overflow, &college_html(&overflow).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn mse_page_ordinal_uses_only_active_scoped_notice_pagination() {
        let base = Url::parse(MSE_NOTICES_URL).unwrap();
        let html = br#"<div class="pagestyle"><span class="p_no"><a href="gggs/99.htm">2</a></span></div><div class="nymain"><div class="ny-right"><div class="notice-list"><div><div class="pagestyle"><template><span class="p_no"><a href="gggs/98.htm">2</a></span></template><span class="p_no"><a href="gggs/8.htm">2</a></span></div></div></div></div></div>"#;
        let selected = advertised_page_url(
            html,
            &base,
            2,
            "div.nymain div.ny-right div.notice-list > div > div.pagestyle span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/xwdt/gggs/"),
        )
        .unwrap();
        assert_eq!(selected.as_str(), "https://mse.buaa.edu.cn/xwdt/gggs/8.htm");
        assert_eq!(
            advertised_page_url(
                html,
                &base,
                3,
                "div.nymain div.ny-right div.notice-list > div > div.pagestyle span.p_no a[href]",
                |url| plain_url(url) && url.path().starts_with("/xwdt/gggs/")
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
    }

    #[test]
    fn mse_excerpt_retains_full_source_paragraph_and_rejects_overflow() {
        let base = Url::parse(MSE_NOTICES_URL).unwrap();
        for excerpt in ["源".repeat(200), "x".repeat(super::super::MAX_PARAGRAPH)] {
            let document = listing(&format!(
                "<li><a href=\"../info/1061/42.htm\"><span>2026.09.21</span><h3>Source heading</h3><p>{excerpt}</p></a></li>"
            ));
            let parsed = parse_notice_list(&document, &base).unwrap();
            assert_eq!(parsed.entries[0].summary.as_deref(), Some(excerpt.as_str()));
        }
        let document = listing(&format!(
            "<li><a href=\"../info/1061/42.htm\"><h3>Source heading</h3><p>{}</p></a></li>",
            "x".repeat(super::super::MAX_PARAGRAPH + 1)
        ));
        assert_eq!(
            parse_notice_list(&document, &base).unwrap_err().code,
            "unavailable"
        );
    }
}
