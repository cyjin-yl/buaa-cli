//! Biological and medical engineering college announcements.
//!
//! The BME site is an older ASP.NET application.  Its retained information
//! board is a category portal (`newsList.aspx?catID=13`) rather than the
//! newer static notice-list layout used by several other colleges.  The
//! portal declares the article query URLs and exposes one bounded set of
//! source rows; ASP.NET pager postbacks are deliberately not replayed.

use super::{
    ArticleDocument, ListQuery, MAX_BODY_PARAGRAPHS, MAX_ENTRIES, MAX_HREF, MAX_PARAGRAPH,
    MAX_TEXT, article_output, bind_college_board, college_directory_attribution, college_html,
    describe_college_surface, element_text, entry_in_scope, failed_contract, html_fallback,
    invalid_article, invalid_list, is_admitted_html, is_safe_public_fallback, retrieval,
    unavailable,
};
use crate::net::{
    ArchiveClient, BME_NOTICES_URL, BME_ROOT_URL, CacheMode, Error, Response, bme_url_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://bme.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学生物与医学工程学院";
const CATEGORY: &str = "information";
const CATEGORY_LABEL: &str = "信息公告";
const DOCUMENT_EXTENSIONS: &[&str] = &[
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".txt", ".wps",
    ".ofd",
];

fn plain_url(url: &Url) -> bool {
    bme_url_allowed(url)
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
        "生物与医学工程学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = BME_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_bme(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => BME_ROOT_URL,
        "notices" => BME_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, BME_ROOT_URL, BME_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            if !is_admitted_html(response) {
                return Err(unavailable());
            }
            match describe_college_surface(response, "bme", attribution.clone()) {
                Ok(value) => Ok(value),
                Err(_) if is_safe_public_fallback(response) => Ok(html_fallback(
                    response,
                    "college_source_surface",
                    "bme",
                    "bme_surface_selector_contract",
                )),
                Err(error) => Err(error),
            }
        })
}

fn listing_url(page: u32) -> Result<Url, Error> {
    if page != 1 {
        return Err(Error::new(
            "unsupported",
            "Bme exposes only the retained information portal page; later ASP.NET postback pages are not followed",
        ));
    }
    Url::parse(BME_NOTICES_URL).map_err(|_| unavailable())
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
        .map(|raw| super::parse_iso_date(raw).ok_or_else(invalid_list))
        .transpose()?;
    let until = query
        .until
        .as_deref()
        .map(|raw| super::parse_iso_date(raw).ok_or_else(invalid_list))
        .transpose()?;
    let (client, mut attribution) = bound_client(mode)?;
    bind_college_board(&client, BME_ROOT_URL, BME_NOTICES_URL, &mut attribution)?;
    let target = listing_url(page)?;
    let result: Result<Value, Error> = client.with_cache_mode(mode).get(&target, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &target) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                let mut value = html_fallback(
                    response,
                    "announcements_list",
                    "bme",
                    "bme_listing_selector_contract",
                );
                value["category"] = json!(CATEGORY);
                value["page"] = json!(page);
                return Ok(Ok(value));
            }
            Err(error) => return Err(error),
        };
        let entries: Vec<_> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
            .collect();
        Ok(Ok(json!({
            "schema_version": 1,
            "type": "announcements_list",
            "result": "listing_snapshot",
            "publisher": PUBLISHER,
            "college": "bme",
            "category": CATEGORY,
            "listing_label": CATEGORY_LABEL,
            "page": page,
            "document_title": document.title,
            "filters": {"since": since, "until": until, "match": query.r#match},
            "entries": entries,
            "entry_count": entries.len(),
            "directory_attribution": attribution,
            "completeness": {
                "scope": "single_college_information_portal_page",
                "pagination": "retained_portal_page_only; ASP.NET postback pages are not followed",
                "other_colleges": "not_covered",
                "dates": "source bracketed ISO dates; missing, invalid or ambiguous stays null",
                "summaries": "source visible anchor text; title attributes retain the source full heading when present"
            },
            "retrieval": retrieval(response)
        })))
    })?;
    result
}

fn parse_listing(document: &Html, base: &Url) -> Result<super::ListingDocument, Error> {
    let titles = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&titles)
        .next()
        .map(element_text)
        .unwrap_or_default();
    if title.len() > MAX_TEXT {
        return Err(unavailable());
    }
    let tables = Selector::parse("table#DataList1").map_err(|_| unavailable())?;
    let mut tables = document
        .select(&tables)
        .filter(|table| !super::inert_element(*table));
    let table = tables.next().ok_or_else(|| {
        failed_contract(
            "Bme information portal requires one active DataList1 table",
            file!(),
            line!(),
        )
    })?;
    if tables.next().is_some() {
        return Err(failed_contract(
            "Bme information portal has ambiguous DataList1 tables",
            file!(),
            line!(),
        ));
    }
    let nested_tables = Selector::parse("table").map_err(|_| unavailable())?;
    if table
        .select(&nested_tables)
        .any(|nested| !super::inert_element(nested))
    {
        return Err(failed_contract(
            "Bme information portal requires non-nested category tables",
            file!(),
            line!(),
        ));
    }
    let rows = Selector::parse("tr").map_err(|_| unavailable())?;
    let cells = Selector::parse(":scope > td").map_err(|_| unavailable())?;
    let category_titles = Selector::parse("div.posTit").map_err(|_| unavailable())?;
    let item_rows = Selector::parse("ul > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in table
        .select(&rows)
        .filter(|row| !super::inert_element(*row))
    {
        for cell in row
            .select(&cells)
            .filter(|cell| !super::inert_element(*cell))
        {
            let mut category_nodes = cell.select(&category_titles);
            let category_node = category_nodes.next().ok_or_else(|| {
                failed_contract(
                    "Bme information portal category cell requires one posTit heading",
                    file!(),
                    line!(),
                )
            })?;
            if category_nodes.next().is_some() {
                return Err(failed_contract(
                    "Bme information portal category cell has ambiguous posTit headings",
                    file!(),
                    line!(),
                ));
            }
            let category = element_text(category_node);
            if category.is_empty() || category.len() > MAX_TEXT {
                return Err(failed_contract(
                    "Bme information portal category heading is empty or over budget",
                    file!(),
                    line!(),
                ));
            }
            for item in cell
                .select(&item_rows)
                .filter(|item| !super::inert_element(*item))
            {
                if entries.len() == MAX_ENTRIES {
                    return Err(failed_contract(
                        "Bme information portal exceeds the reviewed entry budget",
                        file!(),
                        line!(),
                    ));
                }
                let mut row_anchors = item.select(&anchors);
                let anchor = row_anchors.next().ok_or_else(|| {
                    failed_contract(
                        "Bme information portal row requires one direct article anchor",
                        file!(),
                        line!(),
                    )
                })?;
                if row_anchors.next().is_some() {
                    return Err(failed_contract(
                        "Bme information portal row has ambiguous article anchors",
                        file!(),
                        line!(),
                    ));
                }
                let visible_title = element_text(anchor);
                let title = anchor
                    .value()
                    .attr("title")
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or(visible_title.as_str())
                    .to_owned();
                if title.is_empty() || title.len() > MAX_TEXT || visible_title.len() > MAX_TEXT {
                    return Err(failed_contract(
                        "Bme information portal article heading is empty or over budget",
                        file!(),
                        line!(),
                    ));
                }
                let summary =
                    (visible_title != title && !visible_title.is_empty()).then_some(visible_title);
                let mut row_dates = item.select(&dates);
                let date = row_dates
                    .next()
                    .filter(|_| row_dates.next().is_none())
                    .and_then(|node| {
                        let raw = element_text(node);
                        let trimmed = raw.trim().trim_start_matches('[').trim_end_matches(']');
                        super::parse_iso_date(trimmed)
                    });
                let listed_href = anchor.value().attr("href");
                if listed_href
                    .is_some_and(|href| href.len() > MAX_HREF || href.chars().any(char::is_control))
                {
                    return Err(unavailable());
                }
                let (resolved_http_url, link_kind) = match listed_href {
                    None => (None, "missing"),
                    Some(raw) => match base.join(raw) {
                        Ok(url) if plain_url(&url) => (Some(url.to_string()), "http"),
                        Ok(url) if matches!(url.scheme(), "http" | "https") => {
                            (Some(url.to_string()), "out_of_scope")
                        }
                        Ok(_) => (None, "non_http"),
                        Err(_) => (None, "invalid"),
                    },
                };
                entries.push(super::ListingEntry {
                    source_order: entries.len() + 1,
                    title,
                    date,
                    category_label: Some(category.clone()),
                    summary,
                    listed_href: listed_href.map(str::to_owned),
                    resolved_http_url,
                    link_kind,
                });
            }
        }
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "Bme information portal has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(super::ListingDocument { title, entries })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || source_page != 1
        || target.path() != "/newsInfo.aspx"
    {
        return Err(invalid_article());
    }
    let (client, attribution) = bound_client(mode)?;
    article_with_client(client, mode, &target, attribution)
}

fn article_with_client(
    client: ArchiveClient,
    mode: CacheMode,
    target: &Url,
    mut attribution: Value,
) -> Result<Value, Error> {
    bind_college_board(&client, BME_ROOT_URL, BME_NOTICES_URL, &mut attribution)?;
    let source = listing_url(1)?;
    let listing_result: Result<Value, Error> = client.get(&source, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &source) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(Ok(html_fallback(
                    response,
                    "announcements_list",
                    "bme",
                    "bme_listing_selector_contract",
                )));
            }
            Err(error) => return Err(error),
        };
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            super::refuse_unsafe_listing(response, &html)?;
            return Ok(Err(Error::new(
                "unsupported",
                "retained Bme information portal does not declare the selected article",
            )));
        }
        Ok(Ok(retrieval(response)))
    })?;
    let listing = listing_result?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained BME listing could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client.with_cache_mode(mode).get(target, false, |response| {
        let document = match college_html(response) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_article",
                    "bme",
                    "bme_article_selector_contract",
                ));
            }
            Err(error) => return Err(error),
        };
        let mut value = match normalize(response, &document) {
            Ok(value) => value,
            Err(_) if is_safe_public_fallback(response) => html_fallback(
                response,
                "announcements_article",
                "bme",
                "bme_article_selector_contract",
            ),
            Err(error) => return Err(error),
        };
        value["publisher"] = json!(PUBLISHER);
        value["college"] = json!("bme");
        value["directory_attribution"] = attribution.clone();
        value["source_listing"] = listing.clone();
        Ok(value)
    })
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
    let mut output = SourceTables {
        values: Vec::new(),
        row_count: 0,
        cell_count: 0,
        has_text: false,
    };
    for table in body
        .select(&tables)
        .filter(|table| !super::inert_element(*table))
    {
        if output.values.len() == MAX_ENTRIES
            || table
                .select(&tables)
                .any(|nested| !super::inert_element(nested))
        {
            return Err(failed_contract(
                "Bme source tables require bounded non-nested active tables",
                file!(),
                line!(),
            ));
        }
        let mut caption_nodes = table.select(&captions);
        let caption = caption_nodes.next().map(element_text);
        if caption_nodes.next().is_some()
            || caption
                .as_ref()
                .is_some_and(|value| value.len() > MAX_PARAGRAPH)
        {
            return Err(failed_contract(
                "Bme table caption is ambiguous or over budget",
                file!(),
                line!(),
            ));
        }
        output.has_text |= caption.as_ref().is_some_and(|value| !value.is_empty());
        let mut source_rows = Vec::new();
        for row in table
            .select(&rows)
            .filter(|row| !super::inert_element(*row))
        {
            if output.row_count == MAX_BODY_PARAGRAPHS {
                return Err(failed_contract(
                    "Bme table rows exceed the reviewed text budget",
                    file!(),
                    line!(),
                ));
            }
            let mut source_cells = Vec::new();
            let mut row_bytes = 0usize;
            for cell in row
                .select(&cells)
                .filter(|cell| !super::inert_element(*cell))
            {
                if source_cells.len() == MAX_ENTRIES {
                    return Err(failed_contract(
                        "Bme table row exceeds the reviewed cell budget",
                        file!(),
                        line!(),
                    ));
                }
                let text = element_text(cell);
                row_bytes = row_bytes.saturating_add(text.len());
                if row_bytes > MAX_PARAGRAPH {
                    return Err(failed_contract(
                        "Bme table row text exceeds the reviewed byte budget",
                        file!(),
                        line!(),
                    ));
                }
                output.has_text |= !text.is_empty();
                let mut value = json!({"header": cell.value().name() == "th", "text": text});
                for span in ["rowspan", "colspan"] {
                    if let Some(raw) = cell.value().attr(span) {
                        if raw.len() > MAX_TEXT {
                            return Err(failed_contract(
                                "Bme table span attribute exceeds the reviewed text budget",
                                file!(),
                                line!(),
                            ));
                        }
                        value[span] = Value::String(raw.to_owned());
                    }
                }
                source_cells.push(value);
            }
            output.row_count += 1;
            output.cell_count += source_cells.len();
            source_rows.push(json!({"cells": source_cells}));
        }
        output.values.push(json!({
            "source_order": output.values.len() + 1,
            "caption": caption.map(Value::String).unwrap_or(Value::Null),
            "rows": source_rows
        }));
    }
    Ok(output)
}

fn is_document_href(href: &str) -> bool {
    let path = href.split(['?', '#']).next().unwrap_or(href);
    let lower = path.to_ascii_lowercase();
    DOCUMENT_EXTENSIONS
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let infos = Selector::parse("div.newsInfo").map_err(|_| unavailable())?;
    let mut infos = document
        .select(&infos)
        .filter(|node| !super::inert_element(*node));
    let info = infos.next().ok_or_else(|| {
        failed_contract(
            "Bme article requires one active newsInfo container",
            file!(),
            line!(),
        )
    })?;
    if infos.next().is_some() {
        return Err(failed_contract(
            "Bme article has ambiguous newsInfo containers",
            file!(),
            line!(),
        ));
    }
    let headings = Selector::parse(":scope > div.newsInfoTit > h3").map_err(|_| unavailable())?;
    let mut headings = info.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "Bme article requires one direct newsInfoTit/h3 heading",
                file!(),
                line!(),
            )
        })?;
    let body_nodes = Selector::parse(":scope > div").map_err(|_| unavailable())?;
    let mut bodies = info
        .select(&body_nodes)
        .filter(|node| node.value().attr("class") != Some("newsInfoTit"));
    let body = bodies.next().ok_or_else(|| {
        failed_contract(
            "Bme article requires one direct newsInfo body container",
            file!(),
            line!(),
        )
    })?;
    if bodies.next().is_some() {
        return Err(failed_contract(
            "Bme article has ambiguous direct newsInfo body containers",
            file!(),
            line!(),
        ));
    }
    let paragraphs_selector = Selector::parse("p").map_err(|_| unavailable())?;
    let mut paragraphs = Vec::new();
    for paragraph in body
        .select(&paragraphs_selector)
        .filter(|paragraph| !super::inert_element(*paragraph))
    {
        let text = element_text(paragraph);
        if text.is_empty() {
            continue;
        }
        if paragraphs.len() == MAX_BODY_PARAGRAPHS || text.len() > MAX_PARAGRAPH {
            return Err(failed_contract(
                "Bme article paragraphs exceed the reviewed text budget",
                file!(),
                line!(),
            ));
        }
        paragraphs.push(text);
    }
    let tables = source_tables(body)?;
    let links = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let mut attachment_hints = Vec::new();
    let mut attachments_found = false;
    for anchor in body
        .select(&links)
        .filter(|anchor| !super::inert_element(*anchor))
    {
        let href = anchor.value().attr("href").unwrap_or_default();
        if !is_document_href(href) {
            continue;
        }
        attachments_found = true;
        if attachment_hints.len() < super::MAX_ATTACHMENT_HINTS {
            attachment_hints.push(json!({
                "href": href,
                "text": element_text(anchor),
                "fetched": false
            }));
        }
    }
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let has_images = body
        .select(&images)
        .any(|image| !super::inert_element(image));
    if paragraphs.is_empty() && !tables.has_text {
        return Err(failed_contract(
            "Bme article must contain source paragraph or table text",
            file!(),
            line!(),
        ));
    }
    if paragraphs.len() + tables.row_count > MAX_BODY_PARAGRAPHS {
        return Err(failed_contract(
            "Bme article paragraphs and table rows exceed the reviewed text budget",
            file!(),
            line!(),
        ));
    }
    let url = Url::parse(&response.url).map_err(|_| unavailable())?;
    let category = url
        .query_pairs()
        .find_map(|(key, value)| (key == "subcatID").then(|| value.into_owned()));
    let mut output = article_output(
        response,
        ArticleDocument {
            title,
            category,
            published_at: None,
            paragraphs,
            attachment_hints,
            attachments_found,
        },
    );
    output["completeness"]["body_source"] = json!(
        "unique newsInfo/newsInfoTit and direct newsInfo body; active p text plus separate ordered flat-table captions/rows/cells; code and fallback payloads excluded"
    );
    output["body_table_count"] = json!(tables.values.len());
    output["body_table_row_count"] = json!(tables.row_count);
    output["body_table_cell_count"] = json!(tables.cell_count);
    output["body_tables"] = Value::Array(tables.values);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn listing() -> Html {
        Html::parse_document(
            r#"<title>BME</title><table id="DataList1"><tr>
                <td><div class="posTit"><span><a href="news.aspx?catID=13&amp;subcatID=46"><img src="more.gif"/></a></span>通知公告</div>
                <ul><li><span>[2026-10-11]</span><a href="newsInfo.aspx?catID=13&amp;subcatID=46&amp;curID=14781" title="完整公告标题">完整公告标题...</a></li>
                <li><span>[2025-01-02]</span><a href="newsInfo.aspx?catID=13&amp;subcatID=46&amp;curID=2">可见标题</a></li></ul></td>
                <td><div class="posTit">综合信息</div><ul><li><span>[2026-03-16]</span><a href="newsInfo.aspx?catID=13&amp;subcatID=45&amp;curID=14715">综合标题</a></li></ul></td>
            </tr></table>"#,
        )
    }

    #[test]
    fn bme_listing_preserves_category_order_and_title_attribute() {
        let base = Url::parse(BME_NOTICES_URL).unwrap();
        let parsed = parse_listing(&listing(), &base).unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[0].source_order, 1);
        assert_eq!(
            parsed.entries[0].category_label.as_deref(),
            Some("通知公告")
        );
        assert_eq!(parsed.entries[0].title, "完整公告标题");
        assert_eq!(
            parsed.entries[0].summary.as_deref(),
            Some("完整公告标题...")
        );
        assert_eq!(parsed.entries[0].date.as_deref(), Some("2026-10-11"));
        assert_eq!(
            parsed.entries[2].category_label.as_deref(),
            Some("综合信息")
        );
        assert_eq!(parsed.entries[2].date.as_deref(), Some("2026-03-16"));
        let filtered = parsed
            .entries
            .iter()
            .filter(|entry| {
                entry_in_scope(
                    entry,
                    &Some("2026-01-01".into()),
                    &Some("2026-12-31".into()),
                    &None,
                )
            })
            .map(|entry| entry.title.as_str())
            .collect::<Vec<_>>();
        assert_eq!(filtered, vec!["完整公告标题", "综合标题"]);
    }

    #[test]
    fn bme_article_scopes_heading_body_tables_and_hints() {
        let html = r#"<html><body><h3>Sidebar</h3><div class="newsInfo"><div class="newsInfoTit"><h3>Original heading</h3></div><div style="padding:0 10px"><p>Paragraph one.</p><table><caption>Source table</caption><tr><th colspan="2">Head</th></tr><tr><td>Cell A</td><td><p>Cell B</p></td></tr></table><script><p>inactive</p></script><a href="/files/source.pdf">source</a></div></div></body></html>"#;
        let response = Response {
            url: "https://bme.buaa.edu.cn/newsInfo.aspx?catID=13&subcatID=46&curID=14781".into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            sha256: format!("{:x}", Sha256::digest(html.as_bytes())),
            body: html.as_bytes().to_vec(),
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        };
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["title"], "Original heading");
        assert_eq!(output["published_at"], Value::Null);
        assert_eq!(
            output["body_paragraphs"],
            json!(["Paragraph one.", "Cell B"])
        );
        assert_eq!(output["body_table_count"], 1);
        assert_eq!(
            output["body_tables"][0]["rows"][1]["cells"][0]["text"],
            "Cell A"
        );
        assert_eq!(output["result"], "partial_text");
        assert_eq!(output["attachments"]["found"], true);
    }

    #[test]
    fn bme_listing_rejects_ambiguous_or_foreign_article_urls() {
        let base = Url::parse(BME_NOTICES_URL).unwrap();
        let document = Html::parse_document(
            r#"<table id="DataList1"><tr><td><div class="posTit">通知公告</div><ul><li><span>[2026-01-01]</span><a href="https://foreign.example/article" title="Foreign">Foreign</a></li></ul></td></tr></table>"#,
        );
        let parsed = parse_listing(&document, &base).unwrap();
        assert_eq!(
            parsed.entries[0].resolved_http_url,
            Some("https://foreign.example/article".into())
        );
        assert_eq!(parsed.entries[0].link_kind, "out_of_scope");
        assert_eq!(listing_url(2).unwrap_err().code, "unsupported");
    }

    #[test]
    fn review_regression_bme_nested_category_table_is_not_published_twice() {
        let document = Html::parse_document(
            r#"<title>BME</title><table id="DataList1"><tr><td><table><tr><td><div class="posTit">通知公告</div><ul><li><span>[2026-01-01]</span><a href="newsInfo.aspx?catID=13&amp;subcatID=46&amp;curID=1" title="One">One</a></li></ul></td></tr></table></td></tr></table>"#,
        );
        match parse_listing(&document, &Url::parse(BME_NOTICES_URL).unwrap()) {
            Ok(parsed) => {
                assert_eq!(parsed.entries.len(), 1);
                assert_eq!(parsed.entries[0].source_order, 1);
                assert_eq!(parsed.entries[0].title, "One");
            }
            Err(error) => assert_eq!(error.code, "unavailable"),
        }
    }
}
