//! 数学科学学院: exact-directory-bound current notice board.
use super::{
    ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_PARAGRAPH, MAX_TEXT,
    active_element_text, article_paragraphs, bind_college_board, college_directory_attribution,
    college_html, describe_college_surface, element_text, entry_in_scope, failed_contract,
    html_fallback, inert_element, invalid_article, invalid_list, is_document_href, is_http,
    is_safe_public_fallback, parse_iso_date, retrieval, source_tables, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, MATH_NOTICES_URL, MATH_ROOT_URL, math_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://math.buaa.edu.cn/";
pub(super) const PUBLISHER: &str = "北京航空航天大学数学科学学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("math.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && math_path_allowed(url.path())
}

pub(super) fn root_listing_source(raw: &str) -> bool {
    raw == LISTED_ROOT_URL
}

fn unique_owned<'a>(parent: ElementRef<'a>, selector: &Selector) -> Result<ElementRef<'a>, Error> {
    let mut nodes = parent.select(selector).filter(|node| !inert_element(*node));
    nodes
        .next()
        .filter(|_| nodes.next().is_none())
        .ok_or_else(unavailable)
}

/// Only the supplied root's source-selected 学院公告 view, not a board body.
pub(super) fn parse_root_listing(document: &Html, base: &Url) -> Result<Value, Error> {
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
    let headers =
        Selector::parse("div.wrapgg > div.w_top > li.hover").map_err(|_| unavailable())?;
    let mut headers = document
        .select(&headers)
        .filter(|node| !inert_element(*node) && element_text(*node) == "学院公告");
    let selected = headers
        .next()
        .filter(|_| headers.next().is_none())
        .ok_or_else(unavailable)?;
    let header = selected
        .parent()
        .and_then(ElementRef::wrap)
        .ok_or_else(unavailable)?;
    let primary = header
        .parent()
        .and_then(ElementRef::wrap)
        .ok_or_else(unavailable)?;
    let labels = Selector::parse(":scope > li:not(.more)").map_err(|_| unavailable())?;
    let active = Selector::parse(":scope > li.hover").map_err(|_| unavailable())?;
    let mut active = header.select(&active).filter(|node| !inert_element(*node));
    if header
        .select(&labels)
        .find(|node| !inert_element(*node))
        .is_none_or(|first| first.id() != selected.id())
        || active.next().is_none_or(|node| node.id() != selected.id())
        || active.next().is_some()
    {
        return Err(unavailable());
    }
    // The observed first label/body and first More declaration belong together.
    // Source markers are not evaluated CSS or verified runtime visibility.
    let more = Selector::parse(":scope > li.more > a").map_err(|_| unavailable())?;
    let more = header
        .select(&more)
        .find(|node| !inert_element(*node))
        .ok_or_else(unavailable)?;
    let board_href = more.value().attr("href").ok_or_else(unavailable)?;
    if board_href.len() > MAX_HREF || board_href.chars().any(char::is_control) {
        return Err(unavailable());
    }
    let (board_url, board_link_kind) = match base.join(board_href) {
        Ok(url) if is_http(&url) => (Some(url.to_string()), "http"),
        Ok(_) => (None, "non_http"),
        Err(_) => (None, "invalid"),
    };
    let views = Selector::parse(":scope > div.hover").map_err(|_| unavailable())?;
    let mut views = primary.select(&views).filter(|node| !inert_element(*node));
    let view = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(unavailable)?;
    let lists = Selector::parse(":scope > ul").map_err(|_| unavailable())?;
    let mut lists = view.select(&lists).filter(|node| !inert_element(*node));
    let list = lists
        .next()
        .filter(|_| lists.next().is_none())
        .ok_or_else(unavailable)?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let links = Selector::parse(":scope > a").map_err(|_| unavailable())?;
    let headings = Selector::parse(":scope > p").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > div.date").map_err(|_| unavailable())?;
    let days = Selector::parse(":scope > div.date_t").map_err(|_| unavailable())?;
    let months = Selector::parse(":scope > div.date_b").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in list.select(&rows).filter(|node| !inert_element(*node)) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut anchors = row.select(&links).filter(|node| !inert_element(*node));
        let anchor = anchors
            .next()
            .filter(|_| anchors.next().is_none())
            .ok_or_else(unavailable)?;
        let mut row_headings = anchor
            .select(&headings)
            .filter(|node| !inert_element(*node));
        let heading = row_headings
            .next()
            .filter(|_| row_headings.next().is_none())
            .map(element_text)
            .filter(|text| !text.is_empty() && text.len() <= MAX_TEXT)
            .ok_or_else(unavailable)?;
        let date = (|| {
            let mut date_nodes = anchor.select(&dates).filter(|node| !inert_element(*node));
            let date = date_nodes.next().filter(|_| date_nodes.next().is_none())?;
            let mut day_nodes = date.select(&days).filter(|node| !inert_element(*node));
            let day = day_nodes
                .next()
                .filter(|_| day_nodes.next().is_none())
                .map(element_text)?;
            let mut month_nodes = date.select(&months).filter(|node| !inert_element(*node));
            let month = month_nodes
                .next()
                .filter(|_| month_nodes.next().is_none())
                .map(element_text)?;
            if !(1..=2).contains(&day.len())
                || !day.bytes().all(|byte| byte.is_ascii_digit())
                || month.len() != 7
            {
                return None;
            }
            let mut iso = *b"0000-00-00";
            iso[..7].copy_from_slice(month.as_bytes());
            iso[10 - day.len()..].copy_from_slice(day.as_bytes());
            parse_iso_date(std::str::from_utf8(&iso).ok()?)
        })();
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
            title: heading,
            date,
            category_label: Some("学院公告".into()),
            summary: None,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(unavailable());
    }
    Ok(json!({
        "schema_version":1,"type":"announcements_history","result":"listing_snapshot",
        "publisher":null,"college":"math","listing_label":"学院公告（根页历史预览）",
        "document_title":title,"entries":entries,
        "source_board_declaration":{
            "listed_href":board_href,"resolved_http_url":board_url,"link_kind":board_link_kind,
        },
        "completeness":{
            "scope":"single_supplied_archive_root_notice_view","pagination":"not_applicable",
            "freshness":"archived_bytes","complete_history":false,
            "source_layout":"observed root wrapgg first source-selected 学院公告 label/body; not evaluated CSS or verified runtime visibility; historical applicability is operator_asserted, not verified",
            "dates":"each row's own explicit YYYY-MM and day; missing, invalid or ambiguous stays null; never capture-derived",
            "source_board":"declaration only; board body not supplied or fetched",
            "other_root_views":"not_covered",
        },
    }))
}

/// The supplied historical root's separate image-declared text view, not its board.
pub(super) fn parse_root_news_listing(document: &Html, base: &Url) -> Result<Value, Error> {
    let selector = |raw| Selector::parse(raw).map_err(|_| unavailable());
    let title = element_text(unique_owned(
        document.root_element(),
        &selector("head > title")?,
    )?);
    if title.is_empty() || title.len() > MAX_TEXT {
        return Err(unavailable());
    }
    let declarations = selector("div.xwdt > div.xw > div.lm > a")?;
    let mut declarations = document.select(&declarations).filter(|node| {
        !inert_element(*node) && node.value().attr("href") == Some("index/xydt.htm")
    });
    let declaration = declarations
        .next()
        .filter(|_| declarations.next().is_none())
        .ok_or_else(unavailable)?;
    let header = declaration
        .parent()
        .and_then(ElementRef::wrap)
        .ok_or_else(unavailable)?;
    let owner = header
        .parent()
        .and_then(ElementRef::wrap)
        .ok_or_else(unavailable)?;
    let links = selector(":scope > a")?;
    if unique_owned(owner, &selector(":scope > div.lm")?)?.id() != header.id()
        || unique_owned(header, &links)?.id() != declaration.id()
        || !element_text(declaration).is_empty()
    {
        return Err(unavailable());
    }
    unique_owned(declaration, &selector(":scope > img")?)?;
    let body = unique_owned(owner, &selector(":scope > ul")?)?;
    let rows = selector(":scope > li")?;
    let contents = selector(":scope > div.ftxt")?;
    let heading_links = selector(":scope > a:not(.more)")?;
    let headings = selector(":scope > h3")?;
    let summaries = selector(":scope > p")?;
    let images = selector(":scope > div.fimg > a")?;
    let details = selector(":scope > a.more")?;
    let featured_dates = selector(":scope > div.time")?;
    let ordinary_dates = selector(":scope > span.date")?;
    let mut entries = Vec::new();
    let mut featured_seen = false;
    for row in body.select(&rows).filter(|node| !inert_element(*node)) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let featured = row
            .value()
            .has_class("first", scraper::CaseSensitivity::CaseSensitive);
        let (anchor, heading, summary, date_owner, date_selector) = if featured {
            if featured_seen || !entries.is_empty() {
                return Err(unavailable());
            }
            featured_seen = true;
            let content = unique_owned(row, &contents)?;
            let anchor = unique_owned(content, &heading_links)?;
            let href = anchor.value().attr("href").ok_or_else(unavailable)?;
            if unique_owned(row, &images)?.value().attr("href") != Some(href)
                || unique_owned(content, &details)?.value().attr("href") != Some(href)
            {
                return Err(unavailable());
            }
            let heading = element_text(unique_owned(anchor, &headings)?);
            let summary = element_text(unique_owned(content, &summaries)?);
            if summary.len() > MAX_PARAGRAPH {
                return Err(unavailable());
            }
            (
                anchor,
                heading,
                Some(summary).filter(|text| !text.is_empty()),
                content,
                &featured_dates,
            )
        } else {
            let anchor = unique_owned(row, &links)?;
            (anchor, element_text(anchor), None, row, &ordinary_dates)
        };
        if heading.is_empty() || heading.len() > MAX_TEXT {
            return Err(unavailable());
        }
        let date = if let Ok(node) = unique_owned(date_owner, date_selector) {
            if node
                .children()
                .any(|child| child.value().as_element().is_some())
            {
                None
            } else {
                let text = element_text(node);
                if text.len() > MAX_TEXT {
                    return Err(unavailable());
                }
                parse_iso_date(&text)
            }
        } else {
            None
        };
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
            title: heading,
            date,
            category_label: None,
            summary,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if !featured_seen {
        return Err(unavailable());
    }
    Ok(json!({
        "schema_version":1,"type":"announcements_history","result":"listing_snapshot",
        "publisher":null,"college":"math","listing_label":"根页新闻区（离线预览）",
        "document_title":title,"source_view_caption":null,"entries":entries,
        "source_board_declaration":{
            "listed_href":"index/xydt.htm","resolved_http_url":base.join("index/xydt.htm").map_err(|_| unavailable())?.to_string(),"link_kind":"http",
        },
        "completeness":{
            "scope":"single_supplied_archive_root_news_view","pagination":"not_applicable",
            "freshness":"archived_bytes","complete_history":false,
            "source_layout":"observed xwdt/xw owner with its own lm/a image-only index/xydt.htm declaration and direct ul/li text records; first/ftxt heading and full excerpt precede ordinary rows; not evaluated scripts, CSS or runtime visibility; historical applicability is operator_asserted, not verified",
            "dates":"each unique own leaf div.time or span.date must contain a complete calendar-valid YYYY-MM-DD; missing, invalid, nested or ambiguous stays null, never heading, href, neighbor or capture-derived",
            "summaries":"complete featured ftxt/p source text up to 8 KiB; ordinary records have no supplied excerpt and stay null",
            "caption":"image-only control supplies no active source caption or category; image is not fetched or interpreted",
            "source_board":"declaration only; board body not supplied or fetched; navigation xyzj/xydt.htm is distinct, not an alias",
            "other_root_views":"not_covered",
        },
    }))
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
        "数学科学学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = MATH_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_math(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => MATH_ROOT_URL,
        "notices" => MATH_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, MATH_ROOT_URL, MATH_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            if !is_safe_public_fallback(response) {
                return Err(unavailable());
            }
            match describe_college_surface(response, "math", attribution.clone()) {
                Ok(value) => Ok(value),
                Err(_) => Ok(html_fallback(
                    response,
                    "college_source_surface",
                    "math",
                    "math_surface_selector_contract",
                )),
            }
        })
}

fn parse_math_date(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let mut bytes: [u8; 10] = raw.as_bytes().try_into().ok()?;
    if bytes[4] != b'/' || bytes[7] != b'/' {
        return None;
    }
    bytes[4] = b'-';
    bytes[7] = b'-';
    parse_iso_date(std::str::from_utf8(&bytes).ok()?)
}

pub(super) fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let title = document
        .select(&Selector::parse("head > title").map_err(|_| unavailable())?)
        .find(|node| !inert_element(*node))
        .map(element_text)
        .unwrap_or_default();
    if title.len() > MAX_TEXT {
        return Err(unavailable());
    }
    let views = Selector::parse("div.list_main > div.list_main_right > div.list_box > ul")
        .map_err(|_| unavailable())?;
    let mut views = document.select(&views).filter(|node| !inert_element(*node));
    let primary = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Math notices require one list_main/list_box view",
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
                    "Math notice row requires one direct title link",
                    file!(),
                    line!(),
                )
            })?;
        let title = element_text(anchor);
        if title.is_empty() || title.len() > MAX_TEXT {
            return Err(failed_contract(
                "Math notice link requires source text",
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
        let mut row_dates = row.select(&dates).filter(|node| !inert_element(*node));
        let date = row_dates
            .next()
            .filter(|_| row_dates.next().is_none())
            .and_then(|node| parse_math_date(&element_text(node)));
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
            category_label: Some("学院公告".into()),
            summary: None,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "Math notice view has no source rows",
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
        .is_some_and(|category| category != "xygg")
        || query.page.is_some_and(|page| page != 1)
    {
        return Err(invalid_list());
    }
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
    bind_college_board(&client, MATH_ROOT_URL, MATH_NOTICES_URL, &mut attribution)?;
    let target = Url::parse(MATH_NOTICES_URL).map_err(|_| unavailable())?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = match college_html(response).and_then(|html| parse_listing(&html, &target)) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                let mut value = html_fallback(
                    response,
                    "announcements_list",
                    "math",
                    "math_listing_selector_contract",
                );
                value["category"] = json!("xygg");
                value["page"] = json!(1);
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
            "schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"math","category":"xygg","listing_label":"学院公告","page":1,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"retained board exposes only page1; no source-advertised later ordinal and no automatic traversal","other_colleges":"not_covered","dates":"source YYYY/MM/DD; missing, invalid or ambiguous stays null","summaries":"not supplied by this source view; not reconstructed","external_links":"retained listing references only; never fetched"},
            "retrieval":retrieval(response)
        }))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1294/")
        || source_page != 1
    {
        return Err(invalid_article());
    }
    let (client, attribution) = bound_client(mode)?;
    article_with_client(client, mode, &target, attribution)
}

pub(crate) fn article_with_client(
    client: ArchiveClient,
    mode: CacheMode,
    target: &Url,
    mut attribution: Value,
) -> Result<Value, Error> {
    bind_college_board(&client, MATH_ROOT_URL, MATH_NOTICES_URL, &mut attribution)?;
    let source = Url::parse(MATH_NOTICES_URL).map_err(|_| unavailable())?;
    let listing_result: Result<Value, Error> = client.get(&source, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &source) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(Ok(html_fallback(
                    response,
                    "announcements_list",
                    "math",
                    "math_listing_selector_contract",
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
                "retained Math notice page does not declare the selected article",
            )));
        }
        Ok(Ok(retrieval(response)))
    })?;
    let listing = listing_result?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained Math listing could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client.with_cache_mode(mode).get(target, false, |response| {
        let document = match college_html(response) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_article",
                    "math",
                    "math_article_selector_contract",
                ));
            }
            Err(error) => return Err(error),
        };
        let mut output = match parse_article(&document) {
            Ok(output) => output,
            Err(_) if is_safe_public_fallback(response) => html_fallback(
                response,
                "announcements_article",
                "math",
                "math_article_selector_contract",
            ),
            Err(error) => return Err(error),
        };
        output["retrieval"] = retrieval(response);
        output["publisher"] = json!(PUBLISHER);
        output["college"] = json!("math");
        output["directory_attribution"] = attribution.clone();
        output["source_listing"] = listing.clone();
        Ok(output)
    })
}

fn math_publication_date(raw: &str) -> Option<String> {
    let mut occurrences = raw.match_indices("发布日期：");
    let (offset, _) = occurrences.next()?;
    if occurrences.next().is_some() {
        return None;
    }
    let value = &raw[offset + "发布日期：".len()..];
    parse_iso_date(value.split_whitespace().next()?)
}

pub(super) fn parse_article(document: &Html) -> Result<Value, Error> {
    let forms =
        Selector::parse("div.icontent > div.c-content > form").map_err(|_| unavailable())?;
    let mut forms = document.select(&forms).filter(|node| !inert_element(*node));
    let primary = forms
        .next()
        .filter(|_| forms.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Math article requires one icontent/c-content form",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > h1.c-title").map_err(|_| unavailable())?;
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
                "Math article requires one direct c-title heading",
                file!(),
                line!(),
            )
        })?;
    let dates = Selector::parse(":scope > div.other-s").map_err(|_| unavailable())?;
    let mut dates = primary.select(&dates).filter(|node| !inert_element(*node));
    let published_at = dates
        .next()
        .filter(|_| dates.next().is_none())
        .and_then(|node| math_publication_date(&element_text(node)));
    let bodies = Selector::parse(":scope > div#vsb_content.nr-info > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = primary.select(&bodies).filter(|node| !inert_element(*node));
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Math article requires one owned vsb_content/nr-info/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let tables = source_tables(body)?;
    let paragraphs = article_paragraphs(body, tables.has_text)?;
    if paragraphs.len() + tables.row_count > super::MAX_BODY_PARAGRAPHS {
        return Err(failed_contract(
            "Math article paragraphs and table rows exceed the reviewed text budget",
            file!(),
            line!(),
        ));
    }
    let links = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let mut attachment_hints = Vec::new();
    let mut attachments_found = false;
    for node in body.select(&links).filter(|node| !inert_element(*node)) {
        let Some(href) = node.value().attr("href") else {
            continue;
        };
        if !is_document_href(href) {
            continue;
        }
        attachments_found = true;
        if attachment_hints.len() < super::MAX_ATTACHMENT_HINTS {
            attachment_hints.push(json!({
                "href": href,
                "text": active_element_text(node),
                "fetched": false,
            }));
        }
    }
    let has_images = Selector::parse("img").map_err(|_| unavailable())?;
    let images = body.select(&has_images).any(|node| !inert_element(node));
    let partial = attachments_found || images || !tables.values.is_empty();
    Ok(json!({
        "schema_version":1,"type":"announcements_article","result":if partial {"partial_text"} else {"full_text"},
        "publisher":PUBLISHER,"college":"math","category":"1294","title":title,
        "published_at":published_at,"body_paragraph_count":paragraphs.len(),"body_paragraphs":paragraphs,
        "body_table_count":tables.values.len(),"body_table_row_count":tables.row_count,"body_table_cell_count":tables.cell_count,"body_tables":tables.values,
        "attachments":{"found":attachments_found,"hints":attachment_hints,"hints_truncated":attachments_found && attachment_hints.len() == super::MAX_ATTACHMENT_HINTS,"note":"source-declared links only; never fetched"},
        "completeness":{"scope":"single_math_article_page","body_source":"unique icontent/c-content form and scoped v_news_content paragraphs; executable/fallback markup excluded","table_representation":"source cells only; no inferred spans or visual reconstruction","image_content_present":images,"missing_nonparagraph_content":if partial {json!("image/table/attachment content is not reconstructed or downloaded")} else {Value::Null}},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_html() -> Html {
        Html::parse_document(
            r#"<!doctype html><html><head><title>学院公告-数学科学学院</title></head><body>
            <div class="list_main"><div class="list_main_right"><div class="list_box"><ul>
              <li><a href="../info/1294/42.htm" title="ignored">First <em>notice</em><script>ignored</script></a><span>2026/02/29</span></li>
              <template><li><a href="../info/1294/99.htm">Inert row</a><span>2026/01/01</span></li></template>
              <li><a href="https://external.example/notice">External reference</a><span>2026/09/01</span><span>2026/09/02</span></li>
              <li><a href="../info/1294/43.htm">Older source row</a><span>2025/12/31</span></li>
            </ul></div></div></div></body></html>"#,
        )
    }

    fn article_html(date: &str, body: &str) -> Html {
        Html::parse_document(&format!(
            r#"<h1 class="c-title">Outside heading</h1><div class="icontent"><div class="c-content"><form name="_newscontent_fromname"><h1 class="c-title">Original <em>inline</em> heading</h1><div class="other-s">发布日期：{date}&nbsp;&nbsp;点击：<script>ignored</script></div><div id="vsb_content" class="nr-info"><div class="v_news_content">{body}</div></div><p>Outside form prose</p></form></div></div>"#
        ))
    }

    #[test]
    fn listing_uses_the_single_list_box_and_keeps_ambiguous_dates_unknown() {
        let output = parse_listing(&list_html(), &Url::parse(MATH_NOTICES_URL).unwrap()).unwrap();
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
                    "First notice",
                    None,
                    Some("https://math.buaa.edu.cn/info/1294/42.htm")
                ),
                (
                    2,
                    "External reference",
                    None,
                    Some("https://external.example/notice")
                ),
                (
                    3,
                    "Older source row",
                    Some("2025-12-31"),
                    Some("https://math.buaa.edu.cn/info/1294/43.htm")
                ),
            ]
        );
    }

    #[test]
    fn article_owns_c_title_publication_header_and_vsb_body() {
        let body = "<p>Source <em>inline</em> paragraph.</p><p>2001-01-01</p><table><tr><th>Header</th><td>Cell</td></tr></table>";
        let output = parse_article(&article_html("2026-10-12", body)).unwrap();
        assert_eq!(output["title"], "Original inline heading");
        assert_eq!(output["published_at"], "2026-10-12");
        assert_eq!(
            output["body_paragraphs"],
            json!(["Source inline paragraph.", "2001-01-01"])
        );
        assert_eq!(
            output["body_tables"][0]["rows"][0]["cells"],
            json!([
                {"header":true,"text":"Header"}, {"header":false,"text":"Cell"}
            ])
        );
        for date in ["", "2026-02-29", "2026-10-12"] {
            let html = if date.is_empty() {
                article_html("", body)
            } else if date == "2026-10-12" {
                Html::parse_document(&format!(
                    r#"<div class="icontent"><div class="c-content"><form><h1 class="c-title">Original</h1><div class="other-s">发布日期：2026-10-12&nbsp;发布日期：2026-10-12</div><div id="vsb_content" class="nr-info"><div class="v_news_content">{body}</div></div></form></div></div>"#
                ))
            } else {
                article_html(date, body)
            };
            let output = parse_article(&html).unwrap();
            assert_eq!(output["published_at"], Value::Null);
        }
    }

    #[test]
    fn aliases_and_unadvertised_paths_are_not_plain_math_urls() {
        for raw in [
            "http://math.buaa.edu.cn/info/1294/42.htm",
            "https://math.buaa.edu.cn/index/xygg.htm?x=1",
            "https://math.buaa.edu.cn/info/1294/42.htm#fragment",
            "https://math.buaa.edu.cn/info/1293/42.htm",
            "https://www.math.buaa.edu.cn/info/1294/42.htm",
        ] {
            assert!(!plain_url(&Url::parse(raw).unwrap()));
        }
    }
}
