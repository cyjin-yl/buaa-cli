//! Directory-bound cyberspace-security college notices; no inferred routes.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    article_body, article_output, bind_college_board, college_directory_attribution, college_html,
    describe_college_surface, element_text, entry_in_scope, failed_contract, html_fallback,
    invalid_article, invalid_list, is_admitted_html, is_http, is_safe_public_fallback,
    parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CST_NOTICES_URL, CST_ROOT_URL, CacheMode, Error, Response, cst_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://cst.buaa.edu.cn";
const RESOLVED_ROOT_URL: &str = "http://cst.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学网络空间安全学院";

fn source_mode(mode: CacheMode) -> CacheMode {
    if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    }
}

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("cst.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && cst_path_allowed(url.path())
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let directory = crate::organizations::list(source_mode(mode))?;
    let mut attribution = college_directory_attribution(
        &directory,
        "网络空间安全学院",
        LISTED_ROOT_URL,
        RESOLVED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = CST_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_cst(source_mode(mode))?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => CST_ROOT_URL,
        "notices" => CST_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, CST_ROOT_URL, CST_NOTICES_URL, &mut attribution)?;
    }
    let url = Url::parse(raw).map_err(|_| unavailable())?;
    client.with_cache_mode(mode).get(&url, false, |response| {
        if !is_admitted_html(response) {
            return Err(unavailable());
        }
        match describe_college_surface(response, "cst", attribution.clone()) {
            Ok(value) => Ok(value),
            Err(_) if is_safe_public_fallback(response) => Ok(html_fallback(
                response,
                "college_source_surface",
                "cst",
                "cst_surface_selector_contract",
            )),
            Err(error) => Err(error),
        }
    })
}

fn parse_date(day_raw: &str, year_raw: &str) -> Option<String> {
    let (month, day) = day_raw.trim().split_once('/')?;
    if month.len() != 2
        || day.len() != 2
        || year_raw.trim().len() != 4
        || ![month, day, year_raw.trim()]
            .into_iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    parse_iso_date(&format!("{}-{month}-{day}", year_raw.trim()))
}

fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(element_text)
        .unwrap_or_default();
    let rows = Selector::parse("div.text-list > ul > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let headings = Selector::parse("div.text-linfo > h3").map_err(|_| unavailable())?;
    let summaries = Selector::parse("div.text-linfo > p").map_err(|_| unavailable())?;
    let days = Selector::parse("div.text-ldata > div > p").map_err(|_| unavailable())?;
    let years = Selector::parse("div.text-ldata > div > span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in document.select(&rows) {
        if entries.len() >= MAX_ENTRIES {
            return Err(failed_contract(
                "CST notice listing exceeds the reviewed entry budget",
                file!(),
                line!(),
            ));
        }
        let title = row
            .select(&headings)
            .next()
            .map(element_text)
            .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
            .ok_or_else(|| {
                failed_contract(
                    "CST notice row requires its text-linfo/h3 source heading",
                    file!(),
                    line!(),
                )
            })?;
        let listed_href = {
            let mut selected = row.select(&anchors);
            let href = selected
                .next()
                .and_then(|anchor| anchor.value().attr("href"));
            if selected.next().is_some() {
                return Err(failed_contract(
                    "CST notice row requires one source article anchor",
                    file!(),
                    line!(),
                ));
            }
            if href.is_some_and(|href| href.len() > MAX_HREF || href.chars().any(char::is_control))
            {
                return Err(unavailable());
            }
            href.map(str::to_owned)
        };
        let date = {
            let mut day_nodes = row.select(&days);
            let day = day_nodes.next().map(element_text);
            let day_ambiguous = day_nodes.next().is_some();
            let mut year_nodes = row.select(&years);
            let year = year_nodes.next().map(element_text);
            let year_ambiguous = year_nodes.next().is_some();
            if day_ambiguous || year_ambiguous {
                None
            } else {
                day.zip(year)
                    .and_then(|(day, year)| parse_date(&day, &year))
            }
        };
        let summary = row
            .select(&summaries)
            .next()
            .map(element_text)
            .filter(|summary| !summary.is_empty())
            .map(|summary| summary.chars().take(MAX_TEXT).collect());
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
            category_label: Some("通知公告".into()),
            summary,
            listed_href,
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "CST notice listing requires its text-list source rows",
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
        .is_some_and(|category| category != "tzgg")
        || query.page == Some(0)
    {
        return Err(invalid_list());
    }
    let page = query.page.unwrap_or(1);
    if page != 1 {
        return Err(Error::new(
            "unavailable",
            "CST notice board has no reviewed later-page declaration",
        ));
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
    bind_college_board(&client, CST_ROOT_URL, CST_NOTICES_URL, &mut attribution)?;
    let target = Url::parse(CST_NOTICES_URL).map_err(|_| unavailable())?;
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
                            "cst",
                            "cst_listing_selector_contract",
                        );
                        value["category"] = json!("tzgg");
                        value["page"] = json!(1);
                        return Ok(value);
                    }
                    Err(error) => return Err(error),
                };
            let entries: Vec<&ListingEntry> = document
                .entries
                .iter()
                .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
                .collect();
            Ok(json!({
                "schema_version": 1,
                "type": "announcements_list",
                "result": "listing_snapshot",
                "publisher": PUBLISHER,
                "college": "cst",
                "category": "tzgg",
                "listing_label": "通知公告",
                "page": page,
                "document_title": document.title,
                "filters": {"since": since, "until": until, "match": query.r#match},
                "entries": entries,
                "entry_count": entries.len(),
                "directory_attribution": attribution,
                "completeness": {
                    "scope": "single_college_selected_page",
                    "pagination": "no reviewed later-page declaration; no traversal",
                    "other_colleges": "not_covered",
                    "dates": "source month/day and year; missing or invalid stays null"
                },
                "retrieval": retrieval(response)
            }))
        })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1102/")
        || source_page == 0
    {
        return Err(invalid_article());
    }
    if source_page != 1 {
        return Err(Error::new(
            "unavailable",
            "CST notice board has no reviewed later-page declaration",
        ));
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
    bind_college_board(&client, CST_ROOT_URL, CST_NOTICES_URL, &mut attribution)?;
    let source = Url::parse(CST_NOTICES_URL).map_err(|_| unavailable())?;
    let listing = client.get(&source, false, |response| {
        let document = match college_html(response).and_then(|html| parse_listing(&html, &source)) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_list",
                    "cst",
                    "cst_listing_selector_contract",
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
                "retained notice page does not declare the selected CST article",
            ));
        }
        Ok(retrieval(response))
    })?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained CST listing could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client
        .with_cache_mode(mode)
        .get(target, false, |response| {
            let document = match college_html(response) {
                Ok(document) => document,
                Err(_) if is_safe_public_fallback(response) => {
                    return Ok(html_fallback(
                        response,
                        "announcements_article",
                        "cst",
                        "cst_article_selector_contract",
                    ));
                }
                Err(error) => return Err(error),
            };
            let mut value = match normalize(response, &document) {
                Ok(value) => value,
                Err(_) if is_safe_public_fallback(response) => html_fallback(
                    response,
                    "announcements_article",
                    "cst",
                    "cst_article_selector_contract",
                ),
                Err(error) => return Err(error),
            };
            Ok({
                value["publisher"] = json!(PUBLISHER);
                value["college"] = json!("cst");
                value["directory_attribution"] = attribution.clone();
                value["source_listing"] = listing.clone();
                value
            })
        })
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let mains = Selector::parse("div.art-main").map_err(|_| unavailable())?;
    let mut mains = document.select(&mains);
    let main = mains
        .next()
        .filter(|_| mains.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "CST article requires one art-main source container",
                file!(),
                line!(),
            )
        })?;
    let headers = Selector::parse(":scope > div.art-tit.cont-tit").map_err(|_| unavailable())?;
    let mut headers = main.select(&headers);
    let header = headers
        .next()
        .filter(|_| headers.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "CST article requires one direct art-tit/cont-tit header",
                file!(),
                line!(),
            )
        })?;
    let mut titles = header
        .children()
        .filter_map(ElementRef::wrap)
        .filter(|node| node.value().name() == "h3")
        .map(element_text)
        .filter(|title| !title.is_empty());
    let title = titles
        .next()
        .filter(|title| titles.next().is_none() && title.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "CST article requires one bounded source h3 heading",
                file!(),
                line!(),
            )
        })?;
    let date_selector = Selector::parse(":scope > p > span").map_err(|_| unavailable())?;
    let mut dates = header
        .select(&date_selector)
        .map(element_text)
        .filter(|text| text.starts_with("发布日期："));
    let published_at = dates.next().and_then(|date| {
        if dates.next().is_some() {
            None
        } else {
            parse_iso_date(date.strip_prefix("发布日期：")?.trim())
        }
    });
    let bodies =
        Selector::parse(":scope > #vsb_content > div.v_news_content").map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "CST article requires one direct vsb_content/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, false)?;
    let article = ArticleDocument {
        title,
        category: Some("1102".into()),
        published_at,
        paragraphs,
        attachment_hints,
        attachments_found,
    };
    Ok(article_output(response, article))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://cst.buaa.edu.cn/info/1102/42.htm".into(),
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
    fn listing_preserves_source_order_and_split_dates() {
        let source = r#"<title>Fixture notices</title><div class="text-list"><ul>
            <li><a href="../info/1102/42.htm"><div class="text-ldata"><div><p>10/12</p><span>2026</span></div></div><div class="text-linfo"><h3>First notice</h3><p>First excerpt</p></div></a></li>
            <li><a href="../info/1102/43.htm"><div class="text-ldata"><div><p>bad</p><span>2026</span></div></div><div class="text-linfo"><h3>Second notice</h3><p></p></div></a></li>
        </ul></div>"#;
        let base = Url::parse(CST_NOTICES_URL).unwrap();
        let document = parse_listing(&college_html(&response(source)).unwrap(), &base).unwrap();
        assert_eq!(document.entries.len(), 2);
        assert_eq!(document.entries[0].source_order, 1);
        assert_eq!(document.entries[0].date.as_deref(), Some("2026-10-12"));
        assert_eq!(
            document.entries[0].summary.as_deref(),
            Some("First excerpt")
        );
        assert_eq!(document.entries[1].date, None);
        assert_eq!(document.entries[1].summary, None);
    }

    #[test]
    fn article_uses_direct_header_and_body_contract() {
        let source = response(
            r#"<div class="art-main"><div class="art-tit cont-tit"><h3>Fixture article</h3><p><span>发布日期：2026-10-12</span></p></div><div id="vsb_content" class="art-body"><div class="v_news_content"><p>First paragraph.</p><p><script>ignored</script></p><p>Second paragraph.</p></div></div></div>"#,
        );
        let value = normalize(&source, &college_html(&source).unwrap()).unwrap();
        assert_eq!(value["title"], "Fixture article");
        assert_eq!(value["published_at"], "2026-10-12");
        assert_eq!(
            value["body_paragraphs"],
            json!(["First paragraph.", "Second paragraph."])
        );
    }

    #[test]
    fn ambiguous_cst_body_is_rejected() {
        let source = response(
            r#"<div class="art-main"><div class="art-tit cont-tit"><h3>Fixture article</h3></div><div id="vsb_content"><div class="v_news_content"><p>Desktop</p></div><div class="v_news_content"><p>Mobile</p></div></div></div>"#,
        );
        assert_eq!(
            normalize(&source, &college_html(&source).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn foreign_and_query_urls_are_not_plain_cst_urls() {
        for raw in [
            "https://cst.buaa.edu.cn/info/1102/42.htm?x=1",
            "https://foreign.example/info/1102/42.htm",
            "http://cst.buaa.edu.cn/info/1102/42.htm",
        ] {
            assert!(!plain_url(&Url::parse(raw).unwrap()));
        }
    }
}
