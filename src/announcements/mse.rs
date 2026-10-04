//! Materials college: exact HTTP directory identity, separate HTTPS observation.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF,
    MAX_PARAGRAPH, MAX_TEXT, advertised_page_url, article_body, article_category_from_url,
    article_output, bind_college_board, college_directory_attribution, college_html,
    describe_college_surface, element_text, entry_in_scope, failed_contract, inert_element,
    invalid_article, invalid_list, is_http, parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, MSE_NOTICES_URL, MSE_ROOT_URL, mse_path_allowed,
};
use chrono::NaiveDate;
use scraper::{Html, Node, Selector};
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

fn source_date(raw: &str) -> Option<String> {
    let mut bytes: [u8; 10] = raw.trim().as_bytes().try_into().ok()?;
    if bytes[4] != b'.' || bytes[7] != b'.' {
        return None;
    }
    bytes[4] = b'-';
    bytes[7] = b'-';
    parse_iso_date(std::str::from_utf8(&bytes).ok()?)
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let mut attribution =
        college_directory_attribution(&directory, "材料科学与工程学院", LISTED_ROOT_URL)?;
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

fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
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
                "Mse notices require one nymain/notice-list view",
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
                    "Mse notice row requires one direct a link",
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
                    "Mse notice row requires one direct h3 heading",
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
            .and_then(|node| source_date(&element_text(node)));
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
            "Mse notice view has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
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
        let document = parse_listing(&college_html(response)?, &target)?;
        let entries: Vec<&ListingEntry> = document.entries.iter()
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
        let document = parse_listing(&college_html(response)?, &source)?;
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

fn publication_date(raw: &str) -> Option<String> {
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
        .and_then(|node| publication_date(&element_text(node)));
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
    let (paragraphs, attachment_hints, attachments_found) = article_body(body)?;
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let has_images = body.select(&images).any(|image| !inert_element(image));
    let tables = Selector::parse("table").map_err(|_| unavailable())?;
    let unextracted_tables = body
        .select(&tables)
        .filter(|table| !inert_element(*table))
        .filter(|table| {
            table.descendants().any(|node| {
                matches!(node.value(), Node::Text(text) if !text.trim().is_empty())
                    && !node.ancestors().any(|ancestor| {
                        ancestor.value().as_element().is_some_and(|element| {
                            matches!(
                                element.name(),
                                "p" | "script" | "style" | "template" | "noscript"
                            )
                        })
                    })
            })
        })
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
    output["completeness"]["body_source"] = json!(
        "unique art-main/art-body-box/art-body/ar_article#vsb_content/v_news_content p; only actual source paragraphs, including paragraph-wrapped table cells, in document order"
    );
    output["completeness"]["unextracted_table_count"] = json!(unextracted_tables);
    output["completeness"]["image_content_present"] = json!(has_images);
    if unextracted_tables > 0 || has_images || attachments_found {
        output["result"] = json!("partial_text");
        output["completeness"]["missing_nonparagraph_content"] = json!(
            "table text outside paragraphs, image text and attachment contents are not reconstructed or downloaded"
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
        let parsed = parse_listing(&document, &Url::parse(MSE_NOTICES_URL).unwrap()).unwrap();
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
            parse_listing(&duplicate, &base).unwrap_err().code,
            "unavailable"
        );
        let duplicate_headings = listing(
            "<li><a href=\"../info/1061/42.htm\"><h3>First heading</h3><h3>Second heading</h3></a></li>",
        );
        assert_eq!(
            parse_listing(&duplicate_headings, &base).unwrap_err().code,
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
        assert_eq!(output["result"], "partial_text");
        assert_eq!(output["completeness"]["unextracted_table_count"], 1);

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
        assert_eq!(
            normalize(&table_only, &college_html(&table_only).unwrap())
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
            let parsed = parse_listing(&document, &base).unwrap();
            assert_eq!(parsed.entries[0].summary.as_deref(), Some(excerpt.as_str()));
        }
        let document = listing(&format!(
            "<li><a href=\"../info/1061/42.htm\"><h3>Source heading</h3><p>{}</p></a></li>",
            "x".repeat(super::super::MAX_PARAGRAPH + 1)
        ));
        assert_eq!(
            parse_listing(&document, &base).unwrap_err().code,
            "unavailable"
        );
    }
}
