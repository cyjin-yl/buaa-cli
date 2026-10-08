//! 自动化科学与电气工程学院: exact HTTP identity, separate HTTPS observation.
use super::{
    ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, inert_element, invalid_article, invalid_list, is_http,
    parse_chinese_date, parse_iso_date, retrieval, table_article_output, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, DEPT3_NOTICES_URL, DEPT3_ROOT_URL, Error, dept3_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://dept3.buaa.edu.cn/";
pub(super) const PUBLISHER: &str = "北京航空航天大学自动化科学与电气工程学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("dept3.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && dept3_path_allowed(url.path())
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
        "自动化科学与电气工程学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = DEPT3_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_dept3(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => DEPT3_ROOT_URL,
        "notices" => DEPT3_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, DEPT3_ROOT_URL, DEPT3_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "dept3", attribution)
        })
}

pub(super) fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let titles = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&titles)
        .next()
        .map(element_text)
        .unwrap_or_default();
    if title.len() > MAX_TEXT {
        return Err(unavailable());
    }
    let containers = Selector::parse("div.main > div.text-list > ul").map_err(|_| unavailable())?;
    let mut containers = document
        .select(&containers)
        .filter(|node| !inert_element(*node));
    let primary = containers
        .next()
        .filter(|_| containers.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Dept3 notices require one main/text-list view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > div.title > a").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > span.time").map_err(|_| unavailable())?;
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
                failed_contract("Dept3 notice row requires one title link", file!(), line!())
            })?;
        let title = element_text(anchor);
        if title.is_empty() || title.len() > MAX_TEXT {
            return Err(failed_contract(
                "Dept3 notice link requires source text",
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
            .and_then(|node| parse_chinese_date(&element_text(node)));
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
            "Dept3 notice view has no source rows",
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
    bind_college_board(&client, DEPT3_ROOT_URL, DEPT3_NOTICES_URL, &mut attribution)?;
    let target = Url::parse(DEPT3_NOTICES_URL).map_err(|_| unavailable())?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = parse_listing(&college_html(response)?, &target)?;
        let entries: Vec<_> = document.entries.iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"dept3","category":"xygg","listing_label":"学院公告","page":1,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"retained board declares only page1; no later ordinal is admitted or automatically traversed","other_colleges":"not_covered","dates":"source YYYY年MM月DD日; missing, invalid or ambiguous stays null","summaries":"not supplied by this source view; not reconstructed","external_links":"retained listing references only; never fetched"},
            "retrieval":retrieval(response)}))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1302/")
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
    bind_college_board(&client, DEPT3_ROOT_URL, DEPT3_NOTICES_URL, &mut attribution)?;
    let source = Url::parse(DEPT3_NOTICES_URL).map_err(|_| unavailable())?;
    let listing = client.get(&source, false, |response| {
        let document = parse_listing(&college_html(response)?, &source)?;
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Err(Error::new(
                "unsupported",
                "retained notice page does not declare the selected Dept3 article",
            ));
        }
        Ok(retrieval(response))
    })?;
    client
        .with_cache_mode(mode)
        .get(target, false, |response| {
            let document = college_html(response)?;
            Ok(parse_article(&document).map(|mut output| {
                output["retrieval"] = retrieval(response);
                output["publisher"] = json!(PUBLISHER);
                output["college"] = json!("dept3");
                output["directory_attribution"] = attribution;
                output["source_listing"] = listing;
                output
            }))
        })?
}

pub(super) fn parse_article(document: &Html) -> Result<Value, Error> {
    let views = Selector::parse("div.main1 > form > div").map_err(|_| unavailable())?;
    let mut views = document.select(&views).filter(|node| !inert_element(*node));
    let primary = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Dept3 article requires one main1/form view",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > h1").map_err(|_| unavailable())?;
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
                "Dept3 article requires one direct h1 original heading",
                file!(),
                line!(),
            )
        })?;
    let dates = Selector::parse(":scope > h1 + div").map_err(|_| unavailable())?;
    let mut dates = primary.select(&dates).filter(|node| !inert_element(*node));
    let published_at = dates
        .next()
        .filter(|_| dates.next().is_none())
        .filter(|node| {
            node.children()
                .all(|child| child.value().as_element().is_none())
        })
        .and_then(|node| parse_iso_date(&element_text(node)));
    let bodies = Selector::parse(":scope > div > div.v_news_content").map_err(|_| unavailable())?;
    let mut bodies = primary.select(&bodies).filter(|node| !inert_element(*node));
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Dept3 article requires one scoped v_news_content body",
                file!(),
                line!(),
            )
        })?;
    table_article_output(
        body,
        title,
        Some("1302".into()),
        published_at,
        "unique main1/form view, direct h1 original heading and adjacent ISO date; scoped v_news_content source paragraphs and separate ordered flat-table captions/rows/cells; code and fallback payloads excluded",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn article_html(header: &str, body: &str) -> String {
        format!(
            r#"<h1>Unrelated heading</h1><div class="main1"><form><div><h1>Original <em>source</em> heading</h1>{header}<div><div class="v_news_content">{body}</div></div><table><tr><td>Outside body table</td></tr></table><p>Outside body prose</p></div></form></div>"#
        )
    }

    #[test]
    fn listing_keeps_external_rows_and_unknown_dates_without_inert_copies() {
        let html = r#"<title>Synthetic notices</title><ul><li>Unrelated navigation</li></ul><div class="main"><div class="text-list"><ul>
<li><span class="time">2024年02月29日</span><div class="title"><a href="../info/1302/42.htm">Before <em>inside</em> after<script>not text</script></a></div></li>
<li><span class="time">2023年02月29日</span><div class="title"><a href="https://external.example/notice">External reference</a></div></li>
<li><span class="time">2026年05月18日</span><span class="time">2026年04月16日</span><div class="title"><a href="../info/1302/43.htm">Ambiguous publication</a></div></li>
</ul></div></div><template><div class="main"><div class="text-list"><ul><li><div class="title"><a href="../info/1302/99.htm">Inactive copy</a></div></li></ul></div></div></template>"#;
        let parsed = parse_listing(
            &Html::parse_document(html),
            &Url::parse(DEPT3_NOTICES_URL).unwrap(),
        )
        .unwrap();
        let rows: Vec<_> = parsed
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.title.as_str(),
                    entry.date.as_deref(),
                    entry.resolved_http_url.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                (
                    "Before inside after",
                    Some("2024-02-29"),
                    Some("https://dept3.buaa.edu.cn/info/1302/42.htm")
                ),
                (
                    "External reference",
                    None,
                    Some("https://external.example/notice")
                ),
                (
                    "Ambiguous publication",
                    None,
                    Some("https://dept3.buaa.edu.cn/info/1302/43.htm")
                ),
            ]
        );
        let filtered: Vec<_> = parsed
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &Some("2024-01-01".into()), &None, &None))
            .map(|entry| entry.title.as_str())
            .collect();
        assert_eq!(filtered, vec!["Before inside after"]);
    }

    #[test]
    fn article_date_and_source_text_cannot_be_taken_from_body_or_siblings() {
        let body = "<p>Before <em>inline</em> after.<script>not prose</script></p><p>2030-01-01</p><table><tr><td>Source cell</td></tr></table><img src='poster.png'><template><p>Inactive body</p></template>";
        let output = parse_article(&Html::parse_document(&article_html(
            "<div>2026-05-18</div>",
            body,
        )))
        .unwrap();
        assert_eq!(output["title"], "Original source heading");
        assert_eq!(output["published_at"], "2026-05-18");
        assert_eq!(
            output["body_paragraphs"],
            json!(["Before inline after.", "2030-01-01"])
        );
        assert_eq!(
            output["body_tables"][0]["rows"][0]["cells"],
            json!([{"header":false,"text":"Source cell"}])
        );
        assert_eq!(output["body_table_count"], 1);
        assert_eq!(output["result"], "partial_text");
        let missing = parse_article(&Html::parse_document(&article_html(
            "",
            "<p>2030-01-01</p>",
        )))
        .unwrap();
        assert_eq!(missing["published_at"], Value::Null);
        assert_eq!(missing["body_paragraphs"], json!(["2030-01-01"]));
    }

    #[test]
    fn history_preserves_http_assertion_and_does_not_turn_it_into_retrieval() {
        let html = article_html(
            "<div>1997-06-10</div>",
            "<p>Original <em>inline</em> text.</p>",
        );
        let mut input = json!({"kind":"article","html":STANDARD.encode(&html),"provenance":{
            "source_url":"http://dept3.buaa.edu.cn/info/1302/42.htm","capture_timestamp":"20000102030405"
        }});
        let output = crate::announcements::history(&input.to_string()).unwrap();
        assert_eq!(output["published_at"], "1997-06-10");
        assert_eq!(output["body_paragraphs"], json!(["Original inline text."]));
        assert_eq!(
            output["provenance"]["source_url"],
            "http://dept3.buaa.edu.cn/info/1302/42.htm"
        );
        assert_eq!(output["provenance"]["status"], "operator_asserted");
        assert_eq!(
            output["retrieval"]["provenance_status"],
            "operator_asserted"
        );
        assert!(output.get("directory_attribution").is_none());
        assert!(output.get("source_listing").is_none());
        assert!(output["retrieval"].get("fetched_at_unix_ms").is_none());
        input["provenance"]["source_url"] = json!("http://dept3.buaa.edu.cn/info/1065/42.htm");
        assert_eq!(
            crate::announcements::history(&input.to_string())
                .unwrap_err()
                .code,
            "invalid_input"
        );
    }
}
