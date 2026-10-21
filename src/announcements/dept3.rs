//! 自动化科学与电气工程学院: exact HTTP identity, separate HTTPS observation.
use super::{
    ListQuery, ListingDocument, MAX_TEXT, article_category_from_url, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, html_fallback, inert_element, invalid_article, invalid_list,
    is_admitted_html, is_safe_public_fallback, parse_chinese_publication_date, parse_iso_date,
    parse_notice_list, retrieval, table_article_output, unavailable,
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
            if !is_admitted_html(response) {
                return Err(unavailable());
            }
            match describe_college_surface(response, "dept3", attribution.clone()) {
                Ok(value) => Ok(value),
                Err(_) if is_safe_public_fallback(response) => Ok(html_fallback(
                    response,
                    "college_source_surface",
                    "dept3",
                    "dept3_surface_selector_contract",
                )),
                Err(error) => Err(error),
            }
        })
}

pub(super) fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    parse_notice_list(document, base)
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    if query
        .category
        .as_deref()
        .is_some_and(|category| category != "tzgg")
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
        let document = match college_html(response).and_then(|html| parse_listing(&html, &target)) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                let mut value = html_fallback(
                    response,
                    "announcements_list",
                    "dept3",
                    "dept3_listing_selector_contract",
                );
                value["category"] = json!("tzgg");
                value["page"] = json!(1);
                return Ok(value);
            }
            Err(error) => return Err(error),
        };
        let entries: Vec<_> = document.entries.iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"dept3","category":"tzgg","listing_label":"通知公告","page":1,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"retained board declares only page1; no later ordinal is admitted or automatically traversed","other_colleges":"not_covered","dates":"source YYYY.MM.DD; missing, invalid or ambiguous stays null","summaries":"source direct a/p excerpt; not original full text","external_links":"retained listing references only; never fetched"},
            "retrieval":retrieval(response)}))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/")
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
        let document = match college_html(response).and_then(|html| parse_listing(&html, &source)) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_list",
                    "dept3",
                    "dept3_listing_selector_contract",
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
                "retained notice page does not declare the selected Dept3 article",
            ));
        }
        Ok(retrieval(response))
    })?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained Dept3 listing could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client.with_cache_mode(mode).get(target, false, |response| {
        let document = match college_html(response) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                return Ok(html_fallback(
                    response,
                    "announcements_article",
                    "dept3",
                    "dept3_article_selector_contract",
                ));
            }
            Err(error) => return Err(error),
        };
        let mut output = match parse_article(&document) {
            Ok(output) => output,
            Err(_) if is_safe_public_fallback(response) => html_fallback(
                response,
                "announcements_article",
                "dept3",
                "dept3_article_selector_contract",
            ),
            Err(error) => return Err(error),
        };
        Ok({
            output["category"] = article_category_from_url(target)
                .map(Value::String)
                .unwrap_or(Value::Null);
            output["retrieval"] = retrieval(response);
            output["publisher"] = json!(PUBLISHER);
            output["college"] = json!("dept3");
            output["directory_attribution"] = attribution.clone();
            output["source_listing"] = listing.clone();
            output
        })
    })
}

pub(super) fn parse_article(document: &Html) -> Result<Value, Error> {
    let mains = Selector::parse("form > div.art-main").map_err(|_| unavailable())?;
    let mut mains = document.select(&mains).filter(|node| !inert_element(*node));
    let main = mains
        .next()
        .filter(|_| mains.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Dept3 article requires one direct art-main container",
                file!(),
                line!(),
            )
        })?;
    let headings =
        Selector::parse(":scope > div.art-tit.cont-tit > h3").map_err(|_| unavailable())?;
    let mut headings = main.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "Dept3 article requires one direct art-tit/h3 original heading",
                file!(),
                line!(),
            )
        })?;
    let dates = Selector::parse(":scope > div.art-tit.cont-tit > p > span.date")
        .map_err(|_| unavailable())?;
    let mut dates = main.select(&dates);
    let published_at = dates
        .next()
        .filter(|_| dates.next().is_none())
        .and_then(|node| parse_chinese_publication_date(&element_text(node)));
    let bodies = Selector::parse(
        ":scope > div.art-body-box > div.art-body.article > div#vsb_content > div.v_news_content",
    )
    .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies).filter(|node| !inert_element(*node));
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Dept3 article requires one scoped art-body/vsb_content/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    table_article_output(
        body,
        title,
        None,
        published_at,
        "unique form/art-main view, direct art-tit/h3 original heading and date span; scoped art-body/vsb_content/v_news_content source paragraphs and separate ordered flat-table captions/rows/cells; code and fallback payloads excluded",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn article_html(header: &str, body: &str) -> String {
        format!(
            r#"<h1>Unrelated heading</h1><form><div class="art-main"><div class="art-tit cont-tit d"><h3>Original <em>source</em> heading</h3><p>{header}</p></div><div class="art-body-box"><div class="art-body d article"><div id="vsb_content"><div class="v_news_content">{body}</div></div></div></div><table><tr><td>Outside body table</td></tr></table><p>Outside body prose</p></div></form>"#
        )
    }

    #[test]
    fn listing_keeps_external_rows_and_unknown_dates_without_inert_copies() {
        let html = r#"<title>Synthetic notices</title><ul><li>Unrelated navigation</li></ul><div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-list"><div><ul>
<li><a href="../../info/1014/42.htm"><span>2024.02.29</span><h3>Before <em>inside</em> after<script>not text</script></h3><p>Distinct excerpt</p></a></li>
<li><a href="https://external.example/notice"><span>2023.02.29</span><h3>External reference</h3><p>External excerpt</p></a></li>
<li><a href="../../info/1093/43.htm"><span>2026.05.18</span><span>2026.04.16</span><h3>Ambiguous publication</h3><p>Ambiguous excerpt</p></a></li>
</ul></div></div></div></div></div><template><div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-list"><div><ul><li><a href="../../info/1014/99.htm"><span>2026.01.01</span><h3>Inactive copy</h3></a></li></ul></div></div></div></div></div></template>"#;
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
                    Some("https://dept3.buaa.edu.cn/info/1014/42.htm")
                ),
                (
                    "External reference",
                    None,
                    Some("https://external.example/notice")
                ),
                (
                    "Ambiguous publication",
                    None,
                    Some("https://dept3.buaa.edu.cn/info/1093/43.htm")
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
    fn review_regression_dept3_notice_links_resolve_from_the_admitted_listing_url() {
        let html = r#"<title>Source notices</title><div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-list"><div><ul>
<li><a href="../info/1014/42.htm"><span>2024.02.29</span><h3>Source-relative notice</h3></a></li>
</ul></div></div></div></div></div>"#;
        let listing_url = Url::parse(DEPT3_NOTICES_URL).unwrap();
        let parsed = parse_listing(&Html::parse_document(html), &listing_url).unwrap();
        assert_eq!(
            parsed.entries[0].resolved_http_url.as_deref(),
            Some("https://dept3.buaa.edu.cn/xwdt/info/1014/42.htm")
        );
        assert!(!parsed.entries.iter().any(|entry| {
            entry.resolved_http_url.as_deref() == Some("https://dept3.buaa.edu.cn/info/1014/42.htm")
        }));
    }

    #[test]
    fn article_date_and_source_text_cannot_be_taken_from_body_or_siblings() {
        let body = "<p>Before <em>inline</em> after.<script>not prose</script></p><p>2030-01-01</p><table><tr><td>Source cell</td></tr></table><img src='poster.png'><template><p>Inactive body</p></template>";
        let output = parse_article(&Html::parse_document(&article_html(
            "<span class=\"date\">日期：2026年05月18日</span>",
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
            "<span class=\"date\">日期：1997年06月10日</span>",
            "<p>Original <em>inline</em> text.</p>",
        );
        let mut input = json!({"kind":"article","html":STANDARD.encode(&html),"provenance":{
            "source_url":"http://dept3.buaa.edu.cn/info/1014/42.htm","capture_timestamp":"20000102030405"
        }});
        let output = crate::announcements::history(&input.to_string()).unwrap();
        assert_eq!(output["published_at"], "1997-06-10");
        assert_eq!(output["body_paragraphs"], json!(["Original inline text."]));
        assert_eq!(
            output["provenance"]["source_url"],
            "http://dept3.buaa.edu.cn/info/1014/42.htm"
        );
        assert_eq!(output["provenance"]["status"], "operator_asserted");
        assert_eq!(
            output["retrieval"]["provenance_status"],
            "operator_asserted"
        );
        assert!(output.get("directory_attribution").is_none());
        assert!(output.get("source_listing").is_none());
        assert!(output["retrieval"].get("fetched_at_unix_ms").is_none());
        input["provenance"]["source_url"] = json!("http://dept3.buaa.edu.cn/info/1302/42.htm");
        assert_eq!(
            crate::announcements::history(&input.to_string())
                .unwrap_err()
                .code,
            "invalid_input"
        );
    }
}
