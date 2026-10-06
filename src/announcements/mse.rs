//! Materials college: exact HTTP directory identity, separate HTTPS observation.
use super::{
    ListQuery, MAX_TEXT, advertised_page_url, article_category_from_url, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, inert_element, invalid_article, invalid_list,
    parse_chinese_publication_date, parse_iso_date, parse_notice_list, retrieval,
    table_article_output, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, MSE_NOTICES_URL, MSE_ROOT_URL, mse_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://mse.buaa.edu.cn/";
pub(super) const PUBLISHER: &str = "北京航空航天大学材料科学与工程学院";

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
    table_article_output(
        response,
        body,
        title,
        Url::parse(&response.url)
            .ok()
            .as_ref()
            .and_then(article_category_from_url),
        published_at,
        "unique art-main/art-body-box/art-body/ar_article#vsb_content/v_news_content; source paragraphs and separate ordered flat-table captions/rows/cells; code and fallback payloads excluded",
    )
}

#[cfg(test)]
mod tests {
    use super::super::MAX_BODY_PARAGRAPHS;
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
