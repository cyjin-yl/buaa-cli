//! Directory-bound Transportation Science and Engineering college notices.
use super::{
    ArticleDocument, ListQuery, MAX_TEXT, advertised_page_url_document,
    article_category_from_url, article_output, article_paragraphs, bind_college_board,
    college_directory_attribution,
    college_html, declared_jsp_attachment_hints, describe_college_surface, element_text,
    entry_in_scope, failed_contract, inert_element, invalid_article, invalid_list,
    parse_chinese_publication_date, parse_iso_date, parse_notice_list, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, TRANSPORTATION_NOTICES_URL, TRANSPORTATION_ROOT_URL,
    transportation_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://transportation.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学交通科学与工程学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("transportation.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && transportation_path_allowed(url.path())
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
        "交通科学与工程学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = TRANSPORTATION_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((
        ArchiveClient::open_transportation(source_mode)?,
        attribution,
    ))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => TRANSPORTATION_ROOT_URL,
        "notices" => TRANSPORTATION_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(
            &client,
            TRANSPORTATION_ROOT_URL,
            TRANSPORTATION_NOTICES_URL,
            &mut attribution,
        )?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "transportation", attribution)
        })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(TRANSPORTATION_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        let document = college_html(response)?;
        let selected = advertised_page_url_document(
            &document,
            &latest,
            page,
            "div.nymain div.ny-right div.notice-list > div > div.pagestyle span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/xwdt/gggs/"),
        );
        if selected.is_err() && !super::is_safe_public_fallback_document(response, &document) {
            return Err(unavailable());
        }
        Ok(selected)
    })?
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
    bind_college_board(
        &client,
        TRANSPORTATION_ROOT_URL,
        TRANSPORTATION_NOTICES_URL,
        &mut attribution,
    )?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let html = college_html(response)?;
        let document = parse_notice_list(&html, &target)?;
        super::refuse_unsafe_listing(response, &html)?;
        let entries: Vec<_> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
            .collect();
        Ok(json!({
            "schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"transportation","category":"gggs","listing_label":"公告公示","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"source YYYY.MM.DD; missing, invalid or ambiguous stays null","summaries":"source direct a/p excerpt; not original full text"},
            "retrieval":retrieval(response)
        }))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || source_page == 0
        || !target.path().starts_with("/info/1058/")
    {
        return Err(invalid_article());
    }
    let (client, mut attribution) = bound_client(mode)?;
    bind_college_board(
        &client,
        TRANSPORTATION_ROOT_URL,
        TRANSPORTATION_NOTICES_URL,
        &mut attribution,
    )?;
    let source = listing_url(&client, source_page)?;
    let listing = client.get(&source, false, |response| {
        let html = college_html(response)?;
        let document = parse_notice_list(&html, &source)?;
        super::refuse_unsafe_listing(response, &html)?;
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Err(Error::new(
                "unsupported",
                "retained notice page does not declare the selected Transportation article",
            ));
        }
        Ok(retrieval(response))
    })?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            let document = college_html(response)?;
            Ok(normalize(response, &document).map(|mut value| {
                value["publisher"] = json!(PUBLISHER);
                value["college"] = json!("transportation");
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
                "Transportation article requires one direct nymain/art-main container",
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
                "Transportation article requires one direct art-tit/h3 heading",
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
    let bodies = Selector::parse(
        ":scope > div.art-body-box > div.art-body > div#vsb_content > div.v_news_content",
    )
    .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Transportation article requires one scoped vsb_content/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let paragraphs = article_paragraphs(body, false)?;
    let (attachment_hints, hints_truncated) = declared_jsp_attachment_hints(main)?;
    let attachments_found = !attachment_hints.is_empty() || hints_truncated;
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let tables = Selector::parse("table").map_err(|_| unavailable())?;
    let has_images = body.select(&images).any(|node| !inert_element(node));
    let table_count = body
        .select(&tables)
        .filter(|node| !inert_element(*node))
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
    output["attachments"]["hints_truncated"] = json!(hints_truncated);
    output["completeness"]["body_source"] = json!(
        "unique art-main/art-body-box/art-body/#vsb_content/v_news_content paragraphs; executable and fallback text excluded"
    );
    output["completeness"]["attachment_source"] = json!(
        "active source-declared JSP file links within art-main, including siblings outside the text body; hints only, never fetched"
    );
    output["completeness"]["image_content_present"] = json!(has_images);
    output["completeness"]["unextracted_table_count"] = json!(table_count);
    if attachments_found || has_images || table_count != 0 {
        output["result"] = json!("partial_text");
        output["completeness"]["missing_nonparagraph_content"] = json!(
            "attachment bytes, image text and nonparagraph table content are not reconstructed or downloaded"
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

    fn source(header: &str, body: &str, siblings: &str) -> Response {
        let html = format!(
            "<h3>Unrelated heading</h3><a href=\"/system/_content/download.jsp?wbfileid=outside\">Outside.pdf</a><div class=\"nymain\"><div class=\"w16\"><div class=\"ny-right\"><form><div class=\"art-main\"><div class=\"art-tit cont-tit d\">{header}</div><div class=\"art-body-box\"><div class=\"art-body d\"><div id=\"vsb_content\"><div class=\"v_news_content\">{body}</div></div></div></div>{siblings}</div></form></div></div></div>"
        );
        Response {
            url: "https://transportation.buaa.edu.cn/info/1058/6401.htm".into(),
            status: 200,
            headers: BTreeMap::from([(String::from("content-type"), String::from("text/html"))]),
            sha256: format!("{:x}", Sha256::digest(html.as_bytes())),
            body: html.into_bytes(),
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn transportation_notice_board_preserves_direct_rows_and_dotted_dates() {
        let document = Html::parse_document(
            r#"<html><head><title>公告公示-交通学院</title></head><body>
            <div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-list"><div><ul>
            <li><a href="../../info/1058/6401.htm"><div class="bg"></div><span>2026.10.18</span><h3>Fixture transportation notice</h3><p>Fixture excerpt</p></a></li>
            </ul></div></div></div></div>
            </body></html>"#,
        );
        let base = Url::parse(TRANSPORTATION_NOTICES_URL).unwrap();
        let listing = parse_notice_list(&document, &base).unwrap();
        assert_eq!(listing.title, "公告公示-交通学院");
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].title, "Fixture transportation notice");
        assert_eq!(listing.entries[0].date.as_deref(), Some("2026-10-18"));
        assert_eq!(
            listing.entries[0].resolved_http_url.as_deref(),
            Some("https://transportation.buaa.edu.cn/info/1058/6401.htm")
        );
    }

    #[test]
    fn transportation_original_body_and_sibling_files_keep_source_boundaries() {
        let response = source(
            "<h3>Original heading</h3><p><span class=\"date\">日期：2026年10月18日</span></p>",
            "<p>First <em>inline</em> body.<script>not prose</script></p>",
            "<p><ul><li><a href=\"/system/_content/download.jsp?wbfileid=form&amp;owner=1\">Form.docx</a></li></ul></p><template><a href=\"/system/_content/download.jsp?wbfileid=inactive\">Inactive.pdf</a></template>",
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["title"], "Original heading");
        assert_eq!(output["published_at"], "2026-10-18");
        assert_eq!(output["body_paragraphs"], json!(["First inline body."]));
        assert_eq!(output["result"], "partial_text");
        assert_eq!(
            output["attachments"]["hints"],
            json!([{"href":"/system/_content/download.jsp?wbfileid=form&owner=1","text":"Form.docx","fetched":false}])
        );
    }

    #[test]
    fn transportation_ambiguous_header_dates_and_untranscribed_content_stay_explicit() {
        let response = source(
            "<h3>Original heading</h3><p><span class=\"date\">日期：2026年10月18日</span><span class=\"date\">日期：2026年10月17日</span></p>",
            "<p>Body date 2026-10-18 is not publication metadata.</p><img src=\"poster.png\" alt=\"not transcribed\"><table><tr><td><p>Source cell paragraph.</p></td></tr></table>",
            "",
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["published_at"], Value::Null);
        assert_eq!(
            output["body_paragraphs"],
            json!([
                "Body date 2026-10-18 is not publication metadata.",
                "Source cell paragraph."
            ])
        );
        assert_eq!(output["result"], "partial_text");
        assert_eq!(output["completeness"]["image_content_present"], true);
        assert_eq!(output["completeness"]["unextracted_table_count"], 1);
    }

    fn board_response(content_type: &str, body: &str) -> Response {
        Response {
            url: TRANSPORTATION_NOTICES_URL.into(),
            status: 200,
            headers: BTreeMap::from([(
                String::from("content-type"),
                String::from(content_type),
            )]),
            sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            body: body.as_bytes().to_vec(),
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    const BOARD_PAGE: &str = r#"<html><head><title>公告公示-交通学院</title></head><body>
        <div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-list"><div><ul>
        <li><a href="../../info/1058/6401.htm"><div class="bg"></div><span>2026.10.18</span><h3>Fixture transportation notice</h3><p>Fixture excerpt</p></a></li>
        </ul><div class="pagestyle"><span class="p_no"><a href="../gggs/1.htm">2</a></span></div></div></div></div></div></div>
        </body></html>"#;

    #[test]
    fn transportation_surface_refuses_non_html_media_types() {
        // A surface snapshot may only describe an admitted text/html
        // original. A text/plain body is never HTML evidence: it must be
        // refused rather than parsed into a successful surface snapshot.
        for content_type in ["text/plain", "application/json"] {
            let response = board_response(content_type, BOARD_PAGE);
            assert!(
                !crate::announcements::is_admitted_html(&response),
                "non-HTML media type must not pass admission: {content_type}"
            );
            assert!(
                describe_college_surface(&response, "transportation", json!({})).is_err(),
                "surface must refuse a {content_type} body"
            );
        }
        // A real text/html original of the same bytes stays describable.
        let html = board_response("text/html", BOARD_PAGE);
        let output = describe_college_surface(&html, "transportation", json!({})).unwrap();
        assert_eq!(output["result"], "surface_snapshot");
        assert_eq!(output["document_title"], "公告公示-交通学院");
    }

    #[test]
    fn transportation_listing_with_token_marker_href_is_refused() {
        // A board that still parses while carrying a credential token
        // marker is unsafe: the real list callback must refuse it before
        // serializing entries and before ArchiveClient::get may persist
        // the response, and no fallback export may carry the unsafe bytes.
        let html = BOARD_PAGE.replace(
            "href=\"../../info/1058/6401.htm\"",
            "href=\"../../info/1058/6401.htm?csrf_token=synthetic-fixture\"",
        );
        let document = Html::parse_document(&html);
        let base = Url::parse(TRANSPORTATION_NOTICES_URL).unwrap();
        let listing = parse_notice_list(&document, &base).unwrap();
        assert!(
            serde_json::to_string(&listing)
                .unwrap()
                .contains("csrf_token"),
            "the declared marker link would otherwise reach serialized output"
        );
        let response = board_response("text/html", &html);
        assert!(
            crate::announcements::refuse_unsafe_listing(&response, &document).is_err(),
            "a credential-marked page must be refused as unsafe evidence"
        );
        assert!(
            !crate::announcements::is_safe_public_fallback(&response),
            "a credential-marked page must not emit fallback source bytes"
        );
        // The identical page without the marker is a public listing.
        let document = Html::parse_document(BOARD_PAGE);
        assert!(parse_notice_list(&document, &base).is_ok());
        let public = board_response("text/html", BOARD_PAGE);
        assert!(crate::announcements::refuse_unsafe_listing(&public, &document).is_ok());
    }

    #[test]
    fn transportation_unadvertised_ordinal_keeps_the_admitted_original() {
        // When page 1 does not advertise the requested ordinal, resolution
        // fails, but the page-1 response itself is still a fully admitted
        // original. The admission must not be rolled back: a later
        // cache-only page-1 read must serve these exact bytes (bound by the
        // recorded sha256), never report an offline miss for content that
        // was already admitted.
        let html = BOARD_PAGE.replace(
            "<div class=\"pagestyle\"><span class=\"p_no\"><a href=\"../gggs/1.htm\">2</a></span></div>",
            "",
        );
        let base = Url::parse(TRANSPORTATION_NOTICES_URL).unwrap();
        // The unadvertised ordinal is refused by resolution...
        assert!(
            crate::announcements::advertised_page_url(
                html.as_bytes(),
                &base,
                2,
                "div.nymain div.ny-right div.notice-list > div > div.pagestyle span.p_no a[href]",
                |url| plain_url(url) && url.path().starts_with("/xwdt/gggs/")
            )
            .is_err(),
            "page 2 is not advertised by this board"
        );
        // ...while the exact admitted original stays parseable and
        // byte-identified for the cache-only page-1 read.
        let response = board_response("text/html", &html);
        let document = college_html(&response).unwrap();
        let parsed = parse_notice_list(&document, &base).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(
            retrieval(&response)["response_body_sha256"],
            format!("{:x}", Sha256::digest(html.as_bytes()))
        );
    }
}
