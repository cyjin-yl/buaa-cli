//! Software college notices: a directory-bound two-hop source contract.
//!
//! The official homepage declares the `/xwdt/gggs.htm` announcement section;
//! that section in turn declares the selected `/xwdt/gggs/tzgg.htm` notice
//! board.  Both declarations are retained before listing or article reads.
//! The CMS uses the shared `nymain/notice-list` listing layout and the
//! `art-main`/`v_news_content` article layout used by the other reviewed
//! college adapters.
use super::{
    ArticleDocument, ListQuery, MAX_TEXT, advertised_page_url, article_category_from_url,
    article_output, article_paragraphs, bind_college_board, college_directory_attribution,
    college_html, declared_jsp_attachment_hints, describe_college_surface, element_text,
    entry_in_scope, failed_contract, inert_element, invalid_article, invalid_list,
    parse_chinese_publication_date, parse_iso_date, parse_notice_list, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, SOFT_NOTICES_URL, SOFT_ROOT_URL, soft_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://soft.buaa.edu.cn/";
const SECTION_URL: &str = "https://soft.buaa.edu.cn/xwdt/gggs.htm";
const PUBLISHER: &str = "北京航空航天大学软件学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("soft.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && soft_path_allowed(url.path())
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let mut attribution =
        college_directory_attribution(&directory, "软件学院", LISTED_ROOT_URL, LISTED_ROOT_URL)?;
    attribution["selected_https_root"] = SOFT_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_soft(source_mode)?, attribution))
}

/// Bind the homepage declaration and then the section's selected notice-board
/// declaration. Keep both retrieval records instead of letting the shared
/// one-hop helper overwrite the first record.
fn bind_source(client: &ArchiveClient, attribution: &mut Value) -> Result<(), Error> {
    bind_college_board(client, SOFT_ROOT_URL, SECTION_URL, attribution)?;
    let root_retrieval = attribution["root_retrieval"].clone();
    bind_college_board(client, SECTION_URL, SOFT_NOTICES_URL, attribution)?;
    let section_retrieval = attribution["root_retrieval"].clone();
    attribution["root_retrieval"] = root_retrieval;
    attribution["section_retrieval"] = section_retrieval;
    Ok(())
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => SOFT_ROOT_URL,
        "notices" => SOFT_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_source(&client, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "soft", attribution)
        })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(SOFT_NOTICES_URL).map_err(|_| unavailable())?;
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
            |url| plain_url(url) && url.path().starts_with("/xwdt/gggs/tzgg/"),
        )
    })
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
    bind_source(&client, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            let document = parse_notice_list(&college_html(response)?, &target)?;
            let entries: Vec<_> = document
                .entries
                .iter()
                .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
                .collect();
            Ok(json!({
                "schema_version":1,
                "type":"announcements_list",
                "result":"listing_snapshot",
                "publisher":PUBLISHER,
                "college":"soft",
                "category":"tzgg",
                "listing_label":"通知公告",
                "page":page,
                "document_title":document.title,
                "filters":{"since":since,"until":until,"match":query.r#match},
                "entries":entries,
                "entry_count":entries.len(),
                "directory_attribution":attribution,
                "completeness":{
                    "scope":"single_college_selected_page",
                    "pagination":"source_advertised_ordinal_only; no automatic traversal",
                    "other_colleges":"not_covered",
                    "dates":"source YYYY.MM.DD; missing, invalid or ambiguous stays null",
                    "summaries":"source direct a/p excerpt; not original full text"
                },
                "retrieval":retrieval(response)
            }))
        })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || source_page == 0
        || !target.path().starts_with("/info/1095/")
    {
        return Err(invalid_article());
    }
    let (client, mut attribution) = bound_client(mode)?;
    bind_source(&client, &mut attribution)?;
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
                "retained notice page does not declare the selected Soft article",
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
                value["college"] = json!("soft");
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
                "Soft article requires one direct nymain/art-main container",
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
                "Soft article requires one direct art-tit/h3 heading",
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
                "Soft article requires one scoped vsb_content/v_news_content body",
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
    output["completeness"]["attachment_source"] =
        json!("active source-declared JSP file links within art-main; hints only, never fetched");
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
            url: "https://soft.buaa.edu.cn/info/1095/42.htm".into(),
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
    fn soft_original_body_and_attachment_boundaries_stay_explicit() {
        let response = source(
            "<h3>Original heading</h3><p><span class=\"date\">日期：2026年10月14日</span></p>",
            "<p>First <em>inline</em> body.<script>not prose</script></p><img src=\"poster.png\"><table><tr><td>unextracted table</td></tr></table>",
            "<p><ul><li><a href=\"/system/_content/download.jsp?wbfileid=form&amp;owner=1\">Form.zip</a></li></ul></p><template><a href=\"/system/_content/download.jsp?wbfileid=inactive\">Inactive.pdf</a></template>",
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["title"], "Original heading");
        assert_eq!(output["published_at"], "2026-10-14");
        assert_eq!(output["body_paragraphs"], json!(["First inline body."]));
        assert_eq!(output["result"], "partial_text");
        assert_eq!(
            output["attachments"]["hints"],
            json!([{"href":"/system/_content/download.jsp?wbfileid=form&owner=1","text":"Form.zip","fetched":false}])
        );
        assert_eq!(output["completeness"]["unextracted_table_count"], 1);
    }

    #[test]
    fn soft_article_rejects_ambiguous_header_and_body() {
        let ambiguous_header = source(
            "<h3>Original heading</h3><p><span class=\"date\">日期：2026年10月14日</span><span class=\"date\">日期：2026年10月15日</span></p>",
            "<p>Body.</p>",
            "",
        );
        let output =
            normalize(&ambiguous_header, &college_html(&ambiguous_header).unwrap()).unwrap();
        assert_eq!(output["published_at"], Value::Null);

        let ambiguous_body = source(
            "<h3>Original heading</h3>",
            "<p>Body.</p>",
            "<div class=\"art-body-box\"><div class=\"art-body\"><div id=\"vsb_content\"><div class=\"v_news_content\"><p>Second body.</p></div></div></div></div>",
        );
        assert_eq!(
            normalize(&ambiguous_body, &college_html(&ambiguous_body).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn soft_paths_allow_only_reviewed_board_and_article_routes() {
        for path in [
            "/",
            "/robots.txt",
            "/xwdt/gggs.htm",
            "/xwdt/gggs/tzgg.htm",
            "/xwdt/gggs/tzgg/1.htm",
            "/info/1095/2385.htm",
        ] {
            assert!(soft_path_allowed(path), "{path}");
        }
        for path in [
            "/xwdt/gggs/cgzq.htm",
            "/xwdt/gggs/tzgg/1.pdf",
            "/info/1094/2385.htm",
            "/info/1095/not-a-number.htm",
            "/system/resource/js/counter.js",
        ] {
            assert!(!soft_path_allowed(path), "{path}");
        }
    }
}
