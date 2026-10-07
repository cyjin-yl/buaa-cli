//! Energy college: retained HTTP directory identity, separate HTTPS observation.
use super::{
    ArticleDocument, DocumentInput, ListQuery, MAX_ATTACHMENT_HINTS, MAX_TEXT, advertised_page_url,
    article_category_from_url, article_output, article_paragraphs, bind_college_board,
    college_directory_attribution, college_html, declared_jsp_attachment_hints,
    describe_college_surface, element_text, entry_in_scope, failed_contract, inert_element,
    invalid_article, invalid_list, parse_chinese_publication_date, parse_iso_date,
    parse_notice_list, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, SEPE_NOTICES_URL, SEPE_ROOT_URL, sepe_document_url_allowed,
    sepe_path_allowed,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://sepe.buaa.edu.cn/";
pub(super) const PUBLISHER: &str = "北京航空航天大学能源与动力工程学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("sepe.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && sepe_path_allowed(url.path())
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
        "能源与动力工程学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = SEPE_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_sepe(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => SEPE_ROOT_URL,
        "notices" => SEPE_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, SEPE_ROOT_URL, SEPE_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "sepe", attribution)
        })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(SEPE_NOTICES_URL).map_err(|_| unavailable())?;
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
    bind_college_board(&client, SEPE_ROOT_URL, SEPE_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = parse_notice_list(&college_html(response)?, &target)?;
        let entries: Vec<_> = document.entries.iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"sepe","category":"gggs","listing_label":"公告公示","page":page,
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
        || !["/info/1078/", "/info/1093/", "/info/1080/"]
            .into_iter()
            .any(|prefix| target.path().starts_with(prefix))
    {
        return Err(invalid_article());
    }
    let (client, mut attribution) = bound_client(mode)?;
    bind_college_board(&client, SEPE_ROOT_URL, SEPE_NOTICES_URL, &mut attribution)?;
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
                "retained notice page does not declare the selected Sepe article",
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
                value["college"] = json!("sepe");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
}

pub(super) fn document(mode: CacheMode, input: &DocumentInput) -> Result<Value, Error> {
    let ordinal = input.attachment_ordinal.ok_or_else(invalid_article)?;
    if ordinal == 0 || ordinal as usize > MAX_ATTACHMENT_HINTS || input.source_page == Some(0) {
        return Err(invalid_article());
    }
    // Document reads cannot turn missing/changed reference snapshots into
    // background source observations. Refresh the article separately.
    let mut source = article(
        CacheMode::Offline,
        &input.article_url,
        input.source_page.unwrap_or(1),
    )?;
    let hint = source["attachments"]["hints"]
        .get(ordinal as usize - 1)
        .ok_or_else(|| {
            Error::new(
                "unsupported",
                "retained article does not declare this file ordinal",
            )
        })?;
    let href = hint["href"].as_str().ok_or_else(unavailable)?;
    let name = hint["text"].as_str().ok_or_else(unavailable)?;
    if !name
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("docx"))
    {
        return Err(Error::new(
            "unsupported",
            "only a source-declared DOCX original is supported for Sepe",
        ));
    }
    let target = Url::parse(&input.article_url)
        .map_err(|_| invalid_article())?
        .join(href)
        .map_err(|_| invalid_article())?;
    if !href.starts_with("/system/_content/download.jsp?") || !sepe_document_url_allowed(&target) {
        return Err(Error::new(
            "unsupported",
            "source file link is outside the bounded read-only Sepe download contract",
        ));
    }
    let declaration = json!({"ordinal":ordinal,"href":href,"text":name,"declared_format":"docx"});
    let source_retrieval = source["retrieval"].take();
    let directory_attribution = source["directory_attribution"].take();
    let source_listing = source["source_listing"].take();
    let hints_truncated = source["attachments"]["hints_truncated"].take();
    let client = ArchiveClient::open_sepe(mode)?;
    client.get(&target, true, |response| {
        validate_document(response)?;
        let media = response.headers.get("content-type").and_then(|value| value.split(';').next()).unwrap_or_default().trim();
        Ok(json!({
            "schema_version":1,"type":"announcement_document","result":"source_document_bytes",
            "publisher":PUBLISHER,"college":"sepe","directory_attribution":directory_attribution,
            "source_article":source_retrieval,"source_listing":source_listing,"source_declaration":declaration,
            "reference_policy":"cache_only_directory_root_listing_article; refresh sources separately, document refresh revalidates only the selected original",
            "relationship":"original from one retained active DOCX-labelled file link; not a preview or transcode",
            "document":{"media_type":media,"declared_format":"docx","byte_length":response.body.len(),"sha256":response.sha256,"content_base64":STANDARD.encode(&response.body)},
            "retrieval":retrieval(response),
            "verification":{"hash_scope":"retrieved_document_bytes","zip_header_and_eocd_framing_checked":true,"word_package_verified":false,"external_published_checksum_verified":false,"publisher_signature_verified":false,"document_safety_scan_performed":false},
            "completeness":{"scope":"single_source_declared_docx_labelled_original","source_hints_truncated":hints_truncated,"other_attachments_fetched":false,"text_extracted":false,"ocr_performed":false},
        }))
    })
}

pub(crate) fn validate_document_metadata(
    status: u16,
    content_type: Option<&str>,
    byte_length: usize,
) -> Result<(), Error> {
    let mime_ok = content_type.is_some_and(|value| {
        let media = value.split(';').next().unwrap_or_default().trim();
        media.eq_ignore_ascii_case(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ) || media.eq_ignore_ascii_case("application/octet-stream")
    });
    if status != 200 || !mime_ok || byte_length == 0 || byte_length > crate::net::MAX_BODY {
        return Err(Error::new(
            "unsupported",
            "DOCX original requires supported MIME and a bounded nonempty response",
        ));
    }
    Ok(())
}

fn validate_document(response: &crate::net::Response) -> Result<(), Error> {
    validate_document_metadata(
        response.status,
        response.headers.get("content-type").map(String::as_str),
        response.body.len(),
    )?;
    let bytes = response.body.as_slice();
    let tail_start = bytes.len().saturating_sub(22 + u16::MAX as usize);
    let framed = bytes.starts_with(b"PK\x03\x04")
        && bytes[tail_start..]
            .windows(22)
            .enumerate()
            .any(|(offset, end)| {
                end.starts_with(b"PK\x05\x06")
                    && tail_start + offset + 22 + u16::from_le_bytes([end[20], end[21]]) as usize
                        == bytes.len()
            });
    if !framed {
        return Err(Error::new(
            "unsupported",
            "declared DOCX lacks ZIP header/end framing; original bytes were not admitted",
        ));
    }
    Ok(())
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
                "Sepe article requires one direct nymain/art-main container",
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
                "Sepe article requires one direct art-tit/h3 heading",
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
                "Sepe article requires one scoped vsb_content/v_news_content body",
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
            url: "https://sepe.buaa.edu.cn/info/1078/42.htm".into(),
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
    fn sepe_original_body_and_sibling_files_keep_source_boundaries() {
        let response = source(
            "<h3>Original heading</h3><p><span class=\"date\">日期：2026年09月30日</span></p>",
            "<p>First <em>inline</em> body.<script>not prose</script></p>",
            "<p><ul><li><a href=\"/system/_content/download.jsp?wbfileid=form&amp;owner=1\">Form.docx</a></li></ul></p><template><a href=\"/system/_content/download.jsp?wbfileid=inactive\">Inactive.pdf</a></template>",
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["title"], "Original heading");
        assert_eq!(output["published_at"], "2026-09-30");
        assert_eq!(output["body_paragraphs"], json!(["First inline body."]));
        assert_eq!(output["result"], "partial_text");
        assert_eq!(
            output["attachments"]["hints"],
            json!([{"href":"/system/_content/download.jsp?wbfileid=form&owner=1","text":"Form.docx","fetched":false}])
        );
    }

    #[test]
    fn sepe_docx_end_record_cannot_hide_truncation_or_unaccounted_trailing_bytes() {
        let mut response = source("", "", "");
        response
            .headers
            .insert("content-type".into(), "application/octet-stream".into());
        response.body = b"PK\x03\x04syntheticPK\x05\x06".to_vec();
        response.body.extend_from_slice(&[0; 18]);
        response
            .body
            .extend_from_slice(b"unaccounted trailing bytes");
        assert_eq!(
            validate_document(&response).unwrap_err().code,
            "unsupported"
        );
        response.body.truncate(10);
        assert_eq!(
            validate_document(&response).unwrap_err().code,
            "unsupported"
        );
    }

    #[test]
    fn sepe_ambiguous_header_dates_and_untranscribed_content_stay_explicit() {
        let response = source(
            "<h3>Original heading</h3><p><span class=\"date\">日期：2026年09月30日</span><span class=\"date\">日期：2026年09月29日</span></p>",
            "<p>Body date 2026-09-30 is not publication metadata.</p><img src=\"poster.png\" alt=\"not transcribed\"><table><tr><td><p>Source cell paragraph.</p></td></tr></table>",
            "",
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["published_at"], Value::Null);
        assert_eq!(
            output["body_paragraphs"],
            json!([
                "Body date 2026-09-30 is not publication metadata.",
                "Source cell paragraph."
            ])
        );
        assert_eq!(output["result"], "partial_text");
        assert_eq!(output["completeness"]["image_content_present"], true);
        assert_eq!(output["completeness"]["unextracted_table_count"], 1);
    }
}
