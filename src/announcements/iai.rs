//! Official-directory-bound Artificial Intelligence college announcements.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    article_body, article_output, bind_college_board, college_directory_attribution, college_html,
    describe_college_surface, element_text, entry_in_scope, failed_contract, invalid_article,
    invalid_list, is_http, parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, IAI_NOTICES_URL, IAI_ROOT_URL, Response, iai_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学人工智能学院";
const LISTED_ROOT_URL: &str = "http://iai.buaa.edu.cn/";
const RESOLVED_ROOT_URL: &str = "http://iai.buaa.edu.cn/";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("iai.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && iai_path_allowed(url.path())
}

fn source_date(raw: &str) -> Option<String> {
    parse_iso_date(raw.trim())
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
        "人工智能学院",
        LISTED_ROOT_URL,
        RESOLVED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = IAI_ROOT_URL.into();
    attribution["selection_relation"] =
        "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_iai(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => IAI_ROOT_URL,
        "notices" => IAI_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, IAI_ROOT_URL, IAI_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "iai", attribution)
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
    let views = Selector::parse("div.mainBox > div.listText > ul").map_err(|_| unavailable())?;
    let mut views = document.select(&views).filter(|node| !super::inert_element(*node));
    let view = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "IAI notice listing requires one mainBox/listText view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a[href]").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > i").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in view.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut links = row.select(&anchors);
        let anchor = links
            .next()
            .filter(|_| links.next().is_none())
            .ok_or_else(|| {
                failed_contract(
                    "IAI notice row requires one direct a source heading",
                    file!(),
                    line!(),
                )
            })?;
        let heading = element_text(anchor);
        let title = (!heading.is_empty() && heading.len() <= MAX_TEXT)
            .then_some(heading)
            .ok_or_else(|| {
                failed_contract(
                    "IAI notice row requires a nonempty bounded source heading",
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
        let mut row_dates = row.select(&dates);
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
            category_label: Some("通知公告".into()),
            summary: None,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "IAI notice listing has no source rows",
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
            "IAI notice board has no reviewed later-page declaration",
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
    bind_college_board(&client, IAI_ROOT_URL, IAI_NOTICES_URL, &mut attribution)?;
    let target = Url::parse(IAI_NOTICES_URL).map_err(|_| unavailable())?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = parse_listing(&college_html(response)?, &target)?;
        let entries: Vec<&ListingEntry> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
            .collect();
        Ok(json!({
            "schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"iai","category":"tzgg","listing_label":"通知公告","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"no reviewed later-page declaration; no traversal","other_colleges":"not_covered","dates":"source YYYY-MM-DD; missing or invalid stays null"},
            "retrieval":retrieval(response)
        }))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1024/")
        || source_page == 0
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
    if source_page != 1 {
        return Err(Error::new(
            "unavailable",
            "IAI notice board has no reviewed later-page declaration",
        ));
    }
    bind_college_board(&client, IAI_ROOT_URL, IAI_NOTICES_URL, &mut attribution)?;
    let source = Url::parse(IAI_NOTICES_URL).map_err(|_| unavailable())?;
    let listing = client.get(&source, false, |response| {
        let document = parse_listing(&college_html(response)?, &source)?;
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Err(Error::new(
                "unsupported",
                "retained notice board does not declare the selected IAI article",
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
                value["college"] = json!("iai");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
}

fn publication_date(raw: &str) -> Option<String> {
    raw.trim()
        .strip_prefix("发布时间:")
        .and_then(source_date)
}

fn declared_embedded_document(
    body: ElementRef<'_>,
    article: &Url,
) -> Result<(Option<String>, Vec<String>), Error> {
    let scripts = Selector::parse("script").map_err(|_| unavailable())?;
    let mut original: Option<String> = None;
    let mut previews = Vec::new();
    for script in body.select(&scripts) {
        if script.value().attr("src").is_some() {
            continue;
        }
        let text = script.text().collect::<String>();
        if let Some(marker) = text.find("vsb_pdf_image_data") {
            let tail = text[marker..]
                .split_once('=')
                .map(|(_, rest)| rest.trim_start())
                .ok_or_else(unavailable)?;
            if tail.starts_with('[') {
                let end = tail.find(']').ok_or_else(unavailable)?;
                if end + 1 > 64 * 1024 {
                    return Err(unavailable());
                }
                let paths: Vec<String> =
                    serde_json::from_str(&tail[..=end]).map_err(|_| unavailable())?;
                if paths.len() > 128
                    || paths.iter().any(|path| {
                        path.len() > MAX_HREF
                            || !path.starts_with("/__local/")
                            || path.chars().any(char::is_control)
                    })
                {
                    return Err(unavailable());
                }
                previews = paths;
            }
        }
        let Some(marker) = text.find("showVsbpdfIframe(") else {
            continue;
        };
        let tail = &text[marker + "showVsbpdfIframe(".len()..];
        let quote = tail
            .chars()
            .next()
            .filter(|quote| *quote == '\'' || *quote == '"')
            .ok_or_else(unavailable)?;
        let path = tail[quote.len_utf8()..]
            .split(quote)
            .next()
            .filter(|path| !path.is_empty() && path.len() <= MAX_HREF)
            .ok_or_else(unavailable)?;
        let url = article.join(path).map_err(|_| unavailable())?;
        if url.scheme() != "https"
            || url.host_str() != article.host_str()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.path().starts_with("/__local/")
            || !url.path().to_ascii_lowercase().ends_with(".pdf")
        {
            return Err(failed_contract(
                "IAI embedded document must be a same-host source-declared PDF",
                file!(),
                line!(),
            ));
        }
        if original.as_deref().is_some_and(|previous| previous != url.as_str()) {
            return Err(failed_contract(
                "IAI article declares ambiguous embedded PDF documents",
                file!(),
                line!(),
            ));
        }
        original = Some(url.to_string());
    }
    Ok((original, previews))
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let forms = Selector::parse("div.mainBox > div.clear > div.nry2 > form")
        .map_err(|_| unavailable())?;
    let mut forms = document.select(&forms).filter(|node| !super::inert_element(*node));
    let form = forms
        .next()
        .filter(|_| forms.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "IAI article requires one mainBox/nry2 source form",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse("div.show01 > h5").map_err(|_| unavailable())?;
    let mut headings = form.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|text| !text.is_empty() && text.len() <= MAX_HREF)
        .ok_or_else(|| {
            failed_contract(
                "IAI article requires one nonempty show01/h5 source heading",
                file!(),
                line!(),
            )
        })?;
    let dates = Selector::parse("div.show01 > div.date > s").map_err(|_| unavailable())?;
    let mut dates = form.select(&dates);
    let published_at_raw = dates
        .next()
        .filter(|_| dates.next().is_none())
        .map(element_text);
    let published_at = published_at_raw.as_deref().and_then(publication_date);
    let bodies = Selector::parse("div#vsb_content.show02 > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = form.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "IAI article requires one vsb_content/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, true)?;
    let article_url = Url::parse(&response.url).map_err(|_| unavailable())?;
    let (original_pdf_url, preview_paths) = declared_embedded_document(body, &article_url)?;
    if paragraphs.is_empty() && original_pdf_url.is_none() && attachment_hints.is_empty() {
        return Err(failed_contract(
            "IAI article requires text or source-declared embedded document/attachment content",
            file!(),
            line!(),
        ));
    }
    let has_document = original_pdf_url.is_some() || !preview_paths.is_empty();
    let result = if has_document {
        if paragraphs.is_empty() {
            "embedded_document"
        } else {
            "partial_text"
        }
    } else if paragraphs.is_empty() {
        "attachment_only"
    } else if attachments_found {
        "partial_text"
    } else {
        "full_text"
    };
    let mut output = article_output(
        response,
        ArticleDocument {
            title,
            published_at,
            category: Some("通知公告".into()),
            paragraphs,
            attachment_hints,
            attachments_found,
        },
    );
    output["result"] = json!(result);
    output["embedded_document"] = json!({
        "present":has_document,
        "original_pdf_url":original_pdf_url,
        "preview_paths":preview_paths,
        "preview_kind":"source_declared_derived_images",
        "assets_fetched":false,
        "ocr_performed":false,
        "original_document_verified":false
    });
    output["completeness"]["body_source"] = json!("v_news_content paragraphs excluding executable/fallback markup");
    output["completeness"]["missing_document_text"] = json!("not_reconstructed");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(url: &str, body: &str) -> Response {
        Response {
            url: url.into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            body: body.as_bytes().to_vec(),
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn listing_preserves_source_order_and_dates() {
        let document = Html::parse_document(
            r#"<title>通知公告-人工智能学院</title><div class="mainBox"><div class="listText"><ul>
            <li class="clear"><a href="../info/1024/42.htm">First notice</a><i>2026-09-24</i></li>
            <li class="clear"><a href="../info/1024/41.htm">Earlier notice</a><i>2026-06-12</i></li>
        </ul></div></div>"#,
        );
        let base = Url::parse(IAI_NOTICES_URL).unwrap();
        let listing = parse_listing(&document, &base).unwrap();
        assert_eq!(listing.entries.len(), 2);
        assert_eq!(listing.entries[0].source_order, 1);
        assert_eq!(listing.entries[0].date.as_deref(), Some("2026-09-24"));
        assert_eq!(listing.entries[0].resolved_http_url.as_deref(), Some("https://iai.buaa.edu.cn/info/1024/42.htm"));
    }

    #[test]
    fn article_accepts_source_declared_embedded_pdf_without_fabricating_text() {
        let source = r#"<div class="mainBox"><div class="clear"><div class="nry2"><form>
            <div class="show01"><h5>Embedded notice</h5><div class="date"><i>点击数:<script>1</script></i><s>发布时间:2026-09-24</s></div></div>
            <div id="vsb_content" class="show02"><div class="v_news_content"><p><script>var vsb_pdf_image_data = ["/__local/a.jpg"];showVsbpdfIframe("/__local/source.pdf","100%");</script></p></div></div>
        </form></div></div></div>"#;
        let response = response("https://iai.buaa.edu.cn/info/1024/42.htm", source);
        let document = college_html(&response).unwrap();
        let output = normalize(&response, &document).unwrap();
        assert_eq!(output["result"], "embedded_document");
        assert_eq!(output["published_at"], "2026-09-24");
        assert_eq!(output["body_paragraph_count"], 0);
        assert_eq!(output["embedded_document"]["original_pdf_url"], "https://iai.buaa.edu.cn/__local/source.pdf");
    }

    #[test]
    fn listing_rejects_missing_source_heading() {
        let document = Html::parse_document(
            r#"<div class="mainBox"><div class="listText"><ul><li><i>2026-09-24</i></li></ul></div></div>"#,
        );
        assert_eq!(parse_listing(&document, &Url::parse(IAI_NOTICES_URL).unwrap()).unwrap_err().code, "unavailable");
    }
}
