//! Official-directory-bound Humanities and Social Sciences college notices.
//!
//! The directory advertises this source as literal HTTP.  The adapter keeps
//! that identity (rather than silently upgrading it to HTTPS), binds the
//! source-declared notice board, and only follows article URLs present in the
//! selected board snapshot.
use super::{
    ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    article_body, bind_college_board, college_directory_attribution, college_html,
    declared_jsp_attachment_hints, describe_college_surface, element_text, entry_in_scope,
    failed_contract, invalid_article, invalid_list, is_http, parse_iso_date, retrieval,
    unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, HSS_NOTICES_URL, HSS_ROOT_URL, Response, hss_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学人文社会科学学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "http"
        && url.host_str() == Some("www.hss.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && hss_path_allowed(url.path())
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let attribution = college_directory_attribution(
        &directory,
        "人文社会科学学院",
        HSS_ROOT_URL,
        HSS_ROOT_URL,
    )?;
    Ok((ArchiveClient::open_hss(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => HSS_ROOT_URL,
        "notices" => HSS_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, HSS_ROOT_URL, HSS_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "hss", attribution)
        })
}

fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(element_text)
        .unwrap_or_default();
    if title.len() > MAX_TEXT {
        return Err(unavailable());
    }
    let lists = Selector::parse("div.n_right > ul.list").map_err(|_| unavailable())?;
    let mut lists = document.select(&lists);
    let list = lists.next().filter(|_| lists.next().is_none()).ok_or_else(|| {
        failed_contract(
            "HSS notice listing requires one n_right/list view",
            file!(),
            line!(),
        )
    })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a[href]").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > a[href] > span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in list.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut row_anchors = row.select(&anchors);
        let anchor = row_anchors.next().ok_or_else(|| {
            failed_contract(
                "HSS notice row requires one direct anchor",
                file!(),
                line!(),
            )
        })?;
        if row_anchors.next().is_some() {
            return Err(failed_contract(
                "HSS notice row requires one direct anchor",
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
        let date_text = {
            let mut row_dates = row.select(&dates);
            let first = row_dates.next().map(element_text);
            if row_dates.next().is_some() {
                None
            } else {
                first
            }
        };
        let date = date_text.as_deref().and_then(parse_iso_date);
        let anchor_text = element_text(anchor);
        let title = date_text
            .as_deref()
            .and_then(|date| anchor_text.strip_prefix(date))
            .map(str::trim)
            .unwrap_or(anchor_text.as_str())
            .to_owned();
        if title.is_empty() || title.len() > MAX_TEXT {
            return Err(failed_contract(
                "HSS notice row requires a nonempty source title",
                file!(),
                line!(),
            ));
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
            "HSS notice listing has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

/// HSS's legacy pagination labels are “下页/尾页”, not numeric anchors.  The
/// source also exposes the `N/2` page indicator and uses zero-based file names
/// (`tzgg/1.htm` is display page 2).  Resolve only that explicit declaration.
fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(HSS_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        let document = college_html(response)?;
        let links = Selector::parse("div.pages a[href]").map_err(|_| unavailable())?;
        let mut selected = None;
        for link in document.select(&links) {
            let raw = link.value().attr("href").ok_or_else(unavailable)?;
            let url = latest.join(raw).map_err(|_| unavailable())?;
            if !plain_url(&url) || !url.path().starts_with("/xwzx1/tzgg/") {
                continue;
            }
            let Some(stem) = url
                .path()
                .strip_prefix("/xwzx1/tzgg/")
                .and_then(|path| path.strip_suffix(".htm"))
            else {
                continue;
            };
            let Some(file_page) = stem.parse::<u32>().ok() else {
                continue;
            };
            if file_page.checked_add(1) != Some(page) {
                continue;
            }
            match selected.as_ref() {
                Some(previous) if previous != &url => {
                    return Err(Error::new(
                        "unavailable",
                        "requested HSS page has conflicting advertised destinations; no URL was selected",
                    ));
                }
                None => selected = Some(url),
                _ => {}
            }
        }
        selected.ok_or_else(|| {
            Error::new(
                "unavailable",
                "requested HSS page is not advertised by the retained notice listing; no URL was inferred",
            )
        })
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
    bind_college_board(&client, HSS_ROOT_URL, HSS_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = parse_listing(&college_html(response)?, &target)?;
        let entries: Vec<&ListingEntry> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
            .collect();
        Ok(json!({
            "schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"hss","category":"tzgg","listing_label":"通知公告","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source-advertised ordinal only; no automatic traversal","other_colleges":"not_covered","dates":"source ISO dates; source order retained; missing or invalid stays null","summaries":"source titles only; no excerpt promotion"},
            "retrieval":retrieval(response)
        }))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1103/")
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
    bind_college_board(&client, HSS_ROOT_URL, HSS_NOTICES_URL, &mut attribution)?;
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
                "retained HSS notice page does not declare the selected article",
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
                value["college"] = json!("hss");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
}

fn local_asset_url(base: &Url, raw: &str, suffix: &str) -> Result<String, Error> {
    if raw.len() > MAX_HREF
        || raw.chars().any(char::is_control)
        || !raw.starts_with("/__local/")
        || !raw.to_ascii_lowercase().ends_with(suffix)
    {
        return Err(unavailable());
    }
    let url = base.join(raw).map_err(|_| unavailable())?;
    if url.scheme() != base.scheme()
        || url.host_str() != base.host_str()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(unavailable());
    }
    Ok(url.to_string())
}

fn quoted_argument(raw: &str) -> Option<String> {
    let raw = raw.trim_start();
    let quote = *raw.as_bytes().first()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let tail = &raw[1..];
    let end = tail.find(quote as char)?;
    Some(tail[..end].to_owned())
}

fn declared_document(
    body: ElementRef<'_>,
    base: &Url,
) -> Result<(bool, Option<String>, Vec<String>), Error> {
    let scripts = Selector::parse("script").map_err(|_| unavailable())?;
    let mut original_pdf = None;
    let mut previews = Vec::new();
    for script in body.select(&scripts) {
        let source = script.text().collect::<String>();
        if let Some(offset) = source.find("showVsbpdfIframe(") {
            let start = offset + "showVsbpdfIframe(".len();
            let raw = quoted_argument(&source[start..]).ok_or_else(unavailable)?;
            original_pdf = Some(local_asset_url(base, &raw, ".pdf")?);
        }
        if let Some(offset) = source.find("vsb_pdf_image_data") {
            let tail = &source[offset..];
            let start = tail.find('[').ok_or_else(unavailable)?;
            let end = tail[start..]
                .find(']')
                .map(|position| start + position)
                .ok_or_else(unavailable)?;
            let paths: Vec<String> = serde_json::from_str(&tail[start..=end]).map_err(|_| unavailable())?;
            if paths.len() > 128 {
                return Err(unavailable());
            }
            for path in paths {
                previews.push(local_asset_url(base, &path, ".jpg")?);
            }
        }
    }
    Ok((original_pdf.is_some() || !previews.is_empty(), original_pdf, previews))
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let mains = Selector::parse(
        "div.n_con > form[name=\"_newscontent_fromname\"] > div.contain_con",
    )
    .map_err(|_| unavailable())?;
    let mut mains = document.select(&mains);
    let main = mains.next().filter(|_| mains.next().is_none()).ok_or_else(|| {
        failed_contract(
            "HSS article requires one n_con/newscontent contain_con container",
            file!(),
            line!(),
        )
    })?;
    let headings = Selector::parse(":scope > h2").map_err(|_| unavailable())?;
    let mut headings = main.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "HSS article requires one direct nonempty h2 heading",
                file!(),
                line!(),
            )
        })?;
    let date_selector = Selector::parse(":scope > p[style*=\"text-align:center\"]")
        .map_err(|_| unavailable())?;
    let mut date_nodes = main.select(&date_selector);
    let published_at = date_nodes
        .next()
        .map(element_text)
        .and_then(|raw| raw.split_once("发布日期：").and_then(|(_, tail)| {
            tail.split_whitespace().next().and_then(parse_iso_date)
        }));
    if date_nodes.next().is_some() {
        return Err(unavailable());
    }
    let bodies = Selector::parse(":scope > div#vsb_content > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies.next().filter(|_| bodies.next().is_none()).ok_or_else(|| {
        failed_contract(
            "HSS article requires one direct vsb_content/v_news_content body",
            file!(),
            line!(),
        )
    })?;
    let (paragraphs, mut attachment_hints, mut attachments_found) = article_body(body, true)?;
    let (declared_hints, hints_truncated) = declared_jsp_attachment_hints(main)?;
    attachments_found |= !declared_hints.is_empty();
    attachment_hints.extend(declared_hints);
    let base = Url::parse(&response.url).map_err(|_| unavailable())?;
    let (has_document, original_pdf, previews) = declared_document(body, &base)?;
    if paragraphs.is_empty() && !has_document && attachment_hints.is_empty() {
        return Err(failed_contract(
            "HSS article requires text or source-declared document/attachment content",
            file!(),
            line!(),
        ));
    }
    let result = if has_document {
        if paragraphs.is_empty() {
            "embedded_document"
        } else {
            "partial_text"
        }
    } else if paragraphs.is_empty() {
        "attachment_only"
    } else {
        "full_text"
    };
    let mut output = json!({
        "schema_version":1,"type":"announcements_article","result":result,"publisher":PUBLISHER,"college":"hss",
        "title":title,"category":"1103","published_at":published_at,
        "body_paragraph_count":paragraphs.len(),"body_paragraphs":paragraphs,
        "embedded_document":{"present":has_document,"original_pdf_url":original_pdf,"preview_paths":previews,"preview_kind":"source_declared_derived_images","assets_fetched":false,"ocr_performed":false,"original_document_verified":false},
        "attachments":{"found":attachments_found,"hints":attachment_hints,"hints_truncated":hints_truncated,"note":"source-declared links only; never fetched"},
        "completeness":{"scope":"single_college_article_page","body_source":"v_news_content paragraphs excluding executable/fallback markup","missing_document_text":"not_reconstructed"},
        "retrieval":retrieval(response)
    });
    output["attachments"]["hints_truncated"] = json!(hints_truncated);
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
            body: body.as_bytes().to_vec(),
            sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            fetched_at_unix_ms: 7,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn listing_uses_direct_rows_and_source_dates_without_promoting_date_text() {
        let html = r#"<title>通知公告-人文社会科学学院</title><div class="n_right"><ul class="list">
            <li><a href="../info/1103/42.htm"><span>2026-10-15</span>First source notice</a></li>
            <li><a href="../info/1103/43.htm"><span>2026-02-30</span>Unknown date notice</a></li>
        </ul></div><ul class="list"><li>unrelated</li></ul>"#;
        let parsed = parse_listing(
            &Html::parse_document(html),
            &Url::parse(HSS_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.entries[0].title, "First source notice");
        assert_eq!(parsed.entries[0].date.as_deref(), Some("2026-10-15"));
        assert_eq!(parsed.entries[1].date, None);
        let since = Some("2026-10-01".to_owned());
        assert_eq!(
            parsed
                .entries
                .iter()
                .filter(|entry| entry_in_scope(entry, &since, &None, &None))
                .map(|entry| entry.title.as_str())
                .collect::<Vec<_>>(),
            vec!["First source notice"]
        );
    }

    #[test]
    fn image_pdf_article_is_embedded_document_with_sibling_attachment_hints() {
        let html = r#"<div class="n_con"><form name="_newscontent_fromname"><div class="contain_con">
            <h2>Source article heading</h2><p style="text-align:center;background:#f5f5f5">【 发布日期：2026-10-15 】</p>
            <div id="vsb_content"><div class="v_news_content"><p><script>var vsb_pdf_image_data=["/__local/1/AA/BB/CC/preview.jpg"];showVsbpdfIframe("/__local/1/AA/BB/CC/original.pdf","100%","600");</script></p></div></div>
            <p><ul><li>附件<a href="/system/_content/download.jsp?file=1">附件：Form.pdf</a></li></ul></p>
        </div></form></div>"#;
        let response = response("http://www.hss.buaa.edu.cn/info/1103/42.htm", html);
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["result"], "embedded_document");
        assert_eq!(output["published_at"], "2026-10-15");
        assert_eq!(output["body_paragraph_count"], 0);
        assert_eq!(output["embedded_document"]["present"], true);
        assert_eq!(output["attachments"]["hints"][0]["text"], "附件：Form.pdf");
    }

    #[test]
    fn page_two_requires_the_explicit_zero_based_board_link() {
        let html = r#"<div class="pages"><span class="PrevDisabled">上页</span><a href="tzgg/1.htm">下页</a><a href="tzgg/1.htm">尾页</a></div>"#;
        let document = Html::parse_document(html);
        let links = Selector::parse("div.pages a[href]").unwrap();
        let base = Url::parse(HSS_NOTICES_URL).unwrap();
        let targets: Vec<_> = document
            .select(&links)
            .filter_map(|node| base.join(node.value().attr("href")?).ok())
            .collect();
        assert_eq!(targets, vec![
            Url::parse("http://www.hss.buaa.edu.cn/xwzx1/tzgg/1.htm").unwrap(),
            Url::parse("http://www.hss.buaa.edu.cn/xwzx1/tzgg/1.htm").unwrap()
        ]);
        assert!(plain_url(&targets[0]));
    }
}
