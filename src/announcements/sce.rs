//! Chemistry-college CMS contract, observed independently of the news center.
//! The root declares the `xwzx/xyxw.htm`学院新闻 board. Listing rows use
//! `.fy-list` with direct date spans and anchors; articles use the scoped
//! `.c-content` title/date/body layout. Source links are never followed unless
//! they remain inside the reviewed Chemistry host and path namespace.

use super::{
    ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT, article_body,
    article_category_from_url,
    article_output, college_directory_attribution, college_html,
    describe_college_surface, element_text, entry_in_scope, failed_contract, inert_element,
    invalid_article, invalid_list, parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, SCE_NOTICES_URL, SCE_ROOT_URL, sce_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://sce.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学化学学院";

fn discovery_mode(mode: CacheMode) -> CacheMode {
    if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    }
}

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("sce.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && sce_path_allowed(url.path())
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let cache_mode = discovery_mode(mode);
    let directory = crate::organizations::list(cache_mode)?;
    let mut attribution = college_directory_attribution(
        &directory,
        "化学学院",
        LISTED_ROOT_URL,
        LISTED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = SCE_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_sce(cache_mode)?, attribution))
}

fn bind_board(client: &ArchiveClient, attribution: &mut Value) -> Result<(), Error> {
    let root = Url::parse(SCE_ROOT_URL).map_err(|_| unavailable())?;
    let board = Url::parse(SCE_NOTICES_URL).map_err(|_| unavailable())?;
    let root_source = client.get(&root, false, |response| {
        let document = college_html(response)?;
        let links = Selector::parse("a[href]").map_err(|_| unavailable())?;
        if !document.select(&links).any(|node| {
            !inert_element(node)
                && node.value().attr("href").is_some_and(|raw| {
                    raw.len() <= MAX_HREF
                        && !raw.chars().any(char::is_control)
                        && !raw.contains(['%', '\\'])
                        && root.join(raw).is_ok_and(|url| url == board)
                })
        }) {
            return Err(Error::new(
                "unsupported",
                "retained Chemistry root does not declare the reviewed news board",
            ));
        }
        Ok(retrieval(response))
    })?;
    attribution["root_retrieval"] = root_source;
    Ok(())
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => SCE_ROOT_URL,
        "notices" => SCE_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_board(&client, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "sce", attribution)
        })
}

fn advertised_sce_page_url(
    bytes: &[u8],
    base: &Url,
    page: u32,
) -> Result<Url, Error> {
    if bytes.is_empty() || bytes.len() > super::MAX_HTML {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(text);
    let links = Selector::parse("table.headStyle16sn2e3sl5 a[href]").map_err(|_| unavailable())?;
    let mut selected = None;
    for link in document.select(&links) {
        let raw = link.value().attr("href").ok_or_else(unavailable)?;
        if raw.len() > MAX_HREF || raw.chars().any(char::is_control) || raw.contains(['%', '\\']) {
            return Err(failed_contract(
                "Chemistry pager links must remain literal source declarations",
                file!(),
                line!(),
            ));
        }
        let url = base.join(raw).map_err(|_| unavailable())?;
        let path_page = url
            .path()
            .strip_prefix("/xwzx/xyxw/")
            .and_then(|tail| tail.strip_suffix(".htm"))
            .and_then(|tail| tail.parse::<u32>().ok());
        let label_page = element_text(link).parse::<u32>().ok();
        if label_page != Some(page) && path_page != Some(page) {
            continue;
        }
        if !plain_url(&url) || !url.path().starts_with("/xwzx/xyxw/") {
            return Err(failed_contract(
                "Chemistry advertised page must remain inside the reviewed board",
                file!(),
                line!(),
            ));
        }
        match selected.as_ref() {
            Some(previous) if previous != &url => {
                return Err(Error::new(
                    "unavailable",
                    "requested Chemistry page has conflicting advertised destinations; no URL was selected",
                ));
            }
            None => selected = Some(url),
            _ => {}
        }
    }
    selected.ok_or_else(|| {
        Error::new(
            "unavailable",
            "requested Chemistry page is not advertised by the retained latest listing; no URL was inferred",
        )
    })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(SCE_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        college_html(response)?;
        advertised_sce_page_url(&response.body, &latest, page)
    })
}

fn parse_listing_document(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let title = document
        .select(&Selector::parse("title").map_err(|_| unavailable())?)
        .next()
        .map(element_text)
        .unwrap_or_default();
    if title.len() > MAX_TEXT {
        return Err(unavailable());
    }
    let views = Selector::parse("div.fy-list > ul").map_err(|_| unavailable())?;
    let mut views = document.select(&views).filter(|node| !inert_element(*node));
    let primary = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Chemistry listing requires one active fy-list view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in primary.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(failed_contract(
                "Chemistry listing exceeds the reviewed row budget",
                file!(),
                line!(),
            ));
        }
        let mut row_anchors = row.select(&anchors);
        let anchor = row_anchors.next().ok_or_else(|| {
            failed_contract(
                "Chemistry listing row requires one direct article anchor",
                file!(),
                line!(),
            )
        })?;
        if row_anchors.next().is_some() {
            return Err(failed_contract(
                "Chemistry listing row has ambiguous direct article anchors",
                file!(),
                line!(),
            ));
        }
        let title = element_text(anchor);
        if title.is_empty() || title.len() > MAX_TEXT {
            return Err(failed_contract(
                "Chemistry listing row requires bounded source title text",
                file!(),
                line!(),
            ));
        }
        let listed_href = anchor.value().attr("href");
        if listed_href.is_some_and(|href| {
            href.len() > MAX_HREF || href.chars().any(char::is_control)
        }) {
            return Err(failed_contract(
                "Chemistry listing href exceeds the reviewed source budget",
                file!(),
                line!(),
            ));
        }
        let listed_href = listed_href.filter(|href| !href.is_empty()).map(str::to_owned);
        let mut row_dates = row.select(&dates);
        let date = row_dates
            .next()
            .filter(|_| row_dates.next().is_none())
            .and_then(|node| parse_iso_date(&element_text(node)));
        let (resolved_http_url, link_kind) = match listed_href.as_deref() {
            None => (None, "missing"),
            Some(raw) => match base.join(raw) {
                Ok(url) if matches!(url.scheme(), "http" | "https") => {
                    (Some(url.to_string()), "http")
                }
                Ok(_) => (None, "non_http"),
                Err(_) => (None, "invalid"),
            },
        };
        entries.push(ListingEntry {
            source_order: entries.len() + 1,
            title,
            date,
            category_label: Some("学院新闻".into()),
            summary: None,
            listed_href,
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "Chemistry listing has no active fy-list rows",
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
        .is_some_and(|category| category != "xyxw")
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
    bind_board(&client, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let base = Url::parse(&response.url).map_err(|_| unavailable())?;
        let document = parse_listing_document(&college_html(response)?, &base)?;
        let entries: Vec<&ListingEntry> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
            .collect();
        Ok(json!({
            "schema_version":1,
            "type":"announcements_list",
            "result":"listing_snapshot",
            "publisher":PUBLISHER,
            "college":"sce",
            "category":"xyxw",
            "listing_label":"学院新闻",
            "page":page,
            "document_title":document.title,
            "filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,
            "entry_count":entries.len(),
            "directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source-advertised board paths only; no automatic traversal","other_colleges":"not_covered","dates":"source YYYY-MM-DD; missing or invalid stays null"},
            "retrieval":retrieval(response)
        }))
    })
}

fn resolve_article(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != url.as_str()
        || !plain_url(&url)
        || !url.path().starts_with("/info/1013/")
    {
        return Err(invalid_article());
    }
    Ok(url)
}

fn parse_sce_date(raw: &str) -> Option<String> {
    let marker = "发布日期：";
    let value = raw.split_once(marker)?.1.trim();
    let value = value.split_whitespace().next()?;
    parse_iso_date(value)
}

fn normalize(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    let containers = Selector::parse("div.c-content").map_err(|_| unavailable())?;
    let mut containers = document.select(&containers).filter(|node| !inert_element(*node));
    let content = containers
        .next()
        .filter(|_| containers.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Chemistry article requires one active c-content container",
                file!(),
                line!(),
            )
        })?;
    let titles = Selector::parse(":scope > h1.c-title").map_err(|_| unavailable())?;
    let mut titles = content.select(&titles);
    let title = titles
        .next()
        .filter(|_| titles.next().is_none())
        .map(element_text)
        .filter(|text| !text.is_empty() && text.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "Chemistry article requires one direct c-title heading",
                file!(),
                line!(),
            )
        })?;
    let metadata = Selector::parse(":scope > div.other-s").map_err(|_| unavailable())?;
    let mut metadata = content.select(&metadata);
    let published_at_raw = metadata
        .next()
        .filter(|_| metadata.next().is_none())
        .map(element_text);
    let published_at = published_at_raw.as_deref().and_then(parse_sce_date);
    let bodies = Selector::parse(
        ":scope > div.nr-info > div#vsb_content > div.v_news_content",
    )
    .map_err(|_| unavailable())?;
    let mut bodies = content.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Chemistry article requires one scoped vsb_content/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, false)?;
    let has_attachments = attachments_found;
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let has_images = body.select(&images).any(|image| !inert_element(image));
    if paragraphs.is_empty() {
        return Err(failed_contract(
            "Chemistry article requires source paragraphs; image-only content is not reconstructed",
            file!(),
            line!(),
        ));
    }
    let mut output = article_output(
        response,
        super::ArticleDocument {
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
    output["publisher"] = json!(PUBLISHER);
    output["college"] = json!("sce");
    output["listing_category"] = json!("xyxw");
    output["completeness"]["body_source"] = json!(
        "unique c-content/nr-info/vsb_content/v_news_content; source paragraphs with executable/fallback markup excluded"
    );
    output["completeness"]["image_content_present"] = json!(has_images);
    if has_images || has_attachments {
        output["result"] = json!("partial_text");
        output["completeness"]["missing_nonparagraph_content"] = json!(
            "image text and attachment contents are not reconstructed or downloaded"
        );
    }
    Ok(output)
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = resolve_article(raw)?;
    if source_page == 0 {
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
    bind_board(&client, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing = client.get(&source, false, |response| {
        let base = Url::parse(&response.url).map_err(|_| unavailable())?;
        let document = parse_listing_document(&college_html(response)?, &base)?;
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Err(Error::new(
                "unsupported",
                "retained Chemistry listing does not declare the selected article",
            ));
        }
        Ok(retrieval(response))
    })?;
    client
        .with_cache_mode(mode)
        .get(target, false, |response| {
            let document = college_html(response)?;
            normalize(response, &document).map(|mut value| {
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CacheStatus, Response};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://sce.buaa.edu.cn/info/1013/42.htm".into(),
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
    fn chemistry_listing_preserves_source_order_and_filters_dates() {
        let document = Html::parse_document(
            r#"<title>学院新闻-化学学院</title><div class="fy-list"><ul>
            <li><span>2026-09-29</span><a href="../info/1013/42.htm">First source heading</a></li>
            <li><span>bad-date</span><a href="../info/1013/43.htm">Unknown date remains null</a></li>
        </ul></div>"#,
        );
        let parsed = parse_listing_document(
            &document,
            &Url::parse(SCE_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.entries[0].date.as_deref(), Some("2026-09-29"));
        assert_eq!(parsed.entries[1].date, None);
        assert_eq!(parsed.entries[0].source_order, 1);
        assert_eq!(parsed.entries[0].resolved_http_url.as_deref(), Some("https://sce.buaa.edu.cn/info/1013/42.htm"));
    }

    #[test]
    fn chemistry_pager_accepts_only_advertised_board_paths() {
        let base = Url::parse(SCE_NOTICES_URL).unwrap();
        let body = br#"<table class="headStyle16sn2e3sl5"><a href="xyxw/30.htm">下页</a><a href="xyxw/1.htm">尾页</a></table>"#;
        assert_eq!(
            advertised_sce_page_url(body, &base, 30).unwrap().path(),
            "/xwzx/xyxw/30.htm"
        );
        assert_eq!(
            advertised_sce_page_url(body, &base, 2).unwrap_err().code,
            "unavailable"
        );
        let foreign = br#"<table class="headStyle16sn2e3sl5"><a href="https://evil.example/2.htm">2</a></table>"#;
        assert_eq!(
            advertised_sce_page_url(foreign, &base, 2).unwrap_err().code,
            "unavailable"
        );
    }

    #[test]
    fn chemistry_article_scopes_title_date_and_body_and_marks_images_partial() {
        let body = r#"<h2>Sidebar heading</h2><div class="c-content"><h1 class="c-title">Original chemistry heading</h1><div class="other-s">发布日期：2026-09-29&nbsp;&nbsp;作者：source</div><div class="nr-info"><div id="vsb_content"><div class="v_news_content"><p>First source paragraph.</p><p><img src="/__local/image.jpg"></p><p>Final source paragraph.</p><script>ignored fallback text</script></div></div></div></div>"#;
        let out = normalize(&response(body), &college_html(&response(body)).unwrap()).unwrap();
        assert_eq!(out["title"], "Original chemistry heading");
        assert_eq!(out["published_at"], "2026-09-29");
        assert_eq!(out["body_paragraph_count"], 2);
        assert_eq!(out["result"], "partial_text");
        assert_eq!(out["completeness"]["image_content_present"], true);
    }

    #[test]
    fn chemistry_article_scope_rejects_foreign_and_query_urls() {
        for raw in [
            "https://sce.buaa.edu.cn/info/1013/42.htm?session=fixture",
            "https://other.buaa.edu.cn/info/1013/42.htm",
            "https://sce.buaa.edu.cn/info/1014/42.htm",
            "https://user:pass@sce.buaa.edu.cn/info/1013/42.htm",
        ] {
            assert_eq!(resolve_article(raw).unwrap_err().code, "invalid_input");
        }
    }

    #[test]
    fn chemistry_image_only_body_is_not_promoted_to_text() {
        let body = r#"<div class="c-content"><h1 class="c-title">Image-only</h1><div class="other-s">发布日期：2026-09-29</div><div class="nr-info"><div id="vsb_content"><div class="v_news_content"><p><img src="/__local/image.jpg"></p></div></div></div></div>"#;
        assert_eq!(
            normalize(&response(body), &college_html(&response(body)).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }
}
