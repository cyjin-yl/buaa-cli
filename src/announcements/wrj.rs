//! Directory-bound 无人系统研究院 announcements.
//!
//! The institute uses the Visual SiteBuilder list/content layout rather than
//! the shared university news-center or the `nymain/notice-list` college
//! layout.  Keep its root-declared `xwgg/tzgg.htm` board and category-1008
//! article URLs source-bound; no sibling site or attachment is inferred.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url_document, article_category_from_url, article_output, article_paragraphs,
    bind_college_board, college_directory_attribution, college_html, declared_jsp_attachment_hints,
    describe_college_surface, element_text, entry_in_scope, failed_contract, html_fallback,
    inert_element, invalid_article, invalid_list, is_http, is_safe_public_fallback_document,
    parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, Response, WRJ_NOTICES_URL, WRJ_ROOT_URL, wrj_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://wrj.buaa.edu.cn";
const RESOLVED_ROOT_URL: &str = "http://wrj.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学无人系统研究院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("wrj.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && wrj_path_allowed(url.path())
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    // Directory authority is cache-first even for a selected-page refresh.
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let mut attribution = college_directory_attribution(
        &directory,
        "无人系统研究院",
        LISTED_ROOT_URL,
        RESOLVED_ROOT_URL,
    )?;
    attribution["selected_https_root"] = WRJ_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed/resolved HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_wrj(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => WRJ_ROOT_URL,
        "notices" => WRJ_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, WRJ_ROOT_URL, WRJ_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "wrj", attribution)
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

    let views =
        Selector::parse("div.main > div.w90 > div.main-right > div.content > div.txt-list > ul")
            .map_err(|_| unavailable())?;
    let mut views = document.select(&views).filter(|node| !inert_element(*node));
    let primary = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Wrj notice listing requires one direct main-right/txt-list view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a.line1[href]").map_err(|_| unavailable())?;
    let dates = Selector::parse(":scope > span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in primary.select(&rows) {
        if entries.len() >= MAX_ENTRIES {
            return Err(failed_contract(
                "Wrj notice listing exceeds the reviewed entry budget",
                file!(),
                line!(),
            ));
        }
        let mut anchors = row.select(&anchors);
        let anchor = anchors
            .next()
            .filter(|_| anchors.next().is_none())
            .ok_or_else(|| {
                failed_contract(
                    "Wrj notice row requires one direct line1 anchor",
                    file!(),
                    line!(),
                )
            })?;
        let title = element_text(anchor);
        if title.is_empty() || title.len() > MAX_TEXT {
            return Err(failed_contract(
                "Wrj notice row requires a bounded nonempty title",
                file!(),
                line!(),
            ));
        }
        let listed_href = anchor.value().attr("href").ok_or_else(|| {
            failed_contract("Wrj notice row requires a source href", file!(), line!())
        })?;
        if listed_href.is_empty()
            || listed_href.len() > MAX_HREF
            || listed_href.chars().any(char::is_control)
        {
            return Err(unavailable());
        }
        let listed_href = listed_href.to_owned();
        let mut dates = row.select(&dates);
        let date = dates
            .next()
            .filter(|_| dates.next().is_none())
            .and_then(|node| parse_iso_date(&element_text(node)));
        let (resolved_http_url, link_kind) = match base.join(&listed_href) {
            Ok(url) if is_http(&url) => (Some(url.to_string()), "http"),
            Ok(_) => (None, "non_http"),
            Err(_) => (None, "invalid"),
        };
        entries.push(ListingEntry {
            source_order: entries.len() + 1,
            title,
            date,
            category_label: None,
            summary: None,
            listed_href: Some(listed_href),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "Wrj notice listing must contain at least one direct row",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(WRJ_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    let result: Result<Url, Error> = client.get(&latest, false, |response| {
        let document = college_html(response)?;
        let selected = advertised_page_url_document(
            &document,
            &latest,
            page,
            "div.main > div.w90 > div.main-right > div.content > div.pb_sys_common span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/xwgg/tzgg/"),
        );
        if selected.is_err() && !is_safe_public_fallback_document(response, &document) {
            return Err(unavailable());
        }
        Ok(selected)
    })?;
    result
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
    bind_college_board(&client, WRJ_ROOT_URL, WRJ_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &target) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback_document(response, &html) => {
                let mut value = html_fallback(
                    response,
                    "announcements_list",
                    "wrj",
                    "wrj_listing_selector_contract",
                );
                value["category"] = json!("tzgg");
                value["page"] = json!(page);
                return Ok(value);
            }
            Err(error) => return Err(error),
        };
        let entries: Vec<_> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match))
            .collect();
        Ok(json!({
            "schema_version": 1,
            "type": "announcements_list",
            "result": "listing_snapshot",
            "publisher": PUBLISHER,
            "college": "wrj",
            "category": "tzgg",
            "listing_label": "通知公告",
            "page": page,
            "document_title": document.title,
            "filters": {"since": since, "until": until, "match": query.r#match},
            "entries": entries,
            "entry_count": entries.len(),
            "directory_attribution": attribution,
            "completeness": {
                "scope": "single_college_selected_page",
                "pagination": "source_advertised_ordinal_only; no automatic traversal",
                "other_colleges": "not_covered",
                "dates": "source YYYY-MM-DD; missing or invalid stays null",
                "summaries": "this board publishes title/date rows without listing excerpts; original article text is separate"
            },
            "retrieval": retrieval(response)
        }))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || source_page == 0
        || !target.path().starts_with("/info/1008/")
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
    bind_college_board(&client, WRJ_ROOT_URL, WRJ_NOTICES_URL, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing_result: Result<Value, Error> = client.get(&source, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &source) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback_document(response, &html) => {
                return Ok(Ok(html_fallback(
                    response,
                    "announcements_list",
                    "wrj",
                    "wrj_listing_selector_contract",
                )));
            }
            Err(error) => return Err(error),
        };
        super::refuse_unsafe_listing(response, &html)?;
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Ok(Err(Error::new(
                "unsupported",
                "retained Wrj notice page does not declare the selected article",
            )));
        }
        Ok(Ok(retrieval(response)))
    })?;
    let listing = listing_result?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained Wrj notice page could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client
        .with_cache_mode(mode)
        .get(target, false, |response| {
            let document = college_html(response)?;
            Ok(normalize(response, &document).map(|mut value| {
                value["publisher"] = json!(PUBLISHER);
                value["college"] = json!("wrj");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
}

fn publication_date(raw: &str) -> Option<String> {
    let raw = raw.strip_prefix("发布时间：")?.trim();
    parse_iso_date(raw)
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let forms =
        Selector::parse("form[name=\"_newscontent_fromname\"]").map_err(|_| unavailable())?;
    let mut forms = document.select(&forms).filter(|node| !inert_element(*node));
    let main = forms
        .next()
        .filter(|_| forms.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Wrj article requires one active _newscontent_fromname form",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > h3.title").map_err(|_| unavailable())?;
    let mut headings = main.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "Wrj article requires one direct title heading",
                file!(),
                line!(),
            )
        })?;

    let date_selector =
        Selector::parse(":scope > div.art-itro > span").map_err(|_| unavailable())?;
    let publication_spans: Vec<_> = main
        .select(&date_selector)
        .filter(|node| element_text(*node).starts_with("发布时间："))
        .collect();
    let published_at = (publication_spans.len() == 1)
        .then(|| publication_date(&element_text(publication_spans[0])))
        .flatten();

    let bodies =
        Selector::parse(":scope > div.article > div[id^=\"vsb_content_\"] > div.v_news_content")
            .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies).filter(|node| !inert_element(*node));
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Wrj article requires one scoped article/vsb_content/v_news_content body",
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
        "unique _newscontent_fromname/article/vsb_content/v_news_content paragraphs; executable and fallback text excluded"
    );
    output["completeness"]["attachment_source"] = json!(
        "active source-declared JSP file links within the article form; hints only, never fetched"
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

    fn listing_html() -> &'static str {
        r#"<title>通知公告-无人系统研究院</title>
<div class="main"><div class="w90"><div class="main-right"><div class="content"><div class="txt-list"><ul>
<li class="flex" id="line_u12_0"><a href="../info/1008/3067.htm" title="博士后岗位招聘" class="line1">北航无人系统研究院卓越百人博士后岗位招聘通知</a><span>2026-07-29</span></li>
</ul></div><div class="pb_sys_common"><span class="p_no"><a href="tzgg/2.htm">2</a></span></div></div></div></div></div>"#
    }

    fn article_response(body: &str, header: &str) -> Response {
        let html = format!(
            r#"<form name="_newscontent_fromname"><h3 class="title">Original article heading</h3><div class="art-itro"><span>{header}</span><span>浏览量：<script>42</script></span></div><div class="article"><div id="vsb_content_4"><div class="v_news_content">{body}</div></div></div><p><a href="/system/_content/download.jsp?urltype=news.DownloadAttachUrl&amp;owner=1&amp;wbfileid=abc">附件.docx</a></p></form>"#
        );
        Response {
            url: "https://wrj.buaa.edu.cn/info/1008/3067.htm".into(),
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
    fn wrj_listing_preserves_source_title_date_and_declared_link() {
        let base = Url::parse(WRJ_NOTICES_URL).unwrap();
        let html = Html::parse_document(listing_html());
        let document = parse_listing(&html, &base).unwrap();
        assert_eq!(document.entries.len(), 1);
        assert_eq!(
            document.entries[0].title,
            "北航无人系统研究院卓越百人博士后岗位招聘通知"
        );
        assert_eq!(document.entries[0].date.as_deref(), Some("2026-07-29"));
        assert_eq!(
            document.entries[0].resolved_http_url.as_deref(),
            Some("https://wrj.buaa.edu.cn/info/1008/3067.htm")
        );
        assert_eq!(document.entries[0].summary, None);
    }

    #[test]
    fn wrj_listing_requires_one_direct_row_anchor() {
        let html = listing_html().replace(
            "<span>2026-07-29</span>",
            "<a href=\"../info/1008/3068.htm\" class=\"line1\">Second</a><span>2026-07-29</span>",
        );
        let base = Url::parse(WRJ_NOTICES_URL).unwrap();
        let document = Html::parse_document(&html);
        assert_eq!(
            parse_listing(&document, &base).unwrap_err().code,
            "unavailable"
        );
    }

    #[test]
    fn wrj_article_uses_publication_span_and_jsp_hints() {
        let response = article_response(
            "<p>First source paragraph.</p><p>Second source paragraph.</p>",
            "发布时间：2026-07-29",
        );
        let document = college_html(&response).unwrap();
        let output = normalize(&response, &document).unwrap();
        assert_eq!(output["title"], "Original article heading");
        assert_eq!(output["published_at"], "2026-07-29");
        assert_eq!(
            output["body_paragraphs"],
            json!(["First source paragraph.", "Second source paragraph."])
        );
        assert_eq!(output["result"], "partial_text");
        assert_eq!(output["attachments"]["hints"][0]["text"], "附件.docx");
    }

    #[test]
    fn wrj_ambiguous_publication_spans_remain_unknown() {
        let response = article_response("<p>Source paragraph.</p>", "发布时间：2026-07-29");
        let html = String::from_utf8(response.body.clone()).unwrap().replace(
            "<span>浏览量：<script>42</script></span>",
            "<span>发布时间：2026-07-28</span><span>浏览量：<script>42</script></span>",
        );
        let response = Response {
            sha256: format!("{:x}", Sha256::digest(html.as_bytes())),
            body: html.into_bytes(),
            ..response
        };
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["published_at"], Value::Null);
    }
}
