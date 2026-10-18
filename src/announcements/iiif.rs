//! Official-directory-bound international interdisciplinary institute sources.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url, article_body, article_output, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, inert_element, invalid_article, invalid_list, is_http,
    parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, IIIF_NOTICES_URL, IIIF_ROOT_URL, iiif_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学国际前沿交叉科学研究院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("iiif.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && iiif_path_allowed(url.path())
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
        "国际前沿交叉科学研究院",
        IIIF_ROOT_URL,
        IIIF_ROOT_URL,
    )?;
    Ok((ArchiveClient::open_iiif(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => IIIF_ROOT_URL,
        "notices" => IIIF_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, IIIF_ROOT_URL, IIIF_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "iiif", attribution)
        })
}

fn parse_listing(document: &Html, base: &Url) -> Result<ListingDocument, Error> {
    let titles = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&titles)
        .next()
        .map(element_text)
        .unwrap_or_default();
    let views = Selector::parse("div.main > div.wape-right > ul.ss").map_err(|_| unavailable())?;
    let mut views = document.select(&views).filter(|node| !inert_element(*node));
    let view = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Iiif notice listing requires one direct wape-right/ss view",
                file!(),
                line!(),
            )
        })?;
    let mut entries = Vec::new();
    for row in view
        .children()
        .filter_map(ElementRef::wrap)
        .filter(|node| node.value().name() == "li")
    {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut links = row
            .children()
            .filter_map(ElementRef::wrap)
            .filter(|node| node.value().name() == "a");
        let link = links
            .next()
            .filter(|_| links.next().is_none())
            .ok_or_else(|| {
                failed_contract(
                    "Iiif notice row requires one direct a source heading",
                    file!(),
                    line!(),
                )
            })?;
        let title = element_text(link);
        if title.is_empty() || title.len() > MAX_TEXT {
            return Err(failed_contract(
                "Iiif notice row requires a nonempty bounded source heading",
                file!(),
                line!(),
            ));
        }
        let listed_href = link.value().attr("href");
        if listed_href
            .is_some_and(|href| href.len() > MAX_HREF || href.chars().any(char::is_control))
        {
            return Err(unavailable());
        }
        let mut dates = row
            .children()
            .filter_map(ElementRef::wrap)
            .filter(|node| node.value().name() == "span");
        let date = dates
            .next()
            .filter(|_| dates.next().is_none())
            .and_then(|node| parse_iso_date(&element_text(node)));
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
            "Iiif notice listing has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(IIIF_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        college_html(response)?;
        advertised_page_url(
            &response.body,
            &latest,
            page,
            "div.main > div.wape-right > div.pb_sys_common span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/xwgg/tzgg/"),
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
    bind_college_board(&client, IIIF_ROOT_URL, IIIF_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = parse_listing(&college_html(response)?, &target)?;
        let entries: Vec<&ListingEntry> = document.entries.iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"iiif","category":"tzgg","listing_label":"通知公告","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"one direct row/span YYYY-MM-DD; missing, invalid or ambiguous stays null"},
            "retrieval":retrieval(response)}))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1186/")
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
    bind_college_board(&client, IIIF_ROOT_URL, IIIF_NOTICES_URL, &mut attribution)?;
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
                "retained notice board does not declare the selected Iiif article",
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
                value["college"] = json!("iiif");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value["completeness"]["images"] = json!("not downloaded or OCR-extracted");
                value["completeness"]["linked_materials"] = json!("not followed");
                value
            }))
        })?
}

fn normalize(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    let forms = Selector::parse("div.main > div.kuaiXun > div.kuaiXun-con > form")
        .map_err(|_| unavailable())?;
    let mut forms = document.select(&forms).filter(|node| !inert_element(*node));
    let form = forms
        .next()
        .filter(|_| forms.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Iiif article requires one direct kuaiXun-con source form",
                file!(),
                line!(),
            )
        })?;
    let mut headers = form.children().filter_map(ElementRef::wrap).filter(|node| {
        node.value().name() == "div"
            && node
                .value()
                .has_class("title", scraper::CaseSensitivity::CaseSensitive)
    });
    let header = headers
        .next()
        .filter(|_| headers.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Iiif article requires one direct title header",
                file!(),
                line!(),
            )
        })?;
    let mut headings = header
        .children()
        .filter_map(ElementRef::wrap)
        .filter(|node| node.value().name() == "h3");
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|text| !text.is_empty() && text.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "Iiif article requires one nonempty direct title/h3 heading",
                file!(),
                line!(),
            )
        })?;
    let mut dates = header
        .children()
        .filter_map(ElementRef::wrap)
        .filter(|node| node.value().name() == "div");
    let published_at = dates
        .next()
        .filter(|_| dates.next().is_none())
        .and_then(|node| {
            let text = element_text(node);
            text.strip_prefix("[发表时间]：")
                .and_then(|date| parse_iso_date(date.trim()))
        });
    let bodies = Selector::parse("div#vsb_content.single-content > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = form.select(&bodies).filter(|body| {
        body.parent()
            .and_then(|node| node.parent())
            .is_some_and(|parent| parent.id() == form.id())
    });
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Iiif article requires one direct vsb_content/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, false)?;
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let has_images = body.select(&images).any(|image| !inert_element(image));
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
    output["completeness"]["image_content_present"] = json!(has_images);
    if has_images {
        output["result"] = json!("partial_text");
        output["completeness"]["missing_image_text"] = json!("not_reconstructed");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CacheStatus, Response};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn source(header: &str, body: &str) -> Response {
        let html = format!(
            "<h3>Sidebar headline</h3><div class=\"main cl\"><div class=\"kuaiXun\"><div class=\"kuaiXun-con\"><form><div class=\"title\">{header}</div><div class=\"single-content\" id=\"vsb_content\"><div class=\"v_news_content\">{body}</div></div></form></div></div></div><div class=\"v_news_content\"><p>Unrelated text</p></div>"
        );
        Response {
            url: "https://iiif.buaa.edu.cn/info/1186/42.htm".into(),
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
    fn iiif_listing_preserves_order_and_unknown_date_filter_boundaries() {
        let document = Html::parse_document(
            r#"<div class="main"><div class="wape-right"><ul class="ss">
            <li><a href="../info/1186/42.htm" title="Do not replace visible heading">First visible<script>not a heading</script></a><span>2026-09-09</span></li>
            <li><a href="../info/1186/43.htm">Earlier source</a><span>2024-09-12</span></li>
            <li><a href="../info/1186/44.htm">Second selected</a><span>2026-09-08</span></li>
            <li><a href="../info/1186/45.htm">Ambiguous date</a><span>2026-09-09</span><span>2026-09-08</span></li>
            <li><a href="../info/1186/46.htm">Invalid date</a><span>2026-02-29</span></li>
            <li><a href="../info/1186/47.htm">Missing date</a><p>2026-09-09 is not metadata</p></li>
        </ul></div></div>"#,
        );
        let listing = parse_listing(&document, &Url::parse(IIIF_NOTICES_URL).unwrap()).unwrap();
        assert_eq!(
            listing
                .entries
                .iter()
                .map(|entry| entry.title.as_str())
                .collect::<Vec<_>>(),
            [
                "First visible",
                "Earlier source",
                "Second selected",
                "Ambiguous date",
                "Invalid date",
                "Missing date"
            ]
        );
        assert_eq!(
            listing
                .entries
                .iter()
                .map(|entry| entry.date.as_deref())
                .collect::<Vec<_>>(),
            [
                Some("2026-09-09"),
                Some("2024-09-12"),
                Some("2026-09-08"),
                None,
                None,
                None
            ]
        );
        assert_eq!(
            listing
                .entries
                .iter()
                .filter(|entry| entry_in_scope(
                    entry,
                    &Some("2026-09-08".into()),
                    &Some("2026-09-09".into()),
                    &None
                ))
                .map(|entry| entry.title.as_str())
                .collect::<Vec<_>>(),
            ["First visible", "Second selected"]
        );
    }

    #[test]
    fn iiif_listing_rejects_ambiguous_views_and_headings() {
        let base = Url::parse(IIIF_NOTICES_URL).unwrap();
        let view = r#"<div class="main"><div class="wape-right"><ul class="ss"><li><a href="../info/1186/42.htm">Source heading</a><span>2026-09-09</span></li></ul></div></div>"#;
        assert_eq!(
            parse_listing(&Html::parse_document(&format!("{view}{view}")), &base)
                .unwrap_err()
                .code,
            "unavailable"
        );
        let ambiguous_heading = r#"<div class="main"><div class="wape-right"><ul class="ss"><li><a href="../info/1186/42.htm">First heading</a><a href="../info/1186/43.htm">Second heading</a></li></ul></div></div>"#;
        assert_eq!(
            parse_listing(&Html::parse_document(ambiguous_heading), &base)
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn iiif_article_header_wins_and_untranscribed_images_remain_partial() {
        let response = source(
            "<h3>Original heading</h3><div>[发表时间]：2026-09-09<script>2020-01-01</script></div>",
            "<p>Original paragraph.</p><p><script>not prose</script></p><img src=\"poster.png\" alt=\"not transcribed\"><table><tr><td><p>Source cell.</p></td></tr></table>",
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["title"], "Original heading");
        assert_eq!(output["published_at"], "2026-09-09");
        assert_eq!(
            output["body_paragraphs"],
            json!(["Original paragraph.", "Source cell."])
        );
        assert_eq!(output["result"], "partial_text");
        let image_only = source("<h3>Original image notice</h3>", "<img src=\"poster.png\">");
        assert_eq!(
            normalize(&image_only, &college_html(&image_only).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
        let empty = source("<h3>Empty source</h3>", "<p><script>not prose</script></p>");
        assert_eq!(
            normalize(&empty, &college_html(&empty).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn iiif_article_unknown_publication_and_body_ambiguity_fail_closed() {
        for metadata in [
            "",
            "<div>[发表时间]：2026-02-29</div>",
            "<div>[发表时间]：2026-09-09</div><div>[发表时间]：2026-09-08</div>",
        ] {
            let response = source(
                &format!("<h3>Original heading</h3>{metadata}"),
                "<p>Body date 2026-09-09 is not publication.</p>",
            );
            let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
            assert_eq!(output["published_at"], Value::Null);
            assert_eq!(
                output["body_paragraphs"],
                json!(["Body date 2026-09-09 is not publication."])
            );
        }
        let mut response = source("<h3>Original heading</h3>", "<p>First body.</p>");
        response.body = String::from_utf8(response.body).unwrap().replacen("</form>", "<div class=\"single-content\" id=\"vsb_content\"><div class=\"v_news_content\"><p>Second body.</p></div></div></form>", 1).into_bytes();
        assert_eq!(
            normalize(&response, &college_html(&response).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn iiif_advertised_ordinal_is_scoped_not_filename_inferred() {
        let base = Url::parse(IIIF_NOTICES_URL).unwrap();
        let html = br#"<div class="pb_sys_common"><span class="p_no"><a href="tzgg/99.htm">2</a></span></div><div class="main"><div class="wape-right"><div class="pb_sys_common"><span class="p_no"><a href="tzgg/8.htm">2</a></span></div></div></div>"#;
        let allowed = |url: &Url| plain_url(url) && url.path().starts_with("/xwgg/tzgg/");
        assert_eq!(
            advertised_page_url(
                html,
                &base,
                2,
                "div.main > div.wape-right > div.pb_sys_common span.p_no a[href]",
                allowed
            )
            .unwrap()
            .as_str(),
            "https://iiif.buaa.edu.cn/xwgg/tzgg/8.htm"
        );
        assert_eq!(
            advertised_page_url(
                html,
                &base,
                3,
                "div.main > div.wape-right > div.pb_sys_common span.p_no a[href]",
                allowed
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
    }
}
