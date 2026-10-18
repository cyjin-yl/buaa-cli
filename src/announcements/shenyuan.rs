//! Official-directory-bound Shenyuan college source observations.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url, article_body, article_output, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, invalid_article, invalid_list, is_http, parse_iso_date,
    retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, Response, SHENYUAN_NOTICES_URL, SHENYUAN_ROOT_URL,
    shenyuan_path_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学沈元学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("hc.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && shenyuan_path_allowed(url.path())
}

fn source_date(day: &str, yearmonth: &str) -> Option<String> {
    let day: &[u8; 2] = day.trim().as_bytes().try_into().ok()?;
    let yearmonth: &[u8; 7] = yearmonth.trim().as_bytes().try_into().ok()?;
    let mut date = [0; 10];
    date[..7].copy_from_slice(yearmonth);
    date[7] = b'-';
    date[8..].copy_from_slice(day);
    parse_iso_date(std::str::from_utf8(&date).ok()?)
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
        "沈元学院",
        SHENYUAN_ROOT_URL,
        SHENYUAN_ROOT_URL,
    )?;
    Ok((ArchiveClient::open_shenyuan(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => SHENYUAN_ROOT_URL,
        "notices" => SHENYUAN_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(
            &client,
            SHENYUAN_ROOT_URL,
            SHENYUAN_NOTICES_URL,
            &mut attribution,
        )?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "shenyuan", attribution)
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
    let containers = Selector::parse("section.n_zhuanti div#tab_a1 > ul.list_box_03s")
        .map_err(|_| unavailable())?;
    let mut primary = document.select(&containers);
    let primary = primary
        .next()
        .filter(|_| primary.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Shenyuan listing requires one canonical tab_a1/list_box_03s view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let headings = Selector::parse("a.a > div.con > h5").map_err(|_| unavailable())?;
    let anchors = Selector::parse("a.a[href]").map_err(|_| unavailable())?;
    let days = Selector::parse("a.a > div.time > h3").map_err(|_| unavailable())?;
    let months = Selector::parse("a.a > div.time > h6").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in primary.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let title = row
            .select(&headings)
            .next()
            .map(element_text)
            .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
            .ok_or_else(|| {
                failed_contract(
                    "Shenyuan notice row requires its con/h5 source heading",
                    file!(),
                    line!(),
                )
            })?;
        let listed_href = row
            .select(&anchors)
            .next()
            .and_then(|node| node.value().attr("href"));
        if listed_href
            .is_some_and(|href| href.len() > MAX_HREF || href.chars().any(char::is_control))
        {
            return Err(unavailable());
        }
        let date = row
            .select(&days)
            .next()
            .zip(row.select(&months).next())
            .and_then(|(day, month)| source_date(&element_text(day), &element_text(month)));
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
            "Shenyuan canonical listing has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(SHENYUAN_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        college_html(response)?;
        advertised_page_url(
            &response.body,
            &latest,
            page,
            "div.pb_sys_common span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with("/index/tzgg/"),
        )
    })
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    if query
        .category
        .as_deref()
        .is_some_and(|category| category != "tzgg")
    {
        return Err(invalid_list());
    }
    let page = query.page.unwrap_or(1);
    if page == 0 {
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
    bind_college_board(
        &client,
        SHENYUAN_ROOT_URL,
        SHENYUAN_NOTICES_URL,
        &mut attribution,
    )?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let document = parse_listing(&college_html(response)?, &target)?;
        let entries: Vec<&ListingEntry> = document.entries.iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
            "publisher":PUBLISHER,"college":"shenyuan","category":"tzgg","listing_label":"通知公告","page":page,
            "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"source split DD and YYYY-MM; missing or invalid stays null"},"retrieval":retrieval(response)}))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1083/")
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
    bind_college_board(
        &client,
        SHENYUAN_ROOT_URL,
        SHENYUAN_NOTICES_URL,
        &mut attribution,
    )?;
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
                "retained notice page does not declare the selected Shenyuan article",
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
                value["college"] = json!("shenyuan");
                value["directory_attribution"] = attribution;
                value["source_listing"] = listing;
                value
            }))
        })?
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let forms = Selector::parse("section.n_news_detail div.ar_article_box > form")
        .map_err(|_| unavailable())?;
    let mut forms = document.select(&forms);
    let main = forms.next().ok_or_else(|| {
        failed_contract(
            "Shenyuan article requires its n_news_detail/ar_article_box form",
            file!(),
            line!(),
        )
    })?;
    if forms.next().is_some() {
        return Err(unavailable());
    }
    let mut headers = main.children().filter_map(ElementRef::wrap).filter(|node| {
        node.value().name() == "div"
            && node
                .value()
                .attr("class")
                .is_some_and(|classes| classes.split_whitespace().any(|class| class == "nav01"))
    });
    let header = headers.next().ok_or_else(|| {
        failed_contract(
            "Shenyuan article requires its direct nav01 header",
            file!(),
            line!(),
        )
    })?;
    if headers.next().is_some() {
        return Err(unavailable());
    }
    let mut titles = header
        .children()
        .filter_map(ElementRef::wrap)
        .filter(|node| node.value().name() == "h3")
        .map(element_text)
        .filter(|title| !title.is_empty());
    let title = titles
        .next()
        .filter(|title| title.len() <= MAX_HREF)
        .ok_or_else(|| {
            failed_contract(
                "Shenyuan article requires one nonempty direct nav01/h3 title",
                file!(),
                line!(),
            )
        })?;
    if titles.next().is_some() {
        return Err(unavailable());
    }
    let mut dates = header
        .children()
        .filter_map(ElementRef::wrap)
        .filter(|node| node.value().name() == "h6");
    let published_at = dates.next().and_then(|date| {
        date.children()
            .filter_map(ElementRef::wrap)
            .find(|node| node.value().name() == "span")
            .and_then(|node| parse_iso_date(&element_text(node)))
    });
    if dates.next().is_some() {
        return Err(unavailable());
    }
    let bodies = Selector::parse("div#vsb_content_2.ar_article > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies).filter(|node| {
        node.parent()
            .and_then(|parent| parent.parent())
            .is_some_and(|parent| parent.id() == main.id())
    });
    let body = bodies.next().ok_or_else(|| {
        failed_contract(
            "Shenyuan article requires its direct vsb_content_2/v_news_content body",
            file!(),
            line!(),
        )
    })?;
    if bodies.next().is_some() {
        return Err(unavailable());
    }
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, false)?;
    Ok(article_output(
        response,
        ArticleDocument {
            title,
            category: Some("1083".into()),
            published_at,
            paragraphs,
            attachment_hints,
            attachments_found,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://hc.buaa.edu.cn/info/1083/42.htm".into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            body: body.as_bytes().to_vec(),
            sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn listing_preserves_canonical_rows_split_dates_and_unfetched_dynamic_links() {
        let source = r#"<title>Fixture notices</title><section class="n_zhuanti"><div id="tab_a1"><ul class="list_box_03 list_box_03s">
            <li><a class="a" href="../info/1083/42.htm"><div class="time"><h3>29</h3><h6>2024-02</h6></div><div class="con"><h5>Fixture leap-day policy</h5></div></a></li>
            <li><a class="a" href="../info/1083/43.htm"><div class="time"><h3>29</h3><h6>2025-02</h6></div><div class="con"><h5>Invalid source date</h5></div></a></li>
            <li><a class="a" href="../content.jsp?wbnewsid=44"><div class="con"><h5>Unknown source date</h5><p>2024-02-29 is not row metadata.</p></div></a></li>
        </ul></div><div id="tab_a2"><ul class="list_box_titu"><li><a href="../info/1083/42.htm"><h5>Responsive duplicate</h5></a></li></ul></div></section>"#;
        let document = parse_listing(
            &Html::parse_document(source),
            &Url::parse(SHENYUAN_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(
            document
                .entries
                .iter()
                .map(|entry| entry.title.as_str())
                .collect::<Vec<_>>(),
            vec![
                "Fixture leap-day policy",
                "Invalid source date",
                "Unknown source date"
            ]
        );
        assert_eq!(
            document
                .entries
                .iter()
                .map(|entry| entry.date.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("2024-02-29"), None, None]
        );
        assert_eq!(
            document.entries[2].resolved_http_url.as_deref(),
            Some("https://hc.buaa.edu.cn/content.jsp?wbnewsid=44")
        );
        let since = Some("2024-02-29".into());
        assert_eq!(
            document
                .entries
                .iter()
                .filter(|entry| entry_in_scope(entry, &since, &since, &None))
                .map(|entry| entry.title.as_str())
                .collect::<Vec<_>>(),
            vec!["Fixture leap-day policy"]
        );
    }

    #[test]
    fn article_uses_direct_header_and_body_without_promoting_other_dates() {
        let source = response(
            r#"<h1>Sidebar heading</h1><section class="n_news_detail"><div class="ar_article_box"><form><div class="nav01"><h3>Fixture original heading</h3><h3></h3><h6><span>2026-09-29</span><span>2020-01-01 is not the publication slot.</span></h6></div><div class="ar_article" id="vsb_content_2"><div class="v_news_content"><p>Source paragraph.</p><table><tr><td><p>Source table cell.</p></td></tr></table><p><script>not source prose</script></p></div></div></form></div></section><div class="v_news_content"><p>Unrelated prose.</p></div>"#,
        );
        let output = normalize(&source, &college_html(&source).unwrap()).unwrap();
        assert_eq!(output["title"], "Fixture original heading");
        assert_eq!(output["published_at"], "2026-09-29");
        assert_eq!(
            output["body_paragraphs"],
            json!(["Source paragraph.", "Source table cell."])
        );
        let missing = response(
            r#"<section class="n_news_detail"><div class="ar_article_box"><form><div class="nav01"><h3>Fixture original heading</h3></div><div class="ar_article" id="vsb_content_2"><div class="v_news_content"><div class="nav01"><h6><span>2026-09-29</span></h6></div><p>Body-only date 2026-09-29.</p></div></div></form></div></section>"#,
        );
        assert_eq!(
            normalize(&missing, &college_html(&missing).unwrap()).unwrap()["published_at"],
            Value::Null
        );
        let invalid = response(
            r#"<section class="n_news_detail"><div class="ar_article_box"><form><div class="nav01"><h3>Fixture original heading</h3><h6><span>2026-02-30</span><span>2026-09-29</span></h6></div><div class="ar_article" id="vsb_content_2"><div class="v_news_content"><p>Source paragraph.</p></div></div></form></div></section>"#,
        );
        assert_eq!(
            normalize(&invalid, &college_html(&invalid).unwrap()).unwrap()["published_at"],
            Value::Null
        );
    }

    #[test]
    fn ambiguous_source_headings_and_bodies_refuse_derived_text() {
        for source in [
            r#"<section class="n_news_detail"><div class="ar_article_box"><form><div class="nav01"><h3>First heading</h3><h3>Second heading</h3></div><div class="ar_article" id="vsb_content_2"><div class="v_news_content"><p>Source paragraph.</p></div></div></form></div></section>"#,
            r#"<section class="n_news_detail"><div class="ar_article_box"><form><div class="nav01"><h3>Fixture heading</h3></div><div class="ar_article" id="vsb_content_2"><div class="v_news_content"><p>First body.</p></div><div class="v_news_content"><p>Second body.</p></div></div></form></div></section>"#,
        ] {
            let source = response(source);
            assert_eq!(
                normalize(&source, &college_html(&source).unwrap())
                    .unwrap_err()
                    .code,
                "unavailable"
            );
        }
    }
}
