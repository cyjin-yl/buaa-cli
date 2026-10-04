//! Official-directory-bound aviation college sources; no inferred routes.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url, article_body, article_output, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, invalid_article, invalid_list, is_http, parse_iso_date,
    retrieval, unavailable,
};
use crate::net::{
    AVIATION_NOTICES_URL, AVIATION_PUBLIC_NOTICES_URL, AVIATION_ROOT_URL, ArchiveClient, CacheMode,
    Error, Response, aviation_path_allowed,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学飞行学院";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("aviation.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && aviation_path_allowed(url.path())
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
        "飞行学院",
        AVIATION_ROOT_URL,
        AVIATION_ROOT_URL,
    )?;
    Ok((ArchiveClient::open_aviation(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => AVIATION_ROOT_URL,
        "notices" => AVIATION_NOTICES_URL,
        "public-notices" => AVIATION_PUBLIC_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    if page != "root" {
        bind_college_board(&client, AVIATION_ROOT_URL, raw, &mut attribution)?;
    }
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            describe_college_surface(response, "aviation", attribution)
        })
}

fn parse_listing(document: &Html, base: &Url, label: &str) -> Result<ListingDocument, Error> {
    let titles = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&titles)
        .next()
        .map(element_text)
        .unwrap_or_default();
    let rows = Selector::parse("div.body.mh div.moudle div.right div.items > div.item")
        .map_err(|_| unavailable())?;
    let headings = Selector::parse("div.r > a > div.title").map_err(|_| unavailable())?;
    let anchors = Selector::parse("div.r > a[href]").map_err(|_| unavailable())?;
    let years = Selector::parse("div.l > div.year").map_err(|_| unavailable())?;
    let date_parts = Selector::parse("div.l > div.mouth > span").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in document.select(&rows) {
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
                    "aviation desktop notice row requires its r/a/title heading",
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
        let mut parts = row.select(&date_parts);
        let date = row
            .select(&years)
            .next()
            .zip(parts.next())
            .zip(parts.next())
            .filter(|_| parts.next().is_none())
            .and_then(|((year, day), month)| {
                let month = element_text(month);
                parse_iso_date(&format!(
                    "{}-{}-{}",
                    element_text(year),
                    month.strip_prefix('/')?,
                    element_text(day)
                ))
            });
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
            category_label: Some(label.into()),
            summary: None,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "aviation listing requires reviewed desktop items; mobile copies are not extra announcements",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, raw: &str, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(raw).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    let prefix = if raw == AVIATION_NOTICES_URL {
        "/xsgz1/tzgg/"
    } else {
        "/gkgs/"
    };
    client.get(&latest, false, |response| {
        college_html(response)?;
        advertised_page_url(
            &response.body,
            &latest,
            page,
            "div.pb_sys_common span.p_no a[href]",
            |url| plain_url(url) && url.path().starts_with(prefix),
        )
    })
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    let category = query.category.as_deref().unwrap_or("tzgg");
    let (raw, label) = match category {
        "tzgg" => (AVIATION_NOTICES_URL, "通知公告（学生工作）"),
        "gkgs" => (AVIATION_PUBLIC_NOTICES_URL, "公开公示"),
        _ => return Err(invalid_list()),
    };
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
    bind_college_board(&client, AVIATION_ROOT_URL, raw, &mut attribution)?;
    let target = listing_url(&client, raw, page)?;
    client.with_cache_mode(mode).get(&target,false,|response| {
        let document = parse_listing(&college_html(response)?,&target,label)?;
        let entries:Vec<&ListingEntry> = document.entries.iter().filter(|entry| entry_in_scope(entry,&since,&until,&query.r#match)).collect();
        Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot","publisher":PUBLISHER,"college":"aviation","category":category,"listing_label":label,"page":page,"document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},"entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,"completeness":{"scope":"single_college_selected_board_page","responsive_copies":"desktop_rows_only; mobile copies omitted","pagination":"source_advertised_ordinal_only; no inferred pages","external_links":"retained as source hints; never fetched","other_colleges":"not_covered","dates":"source_year_then_day_and_slash_month; missing stays null"},"retrieval":retrieval(response)}))
    })
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1061/")
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
        AVIATION_ROOT_URL,
        AVIATION_PUBLIC_NOTICES_URL,
        &mut attribution,
    )?;
    let source = listing_url(&client, AVIATION_PUBLIC_NOTICES_URL, source_page)?;
    let listing = client.get(&source, false, |response| {
        let document = parse_listing(&college_html(response)?, &source, "公开公示")?;
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Err(Error::new(
                "unsupported",
                "retained public notice page does not declare the selected aviation article",
            ));
        }
        Ok(retrieval(response))
    })?;
    client
        .with_cache_mode(mode)
        .get(target, false, |response| {
            let document = college_html(response)?;
            Ok(normalize(response, &document).map(|mut output| {
                output["publisher"] = json!(PUBLISHER);
                output["college"] = json!("aviation");
                output["directory_attribution"] = attribution;
                output["source_listing"] = listing;
                output
            }))
        })?
}

fn normalize(response: &Response, document: &Html) -> Result<Value, Error> {
    let forms = Selector::parse("div.body.mh div.moudle div.right div.items form")
        .map_err(|_| unavailable())?;
    let mut forms = document.select(&forms);
    let form = forms.next().ok_or_else(|| {
        failed_contract(
            "aviation article requires its desktop source form",
            file!(),
            line!(),
        )
    })?;
    if forms.next().is_some() {
        return Err(unavailable());
    }
    let title = form
        .children()
        .filter_map(scraper::ElementRef::wrap)
        .find(|node| {
            node.value().name() == "div"
                && node.value().attr("class").is_some_and(|value| {
                    value
                        .split(|character| {
                            matches!(character, ' ' | '\t' | '\n' | '\r' | '\u{000c}')
                        })
                        .any(|class| class == "title")
                })
        })
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_HREF)
        .ok_or_else(|| {
            failed_contract(
                "aviation article requires its direct desktop form/title heading",
                file!(),
                line!(),
            )
        })?;
    let dates = Selector::parse("div.date > span").map_err(|_| unavailable())?;
    let published_at = form
        .select(&dates)
        .filter(|node| {
            node.parent()
                .and_then(|parent| parent.parent())
                .is_some_and(|parent| parent.id() == form.id())
        })
        .filter_map(|node| {
            let text = element_text(node);
            parse_iso_date(text.strip_prefix("发布时间：")?.trim())
        })
        .next();
    let (paragraphs, attachment_hints, attachments_found) = article_body(form, false)?;
    let mut output = article_output(
        response,
        ArticleDocument {
            title,
            category: Some("1061".into()),
            published_at,
            paragraphs,
            attachment_hints,
            attachments_found,
        },
    );
    output["completeness"]["body_source"] = json!("desktop_source_form div.v_news_content p");
    output["completeness"]["responsive_copies"] =
        json!("desktop_prose_only; mobile copies omitted");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://aviation.buaa.edu.cn/info/1061/42.htm".into(),
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
    fn listing_uses_source_day_then_month_without_mobile_duplicates() {
        let source = response(
            r#"<title>Fixture notices</title><div class="body mh"><div class="moudle"><div class="right"><div class="items"><div class="item"><div class="l"><div class="year">2026</div><div class="mouth"><span>03</span><span>/04</span></div></div><div class="r"><a href="info/1061/42.htm"><div class="title">Fixture policy</div><div class="des">Not the headline</div></a></div></div><div class="item"><div class="l"><div class="year">2026</div><div class="mouth"><span>29</span><span>/02</span></div></div><div class="r"><a href="info/1061/43.htm"><div class="title">Unknown-date fixture</div></a></div></div></div></div></div></div><div class="mbody ph"><div class="items"><div class="item"><div class="r"><a href="info/1061/42.htm"><div class="title">Fixture mobile copy</div></a></div></div></div></div>"#,
        );
        let document = parse_listing(
            &college_html(&source).unwrap(),
            &Url::parse(AVIATION_PUBLIC_NOTICES_URL).unwrap(),
            "公开公示",
        )
        .unwrap();
        assert_eq!(
            document
                .entries
                .iter()
                .map(|entry| (entry.title.as_str(), entry.date.as_deref()))
                .collect::<Vec<_>>(),
            [
                ("Fixture policy", Some("2026-04-03")),
                ("Unknown-date fixture", None)
            ]
        );
        let filtered = document
            .entries
            .iter()
            .filter(|entry| {
                entry_in_scope(
                    entry,
                    &Some("2026-04-03".into()),
                    &Some("2026-04-03".into()),
                    &None,
                )
            })
            .map(|entry| entry.title.as_str())
            .collect::<Vec<_>>();
        assert_eq!(filtered, ["Fixture policy"]);
    }

    #[test]
    fn article_returns_desktop_prose_and_its_publication_header_only() {
        let source = response(
            r#"<h2>Sidebar</h2><div class="body mh"><div class="moudle"><div class="right"><div class="items"><div><form><div class="title">Fixture policy</div><div class="date"><span>发布时间：2026-09-22</span></div><div class="v_news_content"><p>Source policy paragraph.</p></div></form></div></div></div></div></div><div class="mbody ph"><div class="items"><form><div class="title">Mobile title</div><div class="v_news_content"><p>Not an extra paragraph.</p></div></form></div></div>"#,
        );
        let output = normalize(&source, &college_html(&source).unwrap()).unwrap();
        assert_eq!(output["title"], "Fixture policy");
        assert_eq!(output["published_at"], "2026-09-22");
        assert_eq!(
            output["body_paragraphs"],
            json!(["Source policy paragraph."])
        );
    }

    #[test]
    fn body_date_is_not_article_publication_metadata() {
        let source = response(
            r#"<div class="body mh"><div class="moudle"><div class="right"><div class="items"><form><div class="title">Fixture policy</div><div class="v_news_content"><div class="date"><span>发布时间：2026-11-01</span></div><p>Body date is not the publication header.</p></div></form></div></div></div></div>"#,
        );
        let output = normalize(&source, &college_html(&source).unwrap()).unwrap();
        assert_eq!(output["published_at"], Value::Null);
        assert_eq!(
            output["body_paragraphs"],
            json!(["Body date is not the publication header."])
        );
    }
}
