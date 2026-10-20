//! Foreign-languages college notices: exact HTTP directory identity and a
//! deliberately separate HTTPS observation of the public site.
use super::scse::viewer;
use super::{
    ListQuery, ListingDocument, ListingEntry, MAX_HREF, MAX_TEXT, advertised_page_url,
    article_category_from_url, article_paragraphs, bind_college_board,
    college_directory_attribution, college_html, declared_jsp_attachment_hints,
    describe_college_surface, element_text, entry_in_scope, failed_contract, html_fallback,
    invalid_article, invalid_list, is_safe_public_fallback, parse_iso_date, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, FLD_NOTICES_URL, FLD_ROOT_URL, fld_path_allowed,
};
use scraper::{ElementRef, Html, Node, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://fld.buaa.edu.cn/";
const PUBLISHER: &str = "北京航空航天大学外国语学院";
const CATEGORY: &str = "zxtz";
const LISTING_LABEL: &str = "最新通知";

fn plain_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("fld.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && fld_path_allowed(url.path())
}

fn source_mode(mode: CacheMode) -> CacheMode {
    if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    }
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let directory = crate::organizations::list(source_mode(mode))?;
    let mut attribution =
        college_directory_attribution(&directory, "外国语学院", LISTED_ROOT_URL, LISTED_ROOT_URL)?;
    attribution["selected_https_root"] = FLD_ROOT_URL.into();
    attribution["selection_relation"] =
        "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_fld(source_mode(mode))?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => FLD_ROOT_URL,
        "notices" => FLD_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, FLD_ROOT_URL, FLD_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            let _document = college_html(response)?;
            match describe_college_surface(response, "fld", attribution.clone()) {
                Ok(mut value) => {
                    value["completeness"]["announcement_adapter_verified"] = json!(true);
                    value["completeness"]["selected_board"] = json!(FLD_NOTICES_URL);
                    Ok(value)
                }
                Err(_) if is_safe_public_fallback(response) => {
                    let mut value = html_fallback(
                        response,
                        "college_source_surface",
                        "fld",
                        "fld_surface_selector_contract",
                    );
                    value["directory_attribution"] = attribution.clone();
                    Ok(value)
                }
                Err(error) => Err(error),
            }
        })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(FLD_NOTICES_URL).map_err(|_| unavailable())?;
    if page == 1 {
        return Ok(latest);
    }
    client.get(&latest, false, |response| {
        college_html(response)?;
        advertised_page_url(&response.body, &latest, page, "div.fanyxh a[href]", |url| {
            plain_url(url) && url.path().starts_with("/xwzx/zxtz/")
        })
    })
}

fn row_date(row: ElementRef<'_>) -> Option<String> {
    let mut dates = Vec::new();
    for child in row.children() {
        if let Node::Text(text) = child.value() {
            let raw = text.text.trim();
            if raw.is_empty() {
                continue;
            }
            if let Some(date) = parse_iso_date(raw) {
                dates.push(date);
            }
        }
    }
    if dates.len() == 1 { dates.pop() } else { None }
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
    let views = Selector::parse("div.lixistee > ul").map_err(|_| unavailable())?;
    let mut views = document
        .select(&views)
        .filter(|node| !super::inert_element(*node));
    let primary = views
        .next()
        .filter(|_| views.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Fld latest-notice listing requires one lixistee/ul source view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a[href]").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in primary.select(&rows) {
        if entries.len() == super::MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut links = row.select(&anchors);
        let anchor = links
            .next()
            .filter(|_| links.next().is_none())
            .ok_or_else(|| {
                failed_contract(
                    "Fld latest-notice row requires one direct source anchor",
                    file!(),
                    line!(),
                )
            })?;
        let title = anchor
            .value()
            .attr("title")
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT)
            .map(str::to_owned)
            .ok_or_else(|| {
                failed_contract(
                    "Fld latest-notice row requires a complete title attribute",
                    file!(),
                    line!(),
                )
            })?;
        let listed_href = anchor.value().attr("href").ok_or_else(unavailable)?;
        if listed_href.len() > MAX_HREF || listed_href.chars().any(char::is_control) {
            return Err(unavailable());
        }
        let resolved = base.join(listed_href).map_err(|_| unavailable())?;
        if !plain_url(&resolved) || !resolved.path().starts_with("/info/1011/") {
            return Err(failed_contract(
                "Fld latest-notice rows must declare canonical same-host 1011 articles",
                file!(),
                line!(),
            ));
        }
        entries.push(ListingEntry {
            source_order: entries.len() + 1,
            title,
            date: row_date(row),
            category_label: Some(LISTING_LABEL.into()),
            summary: None,
            listed_href: Some(listed_href.to_owned()),
            resolved_http_url: Some(resolved.to_string()),
            link_kind: "https",
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "Fld latest-notice listing requires at least one source row",
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
        .is_some_and(|category| category != CATEGORY)
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
    bind_college_board(&client, FLD_ROOT_URL, FLD_NOTICES_URL, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get(&target, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &target) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                let mut value = html_fallback(
                    response,
                    "announcements_list",
                    "fld",
                    "fld_listing_selector_contract",
                );
                value["category"] = json!(CATEGORY);
                value["listing_label"] = json!(LISTING_LABEL);
                value["page"] = json!(page);
                value["directory_attribution"] = attribution.clone();
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
            "schema_version":1,
            "type":"announcements_list",
            "result":"listing_snapshot",
            "publisher":PUBLISHER,
            "college":"fld",
            "category":CATEGORY,
            "listing_label":LISTING_LABEL,
            "page":page,
            "document_title":document.title,
            "filters":{"since":since,"until":until,"match":query.r#match},
            "entries":entries,
            "entry_count":entries.len(),
            "directory_attribution":attribution,
            "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"source YYYY-MM-DD; missing or invalid stays null","summaries":"source title attribute only; not original full text"},
            "retrieval":retrieval(response)
        }))
    })
}

fn local_asset_path(path: &str, extension: Option<&str>) -> bool {
    let Some(tail) = path.strip_prefix("/__local/") else {
        return false;
    };
    !tail.is_empty()
        && tail.len() <= MAX_HREF
        && !tail.contains("..")
        && !tail.contains(['%', '\\', '?', '#'])
        && !tail.chars().any(char::is_control)
        && extension.is_none_or(|extension| tail.to_ascii_lowercase().ends_with(extension))
}

fn script_show_pdf_path(script: &str) -> Result<Option<String>, Error> {
    let mut selected = None;
    for path in viewer::declarations(script)? {
        match selected.as_deref() {
            Some(previous) if previous != path.as_str() => {
                return Err(failed_contract(
                    "Fld article declares conflicting original PDF paths",
                    file!(),
                    line!(),
                ));
            }
            None => selected = Some(path),
            _ => {}
        }
    }
    Ok(selected)
}

fn preview_paths(script: &str) -> Result<Vec<String>, Error> {
    let paths = super::hss::declared_preview_paths(script)?;
    if paths.len() > 128
        || paths
            .iter()
            .any(|path| !local_asset_path(path, None) || path.len() > MAX_HREF)
    {
        return Err(unavailable());
    }
    Ok(paths)
}

fn declared_assets(
    body: ElementRef<'_>,
    article: &Url,
) -> Result<(Option<Url>, Vec<String>), Error> {
    let scripts = Selector::parse("script").map_err(|_| unavailable())?;
    let mut original_pdf = None;
    let mut previews = Vec::new();
    for script in body.select(&scripts) {
        if crate::html::inert_element(script)
            || script.value().attr("src").is_some()
            || crate::html::script_kind(script) != Some(crate::html::ScriptKind::Classic)
        {
            continue;
        }
        let text = script.text().collect::<Vec<_>>().concat();
        if let Some(path) = script_show_pdf_path(&text)? {
            let url = article.join(&path).map_err(|_| unavailable())?;
            if !plain_url(article)
                || url.scheme() != "https"
                || url.host_str() != Some("fld.buaa.edu.cn")
                || url.username() != ""
                || url.password().is_some()
                || url.port().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !local_asset_path(url.path(), Some(".pdf"))
            {
                return Err(failed_contract(
                    "Fld source-declared original PDF must remain a same-host local PDF path",
                    file!(),
                    line!(),
                ));
            }
            if original_pdf
                .as_ref()
                .is_some_and(|previous: &Url| previous != &url)
            {
                return Err(failed_contract(
                    "Fld article declares conflicting original PDF URLs",
                    file!(),
                    line!(),
                ));
            }
            original_pdf = Some(url);
        }
        previews.extend(preview_paths(&text)?);
    }
    previews.sort();
    previews.dedup();
    Ok((original_pdf, previews))
}

fn publication_date(raw: &str) -> Option<String> {
    let mut dates = Vec::new();
    for token in raw.split_whitespace() {
        let candidate = token
            .strip_prefix("发布时间：")
            .or_else(|| token.strip_prefix("发布时间:"))
            .unwrap_or(token);
        if let Some(date) = parse_iso_date(candidate) {
            dates.push(date);
        }
    }
    if dates.len() == 1 { dates.pop() } else { None }
}

fn normalize_article(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    let mains = Selector::parse("div.ljkm23").map_err(|_| unavailable())?;
    let mut mains = document
        .select(&mains)
        .filter(|node| !super::inert_element(*node));
    let main = mains
        .next()
        .filter(|_| mains.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Fld article requires one active ljkm23 source container",
                file!(),
                line!(),
            )
        })?;
    let titles = Selector::parse(":scope > div.mch3").map_err(|_| unavailable())?;
    let mut titles = main.select(&titles);
    let title = titles
        .next()
        .filter(|_| titles.next().is_none())
        .map(element_text)
        .filter(|text| !text.is_empty() && text.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "Fld article requires one direct mch3 title",
                file!(),
                line!(),
            )
        })?;
    let metadata_selector = Selector::parse(":scope > div.mch3sh").map_err(|_| unavailable())?;
    let mut metadata = main.select(&metadata_selector);
    let published_at_raw = metadata.next().map(element_text);
    if metadata.next().is_some() {
        return Err(failed_contract(
            "Fld article requires one direct mch3sh publication header",
            file!(),
            line!(),
        ));
    }
    let published_at = published_at_raw.as_deref().and_then(publication_date);
    let body_selector = Selector::parse(":scope > div#vsb_content > div.v_news_content")
        .map_err(|_| unavailable())?;
    let mut bodies = main.select(&body_selector);
    let body = bodies.next().ok_or_else(|| {
        failed_contract(
            "Fld article requires one direct vsb_content/v_news_content body",
            file!(),
            line!(),
        )
    })?;
    if bodies.next().is_some() {
        return Err(failed_contract(
            "Fld article requires one direct vsb_content/v_news_content body",
            file!(),
            line!(),
        ));
    }
    let paragraphs = article_paragraphs(body, true)?;
    let article_url = Url::parse(&response.url).map_err(|_| unavailable())?;
    let (original_pdf, previews) = declared_assets(body, &article_url)?;
    let has_document = original_pdf.is_some() || !previews.is_empty();
    let (attachment_hints, hints_truncated) = declared_jsp_attachment_hints(main)?;
    let attachments_found = !attachment_hints.is_empty() || hints_truncated;
    let images = Selector::parse("img").map_err(|_| unavailable())?;
    let tables = Selector::parse("table").map_err(|_| unavailable())?;
    let has_images = body.select(&images).any(|node| !super::inert_element(node));
    let table_count = body
        .select(&tables)
        .filter(|node| !super::inert_element(*node))
        .count();
    if paragraphs.is_empty()
        && !has_document
        && !attachments_found
        && !has_images
        && table_count == 0
    {
        return Err(failed_contract(
            "Fld article requires text or source-declared document/attachment content",
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
    } else if attachments_found || has_images || table_count != 0 {
        "partial_text"
    } else {
        "full_text"
    };
    Ok(json!({
        "schema_version":1,
        "type":"announcements_article",
        "result":result,
        "publisher":PUBLISHER,
        "college":"fld",
        "title":title,
        "published_at":published_at,
        "published_at_raw":published_at_raw,
        "body_paragraph_count":paragraphs.len(),
        "body_paragraphs":paragraphs,
        "embedded_document":{"present":has_document,"original_pdf_url":original_pdf.as_ref().map(Url::as_str),"preview_paths":previews,"preview_kind":"source_declared_derived_images","assets_fetched":false,"ocr_performed":false,"original_document_verified":false},
        "attachments":{"found":attachments_found,"hints":attachment_hints,"hints_truncated":hints_truncated,"note":"source-declared links only; never fetched"},
        "completeness":{"scope":"single_college_article_page","body_source":"ljkm23/#vsb_content/v_news_content paragraphs excluding executable/fallback markup","missing_document_text":"not_reconstructed","image_content_present":has_images,"unextracted_table_count":table_count},
        "category":article_category_from_url(&article_url),
        "retrieval":retrieval(response)
    }))
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || source_page == 0
        || !target.path().starts_with("/info/1011/")
    {
        return Err(invalid_article());
    }
    let (client, mut attribution) = bound_client(mode)?;
    bind_college_board(&client, FLD_ROOT_URL, FLD_NOTICES_URL, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing_result: Result<Value, Error> = client.get(&source, false, |response| {
        let html = college_html(response)?;
        let document = match parse_listing(&html, &source) {
            Ok(document) => document,
            Err(_) if is_safe_public_fallback(response) => {
                let mut value = html_fallback(
                    response,
                    "announcements_list",
                    "fld",
                    "fld_listing_selector_contract",
                );
                value["category"] = json!(CATEGORY);
                value["listing_label"] = json!(LISTING_LABEL);
                value["page"] = json!(source_page);
                return Ok(Ok(value));
            }
            Err(error) => return Err(error),
        };
        if !document
            .entries
            .iter()
            .any(|entry| entry.resolved_http_url.as_deref() == Some(target.as_str()))
        {
            return Ok(Err(Error::new(
                "unsupported",
                "retained latest-notice page does not declare the selected Fld article",
            )));
        }
        Ok(Ok(retrieval(response)))
    })?;
    let listing = listing_result?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            "retained Fld listing could not be parsed; the admitted board snapshot was retained for offline repair",
        ));
    }
    client
        .with_cache_mode(mode)
        .get(&target, false, |response| {
            let document = college_html(response)?;
            let mut output = match normalize_article(response, &document) {
                Ok(value) => value,
                Err(_) if is_safe_public_fallback(response) => html_fallback(
                    response,
                    "announcements_article",
                    "fld",
                    "fld_article_selector_contract",
                ),
                Err(error) => return Err(error),
            };
            output["directory_attribution"] = attribution.clone();
            output["source_listing"] = listing.clone();
            Ok(output)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CacheStatus, Response};
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
    fn latest_notice_listing_keeps_complete_title_attribute_and_source_date() {
        let html = Html::parse_document(
            r#"<title>最新通知-北航外国语</title><div class="lixistee"><ul>
                <li><a href="../info/1011/42.htm" title="Complete source title">Visible truncation...</a> 2026-10-15</li>
            </ul></div>"#,
        );
        let base = Url::parse(FLD_NOTICES_URL).unwrap();
        let listing = parse_listing(&html, &base).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].title, "Complete source title");
        assert_eq!(listing.entries[0].date.as_deref(), Some("2026-10-15"));
        assert_eq!(
            listing.entries[0].resolved_http_url.as_deref(),
            Some("https://fld.buaa.edu.cn/info/1011/42.htm")
        );
    }

    #[test]
    fn pdf_only_article_is_embedded_document_without_script_text() {
        let body = r#"<html><body><div class="ljkm23">
            <div class="mch3">Original notice</div>
            <div class="mch3sh">来源： 发布时间：2026-10-15</div>
            <div id="vsb_content" class="mchcot"><div class="v_news_content"><p><script>var vsb_pdf_image_data = ["/__local/0/DF/7A/preview.jpg"];showVsbpdfIframe("/__local/4/58/94/original_12345678_12A59.pdf","100%","600");</script></p></div></div>
        </div></body></html>"#;
        let response = response("https://fld.buaa.edu.cn/info/1011/42.htm", body);
        let document = college_html(&response).unwrap();
        let output = normalize_article(&response, &document).unwrap();
        assert_eq!(output["result"], "embedded_document");
        assert_eq!(output["published_at"], "2026-10-15");
        assert_eq!(output["body_paragraphs"], json!([]));
        assert_eq!(
            output["embedded_document"]["original_pdf_url"],
            "https://fld.buaa.edu.cn/__local/4/58/94/original_12345678_12A59.pdf"
        );
        assert_eq!(
            output["embedded_document"]["preview_paths"],
            json!(["/__local/0/DF/7A/preview.jpg"])
        );
    }

    #[test]
    fn review_regression_inert_fld_scripts_cannot_authorize_an_embedded_document() {
        for container in ["template", "noscript"] {
            let body = format!(
                r#"<html><body><div class="ljkm23">
                <div class="mch3">Original notice</div>
                <div class="mch3sh">来源： 发布时间：2026-10-15</div>
                <div id="vsb_content" class="mchcot"><div class="v_news_content"><p><{container}><script>showVsbpdfIframe("/__local/4/58/94/original_12345678_12A59.pdf","100%","600");</script></{container}></p></div></div>
            </div></body></html>"#
            );
            let response = response("https://fld.buaa.edu.cn/info/1011/42.htm", &body);
            let document = college_html(&response).unwrap();
            assert_eq!(
                normalize_article(&response, &document).unwrap_err().code,
                "unavailable"
            );
        }
    }

    #[test]
    fn review_regression_inactive_fld_original_calls_cannot_authorize_an_embedded_document() {
        for script in [
            r#"function unused(){showVsbpdfIframe("/__local/4/58/94/original_12345678_12A59.pdf","100%","600");}"#,
            r#"/*;showVsbpdfIframe("/__local/4/58/94/original_12345678_12A59.pdf");*/"#,
        ] {
            let body = format!(
                r#"<html><body><div class="ljkm23">
                <div class="mch3">Original notice</div>
                <div class="mch3sh">来源： 发布时间：2026-10-15</div>
                <div id="vsb_content" class="mchcot"><div class="v_news_content"><p><script>{script}</script></p></div></div>
            </div></body></html>"#
            );
            let response = response("https://fld.buaa.edu.cn/info/1011/42.htm", &body);
            let document = college_html(&response).unwrap();
            assert_eq!(
                normalize_article(&response, &document).unwrap_err().code,
                "unavailable"
            );
        }
    }

    #[test]
    fn review_regression_inactive_fld_preview_assignments_cannot_supply_document_presence() {
        for script in [
            r#"/*vsb_pdf_image_data=["/__local/0/DF/7A/preview.jpg"];*/"#,
            r#"const text = "vsb_pdf_image_data=[\"/__local/0/DF/7A/preview.jpg\"]";"#,
        ] {
            let body = format!(
                r#"<html><body><div class="ljkm23">
                <div class="mch3">Original notice</div>
                <div class="mch3sh">来源： 发布时间：2026-10-15</div>
                <div id="vsb_content" class="mchcot"><div class="v_news_content"><p><script>{script}</script></p></div></div>
            </div></body></html>"#
            );
            let response = response("https://fld.buaa.edu.cn/info/1011/42.htm", &body);
            let document = college_html(&response).unwrap();
            assert_eq!(
                normalize_article(&response, &document).unwrap_err().code,
                "unavailable"
            );
        }

        let active_preview_only = r#"<html><body><div class="ljkm23">
            <div class="mch3">Original notice</div>
            <div class="mch3sh">来源： 发布时间：2026-10-15</div>
            <div id="vsb_content" class="mchcot"><div class="v_news_content"><p><script>var vsb_pdf_image_data=["/__local/0/DF/7A/preview.jpg"];</script></p></div></div>
        </div></body></html>"#;
        let response = response(
            "https://fld.buaa.edu.cn/info/1011/42.htm",
            active_preview_only,
        );
        let document = college_html(&response).unwrap();
        let output = normalize_article(&response, &document).unwrap();
        assert_eq!(output["result"], "embedded_document");
        assert_eq!(output["embedded_document"]["original_pdf_url"], Value::Null);
        assert_eq!(
            output["embedded_document"]["preview_paths"],
            json!(["/__local/0/DF/7A/preview.jpg"])
        );
    }

    #[test]
    fn article_url_rejects_foreign_and_query_routes() {
        let foreign = Url::parse("https://example.com/info/1011/42.htm").unwrap();
        let query = Url::parse("https://fld.buaa.edu.cn/info/1011/42.htm?x=1").unwrap();
        assert!(!plain_url(&foreign));
        assert!(!plain_url(&query));
    }
}
