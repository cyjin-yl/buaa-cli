//! Official-directory-bound Shenyuan college source observations.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url, article_body, article_output, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, invalid_article, invalid_list, is_http, parse_iso_date,
    is_safe_public_fallback_document, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, Response, SHENYUAN_NOTICES_URL, SHENYUAN_ROOT_URL,
    shenyuan_path_allowed,
};
use scraper::{ElementRef, Html, Node, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学沈元学院";

/// Decodes only bounded `&#N;`/`&#xN;` numeric references; malformed or named
/// entities pass through literally. Marker bytes hidden behind a numeric
/// reference stay reachable to the source scan through this decode.
fn decode_numeric_entities(source: &str) -> Option<String> {
    if !source.contains("&#") {
        return None;
    }
    let mut decoded = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("&#") {
        decoded.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let (digits, hex) = match after.strip_prefix(['x', 'X']) {
            Some(tail) => (tail, true),
            None => (after, false),
        };
        let end = digits
            .find(|c: char| {
                if hex {
                    !c.is_ascii_hexdigit()
                } else {
                    !c.is_ascii_digit()
                }
            })
            .unwrap_or(digits.len());
        if end == 0 || end == digits.len() || digits.as_bytes()[end] != b';' {
            decoded.push_str("&#");
            rest = after;
            continue;
        }
        match u32::from_str_radix(&digits[..end], if hex { 16 } else { 10 })
            .ok()
            .and_then(char::from_u32)
        {
            Some(c) => decoded.push(c),
            None => decoded.push_str(&rest[start..start + 2 + (hex as usize) + end + 1]),
        }
        rest = &digits[end + 1..];
    }
    decoded.push_str(rest);
    Some(decoded)
}

/// Whether the exact source bytes may leave the adapter or enter the cache.
/// The shared element scan misses credential markers inside inert
/// script/style/template payloads, comments and discarded raw attributes, so
/// the whole body is screened literally and after numeric-entity decoding.
/// Credential-shaped keys that make a `key=value`, `key:`, name/id attribute
/// or JSON member an actual credential field rather than prose. Substring
/// needles cover compound names (csrf_token, requestVerificationToken); the
/// exact set keeps short words like `cas` or `sso` from matching inside
/// unrelated tokens like `cascade` or `association`.
fn credentialish_key(key: &str) -> bool {
    const CONTAINS: &[&str] = &[
        "password",
        "passwd",
        "passphrase",
        "csrf",
        "xsrf",
        "token",
        "ticket",
        "secret",
        "credential",
        "captcha",
        "session",
        "authenticity",
        "verification",
        "antiforgery",
        "apikey",
        "accesskey",
        "secretkey",
        "privatekey",
        "passcode",
        "passkey",
        "login",
        "signin",
        "oauth",
        "saml",
        "jwt",
        "turnstile",
        "challenge",
    ];
    const EXACT: &[&str] = &[
        "auth",
        "authentication",
        "authorization",
        "authorize",
        "login",
        "signin",
        "signon",
        "sso",
        "cas",
        "user",
        "username",
        "userid",
        "uid",
        "account",
        "pwd",
        "bearer",
        "otp",
        "totp",
        "sid",
        "jsessionid",
        "cookie",
    ];
    let compact: String = key
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect();
    if compact.is_empty() {
        return false;
    }
    CONTAINS.iter().any(|needle| compact.contains(needle))
        || EXACT.contains(&compact.as_str())
        || key
            .split(|c: char| !c.is_ascii_alphanumeric())
            .map(str::to_ascii_lowercase)
            .any(|part| EXACT.contains(&part.as_str()))
}

/// The leading unquoted-or-quoted value token after a `key=` or `key:` marker.
fn value_token(rest: &str) -> &str {
    let value = rest.trim_start_matches(['"', '\'']);
    let end = value
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(value.len());
    &value[..end]
}

/// A `key=` assignment carries a credential field when the key is
/// credential-named and a value follows, when name/id carries a credential
/// field identity, or when type selects a password control.
fn credentialish_assignment(key: &str, rest: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    if key.eq_ignore_ascii_case("name") || key.eq_ignore_ascii_case("id") {
        let value = value_token(rest);
        return !value.is_empty() && credentialish_key(value);
    }
    if key.eq_ignore_ascii_case("type") {
        return value_token(rest).eq_ignore_ascii_case("password");
    }
    credentialish_key(key)
        && (!value_token(rest).is_empty()
            || rest
                .chars()
                .next()
                .is_some_and(|c| matches!(c, '{' | '[' | '(')))
}

/// Literal token shapes that mark live credential material: `Bearer`/`Basic`
/// auth values, JWT segments and CAS `ST-` service tickets.
fn known_token_prefix(source: &str) -> bool {
    let bytes = source.as_bytes();
    let token_run = |start: usize| -> usize {
        bytes
            .get(start..)
            .unwrap_or(&[])
            .iter()
            .take_while(|c| {
                c.is_ascii_alphanumeric() || matches!(**c, b'_' | b'-' | b'.' | b'~' | b'=')
            })
            .count()
    };
    let boundary = |at: usize| at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
    for keyword in ["Bearer ", "Basic ", "Token "] {
        for (at, _) in source.match_indices(keyword) {
            if boundary(at) && token_run(at + keyword.len()) >= 8 {
                return true;
            }
        }
    }
    for (at, _) in source.match_indices("eyJ") {
        if boundary(at) && token_run(at) >= 16 {
            return true;
        }
    }
    for (at, _) in source.match_indices("ST-") {
        if !boundary(at) {
            continue;
        }
        let digits = bytes[at + 3..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        let tail = at + 3 + digits;
        if digits >= 4
            && tail < bytes.len()
            && bytes[tail] == b'-'
            && token_run(tail + 1) >= 8
        {
            return true;
        }
    }
    false
}

/// A credential-bearing construct anywhere in the source bytes, including
/// inert script bodies, comments and raw attributes: a credential-named
/// `key=` or `key:` field with a value, a JSON/object `"key":` member, a
/// name/id/type attribute carrying credential semantics, or a literal token
/// shape. Prose words alone never match: every pattern requires a value or
/// structured field, so "without authentication signals" stays safe.
fn credential_construct(source: &str) -> bool {
    let bytes = source.as_bytes();
    let n = bytes.len();
    let mut at = 0;
    while at < n {
        match bytes[at] {
            b'"' | b'\'' => {
                let quote = bytes[at];
                let mut end = at + 1;
                while end < n && bytes[end] != quote {
                    if bytes[end] == b'\\' {
                        end += 1;
                    }
                    end += 1;
                }
                if end >= n {
                    at += 1;
                    continue;
                }
                let inner = &source[at + 1..end];
                let rest = source[end + 1..].trim_start();
                if (rest.starts_with(':')
                    && rest[1..]
                        .trim_start()
                        .chars()
                        .next()
                        .is_some_and(|c| !matches!(c, ',' | '}' | ']' | ':'))
                    && credentialish_key(inner))
                    || credential_construct(inner)
                {
                    return true;
                }
                at = end + 1;
            }
            b'=' | b':' => {
                let mut start = at;
                while start > 0 && bytes[start - 1].is_ascii_whitespace() {
                    start -= 1;
                }
                let key_end = start;
                while start > 0
                    && (bytes[start - 1].is_ascii_alphanumeric()
                        || bytes[start - 1] == b'_'
                        || bytes[start - 1] == b'-')
                {
                    start -= 1;
                }
                let key = &source[start..key_end];
                let rest = source[at + 1..].trim_start();
                if bytes[at] == b'=' {
                    if credentialish_assignment(key, rest) {
                        return true;
                    }
                } else if source[key_end..at]
                    .bytes()
                    .all(|b| b.is_ascii_whitespace())
                    && credentialish_key(key)
                    && rest
                        .chars()
                        .next()
                        .is_some_and(|c| {
                            c.is_ascii_digit() || matches!(c, '"' | '\'' | '{' | '[')
                        })
                {
                    return true;
                }
                at += 1;
            }
            _ => at += 1,
        }
    }
    known_token_prefix(source)
}

/// DOM decoding resolves entities the literal scan cannot see, so credential
/// field identities hidden behind named entities in name/id/type attribute
/// values are screened a second time.
fn credential_dom_attrs(document: &Html) -> bool {
    document
        .tree
        .root()
        .descendants()
        .any(|node| match node.value() {
            Node::Element(element) => element.attrs.iter().any(|(name, value)| {
                let attr = name.local.as_ref();
                if attr.eq_ignore_ascii_case("type") {
                    return value.trim().eq_ignore_ascii_case("password");
                }
                (attr.eq_ignore_ascii_case("name") || attr.eq_ignore_ascii_case("id"))
                    && credentialish_key(value)
            }),
            _ => false,
        })
}

/// Whether the exact source bytes may leave the adapter or enter the cache.
/// The shared element scan misses credential constructs inside inert
/// script/style/template payloads, comments and discarded raw attributes, so
/// the whole body is screened literally and after numeric-entity decoding;
/// a DOM pass catches named-entity-obfuscated field attributes. Ordinary
/// prose mentioning authentication, login, CAS or CSRF is not a construct
/// and stays exportable.
fn export_safe_body(bytes: &[u8]) -> bool {
    let Ok(source) = std::str::from_utf8(bytes) else {
        return false;
    };
    if credential_construct(source)
        || decode_numeric_entities(source)
            .is_some_and(|decoded| credential_construct(&decoded))
    {
        return false;
    }
    !credential_dom_attrs(&Html::parse_document(source))
}

/// The shared degraded-evidence envelope with original-byte export gated on
/// the source-text marker scan. A structurally safe drifted page keeps its
/// exact bytes, hash and length; a body carrying credential-named fields or
/// markers in inert/comment text publishes no bytes and no header values.
fn html_fallback(
    response: &crate::net::Response,
    output_type: &str,
    college: &str,
    reason: &str,
) -> Value {
    if export_safe_body(&response.body) {
        let mut value = super::html_fallback(response, output_type, college, reason);
        value["raw_withheld"] = json!(false);
        value["raw_withheld_reason"] = Value::Null;
        return value;
    }
    let mut provenance = retrieval(response);
    provenance["http"] =
        json!({"status": response.status, "headers": {}, "headers_withheld": true});
    json!({
        "schema_version": 1,
        "type": output_type,
        "result": "fallback",
        "college": college,
        "raw_html": Value::Null,
        "raw_withheld": true,
        "raw_withheld_reason": "source_screening_refused",
        "raw_html_sha256": response.sha256,
        "content_type": "text/html",
        "body_byte_length": response.body.len(),
        "fallback_reason": reason,
        "retrieval": provenance,
    })
}

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
    client.with_cache_mode(mode).get_with_archive_status_and_persistence(
        &target,
        false,
        |_, _| false,
        |_, response| export_safe_body(&response.body),
        |response| {
            describe_college_surface(response, "shenyuan", attribution)
        },
    )
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
    client.get_with_archive_status_and_persistence(
        &latest,
        false,
        |_, _| false,
        |_, response| export_safe_body(&response.body),
        |response| {
            let document = college_html(response)?;
            super::refuse_unsafe_listing(response, &document)?;
            advertised_page_url(
                &response.body,
                &latest,
                page,
                "div.pb_sys_common span.p_no a[href]",
                |url| plain_url(url) && url.path().starts_with("/index/tzgg/"),
            )
        },
    )
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
    client.with_cache_mode(mode).get_with_archive_status_and_persistence(
        &target,
        false,
        |_, _| false,
        |_, response| export_safe_body(&response.body),
        |response| {
            let html = college_html(response)?;
            let document = match parse_listing(&html, &target) {
                Ok(document) => document,
                Err(_) if is_safe_public_fallback_document(response, &html) => {
                    let mut value = html_fallback(
                        response,
                        "announcements_list",
                        "shenyuan",
                        "shenyuan_listing_selector_contract",
                    );
                    value["category"] = json!("tzgg");
                    value["page"] = json!(page);
                    return Ok(value);
                }
                Err(error) => return Err(error),
            };
            super::refuse_unsafe_listing(response, &html)?;
            let entries: Vec<&ListingEntry> = document.entries.iter()
                .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
            Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
                "publisher":PUBLISHER,"college":"shenyuan","category":"tzgg","listing_label":"通知公告","page":page,
                "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
                "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
                "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"source split DD and YYYY-MM; missing or invalid stays null"},"retrieval":retrieval(response)}))
        },
    )
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
    let listing_result: Result<Value, Error> = client.get_with_archive_status_and_persistence(
        &source,
        false,
        |_, _| false,
        |_, response| export_safe_body(&response.body),
        |response| {
            let html = college_html(response)?;
            let document = match parse_listing(&html, &source) {
                Ok(document) => document,
                Err(_) if is_safe_public_fallback_document(response, &html) => {
                    return Ok(Ok(html_fallback(
                        response,
                        "announcements_list",
                        "shenyuan",
                        "shenyuan_listing_selector_contract",
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
                    "retained notice page does not declare the selected Shenyuan article",
                )));
            }
            Ok(Ok(retrieval(response)))
        },
    )?;
    let listing = listing_result?;
    if listing.get("result").and_then(Value::as_str) == Some("fallback") {
        return Err(Error::new(
            "unavailable",
            if listing["raw_withheld"] == true {
                "retained Shenyuan notice page could not be parsed and its credential-bearing bytes were withheld without retention"
            } else {
                "retained Shenyuan notice page could not be parsed; the admitted board snapshot was retained for offline repair"
            },
        ));
    }
    client.with_cache_mode(mode).get_with_archive_status_and_persistence(
        target,
        false,
        |_, _| false,
        |_, response| export_safe_body(&response.body),
        |response| {
            let html = college_html(response)?;
            let mut output = match normalize(response, &html) {
                Ok(value) => value,
                Err(_) if is_safe_public_fallback_document(response, &html) => html_fallback(
                    response,
                    "announcements_article",
                    "shenyuan",
                    "shenyuan_article_selector_contract",
                ),
                Err(error) => return Err(error),
            };
            output["publisher"] = json!(PUBLISHER);
            output["college"] = json!("shenyuan");
            output["directory_attribution"] = attribution;
            output["source_listing"] = listing;
            Ok(output)
        },
    )
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
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
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

    fn listing_response(body: &str) -> Response {
        Response {
            url: SHENYUAN_NOTICES_URL.into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            body: body.as_bytes().to_vec(),
            sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    /// A safe admitted 200 text/html listing whose selectors no longer match is
    /// degraded evidence, not an outer error: the exact original bytes and hash
    /// are preserved and a later cache-only read replays the same record.
    #[test]
    fn drifted_safe_listing_keeps_exact_bytes_as_replayable_degraded_evidence() {
        const DRIFTED: &str = r#"<title>通知公告</title><section class="n_zhuanti"><div id="tab_a2"><ul class="list_box_03s"><li><a class="a" href="../info/1083/42.htm"><div class="time"><h3>29</h3><h6>2024-02</h6></div><div class="con"><h5>Fixture notice</h5></div></a></li></ul></div></section>"#;
        let source = listing_response(DRIFTED);
        let document = college_html(&source).unwrap();
        assert!(
            parse_listing(&document, &Url::parse(SHENYUAN_NOTICES_URL).unwrap()).is_err()
        );
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_list",
            "shenyuan",
            "shenyuan_listing_selector_contract",
        );
        assert_eq!(evidence["result"], "fallback");
        assert_eq!(
            STANDARD
                .decode(evidence["raw_html"].as_str().unwrap())
                .unwrap()
                .as_slice(),
            DRIFTED.as_bytes()
        );
        assert_eq!(evidence["raw_html_sha256"], source.sha256.as_str());
        assert_eq!(evidence["body_byte_length"], json!(DRIFTED.len()));
        assert!(evidence["entries"].is_null());
        assert!(evidence["entry_count"].is_null());
        assert!(evidence["document_title"].is_null());
        // A later cache-only read of the retained admission replays identical
        // degraded evidence; the recorded hit proves the original was kept.
        let mut replay = listing_response(DRIFTED);
        replay.cache_status = CacheStatus::Hit;
        let replayed = super::html_fallback(
            &replay,
            "announcements_list",
            "shenyuan",
            "shenyuan_listing_selector_contract",
        );
        assert_eq!(replayed["raw_html"], evidence["raw_html"]);
        assert_eq!(replayed["raw_html_sha256"], evidence["raw_html_sha256"]);
        assert_eq!(replayed["retrieval"]["cache_status"], "hit");
        assert_eq!(replayed["retrieval"]["http"]["status"], 200);
    }

    /// A requested page ordinal that the retained latest page does not
    /// advertise yields no inferred URL, but the admitted original stays
    /// usable: it still parses as the page-one listing and its exact bytes
    /// remain available as degraded evidence.
    #[test]
    fn unadvertised_page_ordinal_still_retains_the_admitted_latest() {
        const PAGE: &str = r#"<title>通知公告</title><section class="n_zhuanti"><div id="tab_a1"><ul class="list_box_03s"><li><a class="a" href="../info/1083/42.htm"><div class="time"><h3>29</h3><h6>2024-02</h6></div><div class="con"><h5>Latest notice</h5></div></a></li></ul></div></section><div class="pb_sys_common"><span class="p_no"><a href="tzgg/7.htm">3</a><a href="tzgg/9.htm">4</a></span></div>"#;
        let source = listing_response(PAGE);
        let base = Url::parse(SHENYUAN_NOTICES_URL).unwrap();
        let document = college_html(&source).unwrap();
        assert_eq!(parse_listing(&document, &base).unwrap().entries.len(), 1);
        assert!(
            advertised_page_url(
                &source.body,
                &base,
                2,
                "div.pb_sys_common span.p_no a[href]",
                |url| plain_url(url) && url.path().starts_with("/index/tzgg/")
            )
            .is_err()
        );
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_list",
            "shenyuan",
            "shenyuan_listing_selector_contract",
        );
        assert_eq!(
            STANDARD
                .decode(evidence["raw_html"].as_str().unwrap())
                .unwrap()
                .as_slice(),
            PAGE.as_bytes()
        );
        // An ordinal whose advertised target leaves the board stays refused.
        const FOREIGN: &str = r#"<div class="pb_sys_common"><span class="p_no"><a href="../info/1083/9.htm">2</a></span></div>"#;
        assert!(
            advertised_page_url(
                FOREIGN.as_bytes(),
                &base,
                2,
                "div.pb_sys_common span.p_no a[href]",
                |url| plain_url(url) && url.path().starts_with("/index/tzgg/")
            )
            .is_err()
        );
    }

    /// Credential material must never leave the adapter: inert script bytes
    /// carrying credential markers withhold the entire body from degraded
    /// evidence, and an active credential control refuses the page outright.
    #[test]
    fn drifted_listing_credential_material_is_refused_or_withheld() {
        const MARKED: &str = r#"<title>通知公告</title><script>window.session = {"csrf_token":"synthetic-fixture","id_token":"synthetic-fixture"};</script><section class="n_zhuanti"><div id="tab_a2"><ul class="list_box_03s"><li><a class="a" href="../info/1083/42.htm">Fixture</a></li></ul></div></section>"#;
        let source = listing_response(MARKED);
        let document = college_html(&source).unwrap();
        assert!(
            parse_listing(&document, &Url::parse(SHENYUAN_NOTICES_URL).unwrap()).is_err()
        );
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_list",
            "shenyuan",
            "shenyuan_listing_selector_contract",
        );
        assert!(evidence["raw_html"].is_null());
        assert!(
            !evidence
                .to_string()
                .contains(&*STANDARD.encode(MARKED.as_bytes())),
            "withheld source bytes must not appear anywhere in the emitted record"
        );
        const REFUSED: &str = r#"<title>通知公告</title><a href="/login?ticket=synthetic-fixture">Sign in</a><ul class="list_box_03s"><li>row</li></ul>"#;
        let refused = listing_response(REFUSED);
        let refused_document = college_html(&refused).unwrap();
        assert!(!super::super::is_safe_public_fallback(&refused));
        assert!(super::super::refuse_unsafe_listing(&refused, &refused_document).is_err());
        assert!(
            super::html_fallback(
                &refused,
                "announcements_list",
                "shenyuan",
                "shenyuan_listing_selector_contract"
            )["raw_html"]
                .is_null()
        );
    }

    /// The same drift contract applies to article pages: a safe admitted 200
    /// text/html article whose selectors changed preserves its exact bytes as
    /// degraded evidence instead of surfacing an outer error.
    #[test]
    fn drifted_safe_article_keeps_exact_bytes_as_degraded_evidence() {
        let body = r#"<section class="n_news_detail"><div class="ar_article_wrap"><form><div class="nav01"><h3>Fixture original heading</h3><h6><span>2026-09-29</span></h6></div><div class="ar_article" id="vsb_content_2"><div class="v_news_content"><p>Source paragraph.</p></div></div></form></div></section>"#;
        let source = response(body);
        let document = college_html(&source).unwrap();
        assert!(normalize(&source, &document).is_err());
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_article",
            "shenyuan",
            "shenyuan_article_selector_contract",
        );
        assert_eq!(evidence["result"], "fallback");
        assert_eq!(
            STANDARD
                .decode(evidence["raw_html"].as_str().unwrap())
                .unwrap()
                .as_slice(),
            body.as_bytes()
        );
        assert_eq!(evidence["raw_html_sha256"], source.sha256.as_str());
        assert!(evidence["title"].is_null());
        assert!(evidence["body_paragraphs"].is_null());
        assert!(evidence["published_at"].is_null());
    }

    #[test]
    fn prose_time_colons_stay_exportable_while_token_fields_withhold() {
        // A credentialish word separated from the colon by prose words is not
        // a field: "session 将于 19:00" keeps exact bytes. An adjacent
        // unquoted token field with a value still withholds the body.
        const PROSE: &str = r#"<title>通知公告</title><section class="n_zhuanti"><div id="tab_a2"><ul class="list_box_03s"><li><a class="a" href="../info/1083/42.htm">Fixture</a></li></ul></div></section><p>第三期 session 将于 19:00 开始</p>"#;
        let evidence = super::html_fallback(
            &listing_response(PROSE),
            "announcements_list",
            "shenyuan",
            "shenyuan_listing_selector_contract",
        );
        assert_eq!(
            STANDARD
                .decode(evidence["raw_html"].as_str().unwrap())
                .unwrap()
                .as_slice(),
            PROSE.as_bytes()
        );

        const FIELD: &str = r#"<title>通知公告</title><section class="n_zhuanti"><div id="tab_a2"><ul class="list_box_03s"><li><a class="a" href="../info/1083/42.htm">Fixture</a></li></ul></div></section><script>var s = {token : "synthetic-fixture"};</script>"#;
        let evidence = super::html_fallback(
            &listing_response(FIELD),
            "announcements_list",
            "shenyuan",
            "shenyuan_listing_selector_contract",
        );
        assert!(evidence["raw_html"].is_null());


        const COMPACT: &str = r#"<title>通知公告</title><section class="n_zhuanti"><div id="tab_a2"><ul class="list_box_03s"><li><a class="a" href="../info/1083/42.htm">Fixture</a></li></ul></div></section><script>var s = {token:"x"};</script>"#;
        let compact = super::html_fallback(
            &listing_response(COMPACT),
            "announcements_list",
            "shenyuan",
            "shenyuan_listing_selector_contract",
        );
        assert!(compact["raw_html"].is_null());

        for whitespace in ["\n", "\r\n"] {
            let body = format!(
                "{}<script>var s = {{token{whitespace}: \"x\"}};</script>",
                "<title>通知公告</title><section class=\"n_zhuanti\"><div id=\"tab_a2\"><ul class=\"list_box_03s\"><li><a class=\"a\" href=\"../info/1083/42.htm\">Fixture</a></li></ul></div></section>",
            );
            let output = super::html_fallback(
                &listing_response(&body),
                "announcements_list",
                "shenyuan",
                "shenyuan_listing_selector_contract",
            );
            assert!(output["raw_html"].is_null(), "{whitespace:?} gap must withhold");
        }
    }
}
