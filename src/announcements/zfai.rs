//! Official-directory-bound Sino-French Aviation college source observations.
use super::{
    ArticleDocument, ListQuery, ListingDocument, ListingEntry, MAX_ENTRIES, MAX_HREF, MAX_TEXT,
    advertised_page_url, article_body, article_output, bind_college_board,
    college_directory_attribution, college_html, describe_college_surface, element_text,
    entry_in_scope, failed_contract, invalid_article, invalid_list, is_http, parse_iso_date,
    is_safe_public_fallback_document, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, ZFAI_NOTICES_URL, ZFAI_ROOT_URL, zfai_path_allowed,
};
use scraper::{ElementRef, Html, Node, Selector};
use serde_json::{Value, json};
use url::Url;

const PUBLISHER: &str = "北京航空航天大学中法航空学院";

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
                } else if key_end == at
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
        && url.host_str() == Some("zfai.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && zfai_path_allowed(url.path())
}

fn source_date(monthday: &str, year: &str) -> Option<String> {
    let monthday: &[u8; 5] = monthday.trim().as_bytes().try_into().ok()?;
    let year: &[u8; 4] = year.trim().as_bytes().try_into().ok()?;
    let mut date = [0; 10];
    date[..4].copy_from_slice(year);
    date[4] = b'-';
    date[5..].copy_from_slice(monthday);
    parse_iso_date(std::str::from_utf8(&date).ok()?)
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let attribution =
        college_directory_attribution(&directory, "中法航空学院", ZFAI_ROOT_URL, ZFAI_ROOT_URL)?;
    Ok((ArchiveClient::open_zfai(source_mode)?, attribution))
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => ZFAI_ROOT_URL,
        "notices" => ZFAI_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_college_board(&client, ZFAI_ROOT_URL, ZFAI_NOTICES_URL, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client.with_cache_mode(mode).get_with_archive_status_and_persistence(
        &target,
        false,
        |_, _| false,
        |_, response| export_safe_body(&response.body),
        |response| {
            describe_college_surface(response, "zfai", attribution)
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
    let containers =
        Selector::parse("div.news div.fl1 > div.wp > ul.list11.flex").map_err(|_| unavailable())?;
    let mut containers = document.select(&containers);
    let primary = containers
        .next()
        .filter(|_| containers.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Zfai information listing requires one fl1/list11 view",
                file!(),
                line!(),
            )
        })?;
    let rows = Selector::parse(":scope > li").map_err(|_| unavailable())?;
    let anchors = Selector::parse(":scope > a.a").map_err(|_| unavailable())?;
    let headings = Selector::parse(":scope > div.rr > h4.h4s2").map_err(|_| unavailable())?;
    let summaries = Selector::parse(":scope > div.rr > p.ps3").map_err(|_| unavailable())?;
    let monthdays = Selector::parse(":scope > div.time > h3").map_err(|_| unavailable())?;
    let years = Selector::parse(":scope > div.time > h6").map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in primary.select(&rows) {
        if entries.len() == MAX_ENTRIES {
            return Err(unavailable());
        }
        let mut links = row.select(&anchors);
        let anchor = links
            .next()
            .filter(|_| links.next().is_none())
            .ok_or_else(|| {
                failed_contract(
                    "Zfai information row requires one direct a link",
                    file!(),
                    line!(),
                )
            })?;
        let mut row_headings = anchor.select(&headings);
        let title = row_headings
            .next()
            .filter(|_| row_headings.next().is_none())
            .map(element_text)
            .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
            .ok_or_else(|| {
                failed_contract(
                    "Zfai information row requires one rr/h4s2 heading",
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
        let mut row_summaries = anchor.select(&summaries);
        let summary = row_summaries
            .next()
            .map(element_text)
            .filter(|text| !text.is_empty());
        if row_summaries.next().is_some()
            || summary.as_ref().is_some_and(|text| text.len() > MAX_TEXT)
        {
            return Err(unavailable());
        }
        let mut row_monthdays = anchor.select(&monthdays);
        let monthday = row_monthdays
            .next()
            .filter(|_| row_monthdays.next().is_none());
        let mut row_years = anchor.select(&years);
        let year = row_years.next().filter(|_| row_years.next().is_none());
        let date = monthday
            .zip(year)
            .and_then(|(monthday, year)| source_date(&element_text(monthday), &element_text(year)));
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
            category_label: Some("信息公告".into()),
            summary,
            listed_href: listed_href.map(str::to_owned),
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "Zfai information listing has no source rows",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(ZFAI_NOTICES_URL).map_err(|_| unavailable())?;
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
                "div.pagebar span.p_no a[href]",
                |url| plain_url(url) && url.path().starts_with("/xxgg1/"),
            )
        },
    )
}

pub(super) fn list(mode: CacheMode, query: &ListQuery) -> Result<Value, Error> {
    if query
        .category
        .as_deref()
        .is_some_and(|category| category != "xxgg1")
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
    bind_college_board(&client, ZFAI_ROOT_URL, ZFAI_NOTICES_URL, &mut attribution)?;
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
                        "zfai",
                        "zfai_listing_selector_contract",
                    );
                    value["category"] = json!("xxgg1");
                    value["page"] = json!(page);
                    return Ok(value);
                }
                Err(error) => return Err(error),
            };
            super::refuse_unsafe_listing(response, &html)?;
            let entries: Vec<&ListingEntry> = document.entries.iter()
                .filter(|entry| entry_in_scope(entry, &since, &until, &query.r#match)).collect();
            Ok(json!({"schema_version":1,"type":"announcements_list","result":"listing_snapshot",
                "publisher":PUBLISHER,"college":"zfai","category":"xxgg1","listing_label":"信息公告","page":page,
                "document_title":document.title,"filters":{"since":since,"until":until,"match":query.r#match},
                "entries":entries,"entry_count":entries.len(),"directory_attribution":attribution,
                "completeness":{"scope":"single_college_selected_page","pagination":"source_advertised_ordinal_only; no automatic traversal","other_colleges":"not_covered","dates":"source MM-DD and YYYY; missing or invalid stays null","summaries":"source rr/p.ps3 excerpt; not original full text"},
                "retrieval":retrieval(response)}))
        },
    )
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || !target.path().starts_with("/info/1196/")
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
    bind_college_board(&client, ZFAI_ROOT_URL, ZFAI_NOTICES_URL, &mut attribution)?;
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
                        "zfai",
                        "zfai_listing_selector_contract",
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
                    "retained information board does not declare the selected Zfai article",
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
                "retained Zfai information page could not be parsed and its credential-bearing bytes were withheld without retention"
            } else {
                "retained Zfai information page could not be parsed; the admitted board snapshot was retained for offline repair"
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
                    "zfai",
                    "zfai_article_selector_contract",
                ),
                Err(error) => return Err(error),
            };
            output["publisher"] = json!(PUBLISHER);
            output["college"] = json!("zfai");
            output["directory_attribution"] = attribution;
            output["source_listing"] = listing;
            Ok(output)
        },
    )
}

fn normalize(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    let forms = Selector::parse("div.detail div.fl1 > div.wp.flex > div.left > form")
        .map_err(|_| unavailable())?;
    let mut forms = document.select(&forms);
    let main = forms
        .next()
        .filter(|_| forms.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Zfai article requires one direct detail/left source form",
                file!(),
                line!(),
            )
        })?;
    let headers = Selector::parse(":scope > div.ar_tit").map_err(|_| unavailable())?;
    let mut headers = main.select(&headers);
    let header = headers
        .next()
        .filter(|_| headers.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Zfai article requires one direct ar_tit header",
                file!(),
                line!(),
            )
        })?;
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
                "Zfai article requires one nonempty direct ar_tit/h3 heading",
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
            .filter(|node| node.value().name() == "span")
            .nth(1)
            .and_then(|node| {
                element_text(node)
                    .strip_prefix("时间：")
                    .and_then(|raw| parse_iso_date(raw.trim()))
            })
    });
    if dates.next().is_some() {
        return Err(unavailable());
    }
    let bodies =
        Selector::parse(":scope > div.ar_article > div#vsb_content_1001 > div.v_news_content")
            .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Zfai article requires one direct vsb_content_1001/v_news_content body",
                file!(),
                line!(),
            )
        })?;
    let (paragraphs, attachment_hints, attachments_found) = article_body(body, false)?;
    Ok(article_output(
        response,
        ArticleDocument {
            title,
            category: Some("1196".into()),
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
    use crate::net::{CacheStatus, Response};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(body: &str) -> Response {
        Response {
            url: "https://zfai.buaa.edu.cn/info/1196/42.htm".into(),
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

    fn article_html(header: &str, body: &str) -> String {
        format!(
            r#"<h3>Sidebar heading</h3><div class="detail"><div class="fl1"><div class="wp flex"><div class="left"><form><div class="ar_tit"><h3>Original source heading</h3>{header}</div><div class="ar_article"><div id="vsb_content_1001"><div class="v_news_content">{body}</div></div></div></form></div></div></div></div>"#
        )
    }

    #[test]
    fn ambiguous_date_slots_stay_unknown_and_cannot_satisfy_date_filters() {
        let html = r#"<div class="news"><div class="fl1"><div class="wp"><ul class="list11 flex">
<li><a class="a" href="info/1196/42.htm"><div class="time"><h3>09-14</h3><h3>09-15</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Ambiguous monthday</h4></div></a></li>
<li><a class="a" href="info/1196/43.htm"><div class="time"><h3>09-14</h3><h6>2026</h6><h6>2025</h6></div><div class="rr"><h4 class="h4s2">Ambiguous year</h4></div></a></li>
<li><a class="a" href="info/1196/44.htm"><div class="time"><h3>09-14</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Unambiguous source date</h4></div></a></li>
</ul></div></div></div>"#;
        let parsed = parse_listing(
            &Html::parse_document(html),
            &Url::parse(ZFAI_NOTICES_URL).unwrap(),
        )
        .unwrap();
        assert_eq!(
            parsed
                .entries
                .iter()
                .map(|entry| entry.date.as_deref())
                .collect::<Vec<_>>(),
            vec![None, None, Some("2026-09-14")]
        );
        let since = Some("2026-09-14".into());
        let until = Some("2026-09-14".into());
        let filtered: Vec<_> = parsed
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &None))
            .map(|entry| entry.title.as_str())
            .collect();
        assert_eq!(filtered, vec!["Unambiguous source date"]);
    }

    #[test]
    fn listing_preserves_source_titles_excerpts_order_and_unknown_dates() {
        let html = r#"<title>Information fixture</title><div class="news"><div class="fl1"><div class="wp"><ul class="list11 flex">
<li><a class="a" href="info/1196/42.htm"><div class="time"><h3>06-05</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Earlier source heading</h4><p class="ps3">Distinct excerpt only</p></div></a></li>
<li><a class="a" href="info/1196/43.htm"><div class="time"><h3>09-14</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Later source heading</h4><p class="ps3">Second source excerpt</p></div></a></li>
<li><a class="a" href="info/1196/44.htm"><div class="time"><h3>02-29</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Unknown date heading</h4></div></a></li>
</ul></div></div></div><ul><li><a href="info/1196/99.htm">Unrelated sidebar row</a></li></ul>"#;
        let parsed = parse_listing(
            &Html::parse_document(html),
            &Url::parse(ZFAI_NOTICES_URL).unwrap(),
        )
        .unwrap();
        let rows: Vec<_> = parsed
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.title.as_str(),
                    entry.date.as_deref(),
                    entry.summary.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                (
                    "Earlier source heading",
                    Some("2026-06-05"),
                    Some("Distinct excerpt only")
                ),
                (
                    "Later source heading",
                    Some("2026-09-14"),
                    Some("Second source excerpt")
                ),
                ("Unknown date heading", None, None),
            ]
        );
        let since = Some("2026-09-14".into());
        let until = Some("2026-09-14".into());
        let filtered: Vec<_> = parsed
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &until, &None))
            .map(|entry| entry.title.as_str())
            .collect();
        assert_eq!(filtered, vec!["Later source heading"]);
        assert!(!parsed.entries.iter().any(|entry| entry_in_scope(
            entry,
            &None,
            &None,
            &Some("excerpt only".into())
        )));
    }

    #[test]
    fn pagebar_selects_active_ordinals_without_legacy_container_or_filename_inference() {
        let base = Url::parse(ZFAI_NOTICES_URL).unwrap();
        let source = br#"<div class="pb_sys_common"><span class="p_no"><a href="xxgg1/99.htm">2</a></span></div><template><div class="pagebar"><span class="p_no"><a href="xxgg1/98.htm">2</a></span></div></template><div class="pagebar"><span class="p_no"><a href="xxgg1/8.htm">2</a></span><span class="p_no"><a href="xxgg1/1.htm">3</a></span></div>"#;
        let selected =
            advertised_page_url(source, &base, 2, "div.pagebar span.p_no a[href]", plain_url)
                .unwrap();
        assert_eq!(selected.path(), "/xxgg1/8.htm");
        assert_eq!(
            advertised_page_url(source, &base, 3, "div.pagebar span.p_no a[href]", plain_url)
                .unwrap()
                .path(),
            "/xxgg1/1.htm"
        );
        assert_eq!(
            advertised_page_url(source, &base, 8, "div.pagebar span.p_no a[href]", plain_url)
                .unwrap_err()
                .code,
            "unavailable"
        );
        let foreign = br#"<div class="pagebar"><span class="p_no"><a href="https://foreign.example/xxgg1/8.htm">2</a></span></div>"#;
        assert_eq!(
            advertised_page_url(
                foreign,
                &base,
                2,
                "div.pagebar span.p_no a[href]",
                plain_url
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
    }

    #[test]
    fn article_owns_original_header_table_order_and_second_publication_slot() {
        let body = "<p>Body date 2030-01-01</p><table><tr><td><p>First source cell</p></td><td><p>Second source cell</p></td></tr></table>";
        let source = response(&article_html(
            "<h6><span>时间：2020-01-01<script>counter()</script></span><span>时间：2026-09-14</span><span>时间：2040-01-01</span></h6>",
            body,
        ));
        let parsed = normalize(&source, &college_html(&source).unwrap()).unwrap();
        assert_eq!(parsed["title"], "Original source heading");
        assert_eq!(parsed["published_at"], "2026-09-14");
        assert_eq!(
            parsed["body_paragraphs"],
            json!([
                "Body date 2030-01-01",
                "First source cell",
                "Second source cell"
            ])
        );
        let missing = response(&article_html(
            "<h6><span>时间：2020-01-01</span><span>Invalid publication slot</span><span>时间：2040-01-01</span></h6>",
            body,
        ));
        assert!(
            normalize(&missing, &college_html(&missing).unwrap()).unwrap()["published_at"]
                .is_null()
        );
    }

    #[test]
    fn article_refuses_ambiguous_source_headings_and_bodies() {
        let source = article_html(
            "<h6><span>Count</span><span>时间：2026-09-14</span></h6>",
            "<p>Source policy.</p>",
        );
        let ambiguous_heading = response(&source.replace(
            "<h3>Original source heading</h3>",
            "<h3>Original source heading</h3><h3>Other source heading</h3>",
        ));
        assert_eq!(
            normalize(
                &ambiguous_heading,
                &college_html(&ambiguous_heading).unwrap()
            )
            .unwrap_err()
            .code,
            "unavailable"
        );
        let ambiguous_body = response(&source.replace("<div class=\"v_news_content\"><p>Source policy.</p></div>", "<div class=\"v_news_content\"><p>Source policy.</p></div><div class=\"v_news_content\"><p>Other policy.</p></div>"));
        assert_eq!(
            normalize(&ambiguous_body, &college_html(&ambiguous_body).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    fn listing_response(body: &str) -> Response {
        Response {
            url: ZFAI_NOTICES_URL.into(),
            status: 200,
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            body: body.as_bytes().to_vec(),
            sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            fetched_at_unix_ms: 7,
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
        const DRIFTED: &str = r#"<title>信息公告</title><div class="news"><div class="fl1"><div class="wp"><ul class="list12 flex"><li><a class="a" href="info/1196/42.htm"><div class="time"><h3>09-14</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Fixture notice</h4></div></a></li></ul></div></div></div>"#;
        let source = listing_response(DRIFTED);
        let document = college_html(&source).unwrap();
        assert!(parse_listing(&document, &Url::parse(ZFAI_NOTICES_URL).unwrap()).is_err());
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_list",
            "zfai",
            "zfai_listing_selector_contract",
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
            "zfai",
            "zfai_listing_selector_contract",
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
        const PAGE: &str = r#"<title>信息公告</title><div class="news"><div class="fl1"><div class="wp"><ul class="list11 flex"><li><a class="a" href="info/1196/42.htm"><div class="time"><h3>09-14</h3><h6>2026</h6></div><div class="rr"><h4 class="h4s2">Latest notice</h4></div></a></li></ul></div></div></div><div class="pagebar"><span class="p_no"><a href="xxgg1/7.htm">3</a><a href="xxgg1/9.htm">4</a></span></div>"#;
        let source = listing_response(PAGE);
        let base = Url::parse(ZFAI_NOTICES_URL).unwrap();
        let document = college_html(&source).unwrap();
        assert_eq!(parse_listing(&document, &base).unwrap().entries.len(), 1);
        assert!(
            advertised_page_url(&source.body, &base, 2, "div.pagebar span.p_no a[href]", |url| {
                plain_url(url) && url.path().starts_with("/xxgg1/")
            })
            .is_err()
        );
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_list",
            "zfai",
            "zfai_listing_selector_contract",
        );
        assert_eq!(
            STANDARD
                .decode(evidence["raw_html"].as_str().unwrap())
                .unwrap()
                .as_slice(),
            PAGE.as_bytes()
        );
        // An ordinal whose advertised target leaves the board stays refused.
        const FOREIGN: &str = r#"<div class="pagebar"><span class="p_no"><a href="../info/1196/9.htm">2</a></span></div>"#;
        assert!(
            advertised_page_url(FOREIGN.as_bytes(), &base, 2, "div.pagebar span.p_no a[href]", |url| {
                plain_url(url) && url.path().starts_with("/xxgg1/")
            })
            .is_err()
        );
    }

    /// Credential material must never leave the adapter: inert script bytes
    /// carrying credential markers withhold the entire body from degraded
    /// evidence, and an active credential control refuses the page outright.
    #[test]
    fn drifted_listing_credential_material_is_refused_or_withheld() {
        const MARKED: &str = r#"<title>信息公告</title><script>window.session = {"csrf_token":"synthetic-fixture","id_token":"synthetic-fixture"};</script><div class="news"><div class="fl1"><div class="wp"><ul class="list12"><li><a class="a" href="info/1196/42.htm">Fixture</a></li></ul></div></div></div>"#;
        let source = listing_response(MARKED);
        let document = college_html(&source).unwrap();
        assert!(parse_listing(&document, &Url::parse(ZFAI_NOTICES_URL).unwrap()).is_err());
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_list",
            "zfai",
            "zfai_listing_selector_contract",
        );
        assert!(evidence["raw_html"].is_null());
        assert!(
            !evidence
                .to_string()
                .contains(&*STANDARD.encode(MARKED.as_bytes())),
            "withheld source bytes must not appear anywhere in the emitted record"
        );
        const REFUSED: &str = r#"<title>信息公告</title><a href="/login?ticket=synthetic-fixture">Sign in</a><ul class="list12"><li>row</li></ul>"#;
        let refused = listing_response(REFUSED);
        let refused_document = college_html(&refused).unwrap();
        assert!(!super::super::is_safe_public_fallback(&refused));
        assert!(super::super::refuse_unsafe_listing(&refused, &refused_document).is_err());
        assert!(
            super::html_fallback(
                &refused,
                "announcements_list",
                "zfai",
                "zfai_listing_selector_contract"
            )["raw_html"]
                .is_null()
        );
    }

    /// The same drift contract applies to article pages: a safe admitted 200
    /// text/html article whose selectors changed preserves its exact bytes as
    /// degraded evidence instead of surfacing an outer error.
    #[test]
    fn drifted_safe_article_keeps_exact_bytes_as_degraded_evidence() {
        let body = article_html(
            "<h6><span>时间：2026-09-14</span></h6>",
            "<p>Source paragraph.</p>",
        )
        .replace("vsb_content_1001", "vsb_content_2002");
        let source = response(&body);
        let document = college_html(&source).unwrap();
        assert!(normalize(&source, &document).is_err());
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_article",
            "zfai",
            "zfai_article_selector_contract",
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
        const PROSE: &str = r#"<title>信息公告</title><div class="news"><ul class="list12"><li><a class="a" href="info/1196/42.htm">Fixture</a></li></ul></div><p>第三期 session 将于 19:00 开始</p>"#;
        let evidence = super::html_fallback(
            &listing_response(PROSE),
            "announcements_list",
            "zfai",
            "zfai_listing_selector_contract",
        );
        assert_eq!(
            STANDARD
                .decode(evidence["raw_html"].as_str().unwrap())
                .unwrap()
                .as_slice(),
            PROSE.as_bytes()
        );

        const FIELD: &str = r#"<title>信息公告</title><div class="news"><ul class="list12"><li><a class="a" href="info/1196/42.htm">Fixture</a></li></ul></div><script>var s = {token: "synthetic-fixture"};</script>"#;
        let evidence = super::html_fallback(
            &listing_response(FIELD),
            "announcements_list",
            "zfai",
            "zfai_listing_selector_contract",
        );
        assert!(evidence["raw_html"].is_null());
    }
}
