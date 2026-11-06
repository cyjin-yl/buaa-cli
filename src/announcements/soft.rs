//! Software college notices: a directory-bound two-hop source contract.
//!
//! The official homepage declares the `/xwdt/gggs.htm` announcement section;
//! that section in turn declares the selected `/xwdt/gggs/tzgg.htm` notice
//! board.  Both declarations are retained before listing or article reads.
//! The CMS uses the shared `nymain/notice-list` listing layout and the
//! `art-main`/`v_news_content` article layout used by the other reviewed
//! college adapters.
use super::{
    ArticleDocument, ListQuery, MAX_TEXT, advertised_page_url, article_category_from_url,
    article_output, article_paragraphs, bind_college_board, college_directory_attribution,
    college_html, declared_jsp_attachment_hints, describe_college_surface, element_text,
    entry_in_scope, failed_contract, inert_element, invalid_article, invalid_list,
    is_safe_public_fallback_document, parse_chinese_publication_date, parse_iso_date,
    parse_notice_list, retrieval, unavailable,
};
use crate::net::{
    ArchiveClient, CacheMode, Error, SOFT_NOTICES_URL, SOFT_ROOT_URL, soft_path_allowed,
};
use scraper::{Html, Node, Selector};
use serde_json::{Value, json};
use url::Url;

const LISTED_ROOT_URL: &str = "http://soft.buaa.edu.cn/";
const SECTION_URL: &str = "https://soft.buaa.edu.cn/xwdt/gggs.htm";
const PUBLISHER: &str = "北京航空航天大学软件学院";

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
                    .all(|b| matches!(b, b' ' | b'\t'))
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
        && url.host_str() == Some("soft.buaa.edu.cn")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && soft_path_allowed(url.path())
}

fn bound_client(mode: CacheMode) -> Result<(ArchiveClient, Value), Error> {
    let source_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let directory = crate::organizations::list(source_mode)?;
    let mut attribution =
        college_directory_attribution(&directory, "软件学院", LISTED_ROOT_URL, LISTED_ROOT_URL)?;
    attribution["selected_https_root"] = SOFT_ROOT_URL.into();
    attribution["selection_relation"] = "deliberate separate HTTPS observation; the exact listed HTTP identity and original directory provenance are preserved, not upgraded or aliased".into();
    Ok((ArchiveClient::open_soft(source_mode)?, attribution))
}

/// Bind the homepage declaration and then the section's selected notice-board
/// declaration. Keep both retrieval records instead of letting the shared
/// one-hop helper overwrite the first record.
fn bind_source(client: &ArchiveClient, attribution: &mut Value) -> Result<(), Error> {
    bind_college_board(client, SOFT_ROOT_URL, SECTION_URL, attribution)?;
    let root_retrieval = attribution["root_retrieval"].clone();
    bind_college_board(client, SECTION_URL, SOFT_NOTICES_URL, attribution)?;
    let section_retrieval = attribution["root_retrieval"].clone();
    attribution["root_retrieval"] = root_retrieval;
    attribution["section_retrieval"] = section_retrieval;
    Ok(())
}

pub(super) fn surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => SOFT_ROOT_URL,
        "notices" => SOFT_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let (client, mut attribution) = bound_client(mode)?;
    if page == "notices" {
        bind_source(&client, &mut attribution)?;
    }
    let target = Url::parse(raw).map_err(|_| unavailable())?;
    client.with_cache_mode(mode).get_with_archive_status_and_persistence(
        &target,
        false,
        |_, _| false,
        |_, response| export_safe_body(&response.body),
        |response| {
            describe_college_surface(response, "soft", attribution)
        },
    )
}

fn listing_url(client: &ArchiveClient, page: u32) -> Result<Url, Error> {
    let latest = Url::parse(SOFT_NOTICES_URL).map_err(|_| unavailable())?;
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
                "div.nymain div.ny-right div.notice-list > div > div.pagestyle span.p_no a[href]",
                |url| plain_url(url) && url.path().starts_with("/xwdt/gggs/tzgg/"),
            )
        },
    )
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
    bind_source(&client, &mut attribution)?;
    let target = listing_url(&client, page)?;
    client.with_cache_mode(mode).get_with_archive_status_and_persistence(
        &target,
        false,
        |_, _| false,
        |_, response| export_safe_body(&response.body),
        |response| {
            let html = college_html(response)?;
            let document = match parse_notice_list(&html, &target) {
                Ok(document) => document,
                Err(_) if is_safe_public_fallback_document(response, &html) => {
                    let mut value = html_fallback(
                        response,
                        "announcements_list",
                        "soft",
                        "soft_listing_selector_contract",
                    );
                    value["category"] = json!("tzgg");
                    value["page"] = json!(page);
                    return Ok(value);
                }
                Err(error) => return Err(error),
            };
            super::refuse_unsafe_listing(response, &html)?;
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
                "college":"soft",
                "category":"tzgg",
                "listing_label":"通知公告",
                "page":page,
                "document_title":document.title,
                "filters":{"since":since,"until":until,"match":query.r#match},
                "entries":entries,
                "entry_count":entries.len(),
                "directory_attribution":attribution,
                "completeness":{
                    "scope":"single_college_selected_page",
                    "pagination":"source_advertised_ordinal_only; no automatic traversal",
                    "other_colleges":"not_covered",
                    "dates":"source YYYY.MM.DD; missing, invalid or ambiguous stays null",
                    "summaries":"source direct a/p excerpt; not original full text"
                },
                "retrieval":retrieval(response)
            }))
        },
    )
}

pub(super) fn article(mode: CacheMode, raw: &str, source_page: u32) -> Result<Value, Error> {
    let target = Url::parse(raw).map_err(|_| invalid_article())?;
    if raw != target.as_str()
        || !plain_url(&target)
        || source_page == 0
        || !target.path().starts_with("/info/1095/")
    {
        return Err(invalid_article());
    }
    let (client, mut attribution) = bound_client(mode)?;
    bind_source(&client, &mut attribution)?;
    let source = listing_url(&client, source_page)?;
    let listing_result: Result<Value, Error> = client.get_with_archive_status_and_persistence(
        &source,
        false,
        |_, _| false,
        |_, response| export_safe_body(&response.body),
        |response| {
            let html = college_html(response)?;
            let document = match parse_notice_list(&html, &source) {
                Ok(document) => document,
                Err(_) if is_safe_public_fallback_document(response, &html) => {
                    return Ok(Ok(html_fallback(
                        response,
                        "announcements_list",
                        "soft",
                        "soft_listing_selector_contract",
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
                    "retained notice page does not declare the selected Soft article",
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
                "retained Soft notice page could not be parsed and its credential-bearing bytes were withheld without retention"
            } else {
                "retained Soft notice page could not be parsed; the admitted board snapshot was retained for offline repair"
            },
        ));
    }
    client.with_cache_mode(mode).get_with_archive_status_and_persistence(
        &target,
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
                    "soft",
                    "soft_article_selector_contract",
                ),
                Err(error) => return Err(error),
            };
            output["publisher"] = json!(PUBLISHER);
            output["college"] = json!("soft");
            output["directory_attribution"] = attribution;
            output["source_listing"] = listing;
            Ok(output)
        },
    )
}

fn normalize(response: &crate::net::Response, document: &Html) -> Result<Value, Error> {
    let mains = Selector::parse("div.nymain > div.w16 > div.ny-right > form > div.art-main")
        .map_err(|_| unavailable())?;
    let mut mains = document.select(&mains).filter(|node| !inert_element(*node));
    let main = mains
        .next()
        .filter(|_| mains.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Soft article requires one direct nymain/art-main container",
                file!(),
                line!(),
            )
        })?;
    let headings = Selector::parse(":scope > div.art-tit > h3").map_err(|_| unavailable())?;
    let mut headings = main.select(&headings);
    let title = headings
        .next()
        .filter(|_| headings.next().is_none())
        .map(element_text)
        .filter(|title| !title.is_empty() && title.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract(
                "Soft article requires one direct art-tit/h3 heading",
                file!(),
                line!(),
            )
        })?;
    let dates =
        Selector::parse(":scope > div.art-tit > p > span.date").map_err(|_| unavailable())?;
    let mut dates = main.select(&dates);
    let published_at = dates
        .next()
        .filter(|_| dates.next().is_none())
        .and_then(|node| parse_chinese_publication_date(&element_text(node)));
    let bodies = Selector::parse(
        ":scope > div.art-body-box > div.art-body > div#vsb_content > div.v_news_content",
    )
    .map_err(|_| unavailable())?;
    let mut bodies = main.select(&bodies);
    let body = bodies
        .next()
        .filter(|_| bodies.next().is_none())
        .ok_or_else(|| {
            failed_contract(
                "Soft article requires one scoped vsb_content/v_news_content body",
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
        "unique art-main/art-body-box/art-body/#vsb_content/v_news_content paragraphs; executable and fallback text excluded"
    );
    output["completeness"]["attachment_source"] =
        json!("active source-declared JSP file links within art-main; hints only, never fetched");
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
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use crate::net::{CacheStatus, Response};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn source(header: &str, body: &str, siblings: &str) -> Response {
        let html = format!(
            "<h3>Unrelated heading</h3><a href=\"/system/_content/download.jsp?wbfileid=outside\">Outside.pdf</a><div class=\"nymain\"><div class=\"w16\"><div class=\"ny-right\"><form><div class=\"art-main\"><div class=\"art-tit cont-tit d\">{header}</div><div class=\"art-body-box\"><div class=\"art-body d\"><div id=\"vsb_content\"><div class=\"v_news_content\">{body}</div></div></div></div>{siblings}</div></form></div></div></div>"
        );
        Response {
            url: "https://soft.buaa.edu.cn/info/1095/42.htm".into(),
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
    fn soft_original_body_and_attachment_boundaries_stay_explicit() {
        let response = source(
            "<h3>Original heading</h3><p><span class=\"date\">日期：2026年10月14日</span></p>",
            "<p>First <em>inline</em> body.<script>not prose</script></p><img src=\"poster.png\"><table><tr><td>unextracted table</td></tr></table>",
            "<p><ul><li><a href=\"/system/_content/download.jsp?wbfileid=form&amp;owner=1\">Form.zip</a></li></ul></p><template><a href=\"/system/_content/download.jsp?wbfileid=inactive\">Inactive.pdf</a></template>",
        );
        let output = normalize(&response, &college_html(&response).unwrap()).unwrap();
        assert_eq!(output["title"], "Original heading");
        assert_eq!(output["published_at"], "2026-10-14");
        assert_eq!(output["body_paragraphs"], json!(["First inline body."]));
        assert_eq!(output["result"], "partial_text");
        assert_eq!(
            output["attachments"]["hints"],
            json!([{"href":"/system/_content/download.jsp?wbfileid=form&owner=1","text":"Form.zip","fetched":false}])
        );
        assert_eq!(output["completeness"]["unextracted_table_count"], 1);
    }

    #[test]
    fn soft_article_rejects_ambiguous_header_and_body() {
        let ambiguous_header = source(
            "<h3>Original heading</h3><p><span class=\"date\">日期：2026年10月14日</span><span class=\"date\">日期：2026年10月15日</span></p>",
            "<p>Body.</p>",
            "",
        );
        let output =
            normalize(&ambiguous_header, &college_html(&ambiguous_header).unwrap()).unwrap();
        assert_eq!(output["published_at"], Value::Null);

        let ambiguous_body = source(
            "<h3>Original heading</h3>",
            "<p>Body.</p>",
            "<div class=\"art-body-box\"><div class=\"art-body\"><div id=\"vsb_content\"><div class=\"v_news_content\"><p>Second body.</p></div></div></div></div>",
        );
        assert_eq!(
            normalize(&ambiguous_body, &college_html(&ambiguous_body).unwrap())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn soft_paths_allow_only_reviewed_board_and_article_routes() {
        for path in [
            "/",
            "/robots.txt",
            "/xwdt/gggs.htm",
            "/xwdt/gggs/tzgg.htm",
            "/xwdt/gggs/tzgg/1.htm",
            "/info/1095/2385.htm",
        ] {
            assert!(soft_path_allowed(path), "{path}");
        }
        for path in [
            "/xwdt/gggs/cgzq.htm",
            "/xwdt/gggs/tzgg/1.pdf",
            "/info/1094/2385.htm",
            "/info/1095/not-a-number.htm",
            "/system/resource/js/counter.js",
        ] {
            assert!(!soft_path_allowed(path), "{path}");
        }
    }

    fn page_response(url: &str, body: &str) -> Response {
        Response {
            url: url.into(),
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

    fn listing_response(body: &str) -> Response {
        page_response(SOFT_NOTICES_URL, body)
    }

    /// A safe admitted 200 text/html listing whose selectors no longer match is
    /// degraded evidence, not an outer error: the exact original bytes and hash
    /// are preserved and a later cache-only read replays the same record.
    #[test]
    fn drifted_safe_listing_keeps_exact_bytes_as_replayable_degraded_evidence() {
        const DRIFTED: &str = r#"<title>通知公告</title><div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-board"><div><ul><li><a href="../../info/1095/42.htm"><span>2026.10.14</span><h3>Fixture notice</h3></a></li></ul></div></div></div></div></div>"#;
        let source = listing_response(DRIFTED);
        let document = college_html(&source).unwrap();
        let base = Url::parse(SOFT_NOTICES_URL).unwrap();
        assert!(parse_notice_list(&document, &base).is_err());
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_list",
            "soft",
            "soft_listing_selector_contract",
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
            "soft",
            "soft_listing_selector_contract",
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
        const PAGE: &str = r#"<title>通知公告</title><div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-list"><div><ul><li><a href="../../info/1095/42.htm"><span>2026.10.14</span><h3>Latest notice</h3></a></li></ul><div class="pagestyle"><span class="p_no"><a href="/xwdt/gggs/tzgg/7.htm">3</a><a href="/xwdt/gggs/tzgg/9.htm">4</a></span></div></div></div></div></div></div>"#;
        let source = listing_response(PAGE);
        let base = Url::parse(SOFT_NOTICES_URL).unwrap();
        let document = college_html(&source).unwrap();
        assert_eq!(parse_notice_list(&document, &base).unwrap().entries.len(), 1);
        assert!(
            advertised_page_url(
                &source.body,
                &base,
                2,
                "div.nymain div.ny-right div.notice-list > div > div.pagestyle span.p_no a[href]",
                |url| plain_url(url) && url.path().starts_with("/xwdt/gggs/tzgg/")
            )
            .is_err()
        );
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_list",
            "soft",
            "soft_listing_selector_contract",
        );
        assert_eq!(
            STANDARD
                .decode(evidence["raw_html"].as_str().unwrap())
                .unwrap()
                .as_slice(),
            PAGE.as_bytes()
        );
        // An ordinal whose advertised target leaves the board stays refused.
        const FOREIGN: &str = r#"<div class="nymain"><div class="ny-right"><div class="notice-list"><div><div class="pagestyle"><span class="p_no"><a href="/xwdt/gggs/cgzq/1.htm">2</a></span></div></div></div></div></div>"#;
        assert!(
            advertised_page_url(
                FOREIGN.as_bytes(),
                &base,
                2,
                "div.nymain div.ny-right div.notice-list > div > div.pagestyle span.p_no a[href]",
                |url| plain_url(url) && url.path().starts_with("/xwdt/gggs/tzgg/")
            )
            .is_err()
        );
    }

    /// Credential material must never leave the adapter: inert script bytes
    /// carrying credential markers withhold the entire body from degraded
    /// evidence, and an active credential control refuses the page outright.
    #[test]
    fn drifted_listing_credential_material_is_refused_or_withheld() {
        const MARKED: &str = r#"<title>通知公告</title><script>window.session = {"csrf_token":"synthetic-fixture","id_token":"synthetic-fixture"};</script><div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-board"><div><ul><li><a href="../../info/1095/42.htm">Fixture</a></li></ul></div></div></div></div></div>"#;
        let source = listing_response(MARKED);
        let base = Url::parse(SOFT_NOTICES_URL).unwrap();
        let document = college_html(&source).unwrap();
        assert!(parse_notice_list(&document, &base).is_err());
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_list",
            "soft",
            "soft_listing_selector_contract",
        );
        assert!(evidence["raw_html"].is_null());
        assert!(
            !evidence
                .to_string()
                .contains(&*STANDARD.encode(MARKED.as_bytes())),
            "withheld source bytes must not appear anywhere in the emitted record"
        );
        const REFUSED: &str = r#"<title>通知公告</title><a href="/login?ticket=synthetic-fixture">Sign in</a><ul><li>row</li></ul>"#;
        let refused = listing_response(REFUSED);
        let refused_document = college_html(&refused).unwrap();
        assert!(!super::super::is_safe_public_fallback(&refused));
        assert!(super::super::refuse_unsafe_listing(&refused, &refused_document).is_err());
        assert!(
            super::html_fallback(
                &refused,
                "announcements_list",
                "soft",
                "soft_listing_selector_contract"
            )["raw_html"]
                .is_null()
        );
    }

    /// The same drift contract applies to article pages: a safe admitted 200
    /// text/html article whose selectors changed preserves its exact bytes as
    /// degraded evidence instead of surfacing an outer error.
    #[test]
    fn drifted_safe_article_keeps_exact_bytes_as_degraded_evidence() {
        let body = r#"<div class="nymain"><div class="w16"><div class="ny-right"><form><div class="art-panel"><div class="art-tit"><h3>Fixture heading</h3></div><div class="art-body-box"><div class="art-body"><div id="vsb_content"><div class="v_news_content"><p>Source paragraph.</p></div></div></div></div></form></div></div></div>"#;
        let source = page_response("https://soft.buaa.edu.cn/info/1095/42.htm", body);
        let document = college_html(&source).unwrap();
        assert!(normalize(&source, &document).is_err());
        assert!(super::super::is_safe_public_fallback(&source));
        let evidence = super::html_fallback(
            &source,
            "announcements_article",
            "soft",
            "soft_article_selector_contract",
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
        const PROSE: &str = r#"<title>通知公告</title><div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-board"><div><ul><li><a href="../../info/1095/42.htm">Fixture</a></li></ul></div></div></div></div></div><p>第三期 session 将于 19:00 开始</p>"#;
        let evidence = super::html_fallback(
            &listing_response(PROSE),
            "announcements_list",
            "soft",
            "soft_listing_selector_contract",
        );
        assert_eq!(
            STANDARD
                .decode(evidence["raw_html"].as_str().unwrap())
                .unwrap()
                .as_slice(),
            PROSE.as_bytes()
        );

        const FIELD: &str = r#"<title>通知公告</title><div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-board"><div><ul><li><a href="../../info/1095/42.htm">Fixture</a></li></ul></div></div></div></div></div><script>var s = {token : "synthetic-fixture"};</script>"#;
        let evidence = super::html_fallback(
            &listing_response(FIELD),
            "announcements_list",
            "soft",
            "soft_listing_selector_contract",
        );
        assert!(evidence["raw_html"].is_null());


        const COMPACT: &str = r#"<title>通知公告</title><div class="nymain"><div class="w16"><div class="ny-right"><div class="notice-board"><div><ul><li><a href="../../info/1095/42.htm">Fixture</a></li></ul></div></div></div></div></div><script>var s = {token:"x"};</script>"#;
        let compact = super::html_fallback(
            &listing_response(COMPACT),
            "announcements_list",
            "soft",
            "soft_listing_selector_contract",
        );
        assert!(compact["raw_html"].is_null());
    }
}
