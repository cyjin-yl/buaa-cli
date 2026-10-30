//! Bounded authenticated read-only GitHub issue discovery. No lifecycle writes.
use chrono::DateTime;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::governor::{Governor, Outcome};

const MAX_INPUT: usize = 16 * 1024;
const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_LIST_PAGES: usize = 10;
const MAX_LIST_ITEMS: usize = 1_000;
const MAX_TIMELINE_PAGES: usize = 5;
const MAX_TIMELINE_ITEMS: usize = 500;
const MAX_PR_CANDIDATES: usize = 20;
const MAX_COMMENT_PAGES: usize = 10;
const MAX_COMMENT_ITEMS: usize = 1_000;
const MAX_TITLE_BYTES: usize = 4 * 1024;
/// One total deadline per original request, covering connect, headers and the
/// complete body read. The client builder timeout alone restarts per blocking
/// body read, so slow streams could otherwise hold a shared lease indefinitely.
const REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
const CLAIM_WINDOW_SECONDS: i64 = 72 * 60 * 60;
const API_ROOT: &str = "https://api.github.com/repos";
const API_PREFIX: &str = "https://api.github.com/";
const WEB_ROOT: &str = "https://github.com";


/// A request must be a JSON object: serde can otherwise accept positional
/// arrays for structs, which the schema never declared. The token is only
/// ever materialized as a zeroizing secret, never an ordinary Value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanRequest {
    repository: String,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    github_token: Option<GithubToken>,
}

impl ScanRequest {
    fn from_input(input: &str) -> Result<Self, ()> {
        // A struct visitor silently accepts positional arrays, so the input
        // must be declared an object before any field (including the
        // credential) is read. The gate inspects leading JSON whitespace and
        // the first byte only, allocating nothing and materializing no Value;
        // serde_json then parses the typed request with its own depth limit.
        let first = input
            .bytes()
            .find(|byte| !byte.is_ascii_whitespace())
            .ok_or(())?;
        if first != b'{' {
            return Err(());
        }
        serde_json::from_str::<ScanRequest>(input).map_err(|_| ())
    }
}

/// No Debug/Display/Serialize implementation: credential bytes stay private.
struct GithubToken(zeroize::Zeroizing<String>);

/// The credential visitor transfers decoded JSON strings into an owned
/// zeroizing buffer without an intermediate serde_json::Value.
struct GithubTokenVisitor;

impl<'de> serde::de::Visitor<'de> for GithubTokenVisitor {
    type Value = GithubToken;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a GitHub credential string")
    }

    fn visit_str<E: serde::de::Error>(self, secret: &str) -> Result<Self::Value, E> {
        let secret = zeroize::Zeroizing::new(secret.to_owned());
        if secret.len() < 8
            || secret.len() > 4096
            || !secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(serde::de::Error::custom("invalid GitHub credential"));
        }
        Ok(GithubToken(secret))
    }
}

impl<'de> Deserialize<'de> for GithubToken {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_string(GithubTokenVisitor)
    }
}

#[derive(Clone, Copy, Debug)]
struct RepositoryPermissions {
    admin: bool,
    maintain: bool,
    push: bool,
    triage: bool,
    pull: bool,
}

impl RepositoryPermissions {
    fn can_write(self) -> bool {
        self.admin || self.maintain || self.push
    }

    fn can_triage(self) -> bool {
        self.can_write() || self.triage
    }
}

#[derive(Debug)]
struct Repository {
    id: Option<u64>,
    full_name: String,
    permissions: RepositoryPermissions,
    archived: bool,
    disabled: bool,
}

impl Repository {
    fn permission_json(&self) -> Value {
        json!({
            "source": "authenticated_repository_response",
            "metadata_present": true,
            "admin": self.permissions.admin,
            "maintain": self.permissions.maintain,
            "push": self.permissions.push,
            "triage": self.permissions.triage,
            "pull": self.permissions.pull,
            "can_write": self.permissions.can_write(),
            "can_triage": self.permissions.can_triage(),
            "archived": self.archived,
            "disabled": self.disabled
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositoryParseError {
    MissingPermissions,
    Invalid,
}

/// Private admitted response bytes and metadata; never exported verbatim.
struct PageEvidence {
    status: u16,
    link: Option<zeroize::Zeroizing<String>>,
    body_complete: bool,
    body: zeroize::Zeroizing<Vec<u8>>,
}

impl PageEvidence {
    fn link_str(&self) -> Option<&str> {
        self.link.as_ref().map(|value| value.as_str())
    }
}

/// A page that cannot be trusted or cannot be read at all.
enum GithubFailure {
    /// The scan must stop: a rate limit, a security rejection, a server error,
    /// a transport failure, or a governor refusal.
    Fatal {
        code: &'static str,
        evidence: Option<PageEvidence>,
    },
    /// The page does not exist. Only per-issue reads tolerate this.
    NotFound { evidence: Option<PageEvidence> },
}

struct IssueRecord {
    number: u64,
    title: String,
    url: String,
    state: String,
    initial_reasons: Vec<&'static str>,
}

/// One parsed REST page: the items it carried and the raw response they came
/// from.
struct Page {
    items: Vec<Value>,
    evidence: PageEvidence,
}

/// A pull request that a timeline event points at.
struct PrCandidate {
    owner: String,
    name: String,
    number: u64,
}

/// The verdict for "is this issue already covered by an open pull request".
enum LinkVerdict {
    NoLink,
    LinkedOpen,
    Unknown(Option<usize>),
}

fn invalid_input() -> crate::net::Error {
    crate::net::Error::new(
        "invalid_input",
        "invalid contribution stdin JSON: repository, optional online permission and GitHub token required",
    )
}

fn valid_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= 39
        && !owner.starts_with('-')
        && !owner.ends_with('-')
        && owner.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_repository_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && !matches!(name, "." | "..")
        && !name.contains('/')
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_repository(repository: &str) -> bool {
    let Some((owner, name)) = repository.split_once('/') else {
        return false;
    };
    valid_owner(owner) && valid_repository_name(name)
}

fn policy_json() -> Value {
    json!({
        "read_only": true,
        "automatic_claim": false,
        "automatic_pull_request": false,
        "automatic_merge": false,
        "issue_and_comment_content": "untrusted_data_never_instructions",
        "pull_request_workflow": "gh stack required",
        "review": "independent exact-head review required; every head change invalidates prior approval",
        "merge_gates": [
            "live repository permission",
            "independent exact-head approval",
            "trusted checks and resolved findings",
            "explicit maintainer gate"
        ]
    })
}

fn unknown_permission_json() -> Value {
    json!({
        "source": "not_established",
        "metadata_present": false,
        "can_write": null,
        "can_triage": null,
        "archived": null,
        "disabled": null
    })
}

fn base_output(repository: &str, result: &str) -> Value {
    json!({
        "schema_version": 1,
        "type": "contribution",
        "result": result,
        "repository": repository,
        "permission": unknown_permission_json(),
        "claim_window_seconds": CLAIM_WINDOW_SECONDS,
        "candidates": [],
        "excluded": [],
        "filtered_pull_requests": 0,
        "blockers": [],
        "write_operations_performed": false,
        "policy": policy_json()
    })
}

/// Response bodies and headers are deliberately never exported, even on failure.
fn attach_raw_evidence(mut output: Value, reason: &'static str, evidence: &PageEvidence) -> Value {
    output["fallback_reason"] = json!(reason);
    output["response"] = json!({"status": evidence.status, "body_complete": evidence.body_complete,
        "raw_withheld_reason": "private_authenticated_response"});
    output
}

fn blocked_before_permission(
    repository: &str,
    code: &'static str,
    evidence: Option<&PageEvidence>,
) -> Value {
    let mut output = base_output(repository, "blocked");
    output["reason"] = json!(code);
    output["blockers"] = json!([{"code": code}]);
    if let Some(evidence) = evidence {
        output = attach_raw_evidence(output, code, evidence);
    }
    output
}

fn blocked_after_permission(
    repository: &Repository,
    code: &'static str,
    evidence: Option<&PageEvidence>,
) -> Value {
    let mut output = base_output(&repository.full_name, "blocked");
    output["permission"] = repository.permission_json();
    output["reason"] = json!(code);
    output["blockers"] = json!([{"code": code}]);
    if let Some(evidence) = evidence {
        output = attach_raw_evidence(output, code, evidence);
    }
    output
}

/// One original HTTPS request per shared governor lease; no redirect or retry.
struct GithubReader<'g> {
    client: reqwest::blocking::Client,
    token: &'g GithubToken,
    governor: &'g Governor,
}

fn api_url_allowed(url: &str) -> bool {
    url.starts_with(API_PREFIX) && url::Url::parse(url).is_ok_and(|u| u.scheme() == "https"
        && u.host_str() == Some("api.github.com") && u.username().is_empty()
        && u.password().is_none() && u.port().is_none() && u.fragment().is_none()
        && (u.path().starts_with("/repos/") || u.path().starts_with("/repositories/"))
        && !url.contains('%') && !url.contains('\\'))
}

/// Bind a next-page path either to the original path or to the same collection
/// under the numeric repository id established by the repository response.
fn pagination_path_allowed(
    first_path: &str,
    next_path: &str,
    bound_repository_id: Option<u64>,
) -> bool {
    if first_path == next_path {
        return true;
    }
    // The first path is `/repos/{owner}/{repository}/{collection}`; the
    // numeric form is `/repositories/{id}/{collection}`. Only the collection
    // tail has to match.
    let Some(first_rest) = first_path.strip_prefix("/repos/") else {
        return false;
    };
    let mut first_parts = first_rest.splitn(3, '/');
    let owner = first_parts.next().unwrap_or("");
    let repository = first_parts.next().unwrap_or("");
    let Some(collection) = first_parts.next() else {
        return false;
    };
    if owner.is_empty() || repository.is_empty() || collection.is_empty() {
        return false;
    }
    let Some(next_rest) = next_path.strip_prefix("/repositories/") else {
        return false;
    };
    let mut next_parts = next_rest.splitn(2, '/');
    let identifier = next_parts.next().unwrap_or("");
    let Some(next_collection) = next_parts.next() else {
        return false;
    };
    let Ok(identifier) = identifier.parse::<u64>() else {
        return false;
    };
    bound_repository_id == Some(identifier) && next_collection == collection
}

impl<'g> GithubReader<'g> {
    fn fetch_page(&self, url: &str) -> Result<PageEvidence, GithubFailure> {
        let fail = |code| GithubFailure::Fatal { code, evidence: None };
        if !api_url_allowed(url) { return Err(fail("github_url_rejected")); }
        let request = match github_request(&self.client, url, self.token) {
            Ok(request) => request,
            Err(_) => return Err(fail("invalid_input")),
        };
        let mut lease = crate::net::acquire(self.governor).map_err(|e| fail(e.code))?;
        let mut response = match lease.start_request(|| request.send()) {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                let settled = lease.finish(Outcome::NetworkFailure);
                return Err(fail(if settled.is_ok() { "github_transport_failed" } else { "github_outcome_unrecorded" }));
            }
            Err(crate::governor::FollowupError::Governor(_)) => {
                // No request was admitted. Keep the pending reservation for
                // conservative reconciliation instead of inventing an outcome.
                return Err(fail("github_request_start_unavailable"));
            }
        };
        let status = response.status().as_u16();
        let secret = self.token.0.as_str();
        // Header borrows end here, so the response can be dropped later while
        // its body stream is still open. Every copied header value lives in a
        // zeroizing buffer, so a reflected credential is never materialized in
        // an ordinary owned string.
        let (header_challenge, retry_after, content_type, link, metadata_valid, length, reflected) = {
            let headers = response.headers();
            let reflected = headers.iter().any(|(_, value)| contains_bytes(value.as_bytes(), secret));
            let header_challenge = headers.iter().any(|(k,v)| crate::net::challenge_header(k.as_str(),v.as_bytes()));
            let value = |name: &str| headers.get(name).and_then(|v| v.to_str().ok())
                .map(|v| zeroize::Zeroizing::new(v.to_owned()));
            let retry_after = value("retry-after");
            let content_type = value("content-type");
            let link = value("link");
            let metadata_valid = ["retry-after", "content-type", "content-length", "link"].iter().all(|name|
                headers.get_all(*name).iter().count() <= 1 && headers.get(*name).is_none_or(|v| v.to_str().is_ok()))
                && headers.get_all("content-encoding").iter().all(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"));
            (header_challenge, retry_after, content_type, link, metadata_valid, response.content_length(), reflected)
        };
        let retry_after_text = retry_after.as_ref().map(|value| value.as_str());
        let content_type_text = content_type.as_ref().map(|value| value.as_str());
        if observe_github_headers(&mut lease, status, response.headers(), header_challenge).is_err() {
            drop(response);
            let _ = lease.finish(Outcome::NetworkFailure);
            return Err(fail("github_outcome_unrecorded"));
        }
        // Reserve the bounded maximum once, so growth cannot free an earlier
        // allocation containing a reflected credential before zeroization.
        let mut body = zeroize::Zeroizing::new(Vec::with_capacity(MAX_BODY + 1));
        let read = {
            let mut chunk = zeroize::Zeroizing::new([0u8; 8192]);
            let mut stream = response.by_ref().take((MAX_BODY + 1) as u64);
            loop {
                match stream.read(&mut *chunk) {
                    Ok(0) => break Ok(()),
                    Ok(count) => body.extend_from_slice(&chunk[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => break Err(error),
                }
            }
        };
        let complete = read.is_ok() && body.len() <= MAX_BODY && length.is_none_or(|n| n == body.len() as u64);
        let assessment = crate::html::assess_challenge_body(body.as_slice(),content_type_text,complete);
        let challenge = header_challenge || assessment == crate::html::ChallengeAssessment::Detected;
        // The response is dropped before the lease is released, so an unread
        // body can never outlive the recorded request outcome.
        drop(response);
        lease.finish(Outcome::Http { status, retry_after: retry_after_text, challenge,
            network_failure: !complete || !metadata_valid })
            .map_err(|_| fail("github_outcome_unrecorded"))?;
        if reflected {
            return Err(fail("github_private_response_withheld"));
        }
        if challenge { return Err(fail("github_challenge_detected")); }
        if !complete { return Err(fail("github_response_incomplete")); }
        if !metadata_valid || assessment != crate::html::ChallengeAssessment::Clear {
            return Err(fail("github_response_safety_unreviewed"));
        }
        // Reject any literal or JSON-escaped reflection of the credential
        // before untrusted titles/URLs or metadata can enter the public
        // result. The response is kept in a zeroizing buffer, and escape
        // decoding happens only on temporary zeroizing strings; no ordinary
        // Value ever materializes the credential.
        let json_body = content_type_text.is_some_and(|value| {
            matches!(value.split(';').next().unwrap_or("").trim(),
                "application/json" | "application/vnd.github+json")
        });
        match secret_reflection(body.as_slice(), secret, json_body) {
            SecretReflection::Present => {
                return Err(fail("github_private_response_withheld"));
            }
            SecretReflection::Unresolved => {
                return Err(fail("github_response_safety_unreviewed"));
            }
            SecretReflection::Absent => {}
        }
        if status == 404 {
            return Err(GithubFailure::NotFound { evidence: Some(PageEvidence {
                status,
                link,
                body_complete: complete,
                body,
            }) });
        }
        if status != 200 {
            return Err(fail(match status {
                401 | 403 => "github_unauthorized",
                429 => "github_rate_limited",
                500..=599 => "github_server_error",
                _ => "github_request_rejected",
            }));
        }
        if !json_body {
            return Err(fail("github_response_mime_rejected"));
        }
        let evidence = PageEvidence {
            status,
            link,
            body_complete: complete,
            body,
        };
        Ok(evidence)
    }

}

/// Persist every Retry-After observation before duplicate-header admission or
/// body handling can refuse the response. Invalid values remain observations
/// of unknown duration rather than hiding a later valid, longer cooldown.
fn observe_github_headers(
    lease: &mut crate::governor::RequestLease<'_>,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    challenge: bool,
) -> Result<(), String> {
    lease.observe_http_many(status,
        headers.get_all("retry-after").iter().map(|value| value.to_str().ok()),
        challenge)
}

/// Build one authenticated request with a single total deadline. The
/// credential is copied only into a sensitive header value; it never appears
/// in a URL, a log, or an error message.
fn github_request(
    client: &reqwest::blocking::Client,
    url: &str,
    token: &GithubToken,
) -> Result<reqwest::blocking::RequestBuilder, ()> {
    let mut authorization_text = zeroize::Zeroizing::new(String::with_capacity(7 + token.0.len()));
    authorization_text.push_str("Bearer ");
    authorization_text.push_str(token.0.as_str());
    let mut authorization = reqwest::header::HeaderValue::from_str(authorization_text.as_str())
        .map_err(|_| ())?;
    authorization.set_sensitive(true);
    Ok(client
        .get(url)
        .timeout(REQUEST_DEADLINE)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header("Accept", "application/vnd.github+json")
        .header("Accept-Encoding", "identity"))
}

trait GithubRead {
    fn get(&self, url: &str) -> Result<PageEvidence, GithubFailure>;

    /// Read every page of one list endpoint. Each page is a separate request
    /// with its own lease. The second value reports that the endpoint still
    /// had more pages after the bounded read stopped.
    fn get_pages(
        &self,
        first_url: &str,
        max_pages: usize,
        max_items: usize,
        bound_repository_id: Option<u64>,
    ) -> Result<(Vec<Page>, bool), GithubFailure> {
        let mut pages = Vec::new();
        let mut url = first_url.to_owned();
        let mut total = 0usize;
        let mut seen = std::collections::BTreeSet::new();
        let first = url::Url::parse(first_url).map_err(|_| GithubFailure::Fatal { code: "github_url_rejected", evidence: None })?;
        loop {
            let parsed = url::Url::parse(&url).map_err(|_| GithubFailure::Fatal { code: "github_pagination_invalid", evidence: None })?;
            if !pagination_path_allowed(first.path(), parsed.path(), bound_repository_id)
                || !seen.insert(url.clone())
            {
                return Err(GithubFailure::Fatal { code: "github_pagination_invalid", evidence: None });
            }
            let evidence = self.get(&url)?;
            let items = match serde_json::from_slice::<Value>(evidence.body.as_slice()) {
                Ok(Value::Array(items)) => items,
                _ => {
                    return Err(GithubFailure::Fatal {
                        code: "github_response_invalid",
                        evidence: Some(evidence),
                    });
                }
            };
            total += items.len();
            if total > max_items {
                return Err(GithubFailure::Fatal {
                    code: "github_page_limit_exceeded",
                    evidence: Some(evidence),
                });
            }
            let next = match next_page_url(evidence.link_str()) {
                Ok(next) => next,
                Err(()) => {
                    return Err(GithubFailure::Fatal {
                        code: "github_pagination_invalid",
                        evidence: Some(evidence),
                    });
                }
            };
            pages.push(Page { items, evidence });
            match next {
                Some(next) if pages.len() < max_pages => url = next,
                Some(_) => return Ok((pages, true)),
                None => return Ok((pages, false)),
            }
        }
    }
}

impl GithubRead for GithubReader<'_> {
    fn get(&self, url: &str) -> Result<PageEvidence, GithubFailure> {
        GithubReader::fetch_page(self, url)
    }
}

/// Whether raw JSON bytes contain the credential, either literally or through
/// JSON string escapes. The body is never parsed into an ordinary Value: only
/// the individual escaped strings are decoded, each into a temporary
/// zeroizing string that is wiped when it goes out of scope.
fn contains_bytes(bytes: &[u8], secret: &str) -> bool {
    !secret.is_empty() && bytes.windows(secret.len()).any(|window| window == secret.as_bytes())
}

fn secret_reflection(bytes: &[u8], secret: &str, decode_escapes: bool) -> SecretReflection {
    if secret.is_empty() {
        return SecretReflection::Absent;
    }
    if contains_bytes(bytes, secret) {
        return SecretReflection::Present;
    }
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        let opening = cursor;
        cursor += 1;
        let mut escaped = false;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'\\' => {
                    escaped = true;
                    cursor = cursor.saturating_add(2);
                }
                b'"' => break,
                _ => cursor += 1,
            }
        }
        if cursor >= bytes.len() {
            break;
        }
        if escaped && decode_escapes {
            let content = &bytes[opening + 1..cursor];
            let Ok(text) = std::str::from_utf8(content) else {
                // An undecodable escape sequence leaves the reflection
                // unresolved, so the response cannot be admitted.
                return SecretReflection::Unresolved;
            };
            let mut decoded = zeroize::Zeroizing::new(String::new());
            if !decode_json_string(text, &mut decoded) {
                // An ambiguous escape sequence leaves the reflection
                // unresolved, so the response cannot be admitted.
                return SecretReflection::Unresolved;
            }
            if contains_bytes(decoded.as_bytes(), secret) {
                return SecretReflection::Present;
            }
        }
        cursor += 1;
    }
    SecretReflection::Absent
}

/// The outcome of scanning one response for a reflected credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretReflection {
    Absent,
    Present,
    Unresolved,
}

/// Decode the content of one JSON string into a zeroizing buffer. Only the
/// JSON escape forms are accepted; anything else leaves the content
/// unresolved and is reported as a failure.
fn decode_json_string(content: &str, out: &mut zeroize::Zeroizing<String>) -> bool {
    out.clear();
    out.reserve_exact(content.len());
    let mut characters = content.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                let Some(escaped) = characters.next() else {
                    return false;
                };
                match escaped {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let Some(code) = read_hex4(&mut characters) else {
                            return false;
                        };
                        match code {
                            0xD800..=0xDBFF => {
                                if characters.next() != Some('\\')
                                    || characters.next() != Some('u')
                                {
                                    return false;
                                }
                                let Some(low) = read_hex4(&mut characters) else {
                                    return false;
                                };
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return false;
                                }
                                let combined =
                                    0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                out.push(char::from_u32(combined).unwrap_or('\u{FFFD}'));
                            }
                            0xDC00..=0xDFFF => return false,
                            _ => out.push(char::from_u32(code).unwrap_or('\u{FFFD}')),
                        }
                    }
                    _ => return false,
                }
            }
            control if (control as u32) < 0x20 => return false,
            other => out.push(other),
        }
    }
    true
}

/// Read exactly four hexadecimal digits of a JSON `\u` escape.
fn read_hex4(characters: &mut std::str::Chars<'_>) -> Option<u32> {
    let mut code = 0u32;
    for _ in 0..4 {
        let digit = characters.next()?.to_digit(16)?;
        code = code * 16 + digit;
    }
    Some(code)
}

/// Follow only GitHub's own API links, and only the `rel="next"` one.
fn next_page_url(link: Option<&str>) -> Result<Option<String>, ()> {
    let Some(link) = link else { return Ok(None); };
    let mut next = None;
    for part in link.split(',') {
        let (target, parameters) = part.trim().split_once('>').ok_or(())?;
        let target = target.strip_prefix('<').ok_or(())?;
        if !api_url_allowed(target) { return Err(()); }
        let relation = parameters.trim().strip_prefix(';').ok_or(())?.trim()
            .strip_prefix("rel=").ok_or(())?.trim_matches('"');
        if !matches!(relation,"next" | "prev" | "first" | "last") { return Err(()); }
        if relation == "next" && next.replace(target.to_owned()).is_some() { return Err(()); }
    }
    Ok(next)
}

fn permission_flag(value: &Value, name: &str) -> Result<bool, RepositoryParseError> {
    value
        .get(name)
        .and_then(Value::as_bool)
        .ok_or(RepositoryParseError::Invalid)
}

fn parse_repository(
    bytes: &[u8],
    requested: &str,
) -> Result<Repository, RepositoryParseError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| RepositoryParseError::Invalid)?;
    let object = value.as_object().ok_or(RepositoryParseError::Invalid)?;
    // The repository id binds the numeric pagination form of GitHub's own
    // `Link` header to the repository this scan actually opened.
    let id = object.get("id").and_then(Value::as_u64);
    let full_name = object
        .get("full_name")
        .and_then(Value::as_str)
        .filter(|name| valid_repository(name) && name.eq_ignore_ascii_case(requested))
        .ok_or(RepositoryParseError::Invalid)?
        .to_owned();
    let Some(permissions) = object.get("permissions") else {
        return Err(RepositoryParseError::MissingPermissions);
    };
    if permissions.is_null() {
        return Err(RepositoryParseError::MissingPermissions);
    }
    if !permissions.is_object() {
        return Err(RepositoryParseError::Invalid);
    }
    let permissions = RepositoryPermissions {
        admin: permission_flag(permissions, "admin")?,
        maintain: permission_flag(permissions, "maintain")?,
        push: permission_flag(permissions, "push")?,
        triage: permission_flag(permissions, "triage")?,
        pull: permission_flag(permissions, "pull")?,
    };
    let archived = object
        .get("archived")
        .and_then(Value::as_bool)
        .ok_or(RepositoryParseError::Invalid)?;
    let disabled = object
        .get("disabled")
        .and_then(Value::as_bool)
        .ok_or(RepositoryParseError::Invalid)?;
    Ok(Repository {
        id,
        full_name,
        permissions,
        archived,
        disabled,
    })
}

fn expected_issue_url(repository: &str, number: u64) -> String {
    format!("{WEB_ROOT}/{repository}/issues/{number}")
}

fn parse_issues(items: &[Value], repository: &str) -> Result<IssueList, ()> {
    let mut issues = Vec::new();
    let mut filtered_pull_requests = 0usize;
    for item in items {
        let object = item.as_object().ok_or(())?;
        // GitHub uses this field's presence, not its truthiness, to identify a
        // pull request in the issues API. Conservatively filter even null.
        if object.contains_key("pull_request") {
            filtered_pull_requests = filtered_pull_requests.checked_add(1).ok_or(())?;
            continue;
        }
        let number = object
            .get("number")
            .and_then(Value::as_u64)
            .filter(|number| *number > 0)
            .ok_or(())?;
        let state = object
            .get("state")
            .and_then(Value::as_str)
            .ok_or(())?
            .to_owned();
        let title = object
            .get("title")
            .and_then(Value::as_str)
            .filter(|title| title.len() <= MAX_TITLE_BYTES)
            .ok_or(())?
            .to_owned();
        let url = object
            .get("html_url")
            .and_then(Value::as_str)
            .filter(|url| *url == expected_issue_url(repository, number))
            .ok_or(())?
            .to_owned();
        let assignee = object.get("assignee").ok_or(())?;
        let assignees = object
            .get("assignees")
            .and_then(Value::as_array)
            .ok_or(())?;
        let mut initial_reasons = Vec::new();
        if state != "open" {
            initial_reasons.push("not_open");
        }
        if !assignee.is_null() || !assignees.is_empty() {
            initial_reasons.push("assigned");
        }
        issues.push(IssueRecord {
            number,
            title,
            url,
            state,
            initial_reasons,
        });
    }
    Ok(IssueList {
        issues,
        filtered_pull_requests,
    })
}

struct IssueList {
    issues: Vec<IssueRecord>,
    filtered_pull_requests: usize,
}

/// Parse the pull request a timeline event points at.
///
/// A `connected` event is the Development link between an issue and a pull
/// request. GitHub's REST timeline documents the event without the linked
/// object, so the linked pull request is resolved from the event body and
/// then confirmed against the pull request itself.
fn parse_pr_identity(url: &str) -> Option<PrCandidate> {
    let rest = url.strip_prefix(API_PREFIX)?;
    let mut parts = rest.split('/');
    if parts.next()? != "repos" {
        return None;
    }
    let owner = parts.next()?;
    let name = parts.next()?;
    if parts.next()? != "pulls" {
        return None;
    }
    let number = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    if !valid_owner(owner) || !valid_repository_name(name) || number == 0 {
        return None;
    }
    Some(PrCandidate {
        owner: owner.to_owned(),
        name: name.to_owned(),
        number,
    })
}

/// A timeline event either identifies a pull request or leaves the link
/// unresolved; only a resolved identity can be read live.
enum CrossReference {
    Resolved(PrCandidate),
    /// The event names no pull request at all.
    NotLinked,
    /// The event names a pull request whose identity cannot be read.
    Unresolved,
}

/// The pull request of a `connected` event, if the event identifies one.
fn connected_candidate(
    event: &serde_json::Map<String, Value>,
) -> Result<CrossReference, ()> {
    let Some(subject) = event.get("subject") else {
        // The event names a link but not its target. The link cannot be
        // dismissed, so the issue stays unresolved.
        return Err(());
    };
    let Some(subject) = subject.as_object() else {
        return Err(());
    };
    if let Some(pull_request) = subject.get("pull_request").and_then(Value::as_object) {
        let Some(url) = pull_request.get("url").and_then(Value::as_str) else {
            return Err(());
        };
        return parse_pr_identity(url).map(|candidate| CrossReference::Resolved(candidate)).ok_or(());
    }
    if let Some(url) = subject.get("url").and_then(Value::as_str) {
        if let Some(candidate) = parse_pr_identity(url) {
            return Ok(CrossReference::Resolved(candidate));
        }
        return Err(());
    }
    Err(())
}

/// The pull request a `cross-referenced` event points at.
fn cross_referenced_candidate(
    event: &serde_json::Map<String, Value>,
) -> Result<CrossReference, ()> {
    let Some(source) = event.get("source").and_then(Value::as_object) else {
        return Err(());
    };
    let Some(issue) = source.get("issue").and_then(Value::as_object) else {
        return Err(());
    };
    match issue.get("pull_request") {
        Some(Value::Object(pull_request)) => {
            let Some(url) = pull_request.get("url").and_then(Value::as_str) else {
                return Err(());
            };
            return parse_pr_identity(url)
                .map(|candidate| CrossReference::Resolved(candidate))
                .ok_or(());
        }
        Some(Value::Null) => Ok(CrossReference::Unresolved),
        None => Ok(CrossReference::NotLinked),
        Some(_) => Err(()),
    }
}

/// Read the current state of a linked pull request or retain a failure.
fn pull_request_state(
    reader: &impl GithubRead,
    candidate: &PrCandidate,
) -> Result<bool, GithubFailure> {
    let url = format!(
        "{API_ROOT}/{}/{}/pulls/{}",
        candidate.owner, candidate.name, candidate.number
    );
    match reader.get(&url) {
        Ok(evidence) => {
            let parsed = serde_json::from_slice::<Value>(evidence.body.as_slice()).ok();
            match parsed.as_ref().and_then(|value| {
                if value.get("number").and_then(Value::as_u64) != Some(candidate.number) {
                    return None;
                }
                match value.get("state").and_then(Value::as_str) {
                    Some("open") => Some(true),
                    Some("closed") => Some(false),
                    _ => None,
                }
            }) {
                Some(open) => Ok(open),
                None => Err(GithubFailure::Fatal {
                    code: "linked_pr_response_invalid",
                    evidence: Some(evidence),
                }),
            }
        }
        // GitHub can also mask an inaccessible pull request with 404.
        Err(failure) => Err(failure),
    }
}

/// Decide whether an issue is already covered by an open pull request.
fn analyze_link(
    reader: &impl GithubRead,
    pages: &[Page],
    truncated: bool,
) -> Result<LinkVerdict, GithubFailure> {
    let mut candidates: Vec<PrCandidate> = Vec::new();
    let mut unknown_page = if truncated { pages.len().checked_sub(1) } else { None };
    for (page_index, page) in pages.iter().enumerate() {
        for item in &page.items {
            let Some(event) = item.as_object() else {
                unknown_page.get_or_insert(page_index);
                continue;
            };
            let Some(kind) = event.get("event").and_then(Value::as_str) else {
                unknown_page.get_or_insert(page_index);
                continue;
            };
            let candidate = match kind {
                "connected" => match connected_candidate(event) {
                    Ok(CrossReference::Resolved(candidate)) => Some(candidate),
                    Ok(CrossReference::Unresolved) => {
                        unknown_page.get_or_insert(page_index);
                        continue;
                    }
                    Ok(CrossReference::NotLinked) => continue,
                    Err(()) => {
                        unknown_page.get_or_insert(page_index);
                        continue;
                    }
                },
                "cross-referenced" => match cross_referenced_candidate(event) {
                    Ok(CrossReference::Resolved(candidate)) => Some(candidate),
                    Ok(CrossReference::Unresolved) => {
                        unknown_page.get_or_insert(page_index);
                        continue;
                    }
                    Ok(CrossReference::NotLinked) => continue,
                    Err(()) => {
                        unknown_page.get_or_insert(page_index);
                        continue;
                    }
                },
                // A disconnected event removes a link; it can never establish
                // that a pull request is currently linked.
                _ => continue,
            };
            if let Some(candidate) = candidate {
                if candidates.iter().any(|existing| {
                    existing.owner.eq_ignore_ascii_case(&candidate.owner)
                        && existing.name.eq_ignore_ascii_case(&candidate.name)
                        && existing.number == candidate.number
                }) {
                    continue;
                }
                if candidates.len() < MAX_PR_CANDIDATES {
                    candidates.push(candidate);
                } else {
                    unknown_page.get_or_insert(page_index);
                }
            }
        }
    }
    let mut open = false;
    for candidate in &candidates {
        match pull_request_state(reader, candidate)? {
            true => {
                open = true;
                break;
            }
            false => {}
        }
    }
    if open {
        Ok(LinkVerdict::LinkedOpen)
    } else if unknown_page.is_some() || truncated {
        Ok(LinkVerdict::Unknown(unknown_page))
    } else {
        Ok(LinkVerdict::NoLink)
    }
}

/// Whether a comment marks a positive claim or lease of the issue.
///
/// The markers are matched at a word boundary so ordinary discussion such as
/// "please", "release", or "unclaimed" is never treated as a claim, while
/// "claimed", "claims", "lease", and "leasing" are.
fn claim_or_lease_marker(body: &str) -> bool {
    const WORD_MARKERS: &[&str] = &[
        "claim", "claims", "claimed", "claiming",
        "lease", "leases", "leased", "leasing",
    ];
    const PHRASE_MARKERS: &[&str] = &[
        "working on this",
        "i'll take",
        "i will take",
        "taking this",
    ];
    const CJK_MARKERS: &[&str] = &["认领", "接手"];
    if WORD_MARKERS
        .iter()
        .any(|marker| contains_word_marker(body, marker))
    {
        return true;
    }
    if PHRASE_MARKERS
        .iter()
        .any(|marker| contains_marker(body, marker))
    {
        return true;
    }
    CJK_MARKERS.iter().any(|marker| body.contains(marker))
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Case-insensitive ASCII marker match bounded at both ends of the word.
fn contains_word_marker(body: &str, marker: &str) -> bool {
    let body = body.as_bytes();
    let marker = marker.as_bytes();
    if marker.is_empty() || body.len() < marker.len() {
        return false;
    }
    body.windows(marker.len())
        .enumerate()
        .any(|(index, window)| {
            window.eq_ignore_ascii_case(marker)
                && (index == 0 || !is_word_byte(body[index - 1]))
                && (index + marker.len() == body.len()
                    || !is_word_byte(body[index + marker.len()]))
        })
}

fn contains_marker(body: &str, marker: &str) -> bool {
    if marker.is_ascii() {
        body.as_bytes()
            .windows(marker.len())
            .any(|window| window.eq_ignore_ascii_case(marker.as_bytes()))
    } else {
        body.contains(marker)
    }
}

fn timestamp(value: &Value, field: &str) -> Result<i64, ()> {
    let text = value.get(field).and_then(Value::as_str).ok_or(())?;
    DateTime::parse_from_rfc3339(text)
        .map(|timestamp| timestamp.timestamp())
        .map_err(|_| ())
}

fn recent(timestamp: i64, now: i64) -> bool {
    // Future timestamps are conservatively recent rather than a way to evade
    // an existing claim. Very old timestamps saturate to an old age.
    now.saturating_sub(timestamp) <= CLAIM_WINDOW_SECONDS
}

/// Whether one comment claims the issue inside the claim window.
fn comment_claims_issue(comment: &Value, now: i64) -> Result<bool, ()> {
    let Some(object) = comment.as_object() else {
        return Err(());
    };
    let Some(body) = object.get("body").and_then(Value::as_str) else {
        return Err(());
    };
    let created = timestamp(comment, "created_at")?;
    let updated = timestamp(comment, "updated_at")?;
    if updated < created {
        return Err(());
    }
    Ok(claim_or_lease_marker(body) && (recent(created, now) || recent(updated, now)))
}

fn issue_metadata(issue: &IssueRecord) -> Value {
    json!({
        "number": issue.number,
        "title": issue.title,
        "url": issue.url,
        "state": issue.state,
        "content_trust": "untrusted"
    })
}

fn excluded_issue(issue: &IssueRecord, reasons: Vec<&'static str>) -> Value {
    let mut output = issue_metadata(issue);
    output["reasons"] = json!(reasons);
    output
}

fn api_url(repository: &str, suffix: &str) -> String {
    format!("{API_ROOT}/{repository}{suffix}")
}

fn now_unix() -> Result<i64, crate::net::Error> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            crate::net::Error::new("unavailable", "system clock is before the Unix epoch")
        })?
        .as_secs();
    i64::try_from(seconds).map_err(|_| {
        crate::net::Error::new("unavailable", "system clock exceeds the supported range")
    })
}

fn scan_with_reader(
    request: &ScanRequest,
    reader: &impl GithubRead,
) -> Result<Value, crate::net::Error> {
    let now = now_unix()?;

    let repository_url = api_url(&request.repository, "");
    let repository_evidence = match reader.get(&repository_url) {
        Ok(evidence) => evidence,
        Err(GithubFailure::NotFound { evidence }) => {
            return Ok(blocked_before_permission(
                &request.repository,
                "repository_not_found",
                evidence.as_ref(),
            ));
        }
        Err(GithubFailure::Fatal { code, evidence }) => {
            return Ok(blocked_before_permission(
                &request.repository,
                code,
                evidence.as_ref(),
            ));
        }
    };
    let repository = match parse_repository(repository_evidence.body.as_slice(), &request.repository) {
        Ok(repository) => repository,
        Err(RepositoryParseError::MissingPermissions) => {
            return Ok(blocked_before_permission(
                &request.repository,
                "repository_permissions_missing",
                Some(&repository_evidence),
            ));
        }
        Err(RepositoryParseError::Invalid) => {
            return Ok(blocked_before_permission(
                &request.repository,
                "repository_response_invalid",
                Some(&repository_evidence),
            ));
        }
    };

    let issues_url = api_url(&repository.full_name, "/issues?state=open&per_page=100");
    let (issue_pages, issues_truncated) =
        match reader.get_pages(&issues_url, MAX_LIST_PAGES, MAX_LIST_ITEMS, repository.id) {
            Ok(pages) => pages,
            Err(GithubFailure::NotFound { evidence }) => {
                return Ok(blocked_after_permission(
                    &repository,
                    "issues_not_found",
                    evidence.as_ref(),
                ));
            }
            Err(GithubFailure::Fatal { code, evidence }) => {
                return Ok(blocked_after_permission(&repository, code, evidence.as_ref()));
            }
        };
    let mut issues = Vec::new();
    let mut filtered_pull_requests = 0usize;
    if issues_truncated {
        return Ok(blocked_after_permission(&repository, "issues_list_truncated", None));
    }
    for page in &issue_pages {
        match parse_issues(&page.items, &repository.full_name) {
            Ok(parsed) => {
                filtered_pull_requests += parsed.filtered_pull_requests;
                issues.extend(parsed.issues);
            }
            Err(()) => {
                return Ok(blocked_after_permission(
                    &repository,
                    "issues_response_invalid",
                    Some(&page.evidence),
                ));
            }
        }
    }

    let mut seen_issues = std::collections::BTreeSet::new();
    if issues.iter().any(|issue| !seen_issues.insert(issue.number)) {
        return Ok(blocked_after_permission(&repository, "duplicate_issue_identity", None));
    }
    let mut candidates = Vec::new();
    let mut excluded = Vec::new();
    for issue in issues {
        if !issue.initial_reasons.is_empty() {
            excluded.push(excluded_issue(&issue, issue.initial_reasons.clone()));
            continue;
        }

        let timeline_url = api_url(
            &repository.full_name,
            &format!("/issues/{}/timeline?per_page=100", issue.number),
        );
        let (timeline_pages, timeline_truncated) = match reader.get_pages(
            &timeline_url,
            MAX_TIMELINE_PAGES,
            MAX_TIMELINE_ITEMS,
            repository.id,
        ) {
            Ok(pages) => pages,
            Err(GithubFailure::NotFound { evidence }) => {
                let mut item = excluded_issue(&issue, vec!["linked_pr_status_unknown"]);
                if let Some(evidence) = evidence.as_ref() {
                    item = attach_raw_evidence(item, "linked_pr_status_unknown", evidence);
                }
                excluded.push(item);
                continue;
            }
            Err(GithubFailure::Fatal { code, evidence }) => {
                return Ok(blocked_after_permission(&repository, code, evidence.as_ref()));
            }
        };
        let link_verdict = match analyze_link(reader, &timeline_pages, timeline_truncated) {
            Ok(verdict) => verdict,
            Err(GithubFailure::Fatal { code, evidence }) => {
                return Ok(blocked_after_permission(&repository, code, evidence.as_ref()));
            }
            Err(GithubFailure::NotFound { evidence }) => {
                let mut item = excluded_issue(&issue, vec!["linked_pr_status_unknown"]);
                if let Some(evidence) = evidence.as_ref() {
                    item = attach_raw_evidence(item, "linked_pr_status_unknown", evidence);
                }
                excluded.push(item);
                continue;
            }
        };
        match link_verdict {
            LinkVerdict::LinkedOpen => {
                excluded.push(excluded_issue(&issue, vec!["linked_open_pr"]));
                continue;
            }
            LinkVerdict::Unknown(page_index) => {
                let mut item = excluded_issue(&issue, vec!["linked_pr_status_unknown"]);
                if let Some(page) = page_index.and_then(|index| timeline_pages.get(index)) {
                    item = attach_raw_evidence(item, "linked_pr_status_unknown", &page.evidence);
                }
                excluded.push(item);
                continue;
            }
            LinkVerdict::NoLink => {}
        }

        let comments_url = api_url(
            &repository.full_name,
            &format!("/issues/{}/comments?per_page=100", issue.number),
        );
        let (comment_pages, comments_truncated) = match reader.get_pages(
            &comments_url,
            MAX_COMMENT_PAGES,
            MAX_COMMENT_ITEMS,
            repository.id,
        ) {
            Ok(pages) => pages,
            Err(GithubFailure::NotFound { evidence }) => {
                let mut item = excluded_issue(&issue, vec!["claim_status_unknown"]);
                if let Some(evidence) = evidence.as_ref() {
                    item = attach_raw_evidence(item, "claim_status_unknown", evidence);
                }
                excluded.push(item);
                continue;
            }
            Err(GithubFailure::Fatal { code, evidence }) => {
                return Ok(blocked_after_permission(&repository, code, evidence.as_ref()));
            }
        };
        if comments_truncated {
            let mut item = excluded_issue(&issue, vec!["claim_status_unknown"]);
            if let Some(page) = comment_pages.last() {
                item = attach_raw_evidence(item, "comments_pagination_truncated", &page.evidence);
            }
            excluded.push(item);
            continue;
        }
        let mut claimed = false;
        let mut discussion_recent = false;
        let mut unknown_evidence = None;
        'comments: for page in &comment_pages {
            for comment in &page.items {
                match comment_claims_issue(comment, now) {
                    Ok(true) => {
                        claimed = true;
                        break 'comments;
                    }
                    Ok(false) => {
                        match (timestamp(comment, "created_at"), timestamp(comment, "updated_at")) {
                            (Ok(created), Ok(updated)) => discussion_recent |= recent(created, now) || recent(updated, now),
                            _ => { unknown_evidence = Some(&page.evidence); break 'comments; }
                        }
                    }
                    Err(()) => {
                        unknown_evidence = Some(&page.evidence);
                        break 'comments;
                    }
                }
            }
        }
        if claimed {
            excluded.push(excluded_issue(&issue, vec!["recent_claim_or_lease_comment"]));
        } else if let Some(evidence) = unknown_evidence {
            excluded.push(attach_raw_evidence(
                excluded_issue(&issue, vec!["claim_status_unknown"]),
                "comments_response_invalid",
                evidence,
            ));
        } else if discussion_recent {
            excluded.push(excluded_issue(&issue, vec!["recent_discussion"]));
        } else {
            candidates.push(issue_metadata(&issue));
        }
    }

    let mut output = base_output(&repository.full_name, "scan_completed");
    output["permission"] = repository.permission_json();
    output["candidates"] = json!(candidates);
    output["excluded"] = json!(excluded);
    output["filtered_pull_requests"] = json!(filtered_pull_requests);
    let mut blockers = Vec::new();
    if !repository.permissions.can_triage() {
        blockers.push(json!({"code": "repository_triage_permission_absent"}));
    }
    if !repository.permissions.can_write() {
        blockers.push(json!({"code": "repository_write_permission_absent"}));
    }
    if repository.archived {
        blockers.push(json!({"code": "repository_archived"}));
    }
    if repository.disabled {
        blockers.push(json!({"code": "repository_disabled"}));
    }
    if issues_truncated {
        blockers.push(json!({"code": "issues_list_truncated"}));
    }
    output["blockers"] = json!(blockers);
    Ok(output)
}

/// Input is secret-safe stdin JSON supplied by the caller, never argv.
pub fn scan(input: &str) -> Result<Value, crate::net::Error> {
    if input.len() > MAX_INPUT { return Err(invalid_input()); }
    let request = ScanRequest::from_input(input).map_err(|_| invalid_input())?;
    if !valid_repository(&request.repository) { return Err(invalid_input()); }
    if request.github_token.as_ref().is_some_and(|secret| request.repository.contains(secret.0.as_str())) {
        return Err(invalid_input());
    }
    if !request.online || request.github_token.is_none() {
        return Ok(blocked_before_permission(&request.repository,
            if !request.online { "explicit_online_permission_required" } else { "github_token_required" }, None));
    }
    let governor = Governor::open().map_err(|_| crate::net::Error::new("governor_unavailable", "shared governor unavailable"))?;
    let client = reqwest::blocking::Client::builder().redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never()).referer(false).no_proxy().https_only(true)
        .connect_timeout(std::time::Duration::from_secs(10))
        .user_agent("buaa-cli/0.1").build()
        .map_err(|_| crate::net::Error::new("github_transport_unavailable", "HTTPS client unavailable"))?;
    let reader = GithubReader { client, token: request.github_token.as_ref().ok_or_else(invalid_input)?, governor: &governor };
    scan_with_reader(&request, &reader)
}

pub fn schema() -> Value {
    json!({
        "input": {"type":"object", "additionalProperties":false, "required":["repository"],
            "description":"Exactly one JSON object; top-level arrays and other JSON values are refused. Standard JSON string escapes and whitespace are accepted.",
            "properties": {"repository":{"type":"string",
                    "pattern":"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9._-]{1,100}$",
                    "not":{"pattern":"^[^/]+/(\\.\\.?)$"},
                    "description":"owner/repository, not a URL"},
                "online":{"type":"boolean","default":false,"description":"Explicit authorization for bounded authenticated read-only GitHub requests"},
                "github_token":{"type":"string","writeOnly":true,"minLength":8,"maxLength":4096,
                    "pattern":"^[A-Za-z0-9_]+$","description":"stdin JSON only; decoded credential must match the ASCII pattern; zeroizing typed credential; never argv, URL, log, error or output"}}},
        "output":{"type":"object","required":["schema_version","type","result","repository","permission","candidates","excluded","blockers","write_operations_performed","policy"],
            "properties":{"schema_version":{"const":1},"type":{"const":"contribution"},
                "result":{"enum":["blocked","scan_completed"]},"write_operations_performed":{"const":false},
                "repository":{"type":"string"},
                "reason":{"type":"string","description":"Present when the scan is blocked"},
                "fallback_reason":{"type":"string","description":"Present when a per-issue exclusion carries response metadata"},
                "response":{"type":"object","description":"Status and completeness only. No raw authenticated body, header or credential is exported."},
                "permission":{"type":"object","description":"Authenticated repository permission metadata, or explicitly unknown before admission",
                    "properties":{"source":{"type":"string"},"metadata_present":{"type":"boolean"},
                        "can_write":{"type":["boolean","null"]},"can_triage":{"type":["boolean","null"]},
                        "archived":{"type":["boolean","null"]},"disabled":{"type":["boolean","null"]}}},
                "claim_window_seconds":{"const":CLAIM_WINDOW_SECONDS},
                "candidates":{"type":"array","description":"Untrusted issue metadata, not authorization to claim or create a PR"},
                "excluded":{"type":"array"},"filtered_pull_requests":{"type":"integer","minimum":0},
                "blockers":{"type":"array"},"policy":{"type":"object"}}},
        "limits":{"response_bytes":MAX_BODY,"issue_pages":MAX_LIST_PAGES,"issue_items":MAX_LIST_ITEMS,
            "timeline_pages_per_issue":MAX_TIMELINE_PAGES,"timeline_items_per_issue":MAX_TIMELINE_ITEMS,
            "linked_pr_reads_per_issue":MAX_PR_CANDIDATES,"comment_pages_per_issue":MAX_COMMENT_PAGES,
            "comment_items_per_issue":MAX_COMMENT_ITEMS,"request_total_deadline_seconds":30},
        "description":"Offline default performs no requests or credential lookup. Online requires explicit permission and a stdin token. Each bounded GET uses its own shared governor lease, no redirects or retries. Stops on unsafe response; ambiguous per-issue link/claim evidence excludes that issue. Truncated issue enumeration blocks the scan. Recent comments, claim/lease markers, assigned issues and confirmed open linked PRs exclude candidates. No claim, PR creation, or merge. Discovery is a point-in-time observation, not a lifecycle write gate or online acceptance proof."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn later_retry_after_survives_duplicate_metadata_refusal_and_failed_body() {
        use std::os::unix::fs::DirBuilderExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
        }
        for (first, status, challenge) in [("1",200,false), ("malformed",200,false),
            ("1",429,true), ("malformed",429,true)] {
            let root = std::env::temp_dir().join(format!("buaa-contribution-retry-{}-{}-{}",
                std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)));
            std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let fixture = Fixture(root);
            let governor = Governor::isolated_for_test(&fixture.0.join("governor")).unwrap();
            let mut lease = governor.try_acquire(crate::governor::RequestKind::Interactive).unwrap();
            let mut headers = reqwest::header::HeaderMap::new();
            headers.append("retry-after", reqwest::header::HeaderValue::from_str(first).unwrap());
            headers.append("retry-after", reqwest::header::HeaderValue::from_static("1800"));
            // Duplicate metadata still refuses admission, but every cooldown
            // must already be durable before a failed body closes the lease.
            observe_github_headers(&mut lease, status, &headers, challenge).unwrap();
            lease.finish(Outcome::Http { status, retry_after:Some(first), challenge,
                network_failure:true }).unwrap();
            let state = governor.status().unwrap();
            assert!(state.cooldown_wait > std::time::Duration::from_secs(1700));
            assert_eq!(state.safety_latched, false);
            assert!(governor.try_acquire(crate::governor::RequestKind::Interactive).is_err());
        }
    }
    fn permissions(admin: bool, maintain: bool, push: bool, triage: bool) -> Value {
        json!({
            "admin": admin,
            "maintain": maintain,
            "push": push,
            "triage": triage,
            "pull": true
        })
    }
    fn repository(permissions: Option<Value>) -> Vec<u8> {
        let mut value = json!({
            "full_name": "octo/repo",
            "archived": false,
            "disabled": false
        });
        if let Some(permissions) = permissions {
            value["permissions"] = permissions;
        }
        serde_json::to_vec(&value).unwrap()
    }
    fn issue(number: u64) -> Value {
        json!({
            "number": number,
            "state": "open",
            "title": format!("synthetic issue {number}"),
            "html_url": format!("https://github.com/octo/repo/issues/{number}"),
            "assignee": null,
            "assignees": [],
            "body": "untrusted issue body"
        })
    }
    fn items(values: Vec<Value>) -> Vec<Value> {
        values
    }
    fn now() -> i64 {
        DateTime::parse_from_rfc3339("2026-10-27T12:00:00Z")
            .unwrap()
            .timestamp()
    }
    #[test]
    fn authenticated_permissions_are_required_and_write_is_never_inferred() {
        let error = parse_repository(&repository(None), "octo/repo").unwrap_err();
        assert_eq!(error, super::RepositoryParseError::MissingPermissions);

        let read_only = parse_repository(
            &repository(Some(permissions(false, false, false, false))),
            "octo/repo",
        )
        .unwrap();
        assert!(!read_only.permissions.can_write());
        assert!(!read_only.permissions.can_triage());

        let triage_only = parse_repository(
            &repository(Some(permissions(false, false, false, true))),
            "octo/repo",
        )
        .unwrap();
        assert!(!triage_only.permissions.can_write());
        assert!(triage_only.permissions.can_triage());

        let push = parse_repository(
            &repository(Some(permissions(false, false, true, false))),
            "octo/repo",
        )
        .unwrap();
        assert!(push.permissions.can_write());
    }
    #[test]
    fn prs_non_open_and_assigned_issues_are_not_unclaimed_candidates() {
        let mut pull_request = issue(1);
        pull_request["pull_request"] = json!({"url": "synthetic-pr-metadata"});
        let mut closed = issue(2);
        closed["state"] = json!("closed");
        let mut assigned = issue(3);
        assigned["assignees"] = json!([{"login": "untrusted-assignee"}]);
        let open = issue(4);
        let parsed = parse_issues(&items(vec![pull_request, closed, assigned, open]), "octo/repo")
            .unwrap();
        assert_eq!(parsed.filtered_pull_requests, 1);
        assert_eq!(parsed.issues.len(), 3);
        assert_eq!(parsed.issues[0].initial_reasons, ["not_open"]);
        assert_eq!(parsed.issues[1].initial_reasons, ["assigned"]);
        assert!(parsed.issues[2].initial_reasons.is_empty());
    }
    #[test]
    fn issue_urls_must_be_actual_canonical_github_issue_urls() {
        let mut spoofed = issue(7);
        spoofed["html_url"] = json!("https://example.invalid/issues/7");
        assert!(parse_issues(&items(vec![spoofed]), "octo/repo").is_err());

        let mut pull_request = issue(8);
        pull_request["html_url"] = json!("https://example.invalid/pull/8");
        pull_request["pull_request"] = Value::Null;
        let parsed = parse_issues(&items(vec![pull_request]), "octo/repo").unwrap();
        assert_eq!(parsed.filtered_pull_requests, 1);
        assert!(parsed.issues.is_empty());
    }
    #[test]
    fn claim_markers_need_a_word_boundary() {
        for negative in [
            "please review this issue",
            "we plan to release it soon",
            "this one is unclaimed",
        ] {
            assert!(
                !claim_or_lease_marker(negative),
                "{negative} must not be a claim"
            );
        }
        for positive in [
            "I claim this issue",
            "claimed",
            "claims",
            "lease",
            "leasing this one",
            "working on this",
            "I'll take it",
            "I will take it",
            "taking this",
            "我来认领",
            "我接手了",
        ] {
            assert!(
                claim_or_lease_marker(positive),
                "{positive} must be a claim"
            );
        }
    }
    #[test]
    fn claim_window_boundary_and_invalid_timestamps() {
        let comment = json!({
            "body": "I claim this",
            "created_at": "2026-10-24T12:00:00Z",
            "updated_at": "2026-10-24T12:00:00Z"
        });
        assert!(comment_claims_issue(&comment, now()).unwrap());

        let just_outside = json!({
            "body": "I claim this",
            "created_at": "2026-10-24T11:59:59Z",
            "updated_at": "2026-10-24T11:59:59Z"
        });
        assert!(!comment_claims_issue(&just_outside, now()).unwrap());

        let invalid = json!({
            "body": "I claim this",
            "created_at": "not-a-timestamp",
            "updated_at": "not-a-timestamp"
        });
        assert!(comment_claims_issue(&invalid, now()).is_err());

        let outside = json!({
            "body": "I claim this",
            "created_at": "2026-10-20T12:00:00Z",
            "updated_at": "2026-10-20T12:00:00Z"
        });
        assert!(!comment_claims_issue(&outside, now()).unwrap());
    }
    #[test]
    fn pull_request_identity_is_parsed_from_a_github_api_url() {
        let candidate = parse_pr_identity("https://api.github.com/repos/octo/repo/pulls/42").unwrap();
        assert_eq!(candidate.owner, "octo");
        assert_eq!(candidate.name, "repo");
        assert_eq!(candidate.number, 42);
        assert!(parse_pr_identity("https://example.invalid/repos/octo/repo/pulls/42").is_none());
        assert!(parse_pr_identity("https://api.github.com/repos/octo/repo/issues/42").is_none());
    } 
    struct Pages(std::cell::RefCell<std::collections::VecDeque<(String, PageEvidence)>>);
    impl GithubRead for Pages {
        fn get(&self, url: &str) -> Result<PageEvidence, GithubFailure> {
            let (expected,page) = self.0.borrow_mut().pop_front().expect("unexpected request");
            assert_eq!(url,expected);
            Ok(page)
        }
    }
    fn page(items: Value, link: Option<String>) -> PageEvidence {
        PageEvidence {
            status: 200,
            link: link.map(zeroize::Zeroizing::new),
            body_complete: true,
            body: zeroize::Zeroizing::new(serde_json::to_vec(&items).unwrap()),
        }
    }
    #[test]
    fn later_comment_pages_preserve_recent_claims() {
        let first = "https://api.github.com/repos/octo/repo/issues/1/comments?per_page=100";
        let second = format!("{first}&page=2");
        let pages = Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
            (first.to_owned(),page(json!([]),Some(format!("<{second}>; rel=\"next\"")))),
            (second,page(json!([{"body":"I claim this", "created_at":"2026-10-27T11:00:00Z", "updated_at":"2026-10-27T11:00:00Z"}]),None))
        ])));
        let (all,truncated) = pages.get_pages(first,10,1000,None).unwrap_or_else(|_| panic!("fixture failed"));
        assert_eq!(all.len(),2); assert!(!truncated);
        assert!(all.iter().flat_map(|p| &p.items).any(|c| comment_claims_issue(c,now()) == Ok(true)));
        assert!(pages.0.borrow().is_empty());
    }
    #[test]
    fn bounded_pagination_never_treats_truncation_as_complete() {
        let url="https://api.github.com/repos/octo/repo/issues?per_page=100";
        let pages=Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
            (url.to_owned(),page(json!([]),Some(format!("<{url}&page=2>; rel=\"next\""))))
        ])));
        assert!(pages.get_pages(url,1,1000,None).unwrap_or_else(|_|panic!("fixture failed")).1);
    }
    #[test]
    fn later_timeline_page_requires_live_pull_request_state() {
        let first="https://api.github.com/repos/octo/repo/issues/1/timeline?per_page=100";
        let second=format!("{first}&page=2");
        let pr="https://api.github.com/repos/octo/repo/pulls/42";
        let pages=Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
            (first.to_owned(),page(json!([]),Some(format!("<{second}>; rel=\"next\"")))),
            (second,page(json!([{"event":"cross-referenced","source":{"issue":{"pull_request":{"url":pr}}}}]),None)),
            (pr.to_owned(),page(json!({"number":42,"state":"open"}),None))
        ])));
        let (timeline,truncated)=pages.get_pages(first,5,500,None).unwrap_or_else(|_|panic!("fixture failed"));
        assert!(matches!(analyze_link(&pages,&timeline,truncated),Ok(LinkVerdict::LinkedOpen)));
        assert!(pages.0.borrow().is_empty());
    }
    #[test]
    fn null_pull_request_marker_stays_unknown_not_eligible() {
        let first="https://api.github.com/repos/octo/repo/issues/1/timeline?per_page=100";
        let pages=Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
            (first.to_owned(),page(json!([{"event":"cross-referenced","source":{"issue":{"pull_request":null}}}]),None))
        ])));
        let (timeline,truncated)=pages.get_pages(first,5,500,None).unwrap_or_else(|_|panic!("fixture failed"));
        assert!(matches!(analyze_link(&pages,&timeline,truncated),Ok(LinkVerdict::Unknown(_))));
        // The unresolved marker must not trigger a live pull request read.
        assert!(pages.0.borrow().is_empty());
    }
    #[test]
    fn scan_excludes_issue_with_null_cross_reference_marker() {
        let request = ScanRequest::from_input(r#"{"repository":"octo/repo"}"#).unwrap();
        let pages = Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
            ("https://api.github.com/repos/octo/repo".to_owned(),
                page(json!({"id":123,"full_name":"octo/repo","archived":false,"disabled":false,
                    "permissions":permissions(false,false,true,true)}),None)),
            ("https://api.github.com/repos/octo/repo/issues?state=open&per_page=100".to_owned(),
                page(json!([issue(1)]),None)),
            ("https://api.github.com/repos/octo/repo/issues/1/timeline?per_page=100".to_owned(),
                page(json!([{"event":"cross-referenced","source":{"issue":{"pull_request":null}}}]),None)),
        ])));
        let output = scan_with_reader(&request, &pages).unwrap();
        assert_eq!(output["result"], "scan_completed");
        assert_eq!(output["candidates"], json!([]));
        assert_eq!(output["excluded"][0]["reasons"], json!(["linked_pr_status_unknown"]));
        assert!(pages.0.borrow().is_empty());
    }

    #[test]
    fn pagination_rejects_cross_endpoint_and_cycles() {
        let url="https://api.github.com/repos/octo/repo/issues";
        for next in [url,"https://api.github.com/repos/other/repo/issues"] {
            let pages=Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
                (url.to_owned(),page(json!([]),Some(format!("<{next}>; rel=\"next\""))))
            ])));
            assert!(pages.get_pages(url,10,1000,None).is_err());
        }
        assert!(next_page_url(Some("<https://evil.invalid/>; rel=\"next\"")).is_err());
    }
    #[test]
    fn numeric_pagination_requires_repository_identity_and_collection() {
        let first = "/repos/octo/repo/issues/1/comments";
        let linked = "/repositories/123/issues/1/comments";
        assert!(pagination_path_allowed(first, linked, Some(123)));
        assert!(!pagination_path_allowed(first, linked, Some(124)));
        assert!(!pagination_path_allowed(first, linked, None));
        assert!(!pagination_path_allowed(first, "/repositories/123/issues/2/comments", Some(123)));
    }
    #[test]
    fn offline_default_never_requires_a_transport() {
        let out=scan(r#"{"repository":"octo/repo"}"#).unwrap();
        assert_eq!(out["reason"],"explicit_online_permission_required");
        assert_eq!(out["write_operations_performed"],false);
    }
    #[test]
    fn decoded_secret_reflection_is_private() {
        // A literal reflection and a JSON-escaped reflection are both
        // detected without materializing an ordinary Value.
        assert_eq!(
            secret_reflection(br#"{"nested":["private_token"]}"#,"private_token",true),
            SecretReflection::Present
        );
        assert_eq!(
            secret_reflection(br#"{"nested":["private\u005ftoken"]}"#,"private_token",true),
            SecretReflection::Present
        );
        assert_eq!(
            secret_reflection(br#"{"private\u005ftoken":"value"}"#,"private_token",true),
            SecretReflection::Present
        );
        assert_eq!(
            secret_reflection(br#"{"nested":["unrelated"]}"#,"private_token",true),
            SecretReflection::Absent
        );
        assert_eq!(
            secret_reflection(br#"{"nested":["a\nclean\tvalue"]}"#,"private_token",true),
            SecretReflection::Absent
        );
        // An undecodable escape leaves the reflection unresolved, so the
        // response cannot be admitted.
        assert_eq!(
            secret_reflection(br#"{"nested":["private\u00zztoken"]}"#,"private_token",true),
            SecretReflection::Unresolved
        );
        assert!(serde_json::from_str::<ScanRequest>(r#"{"repository":"octo/repo","github_token":"bad secret"}"#).is_err());
        // Standard JSON escapes are accepted by the real typed input path.
        let escaped = r#"{"repository":"octo\/repo","github_token":"ghp_\u0073ecret"}"#;
        let request = ScanRequest::from_input(escaped).unwrap();
        assert_eq!(request.repository, "octo/repo");
        assert_eq!(request.github_token.as_ref().unwrap().0.as_str(), "ghp_secret");
        let output = scan(escaped).unwrap();
        assert_eq!(output["reason"], "explicit_online_permission_required");
        assert!(!output.to_string().contains("ghp_secret"));
        assert!(!output.to_string().contains(r"\u0073"));
    }
    #[test]
    fn scan_rejects_top_level_arrays_and_keeps_tokens_private() {
        // Positional struct arrays are not the declared object input.
        assert!(ScanRequest::from_input(r#"["octo/repo"]"#).is_err());
        assert!(ScanRequest::from_input(r#"["octo/repo", true, "ghp_synth01"]"#).is_err());
        assert!(ScanRequest::from_input("[]").is_err());
        // Standard JSON whitespace stays accepted.
        let spaced = ScanRequest::from_input(" { \"repository\" : \"octo/repo\" } ");
        assert_eq!(spaced.unwrap().repository, "octo/repo");
        // A rejected array input must not echo a synthetic token in the error
        // or in any retained value; deserialization stops before materializing
        // an ordinary Value.
        let token = "ghp_synth01";
        let error = scan(&format!(r#"["octo/repo", true, "{token}"]"#)).unwrap_err();
        assert_eq!(error.code, "invalid_input");
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(token), "error must not echo the token");
        assert!(ScanRequest::from_input("{\"repository\":\"octo/repo\"} true").is_err());
        assert!(ScanRequest::from_input("{\"repository\":\"octo/repo\",\"other\":1}").is_err());
        let offline = scan("\t\r\n {\"repository\":\"octo/repo\",\"github_token\":\"ghp_synthetic_token\"} \r\n").unwrap();
        assert_eq!(offline["reason"], "explicit_online_permission_required");
        assert!(!offline.to_string().contains("ghp_synthetic_token"));
    }
}
