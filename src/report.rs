//! Agent/user self-reporting: create a GitHub Issue via the local `gh` CLI.
//! Never fabricates an Issue URL; fails closed when `gh` is unavailable or its
//! writer outcome cannot be reconciled.
//!
//! This command is deliberately **not a redactor**: sanitizing private content
//! stays the reporting operator's/Agent's job and the body is published as
//! supplied. The one exception is a bounded pre-write refusal: a title or body
//! that looks like it carries credentials (cookie/authorization headers, secret
//! assignments, known token prefixes, JWTs, PEM private keys, or a long base64
//! blob beside a secret marker) is not published at all. A refusal reports the
//! credential *shape* label only, never the matched text, and writes nothing.

use serde::Deserialize;
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::io::Write;
use std::process::{Command, Stdio};

const REPO: &str = "cyjin-yl/buaa-cli";
const GH_REPO: &str = "github.com/cyjin-yl/buaa-cli";
const ISSUE_URL_PREFIX: &str = "https://github.com/cyjin-yl/buaa-cli/issues/";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportRequest {
    title: String,
    body: String,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GhAuthFailure {
    Missing,
    NotAuthenticated,
    Unavailable,
}

enum GhIssueOutcome {
    Created(String),
    Unknown,
}

fn invalid_input() -> crate::net::Error {
    crate::net::Error::new(
        "invalid_input",
        "report input must contain only title/body strings and optional string labels",
    )
}

fn gh_auth_status(command: &OsStr) -> Result<(), GhAuthFailure> {
    let output = Command::new(command)
        .args(["auth", "status", "-h", "github.com"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                GhAuthFailure::Missing
            } else {
                GhAuthFailure::Unavailable
            }
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(GhAuthFailure::NotAuthenticated)
    }
}

fn canonical_issue_url(value: &str) -> bool {
    let Some(id) = value.strip_prefix(ISSUE_URL_PREFIX) else {
        return false;
    };
    let Some(first) = id.as_bytes().first() else {
        return false;
    };
    *first != b'0' && id.bytes().all(|byte| byte.is_ascii_digit())
}

fn gh_create_issue(command: &OsStr, request: &ReportRequest) -> GhIssueOutcome {
    let mut invocation = Command::new(command);
    invocation.args([
        "issue",
        "create",
        "--repo",
        GH_REPO,
        "--title",
        request.title.as_str(),
        "--body-file",
        "-",
    ]);
    for label in &request.labels {
        invocation.args(["--label", label.as_str()]);
    }

    let mut child = match invocation
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return GhIssueOutcome::Unknown,
    };

    let body_delivered = child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(request.body.as_bytes()).is_ok())
        .unwrap_or(false);
    if !body_delivered {
        let _ = child.kill();
        let _ = child.wait();
        return GhIssueOutcome::Unknown;
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(_) => return GhIssueOutcome::Unknown,
    };
    if !output.status.success() {
        return GhIssueOutcome::Unknown;
    }

    let Ok(raw_url) = std::str::from_utf8(&output.stdout) else {
        return GhIssueOutcome::Unknown;
    };
    let url = raw_url.trim();
    if canonical_issue_url(url) {
        GhIssueOutcome::Created(url.to_owned())
    } else {
        GhIssueOutcome::Unknown
    }
}

fn blocked(failure: GhAuthFailure) -> Value {
    let (reason, next_steps) = match failure {
        GhAuthFailure::Missing => (
            "the local gh CLI is not installed or executable",
            vec![
                "Install GitHub CLI: https://cli.github.com/",
                "Run: gh auth login",
                "Then retry: buaa report",
            ],
        ),
        GhAuthFailure::NotAuthenticated => (
            "authentication for github.com could not be confirmed",
            vec![
                "Run: gh auth status -h github.com",
                "If not logged in, run: gh auth login",
                "Then retry: buaa report",
            ],
        ),
        GhAuthFailure::Unavailable => (
            "the local gh CLI could not be started",
            vec![
                "Install GitHub CLI: https://cli.github.com/",
                "Run: gh auth login",
                "Then retry: buaa report",
            ],
        ),
    };
    json!({
        "schema_version": 1,
        "type": "report",
        "result": "blocked",
        "reason": reason,
        "next_steps": next_steps
    })
}

fn unknown_outcome(request: &ReportRequest) -> Value {
    json!({
        "schema_version": 1,
        "type": "report",
        "result": "unknown_outcome",
        "url": null,
        "repo": REPO,
        "title": &request.title,
        "labels": &request.labels,
        "reconciliation": "required",
        "automatic_retry": false,
        "reason": "gh issue writer did not return a canonical Issue URL; reconcile the repository before retrying"
    })
}

/// Bounded credential shapes refused before any write. Labels are constant
/// text, so a refusal can never echo the value that triggered it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialShape {
    PrivateKeyBlock,
    KnownTokenPrefix,
    Jwt,
    CookieHeader,
    AuthorizationHeader,
    SessionCookie,
    SecretAssignment,
    EncodedSecret,
}

impl CredentialShape {
    const fn label(self) -> &'static str {
        match self {
            Self::PrivateKeyBlock => "private_key_block",
            Self::KnownTokenPrefix => "known_token_prefix",
            Self::Jwt => "jwt",
            Self::CookieHeader => "cookie_header",
            Self::AuthorizationHeader => "authorization_header",
            Self::SessionCookie => "session_cookie",
            Self::SecretAssignment => "secret_assignment",
            Self::EncodedSecret => "encoded_secret",
        }
    }
}

/// Field names that are credential keys only in an assignment position.
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth_token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "access-key",
    "secret_key",
    "secret-key",
    "private_key",
    "client_secret",
    "client-secret",
];

/// Cookie/session names whose `name=value` pair is a credential.
const SESSION_COOKIE_NAMES: &[&str] = &[
    "castgc",
    "jsessionid",
    "sessionid",
    "session_id",
    "phpsessid",
    "csrftoken",
    "csrf_token",
    "xsrf-token",
    "xsrf_token",
];

/// Words that turn a long opaque base64 run into a likely encoded credential.
const SECRET_MARKERS: &[&str] = &[
    "cookie",
    "authorization",
    "bearer",
    "password",
    "passwd",
    "token",
    "secret",
    "credential",
    "session",
    "castgc",
    "jsessionid",
];

/// Values that are obviously placeholders rather than live secrets.
const PLACEHOLDERS: &[&str] = &[
    "redacted",
    "removed",
    "withheld",
    "placeholder",
    "none",
    "null",
    "empty",
    "omitted",
    "censored",
    "example",
    "secret",
    "token",
    "password",
    "value",
];

fn refused(field: &'static str, shape: CredentialShape) -> Value {
    json!({
        "schema_version": 1,
        "type": "report",
        "result": "refused",
        "field": field,
        "detected": shape.label(),
        "reason": format!(
            "report {field} contains credential-shaped content ({}); nothing was written",
            shape.label()
        ),
        "next_steps": [
            "Remove the credential from the report; buaa report refuses to publish it and does not redact it for you.",
            "Describe the secret by its SHA-256, or replace it with a placeholder such as <redacted>.",
            "Report the vulnerability privately instead: https://github.com/cyjin-yl/buaa-cli/security/advisories/new",
            "Then retry: buaa report"
        ]
    })
}

/// Scan the two published text fields for credential shapes. The title is
/// checked first because it is equally public, and both are checked before the
/// `gh` CLI is probed or invoked.
fn credential_shape(title: &str, body: &str) -> Option<(&'static str, CredentialShape)> {
    if let Some(shape) = scan_text(title) {
        return Some(("title", shape));
    }
    if let Some(shape) = scan_text(body) {
        return Some(("body", shape));
    }
    None
}

fn scan_text(text: &str) -> Option<CredentialShape> {
    let mut previous: Option<&str> = None;
    for line in text.split('\n') {
        if let Some(shape) = scan_line(line) {
            return Some(shape);
        }
        // A secret marker on one line with an opaque blob on the adjacent line
        // is still the same declaration; do not let a newline hide it.
        let prior = previous.unwrap_or("");
        if (has_secret_marker(prior) && has_long_base64(line))
            || (has_secret_marker(line) && has_long_base64(prior))
        {
            return Some(CredentialShape::EncodedSecret);
        }
        previous = Some(line);
    }
    None
}

fn scan_line(line: &str) -> Option<CredentialShape> {
    if has_private_key_block(line) {
        return Some(CredentialShape::PrivateKeyBlock);
    }
    if has_known_token_prefix(line) {
        return Some(CredentialShape::KnownTokenPrefix);
    }
    if has_jwt(line) {
        return Some(CredentialShape::Jwt);
    }
    if ci_contains(line, "cookie:") {
        return Some(CredentialShape::CookieHeader);
    }
    if header_secret(line, "authorization") || has_bearer_token(line) {
        return Some(CredentialShape::AuthorizationHeader);
    }
    if SESSION_COOKIE_NAMES
        .iter()
        .any(|name| has_secret_assignment(line, name))
    {
        return Some(CredentialShape::SessionCookie);
    }
    if SECRET_KEYS
        .iter()
        .any(|key| has_secret_assignment(line, key))
    {
        return Some(CredentialShape::SecretAssignment);
    }
    if has_secret_marker(line) && has_long_base64(line) {
        return Some(CredentialShape::EncodedSecret);
    }
    None
}

/// ASCII-only, allocation-free case-insensitive substring search. Every needle
/// is lowercase ASCII, so a match can never start inside a UTF-8 sequence.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .find(|&index| haystack[index..index + needle.len()].eq_ignore_ascii_case(needle))
}

fn ci_contains(haystack: &str, needle: &str) -> bool {
    find_ci(haystack, needle).is_some()
}

fn wordish(byte: u8) -> bool {
    !byte.is_ascii() || byte.is_ascii_alphanumeric() || byte == b'_'
}

fn boundary_before(haystack: &[u8], index: usize) -> bool {
    index == 0 || !wordish(haystack[index - 1])
}

fn boundary_after(haystack: &[u8], index: usize) -> bool {
    haystack.get(index).is_none_or(|byte| !wordish(*byte))
}

/// Extract the `key=value` / `key: value` / `"key": "value"` value that follows
/// an already-matched key, without copying.
fn assignment_value(rest: &str) -> Option<&str> {
    let trimmed = rest.trim_start_matches([' ', '\t', '"', '\'']);
    let trimmed = trimmed
        .strip_prefix('=')
        .or_else(|| trimmed.strip_prefix(':'))?;
    let value = trimmed.trim_start_matches([' ', '\t', '"', '\'']);
    let end = value
        .find(|c: char| {
            c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\'' | '}' | ']' | ')' | '`')
        })
        .unwrap_or(value.len());
    Some(&value[..end])
}

/// Inspect every assignment, including values following harmless placeholders.
fn has_secret_assignment(line: &str, key: &str) -> bool {
    let bytes = line.as_bytes();
    let mut start = 0;
    while let Some(relative) = find_ci(&line[start..], key) {
        let at = start + relative;
        if boundary_before(bytes, at) && boundary_after(bytes, at + key.len()) {
            if let Some(value) = assignment_value(&line[at + key.len()..]) {
                if !value.is_empty() && looks_like_secret(value) {
                    return true;
                }
            }
        }
        start = at + key.len();
    }
    false
}

/// Text after `name:` when it is used as an HTTP-style header.
fn header_rest<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let bytes = line.as_bytes();
    let mut start = 0;
    while let Some(relative) = find_ci(&line[start..], name) {
        let at = start + relative;
        if boundary_before(bytes, at) && boundary_after(bytes, at + name.len()) {
            let rest = line[at + name.len()..].trim_start_matches([' ', '\t', '"', '\'']);
            if let Some(rest) = rest.strip_prefix(':') {
                return Some(rest.trim_start());
            }
        }
        start = at + name.len();
    }
    None
}

fn header_secret(line: &str, name: &str) -> bool {
    let Some(rest) = header_rest(line, name) else {
        return false;
    };
    let mut parts = rest.split_whitespace();
    let Some(first) = parts.next() else {
        return false;
    };
    let scheme = ["bearer", "basic", "digest", "negotiate", "token"]
        .iter()
        .any(|scheme| first.eq_ignore_ascii_case(scheme));
    if scheme {
        return parts
            .next()
            .is_some_and(|value| looks_like_secret(value) || looks_like_credential_token(value));
    }
    looks_like_secret(first)
}

fn has_bearer_token(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut start = 0;
    while let Some(relative) = find_ci(&line[start..], "bearer") {
        let at = start + relative;
        if boundary_before(bytes, at) {
            let rest = line[at + "bearer".len()..].trim_start_matches([' ', '\t', ':', '"', '\'']);
            let value = rest
                .split(|c: char| {
                    c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\'' | '}' | ']' | ')')
                })
                .next()
                .unwrap_or("");
            if looks_like_secret(value) {
                return true;
            }
        }
        start = at + "bearer".len();
    }
    false
}

fn has_private_key_block(line: &str) -> bool {
    ci_contains(line, "-----begin") && ci_contains(line, "private key-----")
}

fn has_known_token_prefix(line: &str) -> bool {
    const PREFIXES: &[(&str, usize)] = &[
        ("ghp_", 10),
        ("gho_", 10),
        ("ghu_", 10),
        ("ghs_", 10),
        ("ghr_", 10),
        ("github_pat_", 10),
        ("xoxb-", 10),
        ("xoxp-", 10),
        ("xoxa-", 10),
        ("xoxr-", 10),
        ("xoxs-", 10),
        ("akia", 16),
        ("asia", 16),
        ("aiza", 30),
        ("sk-", 20),
    ];
    let bytes = line.as_bytes();
    PREFIXES.iter().any(|(prefix, minimum)| {
        let mut start = 0;
        while let Some(relative) = find_ci(&line[start..], prefix) {
            let at = start + relative;
            let tail = &bytes[at + prefix.len()..];
            if boundary_before(bytes, at)
                && tail.len() >= *minimum
                && tail
                    .iter()
                    .take(*minimum)
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
            {
                return true;
            }
            start = at + prefix.len();
        }
        false
    })
}

fn base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+' | b'/' | b'=')
}

fn has_jwt(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        if bytes[index..].starts_with(b"eyJ") {
            let mut dots = 0;
            let mut run = 0;
            let mut cursor = index;
            while cursor < bytes.len() && (bytes[cursor] == b'.' || base64_byte(bytes[cursor])) {
                if bytes[cursor] == b'.' {
                    dots += 1;
                } else {
                    run += 1;
                }
                cursor += 1;
            }
            if dots >= 2 && run >= 32 {
                return true;
            }
        }
        index += 1;
    }
    false
}

fn has_long_base64(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !base64_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && base64_byte(bytes[index]) {
            index += 1;
        }
        if base64_run_is_opaque(&bytes[start..index]) {
            return true;
        }
    }
    false
}

/// Long runs count only when they look random: base64 symbols, or mixed case
/// plus digits. Lower- or upper-only hex digests stay unflagged, so ordinary
/// SHA-256 hashes in bug reports do not trigger a refusal.
fn base64_run_is_opaque(run: &[u8]) -> bool {
    if run.len() < 40 {
        return false;
    }
    let upper = run.iter().any(|byte| byte.is_ascii_uppercase());
    let lower = run.iter().any(|byte| byte.is_ascii_lowercase());
    let digit = run.iter().any(|byte| byte.is_ascii_digit());
    let strong = run.iter().any(|byte| matches!(*byte, b'+' | b'/' | b'='));
    (strong && (upper || lower || digit))
        || (run.len() >= 48 && upper && lower && digit)
        || (run.len() >= 120 && (upper || lower))
}

fn has_secret_marker(line: &str) -> bool {
    SECRET_MARKERS
        .iter()
        .any(|marker| ci_contains(line, marker))
}

fn is_placeholder(value: &str) -> bool {
    PLACEHOLDERS.iter().any(|placeholder| {
        placeholder.len() == value.len()
            && placeholder
                .as_bytes()
                .eq_ignore_ascii_case(value.as_bytes())
    })
}

/// Opaque credential token supplied after an authentication scheme. Shorter
/// than a full blob, so it needs a digit, padding or a dotted/encoded shape
/// before it counts; a plain English word after `Bearer` stays unflagged.
fn looks_like_credential_token(value: &str) -> bool {
    if value.len() < 12 || is_placeholder(value) {
        return false;
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_' | b'.')
    }) {
        return false;
    }
    value.bytes().any(|byte| byte.is_ascii_digit())
        || value.len() >= 20
        || value
            .bytes()
            .any(|byte| matches!(byte, b'+' | b'/' | b'=' | b'.'))
}

/// Bounded plausibility check for a credential value. Shape-only: a short
/// English phrase after a secret-looking key is not treated as a secret.
fn looks_like_secret(raw: &str) -> bool {
    let value = raw.trim_matches(|c: char| {
        c.is_ascii_punctuation() && !matches!(c, '+' | '/' | '=' | '-' | '_')
    });
    if value.len() < 6 || is_placeholder(value) {
        return false;
    }
    let mut digits = false;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            digits = true;
        } else if !(byte.is_ascii_alphabetic()
            || matches!(byte, b'-' | b'_' | b'+' | b'/' | b'=' | b'.' | b'~'))
        {
            return false;
        }
    }
    digits || value.len() >= 20
}

fn report_with_command(input: &str, command: &OsStr) -> Result<Value, crate::net::Error> {
    let request: ReportRequest = serde_json::from_str(input).map_err(|_| invalid_input())?;

    // Credential-shaped payloads are refused before `gh` is probed or spawned.
    // The scan is bounded and label-only: it never rewrites the payload and
    // never echoes the matched text.
    if let Some((field, shape)) = credential_shape(&request.title, &request.body) {
        return Ok(refused(field, shape));
    }

    if let Err(failure) = gh_auth_status(command) {
        return Ok(blocked(failure));
    }

    let outcome = gh_create_issue(command, &request);
    match outcome {
        GhIssueOutcome::Created(url) => Ok(json!({
            "schema_version": 1,
            "type": "report",
            "result": "created",
            "url": url,
            "repo": REPO,
            "title": request.title,
            "labels": request.labels
        })),
        GhIssueOutcome::Unknown => Ok(unknown_outcome(&request)),
    }
}

pub fn report(input: &str) -> Result<Value, crate::net::Error> {
    report_with_command(input, OsStr::new("gh"))
}

pub fn schema() -> Value {
    json!({
        "input": {
            "type":"object", "additionalProperties":false, "required":["title","body"],
            "properties": {
                "title":{"type":"string"}, "body":{"type":"string"},
                "labels":{"type":"array","items":{"type":"string"}}
            }
        },
        "output": {
            "type":"object", "required":["schema_version","type","result"],
            "properties": {
                "schema_version":{"const":1}, "type":{"const":"report"},
                "result":{"enum":["created","blocked","refused","unknown_outcome"]},
                "url":{"type":["string","null"],"pattern":"^https://github[.]com/cyjin-yl/buaa-cli/issues/[1-9][0-9]*$"},
                "reason":{"type":"string"},
                "next_steps":{"type":"array","items":{"type":"string"}},
                "field":{"enum":["title","body"]},
                "detected":{"type":"string","description":"Static credential-shape label; never the matched text."}
            },
            "allOf":[
                {"if":{"properties":{"result":{"const":"created"}}},"then":{"required":["url"],"properties":{"url":{"type":"string"}}}},
                {"if":{"properties":{"result":{"const":"blocked"}}},"then":{"required":["reason","next_steps"]}},
                {"if":{"properties":{"result":{"const":"refused"}}},"then":{"required":["field","detected","reason","next_steps"],"not":{"required":["url"]}}},
                {"if":{"properties":{"result":{"const":"unknown_outcome"}}},"then":{"required":["url","reconciliation","automatic_retry"],"properties":{"url":{"const":null},"reconciliation":{"const":"required"},"automatic_retry":{"const":false}}}}
            ]
        },
        "description":"Explicit sanitized GitHub Issue write through gh. Blocked or uncertain results are not created Issues; reconcile unknown outcomes before retrying. Body is delivered via stdin, never argv. This command is not a redactor: the operator remains responsible for private content. The single refusal is a bounded pre-write scan of title and body for credential shapes (cookie/authorization headers, secret assignments, known token prefixes, JWTs, PEM private keys, long base64 beside secret markers); it writes nothing, reports only the shape label, and leaves all other content unaltered."
    })
}

#[cfg(test)]
mod tests {
    use super::{CredentialShape, canonical_issue_url, credential_shape, report_with_command};
    use serde_json::Value;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "buaa-report-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            Self { root }
        }

        fn command(&self, script: &str) -> PathBuf {
            let path = self.root.join("gh");
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn valid_input() -> &'static str {
        r#"{"title":"synthetic report","body":"synthetic body","labels":["fallback"]}"#
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn malformed_or_spoofed_input_is_rejected_before_any_gh_call() {
        let fixture = Fixture::new();
        let marker = fixture.path("called");
        let command = fixture.command(&format!(
            "#!/bin/sh\nprintf called > '{}'\n",
            marker.display()
        ));
        let error = report_with_command(
            r#"{"title":"ok","body":"body","result":"created","url":"https://github.com/cyjin-yl/buaa-cli/issues/7"}"#,
            command.as_os_str(),
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_input");
        assert!(!marker.exists());

        let error = report_with_command(
            r#"{"title":"ok","body":"body","labels":[7]}"#,
            command.as_os_str(),
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_input");
        assert!(!marker.exists());
    }

    #[test]
    fn missing_gh_and_logged_out_gh_keep_distinct_sanitized_guidance() {
        let fixture = Fixture::new();
        let missing = fixture.path("not-installed");
        let blocked = report_with_command(valid_input(), missing.as_os_str()).unwrap();
        assert_eq!(blocked["result"], "blocked");
        assert!(
            blocked["next_steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step == "Install GitHub CLI: https://cli.github.com/")
        );

        let logged_out =
            fixture.command("#!/bin/sh\nprintf '%s' 'synthetic-auth-secret' >&2\nexit 1\n");
        let blocked = report_with_command(valid_input(), logged_out.as_os_str()).unwrap();
        assert_eq!(blocked["result"], "blocked");
        assert!(!blocked.to_string().contains("synthetic-auth-secret"));
        assert!(
            blocked["next_steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| {
                    step.as_str()
                        .is_some_and(|value| value.contains("gh auth login"))
                })
        );
    }

    #[test]
    fn issue_body_is_delivered_on_stdin_and_not_in_writer_arguments() {
        let fixture = Fixture::new();
        let args = fixture.path("args");
        let body = fixture.path("body");
        let command = fixture.command(&format!(
            "#!/bin/sh\nif [ \"$1\" = auth ]; then exit 0; fi\nprintf '%s\\n' \"$@\" > '{}'\ncat > '{}'\nprintf '%s\\n' 'https://github.com/cyjin-yl/buaa-cli/issues/42'\n",
            args.display(),
            body.display()
        ));
        let output = report_with_command(
            r#"{"title":"synthetic title","body":"body-via-stdin\nsecond line","labels":["fallback","agent-report"]}"#,
            command.as_os_str(),
        )
        .unwrap();
        assert_eq!(output["result"], "created");
        assert_eq!(
            output["url"],
            "https://github.com/cyjin-yl/buaa-cli/issues/42"
        );
        let args = read(&args);
        assert!(args.contains("--body-file\n-\n"));
        assert!(!args.contains("body-via-stdin"));
        assert_eq!(read(&body), "body-via-stdin\nsecond line");
    }

    #[test]
    fn invalid_or_uncertain_writer_outcome_requires_reconciliation_without_retry() {
        let fixture = Fixture::new();
        let command = fixture.command(
            "#!/bin/sh\nif [ \"$1\" = auth ]; then exit 0; fi\nprintf '%s' 'https://example.invalid/not-an-issue'\n",
        );
        let output = report_with_command(valid_input(), command.as_os_str()).unwrap();
        assert_eq!(output["result"], "unknown_outcome");
        assert_eq!(output["url"], Value::Null);
        assert_eq!(output["reconciliation"], "required");
        assert_eq!(output["automatic_retry"], false);

        let command = fixture.command(
            "#!/bin/sh\nif [ \"$1\" = auth ]; then exit 0; fi\nprintf '%s' 'synthetic-writer-secret' >&2\nexit 1\n",
        );
        let output = report_with_command(valid_input(), command.as_os_str()).unwrap();
        assert_eq!(output["result"], "unknown_outcome");
        assert_eq!(output["automatic_retry"], false);
        assert!(!output.to_string().contains("synthetic-writer-secret"));
    }

    #[test]
    fn canonical_issue_url_requires_a_positive_numeric_id() {
        assert!(canonical_issue_url(
            "https://github.com/cyjin-yl/buaa-cli/issues/1"
        ));
        assert!(!canonical_issue_url(
            "https://github.com/cyjin-yl/buaa-cli/issues/0"
        ));
        assert!(!canonical_issue_url(
            "https://github.com/cyjin-yl/buaa-cli/issues/01"
        ));
        assert!(!canonical_issue_url(
            "https://github.com/cyjin-yl/buaa-cli/issues/1?spoof=1"
        ));
        assert!(!canonical_issue_url(
            "https://github.com/other/repo/issues/1"
        ));
    }

    #[test]
    fn credential_shaped_payload_is_refused_before_any_gh_call() {
        let fixture = Fixture::new();
        let marker = fixture.path("called");
        let command = fixture.command(&format!(
            "#!/bin/sh\nprintf called > '{}'\n",
            marker.display()
        ));
        let output = report_with_command(
            r#"{"title":"crash","body":"password = hunter2"}"#,
            command.as_os_str(),
        )
        .unwrap();
        assert_eq!(output["result"], "refused");
        assert_eq!(output["field"], "body");
        assert_eq!(output["detected"], "secret_assignment");
        assert!(
            output.get("url").is_none(),
            "a refusal must not carry a URL"
        );
        assert!(
            !output.to_string().contains("hunter2"),
            "a refusal must not echo the matched value"
        );
        assert!(!marker.exists(), "gh must not be invoked for a refusal");
    }

    #[test]
    fn later_credential_assignments_refuse_before_gh_even_after_placeholders() {
        let fixture = Fixture::new();
        let marker = fixture.path("called");
        let command = fixture.command(&format!(
            "#!/bin/sh\nprintf called > '{}'\n",
            marker.display()
        ));
        for (body, detected) in [
            (
                "token=redacted; token=synthetic-private-a7",
                "secret_assignment",
            ),
            (
                "token=example; TOKEN=synthetic-private-b8",
                "secret_assignment",
            ),
            (
                "JSESSIONID=redacted; JSESSIONID=synthetic-private-c9",
                "session_cookie",
            ),
            (
                "sessionid=null; sessionid=synthetic-private-d0",
                "session_cookie",
            ),
        ] {
            let input = serde_json::json!({"title":"Synthetic failure","body":body});
            let output = report_with_command(&input.to_string(), command.as_os_str()).unwrap();
            assert_eq!(output["result"], "refused");
            assert_eq!(output["detected"], detected);
            assert!(output.get("url").is_none());
            assert!(!output.to_string().contains("synthetic-private"));
            assert!(!marker.exists(), "the writer ran before credential refusal");
        }
    }

    #[test]
    fn credential_shapes_are_classified_from_title_and_body() {
        assert_eq!(
            credential_shape("leaked ghp_A1b2C3d4E5f6G7h8I9j0", ""),
            Some(("title", CredentialShape::KnownTokenPrefix))
        );
        assert_eq!(
            credential_shape("t", "GET /\nCookie: CASTGC=TGT-1234-abcdef"),
            Some(("body", CredentialShape::CookieHeader))
        );
        assert_eq!(
            credential_shape("t", "CASTGC=TGT-1234-abcdef; Path=/"),
            Some(("body", CredentialShape::SessionCookie))
        );
        assert_eq!(
            credential_shape(
                "t",
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNDU2"
            ),
            Some(("body", CredentialShape::Jwt))
        );
        assert_eq!(
            credential_shape("t", "-----BEGIN RSA PRIVATE KEY-----"),
            Some(("body", CredentialShape::PrivateKeyBlock))
        );
    }

    #[test]
    fn base64_blob_beside_a_secret_marker_is_refused() {
        let body =
            "the token value was:\nQWxhZGRpbjpvcGVuIHNlc2FtZQ+/Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==";
        assert_eq!(
            credential_shape("t", body),
            Some(("body", CredentialShape::EncodedSecret))
        );
    }

    #[test]
    fn prose_and_hex_digests_are_not_refused() {
        let body = "The token expired before the request\nsha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\nAuthorization: required for this endpoint";
        assert_eq!(credential_shape("token handling bug", body), None);
    }
}
