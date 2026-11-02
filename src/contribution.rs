//! Bounded authenticated read-only issue discovery on GitHub or the fixed
//! Gitea primary. No lifecycle writes.
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
/// The only admitted Gitea deployment and repository for this slice. The
/// origin is fixed; a caller can never choose another host or repository.
const GITEA_HOST: &str = "doesvm.icefish-exponential.ts.net";
const GITEA_PORT: u16 = 8444;
const GITEA_API_PREFIX: &str = "https://doesvm.icefish-exponential.ts.net:8444/api/v1/";
const GITEA_API_ROOT: &str = "https://doesvm.icefish-exponential.ts.net:8444/api/v1/repos";
const GITEA_WEB_ROOT: &str = "https://doesvm.icefish-exponential.ts.net:8444";
const GITEA_REPOSITORY: &str = "ezra/buaa-cli";
/// Gitea caps list responses at 50 rows even when more are requested.
const GITEA_PAGE_LIMIT: usize = 50;

/// Which forge the scan reads. GitHub stays the default so existing callers
/// and their credentials keep working unchanged.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Provider {
    #[default]
    Github,
    Gitea,
}

impl Provider {
    fn as_str(self) -> &'static str {
        match self {
            Provider::Github => "github",
            Provider::Gitea => "gitea",
        }
    }

    fn api_root(self) -> &'static str {
        match self {
            Provider::Github => API_ROOT,
            Provider::Gitea => GITEA_API_ROOT,
        }
    }

    fn web_root(self) -> &'static str {
        match self {
            Provider::Github => WEB_ROOT,
            Provider::Gitea => GITEA_WEB_ROOT,
        }
    }

    /// Provider-prefixed public reason codes; response bytes are never exported.
    fn code(self, code: Code) -> &'static str {
        use Provider::{Gitea, Github};
        match (self, code) {
            (Github, Code::UrlRejected) => "github_url_rejected",
            (Gitea, Code::UrlRejected) => "gitea_url_rejected",
            (Github, Code::TransportFailed) => "github_transport_failed",
            (Gitea, Code::TransportFailed) => "gitea_transport_failed",
            (Github, Code::OutcomeUnrecorded) => "github_outcome_unrecorded",
            (Gitea, Code::OutcomeUnrecorded) => "gitea_outcome_unrecorded",
            (Github, Code::RequestStartUnavailable) => "github_request_start_unavailable",
            (Gitea, Code::RequestStartUnavailable) => "gitea_request_start_unavailable",
            (Github, Code::PrivateResponseWithheld) => "github_private_response_withheld",
            (Gitea, Code::PrivateResponseWithheld) => "gitea_private_response_withheld",
            (Github, Code::ChallengeDetected) => "github_challenge_detected",
            (Gitea, Code::ChallengeDetected) => "gitea_challenge_detected",
            (Github, Code::ResponseIncomplete) => "github_response_incomplete",
            (Gitea, Code::ResponseIncomplete) => "gitea_response_incomplete",
            (Github, Code::ResponseSafetyUnreviewed) => "github_response_safety_unreviewed",
            (Gitea, Code::ResponseSafetyUnreviewed) => "gitea_response_safety_unreviewed",
            (Github, Code::SetCookieRefused) => "github_set_cookie_refused",
            (Gitea, Code::SetCookieRefused) => "gitea_set_cookie_refused",
            (Github, Code::Unauthorized) => "github_unauthorized",
            (Gitea, Code::Unauthorized) => "gitea_unauthorized",
            (Github, Code::RateLimited) => "github_rate_limited",
            (Gitea, Code::RateLimited) => "gitea_rate_limited",
            (Github, Code::ServerError) => "github_server_error",
            (Gitea, Code::ServerError) => "gitea_server_error",
            (Github, Code::RequestRejected) => "github_request_rejected",
            (Gitea, Code::RequestRejected) => "gitea_request_rejected",
            (Github, Code::ResponseMimeRejected) => "github_response_mime_rejected",
            (Gitea, Code::ResponseMimeRejected) => "gitea_response_mime_rejected",
            (Github, Code::ResponseInvalid) => "github_response_invalid",
            (Gitea, Code::ResponseInvalid) => "gitea_response_invalid",
            (Github, Code::PageLimitExceeded) => "github_page_limit_exceeded",
            (Gitea, Code::PageLimitExceeded) => "gitea_page_limit_exceeded",
            (Github, Code::DuplicateListIdentity) => "github_duplicate_list_identity",
            (Gitea, Code::DuplicateListIdentity) => "gitea_duplicate_list_identity",
            (Github, Code::TotalCountUnstable) => "github_total_count_unstable",
            (Gitea, Code::TotalCountUnstable) => "gitea_total_count_unstable",
            (Github, Code::ListIncomplete) => "github_list_incomplete",
            (Gitea, Code::ListIncomplete) => "gitea_list_incomplete",
            (Github, Code::CommentsIncomplete) => "github_comments_incomplete",
            (Gitea, Code::CommentsIncomplete) => "gitea_comments_incomplete",
        }
    }
}

#[derive(Clone, Copy)]
enum Code {
    UrlRejected,
    TransportFailed,
    OutcomeUnrecorded,
    RequestStartUnavailable,
    PrivateResponseWithheld,
    ChallengeDetected,
    ResponseIncomplete,
    ResponseSafetyUnreviewed,
    SetCookieRefused,
    Unauthorized,
    RateLimited,
    ServerError,
    RequestRejected,
    ResponseMimeRejected,
    ResponseInvalid,
    PageLimitExceeded,
    DuplicateListIdentity,
    TotalCountUnstable,
    ListIncomplete,
    CommentsIncomplete,
}

/// A request must be a JSON object: serde can otherwise accept positional
/// arrays for structs, which the schema never declared. The token is only
/// ever materialized as a zeroizing secret, never an ordinary Value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanRequest {
    repository: String,
    #[serde(default)]
    provider: Provider,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    github_token: Option<ApiToken>,
    #[serde(default)]
    gitea_token: Option<ApiToken>,
}

impl ScanRequest {
    /// The credential belonging to the selected provider. Supplying the other
    /// provider's credential is ambiguous and rejected before any network use.
    fn provider_token(&self) -> Result<Option<&ApiToken>, ()> {
        match self.provider {
            Provider::Github if self.gitea_token.is_some() => Err(()),
            Provider::Gitea if self.github_token.is_some() => Err(()),
            Provider::Github => Ok(self.github_token.as_ref()),
            Provider::Gitea => Ok(self.gitea_token.as_ref()),
        }
    }
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
struct ApiToken(zeroize::Zeroizing<String>);

/// The credential visitor transfers decoded JSON strings into an owned
/// zeroizing buffer without an intermediate serde_json::Value.
struct ApiTokenVisitor;

impl<'de> serde::de::Visitor<'de> for ApiTokenVisitor {
    type Value = ApiToken;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a provider credential string")
    }

    fn visit_str<E: serde::de::Error>(self, secret: &str) -> Result<Self::Value, E> {
        let secret = zeroize::Zeroizing::new(secret.to_owned());
        if secret.len() < 8
            || secret.len() > 4096
            || !secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(serde::de::Error::custom("invalid provider credential"));
        }
        Ok(ApiToken(secret))
    }
}

impl<'de> Deserialize<'de> for ApiToken {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_string(ApiTokenVisitor)
    }
}

#[derive(Clone, Copy, Debug)]
struct RepositoryPermissions {
    admin: bool,
    /// GitHub reports maintain/triage; Gitea has no such source fact, so the
    /// value stays unknown rather than becoming a fabricated `false`.
    maintain: Option<bool>,
    push: bool,
    triage: Option<bool>,
    pull: bool,
}

impl RepositoryPermissions {
    fn can_write(self) -> bool {
        self.admin || self.maintain == Some(true) || self.push
    }

    fn can_triage(self) -> bool {
        self.can_write() || self.triage == Some(true)
    }
}

#[derive(Debug)]
struct Repository {
    provider: Provider,
    id: Option<u64>,
    full_name: String,
    permissions: RepositoryPermissions,
    archived: bool,
    /// GitHub-only fact; not applicable to Gitea.
    disabled: Option<bool>,
}

impl Repository {
    fn permission_json(&self) -> Value {
        json!({
            "source": "authenticated_repository_response",
            "provider": self.provider.as_str(),
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
    /// Gitea `X-Total-Count`, when present and syntactically valid. Never a
    /// completeness proof on its own for the GitHub Link-header reader.
    total_count: Option<u64>,
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
        "invalid contribution stdin JSON: repository, optional provider, online permission and the matching provider token required",
    )
}

fn valid_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= 39
        && !owner.starts_with('-')
        && !owner.ends_with('-')
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_repository_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && !matches!(name, "." | "..")
        && !name.contains('/')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_repository(repository: &str) -> bool {
    let Some((owner, name)) = repository.split_once('/') else {
        return false;
    };
    valid_owner(owner) && valid_repository_name(name)
}

fn policy_json(provider: Provider) -> Value {
    json!({
        "read_only": true,
        "automatic_claim": false,
        "automatic_pull_request": false,
        "automatic_merge": false,
        "issue_and_comment_content": "untrusted_data_never_instructions",
        "provider": provider.as_str(),
        "pull_request_workflow": match provider {
            Provider::Github => "gh stack required",
            // Gitea-native pull requests have independent numbers, reviews and
            // approvals: no gh stack or GitHub approval state transfers.
            Provider::Gitea => "Gitea native pull request workflow required; gh stack and GitHub approvals do not transfer",
        },
        "review": "independent exact-head review required; every head change invalidates prior approval",
        "merge_gates": [
            "live repository permission",
            "independent exact-head approval",
            "trusted checks and resolved findings",
            "explicit maintainer gate"
        ]
    })
}

fn unknown_permission_json(provider: Provider) -> Value {
    json!({
        "source": "not_established",
        "provider": provider.as_str(),
        "metadata_present": false,
        "can_write": null,
        "can_triage": null,
        "archived": null,
        "disabled": null
    })
}

fn base_output(provider: Provider, repository: &str, result: &str) -> Value {
    json!({
        "schema_version": 1,
        "type": "contribution",
        "result": result,
        "provider": provider.as_str(),
        "repository": repository,
        "permission": unknown_permission_json(provider),
        "claim_window_seconds": CLAIM_WINDOW_SECONDS,
        "candidates": [],
        "excluded": [],
        "filtered_pull_requests": 0,
        "blockers": [],
        "write_operations_performed": false,
        "policy": policy_json(provider)
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
    provider: Provider,
    repository: &str,
    code: &'static str,
    evidence: Option<&PageEvidence>,
) -> Value {
    let mut output = base_output(provider, repository, "blocked");
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
    let mut output = base_output(repository.provider, &repository.full_name, "blocked");
    output["permission"] = repository.permission_json();
    output["reason"] = json!(code);
    output["blockers"] = json!([{"code": code}]);
    if let Some(evidence) = evidence {
        output = attach_raw_evidence(output, code, evidence);
    }
    output
}

/// One original HTTPS request per shared governor lease; no redirect or retry.
/// Transport/read failure for either provider; the historical name is kept.
struct GithubReader<'g> {
    client: reqwest::blocking::Client,
    provider: Provider,
    token: &'g ApiToken,
    governor: &'g Governor,
}

fn api_url_allowed(provider: Provider, url: &str) -> bool {
    let prefix = match provider {
        Provider::Github => API_PREFIX,
        Provider::Gitea => GITEA_API_PREFIX,
    };
    url.starts_with(prefix)
        && url::Url::parse(url).is_ok_and(|u| {
            let (host, port, path_ok) = match provider {
                Provider::Github => (
                    "api.github.com",
                    None,
                    u.path().starts_with("/repos/") || u.path().starts_with("/repositories/"),
                ),
                Provider::Gitea => (
                    GITEA_HOST,
                    Some(GITEA_PORT),
                    // Only the fixed admitted repository is reachable; no other
                    // path, owner or private repository can be addressed. The
                    // segment boundary stops `buaa-cli-evil` style suffixes.
                    u.path()
                        .strip_prefix("/api/v1/repos/ezra/buaa-cli")
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/')),
                ),
            };
            u.scheme() == "https"
                && u.host_str() == Some(host)
                && u.username().is_empty()
                && u.password().is_none()
                && u.port() == port
                && u.fragment().is_none()
                && path_ok
                && !url.contains('%')
                && !url.contains('\\')
        })
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
        let provider = self.provider;
        let fail = |code: Code| GithubFailure::Fatal {
            code: provider.code(code),
            evidence: None,
        };
        if !api_url_allowed(provider, url) {
            return Err(fail(Code::UrlRejected));
        }
        let request = match api_request(&self.client, provider, url, self.token) {
            Ok(request) => request,
            Err(_) => {
                return Err(GithubFailure::Fatal {
                    code: "invalid_input",
                    evidence: None,
                });
            }
        };
        let mut lease = crate::net::acquire(self.governor).map_err(|e| GithubFailure::Fatal {
            code: e.code,
            evidence: None,
        })?;
        let mut response = match lease.start_request(|| request.send()) {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                let settled = lease.finish(Outcome::NetworkFailure);
                return Err(fail(if settled.is_ok() {
                    Code::TransportFailed
                } else {
                    Code::OutcomeUnrecorded
                }));
            }
            Err(crate::governor::FollowupError::Governor(_)) => {
                // No request was admitted. Keep the pending reservation for
                // conservative reconciliation instead of inventing an outcome.
                return Err(fail(Code::RequestStartUnavailable));
            }
        };
        let status = response.status().as_u16();
        let secret = self.token.0.as_str();
        // The complete transmitted Authorization header value ("Bearer …" or
        // "token …") is itself a credential: an encoded echo of it is just as
        // sensitive as the raw token.
        let authorization_secret = {
            let scheme = match provider {
                Provider::Github => "Bearer ",
                Provider::Gitea => "token ",
            };
            let mut text =
                zeroize::Zeroizing::new(String::with_capacity(scheme.len() + secret.len()));
            text.push_str(scheme);
            text.push_str(secret);
            text
        };
        // Header borrows end here, so the response can be dropped later while
        // its body stream is still open. Every copied header value lives in a
        // zeroizing buffer, so a reflected credential is never materialized in
        // an ordinary owned string.
        let (
            header_challenge,
            retry_after,
            content_type,
            link,
            total_count,
            set_cookie,
            metadata_valid,
            length,
            reflected,
        ) = {
            let headers = response.headers();
            let reflected = headers.iter().any(|(_, value)| {
                crate::net::carries_secret(value.as_bytes(), secret)
                    || crate::net::carries_secret(value.as_bytes(), authorization_secret.as_str())
            });
            let header_challenge = headers
                .iter()
                .any(|(k, v)| crate::net::challenge_header(k.as_str(), v.as_bytes()));
            let value = |name: &str| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| zeroize::Zeroizing::new(v.to_owned()))
            };
            let retry_after = value("retry-after");
            let content_type = value("content-type");
            let link = value("link");
            let total_count = value("x-total-count");
            // A non-browser reader never adopts cookies: any Set-Cookie on an
            // API response is refused before projection rather than stored.
            let set_cookie = headers.get_all("set-cookie").iter().next().is_some();
            let metadata_valid = [
                "retry-after",
                "content-type",
                "content-length",
                "link",
                "x-total-count",
            ]
            .iter()
            .all(|name| {
                headers.get_all(*name).iter().count() <= 1
                    && headers.get(*name).is_none_or(|v| v.to_str().is_ok())
            }) && headers
                .get_all("content-encoding")
                .iter()
                .all(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"));
            let total_count = match total_count.as_ref().map(|value| value.as_str()) {
                None => Some(None),
                Some(text) => text.parse::<u64>().ok().map(Some),
            };
            let metadata_valid = metadata_valid && total_count.is_some();
            let total_count = total_count.flatten();
            (
                header_challenge,
                retry_after,
                content_type,
                link,
                total_count,
                set_cookie,
                metadata_valid,
                response.content_length(),
                reflected,
            )
        };
        let retry_after_text = retry_after.as_ref().map(|value| value.as_str());
        let content_type_text = content_type.as_ref().map(|value| value.as_str());
        if observe_github_headers(&mut lease, status, response.headers(), header_challenge).is_err()
        {
            drop(response);
            let _ = lease.finish(Outcome::NetworkFailure);
            return Err(fail(Code::OutcomeUnrecorded));
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
        let complete =
            read.is_ok() && body.len() <= MAX_BODY && length.is_none_or(|n| n == body.len() as u64);
        let assessment =
            crate::html::assess_challenge_body(body.as_slice(), content_type_text, complete);
        let challenge =
            header_challenge || assessment == crate::html::ChallengeAssessment::Detected;
        // The response is dropped before the lease is released, so an unread
        // body can never outlive the recorded request outcome.
        drop(response);
        lease
            .finish(Outcome::Http {
                status,
                retry_after: retry_after_text,
                challenge,
                network_failure: !complete || !metadata_valid,
            })
            .map_err(|_| fail(Code::OutcomeUnrecorded))?;
        if reflected {
            return Err(fail(Code::PrivateResponseWithheld));
        }
        if set_cookie {
            return Err(fail(Code::SetCookieRefused));
        }
        if challenge {
            return Err(fail(Code::ChallengeDetected));
        }
        if !complete {
            return Err(fail(Code::ResponseIncomplete));
        }
        if !metadata_valid || assessment != crate::html::ChallengeAssessment::Clear {
            return Err(fail(Code::ResponseSafetyUnreviewed));
        }
        // Reject any literal or JSON-escaped reflection of the credential
        // before untrusted titles/URLs or metadata can enter the public
        // result. The response is kept in a zeroizing buffer, and escape
        // decoding happens only on temporary zeroizing strings; no ordinary
        // Value ever materializes the credential.
        let json_body = content_type_text.is_some_and(|value| {
            let mime = value.split(';').next().unwrap_or("").trim();
            match provider {
                Provider::Github => {
                    matches!(mime, "application/json" | "application/vnd.github+json")
                }
                Provider::Gitea => mime == "application/json",
            }
        });
        // Both the raw credential and the complete transmitted Authorization
        // header value are protected in every reversible encoding form.
        let reflections = [
            secret_reflection(body.as_slice(), secret, json_body),
            secret_reflection(body.as_slice(), authorization_secret.as_str(), json_body),
        ];
        if reflections.contains(&SecretReflection::Present) {
            return Err(fail(Code::PrivateResponseWithheld));
        }
        if reflections.contains(&SecretReflection::Unresolved) {
            return Err(fail(Code::ResponseSafetyUnreviewed));
        }
        if status == 404 {
            return Err(GithubFailure::NotFound {
                evidence: Some(PageEvidence {
                    status,
                    link,
                    total_count,
                    body_complete: complete,
                    body,
                }),
            });
        }
        if status != 200 {
            return Err(fail(match status {
                401 | 403 => Code::Unauthorized,
                429 => Code::RateLimited,
                500..=599 => Code::ServerError,
                _ => Code::RequestRejected,
            }));
        }
        if !json_body {
            return Err(fail(Code::ResponseMimeRejected));
        }
        let evidence = PageEvidence {
            status,
            link,
            total_count,
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
    lease.observe_http_many(
        status,
        headers
            .get_all("retry-after")
            .iter()
            .map(|value| value.to_str().ok()),
        challenge,
    )
}

/// Build one authenticated request with a single total deadline. The
/// credential is copied only into a sensitive header value; it never appears
/// in a URL, a log, or an error message. GitHub uses `Bearer`, Gitea `token`.
fn api_request(
    client: &reqwest::blocking::Client,
    provider: Provider,
    url: &str,
    token: &ApiToken,
) -> Result<reqwest::blocking::RequestBuilder, ()> {
    let scheme = match provider {
        Provider::Github => "Bearer ",
        Provider::Gitea => "token ",
    };
    let accept = match provider {
        Provider::Github => "application/vnd.github+json",
        Provider::Gitea => "application/json",
    };
    let mut authorization_text =
        zeroize::Zeroizing::new(String::with_capacity(scheme.len() + token.0.len()));
    authorization_text.push_str(scheme);
    authorization_text.push_str(token.0.as_str());
    let mut authorization =
        reqwest::header::HeaderValue::from_str(authorization_text.as_str()).map_err(|_| ())?;
    authorization.set_sensitive(true);
    Ok(client
        .get(url)
        .timeout(REQUEST_DEADLINE)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header("Accept", accept)
        .header("Accept-Encoding", "identity"))
}

/// Read side for either provider. The failure type keeps its historical name.
trait GithubRead {
    fn provider(&self) -> Provider {
        Provider::Github
    }

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
        match self.provider() {
            Provider::Github => {
                self.get_github_pages(first_url, max_pages, max_items, bound_repository_id)
            }
            Provider::Gitea => self.get_gitea_pages(first_url, max_pages, max_items),
        }
    }

    /// GitHub pagination follows the admitted `Link: rel="next"` target.
    fn get_github_pages(
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
        let first = url::Url::parse(first_url).map_err(|_| GithubFailure::Fatal {
            code: "github_url_rejected",
            evidence: None,
        })?;
        loop {
            let parsed = url::Url::parse(&url).map_err(|_| GithubFailure::Fatal {
                code: "github_pagination_invalid",
                evidence: None,
            })?;
            if !pagination_path_allowed(first.path(), parsed.path(), bound_repository_id)
                || !seen.insert(url.clone())
            {
                return Err(GithubFailure::Fatal {
                    code: "github_pagination_invalid",
                    evidence: None,
                });
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

    /// Gitea pagination is driven by `page=N&limit=50` query parameters, not
    /// by Link targets. A page shorter than the limit is NOT a terminal: the
    /// reader always continues to a real empty page. A stable `X-Total-Count`
    /// is only an oracle for drift and for agreement at the empty terminal —
    /// never a reason to stop early, and never a completeness proof when
    /// absent. Bounds stop the read without any extra request.
    fn get_gitea_pages(
        &self,
        first_url: &str,
        max_pages: usize,
        max_items: usize,
    ) -> Result<(Vec<Page>, bool), GithubFailure> {
        let fatal = |code: Code, evidence: Option<PageEvidence>| GithubFailure::Fatal {
            code: Provider::Gitea.code(code),
            evidence,
        };
        let mut pages = Vec::new();
        let mut total = 0usize;
        // Gitea reports two different count meanings. The issue list
        // advertises the overall total on every page, so a count larger than
        // the rows that response returned is an overall oracle that must stay
        // stable and must equal the collected rows. The issue timeline
        // advertises this page's own row count, so a count equal to the rows
        // it returned proves nothing and is never compared with another
        // page. The real empty page is the completeness evidence whenever no
        // overall oracle was established.
        let mut overall_total: Option<u64> = None;
        let mut readings: Vec<u64> = Vec::new();
        let mut seen_ids = std::collections::BTreeSet::new();
        loop {
            let url = format!(
                "{first_url}{}page={}",
                if first_url.contains('?') { "&" } else { "?" },
                pages.len() + 1
            );
            let evidence = self.get(&url)?;
            let items = match serde_json::from_slice::<Value>(evidence.body.as_slice()) {
                Ok(Value::Array(items)) => items,
                // Gitea serializes an empty list as JSON `null` instead of an
                // empty array. It is admitted as the empty page and the
                // advertised count then decides whether that empty page
                // agrees with what was collected.
                Ok(Value::Null) => Vec::new(),
                _ => return Err(fatal(Code::ResponseInvalid, Some(evidence))),
            };
            // Every native list row carries a unique numeric id; repeated or
            // missing identities mean drift, never more data.
            for item in &items {
                let Some(id) = item.get("id").and_then(Value::as_u64) else {
                    return Err(fatal(Code::ResponseInvalid, Some(evidence)));
                };
                if !seen_ids.insert(id) {
                    return Err(fatal(Code::DuplicateListIdentity, Some(evidence)));
                }
            }
            let rows = items.len() as u64;
            if let Some(count) = evidence.total_count {
                readings.push(count);
                // A page can never carry more rows than it advertises.
                if count < rows {
                    return Err(fatal(Code::ListIncomplete, Some(evidence)));
                }
                if count > rows {
                    if overall_total.is_some_and(|expected| expected != count) {
                        return Err(fatal(Code::TotalCountUnstable, Some(evidence)));
                    }
                    overall_total = Some(count);
                    // The oracle is established now, so every earlier reading
                    // is checked now too. A contradiction must not wait for
                    // another request to discover it.
                    if readings.iter().any(|reading| *reading != count) {
                        return Err(fatal(Code::ListIncomplete, Some(evidence)));
                    }
                }
                // Once an overall total is established, every later page must
                // repeat it.
                if overall_total.is_some_and(|expected| expected != count) {
                    return Err(fatal(Code::ListIncomplete, Some(evidence)));
                }
            }
            total += items.len();
            if total > max_items {
                return Err(fatal(Code::PageLimitExceeded, Some(evidence)));
            }
            // Rows beyond the advertised total are inconsistency, never a
            // successful truncated omission.
            if overall_total
                .is_some_and(|expected| u64::try_from(total).unwrap_or(u64::MAX) > expected)
            {
                return Err(fatal(Code::ListIncomplete, Some(evidence)));
            }
            let empty = items.is_empty();
            pages.push(Page { items, evidence });
            if empty {
                // The empty terminal must agree with an established overall
                // total; a shortfall is incomplete evidence, not a clean end.
                // A terminal that advertises only its own empty page count
                // establishes no oracle, and the real empty page is then the
                // completeness evidence.
                if overall_total
                    .is_some_and(|expected| u64::try_from(total).unwrap_or(u64::MAX) != expected)
                {
                    let evidence = pages.pop().map(|page| page.evidence);
                    return Err(fatal(Code::ListIncomplete, evidence));
                }
                // Every page of an overall-total list must have advertised
                // that same total.
                if overall_total
                    .is_some_and(|expected| readings.iter().any(|reading| *reading != expected))
                {
                    let evidence = pages.pop().map(|page| page.evidence);
                    return Err(fatal(Code::ListIncomplete, evidence));
                }
                return Ok((pages, false));
            }
            if pages.len() >= max_pages {
                return Ok((pages, true));
            }
        }
    }
}

impl GithubRead for GithubReader<'_> {
    fn provider(&self) -> Provider {
        self.provider
    }

    fn get(&self, url: &str) -> Result<PageEvidence, GithubFailure> {
        GithubReader::fetch_page(self, url)
    }
}

/// Recursion depth and the cumulative decoded-byte ledger for encoded views.
/// Any encoding view that cannot be explored within these bounds leaves the
/// scan unresolved rather than falsely clean.
const MAX_REFLECTION_DEPTH: usize = 6;
const MAX_REFLECTION_DECODE: usize = 16 * 1024 * 1024;

/// Whether raw bytes contain the credential in any supported reversible
/// view: literal text, JSON string escapes, standard/URL-safe base64 (padded
/// or not, ASCII whitespace folded), and percent/form encodings — including
/// those encodings nested inside decoded string views (JSON inside JSON, an
/// encoded JSON envelope inside a title, and so on), bounded by depth and a
/// cumulative decoded-byte ledger. The body is never parsed into an ordinary
/// Value: only the individual string or encoding views are decoded, each
/// into a temporary zeroizing buffer that is wiped when it goes out of
/// scope.
fn secret_reflection(bytes: &[u8], secret: &str, decode_escapes: bool) -> SecretReflection {
    if secret.is_empty() {
        return SecretReflection::Absent;
    }
    let mut budget = ReflectionBudget {
        remaining: MAX_REFLECTION_DECODE,
    };
    reflection_scan(bytes, secret, decode_escapes, 0, &mut budget)
}

struct ReflectionBudget {
    remaining: usize,
}

impl ReflectionBudget {
    /// Charge one decoded view's materialized size against the ledger.
    fn spend(&mut self, size: usize) -> bool {
        if size > self.remaining {
            return false;
        }
        self.remaining -= size;
        true
    }
}

fn merge_reflection(a: SecretReflection, b: SecretReflection) -> SecretReflection {
    match (a, b) {
        (SecretReflection::Present, _) | (_, SecretReflection::Present) => {
            SecretReflection::Present
        }
        (SecretReflection::Unresolved, _) | (_, SecretReflection::Unresolved) => {
            SecretReflection::Unresolved
        }
        _ => SecretReflection::Absent,
    }
}

fn is_base64_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' | b'-' | b'_'
    )
}

/// A run that plausibly carries an encoding rather than ordinary prose: long
/// enough to matter, and either long enough to be an envelope or containing
/// at least one character no ordinary word would have.
fn base64_candidate(run: &[u8]) -> bool {
    run.len() >= 8 && (run.len() >= 48 || run.iter().any(|byte| !byte.is_ascii_alphabetic()))
}

/// Decode one folded base64 view with padding normalization, trying the
/// standard alphabet and then the URL-safe one. A failed decode means the
/// view is not an encoding at all — never a finding on its own.
fn base64_decode_view(text: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE},
    };
    let mut folded = Vec::with_capacity(text.len());
    folded.extend(text.bytes().filter(|byte| !byte.is_ascii_whitespace()));
    if folded.len() < 8 || folded.len() % 4 == 1 || !folded.iter().all(|byte| is_base64_byte(*byte))
    {
        return None;
    }
    let remainder = folded.len() % 4;
    if remainder != 0 {
        folded.resize(folded.len() + (4 - remainder), b'=');
    }
    STANDARD
        .decode(&folded)
        .ok()
        .or_else(|| URL_SAFE.decode(&folded).ok())
        .map(zeroize::Zeroizing::new)
}

/// Scan one text view for the credential: direct comparison of every
/// reversible form, then bounded exploration of nested encodings. JSON
/// string decoding runs when the view is trusted JSON (`parse_strings`) —
/// the top-level gate keeps the existing decode_escapes rule, while every
/// derived view is parsed since it is itself an encoding context. Views
/// that remain unexplored at the depth limit or beyond the byte ledger are
/// unresolved, never absent.
fn reflection_scan(
    view: &[u8],
    secret: &str,
    parse_strings: bool,
    depth: usize,
    budget: &mut ReflectionBudget,
) -> SecretReflection {
    let mut worst = SecretReflection::Absent;
    if crate::net::carries_secret(view, secret) {
        return SecretReflection::Present;
    }
    let at_limit = depth >= MAX_REFLECTION_DEPTH;
    // Quoted-string views: the decoded content of every string is itself a
    // supported text view, so JSON inside JSON is reviewed recursively.
    let mut cursor = 0;
    while cursor < view.len() {
        if view[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        let opening = cursor;
        cursor += 1;
        let mut escaped = false;
        while cursor < view.len() {
            match view[cursor] {
                b'\\' => {
                    escaped = true;
                    cursor = cursor.saturating_add(2);
                }
                b'"' => break,
                _ => cursor += 1,
            }
        }
        if cursor >= view.len() {
            // An unterminated string tail is only a hidden-encoding channel
            // when it carries a backslash in a JSON context: without one the
            // raw bytes were already compared. Decode it like any other
            // string view — a clean decode is reviewed for the credential,
            // while a failed decode is unresolved only when a \u escape (the
            // form that can produce bytes not literally present) is in play.
            // Ordinary prose tails such as `C:\path` fail decoding without
            // \u and stay absent; their bytes were already compared.
            let tail = &view[opening + 1..];
            if parse_strings && tail.contains(&b'\\') {
                if at_limit {
                    worst = merge_reflection(worst, SecretReflection::Unresolved);
                } else {
                    match std::str::from_utf8(tail) {
                        Err(_) => {
                            worst = merge_reflection(worst, SecretReflection::Unresolved);
                        }
                        Ok(text) if !budget.spend(text.len()) => {
                            worst = merge_reflection(worst, SecretReflection::Unresolved);
                        }
                        Ok(text) => {
                            let mut decoded = zeroize::Zeroizing::new(String::new());
                            if decode_json_string(text, &mut decoded) {
                                worst = merge_reflection(
                                    worst,
                                    reflection_scan(
                                        decoded.as_bytes(),
                                        secret,
                                        true,
                                        depth + 1,
                                        budget,
                                    ),
                                );
                            } else if text.contains("\\u") {
                                worst = merge_reflection(worst, SecretReflection::Unresolved);
                            }
                        }
                    }
                }
            }
            break;
        }
        let content = &view[opening + 1..cursor];
        cursor += 1;
        if !escaped {
            // Unescaped content is already part of this view's own scan;
            // recurse so nested encoding views inside it are explored.
            worst = merge_reflection(
                worst,
                reflection_scan(content, secret, true, depth + 1, budget),
            );
            continue;
        }
        if !parse_strings {
            // Escaped content in a non-JSON view was already compared raw by
            // the shared helper; it is not a JSON string to decode.
            continue;
        }
        if at_limit {
            worst = merge_reflection(worst, SecretReflection::Unresolved);
            continue;
        }
        let Ok(text) = std::str::from_utf8(content) else {
            // An undecodable escape sequence leaves the reflection
            // unresolved, so the response cannot be admitted.
            worst = merge_reflection(worst, SecretReflection::Unresolved);
            continue;
        };
        if !budget.spend(text.len()) {
            worst = merge_reflection(worst, SecretReflection::Unresolved);
            continue;
        }
        let mut decoded = zeroize::Zeroizing::new(String::new());
        if !decode_json_string(text, &mut decoded) {
            // An ambiguous escape sequence leaves the reflection
            // unresolved, so the response cannot be admitted.
            worst = merge_reflection(worst, SecretReflection::Unresolved);
            continue;
        }
        worst = merge_reflection(
            worst,
            reflection_scan(decoded.as_bytes(), secret, true, depth + 1, budget),
        );
    }
    if at_limit {
        // Residual unexplorable candidates keep the view unresolved.
        if has_encoded_candidate(view) {
            worst = merge_reflection(worst, SecretReflection::Unresolved);
        }
        return worst;
    }
    // Whole-view base64 with ASCII whitespace folded (the entire view may be
    // an encoding envelope).
    if let Ok(text) = std::str::from_utf8(view) {
        let folded_len = text
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .count();
        if folded_len >= 8
            && folded_len % 4 != 1
            && text
                .bytes()
                .all(|byte| byte.is_ascii_whitespace() || is_base64_byte(byte))
        {
            if !budget.spend(view.len()) {
                worst = merge_reflection(worst, SecretReflection::Unresolved);
            } else if let Some(decoded) = base64_decode_view(text) {
                worst = merge_reflection(
                    worst,
                    reflection_scan(&decoded, secret, true, depth + 1, budget),
                );
            }
        }
    }
    // Base64 runs inside the view and percent/form views inside
    // whitespace-delimited tokens.
    for run in view.split(|byte| !is_base64_byte(*byte)) {
        if !base64_candidate(run) {
            continue;
        }
        if !budget.spend(run.len()) {
            worst = merge_reflection(worst, SecretReflection::Unresolved);
            continue;
        }
        // Runs consist of ASCII alphabet bytes by construction.
        let Ok(text) = std::str::from_utf8(run) else {
            continue;
        };
        if let Some(decoded) = base64_decode_view(text) {
            worst = merge_reflection(
                worst,
                reflection_scan(&decoded, secret, true, depth + 1, budget),
            );
        }
    }
    for token in view.split(|byte| byte.is_ascii_whitespace()) {
        for plus_as_space in [false, true] {
            if (plus_as_space && !token.contains(&b'+')) || token.is_empty() {
                continue;
            }
            if !plus_as_space && !token.contains(&b'%') {
                continue;
            }
            if !budget.spend(token.len()) {
                worst = merge_reflection(worst, SecretReflection::Unresolved);
                continue;
            }
            let mut decoded = zeroize::Zeroizing::new(Vec::with_capacity(token.len()));
            crate::net::percent_decode_into(token, plus_as_space, &mut decoded);
            // A decode that changes nothing is not a new view: a literal '%'
            // without a valid triplet (or a '+' under the other form) would
            // otherwise recurse on identical bytes until the depth limit.
            if decoded.as_slice() == token {
                continue;
            }
            worst = merge_reflection(
                worst,
                reflection_scan(&decoded, secret, true, depth + 1, budget),
            );
        }
    }
    worst
}

/// Whether a view still contains an explorable encoding candidate at the
/// recursion limit: a base64-looking run or a percent/form token.
fn has_encoded_candidate(view: &[u8]) -> bool {
    view.split(|byte| !is_base64_byte(*byte))
        .any(base64_candidate)
        || view
            .split(|byte| byte.is_ascii_whitespace())
            .any(|token| token.contains(&b'%') || token.contains(&b'+'))
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
                                if characters.next() != Some('\\') || characters.next() != Some('u')
                                {
                                    return false;
                                }
                                let Some(low) = read_hex4(&mut characters) else {
                                    return false;
                                };
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return false;
                                }
                                let combined = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
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
    let Some(link) = link else {
        return Ok(None);
    };
    let mut next = None;
    for part in link.split(',') {
        let (target, parameters) = part.trim().split_once('>').ok_or(())?;
        let target = target.strip_prefix('<').ok_or(())?;
        if !api_url_allowed(Provider::Github, target) {
            return Err(());
        }
        let relation = parameters
            .trim()
            .strip_prefix(';')
            .ok_or(())?
            .trim()
            .strip_prefix("rel=")
            .ok_or(())?
            .trim_matches('"');
        if !matches!(relation, "next" | "prev" | "first" | "last") {
            return Err(());
        }
        if relation == "next" && next.replace(target.to_owned()).is_some() {
            return Err(());
        }
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
    provider: Provider,
) -> Result<Repository, RepositoryParseError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| RepositoryParseError::Invalid)?;
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
    let permissions = match provider {
        Provider::Github => RepositoryPermissions {
            admin: permission_flag(permissions, "admin")?,
            maintain: Some(permission_flag(permissions, "maintain")?),
            push: permission_flag(permissions, "push")?,
            triage: Some(permission_flag(permissions, "triage")?),
            pull: permission_flag(permissions, "pull")?,
        },
        // Gitea reports only admin/push/pull. maintain/triage have no native
        // source fact and stay unknown rather than defaulting to false.
        Provider::Gitea => RepositoryPermissions {
            admin: permission_flag(permissions, "admin")?,
            maintain: None,
            push: permission_flag(permissions, "push")?,
            triage: None,
            pull: permission_flag(permissions, "pull")?,
        },
    };
    let archived = object
        .get("archived")
        .and_then(Value::as_bool)
        .ok_or(RepositoryParseError::Invalid)?;
    let disabled = match provider {
        Provider::Github => Some(
            object
                .get("disabled")
                .and_then(Value::as_bool)
                .ok_or(RepositoryParseError::Invalid)?,
        ),
        // Gitea has no repository `disabled` flag: not applicable, not false.
        Provider::Gitea => None,
    };
    Ok(Repository {
        provider,
        id,
        full_name,
        permissions,
        archived,
        disabled,
    })
}

fn expected_issue_url(provider: Provider, repository: &str, number: u64) -> String {
    format!("{}/{repository}/issues/{number}", provider.web_root())
}

fn parse_issues(items: &[Value], repository: &str, provider: Provider) -> Result<IssueList, ()> {
    let mut issues = Vec::new();
    let mut filtered_pull_requests = 0usize;
    for item in items {
        let object = item.as_object().ok_or(())?;
        // GitHub uses this field's presence, not its truthiness, to identify a
        // pull request in the issues API. Gitea emits `pull_request: null` on
        // every plain issue, so only a non-null value marks a pull request;
        // the `type=issues` query alone is not treated as proof.
        let is_pull_request = match provider {
            Provider::Github => object.contains_key("pull_request"),
            Provider::Gitea => match object.get("pull_request") {
                Some(Value::Null) => false,
                Some(Value::Object(_)) => true,
                // Missing or malformed PR metadata is ambiguous, never an
                // unclaimed issue.
                _ => return Err(()),
            },
        };
        if is_pull_request {
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
            .filter(|url| *url == expected_issue_url(provider, repository, number))
            .ok_or(())?
            .to_owned();
        let assignee = object.get("assignee").ok_or(())?;
        // Gitea serializes an unassigned issue with `assignees: null` rather
        // than an empty array. A null list means no assignee; any other
        // non-array shape is ambiguous and never an unclaimed issue. The null
        // spelling is admitted for the Gitea primary only; GitHub keeps its
        // own array requirement unchanged.
        let assignees: &[Value] = match object.get("assignees") {
            Some(Value::Null) if provider == Provider::Gitea => &[],
            Some(Value::Array(items)) => items.as_slice(),
            _ => return Err(()),
        };
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

/// Resolve a Gitea pull request identity from either the API URL carried by
/// `pull_request_url` or the web URL carried by `ref_issue.pull_request
/// .html_url`. Only the fixed admitted repository can resolve; foreign,
/// malformed or non-PR URLs stay unresolved.
fn gitea_pr_candidate(url: &str) -> Option<PrCandidate> {
    let rest = url
        .strip_prefix(GITEA_API_PREFIX)
        .map(|rest| rest.strip_prefix("repos/").unwrap_or(""))
        .or_else(|| {
            url.strip_prefix(GITEA_WEB_ROOT)
                .map(|rest| rest.strip_prefix('/').unwrap_or(""))
        })?;
    let (owner, rest) = rest.split_once('/')?;
    let (name, rest) = rest.split_once('/')?;
    let (kind, number) = rest.split_once('/')?;
    if kind != "pulls"
        || owner != "ezra"
        || name != "buaa-cli"
        || number.is_empty()
        || number.contains('/')
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let number = number.parse::<u64>().ok().filter(|number| *number > 0)?;
    Some(PrCandidate {
        owner: owner.to_owned(),
        name: name.to_owned(),
        number,
    })
}

/// What one timeline event says about a possibly linked pull request.
enum EventLink {
    Candidate(PrCandidate),
    /// Potentially linked evidence that cannot be resolved conservatively.
    Unknown,
    /// The event establishes no pull request link at all.
    Skip,
}

/// GitHub timeline vocabulary: `connected` and `cross-referenced` only.
fn github_event_link(item: &Value) -> EventLink {
    let Some(event) = item.as_object() else {
        return EventLink::Unknown;
    };
    let Some(kind) = event.get("event").and_then(Value::as_str) else {
        return EventLink::Unknown;
    };
    let parsed = match kind {
        "connected" => connected_candidate(event),
        "cross-referenced" => cross_referenced_candidate(event),
        // A disconnected event removes a link; it can never establish that a
        // pull request is currently linked.
        _ => return EventLink::Skip,
    };
    match parsed {
        Ok(CrossReference::Resolved(candidate)) => EventLink::Candidate(candidate),
        Ok(CrossReference::Unresolved) | Err(()) => EventLink::Unknown,
        Ok(CrossReference::NotLinked) => EventLink::Skip,
    }
}

/// Gitea timeline vocabulary. There is no GitHub `connected` equivalent:
/// `pull_ref`/`issue_ref` entries carry `ref_issue` (whose `pull_request`
/// meta marks a PR) and comments may carry `pull_request_url`. Anything
/// potentially linked but unknown, foreign or malformed stays `Unknown`.
fn gitea_event_link(item: &Value) -> EventLink {
    let Some(event) = item.as_object() else {
        return EventLink::Unknown;
    };
    let Some(kind) = event.get("type").and_then(Value::as_str) else {
        return EventLink::Unknown;
    };
    // `pull_request_url` is potential PR evidence whenever it is present and
    // meaningful. Only an absent, null or empty-string field may be ignored;
    // a malformed non-string value can never be dismissed.
    enum UrlEvidence<'a> {
        Absent,
        Malformed,
        Present(&'a str),
    }
    let url_evidence = match event.get("pull_request_url") {
        None | Some(Value::Null) => UrlEvidence::Absent,
        Some(Value::String(url)) if url.is_empty() => UrlEvidence::Absent,
        Some(Value::String(url)) => UrlEvidence::Present(url.as_str()),
        Some(_) => UrlEvidence::Malformed,
    };
    let from_url = |evidence: UrlEvidence<'_>| match evidence {
        UrlEvidence::Present(url) => match gitea_pr_candidate(url) {
            Some(candidate) => EventLink::Candidate(candidate),
            None => EventLink::Unknown,
        },
        UrlEvidence::Malformed | UrlEvidence::Absent => EventLink::Unknown,
    };
    match kind {
        "pull_ref" | "issue_ref" => match event.get("ref_issue") {
            Some(Value::Object(issue)) => match issue.get("pull_request") {
                Some(Value::Object(pull_request)) => {
                    let html_url = pull_request.get("html_url").and_then(Value::as_str);
                    match html_url.and_then(gitea_pr_candidate) {
                        Some(candidate) => match url_evidence {
                            UrlEvidence::Absent => EventLink::Candidate(candidate),
                            // A malformed secondary signal is contradictory
                            // evidence, never decoration on a resolved link.
                            UrlEvidence::Malformed => EventLink::Unknown,
                            UrlEvidence::Present(url) => match gitea_pr_candidate(url) {
                                // Both signals must name the same admitted
                                // pull request; a foreign or different PR is
                                // contradictory evidence, not a second link.
                                Some(secondary)
                                    if secondary.owner == candidate.owner
                                        && secondary.name == candidate.name
                                        && secondary.number == candidate.number =>
                                {
                                    EventLink::Candidate(candidate)
                                }
                                _ => EventLink::Unknown,
                            },
                        },
                        // A PR-shaped reference whose own URL cannot be
                        // resolved is never dismissed via a secondary field.
                        None => EventLink::Unknown,
                    }
                }
                // A plain referenced issue is no PR link on its own — but a
                // `pull_request_url` on the same event is contradictory
                // evidence and is examined before the plain-issue shortcut.
                Some(Value::Null) => match url_evidence {
                    UrlEvidence::Absent if kind == "issue_ref" => EventLink::Skip,
                    evidence => from_url(evidence),
                },
                None => from_url(url_evidence),
                Some(_) => EventLink::Unknown,
            },
            // The reference target itself is unreadable: potentially linked.
            _ => from_url(url_evidence),
        },
        // Any other event carrying a PR URL is potentially linked evidence.
        _ => match url_evidence {
            UrlEvidence::Absent => EventLink::Skip,
            evidence => from_url(evidence),
        },
    }
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
fn connected_candidate(event: &serde_json::Map<String, Value>) -> Result<CrossReference, ()> {
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
        return parse_pr_identity(url)
            .map(CrossReference::Resolved)
            .ok_or(());
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
                .map(CrossReference::Resolved)
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
    let provider = reader.provider();
    if provider == Provider::Gitea && (candidate.owner != "ezra" || candidate.name != "buaa-cli") {
        // A foreign candidate is never fetched: the live state of a linked
        // pull request is read only inside the admitted repository.
        return Err(GithubFailure::Fatal {
            code: "linked_pr_response_invalid",
            evidence: None,
        });
    }
    let url = format!(
        "{}/{}/{}/pulls/{}",
        provider.api_root(),
        candidate.owner,
        candidate.name,
        candidate.number
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
    let mut unknown_page = if truncated {
        pages.len().checked_sub(1)
    } else {
        None
    };
    for (page_index, page) in pages.iter().enumerate() {
        for item in &page.items {
            let link = match reader.provider() {
                Provider::Github => github_event_link(item),
                Provider::Gitea => gitea_event_link(item),
            };
            match link {
                EventLink::Skip => continue,
                EventLink::Unknown => {
                    unknown_page.get_or_insert(page_index);
                    continue;
                }
                EventLink::Candidate(candidate) => {
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
        "claim", "claims", "claimed", "claiming", "lease", "leases", "leased", "leasing",
    ];
    const PHRASE_MARKERS: &[&str] = &["working on this", "i'll take", "i will take", "taking this"];
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
                && (index + marker.len() == body.len() || !is_word_byte(body[index + marker.len()]))
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

fn api_url(provider: Provider, repository: &str, suffix: &str) -> String {
    format!("{}/{repository}{suffix}", provider.api_root())
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
    let provider = request.provider;

    let repository_url = api_url(provider, &request.repository, "");
    let repository_evidence = match reader.get(&repository_url) {
        Ok(evidence) => evidence,
        Err(GithubFailure::NotFound { evidence }) => {
            return Ok(blocked_before_permission(
                provider,
                &request.repository,
                "repository_not_found",
                evidence.as_ref(),
            ));
        }
        Err(GithubFailure::Fatal { code, evidence }) => {
            return Ok(blocked_before_permission(
                provider,
                &request.repository,
                code,
                evidence.as_ref(),
            ));
        }
    };
    let repository = match parse_repository(
        repository_evidence.body.as_slice(),
        &request.repository,
        provider,
    ) {
        Ok(repository) => repository,
        Err(RepositoryParseError::MissingPermissions) => {
            return Ok(blocked_before_permission(
                provider,
                &request.repository,
                "repository_permissions_missing",
                Some(&repository_evidence),
            ));
        }
        Err(RepositoryParseError::Invalid) => {
            return Ok(blocked_before_permission(
                provider,
                &request.repository,
                "repository_response_invalid",
                Some(&repository_evidence),
            ));
        }
    };

    let issues_url = api_url(
        provider,
        &repository.full_name,
        match provider {
            Provider::Github => "/issues?state=open&per_page=100",
            Provider::Gitea => "/issues?state=open&type=issues&limit=50",
        },
    );
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
                return Ok(blocked_after_permission(
                    &repository,
                    code,
                    evidence.as_ref(),
                ));
            }
        };
    let mut issues = Vec::new();
    let mut filtered_pull_requests = 0usize;
    if issues_truncated {
        return Ok(blocked_after_permission(
            &repository,
            "issues_list_truncated",
            None,
        ));
    }
    for page in &issue_pages {
        match parse_issues(&page.items, &repository.full_name, provider) {
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
        return Ok(blocked_after_permission(
            &repository,
            "duplicate_issue_identity",
            None,
        ));
    }
    let mut candidates = Vec::new();
    let mut excluded = Vec::new();
    for issue in issues {
        if !issue.initial_reasons.is_empty() {
            excluded.push(excluded_issue(&issue, issue.initial_reasons.clone()));
            continue;
        }

        let timeline_url = api_url(
            provider,
            &repository.full_name,
            &match provider {
                Provider::Github => format!("/issues/{}/timeline?per_page=100", issue.number),
                Provider::Gitea => format!("/issues/{}/timeline?limit=50", issue.number),
            },
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
                return Ok(blocked_after_permission(
                    &repository,
                    code,
                    evidence.as_ref(),
                ));
            }
        };
        let link_verdict = match analyze_link(reader, &timeline_pages, timeline_truncated) {
            Ok(verdict) => verdict,
            Err(GithubFailure::Fatal { code, evidence }) => {
                return Ok(blocked_after_permission(
                    &repository,
                    code,
                    evidence.as_ref(),
                ));
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
            provider,
            &repository.full_name,
            &match provider {
                Provider::Github => format!("/issues/{}/comments?per_page=100", issue.number),
                // The Gitea comments endpoint has no pagination: one complete read.
                Provider::Gitea => format!("/issues/{}/comments", issue.number),
            },
        );
        let (comment_pages, comments_truncated) = match provider {
            Provider::Github => match reader.get_pages(
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
                    return Ok(blocked_after_permission(
                        &repository,
                        code,
                        evidence.as_ref(),
                    ));
                }
            },
            Provider::Gitea => match reader.get(&comments_url) {
                Ok(evidence) => {
                    let parsed = serde_json::from_slice::<Value>(evidence.body.as_slice());
                    // Exactly one complete response: unique numeric comment
                    // ids and an X-Total-Count equal to the number of rows.
                    // Anything less excludes the issue as claim-unknown.
                    let complete = match &parsed {
                        Ok(Value::Array(items)) => {
                            let mut ids = std::collections::BTreeSet::new();
                            items.len() <= MAX_COMMENT_ITEMS
                                && items.iter().all(|item| {
                                    item.get("id")
                                        .and_then(Value::as_u64)
                                        .is_some_and(|id| ids.insert(id))
                                })
                                && evidence.total_count == Some(items.len() as u64)
                        }
                        _ => false,
                    };
                    if !complete {
                        let mut item = excluded_issue(&issue, vec!["claim_status_unknown"]);
                        item = attach_raw_evidence(
                            item,
                            provider.code(Code::CommentsIncomplete),
                            &evidence,
                        );
                        excluded.push(item);
                        continue;
                    }
                    let items = match parsed {
                        Ok(Value::Array(items)) => items,
                        _ => unreachable!("completeness required an array"),
                    };
                    (vec![Page { items, evidence }], false)
                }
                Err(GithubFailure::NotFound { evidence }) => {
                    let mut item = excluded_issue(&issue, vec!["claim_status_unknown"]);
                    if let Some(evidence) = evidence.as_ref() {
                        item = attach_raw_evidence(item, "claim_status_unknown", evidence);
                    }
                    excluded.push(item);
                    continue;
                }
                Err(GithubFailure::Fatal { code, evidence }) => {
                    return Ok(blocked_after_permission(
                        &repository,
                        code,
                        evidence.as_ref(),
                    ));
                }
            },
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
                        match (
                            timestamp(comment, "created_at"),
                            timestamp(comment, "updated_at"),
                        ) {
                            (Ok(created), Ok(updated)) => {
                                discussion_recent |= recent(created, now) || recent(updated, now)
                            }
                            _ => {
                                unknown_evidence = Some(&page.evidence);
                                break 'comments;
                            }
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
            excluded.push(excluded_issue(
                &issue,
                vec!["recent_claim_or_lease_comment"],
            ));
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

    let mut output = base_output(provider, &repository.full_name, "scan_completed");
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
    if repository.disabled == Some(true) {
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
    if input.len() > MAX_INPUT {
        return Err(invalid_input());
    }
    let request = ScanRequest::from_input(input).map_err(|_| invalid_input())?;
    if !valid_repository(&request.repository) {
        return Err(invalid_input());
    }
    // Ambiguous cross-provider credentials are refused before any network
    // use; only the selected provider's own token may remain.
    let provider_token = request.provider_token().map_err(|_| invalid_input())?;
    if request
        .github_token
        .iter()
        .chain(request.gitea_token.iter())
        .any(|secret| request.repository.contains(secret.0.as_str()))
    {
        return Err(invalid_input());
    }
    if request.provider == Provider::Gitea
        && !request.repository.eq_ignore_ascii_case(GITEA_REPOSITORY)
    {
        // No caller-chosen origin or foreign/private repository: this slice
        // reads only the fixed admitted Gitea primary repository.
        return Err(invalid_input());
    }
    if !request.online || provider_token.is_none() {
        let reason = if !request.online {
            "explicit_online_permission_required"
        } else {
            match request.provider {
                Provider::Github => "github_token_required",
                Provider::Gitea => "gitea_token_required",
            }
        };
        return Ok(blocked_before_permission(
            request.provider,
            &request.repository,
            reason,
            None,
        ));
    }
    let governor = Governor::open().map_err(|_| {
        crate::net::Error::new("governor_unavailable", "shared governor unavailable")
    })?;
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .no_proxy()
        .https_only(true)
        .connect_timeout(std::time::Duration::from_secs(10))
        .user_agent("buaa-cli/0.1")
        .build()
        .map_err(|_| {
            crate::net::Error::new(
                match request.provider {
                    Provider::Github => "github_transport_unavailable",
                    Provider::Gitea => "gitea_transport_unavailable",
                },
                "HTTPS client unavailable",
            )
        })?;
    let reader = GithubReader {
        client,
        provider: request.provider,
        token: provider_token.ok_or_else(invalid_input)?,
        governor: &governor,
    };
    scan_with_reader(&request, &reader)
}

pub fn schema() -> Value {
    json!({
        "input": {"type":"object", "additionalProperties":false, "required":["repository"],
            "description":"Exactly one JSON object; top-level arrays and other JSON values are refused. Standard JSON string escapes and whitespace are accepted.",
            "properties": {"repository":{"type":"string",
                    "pattern":"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9._-]{1,100}$",
                    "not":{"pattern":"^[^/]+/(\\.\\.?)$"},
                    "description":"owner/repository, not a URL. provider gitea admits only ezra/buaa-cli"},
                "provider":{"type":"string","enum":["github","gitea"],"default":"github",
                    "description":"Forge to read. gitea is pinned to https://doesvm.icefish-exponential.ts.net:8444/api/v1 and repository ezra/buaa-cli; no caller-chosen origin"},
                "online":{"type":"boolean","default":false,"description":"Explicit authorization for bounded authenticated read-only provider requests"},
                "github_token":{"type":"string","writeOnly":true,"minLength":8,"maxLength":4096,
                    "pattern":"^[A-Za-z0-9_]+$","description":"GitHub credential for provider github only; rejected when provider is gitea. stdin JSON only; decoded credential must match the ASCII pattern; zeroizing typed credential; never argv, URL, log, error or output"},
                "gitea_token":{"type":"string","writeOnly":true,"minLength":8,"maxLength":4096,
                    "pattern":"^[A-Za-z0-9_]+$","description":"Gitea credential for provider gitea only; rejected when provider is github. Same stdin/zeroizing/non-disclosure rules as github_token"}}},
        "output":{"type":"object","required":["schema_version","type","result","provider","repository","permission","candidates","excluded","blockers","write_operations_performed","policy"],
            "properties":{"schema_version":{"const":1},"type":{"const":"contribution"},
                "result":{"enum":["blocked","scan_completed"]},"write_operations_performed":{"const":false},
                "provider":{"type":"string","enum":["github","gitea"]},
                "repository":{"type":"string"},
                "reason":{"type":"string","description":"Present when the scan is blocked"},
                "fallback_reason":{"type":"string","description":"Present when a per-issue exclusion carries response metadata"},
                "response":{"type":"object","description":"Status and completeness only. No raw authenticated body, header or credential is exported."},
                "permission":{"type":"object","description":"Authenticated repository permission metadata, or explicitly unknown before admission",
                    "properties":{"source":{"type":"string"},"provider":{"type":"string","enum":["github","gitea"]},"metadata_present":{"type":"boolean"},
                        "admin":{"type":["boolean","null"]},"maintain":{"type":["boolean","null"],"description":"GitHub only; null for Gitea, never a fabricated false"},
                        "push":{"type":["boolean","null"]},"triage":{"type":["boolean","null"],"description":"GitHub only; null for Gitea"},
                        "pull":{"type":["boolean","null"]},
                        "can_write":{"type":["boolean","null"]},"can_triage":{"type":["boolean","null"]},
                        "archived":{"type":["boolean","null"]},"disabled":{"type":["boolean","null"],"description":"GitHub only; null for Gitea (not applicable)"}}},
                "claim_window_seconds":{"const":CLAIM_WINDOW_SECONDS},
                "candidates":{"type":"array","description":"Untrusted issue metadata, not authorization to claim or create a PR"},
                "excluded":{"type":"array"},"filtered_pull_requests":{"type":"integer","minimum":0},
                "blockers":{"type":"array"},"policy":{"type":"object"}}},
        "limits":{"response_bytes":MAX_BODY,"issue_pages":MAX_LIST_PAGES,"issue_items":MAX_LIST_ITEMS,
            "timeline_pages_per_issue":MAX_TIMELINE_PAGES,"timeline_items_per_issue":MAX_TIMELINE_ITEMS,
            "linked_pr_reads_per_issue":MAX_PR_CANDIDATES,"comment_pages_per_issue":MAX_COMMENT_PAGES,
            "comment_items_per_issue":MAX_COMMENT_ITEMS,"gitea_page_limit":GITEA_PAGE_LIMIT,
            "request_total_deadline_seconds":30},
        "description":"Offline default performs no requests or credential lookup. Online requires explicit permission and the selected provider's stdin token; the other provider's token is rejected as ambiguous. Each bounded GET uses its own shared governor lease, no redirects or retries, strict TLS, and Set-Cookie responses are refused rather than adopted. Stops on unsafe response; ambiguous per-issue link/claim evidence excludes that issue. Truncated issue enumeration blocks the scan. GitHub pages via Link headers; Gitea pages issues/timeline with page+limit=50 to a real empty page. X-Total-Count never stops the read: a count larger than the rows that response returned is an overall total that must stay stable and must equal the collected rows, while a count equal to that page's own rows is this page's row count and proves nothing. Gitea comments are read exactly once with a required matching X-Total-Count. Recent comments, claim/lease markers, assigned issues and confirmed open linked PRs exclude candidates. Gitea linked-PR evidence comes only from pull_ref/issue_ref timeline entries and pull_request_url URLs inside ezra/buaa-cli; unknown or foreign links exclude. No claim, PR creation, or merge; Gitea policy does not transfer gh stack or GitHub approvals. Discovery is a point-in-time observation, not a lifecycle write gate or online acceptance proof."
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
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        for (first, status, challenge) in [
            ("1", 200, false),
            ("malformed", 200, false),
            ("1", 429, true),
            ("malformed", 429, true),
        ] {
            let root = std::env::temp_dir().join(format!(
                "buaa-contribution-retry-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            let fixture = Fixture(root);
            let governor = Governor::isolated_for_test(&fixture.0.join("governor")).unwrap();
            let mut lease = governor
                .try_acquire(crate::governor::RequestKind::Interactive)
                .unwrap();
            let mut headers = reqwest::header::HeaderMap::new();
            headers.append(
                "retry-after",
                reqwest::header::HeaderValue::from_str(first).unwrap(),
            );
            headers.append(
                "retry-after",
                reqwest::header::HeaderValue::from_static("1800"),
            );
            // Duplicate metadata still refuses admission, but every cooldown
            // must already be durable before a failed body closes the lease.
            observe_github_headers(&mut lease, status, &headers, challenge).unwrap();
            lease
                .finish(Outcome::Http {
                    status,
                    retry_after: Some(first),
                    challenge,
                    network_failure: true,
                })
                .unwrap();
            let state = governor.status().unwrap();
            assert!(state.cooldown_wait > std::time::Duration::from_secs(1700));
            assert_eq!(state.safety_latched, false);
            assert!(
                governor
                    .try_acquire(crate::governor::RequestKind::Interactive)
                    .is_err()
            );
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
        let error = parse_repository(&repository(None), "octo/repo", Provider::Github).unwrap_err();
        assert_eq!(error, super::RepositoryParseError::MissingPermissions);

        let read_only = parse_repository(
            &repository(Some(permissions(false, false, false, false))),
            "octo/repo",
            Provider::Github,
        )
        .unwrap();
        assert!(!read_only.permissions.can_write());
        assert!(!read_only.permissions.can_triage());

        let triage_only = parse_repository(
            &repository(Some(permissions(false, false, false, true))),
            "octo/repo",
            Provider::Github,
        )
        .unwrap();
        assert!(!triage_only.permissions.can_write());
        assert!(triage_only.permissions.can_triage());

        let push = parse_repository(
            &repository(Some(permissions(false, false, true, false))),
            "octo/repo",
            Provider::Github,
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
        let parsed = parse_issues(
            &items(vec![pull_request, closed, assigned, open]),
            "octo/repo",
            Provider::Github,
        )
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
        assert!(parse_issues(&items(vec![spoofed]), "octo/repo", Provider::Github).is_err());

        let mut pull_request = issue(8);
        pull_request["html_url"] = json!("https://example.invalid/pull/8");
        pull_request["pull_request"] = Value::Null;
        let parsed =
            parse_issues(&items(vec![pull_request]), "octo/repo", Provider::Github).unwrap();
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
        let candidate =
            parse_pr_identity("https://api.github.com/repos/octo/repo/pulls/42").unwrap();
        assert_eq!(candidate.owner, "octo");
        assert_eq!(candidate.name, "repo");
        assert_eq!(candidate.number, 42);
        assert!(parse_pr_identity("https://example.invalid/repos/octo/repo/pulls/42").is_none());
        assert!(parse_pr_identity("https://api.github.com/repos/octo/repo/issues/42").is_none());
    }
    struct Pages(std::cell::RefCell<std::collections::VecDeque<(String, PageEvidence)>>);
    impl GithubRead for Pages {
        fn get(&self, url: &str) -> Result<PageEvidence, GithubFailure> {
            let (expected, page) = self.0.borrow_mut().pop_front().expect("unexpected request");
            assert_eq!(url, expected);
            Ok(page)
        }
    }
    fn page(items: Value, link: Option<String>) -> PageEvidence {
        PageEvidence {
            status: 200,
            link: link.map(zeroize::Zeroizing::new),
            total_count: None,
            body_complete: true,
            body: zeroize::Zeroizing::new(serde_json::to_vec(&items).unwrap()),
        }
    }
    #[test]
    fn later_comment_pages_preserve_recent_claims() {
        let first = "https://api.github.com/repos/octo/repo/issues/1/comments?per_page=100";
        let second = format!("{first}&page=2");
        let pages = Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
            (
                first.to_owned(),
                page(json!([]), Some(format!("<{second}>; rel=\"next\""))),
            ),
            (
                second,
                page(
                    json!([{"body":"I claim this", "created_at":"2026-10-27T11:00:00Z", "updated_at":"2026-10-27T11:00:00Z"}]),
                    None,
                ),
            ),
        ])));
        let (all, truncated) = pages
            .get_pages(first, 10, 1000, None)
            .unwrap_or_else(|_| panic!("fixture failed"));
        assert_eq!(all.len(), 2);
        assert!(!truncated);
        assert!(
            all.iter()
                .flat_map(|p| &p.items)
                .any(|c| comment_claims_issue(c, now()) == Ok(true))
        );
        assert!(pages.0.borrow().is_empty());
    }
    #[test]
    fn bounded_pagination_never_treats_truncation_as_complete() {
        let url = "https://api.github.com/repos/octo/repo/issues?per_page=100";
        let pages = Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
            (
                url.to_owned(),
                page(json!([]), Some(format!("<{url}&page=2>; rel=\"next\""))),
            ),
        ])));
        assert!(
            pages
                .get_pages(url, 1, 1000, None)
                .unwrap_or_else(|_| panic!("fixture failed"))
                .1
        );
    }
    #[test]
    fn later_timeline_page_requires_live_pull_request_state() {
        let first = "https://api.github.com/repos/octo/repo/issues/1/timeline?per_page=100";
        let second = format!("{first}&page=2");
        let pr = "https://api.github.com/repos/octo/repo/pulls/42";
        let pages = Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
            (
                first.to_owned(),
                page(json!([]), Some(format!("<{second}>; rel=\"next\""))),
            ),
            (
                second,
                page(
                    json!([{"event":"cross-referenced","source":{"issue":{"pull_request":{"url":pr}}}}]),
                    None,
                ),
            ),
            (
                pr.to_owned(),
                page(json!({"number":42,"state":"open"}), None),
            ),
        ])));
        let (timeline, truncated) = pages
            .get_pages(first, 5, 500, None)
            .unwrap_or_else(|_| panic!("fixture failed"));
        assert!(matches!(
            analyze_link(&pages, &timeline, truncated),
            Ok(LinkVerdict::LinkedOpen)
        ));
        assert!(pages.0.borrow().is_empty());
    }
    #[test]
    fn null_pull_request_marker_stays_unknown_not_eligible() {
        let first = "https://api.github.com/repos/octo/repo/issues/1/timeline?per_page=100";
        let pages = Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
            (
                first.to_owned(),
                page(
                    json!([{"event":"cross-referenced","source":{"issue":{"pull_request":null}}}]),
                    None,
                ),
            ),
        ])));
        let (timeline, truncated) = pages
            .get_pages(first, 5, 500, None)
            .unwrap_or_else(|_| panic!("fixture failed"));
        assert!(matches!(
            analyze_link(&pages, &timeline, truncated),
            Ok(LinkVerdict::Unknown(_))
        ));
        // The unresolved marker must not trigger a live pull request read.
        assert!(pages.0.borrow().is_empty());
    }
    #[test]
    fn scan_excludes_issue_with_null_cross_reference_marker() {
        let request = ScanRequest::from_input(r#"{"repository":"octo/repo"}"#).unwrap();
        let pages = Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
            (
                "https://api.github.com/repos/octo/repo".to_owned(),
                page(
                    json!({"id":123,"full_name":"octo/repo","archived":false,"disabled":false,
                    "permissions":permissions(false,false,true,true)}),
                    None,
                ),
            ),
            (
                "https://api.github.com/repos/octo/repo/issues?state=open&per_page=100".to_owned(),
                page(json!([issue(1)]), None),
            ),
            (
                "https://api.github.com/repos/octo/repo/issues/1/timeline?per_page=100".to_owned(),
                page(
                    json!([{"event":"cross-referenced","source":{"issue":{"pull_request":null}}}]),
                    None,
                ),
            ),
        ])));
        let output = scan_with_reader(&request, &pages).unwrap();
        assert_eq!(output["result"], "scan_completed");
        assert_eq!(output["candidates"], json!([]));
        assert_eq!(
            output["excluded"][0]["reasons"],
            json!(["linked_pr_status_unknown"])
        );
        assert!(pages.0.borrow().is_empty());
    }

    #[test]
    fn pagination_rejects_cross_endpoint_and_cycles() {
        let url = "https://api.github.com/repos/octo/repo/issues";
        for next in [url, "https://api.github.com/repos/other/repo/issues"] {
            let pages = Pages(std::cell::RefCell::new(std::collections::VecDeque::from([
                (
                    url.to_owned(),
                    page(json!([]), Some(format!("<{next}>; rel=\"next\""))),
                ),
            ])));
            assert!(pages.get_pages(url, 10, 1000, None).is_err());
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
        assert!(!pagination_path_allowed(
            first,
            "/repositories/123/issues/2/comments",
            Some(123)
        ));
    }
    #[test]
    fn offline_default_never_requires_a_transport() {
        let out = scan(r#"{"repository":"octo/repo"}"#).unwrap();
        assert_eq!(out["reason"], "explicit_online_permission_required");
        assert_eq!(out["write_operations_performed"], false);
    }
    #[test]
    fn decoded_secret_reflection_is_private() {
        // A literal reflection and a JSON-escaped reflection are both
        // detected without materializing an ordinary Value.
        assert_eq!(
            secret_reflection(br#"{"nested":["private_token"]}"#, "private_token", true),
            SecretReflection::Present
        );
        assert_eq!(
            secret_reflection(
                br#"{"nested":["private\u005ftoken"]}"#,
                "private_token",
                true
            ),
            SecretReflection::Present
        );
        assert_eq!(
            secret_reflection(br#"{"private\u005ftoken":"value"}"#, "private_token", true),
            SecretReflection::Present
        );
        assert_eq!(
            secret_reflection(br#"{"nested":["unrelated"]}"#, "private_token", true),
            SecretReflection::Absent
        );
        assert_eq!(
            secret_reflection(br#"{"nested":["a\nclean\tvalue"]}"#, "private_token", true),
            SecretReflection::Absent
        );
        // An undecodable escape leaves the reflection unresolved, so the
        // response cannot be admitted.
        assert_eq!(
            secret_reflection(
                br#"{"nested":["private\u00zztoken"]}"#,
                "private_token",
                true
            ),
            SecretReflection::Unresolved
        );
        assert!(
            serde_json::from_str::<ScanRequest>(
                r#"{"repository":"octo/repo","github_token":"bad secret"}"#
            )
            .is_err()
        );
        // Standard JSON escapes are accepted by the real typed input path.
        let escaped = r#"{"repository":"octo\/repo","github_token":"ghp_\u0073ecret"}"#;
        let request = ScanRequest::from_input(escaped).unwrap();
        assert_eq!(request.repository, "octo/repo");
        assert_eq!(
            request.github_token.as_ref().unwrap().0.as_str(),
            "ghp_secret"
        );
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
        let offline = scan(
            "\t\r\n {\"repository\":\"octo/repo\",\"github_token\":\"ghp_synthetic_token\"} \r\n",
        )
        .unwrap();
        assert_eq!(offline["reason"], "explicit_online_permission_required");
        assert!(!offline.to_string().contains("ghp_synthetic_token"));
    }

    const GITEA_BASE: &str =
        "https://doesvm.icefish-exponential.ts.net:8444/api/v1/repos/ezra/buaa-cli";

    struct GiteaPages(std::cell::RefCell<std::collections::VecDeque<(String, PageEvidence)>>);
    impl GithubRead for GiteaPages {
        fn provider(&self) -> Provider {
            Provider::Gitea
        }
        fn get(&self, url: &str) -> Result<PageEvidence, GithubFailure> {
            let (expected, page) = self.0.borrow_mut().pop_front().expect("unexpected request");
            assert_eq!(url, expected);
            Ok(page)
        }
    }
    fn gpages(pages: Vec<(String, PageEvidence)>) -> GiteaPages {
        GiteaPages(std::cell::RefCell::new(std::collections::VecDeque::from(
            pages,
        )))
    }
    fn gpage(items: Value, total_count: Option<u64>) -> PageEvidence {
        PageEvidence {
            status: 200,
            link: None,
            total_count,
            body_complete: true,
            body: zeroize::Zeroizing::new(serde_json::to_vec(&items).unwrap()),
        }
    }
    fn gitea_issue(number: u64) -> Value {
        json!({
            "id": number + 1000,
            "number": number,
            "state": "open",
            "title": format!("synthetic gitea issue {number}"),
            "html_url": format!("https://doesvm.icefish-exponential.ts.net:8444/ezra/buaa-cli/issues/{number}"),
            "assignee": null,
            // The live Gitea primary serializes an unassigned issue with a
            // null assignee list, not an empty array.
            "assignees": null,
            "pull_request": null,
            "body": "untrusted issue body"
        })
    }
    fn gitea_repository_body(push: bool) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": 161,
            "full_name": "ezra/buaa-cli",
            "archived": false,
            "permissions": {"admin": false, "push": push, "pull": true}
        }))
        .unwrap()
    }
    fn gitea_request() -> ScanRequest {
        ScanRequest::from_input(r#"{"repository":"ezra/buaa-cli","provider":"gitea"}"#).unwrap()
    }

    // Page, PageEvidence and GithubFailure deliberately have no Debug
    // implementation: raw authenticated evidence must never be rendered.
    // These explicit matches are the opaque-safe equivalent of unwrap().
    fn gitea_pages_or_panic(result: Result<(Vec<Page>, bool), GithubFailure>) -> (Vec<Page>, bool) {
        match result {
            Ok(pages) => pages,
            Err(GithubFailure::Fatal { .. } | GithubFailure::NotFound { .. }) => {
                panic!("fixture failed")
            }
        }
    }
    fn gitea_fatal_code(result: Result<(Vec<Page>, bool), GithubFailure>) -> &'static str {
        match result {
            Err(GithubFailure::Fatal { code, .. }) => code,
            Err(GithubFailure::NotFound { .. }) | Ok(_) => panic!("expected a fatal read failure"),
        }
    }
    fn gitea_scan_or_panic(result: Result<Value, crate::net::Error>) -> Value {
        match result {
            Ok(output) => output,
            Err(_) => panic!("scan failed"),
        }
    }

    #[test]
    fn gitea_null_pull_request_is_an_issue_and_object_is_a_pr() {
        let plain = gitea_issue(1);
        let mut pull_request = gitea_issue(2);
        pull_request["pull_request"] = json!({"merged": false, "draft": true});
        let parsed = parse_issues(
            &items(vec![plain, pull_request]),
            "ezra/buaa-cli",
            Provider::Gitea,
        )
        .unwrap();
        assert_eq!(parsed.filtered_pull_requests, 1);
        assert_eq!(parsed.issues.len(), 1);
        assert_eq!(parsed.issues[0].number, 1);
        // Missing or malformed PR metadata is ambiguous, never a candidate.
        let mut missing = gitea_issue(3);
        missing.as_object_mut().unwrap().remove("pull_request");
        assert!(parse_issues(&items(vec![missing]), "ezra/buaa-cli", Provider::Gitea).is_err());
        let mut spoofed = gitea_issue(4);
        spoofed["html_url"] = json!("https://example.invalid/ezra/buaa-cli/issues/4");
        assert!(parse_issues(&items(vec![spoofed]), "ezra/buaa-cli", Provider::Gitea).is_err());
    }

    #[test]
    fn gitea_assignee_shapes_are_admitted_or_refused_by_their_own_meaning() {
        // The live primary serializes an unassigned issue with a null list.
        let null_list = gitea_issue(11);
        assert_eq!(null_list["assignees"], Value::Null);
        let parsed = parse_issues(
            &items(vec![null_list.clone()]),
            "ezra/buaa-cli",
            Provider::Gitea,
        )
        .expect("a null assignee list means no assignee");
        assert_eq!(parsed.issues.len(), 1);
        assert!(parsed.issues[0].initial_reasons.is_empty());

        // An explicit empty list means the same thing.
        let mut empty_list = null_list.clone();
        empty_list["assignees"] = json!([]);
        let parsed =
            parse_issues(&items(vec![empty_list]), "ezra/buaa-cli", Provider::Gitea).unwrap();
        assert!(parsed.issues[0].initial_reasons.is_empty());

        // A populated list is an assignment, never an unclaimed issue.
        let mut assigned = null_list.clone();
        assigned["assignees"] = json!([{"login": "untrusted-assignee"}]);
        let parsed =
            parse_issues(&items(vec![assigned]), "ezra/buaa-cli", Provider::Gitea).unwrap();
        assert_eq!(parsed.issues[0].initial_reasons, vec!["assigned"]);

        // Any other shape is ambiguous and never an unclaimed issue.
        for malformed in [json!("untrusted"), json!({"login": "untrusted"}), json!(7)] {
            let mut item = null_list.clone();
            item["assignees"] = malformed;
            assert!(
                parse_issues(&items(vec![item]), "ezra/buaa-cli", Provider::Gitea).is_err(),
                "a malformed assignee list must be refused"
            );
        }
        let mut missing = null_list.clone();
        missing.as_object_mut().unwrap().remove("assignees");
        assert!(parse_issues(&items(vec![missing]), "ezra/buaa-cli", Provider::Gitea).is_err());

        // The null spelling is a Gitea fact. GitHub keeps its own array
        // requirement, so the same shape stays refused there.
        let github_issue = json!({
            "id": 11,
            "number": 11,
            "state": "open",
            "title": "synthetic github issue",
            "html_url": "https://github.com/cyjin-yl/buaa-cli/issues/11",
            "assignee": null,
            "assignees": null,
            "body": "untrusted issue body"
        });
        assert!(
            parse_issues(
                &items(vec![github_issue]),
                "cyjin-yl/buaa-cli",
                Provider::Github
            )
            .is_err()
        );
    }

    #[test]
    fn gitea_empty_timeline_is_a_null_body_and_the_count_oracle_is_read_consistently() {
        let first = format!("{GITEA_BASE}/issues/1/timeline?limit=50");
        // The live primary returns JSON `null` for an empty timeline.
        let pages = gpages(vec![
            (format!("{first}&page=1"), gpage(Value::Null, Some(0))),
            (format!("{first}&page=2"), gpage(Value::Null, Some(0))),
        ]);
        let (pages, truncated) = gitea_pages_or_panic(pages.get_pages(&first, 5, 500, None));
        assert!(!truncated);
        assert_eq!(pages.len(), 1);
        assert!(pages[0].items.is_empty());

        // A null body without an advertised count establishes no oracle; the
        // real empty page is then the completeness evidence.
        let pages = gpages(vec![(format!("{first}&page=1"), gpage(Value::Null, None))]);
        let (pages, truncated) = gitea_pages_or_panic(pages.get_pages(&first, 5, 500, None));
        assert!(!truncated);
        assert_eq!(pages.len(), 1);

        // A null body that advertises more rows than it returned is an
        // overall total, and the collected rows must agree with it.
        let pages = gpages(vec![(
            format!("{first}&page=1"),
            gpage(Value::Null, Some(3)),
        )]);
        assert_eq!(
            gitea_fatal_code(pages.get_pages(&first, 5, 500, None)),
            "gitea_list_incomplete"
        );
    }

    #[test]
    fn gitea_page_counts_may_be_overall_totals_or_this_page_rows() {
        let first = format!("{GITEA_BASE}/issues/1/timeline?limit=10");
        // The live timeline endpoint advertises this page's own row count, so
        // a shrinking count across pages is normal there.
        let pages = gpages(vec![
            (
                format!("{first}&page=1"),
                gpage(json!([gitea_issue(1), gitea_issue(2)]), Some(2)),
            ),
            (
                format!("{first}&page=2"),
                gpage(json!([gitea_issue(3)]), Some(1)),
            ),
            (format!("{first}&page=3"), gpage(Value::Null, Some(0))),
        ]);
        let (pages, truncated) = gitea_pages_or_panic(pages.get_pages(&first, 5, 500, None));
        assert!(!truncated);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages.iter().map(|page| page.items.len()).sum::<usize>(), 3);

        // The issue list advertises the overall total on every page. Two
        // different overall totals are drift and never a clean end.
        let list = format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50");
        let pages = gpages(vec![
            (
                format!("{list}&page=1"),
                gpage(json!([gitea_issue(1)]), Some(9)),
            ),
            (format!("{list}&page=2"), gpage(json!([]), Some(8))),
        ]);
        assert_eq!(
            gitea_fatal_code(pages.get_pages(&list, 5, 500, None)),
            "gitea_total_count_unstable"
        );

        // A page that carries more rows than it advertises is a contradiction.
        let pages = gpages(vec![(
            format!("{list}&page=1"),
            gpage(json!([gitea_issue(1), gitea_issue(2)]), Some(1)),
        )]);
        assert_eq!(
            gitea_fatal_code(pages.get_pages(&list, 5, 500, None)),
            "gitea_list_incomplete"
        );

        // An overall oracle established on a later page must reject the
        // earlier readings immediately, without another request.
        let pages = gpages(vec![
            (
                format!("{list}&page=1"),
                gpage(json!([gitea_issue(1), gitea_issue(2)]), Some(2)),
            ),
            (
                format!("{list}&page=2"),
                gpage(json!([gitea_issue(3)]), Some(3)),
            ),
        ]);
        assert_eq!(
            gitea_fatal_code(pages.get_pages(&list, 5, 500, None)),
            "gitea_list_incomplete"
        );
        assert!(pages.0.borrow().is_empty());
    }

    #[test]
    fn gitea_permission_provenance_keeps_unreported_fields_unknown() {
        let repository = parse_repository(
            &gitea_repository_body(true),
            "ezra/buaa-cli",
            Provider::Gitea,
        )
        .unwrap();
        assert!(repository.permissions.can_write());
        assert!(repository.permissions.can_triage());
        let permission = repository.permission_json();
        assert_eq!(permission["provider"], "gitea");
        assert_eq!(permission["maintain"], Value::Null);
        assert_eq!(permission["triage"], Value::Null);
        assert_eq!(permission["disabled"], Value::Null);
        assert_eq!(permission["push"], true);
        assert_eq!(permission["archived"], false);

        let read_only = parse_repository(
            &gitea_repository_body(false),
            "ezra/buaa-cli",
            Provider::Gitea,
        )
        .unwrap();
        assert!(!read_only.permissions.can_write());
        assert!(!read_only.permissions.can_triage());
        let without_permissions = serde_json::to_vec(&json!({
            "id": 161, "full_name": "ezra/buaa-cli", "archived": false
        }))
        .unwrap();
        let error =
            parse_repository(&without_permissions, "ezra/buaa-cli", Provider::Gitea).unwrap_err();
        assert_eq!(error, super::RepositoryParseError::MissingPermissions);
    }

    #[test]
    fn gitea_short_page_is_not_terminal_and_empty_page_completes() {
        let first = format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50");
        let pages = gpages(vec![
            (
                format!("{first}&page=1"),
                gpage(json!([gitea_issue(1), gitea_issue(2)]), None),
            ),
            (format!("{first}&page=2"), gpage(json!([]), None)),
        ]);
        // Two rows is below the 50-row server cap, yet only the real empty
        // page proves completeness when no X-Total-Count is present.
        let (all, truncated) = gitea_pages_or_panic(pages.get_pages(&first, 10, 1000, None));
        assert!(!truncated);
        assert_eq!(all.iter().map(|page| page.items.len()).sum::<usize>(), 2);
        assert!(pages.0.borrow().is_empty());
    }

    #[test]
    fn gitea_count_agreement_still_reads_the_empty_terminal() {
        let first = format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50");
        // Reaching the advertised total is not a stop condition: the reader
        // must still consume the real empty page that agrees with it.
        let pages = gpages(vec![
            (
                format!("{first}&page=1"),
                gpage(json!([gitea_issue(1), gitea_issue(2)]), Some(2)),
            ),
            (format!("{first}&page=2"), gpage(json!([]), Some(2))),
        ]);
        let (all, truncated) = gitea_pages_or_panic(pages.get_pages(&first, 10, 1000, None));
        assert!(!truncated);
        assert_eq!(all.iter().map(|page| page.items.len()).sum::<usize>(), 2);
        assert!(pages.0.borrow().is_empty());
    }

    #[test]
    fn gitea_count_drift_and_incomplete_terminal_are_refused() {
        let first = format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50");
        // An empty page that contradicts the advertised total is incomplete.
        let pages = gpages(vec![(format!("{first}&page=1"), gpage(json!([]), Some(1)))]);
        assert_eq!(
            gitea_fatal_code(pages.get_pages(&first, 10, 1000, None)),
            "gitea_list_incomplete"
        );
        // A total that changes between pages is drift, not more data.
        let pages = gpages(vec![
            (
                format!("{first}&page=1"),
                gpage(json!([gitea_issue(1)]), Some(3)),
            ),
            (
                format!("{first}&page=2"),
                gpage(json!([gitea_issue(2)]), Some(4)),
            ),
        ]);
        assert_eq!(
            gitea_fatal_code(pages.get_pages(&first, 10, 1000, None)),
            "gitea_total_count_unstable"
        );
        assert!(pages.0.borrow().is_empty());
        // A page that disagrees with an already established overall total is
        // inconsistency, never a successful truncated omission.
        let pages = gpages(vec![
            (
                format!("{first}&page=1"),
                gpage(json!([gitea_issue(1)]), Some(3)),
            ),
            (
                format!("{first}&page=2"),
                gpage(json!([gitea_issue(2)]), Some(1)),
            ),
        ]);
        assert_eq!(
            gitea_fatal_code(pages.get_pages(&first, 10, 1000, None)),
            "gitea_list_incomplete"
        );
        assert!(pages.0.borrow().is_empty());

        // A list whose count is this page's own row count is accepted, and
        // the real empty page is its completeness evidence.
        let pages = gpages(vec![
            (
                format!("{first}&page=1"),
                gpage(json!([gitea_issue(1)]), Some(1)),
            ),
            (
                format!("{first}&page=2"),
                gpage(json!([gitea_issue(2)]), Some(1)),
            ),
            (format!("{first}&page=3"), gpage(json!([]), Some(0))),
        ]);
        let (pages, truncated) = gitea_pages_or_panic(pages.get_pages(&first, 10, 1000, None));
        assert!(!truncated);
        assert_eq!(pages.iter().map(|page| page.items.len()).sum::<usize>(), 2);
    }

    #[test]
    fn gitea_duplicate_identity_and_bound_stop_without_extra_requests() {
        let first = format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50");
        let pages = gpages(vec![
            (
                format!("{first}&page=1"),
                gpage(json!([gitea_issue(1)]), None),
            ),
            (
                format!("{first}&page=2"),
                gpage(json!([gitea_issue(1)]), None),
            ),
        ]);
        assert_eq!(
            gitea_fatal_code(pages.get_pages(&first, 10, 1000, None)),
            "gitea_duplicate_list_identity"
        );
        assert!(pages.0.borrow().is_empty());
        // The page bound reports truncation without probing another page.
        let pages = gpages(vec![(
            format!("{first}&page=1"),
            gpage(json!([gitea_issue(1)]), Some(5)),
        )]);
        let (_, truncated) = gitea_pages_or_panic(pages.get_pages(&first, 1, 1000, None));
        assert!(truncated);
        assert!(pages.0.borrow().is_empty());
    }

    #[test]
    fn gitea_pr_identity_is_confined_to_the_admitted_repository() {
        let api = format!("{GITEA_BASE}/pulls/42");
        assert_eq!(gitea_pr_candidate(&api).unwrap().number, 42);
        assert_eq!(
            gitea_pr_candidate(
                "https://doesvm.icefish-exponential.ts.net:8444/ezra/buaa-cli/pulls/42"
            )
            .unwrap()
            .number,
            42
        );
        for rejected in [
            "https://example.invalid/api/v1/repos/ezra/buaa-cli/pulls/42",
            "https://doesvm.icefish-exponential.ts.net:8444/api/v1/repos/other/private/pulls/42",
            "https://doesvm.icefish-exponential.ts.net:8444/other/buaa-cli/pulls/42",
            "https://doesvm.icefish-exponential.ts.net:8444/api/v1/repos/ezra/buaa-cli/issues/42",
            "https://doesvm.icefish-exponential.ts.net:8444/ezra/buaa-cli/pulls/0",
            "https://doesvm.icefish-exponential.ts.net:8444/ezra/buaa-cli/pulls/42/files",
        ] {
            assert!(
                gitea_pr_candidate(rejected).is_none(),
                "{rejected} must stay unresolved"
            );
        }
        assert!(api_url_allowed(Provider::Gitea, &api));
        assert!(!api_url_allowed(
            Provider::Gitea,
            "https://doesvm.icefish-exponential.ts.net:8444/api/v1/repos/other/private"
        ));
        assert!(!api_url_allowed(
            Provider::Gitea,
            "https://api.github.com/repos/ezra/buaa-cli"
        ));
        assert!(!api_url_allowed(
            Provider::Gitea,
            "https://doesvm.icefish-exponential.ts.net/api/v1/repos/ezra/buaa-cli"
        ));
    }

    #[test]
    fn gitea_open_linked_pr_excludes_and_unknown_link_never_reads_live_state() {
        let pr_web = "https://doesvm.icefish-exponential.ts.net:8444/ezra/buaa-cli/pulls/42";
        let timeline = json!([{
            "id": 900,
            "type": "pull_ref",
            "ref_issue": {"id": 42, "pull_request": {"merged": false, "html_url": pr_web}}
        }]);
        let pages = gpages(vec![
            (
                GITEA_BASE.to_owned(),
                gpage(
                    json!({"id":161,"full_name":"ezra/buaa-cli","archived":false,
                "permissions":{"admin":false,"push":true,"pull":true}}),
                    None,
                ),
            ),
            (
                format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50&page=1"),
                gpage(json!([gitea_issue(1)]), Some(1)),
            ),
            (
                format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50&page=2"),
                gpage(json!([]), Some(1)),
            ),
            (
                format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=1"),
                gpage(timeline.clone(), Some(1)),
            ),
            (
                format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=2"),
                gpage(json!([]), Some(1)),
            ),
            (
                format!("{GITEA_BASE}/pulls/42"),
                gpage(json!({"number":42,"state":"open"}), None),
            ),
        ]);
        let output = gitea_scan_or_panic(scan_with_reader(&gitea_request(), &pages));
        assert_eq!(output["provider"], "gitea");
        assert_eq!(output["candidates"], json!([]));
        assert_eq!(output["excluded"][0]["reasons"], json!(["linked_open_pr"]));
        assert!(pages.0.borrow().is_empty());

        // A foreign PR-shaped reference excludes as unknown and triggers no
        // live pull request read and no comments read.
        let mut foreign = timeline.clone();
        foreign[0]["ref_issue"]["pull_request"]["html_url"] =
            json!("https://example.invalid/ezra/buaa-cli/pulls/42");
        let pages = gpages(vec![
            (
                GITEA_BASE.to_owned(),
                gpage(
                    json!({"id":161,"full_name":"ezra/buaa-cli","archived":false,
                "permissions":{"admin":false,"push":true,"pull":true}}),
                    None,
                ),
            ),
            (
                format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50&page=1"),
                gpage(json!([gitea_issue(1)]), Some(1)),
            ),
            (
                format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50&page=2"),
                gpage(json!([]), Some(1)),
            ),
            (
                format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=1"),
                gpage(foreign, Some(1)),
            ),
            (
                format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=2"),
                gpage(json!([]), Some(1)),
            ),
        ]);
        let output = gitea_scan_or_panic(scan_with_reader(&gitea_request(), &pages));
        assert_eq!(
            output["excluded"][0]["reasons"],
            json!(["linked_pr_status_unknown"])
        );
        assert_eq!(output["candidates"], json!([]));
        assert!(pages.0.borrow().is_empty());
    }

    #[test]
    fn gitea_issue_reference_to_plain_issue_and_comment_url_mapping() {
        let first = format!("{GITEA_BASE}/issues/1/timeline?limit=50");
        let plain = json!([{"id":900,"type":"issue_ref","ref_issue":{"id":7,"pull_request":null}}]);
        let pages = gpages(vec![
            (format!("{first}&page=1"), gpage(plain, Some(1))),
            (format!("{first}&page=2"), gpage(json!([]), Some(1))),
        ]);
        let (timeline, truncated) = gitea_pages_or_panic(pages.get_pages(&first, 5, 500, None));
        assert!(matches!(
            analyze_link(&pages, &timeline, truncated),
            Ok(LinkVerdict::NoLink)
        ));
        assert!(pages.0.borrow().is_empty());

        // A comment carrying an admitted pull_request_url resolves the PR.
        let pr_api = format!("{GITEA_BASE}/pulls/42");
        let comment = json!([{"id":901,"type":"comment","pull_request_url":pr_api.clone()}]);
        let pages = gpages(vec![
            (format!("{first}&page=1"), gpage(comment, Some(1))),
            (format!("{first}&page=2"), gpage(json!([]), Some(1))),
            (
                pr_api.clone(),
                gpage(json!({"number":42,"state":"closed"}), None),
            ),
        ]);
        let (timeline, truncated) = gitea_pages_or_panic(pages.get_pages(&first, 5, 500, None));
        assert!(matches!(
            analyze_link(&pages, &timeline, truncated),
            Ok(LinkVerdict::NoLink)
        ));
        assert!(pages.0.borrow().is_empty());
    }

    #[test]
    fn gitea_contradictory_or_malformed_pr_evidence_is_never_eligible() {
        let repository_page = || {
            (
                GITEA_BASE.to_owned(),
                gpage(
                    json!({"id":161,"full_name":"ezra/buaa-cli","archived":false,
                "permissions":{"admin":false,"push":true,"pull":true}}),
                    None,
                ),
            )
        };
        let issue_pages = || {
            vec![
                (
                    format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50&page=1"),
                    gpage(json!([gitea_issue(1)]), Some(1)),
                ),
                (
                    format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50&page=2"),
                    gpage(json!([]), Some(1)),
                ),
            ]
        };
        let timeline_pages = |event: Value| {
            vec![
                (
                    format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=1"),
                    gpage(json!([event]), Some(1)),
                ),
                (
                    format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=2"),
                    gpage(json!([]), Some(1)),
                ),
            ]
        };

        // A plain issue reference carrying a foreign pull_request_url is
        // contradictory evidence: the issue stays excluded as unknown and no
        // live read follows.
        let contradictory = json!({
            "id": 900, "type": "issue_ref",
            "ref_issue": {"id": 7, "pull_request": null},
            "pull_request_url": "https://example.invalid/other/repo/pulls/42"
        });
        let pages = gpages(
            [repository_page()]
                .into_iter()
                .chain(issue_pages())
                .chain(timeline_pages(contradictory))
                .collect(),
        );
        let output = gitea_scan_or_panic(scan_with_reader(&gitea_request(), &pages));
        assert_eq!(
            output["excluded"][0]["reasons"],
            json!(["linked_pr_status_unknown"])
        );
        assert_eq!(output["candidates"], json!([]));
        assert!(pages.0.borrow().is_empty());

        // The same plain issue reference with an admitted pull_request_url
        // resolves to that pull request and reads its live state.
        let admitted = json!({
            "id": 901, "type": "issue_ref",
            "ref_issue": {"id": 7, "pull_request": null},
            "pull_request_url": format!("{GITEA_BASE}/pulls/42")
        });
        let pages = gpages(
            [repository_page()]
                .into_iter()
                .chain(issue_pages())
                .chain(timeline_pages(admitted))
                .chain([(
                    format!("{GITEA_BASE}/pulls/42"),
                    gpage(json!({"number":42,"state":"open"}), None),
                )])
                .collect(),
        );
        let output = gitea_scan_or_panic(scan_with_reader(&gitea_request(), &pages));
        assert_eq!(output["excluded"][0]["reasons"], json!(["linked_open_pr"]));
        assert!(pages.0.borrow().is_empty());

        // A malformed non-string pull_request_url can never be dismissed.
        let malformed = json!({"id": 902, "type": "comment", "pull_request_url": 17});
        let pages = gpages(
            [repository_page()]
                .into_iter()
                .chain(issue_pages())
                .chain(timeline_pages(malformed))
                .collect(),
        );
        let output = gitea_scan_or_panic(scan_with_reader(&gitea_request(), &pages));
        assert_eq!(
            output["excluded"][0]["reasons"],
            json!(["linked_pr_status_unknown"])
        );
        assert_eq!(output["candidates"], json!([]));
        assert!(pages.0.borrow().is_empty());

        // Absent, null and empty pull_request_url carry no evidence at all.
        for value in [
            json!({}),
            json!({"pull_request_url": null}),
            json!({"pull_request_url": ""}),
        ] {
            let mut event = json!({"id": 903, "type": "comment"});
            event
                .as_object_mut()
                .unwrap()
                .extend(value.as_object().unwrap().clone());
            let pages = gpages(vec![
                (
                    format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=1"),
                    gpage(json!([event]), Some(1)),
                ),
                (
                    format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=2"),
                    gpage(json!([]), Some(1)),
                ),
            ]);
            let (timeline, truncated) = gitea_pages_or_panic(pages.get_pages(
                &format!("{GITEA_BASE}/issues/1/timeline?limit=50"),
                5,
                500,
                None,
            ));
            assert!(matches!(
                analyze_link(&pages, &timeline, truncated),
                Ok(LinkVerdict::NoLink)
            ));
            assert!(pages.0.borrow().is_empty());
        }
    }

    #[test]
    fn gitea_co_present_pr_signals_must_agree() {
        let repository_page = || {
            (
                GITEA_BASE.to_owned(),
                gpage(
                    json!({"id":161,"full_name":"ezra/buaa-cli","archived":false,
                        "permissions":{"admin":false,"push":true,"pull":true}}),
                    None,
                ),
            )
        };
        let issue_pages = || {
            vec![
                (
                    format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50&page=1"),
                    gpage(json!([gitea_issue(1)]), Some(1)),
                ),
                (
                    format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50&page=2"),
                    gpage(json!([]), Some(1)),
                ),
            ]
        };
        let primary_url = "https://doesvm.icefish-exponential.ts.net:8444/ezra/buaa-cli/pulls/42";
        let event_with_secondary = |id: u64, secondary: Value| {
            let mut event = json!({
                "id": id, "type": "pull_ref",
                "ref_issue": {"id": 42, "pull_request": {"merged": false, "html_url": primary_url}}
            });
            if !secondary.is_null() {
                event["pull_request_url"] = secondary;
            }
            event
        };
        let timeline_pages = |event: Value| {
            vec![
                (
                    format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=1"),
                    gpage(json!([event]), Some(1)),
                ),
                (
                    format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=2"),
                    gpage(json!([]), Some(1)),
                ),
            ]
        };

        // A malformed, foreign or different-number secondary signal is
        // contradictory evidence: exclusion as unknown, and no pull request
        // state or comments read follows.
        for (index, secondary) in [
            json!(17),
            json!("https://example.invalid/other/repo/pulls/42"),
            json!(format!("{GITEA_BASE}/pulls/43")),
        ]
        .into_iter()
        .enumerate()
        {
            let pages = gpages(
                [repository_page()]
                    .into_iter()
                    .chain(issue_pages())
                    .chain(timeline_pages(event_with_secondary(
                        900 + index as u64,
                        secondary,
                    )))
                    .collect(),
            );
            let output = gitea_scan_or_panic(scan_with_reader(&gitea_request(), &pages));
            assert_eq!(
                output["excluded"][0]["reasons"],
                json!(["linked_pr_status_unknown"])
            );
            assert_eq!(output["candidates"], json!([]));
            assert!(pages.0.borrow().is_empty());
        }

        // Control: a consistent secondary naming the same admitted pull
        // request preserves the resolved link; a closed linked PR leaves the
        // issue eligible once comments prove empty.
        let pages = gpages(
            [repository_page()]
                .into_iter()
                .chain(issue_pages())
                .chain(timeline_pages(event_with_secondary(
                    903,
                    json!(format!("{GITEA_BASE}/pulls/42")),
                )))
                .chain([
                    (
                        format!("{GITEA_BASE}/pulls/42"),
                        gpage(json!({"number":42,"state":"closed"}), None),
                    ),
                    (
                        format!("{GITEA_BASE}/issues/1/comments"),
                        gpage(json!([]), Some(0)),
                    ),
                ])
                .collect(),
        );
        let output = gitea_scan_or_panic(scan_with_reader(&gitea_request(), &pages));
        assert_eq!(output["result"], "scan_completed");
        assert_eq!(output["candidates"][0]["number"], 1);
        assert_eq!(output["excluded"], json!([]));
        assert!(pages.0.borrow().is_empty());
    }

    #[test]
    fn gitea_encoded_credential_reflection_is_withheld_before_projection() {
        use base64::{
            Engine as _,
            engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        };
        let token = "gitea_pat_0123456789abcdef0123456789abcdef01234567";
        let authorization = format!("token {token}");
        // An assigned (already excluded) issue still passes through title
        // projection: any reversible credential encoding inside untrusted
        // fields must withhold the whole page before titles are exported.
        let issue_page = |title: &str| {
            let mut issue = gitea_issue(5);
            issue["assignee"] = json!({"login": "untrusted-assignee"});
            issue["title"] = json!(title);
            serde_json::to_vec(&json!([issue])).unwrap()
        };
        let standard = STANDARD.encode(token);
        let percent_encode = |text: &str| {
            text.bytes()
                .map(|byte| format!("%{byte:02x}"))
                .collect::<String>()
        };
        for (name, title) in [
            ("base64", format!("assigned {standard}")),
            (
                "base64 unpadded",
                format!("assigned {}", standard.trim_end_matches('=')),
            ),
            (
                "url-safe base64",
                format!("assigned {}", URL_SAFE_NO_PAD.encode(token)),
            ),
            (
                "percent-encoded token",
                format!("assigned {}", percent_encode(token)),
            ),
            (
                "percent-encoded base64",
                format!("assigned {}", percent_encode(&standard)),
            ),
        ] {
            let body = issue_page(&title);
            assert_eq!(
                secret_reflection(&body, token, true),
                SecretReflection::Present,
                "{name} credential echo must withhold the page"
            );
        }
        // The first base64 character expressed as a JSON \u escape: the raw
        // bytes show no encoded credential, only the decoded string view
        // does. Raw JSON text is built by hand because serde_json never emits
        // \u escapes for printable ASCII.
        let escaped_base64 = {
            let first = standard.chars().next().unwrap();
            format!("\\u{:04x}{}", first as u32, &standard[first.len_utf8()..])
        };
        let escaped_body =
            format!(r#"[{{"id":1005,"title":"assigned {escaped_base64}","assignee":null}}]"#);
        assert_eq!(
            secret_reflection(escaped_body.as_bytes(), token, true),
            SecretReflection::Present,
            "JSON-escaped base64 credential echo must withhold the page"
        );
        // The complete transmitted Authorization value is itself protected.
        let header_echo = issue_page(&format!("assigned {}", STANDARD.encode(&authorization)));
        assert_eq!(
            secret_reflection(&header_echo, &authorization, true),
            SecretReflection::Present
        );
        // Ordinary control: an unrelated base64 payload stays admissible.
        let clean = issue_page(&format!(
            "assigned {}",
            STANDARD.encode("unrelated content")
        ));
        assert_eq!(
            secret_reflection(&clean, token, true),
            SecretReflection::Absent
        );
        assert_eq!(
            secret_reflection(&clean, &authorization, true),
            SecretReflection::Absent
        );
    }

    #[test]
    fn gitea_nested_encoding_reflection_is_withheld_before_projection() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let token = "gitea_pat_0123456789abcdef0123456789abcdef01234567";
        let issue_page = |title: &str| {
            let mut issue = gitea_issue(6);
            issue["assignee"] = json!({"login": "untrusted-assignee"});
            issue["title"] = json!(title);
            serde_json::to_vec(&json!([issue])).unwrap()
        };

        // JSON inside JSON: the credential hides behind an escape inside a
        // nested object carried in an ordinary title string.
        let nested = "note {\"v\":\"gitea_pat\\u005f0123456789abcdef0123456789abcdef01234567\"}";
        let body = issue_page(nested);
        assert_eq!(
            secret_reflection(&body, token, true),
            SecretReflection::Present,
            "escaped credential inside nested JSON must withhold the page"
        );
        // A duplicate inner key does not collapse: every string view is
        // reviewed, even one shadowed by a later safe value.
        let shadowed = "note {\"v\":\"gitea_pat\\u005f0123456789abcdef0123456789abcdef01234567\",\"v\":\"safe\"}";
        let body = issue_page(shadowed);
        assert_eq!(
            secret_reflection(&body, token, true),
            SecretReflection::Present,
            "duplicate-key shadowing must never hide the credential view"
        );
        // A base64 JSON envelope inside the title: nothing matches until the
        // envelope is decoded and its strings reviewed.
        let envelope = STANDARD.encode(format!("{{\"v\":\"{token}\"}}").as_bytes());
        for (name, title) in [
            ("base64 envelope", format!("assigned {envelope}")),
            // ASCII whitespace folds before decoding.
            (
                "base64 envelope with spaces",
                format!("{} {}", &envelope[..8], &envelope[8..]),
            ),
            // Percent composition: a percent-encoded envelope decodes to the
            // base64 text, which decodes to the JSON carrying the credential.
            (
                "percent-encoded envelope",
                format!(
                    "assigned {}",
                    envelope
                        .bytes()
                        .map(|byte| format!("%{byte:02x}"))
                        .collect::<String>()
                ),
            ),
        ] {
            let body = issue_page(&title);
            assert_eq!(
                secret_reflection(&body, token, true),
                SecretReflection::Present,
                "{name} must withhold the page"
            );
        }
        // Ordinary controls: long alphabetic runs, markdown, percent prose
        // and C++ all stay admissible — supported views are reviewed, not
        // blanket-refused.
        for title in [
            "a".repeat(64),
            "**bold** [link](https://example.invalid) 100% certain C++ code".to_owned(),
            format!("assigned {}", STANDARD.encode("another safe payload")),
        ] {
            let body = issue_page(&title);
            assert_eq!(
                secret_reflection(&body, token, true),
                SecretReflection::Absent,
                "{title} must stay admissible"
            );
        }
        // Budget/depth exhaustion and unreviewable nested JSON are
        // unresolved, never falsely clean.
        let mut deep = "{\"v\":\"clean\"}".to_owned();
        for _ in 0..8 {
            deep = STANDARD.encode(deep.as_bytes());
        }
        let body = issue_page(&deep);
        assert_eq!(
            secret_reflection(&body, token, true),
            SecretReflection::Unresolved,
            "depth exhaustion must never report absent"
        );
        let ambiguous = "note {\"v\":\"bad\\u00zz\"}";
        let body = issue_page(ambiguous);
        assert_eq!(
            secret_reflection(&body, token, true),
            SecretReflection::Unresolved,
            "unreviewable nested JSON must never report absent"
        );

        // An unterminated string tail carrying \u escapes hides bytes never
        // present literally: the decoded view must still expose the secret.
        let leak = STANDARD.encode("\"\\u0061bcdefgh".as_bytes());
        let body = issue_page(&format!("assigned {leak}"));
        assert_eq!(
            secret_reflection(&body, "abcdefgh", true),
            SecretReflection::Present,
            "escaped credential inside an unterminated string must withhold"
        );
        // An unterminated tail that cannot be reviewed for escapes is
        // unresolved, never silently absent.
        let bad_tail = "note \"bad\\u00zz";
        let body = issue_page(bad_tail);
        assert_eq!(
            secret_reflection(&body, token, true),
            SecretReflection::Unresolved
        );
        // Ordinary unmatched-quote and Windows-path prose without \u escapes
        // stay admissible: their bytes were already compared literally.
        for title in ["it's a \"quote without a pair", "open \"C:\\tools\\build"] {
            let body = issue_page(title);
            assert_eq!(
                secret_reflection(&body, token, true),
                SecretReflection::Absent,
                "{title} must stay admissible"
            );
        }
    }

    #[test]
    fn gitea_comments_are_one_complete_read_and_mismatch_excludes() {
        let comment = json!({
            "id": 501,
            "body": "ordinary old discussion",
            "created_at": "2020-01-01T00:00:00Z",
            "updated_at": "2020-01-01T00:00:00Z"
        });
        let repository_page = || {
            gpage(
                json!({"id":161,"full_name":"ezra/buaa-cli","archived":false,
                "permissions":{"admin":false,"push":true,"pull":true}}),
                None,
            )
        };
        let issues = || {
            vec![
                (
                    format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50&page=1"),
                    gpage(json!([gitea_issue(1)]), Some(1)),
                ),
                (
                    format!("{GITEA_BASE}/issues?state=open&type=issues&limit=50&page=2"),
                    gpage(json!([]), Some(1)),
                ),
            ]
        };
        let timeline = || {
            (
                format!("{GITEA_BASE}/issues/1/timeline?limit=50&page=1"),
                gpage(json!([]), Some(0)),
            )
        };
        // Exactly one comments request; the matching total makes it complete.
        let pages = gpages(
            [(GITEA_BASE.to_owned(), repository_page())]
                .into_iter()
                .chain(issues())
                .chain([
                    timeline(),
                    (
                        format!("{GITEA_BASE}/issues/1/comments"),
                        gpage(json!([comment.clone()]), Some(1)),
                    ),
                ])
                .collect(),
        );
        let output = gitea_scan_or_panic(scan_with_reader(&gitea_request(), &pages));
        assert_eq!(output["result"], "scan_completed");
        assert_eq!(output["candidates"][0]["number"], 1);
        assert_eq!(output["permission"]["provider"], "gitea");
        assert_eq!(output["policy"]["provider"], "gitea");
        assert!(pages.0.borrow().is_empty());

        // A count mismatch means the single endpoint was not complete: the
        // issue is excluded as claim-unknown after exactly one read.
        let pages = gpages(
            [(GITEA_BASE.to_owned(), repository_page())]
                .into_iter()
                .chain(issues())
                .chain([
                    timeline(),
                    (
                        format!("{GITEA_BASE}/issues/1/comments"),
                        gpage(json!([comment.clone()]), Some(2)),
                    ),
                ])
                .collect(),
        );
        let output = gitea_scan_or_panic(scan_with_reader(&gitea_request(), &pages));
        assert_eq!(
            output["excluded"][0]["reasons"],
            json!(["claim_status_unknown"])
        );
        assert_eq!(
            output["excluded"][0]["fallback_reason"],
            "gitea_comments_incomplete"
        );
        assert_eq!(output["candidates"], json!([]));
        assert!(pages.0.borrow().is_empty());

        // Duplicate comment identities are likewise not a complete read.
        let pages = gpages(
            [(GITEA_BASE.to_owned(), repository_page())]
                .into_iter()
                .chain(issues())
                .chain([
                    timeline(),
                    (
                        format!("{GITEA_BASE}/issues/1/comments"),
                        gpage(json!([comment.clone(), comment]), Some(2)),
                    ),
                ])
                .collect(),
        );
        let output = gitea_scan_or_panic(scan_with_reader(&gitea_request(), &pages));
        assert_eq!(
            output["excluded"][0]["reasons"],
            json!(["claim_status_unknown"])
        );
        assert!(pages.0.borrow().is_empty());
    }

    #[test]
    fn provider_credentials_and_gitea_repository_are_validated_before_network() {
        // Cross-provider credentials are ambiguous and rejected outright.
        for input in [
            r#"{"repository":"ezra/buaa-cli","provider":"gitea","online":true,"github_token":"ghp_synth01"}"#,
            r#"{"repository":"octo/repo","online":true,"gitea_token":"gt_synth01"}"#,
            r#"{"repository":"ezra/buaa-cli","provider":"gitea","online":true,"github_token":"ghp_synth01","gitea_token":"gt_synth01"}"#,
        ] {
            let error = scan(input).unwrap_err();
            assert_eq!(error.code, "invalid_input");
            assert!(!format!("{error:?}").contains("synth01"));
        }
        // Only the fixed admitted Gitea repository may be addressed.
        assert_eq!(
            scan(r#"{"repository":"other/private","provider":"gitea","online":true,"gitea_token":"gt_synth01"}"#)
                .unwrap_err()
                .code,
            "invalid_input"
        );
        assert!(
            ScanRequest::from_input(r#"{"repository":"octo/repo","provider":"gitlab"}"#).is_err()
        );
        // Offline and missing-token paths never need a transport.
        let offline =
            scan(r#"{"repository":"ezra/buaa-cli","provider":"gitea","gitea_token":"gt_synth01"}"#)
                .unwrap();
        assert_eq!(offline["reason"], "explicit_online_permission_required");
        assert_eq!(offline["provider"], "gitea");
        assert!(!offline.to_string().contains("gt_synth01"));
        let missing =
            scan(r#"{"repository":"ezra/buaa-cli","provider":"gitea","online":true}"#).unwrap();
        assert_eq!(missing["reason"], "gitea_token_required");
        let github_default = scan(r#"{"repository":"octo/repo","online":true}"#).unwrap();
        assert_eq!(github_default["reason"], "github_token_required");
        assert_eq!(github_default["provider"], "github");
        // The typed credential path decodes escapes for either provider.
        let request = ScanRequest::from_input(
            r#"{"repository":"ezra/buaa-cli","provider":"gitea","gitea_token":"gt\u005fsecret"}"#,
        )
        .unwrap();
        assert_eq!(
            request.provider_token().unwrap().unwrap().0.as_str(),
            "gt_secret"
        );
    }
}
