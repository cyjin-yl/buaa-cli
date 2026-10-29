//! Fixed community-repository material inventories and rights-reviewed raw reads.
//!
//! School numbers are admission keys, not organization-directory ordinals. The
//! GitHub tree API has no continuation cursor; truncated inventories stay
//! explicitly partial. No upstream digest, license, or successful download is
//! inferred from a listing. A retrieval attestation binds an exact tree, path
//! and blob, never a mutable branch or an independent proof of legal rights.
//! Credential-bearing API/fallback bodies and session-cookie issuance are
//! refused, not exported or cached. Cache record v2 proves cookie admission;
//! older originals remain untouched but cannot be reused or silently refetched.

use crate::governor::{self, Governor, Outcome};
use crate::git_tree::{GitTreeEntry, verify_recursive_tree};
use crate::html::{self, ChallengeAssessment};
use crate::net::{self, CacheStatus, Error, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const MAX_INPUT: usize = 16 * 1024;
const MAX_TREE_BODY: usize = 16 * 1024 * 1024;
const MAX_RAW_BODY: usize = 8 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 24 * 1024 * 1024;
const MAX_HEADERS: usize = 16 * 1024;
const MAX_PATH: usize = 4096;
const MAX_BRANCH: usize = 255;
const MAX_ENTRIES: usize = 100_000;
const CACHE_DIR: &str = ".buaa-cli-departments-cache-v2";
const HEADER_NAMES: &[&str] = &[
    "content-type",
    "content-length",
    "date",
    "etag",
    "last-modified",
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-ratelimit-resource",
    "x-ratelimit-used",
];

#[derive(Debug)]
struct Repository {
    school: u8,
    owner: &'static str,
    name: &'static str,
    full_name: &'static str,
    default_branch: Option<&'static str>,
    /// Empty means that no branch vocabulary was pinned by the source review.
    branches: &'static [&'static str],
}

static REPOSITORIES: &[Repository] = &[
    Repository {
        school: 3,
        owner: "AccSrd",
        name: "BUAA_Course_Automation",
        full_name: "AccSrd/BUAA_Course_Automation",
        default_branch: Some("main"),
        branches: &["main"],
    },
    Repository {
        school: 6,
        owner: "TheBloodthirster",
        name: "BUAA_Course_Sharing",
        full_name: "TheBloodthirster/BUAA_Course_Sharing",
        default_branch: Some("master"),
        branches: &["master"],
    },
    Repository {
        school: 8,
        owner: "HoBeedzc",
        name: "CreditCount",
        full_name: "HoBeedzc/CreditCount",
        default_branch: None,
        branches: &[],
    },
    Repository {
        school: 8,
        owner: "grandchicken",
        name: "1708SEM_ISIM",
        full_name: "grandchicken/1708SEM_ISIM",
        default_branch: None,
        branches: &[],
    },
    Repository {
        school: 21,
        owner: "Soft-Where-21",
        name: "21CoreDocs",
        full_name: "Soft-Where-21/21CoreDocs",
        default_branch: Some("main"),
        branches: &[
            "main",
            "second-autumn",
            "second-spring",
            "third-autumn",
            "third-spring",
        ],
    },
];

#[derive(Debug)]
struct SourceSelection {
    repository: &'static Repository,
    branch: String,
}

impl Repository {
    fn repository_url(&self) -> String {
        format!("https://github.com/{}", self.full_name)
    }

    fn tree_url(&self, reference: &str) -> Result<Url, Error> {
        let mut url = Url::parse("https://api.github.com/").map_err(|_| invalid_url())?;
        url.path_segments_mut()
            .map_err(|_| invalid_url())?
            .push("repos")
            .push(self.owner)
            .push(self.name)
            .push("git")
            .push("trees")
            .push(reference);
        url.query_pairs_mut().append_pair("recursive", "1");
        Ok(url)
    }

    fn blob_url(&self, sha: &str) -> Result<Url, Error> {
        if !valid_upstream_sha(sha) {
            return Err(invalid_input("blob_sha must be an exact Git object ID"));
        }
        let mut url = Url::parse("https://api.github.com/").map_err(|_| invalid_url())?;
        url.path_segments_mut()
            .map_err(|_| invalid_url())?
            .push("repos")
            .push(self.owner)
            .push(self.name)
            .push("git")
            .push("blobs")
            .push(sha);
        Ok(url)
    }
}

impl SourceSelection {
    fn school(&self) -> u8 {
        self.repository.school
    }

    fn repo(&self) -> &'static str {
        self.repository.full_name
    }

    fn repository_url(&self) -> String {
        self.repository.repository_url()
    }

    fn tree_url(&self) -> Result<Url, Error> {
        self.repository.tree_url(&self.branch)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryInput {
    school: u8,
    branch: Option<String>,
    repo: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetrievalInput {
    school: u8,
    repo: Option<String>,
    path: String,
    tree_sha: Option<String>,
    blob_sha: Option<String>,
    #[serde(default)]
    rights_reviewed: bool,
}

#[derive(Debug)]
struct RetrievalRequest {
    repository: &'static Repository,
    path: String,
    tree_sha: String,
    blob_sha: String,
}

fn invalid_input(message: &'static str) -> Error {
    Error::new("invalid_input", message)
}

fn invalid_url() -> Error {
    Error::new("invalid_url", "fixed department source URL is invalid")
}

fn cache_error() -> Error {
    Error::new("cache_error", "department response cache is unavailable")
}

fn corrupt_cache() -> Error {
    Error::new("corrupt_cache", "department response cache is invalid")
}

fn governor_error() -> Error {
    Error::new(
        "governor_denied",
        "shared request governor cannot authorize or persist this request",
    )
}

fn network_error() -> Error {
    Error::new("network_error", "department source request failed")
}

fn unreviewed_body() -> Error {
    Error::new(
        "unreviewed_body",
        "department source body cannot be safely assessed; no processing or caching was admitted",
    )
}

fn safety_latched() -> Error {
    Error::new(
        "safety_latched",
        "GitHub access was rejected or challenged; the shared governor recorded a safety latch and any cooldown, so an explicit safety resume is required",
    )
}

fn assess_response_body(response: &Response) -> ChallengeAssessment {
    // Cached headers join repeated field lines with commas; they cannot serve
    // as a single trustworthy Content-Type, including after MIME parameters.
    if response.headers.get("content-type").is_some_and(|value| value.contains(',')) {
        return ChallengeAssessment::Unreviewed;
    }
    html::assess_challenge_body(
        &response.body,
        response.headers.get("content-type").map(String::as_str),
        true,
    )
}

fn body_limit() -> Error {
    Error::new("body_limit", "department source response exceeds its byte limit")
}

fn unexpected_content() -> Error {
    Error::new(
        "unexpected_content",
        "department source returned an unexpected content type",
    )
}

fn upstream_parse() -> Error {
    Error::new(
        "upstream_parse",
        "GitHub tree response cannot be normalized safely",
    )
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_upstream_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_branch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BRANCH
        && value != "@"
        && !value.starts_with('/')
        && !value.starts_with('.')
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.contains("//")
        && !value.contains("..")
        && !value.contains("@{")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
        && value
            .split('/')
            .all(|component| !component.is_empty() && !component.ends_with(".lock"))
}

fn valid_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PATH
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn select_repository(school: u8, repo: Option<&str>) -> Result<&'static Repository, Error> {
    let mut candidates = REPOSITORIES
        .iter()
        .filter(|repository| repository.school == school);
    let first = candidates
        .next()
        .ok_or_else(|| invalid_input("school must be one of 3, 6, 8, or 21"))?;
    let repository = if let Some(requested) = repo {
        if first.full_name != requested {
            let second = candidates
                .next()
                .filter(|candidate| candidate.full_name == requested);
            second.ok_or_else(|| invalid_input("repo is not fixed to the requested school"))?
        } else {
            first
        }
    } else {
        if candidates.next().is_some() {
            return Err(invalid_input(
                "school 8 requires an explicit fixed repo selector",
            ));
        }
        first
    };
    Ok(repository)
}

fn select_source(
    school: u8,
    repo: Option<&str>,
    branch: Option<&str>,
) -> Result<SourceSelection, Error> {
    let repository = select_repository(school, repo)?;
    let branch = match branch {
        Some(value) => {
            if !valid_branch(value)
                || (!repository.branches.is_empty() && !repository.branches.contains(&value))
            {
                return Err(invalid_input(
                    "branch is invalid or not admitted for this fixed repository",
                ));
            }
            value
        }
        None => repository.default_branch.ok_or_else(|| {
            invalid_input("an explicit branch is required because no default was pinned")
        })?,
    };
    Ok(SourceSelection {
        repository,
        branch: branch.to_owned(),
    })
}

fn parse_inventory_input(input: &str) -> Result<SourceSelection, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid_input("department inventory request is too large"));
    }
    let input: InventoryInput = serde_json::from_str(input)
        .map_err(|_| invalid_input("invalid department inventory request"))?;
    select_source(
        input.school,
        input.repo.as_deref(),
        input.branch.as_deref(),
    )
}

fn parse_retrieval_input(input: &str) -> Result<RetrievalRequest, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid_input("department retrieval request is too large"));
    }
    let input: RetrievalInput = serde_json::from_str(input)
        .map_err(|_| invalid_input("invalid department retrieval request"))?;
    if !input.rights_reviewed {
        return Err(Error::new(
            "authorization_required",
            "explicit rights_reviewed:true is required before raw retrieval",
        ));
    }
    if !valid_path(&input.path) {
        return Err(invalid_input(
            "path must be one explicit normalized repository file path",
        ));
    }
    let tree_sha = input.tree_sha.filter(|value| valid_upstream_sha(value))
        .ok_or_else(|| invalid_input("tree_sha must confirm the exact inventory tree object"))?;
    let blob_sha = input.blob_sha.filter(|value| valid_upstream_sha(value))
        .ok_or_else(|| invalid_input("blob_sha must confirm the exact inventory path's blob object"))?;
    if tree_sha.len() != blob_sha.len() {
        return Err(invalid_input("tree_sha and blob_sha must use the same Git object format"));
    }
    Ok(RetrievalRequest {
        repository: select_repository(input.school, input.repo.as_deref())?,
        path: input.path,
        tree_sha,
        blob_sha,
    })
}

#[derive(Clone, Copy)]
enum Surface {
    Tree,
    Blob,
}

impl Surface {
    fn body_limit(self) -> usize {
        match self {
            Self::Tree => MAX_TREE_BODY,
            Self::Blob => MAX_RAW_BODY,
        }
    }

    fn accept(self) -> &'static str {
        match self {
            Self::Tree => "application/vnd.github+json",
            Self::Blob => "application/vnd.github.raw+json",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cached {
    version: u8,
    url: String,
    status: u16,
    headers: BTreeMap<String, String>,
    body_base64: String,
    sha256: String,
    fetched_at_unix_ms: u64,
}

struct ResponseCache {
    directory: File,
}

#[cfg(test)]
thread_local! {
    static TEST_CACHE_DIR: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
    static TEST_ROUTE: std::cell::Cell<Option<std::net::SocketAddr>> = const { std::cell::Cell::new(None) };
    static TEST_GOVERNOR: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
}

impl ResponseCache {
    fn open() -> Result<Self, Error> {
        #[cfg(test)]
        if let Some(path) = TEST_CACHE_DIR.with(|cell| cell.borrow().clone()) {
            let directory = governor::open_directory(&path, true, true).map_err(|_| cache_error())?;
            return Ok(Self { directory });
        }
        let home = governor::identity_home().map_err(|_| cache_error())?;
        let _home = governor::open_directory(&home, false, false).map_err(|_| cache_error())?;
        let directory = governor::open_directory(&home.join(CACHE_DIR), true, true)
            .map_err(|_| cache_error())?;
        Ok(Self { directory })
    }

    fn open_governor(&self) -> Result<Governor, Error> {
        #[cfg(test)]
        if let Some(path) = TEST_GOVERNOR.with(|cell| cell.borrow().clone()) {
            return Governor::isolated_for_test(&path).map_err(|_| governor_error());
        }
        Governor::open().map_err(|_| governor_error())
    }

    fn publish_cached_challenge(&self) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(path) = TEST_GOVERNOR.with(|cell| cell.borrow().clone()) {
            return governor::publish_cached_challenge_for_test(&path)
                .map_err(|_| governor_error());
        }
        governor::publish_cached_challenge().map_err(|_| governor_error())
    }

    fn http_client(&self) -> Result<Client, Error> {
        let builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .http1_only()
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            .user_agent("buaa-cli/0.1 departments");
        #[cfg(not(test))]
        let builder = builder.https_only(true);
        #[cfg(test)]
        let builder = builder.https_only(TEST_ROUTE.with(|cell| cell.get()).is_none());
        builder
            .build()
            .map_err(|_| {
                Error::new(
                    "transport_unavailable",
                    "cannot initialize department source transport",
                )
            })
    }

    fn open_transport(&self) -> Result<Transport, Error> {
        let governor = self.open_governor()?;
        let http = self.http_client()?;
        Ok(Transport {
            governor,
            http,
            #[cfg(test)]
            test_route: TEST_ROUTE.with(|cell| cell.get()),
        })
    }

    fn validate_directory(&self) -> Result<(), Error> {
        let metadata = self.directory.metadata().map_err(|_| cache_error())?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(cache_error());
        }
        Ok(())
    }

    fn name(url: &Url) -> String {
        format!("{}.json", sha256(url.as_str().as_bytes()))
    }

    fn load(&self, url: &Url) -> Result<Option<Response>, Error> {
        self.validate_directory()?;
        let file = match governor::open_child(&self.directory, &Self::name(url), libc::O_RDONLY) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(cache_error()),
        };
        governor::validate_private_file(&file).map_err(|_| corrupt_cache())?;
        let mut bytes = Vec::new();
        file.take(MAX_CACHE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| cache_error())?;
        if bytes.len() as u64 > MAX_CACHE_BYTES {
            return Err(corrupt_cache());
        }
        let cached: Cached = serde_json::from_slice(&bytes).map_err(|_| corrupt_cache())?;
        if !matches!(cached.version, 1 | 2)
            || cached.url != url.as_str()
            || cached.status != 200
            || !valid_sha256(&cached.sha256)
            || cached.body_base64.len() > MAX_TREE_BODY.div_ceil(3) * 4
            || cached.headers.iter().any(|(name, value)| {
                !HEADER_NAMES.contains(&name.as_str()) || !valid_header(value)
            })
            || cached
                .headers
                .iter()
                .map(|(name, value)| name.len() + value.len())
                .sum::<usize>()
                > MAX_HEADERS
        {
            return Err(corrupt_cache());
        }
        let body = STANDARD
            .decode(&cached.body_base64)
            .map_err(|_| corrupt_cache())?;
        if body.len() > MAX_TREE_BODY || sha256(&body) != cached.sha256 {
            return Err(corrupt_cache());
        }
        let response = Response {
            url: cached.url,
            status: cached.status,
            headers: cached.headers,
            body,
            sha256: cached.sha256,
            fetched_at_unix_ms: cached.fetched_at_unix_ms,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        };
        if cached.version == 1 {
            if assess_response_body(&response) == ChallengeAssessment::Detected {
                self.publish_cached_challenge()?;
                return Err(safety_latched());
            }
            return Err(Error::new("unreviewed_cache", "department cache predates session-cookie admission; original retained without reuse or automatic refetch"));
        }
        Ok(Some(response))
    }

    fn save(&self, response: &Response) -> Result<(), Error> {
        self.validate_directory()?;
        let url = Url::parse(&response.url).map_err(|_| invalid_url())?;
        let name = Self::name(&url);
        match governor::open_child(&self.directory, &name, libc::O_RDONLY) {
            Ok(existing) => {
                governor::validate_private_file(&existing).map_err(|_| cache_error())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(cache_error()),
        }
        #[derive(Serialize)]
        struct Stored<'a> {
            version: u8,
            url: &'a str,
            status: u16,
            headers: &'a BTreeMap<String, String>,
            body_base64: String,
            sha256: &'a str,
            fetched_at_unix_ms: u64,
        }
        let stored = Stored {
            version: 2,
            url: &response.url,
            status: response.status,
            headers: &response.headers,
            body_base64: STANDARD.encode(&response.body),
            sha256: &response.sha256,
            fetched_at_unix_ms: response.fetched_at_unix_ms,
        };
        let (temporary_name, mut temporary) =
            governor::create_temporary(&self.directory).map_err(|_| cache_error())?;
        let result = (|| {
            governor::validate_private_file(&temporary).map_err(|_| cache_error())?;
            serde_json::to_writer(&mut temporary, &stored).map_err(|_| cache_error())?;
            temporary.write_all(b"\n").map_err(|_| cache_error())?;
            temporary.sync_all().map_err(|_| cache_error())?;
            let target = CString::new(name).map_err(|_| cache_error())?;
            // SAFETY: both names are single components in this pinned directory.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    self.directory.as_raw_fd(),
                    target.as_ptr(),
                )
            } != 0
            {
                return Err(cache_error());
            }
            self.directory.sync_all().map_err(|_| cache_error())
        })();
        if result.is_err() {
            // SAFETY: this is our exclusively created temporary, not user input.
            unsafe {
                libc::unlinkat(
                    self.directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    0,
                )
            };
        }
        result
    }

    fn get<T>(
        &self,
        url: &Url,
        surface: Surface,
        online: bool,
        process: impl FnOnce(&Response) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if let Some(response) = self.load(url)? {
            return match assess_response_body(&response) {
                ChallengeAssessment::Clear => {
                    screen_api_response(surface, &response)?;
                    process(&response)
                }
                ChallengeAssessment::Unreviewed => Err(unreviewed_body()),
                ChallengeAssessment::Detected => {
                    self.publish_cached_challenge()?;
                    Err(safety_latched())
                }
            };
        }
        if !online {
            return Err(Error::new(
                "offline_miss",
                "department response is not in the local cache",
            ));
        }
        self.open_transport()?.fetch(self, url, surface, process)
    }
}

struct Transport {
    governor: Governor,
    http: Client,
    #[cfg(test)]
    test_route: Option<std::net::SocketAddr>,
}

impl Transport {
    fn request_url(&self, url: &Url) -> Url {
        #[cfg(test)]
        if let Some(address) = self.test_route {
            let mut routed = url.clone();
            routed
                .set_scheme("http")
                .expect("test loopback scheme");
            routed
                .set_host(Some(&address.ip().to_string()))
                .expect("test loopback host");
            routed.set_port(Some(address.port())).expect("test loopback port");
            return routed;
        }
        url.clone()
    }

    fn fetch<T>(
        &self,
        cache: &ResponseCache,
        url: &Url,
        surface: Surface,
        process: impl FnOnce(&Response) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut lease = net::acquire(&self.governor)?;
        // Another cooperating process may have populated the cache while this
        // request waited for admission. Reload before any network transmission.
        match cache.load(url) {
            Ok(Some(response)) => {
                let processed = match assess_response_body(&response) {
                    ChallengeAssessment::Clear => screen_api_response(surface, &response)
                        .and_then(|()| process(&response)),
                    ChallengeAssessment::Unreviewed => Err(unreviewed_body()),
                    ChallengeAssessment::Detected => {
                        lease.finish_cached_challenge().map_err(|_| governor_error())?;
                        return Err(safety_latched());
                    }
                };
                lease
                    .finish_without_request()
                    .map_err(|_| governor_error())?;
                return processed;
            }
            Ok(None) => {}
            Err(error) => {
                lease
                    .finish_without_request()
                    .map_err(|_| governor_error())?;
                return Err(error);
            }
        }
        let mut request = self
            .http
            .get(self.request_url(url))
            .timeout(Duration::from_secs(45))
            .header("Accept-Encoding", "identity")
            .header("Accept", surface.accept());
        request = request.header("X-GitHub-Api-Version", "2022-11-28");
        let mut raw = match lease.start_request(|| request.send()) {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                lease
                    .finish(Outcome::NetworkFailure)
                    .map_err(|_| governor_error())?;
                return Err(network_error());
            }
            Err(governor::FollowupError::CachedChallenge) => {
                lease.finish_with_safety_latch(Outcome::SafetyObserved)
                    .map_err(|_| governor_error())?;
                return Err(safety_latched());
            }
            // No request was started; leave the pending lease for conservative
            // recovery if the shared request-start fence cannot be established.
            Err(governor::FollowupError::Governor(_)) => return Err(governor_error()),
        };
        let status = raw.status().as_u16();
        let retry_after = raw
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let rate_remaining = raw
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut challenge = raw.headers().iter().any(|(name, value)| {
            net::challenge_header(name.as_str(), value.as_bytes())
        });
        // Persist header facts without ending this same pending lease. A body
        // failure must not erase a previously observed rejection or cooldown.
        lease.observe_http_many(status, raw.headers().get_all("retry-after").iter().map(|value| value.to_str().ok()), challenge)
            .map_err(|_| governor_error())?;
        let mut read_failure = false;
        let result = (|| {
            let limit = surface.body_limit();
            let declared_oversize = raw
                .content_length()
                .is_some_and(|length| length > limit as u64);
            let identity_encoding = raw.headers().get_all("content-encoding").iter()
                .all(|value| value.as_bytes().eq_ignore_ascii_case(b"identity"));
            let mut mime_values = raw.headers().get_all("content-type").iter();
            let observed_mime = mime_values.next().and_then(|value| value.to_str().ok()).map(str::to_owned);
            let unambiguous_mime = observed_mime.is_some() && mime_values.next().is_none();
            let headers = collect_headers(raw.headers());
            let mut body = Vec::new();
            let read = raw.by_ref()
                .take(limit as u64 + 1)
                .read_to_end(&mut body);
            read_failure = read.is_err();
            let complete = !read_failure && !declared_oversize && body.len() <= limit;
            let assessment = if identity_encoding && unambiguous_mime {
                html::assess_challenge_body(
                    &body,
                    observed_mime.as_deref(),
                    complete,
                )
            } else {
                // Missing/ambiguous MIME and unsupported encoding cannot
                // establish a clear or challenged decoded representation.
                ChallengeAssessment::Unreviewed
            };
            if assessment == ChallengeAssessment::Detected {
                challenge = true;
                lease.observe_http_many(status, raw.headers().get_all("retry-after").iter().map(|value| value.to_str().ok()), true)
                    .map_err(|_| governor_error())?;
            }
            classify_status(status, challenge, retry_after.as_deref(), rate_remaining.as_deref())?;
            if net::issues_session_cookie(raw.headers()) {
                return Err(Error::new("sensitive_response", "public department transport issued a session cookie; response withheld"));
            }
            if declared_oversize || body.len() > limit {
                return Err(body_limit());
            }
            read.map_err(|_| network_error())?;
            if !identity_encoding {
                return Err(Error::new(
                    "unsupported_encoding",
                    "department source content encoding is unsupported",
                ));
            }
            let headers = headers?;
            if assessment != ChallengeAssessment::Clear {
                return Err(unreviewed_body());
            }
            let response = Response {
                url: url.as_str().to_owned(),
                status,
                headers,
                sha256: sha256(&body),
                body,
                fetched_at_unix_ms: unix_ms()?,
                cache_status: CacheStatus::Miss,
                revalidated_at_unix_ms: None,
                revalidation_status: None,
            };
            screen_api_response(surface, &response)?;
            let processed = process(&response)?;
            cache.save(&response)?;
            Ok(processed)
        })();
        let network_failure = read_failure;
        drop(raw);
        let latched = lease
            .finish_with_safety_latch(Outcome::Http {
                status,
                retry_after: retry_after.as_deref(),
                challenge,
                network_failure,
            })
            .map_err(|_| governor_error())?;
        if latched && result.is_err() {
            return Err(safety_latched());
        }
        result
    }
}

fn classify_status(
    status: u16,
    challenge: bool,
    retry_after: Option<&str>,
    rate_remaining: Option<&str>,
) -> Result<(), Error> {
    if challenge {
        return Err(Error::new(
            "safety_latched",
            "GitHub access was challenged; explicit safety review is required",
        ));
    }
    if status == 429
        || (status == 403 && (retry_after.is_some() || rate_remaining == Some("0")))
    {
        return Err(Error::new(
            "rate_limited",
            "GitHub rate limiting or a cooldown was observed; no retry was attempted",
        ));
    }
    if matches!(status, 401 | 403) {
        return Err(Error::new(
            "safety_latched",
            "GitHub access was rejected; explicit safety review is required",
        ));
    }
    if (300..400).contains(&status) {
        return Err(Error::new(
            "redirect_refused",
            "department source redirects are not followed",
        ));
    }
    if status != 200 {
        return Err(Error::new(
            "http_rejected",
            "GitHub returned an unsupported HTTP status",
        ));
    }
    Ok(())
}

fn valid_header(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
}

fn collect_headers(headers: &reqwest::header::HeaderMap) -> Result<BTreeMap<String, String>, Error> {
    let mut collected = BTreeMap::new();
    let mut total = 0usize;
    for name in HEADER_NAMES {
        let mut values = headers.get_all(*name).iter();
        let Some(first) = values.next() else {
            continue;
        };
        let mut value = first
            .to_str()
            .map_err(|_| unexpected_content())?
            .to_owned();
        for next in values {
            value.push_str(", ");
            value.push_str(next.to_str().map_err(|_| unexpected_content())?);
        }
        if !valid_header(&value) {
            return Err(unexpected_content());
        }
        total = total
            .checked_add(name.len() + value.len())
            .ok_or_else(unexpected_content)?;
        if total > MAX_HEADERS {
            return Err(unexpected_content());
        }
        collected.insert((*name).to_owned(), value);
    }
    Ok(collected)
}

fn unix_ms() -> Result<u64, Error> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| cache_error())?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| cache_error())
}

fn content_type(response: &Response) -> Option<String> {
    response
        .headers
        .get("content-type")?
        .split(';')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

fn retrieval(response: &Response) -> Value {
    json!({
        "source_url": response.url,
        "fetched_at_unix_ms": response.fetched_at_unix_ms,
        "cache_status": response.cache_status,
        "revalidated_at_unix_ms": response.revalidated_at_unix_ms,
        "revalidation_status": response.revalidation_status,
        "response_body_sha256": response.sha256,
        "response_body_byte_length": response.body.len(),
        "http": {"status": response.status, "headers": response.headers}
    })
}

#[derive(Deserialize)]
struct TreeEnvelope {
    sha: String,
    tree: Vec<TreeEntry>,
    truncated: bool,
}

#[derive(Deserialize)]
struct TreeEntry {
    path: String,
    mode: String,
    #[serde(rename = "type")]
    object_type: String,
    sha: String,
    size: Option<u64>,
}

fn entry_kind(entry: &TreeEntry) -> Result<&'static str, Error> {
    if !valid_path(&entry.path) || !valid_upstream_sha(&entry.sha) {
        return Err(upstream_parse());
    }
    let kind = match (entry.mode.as_str(), entry.object_type.as_str()) {
        ("100644" | "100755", "blob") => "file",
        ("040000", "tree") => "directory",
        ("120000", "blob") => "symlink",
        ("160000", "commit") => "submodule",
        _ => return Err(upstream_parse()),
    };
    if matches!(kind, "file" | "symlink") != entry.size.is_some() {
        return Err(upstream_parse());
    }
    Ok(kind)
}

fn parse_tree_response(response: &Response) -> Result<TreeEnvelope, Error> {
    if response.status != 200 || response.body.len() > MAX_TREE_BODY {
        return Err(upstream_parse());
    }
    if !matches!(content_type(response).as_deref(), Some("application/json" | "application/vnd.github+json")) {
        return Err(unexpected_content());
    }
    let envelope: TreeEnvelope = serde_json::from_slice(&response.body).map_err(|_| upstream_parse())?;
    if !valid_upstream_sha(&envelope.sha) || envelope.tree.len() > MAX_ENTRIES {
        return Err(upstream_parse());
    }
    let mut paths = BTreeSet::new();
    for entry in &envelope.tree {
        entry_kind(entry)?;
        if entry.sha.len() != envelope.sha.len() || !paths.insert(entry.path.as_str()) {
            return Err(upstream_parse());
        }
    }
    if !envelope.truncated {
        verify_recursive_tree(&envelope.sha, envelope.tree.iter().map(|entry| GitTreeEntry {
            path: &entry.path,
            mode: &entry.mode,
            object_type: &entry.object_type,
            sha: &entry.sha,
        })).map_err(|_| upstream_parse())?;
    }
    Ok(envelope)
}

fn normalize_entry(selection: &SourceSelection, entry: TreeEntry) -> Result<Value, Error> {
    let kind = entry_kind(&entry)?;
    Ok(json!({
        "path": entry.path,
        "size": entry.size,
        "kind": kind,
        "branch": selection.branch,
        "repo": selection.repo(),
        "rights_review_required": true,
        "blob_sha": if kind == "file" { Some(entry.sha.as_str()) } else { None },
        "upstream_sha": entry.sha
    }))
}

fn screen_private_response(response: &Response) -> Result<(), Error> {
    if crate::welearn::learning::private_evidence(&response.body, content_type(response).as_deref()) {
        return Err(Error::new("sensitive_response", "department source contains credential-shaped evidence; raw response withheld"));
    }
    Ok(())
}

fn screen_api_response(surface: Surface, response: &Response) -> Result<(), Error> {
    match surface {
        Surface::Tree => screen_private_response(response),
        // Verified raw learning files are not API envelopes. Only their
        // rejected fallback is screened, before any output or cache write.
        Surface::Blob => Ok(()),
    }
}

fn inventory_output(
    selection: &SourceSelection,
    expected_url: &Url,
    response: &Response,
) -> Result<Value, Error> {
    screen_private_response(response)?;
    if response.url != expected_url.as_str() || response.status != 200 {
        return Err(Error::new(
            "http_rejected",
            "department inventory provenance does not match the requested tree",
        ));
    }
    if response.body.len() > MAX_TREE_BODY {
        return Err(body_limit());
    }
    let parsed: Result<_, Error> = (|| {
        let envelope = parse_tree_response(response)?;
        let mut entries = Vec::with_capacity(envelope.tree.len());
        for entry in envelope.tree {
            entries.push(normalize_entry(selection, entry)?);
        }
        Ok((envelope.sha, envelope.truncated, entries))
    })();
    let common = json!({
        "schema_version": 1,
        "type": "department_material_inventory",
        "school": selection.school(),
        "repo": selection.repo(),
        "repository_url": selection.repository_url(),
        "branch": selection.branch,
        "community_source": true,
        "next_cursor": null,
        "retrieval": retrieval(response)
    });
    match parsed {
        Ok((tree_sha, truncated, entries)) => {
            let mut output = common;
            output["result"] = json!(if truncated {
                "inventory_partial"
            } else {
                "inventory_snapshot"
            });
            // A truncated response supplies observations, not authenticated
            // membership in the advertised root or proof of absent aliases.
            output["tree_sha"] = if truncated { Value::Null } else { json!(tree_sha) };
            output["truncated"] = json!(truncated);
            output["complete"] = json!(!truncated);
            output["entries"] = json!(entries);
            output["fallback_reason"] = Value::Null;
            output["raw_response_base64"] = if truncated {
                json!(STANDARD.encode(&response.body))
            } else { Value::Null };
            Ok(output)
        }
        Err(error) => {
            let mut output = common;
            output["result"] = json!("degraded");
            output["tree_sha"] = Value::Null;
            output["truncated"] = Value::Null;
            output["complete"] = json!(false);
            output["entries"] = json!([]);
            output["fallback_reason"] = json!(error.code);
            output["raw_response_base64"] = json!(STANDARD.encode(&response.body));
            Ok(output)
        }
    }
}

fn raw_content_type_allowed(value: &str) -> bool {
    matches!(
        value,
        "application/octet-stream"
            | "application/vnd.github.raw+json"
            | "application/json"
            | "application/pdf"
            | "application/zip"
            | "application/gzip"
            | "application/x-tar"
            | "application/msword"
            | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            | "application/vnd.ms-powerpoint"
            | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            | "application/vnd.ms-excel"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            | "text/plain"
            | "text/markdown"
            | "text/csv"
            | "image/png"
            | "image/jpeg"
            | "image/gif"
            | "image/webp"
    )
}

fn git_blob_sha(bytes: &[u8], object_id_length: usize) -> String {
    let header = format!("blob {}\0", bytes.len());
    if object_id_length == 40 {
        let mut digest = sha1::Sha1::new();
        digest.update(header.as_bytes());
        digest.update(bytes);
        format!("{:x}", digest.finalize())
    } else {
        let mut digest = Sha256::new();
        digest.update(header.as_bytes());
        digest.update(bytes);
        format!("{:x}", digest.finalize())
    }
}

fn immutable_tree_binding(
    request: &RetrievalRequest,
    expected_url: &Url,
    response: &Response,
) -> Result<usize, &'static str> {
    if response.url != expected_url.as_str() {
        return Err("tree_provenance_mismatch");
    }
    let tree = parse_tree_response(response).map_err(|error| error.code)?;
    if tree.sha != request.tree_sha {
        return Err("tree_identity_mismatch");
    }
    if tree.truncated {
        return Err("tree_incomplete");
    }
    let entry = tree.tree.iter().find(|entry| entry.path == request.path)
        .ok_or("tree_path_missing")?;
    if entry_kind(entry).map_err(|error| error.code)? != "file" {
        return Err("tree_path_not_file");
    }
    if entry.sha != request.blob_sha {
        return Err("tree_blob_mismatch");
    }
    let size = entry.size.and_then(|size| usize::try_from(size).ok())
        .filter(|size| *size <= MAX_RAW_BODY)
        .ok_or("tree_blob_size_limit")?;
    Ok(size)
}

fn retrieval_base(request: &RetrievalRequest, response: &Response, tree_binding: Value) -> Value {
    json!({
        "schema_version": 2,
        "type": "department_material_raw",
        "result": "degraded_raw",
        "school": request.repository.school,
        "repo": request.repository.full_name,
        "repository_url": request.repository.repository_url(),
        "path": request.path,
        "operator_attestation": {
            "rights_reviewed": true,
            "school": request.repository.school,
            "repo": request.repository.full_name,
            "tree_sha": request.tree_sha,
            "path": request.path,
            "blob_sha": request.blob_sha,
            "independent_rights_proof": false
        },
        "material_admitted": false,
        "material_identity": null,
        "bytes": null,
        "byte_encoding": "base64",
        "byte_length": null,
        "sha256": null,
        "content_type": content_type(response),
        "fallback_reason": null,
        "tree_binding": tree_binding,
        "raw_evidence": null,
        "retrieval": retrieval(response)
    })
}

fn degraded_retrieval(
    request: &RetrievalRequest,
    response: &Response,
    reason: &'static str,
    tree_binding: Value,
) -> Result<Value, Error> {
    screen_private_response(response)?;
    let mut output = retrieval_base(request, response, tree_binding);
    output["fallback_reason"] = json!(reason);
    // These are rejected HTTP-source bytes, not admitted or rights-proven
    // material. Preserve the original representation separately from bytes.
    output["raw_evidence"] = json!({
        "raw_response_base64": STANDARD.encode(&response.body),
        "content_type": content_type(response),
        "byte_length": response.body.len(),
        "sha256": response.sha256
    });
    Ok(output)
}

fn retrieval_output(
    request: &RetrievalRequest,
    expected_url: &Url,
    response: &Response,
    expected_size: usize,
    tree_binding: Value,
) -> Result<Value, Error> {
    if response.url != expected_url.as_str() || response.status != 200 {
        return Err(Error::new(
            "http_rejected",
            "raw material provenance does not match the requested path",
        ));
    }
    if response.body.len() > MAX_RAW_BODY {
        return Err(body_limit());
    }
    let actual_blob = git_blob_sha(&response.body, request.blob_sha.len());
    let reason = if actual_blob != request.blob_sha {
        Some("blob_identity_mismatch")
    } else if response.body.len() != expected_size {
        Some("blob_size_mismatch")
    } else {
        match content_type(response).as_deref() {
            None => Some("missing_content_type"),
            Some(value) if !raw_content_type_allowed(value) => Some("unexpected_content"),
            Some(_) => None,
        }
    };
    if let Some(reason) = reason {
        return degraded_retrieval(request, response, reason, tree_binding);
    }
    let mut output = retrieval_base(request, response, tree_binding);
    output["result"] = json!("raw_snapshot");
    output["material_admitted"] = json!(true);
    output["bytes"] = json!(STANDARD.encode(&response.body));
    output["byte_length"] = json!(response.body.len());
    output["sha256"] = json!(response.sha256);
    output["material_identity"] = json!({
        "tree_sha": request.tree_sha,
        "path": request.path,
        "blob_sha": actual_blob,
        "git_object_format": if request.blob_sha.len() == 40 { "sha1" } else { "sha256" },
        "verified": true,
        "byte_length": response.body.len(),
        "sha256": response.sha256
    });
    // The requested GitHub raw media representation is the material itself,
    // not a JSON envelope. Its original bytes live in bytes, with independent
    // HTTP-body metadata in retrieval and Git-object metadata above.
    output["retrieval"]["response_representation"] = json!("github_git_blob_raw");
    output["retrieval"]["response_body_base64_field"] = json!("bytes");
    Ok(output)
}

/// Return one recursive GitHub tree snapshot. Offline is the default; `online`
/// only permits a governed fetch on a cache miss and never triggers a retry.
pub fn inventory(input: &str, online: bool) -> Result<Value, Error> {
    let selection = parse_inventory_input(input)?;
    let url = selection.tree_url()?;
    let cache = ResponseCache::open()?;
    cache.get(&url, Surface::Tree, online, |response| {
        inventory_output(&selection, &url, response)
    })
}

/// Bind the operator attestation to a complete immutable tree and file blob.
/// A branch cannot redirect this read. Raw GitHub blob bytes are admitted only
/// after their Git object hash and the tree-declared length both match.
pub fn retrieve(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_retrieval_input(input)?;
    let tree_url = request.repository.tree_url(&request.tree_sha)?;
    let cache = ResponseCache::open()?;
    let admission = cache.get(&tree_url, Surface::Tree, online, |response| {
        // Cache only an HTTP-source original, never a successful membership
        // decision: every replay rechecks the complete canonical tree. Rejected
        // originals remain raw evidence and cannot authorize a blob request.
        Ok(match immutable_tree_binding(&request, &tree_url, response) {
            Ok(size) => Ok((size, json!({
                "tree_sha": request.tree_sha,
                "path": request.path,
                "blob_sha": request.blob_sha,
                "byte_length": size,
                "raw_response_base64": STANDARD.encode(&response.body),
                "retrieval": retrieval(response)
            }))),
            Err(reason) => Err(degraded_retrieval(&request, response, reason, Value::Null)?),
        })
    })?;
    match admission {
        Err(rejected) => Ok(rejected),
        Ok((size, binding)) => {
            let url = request.repository.blob_url(&request.blob_sha)?;
            cache.get(&url, Surface::Blob, online, |response| {
                retrieval_output(&request, &url, response, size, binding)
            })
        }
    }
}

fn retrieval_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["source_url","fetched_at_unix_ms","cache_status","revalidated_at_unix_ms","revalidation_status","response_body_sha256","response_body_byte_length","http"],
        "properties":{
            "source_url":{"type":"string"},
            "fetched_at_unix_ms":{"type":"integer","minimum":0},
            "cache_status":{"enum":["hit","miss"]},
            "revalidated_at_unix_ms":{"type":"null"},
            "revalidation_status":{"type":"null"},
            "response_body_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "response_body_byte_length":{"type":"integer","minimum":0,"maximum":MAX_TREE_BODY},
            "http":{"type":"object","additionalProperties":false,
                "required":["status","headers"],
                "properties":{"status":{"const":200},"headers":{"type":"object"}}
            },
            "response_representation":{"const":"github_git_blob_raw"},
            "response_body_base64_field":{"const":"bytes"}
        }
    })
}

/// Machine-readable stdin/output contracts for CLI integration.
pub fn schema() -> Value {
    let source_input = json!({
        "school":{"type":"integer","enum":[3,6,8,21],"description":"Fixed school key; never an organizations source_order."},
        "branch":{"type":"string","minLength":1,"maxLength":MAX_BRANCH,"description":"Optional for pinned defaults. School 8 requires an explicit branch because no default was source-reviewed. School 21 admits main/second-autumn/second-spring/third-autumn/third-spring."},
        "repo":{"type":"string","enum":["AccSrd/BUAA_Course_Automation","TheBloodthirster/BUAA_Course_Sharing","HoBeedzc/CreditCount","grandchicken/1708SEM_ISIM","Soft-Where-21/21CoreDocs"],"description":"Optional only when the school has exactly one fixed repository; required for school 8."}
    });
    let entry = json!({
        "type":"object","additionalProperties":false,
        "required":["path","size","kind","branch","repo","rights_review_required","blob_sha","upstream_sha"],
        "properties":{
            "path":{"type":"string","minLength":1,"maxLength":MAX_PATH},
            "size":{"type":["integer","null"],"minimum":0},
            "kind":{"enum":["file","directory","symlink","submodule"]},
            "branch":{"type":"string"},"repo":{"type":"string"},
            "rights_review_required":{"const":true},
            "blob_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"Exact retrievable file object; null for directories, symlinks and submodules."},
            "upstream_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"}
        }
    });
    let object_id = json!({"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"});
    let tree_binding = json!({
        "type":["object","null"],"additionalProperties":false,
        "required":["tree_sha","path","blob_sha","byte_length","raw_response_base64","retrieval"],
        "properties":{
            "tree_sha":object_id.clone(),"path":{"type":"string"},"blob_sha":object_id.clone(),
            "byte_length":{"type":"integer","minimum":0,"maximum":MAX_RAW_BODY},
            "raw_response_base64":{"type":"string","contentEncoding":"base64"},
            "retrieval":retrieval_schema()
        }
    });
    let raw_evidence = json!({
        "type":["object","null"],"additionalProperties":false,
        "required":["raw_response_base64","content_type","byte_length","sha256"],
        "properties":{
            "raw_response_base64":{"type":"string","contentEncoding":"base64"},
            "content_type":{"type":["string","null"]},
            "byte_length":{"type":"integer","minimum":0,"maximum":MAX_TREE_BODY},
            "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}
        }
    });
    let material_identity = json!({
        "type":["object","null"],"additionalProperties":false,
        "required":["tree_sha","path","blob_sha","git_object_format","verified","byte_length","sha256"],
        "properties":{
            "tree_sha":object_id.clone(),"path":{"type":"string"},"blob_sha":object_id,
            "git_object_format":{"enum":["sha1","sha256"]},"verified":{"const":true},
            "byte_length":{"type":"integer","minimum":0,"maximum":MAX_RAW_BODY},
            "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}
        }
    });
    json!({
        "inventory":{
            "input":{
                "type":"object","additionalProperties":false,"required":["school"],
                "properties":source_input.clone()
            },
            "options":{"--online":"Permit one governed GitHub tree request on a cache miss; no automatic retry. Credential-bearing API/fallback bodies and Set-Cookie responses are withheld without new cache entries. Pre-cookie-admission cache records are retained but refused, not automatically refetched."},
            "output":{
                "type":"object","additionalProperties":false,
                "required":["schema_version","type","result","school","repo","repository_url","branch","community_source","tree_sha","truncated","complete","next_cursor","entries","fallback_reason","raw_response_base64","retrieval"],
                "properties":{
                    "schema_version":{"const":1},"type":{"const":"department_material_inventory"},
                    "result":{"enum":["inventory_snapshot","inventory_partial","degraded"]},
                    "school":{"enum":[3,6,8,21]},"repo":{"type":"string"},"repository_url":{"type":"string"},"branch":{"type":"string"},
                    "community_source":{"const":true},
                    "tree_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
                    "truncated":{"type":["boolean","null"]},"complete":{"type":"boolean"},
                    "next_cursor":{"type":"null","description":"GitHub's recursive tree response supplies no continuation cursor; truncation is never hidden behind a fabricated cursor."},
                    "entries":{"type":"array","maxItems":MAX_ENTRIES,"items":entry},
                    "fallback_reason":{"type":["string","null"],"enum":["unexpected_content","upstream_parse",null]},
                    "raw_response_base64":{"type":["string","null"],"description":"Original response bytes when normalization degrades or a truncated inventory cannot authenticate membership."},
                    "retrieval":retrieval_schema()
                }
            }
        },
        "retrieve":{
            "input":{
                "type":"object","additionalProperties":false,"required":["school","path","tree_sha","blob_sha","rights_reviewed"],
                "properties":{
                    "school":source_input["school"].clone(),
                    "repo":source_input["repo"].clone(),
                    "path":{"type":"string","minLength":1,"maxLength":MAX_PATH,"description":"Explicit normalized repository-relative path; absolute paths, empty segments, dot segments, controls and backslashes are rejected."},
                    "tree_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"Exact complete inventory tree object, not a branch."},
                    "blob_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"Exact file blob at path in the confirmed tree; the tree and blob must use the same object-ID length."},
                    "rights_reviewed":{"const":true,"description":"Operator attestation that this exact tree/path/blob was rights-reviewed. It is not an independent legal rights proof. False or omitted fails before cache or network access."}
                }
            },
            "options":{"--online":"Permit up to two paced governed GitHub tree/blob requests on cache misses, one pending at a time; no automatic retry or redirect. A rejected tree stops before the blob request."},
            "output":{
                "type":"object","additionalProperties":false,
                "required":["schema_version","type","result","school","repo","repository_url","path","operator_attestation","material_admitted","material_identity","bytes","byte_encoding","byte_length","sha256","content_type","fallback_reason","tree_binding","raw_evidence","retrieval"],
                "properties":{
                    "schema_version":{"const":2},"type":{"const":"department_material_raw"},
                    "result":{"enum":["raw_snapshot","degraded_raw"]},
                    "school":{"enum":[3,6,8,21]},"repo":{"type":"string"},"repository_url":{"type":"string"},"path":{"type":"string"},
                    "operator_attestation":{"type":"object","additionalProperties":false,
                        "required":["rights_reviewed","school","repo","tree_sha","path","blob_sha","independent_rights_proof"],
                        "properties":{
                            "rights_reviewed":{"const":true},"school":{"enum":[3,6,8,21]},
                            "repo":{"type":"string"},"tree_sha":{"type":"string"},"path":{"type":"string"},"blob_sha":{"type":"string"},
                            "independent_rights_proof":{"const":false}
                        }
                    },
                    "material_admitted":{"type":"boolean"},
                    "material_identity":material_identity,
                    "bytes":{"type":["string","null"],"contentEncoding":"base64"},"byte_encoding":{"const":"base64"},
                    "byte_length":{"type":["integer","null"],"minimum":0,"maximum":MAX_RAW_BODY},
                    "sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$","description":"Local SHA-256 of returned bytes, distinct from the Git object ID."},
                    "content_type":{"type":["string","null"],"description":"Actual response MIME; null when the header is absent."},
                    "fallback_reason":{"type":["string","null"],"enum":["tree_provenance_mismatch","unexpected_content","upstream_parse","tree_identity_mismatch","tree_incomplete","tree_path_missing","tree_path_not_file","tree_blob_mismatch","tree_blob_size_limit","blob_identity_mismatch","blob_size_mismatch","missing_content_type",null]},
                    "tree_binding":tree_binding,
                    "raw_evidence":raw_evidence,
                    "retrieval":retrieval_schema()
                },
                "allOf":[
                    {"if":{"properties":{"result":{"const":"raw_snapshot"}}},
                     "then":{"properties":{"material_admitted":{"const":true},"bytes":{"type":"string"},"byte_length":{"type":"integer"},"sha256":{"type":"string"}}},
                     "else":{"properties":{"material_admitted":{"const":false},"bytes":{"type":"null"},"material_identity":{"type":"null"},"byte_length":{"type":"null"},"sha256":{"type":"null"}}}}
                ]
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    fn selection(school: u8, repo: Option<&str>, branch: Option<&str>) -> SourceSelection {
        select_source(school, repo, branch).unwrap()
    }

    fn response(url: &Url, body: &[u8], content_type: &str) -> Response {
        Response {
            url: url.as_str().to_owned(),
            status: 200,
            headers: BTreeMap::from([(
                "content-type".to_owned(),
                content_type.to_owned(),
            )]),
            body: body.to_vec(),
            sha256: sha256(body),
            fetched_at_unix_ms: 1_700_000_000_000,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    // Independent canonical Git object vectors, including the intermediate
    // directory object required by the recursive tree representation.
    const TREE_SHA: &str = "6aae43dbff092dd6c3e333827194a2ca05feb0c3";
    const DOCS_SHA: &str = "9aa4816ed4d7cce80d7fa619412de2aebededcee";
    const BINARY_TREE_SHA256: &str = "04c8a6f66471686b88d015154eb5a8ee15dcdf1fb48b6aed4bfb2a6aeafa78b2";
    const BINARY_DOCS_SHA256: &str = "7ef6b7e527a3ea5224a145c6542909ea18d52bf1ceb1bd300d68881e9f7ba875";
    const HELLO_BLOB: &str = "95d09f2b10159347eece71399a7e2e907ea3df4f";
    const MATERIAL: &[u8] = b"hello world";

    fn retrieval_input(tree_sha: &str, blob_sha: &str) -> String {
        retrieval_input_with_rights(tree_sha, blob_sha, true)
    }

    fn retrieval_input_with_rights(tree_sha: &str, blob_sha: &str, reviewed: bool) -> String {
        json!({
            "school": 3,
            "path": "docs/readme.md",
            "tree_sha": tree_sha,
            "blob_sha": blob_sha,
            "rights_reviewed": reviewed
        })
        .to_string()
    }

    fn request(tree_sha: &str, blob_sha: &str) -> RetrievalRequest {
        parse_retrieval_input(&retrieval_input(tree_sha, blob_sha)).unwrap()
    }

    fn tree_body(tree_sha: &str, blob_sha: &str, truncated: bool) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "sha": tree_sha,
            "tree": [{
                "path": "docs/readme.md",
                "mode": "100644",
                "type": "blob",
                "sha": blob_sha,
                "size": MATERIAL.len()
            }, {
                "path": "docs",
                "mode": "040000",
                "type": "tree",
                "sha": if tree_sha.len() == 64 { BINARY_DOCS_SHA256 } else { DOCS_SHA }
            }],
            "truncated": truncated
        }))
        .unwrap()
    }

    fn tree_response(request: &RetrievalRequest, truncated: bool) -> Response {
        let url = request.repository.tree_url(&request.tree_sha).unwrap();
        response(
            &url,
            &tree_body(&request.tree_sha, &request.blob_sha, truncated),
            "application/json",
        )
    }

    fn admitted_output(request: &RetrievalRequest, body: &[u8], content_type: &str) -> Value {
        let tree = tree_response(request, false);
        let tree_url = request.repository.tree_url(&request.tree_sha).unwrap();
        let size = immutable_tree_binding(request, &tree_url, &tree).unwrap();
        let binding = json!({
            "tree_sha": request.tree_sha,
            "path": request.path,
            "blob_sha": request.blob_sha,
            "byte_length": size,
            "raw_response_base64": STANDARD.encode(&tree.body),
            "retrieval": retrieval(&tree)
        });
        let url = request.repository.blob_url(&request.blob_sha).unwrap();
        retrieval_output(request, &url, &response(&url, body, content_type), size, binding)
            .unwrap()
    }

    fn schema_type(value: &Value, expected: &str) -> bool {
        match expected {
            "null" => value.is_null(),
            "boolean" => value.is_boolean(),
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            other => panic!("unsupported schema type {other}"),
        }
    }

    fn validate_schema(value: &Value, schema: &Value, path: &str) -> Result<(), String> {
        let fail = |message: &str| Err(format!("{path}: {message} for {value}"));
        if let Some(expected) = schema.get("const") {
            if value != expected {
                return fail("const mismatch");
            }
        }
        if let Some(expected) = schema.get("enum").and_then(Value::as_array) {
            if !expected.contains(value) {
                return fail("enum mismatch");
            }
        }
        if let Some(expected) = schema.get("type") {
            let matches = match expected {
                Value::String(kind) => schema_type(value, kind),
                Value::Array(kinds) => kinds
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|kind| schema_type(value, kind)),
                _ => false,
            };
            if !matches {
                return fail("type mismatch");
            }
        }
        if let Some(object) = value.as_object() {
            if let Some(required) = schema.get("required").and_then(Value::as_array) {
                for key in required.iter().filter_map(Value::as_str) {
                    if !object.contains_key(key) {
                        return fail(&format!("missing required {key}"));
                    }
                }
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                for key in value.as_object().into_iter().flat_map(|map| map.keys()) {
                    if !properties.contains_key(key) {
                        return fail(&format!("additional property {key}"));
                    }
                }
            }
            for (key, subschema) in properties {
                if let Some(child) = value.get(key) {
                    validate_schema(child, subschema, &format!("{path}.{key}"))?;
                }
            }
        }
        if let Some(items) = schema.get("items") {
            for (index, child) in value.as_array().into_iter().flatten().enumerate() {
                validate_schema(child, items, &format!("{path}[{index}]"))?;
            }
        }
        if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64) {
            if value.as_array().map_or(0, Vec::len) as u64 > maximum {
                return fail("too many items");
            }
        }
        if let Some(minimum) = schema.get("minimum").and_then(Value::as_u64) {
            if value.as_u64().is_some_and(|number| number < minimum) {
                return fail("below minimum");
            }
        }
        if let Some(maximum) = schema.get("maximum").and_then(Value::as_u64) {
            if value.as_u64().is_some_and(|number| number > maximum) {
                return fail("above maximum");
            }
        }
        if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64) {
            if value
                .as_str()
                .is_some_and(|text| (text.chars().count() as u64) < minimum)
            {
                return fail("too short");
            }
        }
        if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64) {
            if value
                .as_str()
                .is_some_and(|text| (text.chars().count() as u64) > maximum)
            {
                return fail("too long");
            }
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            if let Some(text) = value.as_str() {
                let matches = match pattern {
                    "^[0-9a-f]{64}$" => valid_sha256(text),
                    "^([0-9a-f]{40}|[0-9a-f]{64})$" => valid_upstream_sha(text),
                    other => panic!("unsupported schema pattern {other}"),
                };
                if !matches {
                    return fail("pattern mismatch");
                }
            }
        }
        if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
            for subschema in all {
                validate_schema(value, subschema, path)?;
            }
        }
        if let Some(condition) = schema.get("if") {
            if validate_schema(value, condition, path).is_ok() {
                if let Some(then) = schema.get("then") {
                    validate_schema(value, then, path)?;
                }
            } else if let Some(otherwise) = schema.get("else") {
                validate_schema(value, otherwise, path)?;
            }
        }
        Ok(())
    }

    fn assert_schema(value: &Value, contract: &Value) {
        validate_schema(value, contract, "$").unwrap();
    }

    #[test]
    fn fixed_school_mapping_does_not_infer_school8_defaults() {
        assert_eq!(selection(3, None, None).repo(), "AccSrd/BUAA_Course_Automation");
        assert_eq!(selection(3, None, None).branch, "main");
        assert_eq!(selection(6, None, None).branch, "master");
        assert_eq!(selection(21, None, None).branch, "main");
        assert_eq!(
            selection(21, None, Some("third-spring")).branch,
            "third-spring"
        );
        assert_eq!(
            selection(8, Some("grandchicken/1708SEM_ISIM"), Some("master")).repo(),
            "grandchicken/1708SEM_ISIM"
        );
        assert_eq!(
            select_source(8, None, Some("main"))
                .err()
                .unwrap()
                .code,
            "invalid_input"
        );
        assert_eq!(
            select_source(8, Some("HoBeedzc/CreditCount"), None)
                .err()
                .unwrap()
                .code,
            "invalid_input"
        );
        assert!(select_source(21, None, Some("master")).is_err());
        assert!(select_source(4, None, None).is_err());
    }

    #[test]
    fn inventory_normalizes_entries_and_marks_truncation_without_a_cursor() {
        let selected = selection(3, None, None);
        let url = selected.tree_url().unwrap();
        let body = br#"{
            "sha":"0123456789abcdef0123456789abcdef01234567",
            "url":"https://api.github.com/ignored",
            "truncated":true,
            "tree":[
                {"path":"docs/readme.md","mode":"100644","type":"blob","sha":"1123456789abcdef0123456789abcdef01234567","size":12,"url":"https://api.github.com/ignored"},
                {"path":"docs","mode":"040000","type":"tree","sha":"2123456789abcdef0123456789abcdef01234567","url":"https://api.github.com/ignored"},
                {"path":"latest","mode":"120000","type":"blob","sha":"3123456789abcdef0123456789abcdef01234567","size":4},
                {"path":"vendor","mode":"160000","type":"commit","sha":"4123456789abcdef0123456789abcdef01234567"}
            ]
        }"#;
        let output = inventory_output(&selected, &url, &response(&url, body, "application/json; charset=utf-8")).unwrap();
        assert_eq!(output["result"], "inventory_partial");
        assert_eq!(output["tree_sha"], Value::Null);
        assert_eq!(output["raw_response_base64"], STANDARD.encode(body));
        assert_eq!(output["complete"], false);
        assert_eq!(output["next_cursor"], Value::Null);
        assert_eq!(output["entries"][0]["path"], "docs/readme.md");
        assert_eq!(output["entries"][0]["size"], 12);
        assert_eq!(output["entries"][0]["kind"], "file");
        assert_eq!(output["entries"][0]["branch"], "main");
        assert_eq!(output["entries"][0]["repo"], selected.repo());
        assert_eq!(output["entries"][0]["rights_review_required"], true);
        assert_eq!(output["entries"][1]["size"], Value::Null);
        assert_eq!(output["entries"][2]["kind"], "symlink");
        assert_eq!(output["entries"][3]["kind"], "submodule");
        assert_eq!(output["fallback_reason"], Value::Null);
        assert_eq!(
            output["retrieval"]["response_body_sha256"],
            sha256(body)
        );
    }

    #[test]
    fn malformed_inventory_degrades_with_original_bytes_and_reason() {
        let selected = selection(6, None, None);
        let url = selected.tree_url().unwrap();
        let body = br#"{"sha":"not-a-digest","tree":[],"truncated":false}"#;
        let original = response(&url, body, "application/json");
        let output = inventory_output(&selected, &url, &original).unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["complete"], false);
        assert_eq!(output["tree_sha"], Value::Null);
        assert_eq!(output["fallback_reason"], "upstream_parse");
        assert_eq!(output["raw_response_base64"], STANDARD.encode(body));
        assert_eq!(
            output["retrieval"]["response_body_byte_length"],
            body.len()
        );

        let wrong_type = response(&url, b"<html>not a tree</html>", "text/html");
        let degraded = inventory_output(&selected, &url, &wrong_type).unwrap();
        assert_eq!(degraded["fallback_reason"], "unexpected_content");
    }

    #[test]
    fn duplicate_inventory_paths_cannot_be_silently_overwritten() {
        let selected = selection(3, None, None);
        let url = selected.tree_url().unwrap();
        let body = br#"{"sha":"0123456789abcdef0123456789abcdef01234567","truncated":false,"tree":[
            {"path":"same","mode":"100644","type":"blob","sha":"1123456789abcdef0123456789abcdef01234567","size":1},
            {"path":"same","mode":"100644","type":"blob","sha":"2123456789abcdef0123456789abcdef01234567","size":2}
        ]}"#;
        let output = inventory_output(&selected, &url, &response(&url, body, "application/json")).unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["fallback_reason"], "upstream_parse");
    }

    #[test]
    fn rights_gate_precedes_any_cache_or_network_admission() {
        let denied = parse_retrieval_input(
            r#"{"school":3,"path":"docs/readme.md","rights_reviewed":false}"#,
        )
        .err()
        .unwrap();
        assert_eq!(denied.code, "authorization_required");
        let missing = parse_retrieval_input(r#"{"school":3,"path":"docs/readme.md"}"#)
            .err()
            .unwrap();
        assert_eq!(missing.code, "authorization_required");
        for path in ["", "/absolute", "../secret", "a/./b", "a//b", "a\\b"] {
            let input = json!({"school":3,"path":path,"tree_sha":TREE_SHA,"blob_sha":HELLO_BLOB,"rights_reviewed":true}).to_string();
            assert_eq!(
                parse_retrieval_input(&input).err().unwrap().code,
                "invalid_input",
                "path {path:?}"
            );
        }
        let accepted = request(TREE_SHA, HELLO_BLOB);
        assert_eq!(accepted.path, "docs/readme.md");
        for input in [
            json!({"school":3,"path":"docs/readme.md","rights_reviewed":true}),
            json!({"school":3,"path":"docs/readme.md","tree_sha":TREE_SHA,"rights_reviewed":true}),
            json!({"school":3,"path":"docs/readme.md","tree_sha":TREE_SHA,"blob_sha":"bad","rights_reviewed":true}),
            json!({"school":3,"path":"docs/readme.md","tree_sha":TREE_SHA,"blob_sha":HELLO_BLOB,"branch":"main","rights_reviewed":true}),
            json!({"school":3,"path":"docs/readme.md","tree_sha":TREE_SHA,"blob_sha":"473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813","rights_reviewed":true}),
        ] {
            assert_eq!(
                parse_retrieval_input(&input.to_string()).err().unwrap().code,
                "invalid_input",
                "input {input}"
            );
        }
    }

    #[test]
    fn git_blob_object_hashes_cover_sha1_sha256_and_known_vectors() {
        assert_eq!(
            git_blob_sha(b"", 40),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
        assert_eq!(git_blob_sha(MATERIAL, 40), HELLO_BLOB);
        assert_eq!(
            git_blob_sha(b"", 64),
            "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"
        );
    }

    #[test]
    fn complete_inventory_rejects_unbound_root_subtree_mode_and_path() {
        let selected = selection(3, None, None);
        let url = selected.tree_url().unwrap();
        let original: Value = serde_json::from_slice(&tree_body(TREE_SHA, HELLO_BLOB, false)).unwrap();
        let mut variants = Vec::new();
        let mut root = original.clone();
        root["sha"] = json!("4b825dc642cb6eb9a060e54bf8d69288fbee4904");
        variants.push(root);
        let mut subtree = original.clone();
        subtree["tree"][1]["sha"] = json!("4b825dc642cb6eb9a060e54bf8d69288fbee4904");
        variants.push(subtree);
        let mut mode = original.clone();
        mode["tree"][0]["mode"] = json!("100755");
        variants.push(mode);
        let mut path = original;
        path["tree"][0]["path"] = json!("docs/changed.md");
        variants.push(path);
        let mut alias: Value = serde_json::from_slice(&tree_body(TREE_SHA, HELLO_BLOB, false)).unwrap();
        alias["tree"][1]["mode"] = json!("120000");
        alias["tree"][1]["type"] = json!("blob");
        variants.push(alias);
        for variant in variants {
            let bytes = serde_json::to_vec(&variant).unwrap();
            let output = inventory_output(&selected, &url, &response(&url, &bytes, "application/json")).unwrap();
            assert_eq!(output["result"], "degraded");
            assert_eq!(output["tree_sha"], Value::Null);
            assert_eq!(output["complete"], false);
            assert_eq!(output["entries"], json!([]));
            assert_eq!(output["raw_response_base64"], STANDARD.encode(bytes));
        }
    }

    #[test]
    fn valid_empty_tree_proves_missing_path_without_invented_membership() {
        let request = request("4b825dc642cb6eb9a060e54bf8d69288fbee4904", HELLO_BLOB);
        let url = request.repository.tree_url(&request.tree_sha).unwrap();
        let bytes = serde_json::to_vec(&json!({"sha":request.tree_sha,"tree":[],"truncated":false})).unwrap();
        assert_eq!(immutable_tree_binding(&request, &url, &response(&url, &bytes, "application/json")), Err("tree_path_missing"));
    }

    #[test]
    fn authenticated_tree_rejects_a_different_attested_blob() {
        let request = request(TREE_SHA, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        let url = request.repository.tree_url(TREE_SHA).unwrap();
        let bytes = tree_body(TREE_SHA, HELLO_BLOB, false);
        assert_eq!(immutable_tree_binding(&request, &url, &response(&url, &bytes, "application/json")), Err("tree_blob_mismatch"));
    }

    #[test]
    fn exact_tree_binding_rejects_incomplete_missing_or_changed_paths() {
        let request = request(TREE_SHA, HELLO_BLOB);
        let tree_url = request.repository.tree_url(&request.tree_sha).unwrap();
        assert_eq!(
            immutable_tree_binding(&request, &tree_url, &tree_response(&request, false)),
            Ok(MATERIAL.len())
        );
        assert_eq!(
            immutable_tree_binding(&request, &tree_url, &tree_response(&request, true)),
            Err("tree_incomplete")
        );
        let mut missing = tree_response(&request, false);
        missing.body = br#"{"sha":"0123456789abcdef0123456789abcdef01234567","tree":[],"truncated":false}"#.to_vec();
        missing.sha256 = sha256(&missing.body);
        assert_eq!(
            immutable_tree_binding(&request, &tree_url, &missing),
            Err("upstream_parse")
        );
        let mut other_blob = tree_response(&request, false);
        other_blob.body = tree_body(TREE_SHA, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", false);
        other_blob.sha256 = sha256(&other_blob.body);
        assert_eq!(
            immutable_tree_binding(&request, &tree_url, &other_blob),
            Err("upstream_parse")
        );
        let other_url = request.repository.tree_url("1123456789abcdef0123456789abcdef01234567").unwrap();
        assert_eq!(
            immutable_tree_binding(&request, &other_url, &tree_response(&request, false)),
            Err("tree_provenance_mismatch")
        );
    }

    #[test]
    fn immutable_blob_identity_is_required_before_any_material_bytes() {
        let request = request(TREE_SHA, HELLO_BLOB);
        let output = admitted_output(&request, MATERIAL, "application/octet-stream");
        assert_eq!(output["result"], "raw_snapshot");
        assert_eq!(output["material_admitted"], true);
        assert_eq!(output["bytes"], STANDARD.encode(MATERIAL));
        assert_eq!(output["byte_length"], MATERIAL.len());
        assert_eq!(output["material_identity"]["blob_sha"], HELLO_BLOB);
        assert_eq!(output["material_identity"]["tree_sha"], TREE_SHA);
        assert_eq!(output["material_identity"]["verified"], true);
        assert_eq!(output["operator_attestation"]["independent_rights_proof"], false);
        assert_eq!(output["raw_evidence"], Value::Null);
        assert_eq!(output["retrieval"]["response_representation"], "github_git_blob_raw");
        assert_schema(&output, &schema()["retrieve"]["output"]);

        let mismatch = admitted_output(&request, b"changed branch bytes", "application/octet-stream");
        assert_eq!(mismatch["result"], "degraded_raw");
        assert_eq!(mismatch["material_admitted"], false);
        assert_eq!(mismatch["fallback_reason"], "blob_identity_mismatch");
        assert_eq!(mismatch["bytes"], Value::Null);
        assert_eq!(mismatch["byte_length"], Value::Null);
        assert_eq!(mismatch["sha256"], Value::Null);
        assert_eq!(mismatch["material_identity"], Value::Null);
        assert_eq!(
            mismatch["raw_evidence"]["raw_response_base64"],
            STANDARD.encode(b"changed branch bytes")
        );
        assert_schema(&mismatch, &schema()["retrieve"]["output"]);
    }

    #[test]
    fn immutable_raw_mime_fallback_keeps_evidence_outside_material_bytes() {
        let request = request(TREE_SHA, HELLO_BLOB);
        let degraded = admitted_output(&request, MATERIAL, "text/html");
        assert_eq!(degraded["fallback_reason"], "unexpected_content");
        assert_eq!(degraded["content_type"], "text/html");
        assert_eq!(degraded["bytes"], Value::Null);
        assert_eq!(degraded["raw_evidence"]["raw_response_base64"], STANDARD.encode(MATERIAL));

        let url = request.repository.blob_url(&request.blob_sha).unwrap();
        let no_mime = Response {
            url: url.as_str().to_owned(),
            status: 200,
            headers: BTreeMap::new(),
            body: MATERIAL.to_vec(),
            sha256: sha256(MATERIAL),
            fetched_at_unix_ms: 1_700_000_000_000,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        };
        let tree = tree_response(&request, false);
        let tree_url = request.repository.tree_url(&request.tree_sha).unwrap();
        let size = immutable_tree_binding(&request, &tree_url, &tree).unwrap();
        let missing = retrieval_output(&request, &url, &no_mime, size, json!({
            "tree_sha": TREE_SHA,
            "path": request.path,
            "blob_sha": HELLO_BLOB,
            "byte_length": size,
            "raw_response_base64": STANDARD.encode(&tree.body),
            "retrieval": retrieval(&tree)
        }))
        .unwrap();
        assert_eq!(missing["result"], "degraded_raw");
        assert_eq!(missing["fallback_reason"], "missing_content_type");
        assert_eq!(missing["content_type"], Value::Null);
        assert_eq!(missing["bytes"], Value::Null);
        assert_eq!(missing["raw_evidence"]["raw_response_base64"], STANDARD.encode(MATERIAL));
        assert_schema(&missing, &schema()["retrieve"]["output"]);
    }

    #[test]
    fn github_failures_are_typed_and_never_reclassified_as_success() {
        assert_eq!(
            classify_status(429, false, None, None).err().unwrap().code,
            "rate_limited"
        );
        assert_eq!(
            classify_status(403, false, None, Some("0"))
                .err()
                .unwrap()
                .code,
            "rate_limited"
        );
        assert_eq!(
            classify_status(403, false, Some("30"), None)
                .err()
                .unwrap()
                .code,
            "rate_limited"
        );
        assert_eq!(
            classify_status(403, false, None, Some("10"))
                .err()
                .unwrap()
                .code,
            "safety_latched"
        );
        assert_eq!(
            classify_status(401, false, None, None).err().unwrap().code,
            "safety_latched"
        );
        assert_eq!(
            classify_status(302, false, None, None).err().unwrap().code,
            "redirect_refused"
        );
        assert_eq!(
            classify_status(404, false, None, None).err().unwrap().code,
            "http_rejected"
        );
        assert!(classify_status(200, false, None, None).is_ok());
    }

    #[test]
    fn schema_exposes_the_rights_gate_and_fixed_repositories() {
        let contract = schema();
        assert_eq!(
            contract["retrieve"]["input"]["properties"]["rights_reviewed"]["const"],
            true
        );
        assert_eq!(
            contract["inventory"]["output"]["properties"]["next_cursor"]["type"],
            "null"
        );
        let repos = contract["inventory"]["input"]["properties"]["repo"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(repos.len(), REPOSITORIES.len());
        assert!(repos.iter().any(|repo| repo == "Soft-Where-21/21CoreDocs"));
        let retrieve_output = &contract["retrieve"]["output"];
        assert_eq!(
            retrieve_output["properties"]["result"]["enum"],
            json!(["raw_snapshot", "degraded_raw"])
        );
        assert!(retrieve_output["properties"]["fallback_reason"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("blob_identity_mismatch")));
        assert_eq!(
            retrieve_output["properties"]["content_type"]["type"],
            json!(["string", "null"])
        );
        assert!(contract["retrieve"]["input"]["properties"]
            .get("branch")
            .is_none());
        assert_eq!(
            contract["retrieve"]["input"]["required"],
            json!(["school", "path", "tree_sha", "blob_sha", "rights_reviewed"])
        );
        assert_eq!(
            contract["retrieve"]["output"]["properties"]["schema_version"]["const"],
            2
        );
    }

    #[test]
    fn inventory_schema_conforms_to_the_published_contract() {
        let selected = selection(3, None, None);
        let url = selected.tree_url().unwrap();
        let body = tree_body(TREE_SHA, HELLO_BLOB, false);
        let output = inventory_output(&selected, &url, &response(&url, &body, "application/json"))
            .unwrap();
        assert_eq!(output["entries"][0]["blob_sha"], HELLO_BLOB);
        assert_eq!(output["entries"][0]["upstream_sha"], HELLO_BLOB);
        assert_schema(&output, &schema()["inventory"]["output"]);
    }

    #[test]
    fn immutable_urls_bind_exact_objects_and_encode_inventory_branches() {
        let slanted = selection(8, Some("HoBeedzc/CreditCount"), Some("feature/x"));
        let tree = slanted.tree_url().unwrap().to_string();
        assert!(tree.contains("trees/feature%2Fx"), "{tree}");
        let request = request(TREE_SHA, HELLO_BLOB);
        let immutable_tree = request.repository.tree_url(&request.tree_sha).unwrap();
        let immutable_blob = request.repository.blob_url(&request.blob_sha).unwrap();
        assert!(immutable_tree.as_str().contains(&format!("trees/{TREE_SHA}")));
        assert!(immutable_blob.as_str().ends_with(&format!("/git/blobs/{HELLO_BLOB}")));
        assert!(!immutable_tree.as_str().contains("main"));
        assert!(!immutable_blob.as_str().contains("main"));
        assert_ne!(
            ResponseCache::name(&immutable_tree),
            ResponseCache::name(&selection(3, None, None).tree_url().unwrap())
        );
        assert!(select_source(8, Some("HoBeedzc/CreditCount"), Some("a//b")).is_err());
        assert!(select_source(8, Some("HoBeedzc/CreditCount"), Some("/x")).is_err());
    }

    static SEQUENCE: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "buaa-departments-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn cache_dir(&self) -> std::path::PathBuf {
            self.0.join("cache")
        }
        fn governor_dir(&self) -> std::path::PathBuf {
            self.0.join("governor")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Server {
        address: std::net::SocketAddr,
        requests: std::sync::mpsc::Receiver<String>,
        count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }
    impl Server {
        fn new(
            handler: impl FnMut(&mut std::net::TcpStream, &str, usize) + Send + 'static,
        ) -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let (sender, requests) = std::sync::mpsc::channel();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let worker_stop = std::sync::Arc::clone(&stop);
            let worker_count = std::sync::Arc::clone(&count);
            let worker = std::thread::spawn(move || {
                let mut handler = handler;
                while !worker_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            socket
                                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                                .unwrap();
                            let mut bytes = Vec::new();
                            let mut byte = [0u8];
                            while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 32 * 1024 {
                                match socket.read(&mut byte) {
                                    Ok(1) => bytes.push(byte[0]),
                                    _ => break,
                                }
                            }
                            let request = String::from_utf8(bytes).unwrap();
                            let index = worker_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            sender.send(request.clone()).unwrap();
                            handler(&mut socket, &request, index);
                        }
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock =>
                        {
                            std::thread::sleep(std::time::Duration::from_millis(2))
                        }
                        Err(error) => panic!("loopback listener failed: {error}"),
                    }
                }
            });
            Self { address, requests, count, stop, worker: Some(worker) }
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }

    fn reply(socket: &mut std::net::TcpStream, status: u16, headers: &str, body: &[u8]) {
        write!(
            socket,
            "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
            body.len()
        )
        .unwrap();
        socket.write_all(body).unwrap();
    }

    fn env(fixture: &Fixture, route: Option<std::net::SocketAddr>, governor: bool) {
        TEST_CACHE_DIR.with(|cell| *cell.borrow_mut() = Some(fixture.cache_dir()));
        TEST_ROUTE.with(|cell| cell.set(route));
        TEST_GOVERNOR.with(|cell| *cell.borrow_mut() = governor.then(|| fixture.governor_dir()));
    }

    fn governor_state(fixture: &Fixture) -> Value {
        serde_json::from_slice(
            &std::fs::read(fixture.governor_dir().join("state.json")).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn rights_gate_denial_has_no_cache_or_network_side_effects() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| reply(socket, 200, "", b""));
        env(&fixture, Some(server.address), true);
        let denied = retrieve(
            &retrieval_input_with_rights(TREE_SHA, HELLO_BLOB, false),
            true,
        )
        .err()
        .unwrap();
        assert_eq!(denied.code, "authorization_required");
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!fixture.cache_dir().exists());
        assert!(!fixture.governor_dir().exists());
    }

    #[test]
    fn credential_fallback_is_withheld_fresh_and_cached() {
        let fixture = Fixture::new();
        let body = b"<html><form action='/login'><input name='authenticity_token' value='tok'><input type='password' name='password'></form>";
        let server = Server::new(move |socket, _, _| {
            reply(socket, 200, "Content-Type: text/html\r\n", body)
        });
        env(&fixture, Some(server.address), true);
        let error = inventory(r#"{"school":3}"#, true).unwrap_err();
        assert_eq!(error.code, "sensitive_response");
        assert!(!format!("{error:?}").contains("authenticity_token"));
        assert_eq!(fixture.cache_dir().read_dir().unwrap().count(), 0);
        assert_eq!(governor_state(&fixture)["safety_latched"], false);
        let url = selection(3, None, None).tree_url().unwrap();
        // Simulate a retained original from an older classifier. Loading must
        // re-screen even a record with the current cookie-admission version.
        ResponseCache::open().unwrap().save(&response(&url, body, "text/html")).unwrap();
        assert_eq!(inventory(r#"{"school":3}"#, false).unwrap_err().code, "sensitive_response");
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(fixture.cache_dir().read_dir().unwrap().count(), 1);
    }

    #[test]
    fn safe_malformed_fallback_retains_exact_original_offline() {
        let fixture = Fixture::new();
        let body = b"<html><p>Reference: token/password vocabulary, no credential controls.</p></html>";
        let server = Server::new(move |socket, _, _| {
            reply(socket, 200, "Content-Type: text/html\r\n", body)
        });
        env(&fixture, Some(server.address), true);
        let first = inventory(r#"{"school":3}"#, true).unwrap();
        assert_eq!(first["raw_response_base64"], STANDARD.encode(body));
        let cached = inventory(r#"{"school":3}"#, false).unwrap();
        assert_eq!(cached["raw_response_base64"], STANDARD.encode(body));
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn cookie_refusal_preserves_observed_cooldown() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| {
            reply(socket, 200, "Content-Type: text/html\r\nSet-Cookie: session=private\r\nRetry-After: 120\r\n", b"<html>reference</html>")
        });
        env(&fixture, Some(server.address), true);
        assert_eq!(inventory(r#"{"school":3}"#, true).unwrap_err().code, "sensitive_response");
        assert_eq!(fixture.cache_dir().read_dir().unwrap().count(), 0);
        let state = governor_state(&fixture);
        assert_eq!(state["safety_latched"], false);
        assert!(state["cooldown_until_ms"].as_u64().unwrap()
            >= state["last_observed_ms"].as_u64().unwrap() + 119_000);
    }

    #[test]
    fn old_cache_has_no_cookie_proof_and_is_not_automatically_refetched() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _, _| panic!("old cache triggered a request"));
        env(&fixture, Some(server.address), true);
        let url = selection(3, None, None).tree_url().unwrap();
        let cache = ResponseCache::open().unwrap();
        cache.save(&response(&url, b"<html>reference</html>", "text/html")).unwrap();
        let path = fixture.cache_dir().join(ResponseCache::name(&url));
        let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["version"] = json!(1);
        let original = serde_json::to_vec(&record).unwrap();
        std::fs::write(&path, &original).unwrap();
        assert_eq!(inventory(r#"{"school":3}"#, true).unwrap_err().code, "unreviewed_cache");
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!fixture.governor_dir().exists());
    }

    #[test]
    fn mismatched_blob_credential_fallback_is_not_cached_or_exported() {
        let fixture = Fixture::new();
        let tree = tree_body(TREE_SHA, HELLO_BLOB, false);
        let server = Server::new(move |socket, _, index| match index {
            0 => reply(socket, 200, "Content-Type: application/json\r\n", &tree),
            1 => reply(socket, 200, "Content-Type: text/html\r\n", b"<form><input type='password' name='password' value='private'></form>"),
            _ => panic!("unexpected request"),
        });
        env(&fixture, Some(server.address), true);
        assert_eq!(retrieve(&retrieval_input(TREE_SHA, HELLO_BLOB), true).unwrap_err().code, "sensitive_response");
        // Only the independently admitted tree original survives.
        assert_eq!(fixture.cache_dir().read_dir().unwrap().count(), 1);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn identity_verified_teaching_json_is_not_an_api_wrapper() {
        let body = br#"{"token":"example","password":"teaching example"}"#;
        let blob = git_blob_sha(body, 40);
        let request = parse_retrieval_input(&retrieval_input(TREE_SHA, &blob)).unwrap();
        let url = request.repository.blob_url(&request.blob_sha).unwrap();
        let original = response(&url, body, "application/json");
        let output = retrieval_output(&request, &url, &original, body.len(), Value::Null).unwrap();
        assert_eq!(output["result"], "raw_snapshot");
        assert_eq!(output["bytes"], STANDARD.encode(body));
    }

    #[test]
    fn offline_miss_makes_zero_requests_and_writes_no_cache() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| reply(socket, 200, "", b""));
        env(&fixture, Some(server.address), true);
        let error = retrieve(
            &retrieval_input(TREE_SHA, HELLO_BLOB),
            false,
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "offline_miss");
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(fixture.cache_dir().read_dir().unwrap().count() == 0);
    }

    #[test]
    fn immutable_tree_and_blob_fetch_verifies_then_replays_offline() {
        let fixture = Fixture::new();
        let tree = tree_body(TREE_SHA, HELLO_BLOB, false);
        let server = Server::new(move |socket, _, index| match index {
            0 => reply(socket, 200, "Content-Type: application/json\r\n", &tree),
            1 => reply(
                socket,
                200,
                "Content-Type: application/octet-stream\r\n",
                MATERIAL,
            ),
            _ => panic!("unexpected extra request"),
        });
        env(&fixture, Some(server.address), true);
        let input = retrieval_input(TREE_SHA, HELLO_BLOB);
        let first = retrieve(&input, true).unwrap();
        assert_eq!(first["result"], "raw_snapshot");
        assert_eq!(first["material_admitted"], true);
        assert_eq!(first["material_identity"]["blob_sha"], HELLO_BLOB);
        assert_eq!(first["retrieval"]["cache_status"], "miss");
        assert_eq!(first["tree_binding"]["retrieval"]["cache_status"], "miss");
        assert_eq!(first["bytes"], STANDARD.encode(MATERIAL));
        assert_eq!(first["tree_binding"]["raw_response_base64"], STANDARD.encode(&tree_body(TREE_SHA, HELLO_BLOB, false)));
        assert_schema(&first, &schema()["retrieve"]["output"]);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 2);
        let requests: Vec<_> = server.requests.try_iter().collect();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with(&format!(
            "GET /repos/AccSrd/BUAA_Course_Automation/git/trees/{TREE_SHA}?recursive=1 "
        )));
        assert!(requests[1].starts_with(&format!(
            "GET /repos/AccSrd/BUAA_Course_Automation/git/blobs/{HELLO_BLOB} "
        )));
        assert!(requests[1]
            .to_ascii_lowercase()
            .contains("accept: application/vnd.github.raw+json"));
        assert!(!requests[0].contains("main") && !requests[1].contains("main"));

        let second = retrieve(&input, false).unwrap();
        assert_eq!(second["retrieval"]["cache_status"], "hit");
        assert_eq!(second["tree_binding"]["retrieval"]["cache_status"], "hit");
        assert_eq!(second["bytes"], first["bytes"]);
        assert_eq!(second["material_identity"], first["material_identity"]);
        assert_schema(&second, &schema()["retrieve"]["output"]);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn repeated_retry_after_preserves_the_longest_cooldown() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| {
            reply(socket, 429, "Retry-After: 1\r\nRetry-After: 120\r\n", b"")
        });
        env(&fixture, Some(server.address), true);
        assert!(inventory(r#"{"school":3}"#, true).is_err());
        let state = governor_state(&fixture);
        assert!(state["cooldown_until_ms"].as_u64().unwrap()
            >= state["last_observed_ms"].as_u64().unwrap() + 119_000);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn repeated_content_type_never_admits_or_caches_a_tree() {
        let fixture = Fixture::new();
        let tree = tree_body(TREE_SHA, HELLO_BLOB, false);
        let server = Server::new(move |socket, _, _| {
            reply(socket, 200, "Content-Type: application/json; charset=utf-8\r\nContent-Type: text/html\r\n", &tree)
        });
        env(&fixture, Some(server.address), true);
        let error = inventory(r#"{"school":3}"#, true).err().unwrap();
        assert_eq!(error.code, "unreviewed_body");
        assert_eq!(fixture.cache_dir().read_dir().unwrap().count(), 0);
        assert_eq!(governor_state(&fixture)["safety_latched"], false);
        let url = selection(3, None, None).tree_url().unwrap();
        let cached = response(&url, &tree_body(TREE_SHA, HELLO_BLOB, false), "application/json; charset=utf-8, text/html");
        assert_eq!(assess_response_body(&cached), ChallengeAssessment::Unreviewed);
    }

    #[test]
    fn raw_429_without_challenge_records_cooldown_without_a_safety_latch() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| reply(socket, 429, "", b""));
        env(&fixture, Some(server.address), true);
        let error = retrieve(
            &retrieval_input(TREE_SHA, HELLO_BLOB),
            true,
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "rate_limited");
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
        let state = governor_state(&fixture);
        assert_eq!(state["safety_latched"], false);
        assert!(state["cooldown_until_ms"].as_u64().unwrap() > state["last_observed_ms"].as_u64().unwrap());
    }

    #[test]
    fn raw_403_rate_limit_latches_safety_and_preserves_the_cooldown() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| {
            reply(socket, 403, "Retry-After: 30\r\nx-ratelimit-remaining: 0\r\n", b"")
        });
        env(&fixture, Some(server.address), true);
        let error = retrieve(
            &retrieval_input(TREE_SHA, HELLO_BLOB),
            true,
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "safety_latched");
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
        let state = governor_state(&fixture);
        assert_eq!(state["safety_latched"], true);
        assert!(state["cooldown_until_ms"].as_u64().unwrap() > state["last_observed_ms"].as_u64().unwrap());
    }

    #[test]
    fn raw_429_with_challenge_latches_safety_and_keeps_the_cooldown() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| {
            reply(socket, 429, "cf-mitigated: challenge\r\n", b"")
        });
        env(&fixture, Some(server.address), true);
        let error = retrieve(
            &retrieval_input(TREE_SHA, HELLO_BLOB),
            true,
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "safety_latched");
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
        let state = governor_state(&fixture);
        assert_eq!(state["safety_latched"], true);
        assert!(state["cooldown_until_ms"].as_u64().unwrap() > state["last_observed_ms"].as_u64().unwrap());
    }

    #[test]
    fn truncated_tree_rejection_stops_before_blob_and_replays_offline() {
        let fixture = Fixture::new();
        let tree = tree_body(TREE_SHA, HELLO_BLOB, true);
        let server = Server::new(move |socket, _, _| {
            reply(socket, 200, "Content-Type: application/json\r\n", &tree)
        });
        env(&fixture, Some(server.address), true);
        let input = retrieval_input(TREE_SHA, HELLO_BLOB);
        let first = retrieve(&input, true).unwrap();
        assert_eq!(first["result"], "degraded_raw");
        assert_eq!(first["fallback_reason"], "tree_incomplete");
        assert_eq!(first["material_admitted"], false);
        assert_eq!(first["material_identity"], Value::Null);
        assert_eq!(first["bytes"], Value::Null);
        assert_eq!(first["byte_length"], Value::Null);
        assert_eq!(first["sha256"], Value::Null);
        assert_eq!(
            first["raw_evidence"]["raw_response_base64"],
            STANDARD.encode(&tree_body(TREE_SHA, HELLO_BLOB, true))
        );
        assert_schema(&first, &schema()["retrieve"]["output"]);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
        let second = retrieve(&input, false).unwrap();
        assert_eq!(second["result"], "degraded_raw");
        assert_eq!(second["fallback_reason"], "tree_incomplete");
        assert_eq!(second["bytes"], Value::Null);
        assert_eq!(second["raw_evidence"], first["raw_evidence"]);
        assert_eq!(server.requests.try_iter().count(), 1);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn blob_mismatch_preserves_http_evidence_but_never_admits_material() {
        let fixture = Fixture::new();
        let tree = tree_body(TREE_SHA, HELLO_BLOB, false);
        let server = Server::new(move |socket, _, index| match index {
            0 => reply(socket, 200, "Content-Type: application/json\r\n", &tree),
            1 => reply(
                socket,
                200,
                "Content-Type: application/octet-stream\r\n",
                b"changed branch bytes",
            ),
            _ => panic!("unexpected extra request"),
        });
        env(&fixture, Some(server.address), true);
        let input = retrieval_input(TREE_SHA, HELLO_BLOB);
        let first = retrieve(&input, true).unwrap();
        assert_eq!(first["fallback_reason"], "blob_identity_mismatch");
        assert_eq!(first["material_admitted"], false);
        assert_eq!(first["material_identity"], Value::Null);
        assert_eq!(first["bytes"], Value::Null);
        assert_eq!(
            first["raw_evidence"]["raw_response_base64"],
            STANDARD.encode(b"changed branch bytes")
        );
        assert_eq!(first["tree_binding"]["tree_sha"], TREE_SHA);
        assert_eq!(first["tree_binding"]["blob_sha"], HELLO_BLOB);
        assert_schema(&first, &schema()["retrieve"]["output"]);
        let second = retrieve(&input, false).unwrap();
        assert_eq!(second["raw_evidence"], first["raw_evidence"]);
        assert_eq!(second["bytes"], Value::Null);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn network_failure_is_typed_and_never_retried() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _, _| {});
        env(&fixture, Some(server.address), true);
        let error = retrieve(&retrieval_input(TREE_SHA, HELLO_BLOB), true)
            .err()
            .unwrap();
        assert_eq!(error.code, "network_error");
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(server.requests.try_iter().count(), 1);
        assert!(fixture.cache_dir().read_dir().unwrap().count() == 0);
    }

    #[test]
    fn github_raw_vendor_response_is_verified_without_a_json_envelope() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| {
            reply(socket, 200, "Content-Type: application/vnd.github.raw+json\r\n", MATERIAL)
        });
        env(&fixture, Some(server.address), true);
        let request = request(TREE_SHA, HELLO_BLOB);
        let cache = ResponseCache::open().unwrap();
        cache.save(&tree_response(&request, false)).unwrap();
        let input = retrieval_input(TREE_SHA, HELLO_BLOB);
        let output = retrieve(&input, true).unwrap();
        assert_eq!(output["result"], "raw_snapshot");
        assert_eq!(output["bytes"], STANDARD.encode(MATERIAL));
        assert_eq!(output["content_type"], "application/vnd.github.raw+json");
        assert_eq!(output["retrieval"]["http"]["headers"]["content-type"], "application/vnd.github.raw+json");
        let requests: Vec<_> = server.requests.try_iter().collect();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].to_ascii_lowercase().contains("accept: application/vnd.github.raw+json"));
        assert!(requests[0].starts_with(&format!(
            "GET /repos/AccSrd/BUAA_Course_Automation/git/blobs/{HELLO_BLOB} "
        )));
        let offline = retrieve(&input, false).unwrap();
        assert_eq!(offline["material_identity"], output["material_identity"]);
        assert_eq!(offline["bytes"], output["bytes"]);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_schema(&offline, &schema()["retrieve"]["output"]);
    }

    #[test]
    fn cached_binary_sha256_blob_uses_the_same_exact_identity_gate() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _, _| panic!("offline SHA256 retrieval sent a request"));
        env(&fixture, Some(server.address), true);
        let bytes = [0xff; 11];
        let tree_sha = BINARY_TREE_SHA256;
        let blob_sha = "4646e28646e4ca51ae58ec2f203902342dd2ff948be0415dd47f7b9995732f5c";
        let request = request(&tree_sha, &blob_sha);
        let url = request.repository.blob_url(&blob_sha).unwrap();
        let cache = ResponseCache::open().unwrap();
        cache.save(&tree_response(&request, false)).unwrap();
        cache.save(&response(&url, &bytes, "application/octet-stream")).unwrap();
        let output = retrieve(&retrieval_input(&tree_sha, &blob_sha), false).unwrap();
        assert_eq!(output["result"], "raw_snapshot");
        assert_eq!(output["material_admitted"], true);
        assert_eq!(output["material_identity"]["git_object_format"], "sha256");
        assert_eq!(output["material_identity"]["blob_sha"], blob_sha);
        assert_eq!(output["bytes"], STANDARD.encode(bytes));
        assert_eq!(output["sha256"], sha256(&bytes));
        assert_schema(&output, &schema()["retrieve"]["output"]);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!fixture.governor_dir().exists());
    }

    #[test]
    fn cached_missing_path_refuses_before_any_blob_read() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _, _| panic!("missing tree path sent a blob request"));
        env(&fixture, Some(server.address), true);
        let request = request(TREE_SHA, HELLO_BLOB);
        let url = request.repository.tree_url(TREE_SHA).unwrap();
        let cache = ResponseCache::open().unwrap();
        let bytes = serde_json::to_vec(&json!({"sha": TREE_SHA, "tree": [], "truncated": false})).unwrap();
        cache.save(&response(&url, &bytes, "application/json")).unwrap();
        let output = retrieve(&retrieval_input(TREE_SHA, HELLO_BLOB), false).unwrap();
        assert_eq!(output["fallback_reason"], "upstream_parse");
        assert_eq!(output["material_admitted"], false);
        assert_eq!(output["bytes"], Value::Null);
        assert_eq!(output["material_identity"], Value::Null);
        assert_schema(&output, &schema()["retrieve"]["output"]);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!fixture.governor_dir().exists());
    }

    fn assert_live_challenge_stops_followup(fixture: &Fixture, server: &Server) {
        let state = governor_state(fixture);
        assert_eq!(state["safety_latched"], true);
        assert_eq!(state["authentication_armed"], false);
        assert_eq!(state["pending"], Value::Null);
        assert_eq!(fixture.cache_dir().read_dir().unwrap().count(), 0);
        let followup = retrieve(&retrieval_input(TREE_SHA, HELLO_BLOB), true)
            .err()
            .unwrap();
        assert_eq!(followup.code, "safety_latched");
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn header_only_challenge_latches_without_body_processing_or_followup() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| {
            reply(socket, 200, "Content-Type: application/json\r\nX-Captcha: required\r\n", b"{}")
        });
        env(&fixture, Some(server.address), true);
        let error = retrieve(&retrieval_input(TREE_SHA, HELLO_BLOB), true).err().unwrap();
        assert_eq!(error.code, "safety_latched");
        assert_live_challenge_stops_followup(&fixture, &server);
    }

    #[test]
    fn body_only_active_challenge_latches_without_caching_or_followup() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| {
            reply(socket, 200, "Content-Type: text/html\r\n", br#"<form><input name="captcha"></form>"#)
        });
        env(&fixture, Some(server.address), true);
        let error = retrieve(&retrieval_input(TREE_SHA, HELLO_BLOB), true).err().unwrap();
        assert_eq!(error.code, "safety_latched");
        assert_live_challenge_stops_followup(&fixture, &server);
    }

    #[test]
    fn detected_read_prefix_keeps_latch_cooldown_and_network_failure() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| {
            let prefix = br#"<form><input name="captcha"></form>"#;
            write!(
                socket,
                "HTTP/1.1 429 Fixture\r\nConnection: close\r\nContent-Type: text/html\r\nRetry-After: 30\r\nContent-Length: {}\r\n\r\n",
                prefix.len() + 100
            )
            .unwrap();
            socket.write_all(prefix).unwrap();
        });
        env(&fixture, Some(server.address), true);
        let error = retrieve(&retrieval_input(TREE_SHA, HELLO_BLOB), true).err().unwrap();
        assert_eq!(error.code, "safety_latched");
        let state = governor_state(&fixture);
        assert!(state["cooldown_until_ms"].as_u64().unwrap() > state["last_observed_ms"].as_u64().unwrap());
        assert_eq!(state["network_failures"], 1);
        assert_live_challenge_stops_followup(&fixture, &server);
    }

    #[test]
    fn inert_html_challenge_examples_do_not_latch_and_replay_offline() {
        let fixture = Fixture::new();
        let inert = br#"<script>const example = '<input name="captcha">';</script><template><input name="captcha"></template><input name="captcha" disabled><input name="captcha" type="hidden"><p>captcha documentation</p>"#;
        let server = Server::new(move |socket, _, _| {
            reply(socket, 200, "Content-Type: text/html\r\n", inert)
        });
        env(&fixture, Some(server.address), true);
        let output = inventory(r#"{"school":3}"#, true).unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["fallback_reason"], "unexpected_content");
        assert_eq!(output["raw_response_base64"], STANDARD.encode(inert));
        assert_eq!(governor_state(&fixture)["safety_latched"], false);
        let offline = inventory(r#"{"school":3}"#, false).unwrap();
        assert_eq!(offline["raw_response_base64"], output["raw_response_base64"]);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn json_embedded_html_is_data_not_an_active_challenge() {
        let fixture = Fixture::new();
        let mut tree: Value = serde_json::from_slice(&tree_body(TREE_SHA, HELLO_BLOB, false)).unwrap();
        tree["note"] = json!(r#"<!doctype html><html><input name="captcha"></html>"#);
        let bytes = serde_json::to_vec(&tree).unwrap();
        let server = Server::new(move |socket, _, _| {
            reply(socket, 200, "Content-Type: application/json\r\n", &bytes)
        });
        env(&fixture, Some(server.address), true);
        let output = inventory(r#"{"school":3}"#, true).unwrap();
        assert_eq!(output["result"], "inventory_snapshot");
        assert_eq!(governor_state(&fixture)["safety_latched"], false);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn unreviewed_live_bodies_never_latch_process_or_enter_cache() {
        for (mime, body) in [
            (Some("text/html"), b"\xff<input name='captcha'>".as_slice()),
            (Some("application/xhtml+xml"), b"<input name='captcha'/>".as_slice()),
            (Some("application/octet-stream"), b"<!doctype html><html><input name='captcha'>".as_slice()),
            (None, b"ordinary material without MIME".as_slice()),
        ] {
            let fixture = Fixture::new();
            let headers = mime.map_or_else(String::new, |mime| format!("Content-Type: {mime}\r\n"));
            let server = Server::new(move |socket, _, _| reply(socket, 200, &headers, body));
            env(&fixture, Some(server.address), true);
            let error = inventory(r#"{"school":3}"#, true).err().unwrap();
            assert_eq!(error.code, "unreviewed_body", "mime {mime:?}");
            assert_eq!(governor_state(&fixture)["safety_latched"], false);
            assert_eq!(fixture.cache_dir().read_dir().unwrap().count(), 0);
            assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn cached_challenge_survives_another_pending_lease() {
        let fixture = Fixture::new();
        env(&fixture, None, true);
        let request = request(TREE_SHA, HELLO_BLOB);
        let url = request.repository.tree_url(TREE_SHA).unwrap();
        let cache = ResponseCache::open().unwrap();
        cache.save(&response(&url, br#"<input name="captcha">"#, "text/html")).unwrap();
        let governor = cache.open_governor().unwrap();
        let lease = net::acquire(&governor).unwrap();
        let error = retrieve(&retrieval_input(TREE_SHA, HELLO_BLOB), false).err().unwrap();
        assert_eq!(error.code, "safety_latched");
        lease.finish_without_request().unwrap();
        drop(governor);
        let reopened = cache.open_governor().unwrap();
        assert!(net::acquire(&reopened).is_err());
        let state = governor_state(&fixture);
        assert_eq!(state["safety_latched"], true);
        assert_eq!(state["authentication_armed"], false);
    }

    #[test]
    fn cached_detected_body_latches_without_sending_a_request() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _, _| panic!("cached challenge transmitted a request"));
        env(&fixture, Some(server.address), true);
        let request = request(TREE_SHA, HELLO_BLOB);
        let url = request.repository.tree_url(TREE_SHA).unwrap();
        let cache = ResponseCache::open().unwrap();
        cache.save(&response(&url, br#"<input name="captcha">"#, "text/html")).unwrap();
        let error = retrieve(&retrieval_input(TREE_SHA, HELLO_BLOB), false).err().unwrap();
        assert_eq!(error.code, "safety_latched");
        // Opening the isolated governor consumes the durable cached marker.
        let persisted = cache.open_governor().unwrap();
        assert!(net::acquire(&persisted).is_err());
        let state = governor_state(&fixture);
        assert_eq!(state["safety_latched"], true);
        assert_eq!(state["authentication_armed"], false);
        assert_eq!(state["pending"], Value::Null);
        assert_eq!(state["network_failures"], 0);
        assert_eq!(state["next_request_ms"], 0);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn cached_unreviewed_body_stops_before_governor_or_processing() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _, _| panic!("unreviewed cache transmitted a request"));
        env(&fixture, Some(server.address), true);
        let request = request(TREE_SHA, HELLO_BLOB);
        let url = request.repository.tree_url(TREE_SHA).unwrap();
        let cache = ResponseCache::open().unwrap();
        cache.save(&response(&url, b"\xff<input name='captcha'>", "text/html")).unwrap();
        let path = fixture.cache_dir().join(ResponseCache::name(&url));
        let before = std::fs::read(&path).unwrap();
        let error = retrieve(&retrieval_input(TREE_SHA, HELLO_BLOB), false).err().unwrap();
        assert_eq!(error.code, "unreviewed_body");
        assert!(!fixture.governor_dir().exists());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn cache_race_detected_body_finishes_on_the_original_lease() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _, _| panic!("cache race transmitted a request"));
        env(&fixture, Some(server.address), true);
        let request = request(TREE_SHA, HELLO_BLOB);
        let url = request.repository.tree_url(TREE_SHA).unwrap();
        let cache = ResponseCache::open().unwrap();
        let transport = cache.open_transport().unwrap();
        cache.save(&response(&url, br#"<input name="captcha">"#, "text/html")).unwrap();
        let error = transport.fetch::<Value>(&cache, &url, Surface::Tree, |_| {
            panic!("cached challenge reached structured processing")
        }).err().unwrap();
        assert_eq!(error.code, "safety_latched");
        let state = governor_state(&fixture);
        assert_eq!(state["safety_latched"], true);
        assert_eq!(state["pending"], Value::Null);
        assert_eq!(state["network_failures"], 0);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn cache_race_unreviewed_body_releases_without_latching_or_processing() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _, _| panic!("unreviewed cache race transmitted a request"));
        env(&fixture, Some(server.address), true);
        let request = request(TREE_SHA, HELLO_BLOB);
        let url = request.repository.tree_url(TREE_SHA).unwrap();
        let cache = ResponseCache::open().unwrap();
        let transport = cache.open_transport().unwrap();
        cache.save(&response(&url, b"\xff<input name='captcha'>", "text/html")).unwrap();
        let error = transport.fetch::<Value>(&cache, &url, Surface::Tree, |_| {
            panic!("unreviewed cache reached structured processing")
        }).err().unwrap();
        assert_eq!(error.code, "unreviewed_body");
        let state = governor_state(&fixture);
        assert_eq!(state["safety_latched"], false);
        assert_eq!(state["pending"], Value::Null);
        assert_eq!(state["network_failures"], 0);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn declared_size_refusal_retains_independent_read_failure_without_latching() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| {
            write!(
                socket,
                "HTTP/1.1 200 Fixture\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\nordinary prefix",
                MAX_TREE_BODY + 1
            )
            .unwrap();
        });
        env(&fixture, Some(server.address), true);
        let error = inventory(r#"{"school":3}"#, true).err().unwrap();
        assert_eq!(error.code, "body_limit");
        let state = governor_state(&fixture);
        assert_eq!(state["safety_latched"], false);
        assert_eq!(state["network_failures"], 1);
        assert_eq!(fixture.cache_dir().read_dir().unwrap().count(), 0);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn unsupported_wire_encoding_cannot_confirm_a_body_challenge() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, _| {
            reply(
                socket,
                200,
                "Content-Type: text/html\r\nContent-Encoding: gzip\r\n",
                br#"<input name="captcha">"#,
            )
        });
        env(&fixture, Some(server.address), true);
        let error = inventory(r#"{"school":3}"#, true).err().unwrap();
        assert_eq!(error.code, "unsupported_encoding");
        assert_eq!(governor_state(&fixture)["safety_latched"], false);
        assert_eq!(fixture.cache_dir().read_dir().unwrap().count(), 0);
        assert_eq!(server.count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
