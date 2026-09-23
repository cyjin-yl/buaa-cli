//! Opt-in, allowlisted HTTP sources with a private byte-preserving cache.
//!
//! Cache reads never open the governor or construct an HTTP client. Every remote
//! observation, including robots.txt, owns a shared governor lease until its body
//! is validated and cache persistence completes. Errors contain no remote data.

use crate::governor::{self, Governor, Outcome, RequestKind, RequestLease};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 12 * 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;
const MAX_URL: usize = 16 * 1024;
const ARCHIVE_ROBOTS_URL: &str = "https://web.archive.org/robots.txt";
const ORGANIZATIONS_ROBOTS_URL: &str = "https://www.buaa.edu.cn/robots.txt";
pub(crate) const ORGANIZATIONS_URL: &str = "https://www.buaa.edu.cn/jgsz/jxkyjg02.htm";
#[cfg(test)]
const ROBOTS_URL: &str = ARCHIVE_ROBOTS_URL;
const ROBOTS_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;
const HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "etag",
    "last-modified",
    "memento-datetime",
    "link",
    "date",
    "x-archive-orig-date",
    "x-archive-orig-last-modified",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceProfile {
    Archive,
    Organizations,
    Announcements,
}

impl SourceProfile {
    fn robots_url(self) -> &'static str {
        match self {
            Self::Archive => ARCHIVE_ROBOTS_URL,
            Self::Organizations | Self::Announcements => ORGANIZATIONS_ROBOTS_URL,
        }
    }

    fn cache_directory(self) -> &'static str {
        match self {
            Self::Archive => ".buaa-cli-archive-cache",
            Self::Organizations => ".buaa-cli-organizations-cache",
            Self::Announcements => ".buaa-cli-announcements-cache",
        }
    }

    fn validate_url(self, url: &Url) -> Result<(), Error> {
        let common_invalid = url.as_str().len() > MAX_URL
            || url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some();
        let allowed = match self {
            Self::Archive => {
                url.host_str() == Some("web.archive.org")
                    && (url.path() == "/cdx/search/cdx"
                        || url.path().starts_with("/web/")
                        || url.as_str() == ARCHIVE_ROBOTS_URL)
            }
            Self::Organizations => {
                url.host_str() == Some("www.buaa.edu.cn")
                    && url.query().is_none()
                    && matches!(url.path(), "/robots.txt" | "/jgsz/jxkyjg02.htm")
            }
            Self::Announcements => {
                url.host_str() == Some("www.buaa.edu.cn")
                    && url.query().is_none()
                    && matches!(url.path(), "/robots.txt" | "/xwzx.htm")
            }
        };
        if common_invalid || !allowed {
            Err(invalid_url())
        } else {
            Ok(())
        }
    }

    fn allows_missing(self, url: &Url, status: u16) -> bool {
        matches!(status, 404 | 410)
            && (url.as_str() == self.robots_url()
                || (self == Self::Archive && url.path().starts_with("/web/")))
    }

    fn cacheable(self, url: &Url, response: &Response) -> bool {
        response.status == 200
            || url.as_str() == self.robots_url()
            || (self == Self::Archive
                && response.headers.contains_key("memento-datetime")
                && response.headers.contains_key("link"))
    }

    fn valid_cached(self, url: &Url, cached: &Cached) -> bool {
        cached.status == 200
            || (matches!(cached.status, 404 | 410)
                && (url.as_str() == self.robots_url()
                    || (self == Self::Archive
                        && url.path().starts_with("/web/")
                        && cached.headers.contains_key("memento-datetime")
                        && cached.headers.contains_key("link"))))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheMode {
    Offline,
    PreferCache,
    Revalidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub code: &'static str,
    pub message: &'static str,
    pub source: Option<ErrorSource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorSource {
    /// Rust file path relative to crate root; e.g. `src/announcements.rs`.
    pub file: &'static str,
    pub line: u32,
    /// Human-readable invariant that failed.
    pub invariant: &'static str,
}

impl Error {
    pub const fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            source: None,
        }
    }

    pub const fn with_source(
        code: &'static str,
        message: &'static str,
        file: &'static str,
        line: u32,
        invariant: &'static str,
    ) -> Self {
        Self {
            code,
            message,
            source: Some(ErrorSource {
                file,
                line,
                invariant,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheStatus {
    Hit,
    Miss,
    Revalidated,
}

#[cfg_attr(test, derive(Clone))]
#[derive(Debug)]
pub struct Response {
    pub url: String,
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub sha256: String,
    /// When these exact response bytes and original headers were fetched.
    pub fetched_at_unix_ms: u64,
    pub cache_status: CacheStatus,
    /// A later validation never rewrites the original fetch facts above.
    pub revalidated_at_unix_ms: Option<u64>,
    pub revalidation_status: Option<u16>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cached {
    version: u8,
    url: String,
    status: u16,
    headers: BTreeMap<String, String>,
    body_base64: String,
    sha256: String,
    fetched_at_unix_ms: u64,
    immutable: bool,
    revalidated_at_unix_ms: Option<u64>,
    revalidation_status: Option<u16>,
    // Validators may change on 304 without changing the captured headers.
    etag: Option<String>,
    last_modified: Option<String>,
}

struct Entry {
    response: Response,
    immutable: bool,
    etag: Option<String>,
    last_modified: Option<String>,
}

pub struct ArchiveClient {
    mode: CacheMode,
    profile: SourceProfile,
    directory: File,
    #[cfg(test)]
    test_route: Option<std::net::SocketAddr>,
    #[cfg(test)]
    test_governor: Option<std::path::PathBuf>,
}

impl ArchiveClient {
    pub fn open(mode: CacheMode) -> Result<Self, Error> {
        Self::open_profile(mode, SourceProfile::Archive)
    }

    pub(crate) fn open_organizations(mode: CacheMode) -> Result<Self, Error> {
        Self::open_profile(mode, SourceProfile::Organizations)
    }

    pub(crate) fn open_announcements(mode: CacheMode) -> Result<Self, Error> {
        Self::open_profile(mode, SourceProfile::Announcements)
    }

    fn open_profile(mode: CacheMode, profile: SourceProfile) -> Result<Self, Error> {
        let home = governor::identity_home().map_err(|_| cache_error())?;
        let _home = governor::open_directory(&home, false, false).map_err(|_| cache_error())?;
        let directory = governor::open_directory(&home.join(profile.cache_directory()), true, true)
            .map_err(|_| cache_error())?;
        Ok(Self {
            mode,
            directory,
            profile,
            #[cfg(test)]
            test_route: None,
            #[cfg(test)]
            test_governor: None,
        })
    }

    /// Process and validate a response before caching it or releasing its lease.
    pub fn get<T>(
        &self,
        url: &Url,
        immutable: bool,
        process: impl FnOnce(&Response) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.profile.validate_url(url)?;
        let cached = self.load(url)?;
        if self.mode != CacheMode::Revalidate {
            if let Some(entry) = cached {
                return process(&entry.response);
            }
            if self.mode == CacheMode::Offline {
                return Err(Error::new(
                    "offline_miss",
                    "archive response is not in the local cache",
                ));
            }
        }
        // No governor or reqwest construction occurs on either offline path.
        let governor = self.open_governor()?;
        let http = self.http_client()?;
        if url.as_str() != self.profile.robots_url() {
            self.check_robots(url, &governor, &http)?;
        }
        // Reload only under the lease in fetch: another process may have populated
        // this immutable URL while this process was checking robots or waiting.
        self.fetch(url, immutable, &governor, &http, process)
    }

    #[cfg(test)]
    fn snapshot(&self, url: &Url, immutable: bool) -> Result<Response, Error> {
        self.get(url, immutable, |response| Ok(response.clone()))
    }

    fn open_governor(&self) -> Result<Governor, Error> {
        #[cfg(test)]
        if let Some(path) = &self.test_governor {
            return Governor::isolated_for_test(path).map_err(|_| governor_error());
        }
        Governor::open().map_err(|_| governor_error())
    }

    fn http_client(&self) -> Result<Client, Error> {
        let builder = Client::builder()
            .user_agent("buaa-cli/0.1")
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
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10));
        #[cfg(not(test))]
        let builder = builder.https_only(true);
        #[cfg(test)]
        let builder = builder.https_only(self.test_route.is_none());
        builder.build().map_err(|_| {
            Error::new(
                "transport_unavailable",
                "cannot initialize archive transport",
            )
        })
    }

    fn check_robots(&self, target: &Url, governor: &Governor, http: &Client) -> Result<(), Error> {
        let url = Url::parse(self.profile.robots_url()).map_err(|_| invalid_url())?;
        let now = unix_ms()?;
        let cached = self.load(&url)?;
        if let Some(entry) = cached.filter(|entry| fresh_robots(&entry.response, now)) {
            return Self::robots_decision(&entry.response, target);
        }
        // Cache a valid disallow policy too; denial must not cause repeat reads.
        self.fetch(&url, false, governor, http, |response| {
            Ok(Self::robots_decision(response, target))
        })?
    }

    fn robots_decision(response: &Response, target: &Url) -> Result<(), Error> {
        match response.status {
            404 | 410 => Ok(()),
            200 => {
                let body = std::str::from_utf8(&response.body).map_err(|_| {
                    Error::new("robots_invalid", "robots policy cannot be interpreted")
                })?;
                if robotstxt::DefaultMatcher::default().one_agent_allowed_by_robots(
                    body,
                    "buaa-cli",
                    target.as_str(),
                ) {
                    Ok(())
                } else {
                    Err(Error::new(
                        "robots_denied",
                        "robots policy disallows this request",
                    ))
                }
            }
            _ => Err(Error::new(
                "robots_unavailable",
                "robots policy is unavailable",
            )),
        }
    }

    fn fetch<T>(
        &self,
        url: &Url,
        immutable: bool,
        governor: &Governor,
        http: &Client,
        process: impl FnOnce(&Response) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let lease = acquire(governor)?;
        let cached = match self.load(url) {
            Ok(value) => value,
            Err(error) => {
                lease
                    .finish(Outcome::Success)
                    .map_err(|_| governor_error())?;
                return Err(error);
            }
        };
        let request_url = self.request_url(url);
        let mut request = http.get(request_url).header("Accept-Encoding", "identity");
        if let Some(entry) = &cached {
            if let Some(etag) = &entry.etag {
                request = request.header("If-None-Match", etag);
            }
            if let Some(last_modified) = &entry.last_modified {
                request = request.header("If-Modified-Since", last_modified);
            }
        }
        let mut raw = match request.send() {
            Ok(response) => response,
            Err(_) => {
                lease
                    .finish(Outcome::NetworkFailure)
                    .map_err(|_| governor_error())?;
                return Err(network_error());
            }
        };
        let status = raw.status().as_u16();
        let retry_after = raw
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        // Cloudflare documents this header specifically as a challenge signal;
        // HTML/content-type or body keywords are not reliable challenge detectors.
        let challenge = raw
            .headers()
            .get_all("cf-mitigated")
            .iter()
            .any(|value| value.as_bytes().eq_ignore_ascii_case(b"challenge"));
        let result = (|| {
            if challenge || status == 401 || status == 403 {
                return Err(Error::new(
                    "safety_latched",
                    "public source access was rejected; explicit safety review is required",
                ));
            }
            if status == 429 {
                return Err(Error::new(
                    "cooldown",
                    "public source requested a request cooldown",
                ));
            }
            if (300..400).contains(&status) && status != 304 {
                return Err(Error::new(
                    "redirect_refused",
                    "public source redirects are not followed",
                ));
            }
            let missing_response = self.profile.allows_missing(url, status);
            if status != 200 && status != 304 && !missing_response {
                return Err(Error::new(
                    "http_rejected",
                    "public source returned an unsupported HTTP status",
                ));
            }
            for encoding in raw.headers().get_all("content-encoding") {
                if !encoding.as_bytes().eq_ignore_ascii_case(b"identity") {
                    return Err(Error::new(
                        "unsupported_encoding",
                        "public source content encoding is not supported",
                    ));
                }
            }
            if raw
                .content_length()
                .is_some_and(|length| length > MAX_BODY as u64)
            {
                return Err(body_limit());
            }
            let headers = collect_headers(raw.headers())?;
            let mut body = Vec::new();
            raw.by_ref()
                .take(MAX_BODY as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|_| network_error())?;
            if body.len() > MAX_BODY {
                return Err(body_limit());
            }
            let now = unix_ms()?;
            let mut entry = if status == 304 {
                let mut entry = cached.ok_or_else(|| {
                    Error::new(
                        "invalid_304",
                        "public source returned not-modified without a valid cached response",
                    )
                })?;
                entry.immutable |= immutable;
                entry.response.revalidated_at_unix_ms = Some(now);
                entry.response.revalidation_status = Some(status);
                update_validators(&mut entry, &headers);
                entry
            } else {
                let hash = hash(&body);
                match cached {
                    Some(mut entry) if immutable || entry.immutable => {
                        if entry.response.sha256 != hash
                            || entry.response.body != body
                            || entry.response.status != status
                            || ["memento-datetime", "link"]
                                .iter()
                                .any(|name| entry.response.headers.get(*name) != headers.get(*name))
                        {
                            return Err(Error::new(
                                "immutable_conflict",
                                "archive bytes or attribution conflict with the retained immutable capture",
                            ));
                        }
                        entry.immutable = true;
                        entry.response.revalidated_at_unix_ms = Some(now);
                        entry.response.revalidation_status = Some(status);
                        entry.etag = headers.get("etag").cloned();
                        entry.last_modified = headers.get("last-modified").cloned();
                        entry
                    }
                    previous => Entry {
                        etag: headers.get("etag").cloned(),
                        last_modified: headers.get("last-modified").cloned(),
                        immutable,
                        response: Response {
                            url: url.as_str().to_owned(),
                            status,
                            headers,
                            body,
                            sha256: hash,
                            fetched_at_unix_ms: now,
                            cache_status: if previous.is_some() {
                                CacheStatus::Revalidated
                            } else {
                                CacheStatus::Miss
                            },
                            revalidated_at_unix_ms: None,
                            revalidation_status: None,
                        },
                    },
                }
            };
            if entry.response.revalidated_at_unix_ms.is_some() {
                entry.response.cache_status = CacheStatus::Revalidated;
            }
            let response = &entry.response;
            let processed = process(response)?;
            // An unattributed replay 404/410 is an archive gap, not immutable
            // captured content. Return its facts without persisting the gap.
            if self.profile.cacheable(url, response) {
                self.save(&entry)?;
            }
            Ok(processed)
        })();
        // Preserve independent HTTP, challenge and body-failure facts in one
        // durable outcome. No synthetic status or competing backoff precedence.
        let outcome = Outcome::Http {
            status,
            retry_after: retry_after.as_deref(),
            challenge,
            network_failure: result
                .as_ref()
                .is_err_and(|error| error.code == "network_error"),
        };
        // Dropping an unread response cancels it before releasing shared ownership.
        // No early return between receiving headers and this durable finish.
        drop(raw);
        lease.finish(outcome).map_err(|_| governor_error())?;
        result
    }

    fn request_url(&self, url: &Url) -> Url {
        #[cfg(test)]
        if let Some(address) = self.test_route {
            let mut routed = url.clone();
            routed.set_scheme("http").expect("test HTTP scheme");
            routed
                .set_host(Some(&address.ip().to_string()))
                .expect("test loopback host");
            routed
                .set_port(Some(address.port()))
                .expect("test loopback port");
            return routed;
        }
        url.clone()
    }

    fn validate_directory(&self) -> Result<(), Error> {
        let metadata = self.directory.metadata().map_err(|_| cache_error())?;
        // SAFETY: geteuid has no preconditions.
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(cache_error());
        }
        Ok(())
    }

    fn load(&self, url: &Url) -> Result<Option<Entry>, Error> {
        self.validate_directory()?;
        let file = match governor::open_child(&self.directory, &cache_name(url), libc::O_RDONLY) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(cache_error()),
        };
        governor::validate_private_file(&file).map_err(|_| cache_error())?;
        let mut bytes = Vec::new();
        file.take(MAX_CACHE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| cache_error())?;
        if bytes.len() as u64 > MAX_CACHE_BYTES {
            return Err(corrupt_cache());
        }
        let cached: Cached = serde_json::from_slice(&bytes).map_err(|_| corrupt_cache())?;
        if cached.version != 1
            || cached.url != url.as_str()
            || !self.profile.valid_cached(url, &cached)
            || cached.body_base64.len() > MAX_BODY.div_ceil(3) * 4
            || cached
                .headers
                .iter()
                .any(|(key, value)| !HEADERS.contains(&key.as_str()) || !valid_header(value))
            || cached
                .headers
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum::<usize>()
                > MAX_HEADERS
            || cached
                .etag
                .as_ref()
                .is_some_and(|value| !valid_header(value))
            || cached
                .last_modified
                .as_ref()
                .is_some_and(|value| !valid_header(value))
            || cached.revalidated_at_unix_ms.is_some() != cached.revalidation_status.is_some()
            || cached
                .revalidation_status
                .is_some_and(|status| !matches!(status, 200 | 304 | 404 | 410))
        {
            return Err(corrupt_cache());
        }
        let body = STANDARD
            .decode(&cached.body_base64)
            .map_err(|_| corrupt_cache())?;
        if body.len() > MAX_BODY || hash(&body) != cached.sha256 {
            return Err(corrupt_cache());
        }
        Ok(Some(Entry {
            immutable: cached.immutable,
            etag: cached.etag,
            last_modified: cached.last_modified,
            response: Response {
                url: cached.url,
                status: cached.status,
                headers: cached.headers,
                body,
                sha256: cached.sha256,
                fetched_at_unix_ms: cached.fetched_at_unix_ms,
                cache_status: CacheStatus::Hit,
                revalidated_at_unix_ms: cached.revalidated_at_unix_ms,
                revalidation_status: cached.revalidation_status,
            },
        }))
    }

    fn save(&self, entry: &Entry) -> Result<(), Error> {
        self.validate_directory()?;
        let url = Url::parse(&entry.response.url).map_err(|_| invalid_url())?;
        let name = cache_name(&url);
        match governor::open_child(&self.directory, &name, libc::O_RDONLY) {
            Ok(existing) => {
                governor::validate_private_file(&existing).map_err(|_| cache_error())?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(cache_error()),
        }
        // Borrow metadata; only base64 expands the body, never a JSON byte array.
        #[derive(Serialize)]
        struct Stored<'a> {
            version: u8,
            url: &'a str,
            status: u16,
            headers: &'a BTreeMap<String, String>,
            body_base64: String,
            sha256: &'a str,
            fetched_at_unix_ms: u64,
            immutable: bool,
            revalidated_at_unix_ms: Option<u64>,
            revalidation_status: Option<u16>,
            etag: &'a Option<String>,
            last_modified: &'a Option<String>,
        }
        let response = &entry.response;
        let cached = Stored {
            version: 1,
            url: &response.url,
            status: response.status,
            headers: &response.headers,
            body_base64: STANDARD.encode(&response.body),
            sha256: &response.sha256,
            fetched_at_unix_ms: response.fetched_at_unix_ms,
            immutable: entry.immutable,
            revalidated_at_unix_ms: response.revalidated_at_unix_ms,
            revalidation_status: response.revalidation_status,
            etag: &entry.etag,
            last_modified: &entry.last_modified,
        };
        let (temporary_name, mut temporary) =
            governor::create_temporary(&self.directory).map_err(|_| cache_error())?;
        let result = (|| {
            governor::validate_private_file(&temporary).map_err(|_| cache_error())?;
            serde_json::to_writer(&mut temporary, &cached).map_err(|_| cache_error())?;
            temporary.write_all(b"\n").map_err(|_| cache_error())?;
            temporary.sync_all().map_err(|_| cache_error())?;
            let name = CString::new(name).map_err(|_| cache_error())?;
            // SAFETY: both names are live single components in the pinned directory.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                )
            } != 0
            {
                return Err(cache_error());
            }
            self.directory.sync_all().map_err(|_| cache_error())
        })();
        if result.is_err() {
            // SAFETY: this is our exclusively created temporary, not caller input.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
        }
        result
    }
}

pub(crate) fn acquire(governor: &Governor) -> Result<RequestLease<'_>, Error> {
    acquire_kind(governor, RequestKind::Interactive)
}

pub(crate) fn acquire_kind(
    governor: &Governor,
    kind: RequestKind,
) -> Result<RequestLease<'_>, Error> {
    let status = governor.status().map_err(|_| governor_error())?;
    if status.safety_latched {
        return Err(Error::new(
            "safety_latched",
            "shared request safety is latched",
        ));
    }
    if !status.cooldown_wait.is_zero() {
        return Err(Error::new(
            "cooldown",
            "shared request cooldown has not elapsed",
        ));
    }
    if status.request_wait > Duration::from_secs(30) {
        return Err(Error::new(
            "request_gap",
            "shared request interval exceeds the bounded wait",
        ));
    }
    if !status.request_wait.is_zero() {
        std::thread::sleep(status.request_wait);
    }
    // Exactly one attempt after at most one gap sleep. A competing owner is never
    // treated as a request gap, retried, or bypassed.
    governor.try_acquire(kind).map_err(|_| governor_error())
}

fn collect_headers(raw: &reqwest::header::HeaderMap) -> Result<BTreeMap<String, String>, Error> {
    let mut headers = BTreeMap::new();
    let mut total = 0;
    for &name in HEADERS {
        for value in raw.get_all(name) {
            let value = value.to_str().map_err(|_| {
                Error::new("invalid_headers", "archive response headers are invalid")
            })?;
            total += name.len() + value.len();
            if total > MAX_HEADERS {
                return Err(Error::new(
                    "invalid_headers",
                    "archive response headers exceed the bound",
                ));
            }
            match headers.entry(name.to_owned()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(value.to_owned());
                }
                std::collections::btree_map::Entry::Occupied(mut entry) if name == "link" => {
                    entry.get_mut().push_str(", ");
                    entry.get_mut().push_str(value);
                }
                _ => {
                    return Err(Error::new(
                        "invalid_headers",
                        "archive response has ambiguous metadata",
                    ));
                }
            }
        }
    }
    Ok(headers)
}

fn update_validators(entry: &mut Entry, headers: &BTreeMap<String, String>) {
    if let Some(value) = headers.get("etag") {
        entry.etag = Some(value.clone());
    }
    if let Some(value) = headers.get("last-modified") {
        entry.last_modified = Some(value.clone());
    }
}

fn valid_header(value: &str) -> bool {
    value.len() <= MAX_HEADERS && reqwest::header::HeaderValue::from_str(value).is_ok()
}

fn fresh_robots(response: &Response, now: u64) -> bool {
    let checked = response
        .revalidated_at_unix_ms
        .unwrap_or(response.fetched_at_unix_ms);
    now.checked_sub(checked)
        .is_some_and(|age| age < ROBOTS_MAX_AGE_MS)
}

fn unix_ms() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or_else(|| {
            Error::new(
                "clock_unavailable",
                "cannot read the archive provenance clock",
            )
        })
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn cache_name(url: &Url) -> String {
    format!("{}.json", hash(url.as_str().as_bytes()))
}
fn cache_error() -> Error {
    Error::new(
        "cache_unavailable",
        "public source cache cannot be accessed safely",
    )
}
fn corrupt_cache() -> Error {
    Error::new(
        "cache_invalid",
        "public source cache failed integrity validation",
    )
}
fn governor_error() -> Error {
    Error::new(
        "governor_denied",
        "shared request governor cannot authorize or persist this request",
    )
}
fn network_error() -> Error {
    Error::new("network_error", "public source request did not complete")
}
fn body_limit() -> Error {
    Error::new(
        "body_too_large",
        "public source response exceeds the byte bound",
    )
}
fn invalid_url() -> Error {
    Error::new(
        "egress_denied",
        "only approved HTTPS public-source routes are supported",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, DirBuilder};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const TARGET: &str = "https://web.archive.org/web/20240102030405id_/https://www.buaa.edu.cn/";

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "buaa-archive-net-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn client(&self, mode: CacheMode, server: &Server) -> ArchiveClient {
            ArchiveClient {
                mode,
                profile: SourceProfile::Archive,
                directory: governor::open_directory(&self.0.join("cache"), true, true).unwrap(),
                test_route: Some(server.address),
                test_governor: Some(self.0.join("governor")),
            }
        }

        fn organization_client(&self, mode: CacheMode, server: &Server) -> ArchiveClient {
            ArchiveClient {
                mode,
                profile: SourceProfile::Organizations,
                directory: governor::open_directory(
                    &self.0.join("organizations-cache"),
                    true,
                    true,
                )
                .unwrap(),
                test_route: Some(server.address),
                test_governor: Some(self.0.join("governor")),
            }
        }

        fn governor(&self) -> Governor {
            Governor::isolated_for_test(&self.0.join("governor")).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Server {
        address: std::net::SocketAddr,
        requests: mpsc::Receiver<(Instant, String)>,
        request_count: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl Server {
        fn new(mut handler: impl FnMut(&mut TcpStream, &str) + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let (server_requests, requests) = mpsc::channel();
            let request_count = Arc::new(AtomicUsize::new(0));
            let server_stop = Arc::clone(&stop);
            let server_count = Arc::clone(&request_count);
            let worker = thread::spawn(move || {
                while !server_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            socket
                                .set_read_timeout(Some(Duration::from_secs(5)))
                                .unwrap();
                            socket
                                .set_write_timeout(Some(Duration::from_secs(5)))
                                .unwrap();
                            let mut bytes = Vec::new();
                            let mut byte = [0];
                            while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 32 * 1024 {
                                match socket.read(&mut byte) {
                                    Ok(1) => bytes.push(byte[0]),
                                    _ => break,
                                }
                            }
                            let request = String::from_utf8(bytes).unwrap();
                            server_requests
                                .send((Instant::now(), request.clone()))
                                .unwrap();
                            server_count.fetch_add(1, Ordering::SeqCst);
                            handler(&mut socket, &request);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("loopback listener failed: {error}"),
                    }
                }
            });
            Self {
                address,
                requests,
                request_count,
                stop,
                worker: Some(worker),
            }
        }

        fn count(&self) -> usize {
            self.request_count.load(Ordering::SeqCst)
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }

    fn reply(socket: &mut TcpStream, status: u16, headers: &str, body: &[u8]) {
        let head = format!(
            "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
            body.len()
        );
        let _ = socket.write_all(head.as_bytes());
        let _ = socket.write_all(body);
    }

    fn seed(client: &ArchiveClient, url: &str, body: &[u8], immutable: bool) {
        client
            .save(&Entry {
                response: Response {
                    url: url.to_owned(),
                    status: 200,
                    headers: BTreeMap::new(),
                    body: body.to_vec(),
                    sha256: hash(body),
                    fetched_at_unix_ms: unix_ms().unwrap(),
                    cache_status: CacheStatus::Miss,
                    revalidated_at_unix_ms: None,
                    revalidation_status: None,
                },
                immutable,
                etag: None,
                last_modified: None,
            })
            .unwrap();
    }

    fn seed_robots(client: &ArchiveClient) {
        seed(client, ROBOTS_URL, b"User-agent: *\nAllow: /\n", false);
    }

    #[test]
    fn offline_and_prefer_cache_make_no_observation_or_governor_state() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _| panic!("offline operation contacted the network"));
        let mut client = fixture.client(CacheMode::Offline, &server);
        let target = Url::parse(TARGET).unwrap();
        assert_eq!(
            client.snapshot(&target, true).unwrap_err().code,
            "offline_miss"
        );
        seed(&client, TARGET, b"original bytes", true);
        for mode in [CacheMode::Offline, CacheMode::PreferCache] {
            client.mode = mode;
            let response = client.snapshot(&target, true).unwrap();
            assert_eq!(response.body, b"original bytes");
            assert_eq!(response.cache_status, CacheStatus::Hit);
        }
        for url in [
            "http://web.archive.org/web/x",
            "https://example.org/web/x",
            "https://web.archive.org:444/web/x",
            "https://u:p@web.archive.org/web/x",
            "https://web.archive.org/web/x#fragment",
            "https://web.archive.org/save/x",
        ] {
            assert_eq!(
                client
                    .snapshot(&Url::parse(url).unwrap(), false)
                    .unwrap_err()
                    .code,
                "egress_denied"
            );
        }
        assert_eq!(server.count(), 0);
        assert!(!fixture.0.join("governor").exists());
    }

    #[test]
    fn real_get_checks_robots_and_observes_the_full_shared_gap() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, request| {
            if request.starts_with("GET /robots.txt ") {
                reply(socket, 404, "", b"missing policy");
            } else {
                assert!(request.starts_with("GET /web/20240102030405id_/"));
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("accept-encoding: identity\r\n")
                );
                assert!(!request.to_ascii_lowercase().contains("cookie:"));
                reply(
                    socket,
                    200,
                    "ETag: \"first\"\r\nSet-Cookie: ignored=yes\r\n",
                    b"\0original\xff",
                );
            }
        });
        let client = fixture.client(CacheMode::PreferCache, &server);
        let target = Url::parse(TARGET).unwrap();
        let first = client.snapshot(&target, true).unwrap();
        assert_eq!(first.body, b"\0original\xff");
        assert_eq!(first.sha256, hash(b"\0original\xff"));
        assert_eq!(first.cache_status, CacheStatus::Miss);
        assert!(!first.headers.contains_key("set-cookie"));
        let again = client.snapshot(&target, true).unwrap();
        assert_eq!(again.body, first.body);
        assert_eq!(again.fetched_at_unix_ms, first.fetched_at_unix_ms);
        let requests: Vec<_> = server.requests.try_iter().collect();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].0.duration_since(requests[0].0) >= Duration::from_secs(5));
    }

    #[test]
    fn official_directory_profile_checks_robots_paces_and_caches() {
        const BODY: &[u8] = br#"<html><title>directory</title><div class='kyjg-box'><div class='kyjg-tit'><h3>A</h3></div><div class='kyjg-bd'><a href='https://one.buaa.edu.cn/'>One</a></div></div></html>"#;
        let fixture = Fixture::new();
        let server = Server::new(|socket, request| {
            assert!(!request.to_ascii_lowercase().contains("cookie:"));
            if request.starts_with("GET /robots.txt ") {
                reply(socket, 404, "Content-Type: text/plain\r\n", b"missing");
            } else {
                assert!(request.starts_with("GET /jgsz/jxkyjg02.htm "));
                reply(
                    socket,
                    200,
                    "Content-Type: text/html; charset=utf-8\r\nETag: \"directory\"\r\n",
                    BODY,
                );
            }
        });
        let client = fixture.organization_client(CacheMode::PreferCache, &server);
        let url = Url::parse(ORGANIZATIONS_URL).unwrap();
        let count = client
            .get(&url, false, |response| {
                Ok(crate::organizations::parse_html(&response.body)?
                    .entries
                    .len())
            })
            .unwrap();
        assert_eq!(count, 1);
        let requests: Vec<_> = server.requests.try_iter().collect();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].0.duration_since(requests[0].0) >= Duration::from_secs(5));
        assert_eq!(
            client.snapshot(&url, false).unwrap().cache_status,
            CacheStatus::Hit
        );
        assert_eq!(server.count(), 2);
        for denied in [
            "https://www.buaa.edu.cn/",
            "https://www.buaa.edu.cn/jgsz/jxkyjg02.htm?unexpected=1",
            "https://dept3.buaa.edu.cn/",
        ] {
            assert_eq!(
                client
                    .snapshot(&Url::parse(denied).unwrap(), false)
                    .unwrap_err()
                    .code,
                "egress_denied"
            );
        }
        assert_eq!(server.count(), 2);
    }

    #[test]
    fn robots_denial_and_server_failure_never_reach_the_target() {
        for (status, body, code) in [
            (
                200,
                "User-agent: buaa-cli\nDisallow: /web/\n",
                "robots_denied",
            ),
            (500, "unavailable", "http_rejected"),
            (403, "forbidden", "safety_latched"),
        ] {
            let fixture = Fixture::new();
            let server = Server::new(move |socket, request| {
                assert!(request.starts_with("GET /robots.txt "));
                reply(socket, status, "", body.as_bytes());
            });
            let client = fixture.client(CacheMode::PreferCache, &server);
            assert_eq!(
                client
                    .snapshot(&Url::parse(TARGET).unwrap(), true)
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(server.count(), 1);
            if status == 403 {
                assert!(fixture.governor().status().unwrap().safety_latched);
            }
        }
    }

    #[test]
    fn immutable_validation_preserves_fetch_facts_and_rejects_conflicting_bytes() {
        let fixture = Fixture::new();
        let mut request_number = 0;
        let server = Server::new(move |socket, request| {
            request_number += 1;
            let request = request.to_ascii_lowercase();
            if request_number == 1 {
                assert!(request.contains("if-none-match: \"v1\"\r\n"));
                assert!(request.contains("if-modified-since: tue, 02 jan 2024 03:04:05 gmt\r\n"));
                reply(
                    socket,
                    304,
                    "ETag: \"v2\"\r\nMemento-Datetime: Wed, 03 Jan 2024 03:04:05 GMT\r\n",
                    b"",
                );
            } else {
                assert!(request.contains("if-none-match: \"v2\"\r\n"));
                reply(
                    socket,
                    200,
                    "ETag: \"v2\"\r\n",
                    if request_number == 2 {
                        b"snapshot"
                    } else {
                        b"changed!"
                    },
                );
            }
        });
        let client = fixture.client(CacheMode::Revalidate, &server);
        seed_robots(&client);
        seed(&client, TARGET, b"snapshot", true);
        let url = Url::parse(TARGET).unwrap();
        let mut entry = client.load(&url).unwrap().unwrap();
        let original_time = entry.response.fetched_at_unix_ms;
        entry.etag = Some("\"v1\"".into());
        entry.last_modified = Some("Tue, 02 Jan 2024 03:04:05 GMT".into());
        entry
            .response
            .headers
            .insert("etag".into(), "\"v1\"".into());
        client.save(&entry).unwrap();
        for status in [304, 200] {
            let response = client.snapshot(&url, true).unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"snapshot");
            assert_eq!(response.fetched_at_unix_ms, original_time);
            assert_eq!(response.headers["etag"], "\"v1\"");
            assert!(!response.headers.contains_key("memento-datetime"));
            assert_eq!(response.revalidation_status, Some(status));
            assert!(response.revalidated_at_unix_ms.unwrap() >= original_time);
            assert_eq!(response.cache_status, CacheStatus::Revalidated);
        }
        assert_eq!(
            client.snapshot(&url, true).unwrap_err().code,
            "immutable_conflict"
        );
        let offline = fixture
            .client(CacheMode::Offline, &server)
            .snapshot(&url, true)
            .unwrap();
        assert_eq!(offline.body, b"snapshot");
        assert_eq!(offline.fetched_at_unix_ms, original_time);
        assert_eq!(server.count(), 3);
    }

    #[test]
    fn redirects_and_unbacked_304_do_not_issue_another_request() {
        for (status, headers, code) in [
            (302, "Location: /never\r\n", "redirect_refused"),
            (304, "", "invalid_304"),
            (200, "Content-Encoding: gzip\r\n", "unsupported_encoding"),
        ] {
            let fixture = Fixture::new();
            let server = Server::new(move |socket, _| reply(socket, status, headers, b""));
            let client = fixture.client(CacheMode::PreferCache, &server);
            seed_robots(&client);
            assert_eq!(
                client
                    .snapshot(&Url::parse(TARGET).unwrap(), true)
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(server.count(), 1);
            assert!(client.load(&Url::parse(TARGET).unwrap()).unwrap().is_none());
        }
    }

    #[test]
    fn body_limits_and_truncation_do_not_erase_rejection_or_cooldown() {
        for (status, headers, code, latch, cooldown, network_failure) in [
            (200, "", "network_error", false, false, true),
            (401, "", "safety_latched", true, false, false),
            (429, "Retry-After: 60\r\n", "cooldown", false, true, false),
            (
                200,
                "CF-Mitigated: challenge\r\nRetry-After: 60\r\n",
                "safety_latched",
                true,
                true,
                false,
            ),
        ] {
            let fixture = Fixture::new();
            let server = Server::new(move |socket, _| {
                // Intentionally truncated. Rejection/challenge is known before
                // any attempted body processing and must always remain durable.
                let _ = write!(
                    socket,
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: 100\r\nConnection: close\r\n{headers}\r\nx"
                );
            });
            let client = fixture.client(CacheMode::PreferCache, &server);
            seed_robots(&client);
            assert_eq!(
                client
                    .snapshot(&Url::parse(TARGET).unwrap(), true)
                    .unwrap_err()
                    .code,
                code
            );
            let state = fixture.governor().status().unwrap();
            assert_eq!(state.safety_latched, latch);
            if cooldown {
                assert!(state.cooldown_wait > Duration::from_secs(50));
            }
            assert_eq!(
                state.consecutive_network_failures,
                u32::from(network_failure)
            );
            if network_failure {
                assert!(!state.cooldown_wait.is_zero());
            }
            assert_eq!(server.count(), 1);
        }
        for declared_length in [true, false] {
            let fixture = Fixture::new();
            let server = Server::new(move |socket, _| {
                if declared_length {
                    let _ = write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                        MAX_BODY + 1
                    );
                } else {
                    let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
                    let _ = socket.write_all(&vec![b'x'; MAX_BODY + 1]);
                }
            });
            let client = fixture.client(CacheMode::PreferCache, &server);
            seed_robots(&client);
            assert_eq!(
                client
                    .snapshot(&Url::parse(TARGET).unwrap(), true)
                    .unwrap_err()
                    .code,
                "body_too_large"
            );
            assert!(client.load(&Url::parse(TARGET).unwrap()).unwrap().is_none());
        }
    }

    #[test]
    fn lease_is_exclusive_until_the_response_body_finishes() {
        let fixture = Fixture::new();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server = Server::new(move |socket, _| {
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab")
                .unwrap();
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            socket.write_all(b"cd").unwrap();
        });
        let client = fixture.client(CacheMode::PreferCache, &server);
        seed_robots(&client);
        let governor = fixture.governor();
        let worker = thread::spawn(move || client.snapshot(&Url::parse(TARGET).unwrap(), true));
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let competing = governor.try_acquire(RequestKind::Interactive);
        assert!(competing.is_err());
        assert!(governor.status().is_err());
        release_tx.send(()).unwrap();
        assert_eq!(worker.join().unwrap().unwrap().body, b"abcd");
        assert!(governor.status().is_ok());
    }

    #[test]
    fn identical_bytes_with_changed_capture_attribution_are_not_accepted() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _| {
            reply(
                socket,
                200,
                "Memento-Datetime: Wed, 03 Jan 2024 03:04:05 GMT\r\nLink: <https://www.buaa.edu.cn/>; rel=\"original\"\r\n",
                b"same bytes",
            );
        });
        let client = fixture.client(CacheMode::Revalidate, &server);
        seed_robots(&client);
        seed(&client, TARGET, b"same bytes", true);
        let url = Url::parse(TARGET).unwrap();
        let mut entry = client.load(&url).unwrap().unwrap();
        entry.response.headers.insert(
            "memento-datetime".into(),
            "Tue, 02 Jan 2024 03:04:05 GMT".into(),
        );
        entry.response.headers.insert(
            "link".into(),
            "<https://www.buaa.edu.cn/>; rel=\"original\"".into(),
        );
        client.save(&entry).unwrap();
        assert_eq!(
            client.snapshot(&url, true).unwrap_err().code,
            "immutable_conflict"
        );
        let retained = client.load(&url).unwrap().unwrap().response;
        assert_eq!(
            retained.headers["memento-datetime"],
            "Tue, 02 Jan 2024 03:04:05 GMT"
        );
        assert_eq!(retained.body, b"same bytes");
        assert_eq!(retained.revalidated_at_unix_ms, None);
    }

    #[test]
    fn stale_robots_are_rechecked_before_target_observation() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, request| {
            assert!(request.starts_with("GET /robots.txt "));
            reply(socket, 200, "", b"User-agent: *\nDisallow: /\n");
        });
        let client = fixture.client(CacheMode::PreferCache, &server);
        seed_robots(&client);
        let robots = Url::parse(ROBOTS_URL).unwrap();
        let mut entry = client.load(&robots).unwrap().unwrap();
        entry.response.fetched_at_unix_ms -= ROBOTS_MAX_AGE_MS;
        client.save(&entry).unwrap();
        assert_eq!(
            client
                .snapshot(&Url::parse(TARGET).unwrap(), true)
                .unwrap_err()
                .code,
            "robots_denied"
        );
        assert_eq!(server.count(), 1);
    }

    #[test]
    fn missing_replay_facts_are_returned_but_only_attributed_capture_is_cached() {
        for (status, headers, cached) in [
            (404, "", false),
            (
                410,
                "Memento-Datetime: Tue, 02 Jan 2024 03:04:05 GMT\r\nLink: <https://www.buaa.edu.cn/>; rel=\"original\"\r\n",
                true,
            ),
        ] {
            let fixture = Fixture::new();
            let server = Server::new(move |socket, _| reply(socket, status, headers, b"gone"));
            let client = fixture.client(CacheMode::PreferCache, &server);
            seed_robots(&client);
            let url = Url::parse(TARGET).unwrap();
            let response = client.snapshot(&url, true).unwrap();
            assert_eq!(response.status, status);
            assert_eq!(response.body, b"gone");
            assert_eq!(client.load(&url).unwrap().is_some(), cached);
            assert_eq!(server.count(), 1);
        }
    }

    #[test]
    fn cache_write_failure_cannot_waive_an_observed_retry_after() {
        let fixture = Fixture::new();
        let url = Url::parse(TARGET).unwrap();
        let target = fixture.0.join("cache").join(cache_name(&url));
        let server = Server::new(move |socket, _| {
            std::os::unix::fs::symlink("missing", &target).unwrap();
            reply(socket, 200, "Retry-After: 60\r\n", b"complete response");
        });
        let client = fixture.client(CacheMode::PreferCache, &server);
        seed_robots(&client);
        assert_eq!(
            client.snapshot(&url, true).unwrap_err().code,
            "cache_unavailable"
        );
        assert!(fixture.governor().status().unwrap().cooldown_wait > Duration::from_secs(50));
        assert_eq!(server.count(), 1);
    }

    #[test]
    fn truncated_body_preserves_network_backoff_and_retry_after_together() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _| {
            socket.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 10\r\nRetry-After: 1\r\n\r\nab").unwrap();
        });
        let client = fixture.client(CacheMode::PreferCache, &server);
        seed_robots(&client);
        assert_eq!(
            client
                .snapshot(&Url::parse(TARGET).unwrap(), true)
                .unwrap_err()
                .code,
            "network_error"
        );
        let status = fixture.governor().status().unwrap();
        assert_eq!(status.consecutive_network_failures, 1);
        assert!(status.cooldown_wait > Duration::from_secs(29));
        assert_eq!(server.count(), 1);
    }

    #[test]
    fn simultaneous_challenge_and_malformed_429_still_latch_and_cool_down() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _| {
            reply(
                socket,
                429,
                "CF-Mitigated: challenge\r\nRetry-After: invalid\r\n",
                b"",
            );
        });
        let client = fixture.client(CacheMode::PreferCache, &server);
        seed_robots(&client);
        assert_eq!(
            client
                .snapshot(&Url::parse(TARGET).unwrap(), true)
                .unwrap_err()
                .code,
            "safety_latched"
        );
        let status = fixture.governor().status().unwrap();
        assert!(status.safety_latched);
        assert!(status.cooldown_wait > Duration::from_secs(1790));
    }

    #[test]
    fn unsafe_or_tampered_cache_fails_without_network() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _| panic!("invalid cache triggered network"));
        let client = fixture.client(CacheMode::PreferCache, &server);
        let url = Url::parse(TARGET).unwrap();
        seed(&client, TARGET, b"authentic bytes", true);
        let path = fixture.0.join("cache").join(cache_name(&url));
        let link = fixture.0.join("hardlink");
        fs::hard_link(&path, &link).unwrap();
        assert_eq!(
            client.snapshot(&url, true).unwrap_err().code,
            "cache_unavailable"
        );
        fs::remove_file(&link).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            client.snapshot(&url, true).unwrap_err().code,
            "cache_unavailable"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        stored["body_base64"] = serde_json::json!(STANDARD.encode(b"tampered bytes"));
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert_eq!(
            client.snapshot(&url, true).unwrap_err().code,
            "cache_invalid"
        );
        stored["body_base64"] = serde_json::json!(STANDARD.encode(b"authentic bytes"));
        stored["url"] = serde_json::json!("https://web.archive.org/web/other");
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert_eq!(
            client.snapshot(&url, true).unwrap_err().code,
            "cache_invalid"
        );
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_CACHE_BYTES + 1)
            .unwrap();
        assert_eq!(
            client.snapshot(&url, true).unwrap_err().code,
            "cache_invalid"
        );
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&link, &path).unwrap();
        assert_eq!(
            client.snapshot(&url, true).unwrap_err().code,
            "cache_unavailable"
        );
        assert_eq!(server.count(), 0);
        assert!(!fixture.0.join("governor").exists());
    }

    #[test]
    fn rejected_capture_cannot_poison_a_later_valid_replay() {
        let fixture = Fixture::new();
        let mut responses = 0;
        let server = Server::new(move |socket, _| {
            responses += 1;
            if responses == 1 {
                reply(socket, 200, "", b"unattributed archive error page");
            } else {
                reply(
                    socket,
                    200,
                    "Memento-Datetime: Tue, 02 Jan 2024 03:04:05 GMT\r\nLink: <https://www.buaa.edu.cn/>; rel=\"original\"\r\n",
                    b"verified original bytes",
                );
            }
        });
        let mut client = fixture.client(CacheMode::PreferCache, &server);
        seed_robots(&client);
        let query = r#"{"url":"https://www.buaa.edu.cn/","timestamp":"20240102030405"}"#;
        assert_eq!(
            crate::archive::capture(query, &client).unwrap_err().code,
            "unavailable"
        );
        assert!(client.load(&Url::parse(TARGET).unwrap()).unwrap().is_none());
        client.mode = CacheMode::Revalidate;
        let accepted = crate::archive::capture(query, &client).unwrap();
        assert_eq!(accepted["result"], "capture_found");
        assert_eq!(
            accepted["immutable_original"]["sha256"],
            hash(b"verified original bytes")
        );
        client.mode = CacheMode::Offline;
        let cached = crate::archive::capture(query, &client).unwrap();
        assert_eq!(cached["immutable_original"], accepted["immutable_original"]);
        assert_eq!(cached["retrieval"]["cache_status"], "hit");
        assert_eq!(server.count(), 2);
    }
}
