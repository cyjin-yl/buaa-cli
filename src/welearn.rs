//! WE Learn course-material inventory and local practice support.
//!
//! The only source-reviewed upstream reference for this capability is the
//! community repository `Micraow/WE-Learn-Answers` (AGPL-3.0). It publishes a
//! Tampermonkey script that highlights and auto-fills answers which are
//! already embedded in WE Learn courseware pages; it publishes no courseware.
//! This module therefore never treats that repository as a material archive
//! and never copies its answers: answer-bearing entries stay visible in the
//! inventory for transparency, and their retrieval is refused.
//!
//! Courseware itself is served by the vendor hosts `welearn.sflep.com` and
//! `centercourseware.sflep.com`, the hosts the upstream script declares. Their
//! material endpoints, authorization model and redistribution terms were not
//! reviewed, so this module never requests them. That capability is
//! explicitly unsupported rather than approximated.
//!
//! Every remote read takes one shared-governor lease, holds it until the
//! response body is processed, settles it against the observed HTTP status
//! and Retry-After, and never retries. A response that cannot be normalized
//! keeps its original bytes, the observed content type, the byte count, the
//! SHA-256 and the reason, and stays re-readable offline from the private
//! response cache.
//! Retrieval uses the tree entry's immutable Git blob endpoint, never the
//! mutable branch raw URL. Complete bytes must match Git's `blob <len>\0`
//! object hash before they become rights-reviewed material; mismatches remain
//! rejected raw evidence. Active HTML challenges latch the shared governor.
//!
//! Every response body is assessed in three states. A confirmed challenge
//! latches the shared governor. An unreviewed body is refused without a
//! CAPTCHA claim and without a cache write. A clear body is admitted only
//! after the tree objects, the blob identity, the reviewed length and the
//! operator's reviewed object identity all verify.
//!
//! Local practice is offline and self-contained: it generates questions from
//! material the operator supplies, records the operator's own answers, and
//! reports a local self-check only. It never asserts an official grade, never
//! reports completion, and never answers on behalf of an assessment system.

use crate::net::Error;
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Shared read-only material transport, private response cache, degraded
/// evidence contract and local-practice primitives.
///
/// `aerospace.rs` reuses this module so that the governor lease handling, the
/// private response cache and the degraded-evidence contract exist exactly
/// once for both learning-material capabilities.
pub(crate) mod learning {
    use crate::governor::{self, Governor, Outcome};
    use crate::html::ChallengeAssessment;
    use crate::net::{self, CacheStatus, Error, Response};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use reqwest::blocking::Client;
    use serde::{Deserialize, Serialize};
    use serde_json::{Map, Value, json};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use url::Url;

    pub(crate) const MAX_INPUT: usize = 16 * 1024;
    pub(crate) const MAX_PRACTICE_INPUT: usize = 1024 * 1024;
    pub(crate) const MAX_MATERIAL_TEXT: usize = 256 * 1024;
    pub(crate) const MAX_PRACTICE_PAGE_HTML: usize = 256 * 1024;
    pub(crate) const MAX_TREE_BODY: usize = 16 * 1024 * 1024;
    pub(crate) const MAX_RAW_BODY: usize = 8 * 1024 * 1024;
    pub(crate) const MAX_CACHE_BYTES: u64 = 24 * 1024 * 1024;
    pub(crate) const MAX_HEADERS: usize = 16 * 1024;
    pub(crate) const MAX_PATH: usize = 4096;
    pub(crate) const MAX_ENTRIES: usize = 100_000;
    pub(crate) const MAX_TITLE_BYTES: usize = 512;
    pub(crate) const MAX_QUERY_BYTES: usize = 512;
    pub(crate) const MAX_QUESTIONS: usize = 200;
    pub(crate) const MAX_QUESTION_BYTES: usize = 4 * 1024;
    pub(crate) const MAX_OPTION_BYTES: usize = 2 * 1024;
    pub(crate) const MAX_OPTIONS: usize = 8;
    pub(crate) const MAX_ANSWERS: usize = 200;
    pub(crate) const MAX_ANSWER_BYTES: usize = 4 * 1024;
    pub(crate) const MAX_PROMPT_CHARS: usize = 2000;

    const CACHE_DIR: &str = ".buaa-cli-learning-materials-cache";
    const REJECT_DIR: &str = ".buaa-cli-learning-materials-rejected";
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

    // ---------------------------------------------------------------- errors

    pub(crate) fn invalid_input(message: &'static str) -> Error {
        Error::new("invalid_input", message)
    }

    pub(crate) fn authorization_required(message: &'static str) -> Error {
        Error::new("authorization_required", message)
    }

    pub(crate) fn answer_material_forbidden() -> Error {
        Error::new(
            "answer_material_forbidden",
            "answer-bearing material is never retrieved, mirrored or imported",
        )
    }

    pub(crate) fn invalid_url() -> Error {
        Error::new("invalid_url", "the pinned learning-material URL is invalid")
    }

    pub(crate) fn cache_error() -> Error {
        Error::new("cache_error", "the learning-material response cache is unavailable")
    }

    pub(crate) fn corrupt_cache() -> Error {
        Error::new("corrupt_cache", "the learning-material response cache is invalid")
    }

    pub(crate) fn governor_error() -> Error {
        Error::new(
            "governor_denied",
            "the shared request governor cannot authorize or persist this request",
        )
    }

    pub(crate) fn network_error() -> Error {
        Error::new("network_error", "the learning-material request did not complete")
    }

    pub(crate) fn body_limit() -> Error {
        Error::new("body_limit", "the learning-material response exceeded its size bound")
    }

    pub(crate) fn unexpected_content() -> Error {
        Error::new(
            "unexpected_content",
            "the learning-material response declared an unexpected content type",
        )
    }

    pub(crate) fn upstream_parse() -> Error {
        Error::new(
            "upstream_parse",
            "the learning-material response could not be normalized",
        )
    }

    fn rejected_cache() -> Error {
        Error::new("cache_error", "the learning-material rejected-evidence cache is unavailable")
    }

    pub(crate) fn incomplete_tree() -> Error {
        Error::new(
            "incomplete_tree",
            "the learning-material tree is incomplete or its object identity could not be verified",
        )
    }

    fn challenge_refusal() -> Error {
        Error::new(
            "safety_latched",
            "the learning-material response was challenged; explicit safety review is required",
        )
    }

    fn unreviewed_refusal() -> Error {
        Error::new(
            "response_safety_unreviewed",
            "the learning-material response could not be reviewed safely; it was not processed and no new cache entry was written",
        )
    }

    fn unreviewed_cache() -> Error {
        Error::new("unreviewed_cache", "learning-material cache predates session-cookie admission; original retained without reuse or automatic refetch")
    }

    fn sensitive_refusal() -> Error {
        Error::new(
            "sensitive_response_withheld",
            "the learning-material response contains private credential material; raw evidence was withheld",
        )
    }

    // ------------------------------------------------------------- primitives

    pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    pub(crate) fn valid_sha256(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    pub(crate) fn valid_upstream_sha(value: &str) -> bool {
        (value.len() == 40 || value.len() == 64)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    /// A repository-relative path: no absolute form, no empty, dot or
    /// backslash segments, and no control characters.
    pub(crate) fn valid_path(path: &str) -> bool {
        if path.is_empty() || path.len() > MAX_PATH {
            return false;
        }
        if path.starts_with('/') || path.contains('\\') || path.contains("//") {
            return false;
        }
        if path.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return false;
        }
        path.split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
    }

    pub(crate) fn unix_ms() -> Result<u64, Error> {
        let milliseconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| cache_error())?
            .as_millis();
        u64::try_from(milliseconds).map_err(|_| cache_error())
    }

    /// The content type exactly as the response declared it, lowercased and
    /// without parameters. `None` means the response declared none; it is
    /// never replaced by the type the endpoint was expected to return.
    pub(crate) fn content_type(response: &Response) -> Option<String> {
        response
            .headers
            .get("content-type")?
            .split(';')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
    }

    pub(crate) fn retrieval(response: &Response) -> Value {
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

    /// The degraded-evidence block for a reviewed, non-sensitive response: the
    /// original bytes, observed content type, byte count, SHA-256 and reason.
    /// Challenge, unreviewed and credential-bearing bodies are never exposed.
    pub(crate) fn degraded_evidence(
        surface: Surface,
        response: &Response,
        identity: &ObservedIdentity,
        reason: &str,
    ) -> Result<Value, Error> {
        let url = Url::parse(&response.url).map_err(|_| upstream_parse())?;
        let observed = content_type(response);
        let assessment = response_assessment(surface, &url, response, identity);
        if assessment == ChallengeAssessment::Detected {
            return Err(challenge_refusal());
        }
        if private_evidence(&response.body, observed.as_deref()) {
            return Err(sensitive_refusal());
        }
        if assessment == ChallengeAssessment::Unreviewed {
            return Err(unreviewed_refusal());
        }
        Ok(json!({
            "kind": "remote_response",
            "content_type": observed,
            "byte_length": response.body.len(),
            "sha256": sha256_hex(&response.body),
            "encoding": "base64",
            "data": STANDARD.encode(&response.body),
            "fallback_reason": reason
        }))
    }

    pub(crate) fn only_keys(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Error> {
        for key in object.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(invalid_input(
                    "the request carries a field that this action does not accept",
                ));
            }
        }
        Ok(())
    }

    /// The body assessment for one surface.
    ///
    /// A blob is admitted by its own immutable identity: bytes that are
    /// exactly the reviewed object are that object's source material, so a
    /// static source text that merely mentions a challenge is not a platform
    /// challenge. Bytes that are not that object are reviewed for challenge
    /// evidence and otherwise fail closed.
    ///
    /// A tree response is reviewed as the declared representation, because
    /// its content is the platform's own answer rather than repository
    /// source.
    fn surface_assessment(
        surface: Surface,
        bytes: &[u8],
        declared: Option<&str>,
        complete: bool,
        bound: bool,
    ) -> ChallengeAssessment {
        match surface {
            Surface::Tree => crate::html::assess_challenge_body(bytes, declared, complete),
            Surface::Raw => {
                if bound && complete {
                    return ChallengeAssessment::Clear;
                }
                // A body that is not the requested object is either a
                // platform challenge or an unreviewed response.
                match crate::html::assess_challenge_body(
                    bytes,
                    Some("text/html; charset=utf-8"),
                    complete,
                ) {
                    ChallengeAssessment::Detected => ChallengeAssessment::Detected,
                    _ => crate::html::assess_challenge_body(bytes, declared, complete),
                }
            }
        }
    }

    fn response_assessment(
        surface: Surface,
        url: &Url,
        response: &Response,
        identity: &ObservedIdentity,
    ) -> ChallengeAssessment {
        if response.headers.iter().any(|(name, value)| {
            net::challenge_header(name, value.as_bytes())
        }) {
            return ChallengeAssessment::Detected;
        }
        let declared = response.headers.get("content-type").map(String::as_str);
        if !declared.is_some_and(valid_content_type) {
            return ambiguous_content_assessment(&response.body, true);
        }
        let bound = matches!(surface, Surface::Raw)
            && identity.blob_sha().is_some()
            && identity.blob_sha() == requested_blob_sha(url);
        surface_assessment(surface, &response.body, declared, true, bound)
    }

    fn single_content_type(headers: &reqwest::header::HeaderMap) -> Option<&str> {
        let mut values = headers.get_all("content-type").iter();
        let value = values.next()?.to_str().ok()?;
        if values.next().is_some() || !valid_header(value) {
            return None;
        }
        valid_content_type(value).then_some(value)
    }

    fn valid_content_type(value: &str) -> bool {
        if !valid_header(value) {
            return false;
        }
        let essence = value.split(';').next().unwrap_or("").trim();
        let Some((kind, subtype)) = essence.split_once('/') else {
            return false;
        };
        let token = |part: &str| !part.is_empty() && part.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
        });
        token(kind) && token(subtype)
    }

    fn ambiguous_content_assessment(bytes: &[u8], complete: bool) -> ChallengeAssessment {
        // Unknown representation is not Clear, even if its bytes happen to
        // match a reviewed blob. Visible challenge evidence still latches.
        match crate::html::assess_challenge_body(bytes, Some("text/html"), complete) {
            ChallengeAssessment::Detected => ChallengeAssessment::Detected,
            _ => ChallengeAssessment::Unreviewed,
        }
    }

    #[cfg(test)]
    mod header_tests {
        use super::*;
        #[cfg(test)]
        use reqwest::header::{HeaderMap, HeaderValue};
        use std::net::TcpListener;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);
        static PUBLICATION_SEEN: AtomicBool = AtomicBool::new(false);

        struct TransportFixture {
            root: PathBuf,
            cache: ResponseCache,
            transport: Transport,
        }

        impl TransportFixture {
            fn new() -> Self {
                let root = std::env::temp_dir().join(format!("buaa-learning-transport-{}-{}-{}",
                    std::process::id(), unix_ms().unwrap(), NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)));
                std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
                let cache_dir = root.join("cache");
                let governor_dir = root.join("governor");
                let rejected_dir = root.join("rejected");
                std::fs::DirBuilder::new().mode(0o700).create(&cache_dir).unwrap();
                std::fs::DirBuilder::new().mode(0o700).create(&governor_dir).unwrap();
                std::fs::DirBuilder::new().mode(0o700).create(&rejected_dir).unwrap();
                Self {
                    cache: ResponseCache {
                        directory: File::open(cache_dir).unwrap(),
                        test_rejected_directory: Some(File::open(rejected_dir).unwrap()),
                        test_forbidden_operations: Some(std::cell::Cell::new(0)),
                        test_after_publication: None,
                    },
                    transport: Transport {
                        governor: Governor::isolated_for_test(&governor_dir).unwrap(),
                        http: Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
                            .retry(reqwest::retry::never()).timeout(Duration::from_secs(5)).build().unwrap(),
                    },
                    root,
                }
            }

            fn fetch(&self, url: &Url) -> Result<Value, Error> {
                self.transport.fetch(&self.cache, url, Surface::Tree, |response, identity| {
                    inventory_output(&super::super::SOURCE, super::super::TYPE_LABEL, url,
                        response, identity, &super::super::classify)
                })
            }
        }

        impl Drop for TransportFixture {
            fn drop(&mut self) { std::fs::remove_dir_all(&self.root).unwrap(); }
        }

        struct ServerWorker(Option<std::thread::JoinHandle<()>>);

        impl ServerWorker {
            fn join(mut self) {
                self.0.take().unwrap().join().unwrap();
            }
        }

        impl Drop for ServerWorker {
            fn drop(&mut self) {
                if let Some(worker) = self.0.take() {
                    let _ = worker.join();
                }
            }
        }

        fn server(response: Vec<u8>) -> (Url, ServerWorker) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = Url::parse(&format!("http://{}/tree", listener.local_addr().unwrap())).unwrap();
            let worker = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline, "loopback request was not received");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("loopback accept failed: {error}"),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).unwrap() > 0);
                stream.write_all(&response).unwrap();
            });
            (url, ServerWorker(Some(worker)))
        }

        fn http_response(status: &str, headers: &str, body: &[u8], declared_len: usize) -> Vec<u8> {
            let mut response = format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {declared_len}\r\nConnection: close\r\n\r\n").into_bytes();
            response.extend_from_slice(body);
            response
        }

        #[test]
        pub(super) fn rejected_collision() {
            for version in [1, 2] {
                let fixture = TransportFixture::new();
                let body = b"ordinary current response";
                let requested = git_blob_sha(b"different requested object", 40);
                let (mut url, worker) = server(http_response("200 OK", "Content-Type: text/plain\r\n", body, body.len()));
                url.set_path(&format!("/{requested}"));
                let old_body = b"older rejected response";
                let old = Cached { version, url: url.to_string(), status: 200,
                    headers: BTreeMap::from([("content-type".into(), "text/plain".into())]),
                    body_base64: STANDARD.encode(old_body), sha256: sha256_hex(old_body), fetched_at_unix_ms: 1 };
                let old_bytes = serde_json::to_vec(&old).unwrap();
                let path = fixture.root.join("rejected").join(ResponseCache::name(&url));
                let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
                file.write_all(&old_bytes).unwrap();
                drop(file);
                let result = fixture.transport.fetch(&fixture.cache, &url, Surface::Raw, |response, identity| {
                    assert_ne!(identity.blob_sha(), Some(requested.as_str()));
                    degraded_admission_output(&super::super::SOURCE, super::super::RAW_TYPE_LABEL,
                        "synthetic.txt", response, identity, "blob_identity_mismatch", Surface::Raw)
                });
                worker.join();
                assert_eq!(std::fs::read(&path).unwrap(), old_bytes);
                assert!(!fixture.root.join("cache").join(ResponseCache::name(&url)).exists());
                let output = result.unwrap();
                assert_eq!(output["result"], "degraded");
                assert_eq!(output["fallback_reason"], "blob_identity_mismatch");
                assert_eq!(output["bytes"], Value::Null);
                assert_eq!(output["raw_evidence"], json!({
                    "kind": "remote_response", "content_type": "text/plain", "byte_length": body.len(),
                    "sha256": sha256_hex(body), "encoding": "base64", "data": STANDARD.encode(body),
                    "fallback_reason": "blob_identity_mismatch"
                }));
                let entries: Vec<_> = std::fs::read_dir(fixture.root.join("rejected"))
                    .unwrap().map(|entry| entry.unwrap().path()).collect();
                assert_eq!(entries.len(), 2);
                let retained_path = entries.iter().find(|entry| **entry != path).unwrap();
                let retained_bytes = std::fs::read(retained_path).unwrap();
                let retained_file = File::open(retained_path).unwrap();
                governor::validate_private_file(&retained_file).unwrap();
                let retained: Cached = serde_json::from_reader(retained_file).unwrap();
                assert_eq!(retained.version, 2);
                assert_eq!(retained.url, url.as_str());
                assert_eq!(retained.status, 200);
                assert_eq!(retained.headers.get("content-type").map(String::as_str), Some("text/plain"));
                assert_eq!(serde_json::to_value(&retained.headers).unwrap(), output["retrieval"]["http"]["headers"]);
                assert_eq!(retained.fetched_at_unix_ms, output["retrieval"]["fetched_at_unix_ms"].as_u64().unwrap());
                assert_eq!(retained.sha256, sha256_hex(body));
                let retained_body = STANDARD.decode(&retained.body_base64).unwrap();
                assert_eq!(retained_body, body);
                let repeated = Response {
                    url: retained.url,
                    status: retained.status,
                    headers: retained.headers,
                    body: retained_body,
                    sha256: retained.sha256,
                    fetched_at_unix_ms: retained.fetched_at_unix_ms,
                    cache_status: CacheStatus::Miss,
                    revalidated_at_unix_ms: None,
                    revalidation_status: None,
                };
                fixture.cache.save_rejected(&repeated).unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), old_bytes);
                assert_eq!(std::fs::read(retained_path).unwrap(), retained_bytes);
                let entries: Vec<_> = std::fs::read_dir(fixture.root.join("rejected"))
                    .unwrap().map(|entry| entry.unwrap().path()).collect();
                assert_eq!(entries.len(), 3);
                for entry in entries.iter().filter(|entry| **entry != path) {
                    let mut file = File::open(entry).unwrap();
                    governor::validate_private_file(&file).unwrap();
                    let mut bytes = Vec::new();
                    file.read_to_end(&mut bytes).unwrap();
                    assert_eq!(bytes, retained_bytes);
                }
            }
        }

        #[test]
        pub(super) fn publication_reader() {
            const BODY: &[u8] = b"published synthetic response";
            fn read_published(cache: &ResponseCache, url: &Url) {
                PUBLICATION_SEEN.store(true, Ordering::Relaxed);
                let (response, admission) = cache.load(url).expect("visible cache entry must be readable").expect("published entry must exist");
                assert_eq!(response.body, BODY);
                assert_eq!(response.sha256, sha256_hex(BODY));
                assert!(matches!(admission, CacheAdmission::CookieReviewed));
                let file = governor::open_child(&cache.directory, &ResponseCache::name(url), libc::O_RDONLY).unwrap();
                governor::validate_private_file(&file).expect("published entry must remain a private single-link file");
                assert_eq!(file.metadata().unwrap().nlink(), 1);
            }
            PUBLICATION_SEEN.store(false, Ordering::Relaxed);
            let mut fixture = TransportFixture::new();
            fixture.cache.test_after_publication = Some(read_published);
            let (url, worker) = server(http_response("200 OK", "Content-Type: text/plain\r\n", BODY, BODY.len()));
            let result = fixture.fetch(&url);
            worker.join();
            assert!(result.is_ok());
            assert!(PUBLICATION_SEEN.load(Ordering::Relaxed), "the reader must observe publication before the writer returns");
        }

        #[test]
        fn transport_rejects_cookie_echo_without_output_or_cache() {
            let fixture = TransportFixture::new();
            let body = br#"{"data":"q7Z","tree":[]}"#;
            let (url, worker) = server(http_response("200 OK", "Content-Type: application/json\r\nSet-Cookie: arbitrary=q7Z; Path=/\r\n", body, body.len()));
            let result = fixture.fetch(&url);
            worker.join();
            let cache_path = fixture.root.join("cache").join(ResponseCache::name(&url));
            assert!(result.is_err(), "cookie-bearing response must not become output");
            assert!(!cache_path.exists());
            assert!(std::fs::read_dir(fixture.root.join("rejected")).unwrap().next().is_none());
            let status = fixture.transport.governor.status().unwrap();
            assert!(!status.safety_latched);
            assert_eq!(status.consecutive_network_failures, 0);
        }

        #[test]
        fn cookie_free_unparseable_tree_retains_safe_degraded_evidence() {
            let fixture = TransportFixture::new();
            let body = br#"{"data":"ordinary","tree":[]}"#;
            let (url, worker) = server(http_response("200 OK", "Content-Type: application/json\r\n", body, body.len()));
            let result = fixture.fetch(&url);
            worker.join();
            let output = result.unwrap();
            assert_eq!(output["result"], "degraded");
            assert_eq!(output["raw_evidence"]["data"], STANDARD.encode(body));
            assert!(std::fs::read_dir(fixture.root.join("rejected")).unwrap().next().is_none());
            let retained = std::fs::read(fixture.root.join("cache").join(ResponseCache::name(&url))).unwrap();
            let cached: Cached = serde_json::from_slice(&retained).unwrap();
            assert_eq!(cached.version, 2);
            assert_eq!(STANDARD.decode(cached.body_base64).unwrap(), body);
            let replay = fixture.cache.get(&url, Surface::Tree, false, |response, identity| {
                inventory_output(&super::super::SOURCE, super::super::TYPE_LABEL, &url,
                    response, identity, &super::super::classify)
            }).unwrap();
            assert_eq!(replay["result"], output["result"]);
            assert_eq!(replay["raw_evidence"], output["raw_evidence"]);
        }

        #[test]
        fn transport_preserves_rate_limit_and_challenge_read_failure_facts_with_cookies() {
            let fixture = TransportFixture::new();
            let body = br#"{"data":"q7Z"}"#;
            let (url, worker) = server(http_response("429 Too Many Requests", "Content-Type: application/json\r\nSet-Cookie: arbitrary=q7Z\r\nRetry-After: 120\r\n", body, body.len()));
            let result = fixture.fetch(&url);
            worker.join();
            assert!(result.is_err());
            let status = fixture.transport.governor.status().unwrap();
            assert!(status.cooldown_wait > Duration::from_secs(100));
            assert!(!status.safety_latched);
            assert_eq!(status.consecutive_network_failures, 0);
            assert!(!fixture.root.join("cache").join(ResponseCache::name(&url)).exists());
            assert!(std::fs::read_dir(fixture.root.join("rejected")).unwrap().next().is_none());

            let fixture = TransportFixture::new();
            let body = b"<input name=captcha>";
            let (url, worker) = server(http_response("200 OK", "Content-Type: text/html\r\nSet-Cookie: arbitrary=q7Z\r\n", body, body.len() + 20));
            let result = fixture.fetch(&url);
            worker.join();
            assert!(result.is_err());
            let status = fixture.transport.governor.status().unwrap();
            assert!(!status.safety_latched);
            assert_eq!(status.consecutive_network_failures, 1);
            assert!(!fixture.root.join("cache").join(ResponseCache::name(&url)).exists());
            assert!(std::fs::read_dir(fixture.root.join("rejected")).unwrap().next().is_none());
        }

        #[test]
        fn legacy_cache_without_cookie_admission_is_preserved_and_never_refetched() {
            let fixture = TransportFixture::new();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = Url::parse(&format!("http://{}/tree", listener.local_addr().unwrap())).unwrap();
            let body = br#"{"data":"q7Z","tree":[]}"#;
            let cached = Cached {
                version: 1, url: url.to_string(), status: 200,
                headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
                body_base64: STANDARD.encode(body), sha256: sha256_hex(body), fetched_at_unix_ms: 1,
            };
            let bytes = serde_json::to_vec(&cached).unwrap();
            let path = fixture.root.join("cache").join(ResponseCache::name(&url));
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
            file.write_all(&bytes).unwrap();
            drop(file);
            let result = fixture.fetch(&url);
            let unchanged = std::fs::read(&path).unwrap() == bytes;
            let no_connection = matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock);
            assert!(result.is_err(), "unproven legacy cache must not become output");
            assert!(unchanged);
            assert!(no_connection);
        }

        #[test]
        fn initial_legacy_cache_refuses_without_output_mutation_or_refetch() {
            let fixture = TransportFixture::new();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = Url::parse(&format!("http://{}/tree", listener.local_addr().unwrap())).unwrap();
            let body = br#"{"data":"q7Z","tree":[]}"#;
            let cached = Cached {
                version: 1, url: url.to_string(), status: 200,
                headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
                body_base64: STANDARD.encode(body), sha256: sha256_hex(body), fetched_at_unix_ms: 1,
            };
            let bytes = serde_json::to_vec(&cached).unwrap();
            let path = fixture.root.join("cache").join(ResponseCache::name(&url));
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
            file.write_all(&bytes).unwrap();
            drop(file);
            let result = fixture.cache.get(&url, Surface::Tree, true, |response, identity| {
                inventory_output(&super::super::SOURCE, super::super::TYPE_LABEL, &url,
                    response, identity, &super::super::classify)
            });
            let unchanged = std::fs::read(&path).unwrap() == bytes;
            let no_connection = matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock);
            let attempts = fixture.cache.test_forbidden_operations.as_ref().unwrap().get();
            assert!(result.is_err(), "unproven initial legacy cache must not become output");
            assert_eq!(attempts, 0,
                "initial cache handling must not attempt production governor operations or refetch");
            assert!(unchanged);
            assert!(no_connection);
        }

        #[test]
        fn duplicate_and_invalid_content_types_are_unknown() {
            let mut headers = HeaderMap::new();
            headers.append("content-type", HeaderValue::from_static("application/json"));
            assert_eq!(single_content_type(&headers), Some("application/json"));
            headers.append("content-type", HeaderValue::from_static("text/html"));
            assert_eq!(single_content_type(&headers), None);
            headers.clear();
            headers.insert("content-type", HeaderValue::from_bytes(b"\xff").unwrap());
            assert_eq!(single_content_type(&headers), None);
            headers.insert("content-type", HeaderValue::from_static("not a media type"));
            assert_eq!(single_content_type(&headers), None);
            assert_eq!(ambiguous_content_assessment(b"ordinary", true), ChallengeAssessment::Unreviewed);
            assert_eq!(ambiguous_content_assessment(b"<input name=captcha>", true), ChallengeAssessment::Detected);
        }

        #[test]
        fn retry_after_observation_preserves_all_values_and_invalidity() {
            let mut headers = HeaderMap::new();
            headers.append("retry-after", HeaderValue::from_static("5"));
            headers.append("retry-after", HeaderValue::from_static("120"));
            headers.append("retry-after", HeaderValue::from_bytes(b"\xff").unwrap());
            let observed: Vec<_> = headers.get_all("retry-after").iter()
                .map(|value| value.to_str().ok()).collect();
            assert_eq!(observed, vec![Some("5"), Some("120"), None]);
        }

        #[test]
        fn cookie_headers_and_identity_bound_blob_are_withheld() {
            for cookie in ["Set-Cookie: \r\n", "sEt-CoOkIe: a=b\r\nSet-Cookie: c=d\r\n"] {
                let fixture = TransportFixture::new();
                let body = b"ordinary raw source";
                let (mut url, worker) = server(http_response("200 OK", &format!("Content-Type: application/octet-stream\r\n{cookie}"), body, body.len()));
                url.set_path(&format!("/{}", git_blob_sha(body, 40)));
                let result = fixture.transport.fetch(&fixture.cache, &url, Surface::Raw, |_, _| -> Result<(), Error> {
                    panic!("cookie response reached consumer")
                });
                worker.join();
                assert_eq!(result.err().unwrap().code, "sensitive_response_withheld");
                assert!(!fixture.root.join("cache").join(ResponseCache::name(&url)).exists());
                assert!(std::fs::read_dir(fixture.root.join("rejected")).unwrap().next().is_none());
                let status = fixture.transport.governor.status().unwrap();
                assert!(!status.safety_latched);
                assert_eq!(status.consecutive_network_failures, 0);
            }
        }

        #[test]
        fn cache_epoch_refusal_challenge_and_collision_preserve_originals() {
            for (body, mime, challenge) in [
                (b"ordinary".as_slice(), "text/plain", false),
                (b"\xff\xfe".as_slice(), "text/html", false),
                (b"<input name=captcha>".as_slice(), "text/html", true),
            ] {
                let fixture = TransportFixture::new();
                let url = Url::parse("http://127.0.0.1:9/tree").unwrap();
                let cached = Cached { version: 1, url: url.to_string(), status: 200,
                    headers: BTreeMap::from([("content-type".into(), mime.into())]),
                    body_base64: STANDARD.encode(body), sha256: sha256_hex(body), fetched_at_unix_ms: 1 };
                let bytes = serde_json::to_vec(&cached).unwrap();
                let path = fixture.root.join("cache").join(ResponseCache::name(&url));
                let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
                file.write_all(&bytes).unwrap();
                drop(file);
                let (response, admission) = fixture.cache.load(&url).unwrap().unwrap();
                let identity = observed_identity(Surface::Tree, &url, body, Some(mime));
                let initial = review_initial_cache(Surface::Tree, &url, &response, &identity);
                if challenge {
                    assert_eq!(initial.err().unwrap().code, "safety_latched");
                    assert!(!fixture.transport.governor.status().unwrap().safety_latched);
                } else {
                    for online in [false, true] {
                        let result = fixture.cache.get(&url, Surface::Tree, online, |_, _| -> Result<(), Error> { panic!("legacy reached consumer") });
                        assert!(result.is_err());
                    }
                    assert_eq!(fixture.cache.test_forbidden_operations.as_ref().unwrap().get(), 0);
                    let lease = net::acquire(&fixture.transport.governor).unwrap();
                    let result = process_cached(Surface::Tree, &response, &identity, admission, lease, |_, _| -> Result<(), Error> { panic!("legacy reached consumer") });
                    assert!(result.is_err());
                    assert!(!fixture.transport.governor.status().unwrap().safety_latched);
                }
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
                let rejected = fixture.root.join("rejected").join(ResponseCache::name(&url));
                let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&rejected).unwrap();
                file.write_all(&bytes).unwrap();
                drop(file);
                fixture.cache.save_rejected(&response).unwrap();
                assert_eq!(std::fs::read(rejected).unwrap(), bytes);
                assert!(fixture.cache.save(&response).is_err());
                assert_eq!(std::fs::read(path).unwrap(), bytes);
            }
        }

        #[test]
        fn lease_held_legacy_challenge_latches_before_refusal() {
            let fixture = TransportFixture::new();
            let url = Url::parse("http://127.0.0.1:9/tree").unwrap();
            let body = b"<input name=captcha>";
            let cached = Cached { version: 1, url: url.to_string(), status: 200,
                headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
                body_base64: STANDARD.encode(body), sha256: sha256_hex(body), fetched_at_unix_ms: 1 };
            let bytes = serde_json::to_vec(&cached).unwrap();
            let path = fixture.root.join("cache").join(ResponseCache::name(&url));
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
            file.write_all(&bytes).unwrap();
            drop(file);
            let result = fixture.transport.fetch(&fixture.cache, &url, Surface::Tree, |_, _| -> Result<(), Error> { panic!("legacy reached consumer") });
            assert_eq!(result.err().unwrap().code, "safety_latched");
            assert!(!fixture.transport.governor.status().unwrap().safety_latched);
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }

        #[test]
        fn unsupported_or_corrupt_cache_is_not_a_miss() {
            for (version, digest) in [(3, sha256_hex(b"ordinary")), (2, "0".repeat(64))] {
                let fixture = TransportFixture::new();
                let url = Url::parse("http://127.0.0.1:9/tree").unwrap();
                let cached = Cached { version, url: url.to_string(), status: 200,
                    headers: BTreeMap::from([("content-type".into(), "text/plain".into())]),
                    body_base64: STANDARD.encode(b"ordinary"), sha256: digest, fetched_at_unix_ms: 1 };
                let bytes = serde_json::to_vec(&cached).unwrap();
                let path = fixture.root.join("cache").join(ResponseCache::name(&url));
                let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
                file.write_all(&bytes).unwrap();
                drop(file);
                for online in [false, true] {
                    assert!(fixture.cache.get(&url, Surface::Tree, online, |_, _| -> Result<(), Error> { panic!("corrupt cache reached consumer") }).is_err());
                }
                assert_eq!(fixture.cache.test_forbidden_operations.as_ref().unwrap().get(), 0);
                assert_eq!(std::fs::read(path).unwrap(), bytes);
            }
        }
    }

    /// Publish an initial cached observation without opening a request
    /// governor first. Tests inject an isolated publisher, never the user's
    /// production safety marker.
    pub(super) fn review_initial_cache(
        surface: Surface,
        url: &Url,
        response: &Response,
        identity: &ObservedIdentity,
    ) -> Result<(), Error> {
        match response_assessment(surface, url, response, identity) {
            ChallengeAssessment::Clear => Ok(()),
            ChallengeAssessment::Unreviewed => Err(unreviewed_refusal()),
            ChallengeAssessment::Detected => Err(challenge_refusal()),
        }
    }

    /// True when a body carries private credential material. Only the shape
    /// of the body is inspected: a JSON member name or an HTML form control.
    /// Values are never copied into diagnostics.
    pub(crate) fn private_evidence(bytes: &[u8], mime: Option<&str>) -> bool {
        let private_name = |name: &str| {
            let mut normalized = String::with_capacity(name.len());
            for character in name.chars() {
                if character == '_' || character == '-' {
                    continue;
                }
                normalized.push(character.to_ascii_lowercase());
            }
            matches!(
                normalized.as_str(),
                "username"
                    | "user"
                    | "login"
                    | "password"
                    | "passwd"
                    | "pwd"
                    | "credential"
                    | "credentials"
                    | "cookie"
                    | "setcookie"
                    | "authorization"
                    | "token"
                    | "accesstoken"
                    | "refreshtoken"
                    | "idtoken"
                    | "ssotoken"
                    | "clientsecret"
                    | "secret"
                    | "apikey"
                    | "ticket"
                    | "execution"
                    | "csrf"
                    | "csrftoken"
                    | "xsrftoken"
                    | "session"
                    | "sessionid"
                    | "sessionkey"
                    | "phpsessid"
                    | "castgc"
                    | "jwtuser"
                    | "jsessionid"
            )
        };

        // A JSON member name: a quoted string that is followed by a colon.
        // An escaped name cannot be normalized reliably, so it is withheld.
        let mut cursor = 0;
        while cursor < bytes.len() {
            if bytes[cursor] != b'"' {
                cursor += 1;
                continue;
            }
            let start = cursor + 1;
            cursor = start;
            let mut escaped = false;
            while cursor < bytes.len() && bytes[cursor] != b'"' {
                if bytes[cursor] == b'\\' {
                    escaped = true;
                    cursor = cursor.saturating_add(2);
                } else {
                    cursor += 1;
                }
            }
            if cursor >= bytes.len() {
                break;
            }
            let name = &bytes[start..cursor];
            cursor += 1;
            let mut rest = bytes[cursor..].iter().copied();
            let colon = rest
                .find(|byte| !byte.is_ascii_whitespace())
                .is_some_and(|byte| byte == b':');
            if !colon {
                continue;
            }
            if escaped {
                return true;
            }
            if let Ok(name) = std::str::from_utf8(name)
                && private_name(name)
            {
                return true;
            }
        }

        // An HTML form control that carries a credential by name or type.
        let html = mime.is_some_and(|mime| {
            matches!(mime, "text/html" | "application/xhtml+xml")
        }) || bytes.iter()
            .find(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|byte| *byte == b'<');
        if html {
            // Bytes that are not UTF-8 text are unreviewable, not a
            // credential claim: the assessment refuses them separately.
            let Ok(text) = std::str::from_utf8(bytes) else {
                return false;
            };
            let document = scraper::Html::parse_document(text);
            let Ok(selector) = scraper::Selector::parse("input,textarea,select,button") else {
                return true;
            };
            return document.select(&selector).any(|element| {
                let element = element.value();
                element.attr("type").is_some_and(|value| value.eq_ignore_ascii_case("password"))
                    || ["name", "id", "autocomplete"].iter().any(|attribute| {
                        element.attr(attribute).is_some_and(|value| private_name(value))
                    })
            });
        }
        false
    }

    pub(super) fn process_cached<T>(
        surface: Surface,
        response: &Response,
        identity: &ObservedIdentity,
        admission: CacheAdmission,
        lease: crate::governor::RequestLease<'_>,
        process: impl FnOnce(&Response, &ObservedIdentity) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let url = Url::parse(&response.url).map_err(|_| upstream_parse())?;
        match response_assessment(surface, &url, response, identity) {
            ChallengeAssessment::Detected => {
                lease.finish_without_request().map_err(|_| governor_error())?;
                Err(challenge_refusal())
            }
            ChallengeAssessment::Unreviewed => {
                lease.finish_without_request().map_err(|_| governor_error())?;
                Err(unreviewed_refusal())
            }
            ChallengeAssessment::Clear => {
                if matches!(admission, CacheAdmission::Legacy) {
                    lease.finish_without_request().map_err(|_| governor_error())?;
                    return Err(unreviewed_cache());
                }
                let result = process(response, identity);
                lease.finish_without_request().map_err(|_| governor_error())?;
                result
            }
        }
    }

    pub(crate) fn optional_bool(object: &Map<String, Value>, key: &str) -> Result<bool, Error> {
        match object.get(key) {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            Some(_) => Err(invalid_input("a boolean field carried a non-boolean value")),
        }
    }

    // --------------------------------------------------------------- sources

    /// A pinned, source-reviewed material host. The branch was read from the
    /// upstream repository. License provenance is emitted only against the
    /// immutable license object for the current admitted tree.
    pub(crate) struct SourceSpec {
        pub owner: &'static str,
        pub name: &'static str,
        pub branch: &'static str,
    }

    impl SourceSpec {
        pub(crate) fn blob_url(&self, sha: &str) -> Result<Url, Error> {
            if !valid_upstream_sha(sha) {
                return Err(upstream_parse());
            }
            Url::parse(&format!("https://api.github.com/repos/{}/{}/git/blobs/{sha}", self.owner, self.name))
                .map_err(|_| invalid_url())
        }
        pub(crate) fn full_name(&self) -> String {
            format!("{}/{}", self.owner, self.name)
        }

        pub(crate) fn repository_url(&self) -> String {
            format!("https://github.com/{}/{}", self.owner, self.name)
        }

        pub(crate) fn tree_url(&self) -> Result<Url, Error> {
            let mut url = Url::parse("https://api.github.com/").map_err(|_| invalid_url())?;
            url.path_segments_mut()
                .map_err(|_| invalid_url())?
                .push("repos")
                .push(self.owner)
                .push(self.name)
                .push("git")
                .push("trees")
                .push(self.branch);
            url.query_pairs_mut().append_pair("recursive", "1");
            Ok(url)
        }

    }

    /// The material class of one inventory entry. `AnswerMaterial` is never
    /// retrievable and never mirrorable; `AssessmentContent` carries question
    /// stems without answers and is never mirrorable in bulk.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum MaterialClass {
        CourseMaterial,
        Documentation,
        License,
        AnswerMaterial,
        AssessmentContent,
        SourceCode,
        Asset,
        Other,
    }

    impl MaterialClass {
        pub(crate) fn as_str(self) -> &'static str {
            match self {
                Self::CourseMaterial => "course_material",
                Self::Documentation => "documentation",
                Self::License => "license",
                Self::AnswerMaterial => "answer_material",
                Self::AssessmentContent => "assessment_content",
                Self::SourceCode => "source_code",
                Self::Asset => "asset",
                Self::Other => "other",
            }
        }

        pub(crate) fn mirror_allowed(self) -> bool {
            !matches!(self, Self::AnswerMaterial | Self::AssessmentContent)
        }

        pub(crate) fn retrieval_allowed(self) -> bool {
            !matches!(self, Self::AnswerMaterial)
        }
    }

    pub(crate) const MATERIAL_CLASSES: &[&str] = &[
        "course_material",
        "documentation",
        "license",
        "answer_material",
        "assessment_content",
        "source_code",
        "asset",
        "other",
    ];

    /// True when any path component of the repository-relative path names an
    /// answer directory. Components are compared whole, so a root-level
    /// `answers/` directory is classified exactly like a nested one.
    pub(crate) fn answer_path_component(path: &str) -> bool {
        path.split('/')
            .any(|component| {
                let component = component.to_ascii_lowercase();
                matches!(component.as_str(), "answer" | "answers" | "answerkey" | "solutions")
            })
    }

    /// A blob identity that is also listed as answer material in the same
    /// admitted tree is never retrievable, even under another path.
    pub(crate) fn blob_is_answer_material(
        entries: &[TreeEntry],
        blob_sha: &str,
        classify: &dyn Fn(&str) -> MaterialClass,
    ) -> bool {
        entries
            .iter()
            .filter(|entry| entry.sha == blob_sha)
            .any(|entry| {
                !classify(&entry.path).retrieval_allowed()
                    || answer_path_component(&entry.path)
            })
    }

    // ------------------------------------------------------------------ tree

    #[derive(Clone, Debug, Deserialize)]
    pub(crate) struct TreeEntry {
        pub path: String,
        pub mode: String,
        #[serde(rename = "type")]
        pub object_type: String,
        pub sha: String,
        pub size: Option<u64>,
    }

    impl TreeEntry {
        pub(crate) fn kind(&self) -> Option<&'static str> {
            match (self.mode.as_str(), self.object_type.as_str()) {
                ("100644" | "100755", "blob") => Some("file"),
                ("040000", "tree") => Some("directory"),
                ("120000", "blob") => Some("symlink"),
                ("160000", "commit") => Some("submodule"),
                _ => None,
            }
        }
    }

    #[derive(Deserialize)]
    struct TreeEnvelope {
        sha: String,
        tree: Vec<TreeEntry>,
        truncated: bool,
    }

    /// The JSON media types this client accepts for a tree envelope: the
    /// generic JSON type and the documented GitHub vendor JSON types. The
    /// raw-blob vendor type is a byte representation, never a JSON envelope.
    fn json_media_type(value: &str) -> bool {
        let essence = value.split(';').next().unwrap_or("").trim();
        let Some((kind, subtype)) = essence.split_once('/') else {
            return false;
        };
        if !kind.eq_ignore_ascii_case("application") {
            return false;
        }
        subtype.eq_ignore_ascii_case("json")
            || (subtype.ends_with("+json")
                && !subtype.eq_ignore_ascii_case("vnd.github.raw+json"))
    }

    pub(crate) fn parse_tree(
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<(String, bool, Vec<TreeEntry>), Error> {
        if !content_type.is_some_and(json_media_type) {
            return Err(unexpected_content());
        }
        let envelope: TreeEnvelope =
            serde_json::from_slice(body).map_err(|_| upstream_parse())?;
        if !valid_upstream_sha(&envelope.sha) || envelope.tree.len() > MAX_ENTRIES {
            return Err(upstream_parse());
        }
        let mut paths = BTreeSet::new();
        let mut entries = Vec::with_capacity(envelope.tree.len());
        for entry in envelope.tree {
            if !valid_path(&entry.path) || !valid_upstream_sha(&entry.sha) {
                return Err(upstream_parse());
            }
            let Some(kind) = entry.kind() else {
                return Err(upstream_parse());
            };
            if matches!(kind, "file" | "symlink") != entry.size.is_some() {
                return Err(upstream_parse());
            }
            if !paths.insert(entry.path.clone()) {
                return Err(upstream_parse());
            }
            entries.push(entry);
        }
        Ok((envelope.sha, envelope.truncated, entries))
    }

    /// The admitted tree: a complete, non-truncated recursive tree whose every
    /// directory object and root object hash are reconstructed and verified.
    pub(crate) fn admit_tree(
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<(String, Vec<TreeEntry>), Error> {
        let (tree_sha, truncated, entries) = parse_tree(body, content_type)?;
        if truncated {
            return Err(incomplete_tree());
        }
        verify_tree(&tree_sha, &entries)?;
        Ok((tree_sha, entries))
    }

    pub(crate) fn verify_tree(root_sha: &str, entries: &[TreeEntry]) -> Result<(), Error> {
        crate::git_tree::verify_recursive_tree(root_sha, entries.iter().map(|entry| {
            crate::git_tree::GitTreeEntry {
                path: &entry.path,
                mode: &entry.mode,
                object_type: &entry.object_type,
                sha: &entry.sha,
            }
        }))
        .map_err(|_| upstream_parse())
    }

    /// The license object a tree contains, identified by the conventional
    /// license file name rather than by any module-specific classification.
    pub(crate) fn repository_license(entries: &[TreeEntry]) -> Option<(String, u64)> {
        let entry = entries.iter().find(|entry| {
            let name = entry.path.rsplit('/').next().unwrap_or(&entry.path).to_ascii_lowercase();
            entry.kind() == Some("file")
                && (name.starts_with("license") || name.starts_with("copying"))
        })?;
        let size = entry.size?;
        Some((entry.sha.clone(), size))
    }

    /// The license object provenance for an admitted tree. A historical SPDX
    /// reference is unknown for this version until its text identity has
    /// actually been reviewed; a conventional filename is not that review.
    pub(crate) fn verified_license(
        spec: &SourceSpec,
        entries: &[TreeEntry],
    ) -> Value {
        let Some((blob_sha, size)) = repository_license(entries) else {
            return unknown_license();
        };
        json!({
            // No reviewed license text identity is pinned in SourceSpec.
            // A filename alone cannot bind the historical SPDX reference.
            "operator_reference": Value::Null,
            "bound_license_blob_sha": blob_sha,
            "bound_license_size": size,
            "bound_license_url": spec.blob_url(&blob_sha)
                .map(|url| Value::String(url.as_str().to_owned())).unwrap_or(Value::Null),
            "independently_verified": false
        })
    }

    /// The Git blob object identity of these exact bytes.
    pub(crate) fn git_blob_sha(body: &[u8], width: usize) -> String {
        let header = format!("blob {}\0", body.len());
        if width == 64 {
            let mut digest = Sha256::new();
            digest.update(header.as_bytes());
            digest.update(body);
            format!("{:x}", digest.finalize())
        } else {
            let mut digest = sha1::Sha1::new();
            digest.update(header.as_bytes());
            digest.update(body);
            format!("{:x}", digest.finalize())
        }
    }

    /// The immutable blob identity a blob URL requests.
    fn requested_blob_sha(url: &Url) -> Option<&str> {
        let segment = url.path_segments()?.next_back()?;
        (segment.len() == 40 || segment.len() == 64)
            .then_some(segment)
    }

    /// A complete, object-verified tree and the entries it is bound to.
    pub(crate) struct AdmittedTree {
        pub tree_sha: String,
        pub entries: Vec<TreeEntry>,
    }

    /// The observed identity of one response. A blob carries the Git object
    /// identity of its bytes; a tree carries the root object identity the
    /// response advertises, verified against its own entries, or the reason
    /// why the tree could not be admitted.
    pub(crate) struct ObservedIdentity {
        tree: Option<AdmittedTree>,
        tree_error: Option<&'static str>,
        blob_sha: Option<String>,
    }

    impl ObservedIdentity {
        /// The admitted tree of this response, when it is complete and every
        /// advertised tree object verifies.
        pub(crate) fn tree(&self) -> Option<&AdmittedTree> {
            self.tree.as_ref()
        }

        /// Why the tree could not be admitted, when it could not.
        pub(crate) fn tree_error(&self) -> Option<&str> {
            self.tree_error
        }

        /// The blob object identity of the response bytes, when this response
        /// is a blob whose URL names an immutable object.
        pub(crate) fn blob_sha(&self) -> Option<&str> {
            self.blob_sha.as_deref()
        }
    }

    /// Compute the observed identity of a response body exactly once.
    pub(crate) fn observed_identity(
        surface: Surface,
        url: &Url,
        body: &[u8],
        content_type: Option<&str>,
    ) -> ObservedIdentity {
        match surface {
            Surface::Tree => match admit_tree(body, content_type) {
                Ok((tree_sha, entries)) => ObservedIdentity {
                    tree: Some(AdmittedTree { tree_sha, entries }),
                    tree_error: None,
                    blob_sha: None,
                },
                Err(error) => ObservedIdentity {
                    tree: None,
                    tree_error: Some(error.code),
                    blob_sha: None,
                },
            },
            Surface::Raw => {
                let blob_sha = requested_blob_sha(url)
                    .map(|requested| git_blob_sha(body, requested.len()));
                ObservedIdentity { tree: None, tree_error: None, blob_sha }
            }
        }
    }

    /// Whether a response may be retained as reusable material. A tree
    /// response is the original inventory evidence and stays re-readable even
    /// when it cannot be normalized. A blob response is reusable material only
    /// when its bytes are exactly the immutable object its URL requests.
    fn surface_reusable(
        surface: Surface,
        url: &Url,
        identity: &ObservedIdentity,
    ) -> bool {
        match surface {
            // A tree response is the original inventory evidence. It stays
            // re-readable offline even when it cannot be normalized, and it
            // is verified again on every read, so it never becomes material
            // without a verified root object.
            Surface::Tree => true,
            Surface::Raw => match (requested_blob_sha(url), identity.blob_sha.as_deref()) {
                (Some(requested), Some(actual)) => requested == actual,
                _ => false,
            },
        }
    }

    pub(crate) fn unknown_license() -> Value {
        json!({
            "operator_reference": Value::Null,
            "bound_license_blob_sha": Value::Null,
            "bound_license_size": Value::Null,
            "bound_license_url": Value::Null,
            "independently_verified": false
        })
    }

    fn title_of(path: &str) -> String {
        let title = path.rsplit('/').next().unwrap_or(path);
        if title.chars().count() > MAX_TITLE_BYTES {
            title.chars().take(MAX_TITLE_BYTES).collect()
        } else {
            title.to_owned()
        }
    }

    pub(crate) fn inventory_entries(
        spec: &SourceSpec,
        entries: &[TreeEntry],
        all_entries: &[TreeEntry],
        classify: &dyn Fn(&str) -> MaterialClass,
        license: &Value,
    ) -> Vec<Value> {
        // A blob that is also identified as answer material anywhere in the
        // complete admitted tree must not be advertised as retrievable through
        // a benign-looking alias.
        let forbidden: BTreeSet<&str> = all_entries
            .iter()
            .filter(|entry| {
                !classify(&entry.path).retrieval_allowed()
                    || answer_path_component(&entry.path)
            })
            .map(|entry| entry.sha.as_str())
            .collect();
        let mut values = Vec::with_capacity(entries.len());
        for entry in entries {
            let class = classify(&entry.path);
            let kind = entry.kind().unwrap_or("other");
            // Only a regular file can be retrieved by this client, so the
            // inventory never advertises a retrieval that the fetch refuses,
            // and it points at the immutable object rather than a mutable
            // branch URL that could resolve to different bytes later.
            let retrievable = kind == "file"
                && class.retrieval_allowed()
                && !forbidden.contains(entry.sha.as_str());
            let url = if retrievable {
                spec.blob_url(&entry.sha)
                    .map(|url| Value::String(url.as_str().to_owned()))
                    .unwrap_or(Value::Null)
            } else {
                Value::Null
            };
            values.push(json!({
                "title": title_of(&entry.path),
                "source": spec.full_name(),
                "source_url": spec.repository_url(),
                "branch": spec.branch,
                "path": entry.path,
                "url": url,
                "size": entry.size,
                "kind": kind,
                "material_class": class.as_str(),
                "mirror_allowed": kind == "file"
                    && class.mirror_allowed()
                    && !forbidden.contains(entry.sha.as_str()),
                "retrieval_allowed": retrievable,
                "rights_review_required": true,
                "rights_reviewed": false,
                "license": license.clone(),
                "attribution": spec.full_name(),
                "upstream_sha": entry.sha
            }));
        }
        values
    }

    // -------------------------------------------------------------- transport

    #[derive(Clone, Copy)]
    pub(crate) enum Surface {
        Tree,
        Raw,
    }

    impl Surface {
        fn body_limit(self) -> usize {
            match self {
                Self::Tree => MAX_TREE_BODY,
                Self::Raw => MAX_RAW_BODY,
            }
        }

        fn accept(self) -> &'static str {
            match self {
                Self::Tree => "application/vnd.github+json",
                Self::Raw => "application/vnd.github.raw+json",
            }
        }
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
    }

    #[derive(Clone, Copy)]
    pub(super) enum CacheAdmission {
        Legacy,
        CookieReviewed,
    }

    struct ResponseCache {
        directory: File,
        #[cfg(test)]
        test_rejected_directory: Option<File>,
        #[cfg(test)]
        test_forbidden_operations: Option<std::cell::Cell<usize>>,
        #[cfg(test)]
        test_after_publication: Option<fn(&ResponseCache, &Url)>,
    }

    impl ResponseCache {
        fn open() -> Result<Self, Error> {
            let home = governor::identity_home().map_err(|_| cache_error())?;
            let _home = governor::open_directory(&home, false, false).map_err(|_| cache_error())?;
            let directory = governor::open_directory(&home.join(CACHE_DIR), true, true)
                .map_err(|_| cache_error())?;
            Ok(Self {
                directory,
                #[cfg(test)]
                test_rejected_directory: None,
                #[cfg(test)]
                test_forbidden_operations: None,
                #[cfg(test)]
                test_after_publication: None,
            })
        }

        /// The private namespace for rejected evidence. It is separate from
        /// the reusable response cache, so a wrong blob never shadows the
        /// right object for a later explicit request.
        fn rejected_directory(&self) -> Result<File, Error> {
            #[cfg(test)]
            let directory = if let Some(directory) = &self.test_rejected_directory {
                directory.try_clone().map_err(|_| rejected_cache())?
            } else {
                let home = governor::identity_home().map_err(|_| rejected_cache())?;
                governor::open_directory(&home.join(REJECT_DIR), true, true)
                    .map_err(|_| rejected_cache())?
            };
            #[cfg(not(test))]
            let directory = {
                let home = governor::identity_home().map_err(|_| rejected_cache())?;
                governor::open_directory(&home.join(REJECT_DIR), true, true)
                    .map_err(|_| rejected_cache())?
            };
            let metadata = directory.metadata().map_err(|_| rejected_cache())?;
            if !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o7777 != 0o700
            {
                return Err(rejected_cache());
            }
            Ok(directory)
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
            format!("{}.json", sha256_hex(url.as_str().as_bytes()))
        }

        fn load(&self, url: &Url) -> Result<Option<(Response, CacheAdmission)>, Error> {
            self.validate_directory()?;
            let file = match governor::open_child(&self.directory, &Self::name(url), libc::O_RDONLY)
            {
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
            if body.len() > MAX_TREE_BODY || sha256_hex(&body) != cached.sha256 {
                return Err(corrupt_cache());
            }
            let admission = if cached.version == 1 { CacheAdmission::Legacy } else { CacheAdmission::CookieReviewed };
            Ok(Some((Response {
                url: cached.url,
                status: cached.status,
                headers: cached.headers,
                body,
                sha256: cached.sha256,
                fetched_at_unix_ms: cached.fetched_at_unix_ms,
                cache_status: CacheStatus::Hit,
                revalidated_at_unix_ms: None,
                revalidation_status: None,
            }, admission)))
        }

        fn save(&self, response: &Response) -> Result<(), Error> {
            self.save_in(&self.directory, response, false)
        }

        /// Retain a rejected response as private evidence. It is never read
        /// back as a material response.
        fn save_rejected(&self, response: &Response) -> Result<(), Error> {
            let directory = self.rejected_directory()?;
            self.save_in(&directory, response, true)
        }

        fn save_in(&self, directory: &File, response: &Response, rejected: bool) -> Result<(), Error> {
            let url = Url::parse(&response.url).map_err(|_| invalid_url())?;
            let name = Self::name(&url);
            if !rejected {
                match governor::open_child(directory, &name, libc::O_RDONLY) {
                    Ok(existing) => {
                        governor::validate_private_file(&existing).map_err(|_| cache_error())?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(cache_error()),
                }
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
                governor::create_temporary(directory).map_err(|_| cache_error())?;
            let mut published = false;
            let result = (|| {
                governor::validate_private_file(&temporary).map_err(|_| cache_error())?;
                serde_json::to_writer(&mut temporary, &stored).map_err(|_| cache_error())?;
                temporary.write_all(b"\n").map_err(|_| cache_error())?;
                temporary.sync_all().map_err(|_| cache_error())?;
                // Rejected originals are not reused by URL. Give every
                // observation its own name so an earlier v1 or v2 original
                // cannot discard the current degraded output. The exclusive
                // temporary name distinguishes concurrent writers; retries
                // also handle a prior process having used the same name.
                let temporary_id = temporary_name.to_str().map_err(|_| cache_error())?;
                for attempt in 0..128 {
                    let target = if rejected {
                        format!("{name}.rejected-{temporary_id}-{attempt}")
                    } else {
                        name.clone()
                    };
                    let target = CString::new(target).map_err(|_| cache_error())?;
                    // SAFETY: both names are single components in this pinned directory.
                    // NOREPLACE keeps every old original and rename never exposes
                    // the two-link inode rejected by the private cache reader.
                    if unsafe {
                        libc::renameat2(
                            directory.as_raw_fd(),
                            temporary_name.as_ptr(),
                            directory.as_raw_fd(),
                            target.as_ptr(),
                            libc::RENAME_NOREPLACE,
                        )
                    } == 0 {
                        published = true;
                        break;
                    }
                    if !rejected || std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(cache_error());
                    }
                }
                if !published { return Err(cache_error()); }
                #[cfg(test)]
                if let Some(callback) = self.test_after_publication {
                    callback(self, &url);
                }
                directory.sync_all().map_err(|_| cache_error())
            })();
            if result.is_err() && !published {
                // SAFETY: this is our exclusively created temporary, not user input.
                unsafe {
                    libc::unlinkat(
                        directory.as_raw_fd(),
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
            process: impl FnOnce(&Response, &ObservedIdentity) -> Result<T, Error>,
        ) -> Result<T, Error> {
            if let Some((response, admission)) = self.load(url)? {
                let identity = observed_identity(
                    surface,
                    url,
                    &response.body,
                    response.headers.get("content-type").map(String::as_str),
                );
                review_initial_cache(surface, url, &response, &identity)?;
                if matches!(admission, CacheAdmission::Legacy) {
                    return Err(unreviewed_cache());
                }
                if surface_reusable(surface, url, &identity) {
                    return process(&response, &identity);
                }
                // A retained entry that does not satisfy its own immutable
                // binding is evidence, never material: it is not reused, and
                // an explicit later request may obtain the right object.
            }
            if !online {
                return Err(Error::new(
                    "offline_miss",
                    "the learning-material response is not in the local cache",
                ));
            }
            #[cfg(test)]
            if let Some(attempts) = &self.test_forbidden_operations {
                attempts.set(attempts.get() + 1);
                return Err(governor_error());
            }
            Transport::open()?.fetch(self, url, surface, process)
        }
    }

    struct Transport {
        governor: Governor,
        http: Client,
    }

    impl Transport {
        fn open() -> Result<Self, Error> {
            let governor = Governor::open().map_err(|_| governor_error())?;
            let http = Client::builder()
                .https_only(true)
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
                .user_agent("buaa-cli/0.1 learning-materials")
                .build()
                .map_err(|_| {
                    Error::new(
                        "transport_unavailable",
                        "cannot initialize the learning-material transport",
                    )
                })?;
            Ok(Self { governor, http })
        }

        /// One request, one shared-governor lease. The lease is held until the
        /// response body has been processed and is then settled against the
        /// observed status and Retry-After. No request is ever retried.
        fn fetch<T>(
            &self,
            cache: &ResponseCache,
            url: &Url,
            surface: Surface,
            process: impl FnOnce(&Response, &ObservedIdentity) -> Result<T, Error>,
        ) -> Result<T, Error> {
            let mut lease = net::acquire(&self.governor)?;
            // Another cooperating process may have populated the cache while
            // this request waited for admission. Reload before transmission.
            match cache.load(url) {
                Ok(Some((response, admission))) => {
                    let identity = observed_identity(
                        surface,
                        url,
                        &response.body,
                        response.headers.get("content-type").map(String::as_str),
                    );
                    return process_cached(surface, &response, &identity, admission, lease, process);
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
                .get(url.clone())
                // The request deadline spans connect, headers and body; the
                // blocking client timeout alone restarts on individual reads.
                .timeout(Duration::from_secs(45))
                .header("Accept-Encoding", "identity")
                .header("Accept", surface.accept());
            if matches!(surface, Surface::Tree) {
                request = request.header("X-GitHub-Api-Version", "2022-11-28");
            }
            let mut raw = match lease.start_request(|| request.send()) {
                Ok(Ok(response)) => response,
                Ok(Err(_)) => {
                    lease
                        .finish(Outcome::NetworkFailure)
                        .map_err(|_| governor_error())?;
                    return Err(network_error());
                }
                // The fence could not determine whether the request may
                // start. Drop the still-pending lease without claiming an
                // HTTP or network outcome.
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
            let declared_content_type = single_content_type(raw.headers()).map(str::to_owned);
            let issues_cookie = net::issues_session_cookie(raw.headers());
            let mut challenge = raw.headers().iter().any(|(name, value)| {
                net::challenge_header(name.as_str(), value.as_bytes())
            });
            // Whether the response body was consumed. An early refusal that
            // never read the body must not clear the shared failure history.
            let mut body_consumed = false;
            let result = (|| {
                for encoding in raw.headers().get_all("content-encoding") {
                    if !encoding.as_bytes().eq_ignore_ascii_case(b"identity") {
                        return Err(Error::new(
                            "unsupported_encoding",
                            "the learning-material content encoding is unsupported",
                        ));
                    }
                }
                let limit = surface.body_limit();
                let declared_oversize = raw
                    .content_length()
                    .is_some_and(|length| length > limit as u64);
                if declared_oversize {
                    return Err(body_limit());
                }
                let mut body = Vec::new();
                let read = raw.by_ref()
                    .take(limit as u64 + 1)
                    .read_to_end(&mut body);
                body_consumed = read.is_ok();
                let complete = read.is_ok() && !declared_oversize && body.len() <= limit;
                let identity = observed_identity(surface, url, &body, declared_content_type.as_deref());
                // The retained prefix is assessed too: an interrupted or
                // oversized body is never success, but a visible challenge
                // still has to latch the shared governor.
                let assessment = if declared_content_type.is_none() {
                    ambiguous_content_assessment(&body, complete)
                } else { surface_assessment(
                    surface,
                    &body,
                    declared_content_type.as_deref(),
                    complete,
                    matches!(surface, Surface::Raw)
                        && identity.blob_sha().is_some()
                        && identity.blob_sha() == requested_blob_sha(url),
                ) };
                challenge |= assessment == ChallengeAssessment::Detected;
                read.map_err(|_| network_error())?;
                if body.len() > limit {
                    return Err(body_limit());
                }
                classify_status(status, challenge, retry_after.as_deref(), rate_remaining.as_deref())?;
                if assessment == ChallengeAssessment::Unreviewed {
                    return Err(unreviewed_refusal());
                }
                if issues_cookie {
                    return Err(sensitive_refusal());
                }
                let headers = collect_headers(raw.headers())?;
                let response = Response {
                    url: url.as_str().to_owned(),
                    status,
                    headers,
                    sha256: sha256_hex(&body),
                    body,
                    fetched_at_unix_ms: unix_ms()?,
                    cache_status: CacheStatus::Miss,
                    revalidated_at_unix_ms: None,
                    revalidation_status: None,
                };
                match process(&response, &identity) {
                    Ok(processed) => {
                        // Only a response that still satisfies its own
                        // immutable binding is reusable material.
                        if surface_reusable(surface, url, &identity) {
                            cache.save(&response)?;
                        } else {
                            cache.save_rejected(&response)?;
                        }
                        Ok(processed)
                    }
                    // Refusals may identify confidential or unreviewable
                    // content. Only successfully admitted degraded evidence
                    // above is retained, never a safety refusal's raw bytes.
                    Err(error) => Err(error),
                }
            })();
            let network_failure = result
                .as_ref()
                .is_err_and(|error| {
                    if !body_consumed {
                        // The body was never consumed, so the response is an
                        // incomplete interaction whatever the reason.
                        return true;
                    }
                    matches!(error.code, "network_error" | "body_limit")
                });
            lease.observe_http_many(
                status,
                raw.headers().get_all("retry-after").iter().map(|value| value.to_str().ok()),
                challenge,
            ).map_err(|_| governor_error())?;
            drop(raw);
            lease
                .finish(Outcome::Http {
                    status,
                    retry_after: retry_after.as_deref(),
                    challenge,
                    network_failure,
                })
                .map_err(|_| governor_error())?;
            result
        }
    }

    fn classify_status(
        status: u16,
        challenge: bool,
        retry_after: Option<&str>,
        rate_remaining: Option<&str>,
    ) -> Result<(), Error> {
        if status == 429
            || (status == 403 && (retry_after.is_some() || rate_remaining == Some("0")))
        {
            return Err(Error::new(
                "rate_limited",
                "GitHub rate limiting or a cooldown was observed; no retry was attempted",
            ));
        }
        if challenge || matches!(status, 401 | 403) {
            return Err(Error::new(
                "safety_latched",
                "GitHub access was rejected; explicit safety review is required",
            ));
        }
        if (300..400).contains(&status) {
            return Err(Error::new(
                "redirect_refused",
                "learning-material redirects are not followed",
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

    fn collect_headers(
        headers: &reqwest::header::HeaderMap,
    ) -> Result<BTreeMap<String, String>, Error> {
        let mut collected = BTreeMap::new();
        let mut total = 0usize;
        for name in HEADER_NAMES {
            let mut values = headers.get_all(*name).iter();
            let Some(first) = values.next() else {
                continue;
            };
            let value = first.to_str().map_err(|_| unexpected_content())?;
            if !valid_header(value) {
                return Err(unexpected_content());
            }
            total += name.len() + value.len();
            if total > MAX_HEADERS {
                return Err(body_limit());
            }
            collected.insert((*name).to_owned(), value.to_owned());
        }
        Ok(collected)
    }

    // --------------------------------------------------------------- requests

    pub(crate) fn with_tree_response<T>(
        spec: &SourceSpec,
        online: bool,
        process: impl FnOnce(&Response, &ObservedIdentity) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let url = spec.tree_url()?;
        let cache = ResponseCache::open()?;
        cache.get(&url, Surface::Tree, online, process)
    }

    pub(crate) fn with_raw_response<T>(
        spec: &SourceSpec,
        blob_sha: &str,
        online: bool,
        process: impl FnOnce(&Response, &ObservedIdentity) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let url = spec.blob_url(blob_sha)?;
        let cache = ResponseCache::open()?;
        cache.get(&url, Surface::Raw, online, process)
    }

    // ---------------------------------------------------------------- output

    pub(crate) fn inventory_output(
        spec: &SourceSpec,
        type_label: &str,
        expected: &Url,
        response: &Response,
        identity: &ObservedIdentity,
        classify: &dyn Fn(&str) -> MaterialClass,
    ) -> Result<Value, Error> {
        if response.url != expected.as_str() || response.status != 200 {
            return Err(Error::new(
                "http_rejected",
                "the learning-material inventory provenance does not match the requested tree",
            ));
        }
        if response.body.len() > MAX_TREE_BODY {
            return Err(body_limit());
        }
        let mut output = json!({
            "schema_version": 1,
            "type": type_label,
            "result": Value::Null,
            "source": spec.full_name(),
            "source_url": spec.repository_url(),
            "branch": spec.branch,
            "license": unknown_license(),
            "attribution": spec.full_name(),
            "rights_reviewed": false,
            "tree_sha": Value::Null,
            "truncated": Value::Null,
            "complete": false,
            "next_cursor": Value::Null,
            "entries": Value::Null,
            "entry_count": 0,
            "fallback_reason": Value::Null,
            "raw_evidence": Value::Null,
            "retrieval": retrieval(response)
        });
        match identity.tree() {
            Some(admitted) => {
                let tree_sha = admitted.tree_sha.as_str();
                let entries = admitted.entries.as_slice();
                let license = verified_license(spec, entries);
                let values = inventory_entries(spec, entries, entries, classify, &license);
                output["result"] = json!("inventory_snapshot");
                output["tree_sha"] = json!(tree_sha);
                output["truncated"] = json!(false);
                output["complete"] = json!(true);
                output["entries"] = json!(values.clone());
                output["entry_count"] = json!(values.len());
                output["license"] = license;
                Ok(output)
            }
            None => {
                let reason = identity.tree_error().unwrap_or("upstream_parse");
                output["result"] = json!("degraded");
                output["entries"] = json!([]);
                output["fallback_reason"] = json!(reason);
                output["raw_evidence"] = degraded_evidence(Surface::Tree, response, identity, reason)?;
                Ok(output)
            }
        }
    }

    pub(crate) fn search_output(
        spec: &SourceSpec,
        type_label: &str,
        expected: &Url,
        response: &Response,
        identity: &ObservedIdentity,
        query: &str,
        classify: &dyn Fn(&str) -> MaterialClass,
    ) -> Result<Value, Error> {
        if response.url != expected.as_str() || response.status != 200 {
            return Err(Error::new(
                "http_rejected",
                "the learning-material search provenance does not match the requested tree",
            ));
        }
        if response.body.len() > MAX_TREE_BODY {
            return Err(body_limit());
        }
        let needle = query.to_lowercase();
        let mut output = json!({
            "schema_version": 1,
            "type": type_label,
            "result": Value::Null,
            "query": query,
            "rights_reviewed": true,
            "source": spec.full_name(),
            "source_url": spec.repository_url(),
            "branch": spec.branch,
            "license": unknown_license(),
            "attribution": spec.full_name(),
            "tree_sha": Value::Null,
            "truncated": Value::Null,
            "complete": false,
            "next_cursor": Value::Null,
            "matches": Value::Null,
            "match_count": 0,
            "fallback_reason": Value::Null,
            "raw_evidence": Value::Null,
            "retrieval": retrieval(response)
        });
        match identity.tree() {
            Some(admitted) => {
                let tree_sha = admitted.tree_sha.as_str();
                let entries = admitted.entries.as_slice();
                let mut matched: Vec<TreeEntry> = Vec::new();
                for entry in entries {
                    let title = title_of(&entry.path);
                    if entry.path.to_lowercase().contains(&needle)
                        || title.to_lowercase().contains(&needle)
                    {
                        matched.push(entry.clone());
                    }
                }
                let license = verified_license(spec, entries);
                let values = inventory_entries(spec, &matched, entries, classify, &license);
                output["result"] = json!("search_snapshot");
                output["tree_sha"] = json!(tree_sha);
                output["truncated"] = json!(false);
                output["complete"] = json!(true);
                output["matches"] = json!(values.clone());
                output["match_count"] = json!(values.len());
                output["license"] = license;
                Ok(output)
            }
            None => {
                let reason = identity.tree_error().unwrap_or("upstream_parse");
                output["result"] = json!("degraded");
                output["matches"] = json!([]);
                output["fallback_reason"] = json!(reason);
                output["raw_evidence"] = degraded_evidence(Surface::Tree, response, identity, reason)?;
                Ok(output)
            }
        }
    }

    pub(crate) fn verified_blob_output(
        spec: &SourceSpec,
        type_label: &str,
        path: &str,
        response: &Response,
        identity: &ObservedIdentity,
        class: MaterialClass,
        tree_sha: &str,
        blob_sha: &str,
        license: &Value,
        expected_size: u64,
    ) -> Result<Value, Error> {
        let expected = spec.blob_url(blob_sha)?;
        if response.url != expected.as_str() || response.status != 200 || response.body.len() > MAX_RAW_BODY {
            return Err(upstream_parse());
        }
        if identity.blob_sha() != Some(blob_sha) {
            // The bytes are not the admitted object. They are reported as
            // rejected evidence and never admitted or reused as material.
            return degraded_admission_output(
                spec,
                type_label,
                path,
                response,
                identity,
                "blob_identity_mismatch",
                Surface::Raw,
            );
        }
        if response.body.len() as u64 != expected_size {
            // The reviewed length contradicts the retrieved bytes, so the
            // bytes are rejected evidence rather than material.
            return degraded_admission_output(
                spec,
                type_label,
                path,
                response,
                identity,
                "blob_size_mismatch",
                Surface::Raw,
            );
        }
        let mut output = raw_output_at(
            spec,
            type_label,
            path,
            response,
            identity,
            class,
            &expected,
            license,
        )?;
        output["retrieval"]["admitted_tree_sha"] = json!(tree_sha);
        output["retrieval"]["verified_git_blob_sha"] = json!(blob_sha);
        Ok(output)
    }

    fn raw_output_at(
        spec: &SourceSpec,
        type_label: &str,
        path: &str,
        response: &Response,
        identity: &ObservedIdentity,
        class: MaterialClass,
        expected: &Url,
        license: &Value,
    ) -> Result<Value, Error> {
        if response.url != expected.as_str() || response.status != 200 {
            return Err(Error::new(
                "http_rejected",
                "the learning-material bytes provenance does not match the requested path",
            ));
        }
        if response.body.len() > MAX_RAW_BODY {
            return Err(body_limit());
        }
        let observed = content_type(response);
        let mut output = json!({
            "schema_version": 1,
            "type": type_label,
            "result": Value::Null,
            "path": path,
            "source": spec.full_name(),
            "source_url": spec.repository_url(),
            "branch": spec.branch,
            "license": license.clone(),
            "attribution": spec.full_name(),
            "rights_reviewed": true,
            "material_class": class.as_str(),
            "bytes": Value::Null,
            "byte_encoding": "base64",
            "byte_length": Value::Null,
            "sha256": Value::Null,
            "content_type": Value::Null,
            "fallback_reason": Value::Null,
            "raw_evidence": Value::Null,
            "retrieval": retrieval(response)
        });
        match observed.as_deref() {
            Some(value) if raw_content_type_allowed(value) => {
                output["result"] = json!("raw_snapshot");
                output["bytes"] = json!(STANDARD.encode(&response.body));
                output["byte_length"] = json!(response.body.len());
                output["sha256"] = json!(response.sha256);
                output["content_type"] = json!(value);
                Ok(output)
            }
            _ => {
                let reason = if observed.is_some() {
                    "unexpected_content"
                } else {
                    "missing_content_type"
                };
                output["result"] = json!("degraded");
                output["fallback_reason"] = json!(reason);
                output["raw_evidence"] =
                    degraded_evidence(Surface::Raw, response, identity, reason)?;
                Ok(output)
            }
        }
    }

    /// The fail-closed output for a fetch whose material class could not be
    /// resolved from the reviewed inventory. No bytes are returned; the
    /// original inventory response is preserved as degraded evidence.
    pub(crate) fn degraded_admission_output(
        spec: &SourceSpec,
        type_label: &str,
        path: &str,
        response: &Response,
        identity: &ObservedIdentity,
        reason: &str,
        surface: Surface,
    ) -> Result<Value, Error> {
        let evidence = degraded_evidence(surface, response, identity, reason)?;
        Ok(json!({
            "schema_version": 1,
            "type": type_label,
            "result": "degraded",
            "path": path,
            "source": spec.full_name(),
            "source_url": spec.repository_url(),
            "branch": spec.branch,
            "license": unknown_license(),
            "attribution": spec.full_name(),
            "rights_reviewed": true,
            "material_class": Value::Null,
            "bytes": Value::Null,
            "byte_encoding": "base64",
            "byte_length": Value::Null,
            "sha256": Value::Null,
            "content_type": Value::Null,
            "fallback_reason": reason,
            "raw_evidence": evidence,
            "retrieval": retrieval(response)
        }))
    }

    pub(crate) fn raw_content_type_allowed(value: &str) -> bool {
        matches!(
            value,
            "application/octet-stream"
                | "application/vnd.github.raw+json"
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
                | "application/sqlite3"
                | "application/vnd.sqlite3"
                | "text/plain"
                | "text/markdown"
                | "text/csv"
                | "text/html"
                | "application/javascript"
                | "text/javascript"
                | "application/json"
                | "image/png"
                | "image/jpeg"
                | "image/gif"
                | "image/webp"
        )
    }

    // --------------------------------------------------------------- schemas

    pub(crate) fn license_schema() -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["operator_reference","bound_license_blob_sha","bound_license_size","bound_license_url","independently_verified"],
            "properties":{
                "operator_reference":{"type":["object","null"],"additionalProperties":false,
                    "required":["spdx_id","name"],
                    "properties":{
                        "spdx_id":{"type":"string","minLength":1,"description":"The operator-reviewed upstream reference identifier. It is an attestation, not an independent rights proof."},
                        "name":{"type":"string","minLength":1}
                    },
                    "description":"The operator's reviewed upstream license reference; null when no reference is bound to the admitted snapshot."},
                "bound_license_blob_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"The immutable license blob the admitted tree contains; null when the tree contains no license object."},
                "bound_license_size":{"type":["integer","null"],"minimum":0},
                "bound_license_url":{"type":["string","null"],"description":"The immutable license object URL; never a mutable branch URL."},
                "independently_verified":{"const":false,"description":"Always false: this module never verifies license text against the admitted snapshot."}
            }
        })
    }

    pub(crate) fn retrieval_schema() -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["source_url","fetched_at_unix_ms","cache_status","revalidated_at_unix_ms","revalidation_status","response_body_sha256","response_body_byte_length","http"],
            "properties":{
                "source_url":{"type":"string"},
                "admitted_tree_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
                "verified_git_blob_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
                "fetched_at_unix_ms":{"type":"integer","minimum":0},
                "cache_status":{"enum":["hit","miss"]},
                "revalidated_at_unix_ms":{"type":"null"},
                "revalidation_status":{"type":"null"},
                "response_body_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                "response_body_byte_length":{"type":"integer","minimum":0,"maximum":MAX_TREE_BODY},
                "http":{"type":"object","additionalProperties":false,
                    "required":["status","headers"],
                    "properties":{"status":{"const":200},"headers":{"type":"object"}}
                }
            }
        })
    }

    pub(crate) fn evidence_schema() -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["kind","content_type","byte_length","sha256","encoding","data","fallback_reason"],
            "properties":{
                "kind":{"const":"remote_response"},
                "content_type":{"type":["string","null"],"description":"The content type the response actually declared; null when it declared none."},
                "byte_length":{"type":"integer","minimum":0},
                "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                "encoding":{"const":"base64"},
                "data":{"type":"string","contentEncoding":"base64"},
                "fallback_reason":{"type":"string","minLength":1}
            }
        })
    }

    pub(crate) fn entry_schema() -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["title","source","source_url","branch","path","url","size","kind","material_class","mirror_allowed","retrieval_allowed","rights_review_required","rights_reviewed","license","attribution","upstream_sha"],
            "properties":{
                "title":{"type":"string","minLength":1,"maxLength":MAX_TITLE_BYTES},
                "source":{"type":"string","minLength":1},
                "source_url":{"type":"string","minLength":1},
                "branch":{"type":"string","minLength":1},
                "path":{"type":"string","minLength":1,"maxLength":MAX_PATH},
                "url":{"type":["string","null"],"description":"The immutable blob object URL for a regular file entry; null for entries this client cannot retrieve."},
                "size":{"type":["integer","null"],"minimum":0},
                "kind":{"enum":["file","directory","symlink","submodule"]},
                "material_class":{"enum":MATERIAL_CLASSES},
                "mirror_allowed":{"type":"boolean","description":"False for answer-bearing and assessment material; this module implements no bulk mirror operation at all."},
                "retrieval_allowed":{"type":"boolean","description":"False for answer-bearing material, whose bytes are never retrieved."},
                "rights_review_required":{"const":true},
                "rights_reviewed":{"const":false},
                "license":license_schema(),
                "attribution":{"type":"string","minLength":1},
                "upstream_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"}
            }
        })
    }

    fn fallback_reasons() -> Value {
        json!([
            "unexpected_content",
            "missing_content_type",
            "upstream_parse",
            "incomplete_tree",
            "blob_identity_mismatch",
            "blob_size_mismatch",
            null
        ])
    }

    pub(crate) fn inventory_schema(type_label: &str) -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["schema_version","type","result","source","source_url","branch","license","attribution","rights_reviewed","tree_sha","truncated","complete","next_cursor","entries","entry_count","fallback_reason","raw_evidence","retrieval"],
            "properties":{
                "schema_version":{"const":1},
                "type":{"const":type_label},
                "result":{"enum":["inventory_snapshot","degraded"]},
                "source":{"type":"string","minLength":1},
                "source_url":{"type":"string","minLength":1},
                "branch":{"type":"string","minLength":1},
                "license":license_schema(),
                "attribution":{"type":"string","minLength":1},
                "rights_reviewed":{"const":false},
                "tree_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"The verified root tree object identity; null only in the degraded variant."},
                "truncated":{"type":["boolean","null"]},
                "complete":{"type":"boolean"},
                "next_cursor":{"type":"null","description":"The recursive tree response supplies no continuation cursor; a truncated tree is refused rather than reported as a partial inventory."},
                "entries":{"type":"array","maxItems":MAX_ENTRIES,"items":entry_schema()},
                "entry_count":{"type":"integer","minimum":0},
                "fallback_reason":{"type":["string","null"],"enum":fallback_reasons()},
                "raw_evidence":{"oneOf":[{"type":"null"},evidence_schema()]},
                "retrieval":retrieval_schema()
            },
            "oneOf":[
                {"properties":{
                    "result":{"const":"inventory_snapshot"},
                    "fallback_reason":{"type":"null"},
                    "raw_evidence":{"type":"null"},
                    "tree_sha":{"type":"string"},
                    "truncated":{"type":"boolean"},
                    "entries":{"type":"array"}
                }},
                {"properties":{
                    "result":{"const":"degraded"},
                    "fallback_reason":{"type":"string"},
                    "raw_evidence":{"type":"object"},
                    "tree_sha":{"type":"null"},
                    "truncated":{"type":"null"},
                    "entries":{"type":"array","maxItems":0}
                }}
            ]
        })
    }

    pub(crate) fn search_schema(type_label: &str) -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["schema_version","type","result","query","rights_reviewed","source","source_url","branch","license","attribution","tree_sha","truncated","complete","next_cursor","matches","match_count","fallback_reason","raw_evidence","retrieval"],
            "properties":{
                "schema_version":{"const":1},
                "type":{"const":type_label},
                "result":{"enum":["search_snapshot","degraded"]},
                "query":{"type":"string","minLength":1,"maxLength":MAX_QUERY_BYTES},
                "rights_reviewed":{"const":true},
                "source":{"type":"string","minLength":1},
                "source_url":{"type":"string","minLength":1},
                "branch":{"type":"string","minLength":1},
                "license":license_schema(),
                "attribution":{"type":"string","minLength":1},
                "tree_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
                "truncated":{"type":["boolean","null"]},
                "complete":{"type":"boolean"},
                "next_cursor":{"type":"null"},
                "matches":{"type":"array","maxItems":MAX_ENTRIES,"items":entry_schema()},
                "match_count":{"type":"integer","minimum":0},
                "fallback_reason":{"type":["string","null"],"enum":fallback_reasons()},
                "raw_evidence":{"oneOf":[{"type":"null"},evidence_schema()]},
                "retrieval":retrieval_schema()
            },
            "oneOf":[
                {"properties":{
                    "result":{"const":"search_snapshot"},
                    "fallback_reason":{"type":"null"},
                    "raw_evidence":{"type":"null"},
                    "tree_sha":{"type":"string"},
                    "truncated":{"type":"boolean"},
                    "matches":{"type":"array"}
                }},
                {"properties":{
                    "result":{"const":"degraded"},
                    "fallback_reason":{"type":"string"},
                    "raw_evidence":{"type":"object"},
                    "tree_sha":{"type":"null"},
                    "truncated":{"type":"null"},
                    "matches":{"type":"array","maxItems":0}
                }}
            ]
        })
    }

    pub(crate) fn raw_schema(type_label: &str) -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["schema_version","type","result","path","source","source_url","branch","license","attribution","rights_reviewed","material_class","bytes","byte_encoding","byte_length","sha256","content_type","fallback_reason","raw_evidence","retrieval"],
            "properties":{
                "schema_version":{"const":1},
                "type":{"const":type_label},
                "result":{"enum":["raw_snapshot","degraded"]},
                "path":{"type":"string","minLength":1,"maxLength":MAX_PATH},
                "source":{"type":"string","minLength":1},
                "source_url":{"type":"string","minLength":1},
                "branch":{"type":"string","minLength":1},
                "license":license_schema(),
                "attribution":{"type":"string","minLength":1},
                "rights_reviewed":{"const":true},
                "material_class":{"type":["string","null"],"enum":["course_material","documentation","license","answer_material","assessment_content","source_code","asset","other",null]},
                "bytes":{"type":["string","null"],"contentEncoding":"base64"},
                "byte_encoding":{"const":"base64"},
                "byte_length":{"type":["integer","null"],"minimum":0},
                "sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"},
                "content_type":{"type":["string","null"],"description":"Null in the degraded variant; the observed value is inside raw_evidence.content_type."},
                "fallback_reason":{"type":["string","null"],"enum":fallback_reasons()},
                "raw_evidence":{"oneOf":[{"type":"null"},evidence_schema()]},
                "retrieval":retrieval_schema()
            },
            "oneOf":[
                {"properties":{
                    "result":{"const":"raw_snapshot"},
                    "material_class":{"type":"string"},
                    "bytes":{"type":"string"},
                    "byte_length":{"type":"integer"},
                    "sha256":{"type":"string"},
                    "content_type":{"type":"string"},
                    "fallback_reason":{"type":"null"},
                    "raw_evidence":{"type":"null"}
                }},
                {"properties":{
                    "result":{"const":"degraded"},
                    "bytes":{"type":"null"},
                    "byte_length":{"type":"null"},
                    "sha256":{"type":"null"},
                    "content_type":{"type":"null"},
                    "fallback_reason":{"type":"string"},
                    "raw_evidence":{"type":"object"}
                }}
            ]
        })
    }

    // -------------------------------------------------------------- practice

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct PracticeQuestion {
        pub question_id: String,
        pub kind: String,
        pub prompt: String,
        pub options: Option<Vec<String>>,
        pub blanks: Option<Vec<String>>,
        pub chapter: Option<i64>,
        pub question_type: Option<i64>,
        pub local_self_check_key: Option<Vec<String>>,
        pub key_source: String,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RecordedAnswer {
        pub question_id: String,
        pub text: Option<String>,
        pub choices: Option<Vec<String>>,
        pub recorded_at_unix_ms: u64,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct AnswerInput {
        pub question_id: String,
        pub text: Option<String>,
        pub choices: Option<Vec<String>>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct PracticeSession {
        pub schema_version: u8,
        #[serde(rename = "type")]
        pub type_label: String,
        pub result: String,
        pub session_id: String,
        pub authority: String,
        pub official_grade: Option<Value>,
        pub official_result: Option<Value>,
        pub submission_state: String,
        pub completion_reported: bool,
        pub rights_reviewed: bool,
        pub practice_source: Value,
        pub questions: Vec<PracticeQuestion>,
        pub answers: Vec<RecordedAnswer>,
        pub results: Option<Value>,
    }

    pub(crate) fn new_session(
        type_label: &str,
        practice_source: Value,
        questions: Vec<PracticeQuestion>,
        rights_reviewed: bool,
    ) -> Result<PracticeSession, Error> {
        if questions.is_empty() || questions.len() > MAX_QUESTIONS {
            return Err(invalid_input(
                "a practice set must hold between 1 and 200 questions",
            ));
        }
        let serialized = serde_json::to_string(&questions)
            .map_err(|_| invalid_input("the practice set is not serializable"))?;
        let session_id = sha256_hex(serialized.as_bytes());
        Ok(PracticeSession {
            schema_version: 1,
            type_label: type_label.to_owned(),
            result: "practice_session".to_owned(),
            session_id,
            authority: "local_only".to_owned(),
            official_grade: None,
            official_result: None,
            submission_state: "not_submitted".to_owned(),
            completion_reported: false,
            rights_reviewed,
            practice_source,
            questions,
            answers: Vec::new(),
            results: None,
        })
    }

    fn validate_session(session: &PracticeSession, type_label: &str) -> Result<(), Error> {
        if session.schema_version != 1
            || session.type_label != type_label
            || session.result != "practice_session"
            || session.authority != "local_only"
            || session.official_grade.is_some()
            || session.official_result.is_some()
            || session.submission_state != "not_submitted"
            || session.completion_reported
            || session.questions.is_empty()
            || session.questions.len() > MAX_QUESTIONS
            || session.answers.len() > MAX_ANSWERS
            || !valid_sha256(&session.session_id)
        {
            return Err(invalid_input(
                "the practice session does not satisfy the local-only session contract",
            ));
        }
        let mut identifiers = BTreeSet::new();
        for question in &session.questions {
            if question.question_id.is_empty()
                || question.prompt.chars().count() > MAX_PROMPT_CHARS
                || !identifiers.insert(question.question_id.clone())
            {
                return Err(invalid_input("the practice session carries an invalid question"));
            }
            match question.kind.as_str() {
                "cloze" | "choice" | "fill" | "other" => {}
                _ => {
                    return Err(invalid_input(
                        "the practice session carries an unknown question kind",
                    ));
                }
            }
            if let Some(options) = &question.options {
                if options.is_empty() || options.len() > MAX_OPTIONS {
                    return Err(invalid_input(
                        "a practice question carries an invalid option list",
                    ));
                }
            }
            if question.key_source != "local_material"
                && question.key_source != "operator_supplied"
                && question.key_source != "none"
            {
                return Err(invalid_input(
                    "a practice question carries an unknown key source",
                ));
            }
            if question.key_source == "none" && question.local_self_check_key.is_some() {
                return Err(invalid_input(
                    "a practice question carries a key without a key source",
                ));
            }
        }
        for answer in &session.answers {
            if !identifiers.contains(&answer.question_id) {
                return Err(invalid_input(
                    "a recorded answer refers to an unknown question",
                ));
            }
        }
        Ok(())
    }

    fn normalize_text(value: &str) -> String {
        value
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    }

    fn normalize_answer(
        question: &PracticeQuestion,
        answer: &AnswerInput,
    ) -> Result<RecordedAnswer, Error> {
        let recorded_at_unix_ms = unix_ms()?;
        if question.kind == "choice" {
            if answer.text.is_some() {
                return Err(invalid_input("a choice answer must not carry free text"));
            }
            let choices = answer
                .choices
                .as_ref()
                .ok_or_else(|| invalid_input("a choice answer requires the selected option letters"))?;
            if choices.is_empty() || choices.len() > MAX_OPTIONS {
                return Err(invalid_input("a choice answer must select 1 to 8 options"));
            }
            let available = question
                .options
                .as_ref()
                .map(|options| options.len())
                .unwrap_or(0);
            let mut normalized: Vec<String> = Vec::with_capacity(choices.len());
            for choice in choices {
                let letter = choice.trim().to_ascii_uppercase();
                let bytes = letter.as_bytes();
                if bytes.len() != 1 || !bytes[0].is_ascii_uppercase() {
                    return Err(invalid_input(
                        "an option letter must be a single A-Z character",
                    ));
                }
                let index = usize::from(bytes[0] - b'A');
                if index >= available {
                    return Err(invalid_input(
                        "an option letter is outside the options of this question",
                    ));
                }
                if normalized.contains(&letter) {
                    return Err(invalid_input("an option letter is repeated"));
                }
                normalized.push(letter);
            }
            normalized.sort();
            return Ok(RecordedAnswer {
                question_id: answer.question_id.clone(),
                text: None,
                choices: Some(normalized),
                recorded_at_unix_ms,
            });
        }
        if answer.choices.is_some() {
            return Err(invalid_input(
                "a written answer must not carry option letters",
            ));
        }
        let text = answer
            .text
            .as_ref()
            .ok_or_else(|| invalid_input("a written answer requires the answer text"))?;
        if text.trim().is_empty() || text.len() > MAX_ANSWER_BYTES {
            return Err(invalid_input("a written answer must hold 1 to 4096 bytes"));
        }
        Ok(RecordedAnswer {
            question_id: answer.question_id.clone(),
            text: Some(text.clone()),
            choices: None,
            recorded_at_unix_ms,
        })
    }

    pub(crate) fn record_answers(
        session: &PracticeSession,
        type_label: &str,
        answers: &[AnswerInput],
    ) -> Result<PracticeSession, Error> {
        validate_session(session, type_label)?;
        if answers.is_empty() || answers.len() > MAX_ANSWERS {
            return Err(invalid_input("between 1 and 200 answers are required"));
        }
        let mut updated = session.clone();
        updated.results = None;
        for answer in answers {
            let question = session
                .questions
                .iter()
                .find(|question| question.question_id == answer.question_id)
                .ok_or_else(|| invalid_input("an answer refers to an unknown question"))?;
            let recorded = normalize_answer(question, answer)?;
            updated
                .answers
                .retain(|existing| existing.question_id != recorded.question_id);
            updated.answers.push(recorded);
        }
        Ok(updated)
    }

    fn answer_matches(
        question: &PracticeQuestion,
        answer: &RecordedAnswer,
        key: &[String],
    ) -> bool {
        if question.kind == "choice" {
            let Some(choices) = answer.choices.as_ref() else {
                return false;
            };
            let mut expected: Vec<String> = key.to_vec();
            expected.sort();
            return *choices == expected;
        }
        let (Some(text), Some(expected)) = (answer.text.as_ref(), key.first()) else {
            return false;
        };
        normalize_text(text) == normalize_text(expected)
    }

    /// The local self-check. It reports what the operator answered locally and
    /// nothing else: there is no official grade, no completion claim and no
    /// submission.
    pub(crate) fn check_session(
        session: &PracticeSession,
        type_label: &str,
    ) -> Result<PracticeSession, Error> {
        validate_session(session, type_label)?;
        let mut items = Vec::with_capacity(session.questions.len());
        let mut matched = 0usize;
        let mut mismatched = 0usize;
        let mut unanswered = 0usize;
        let mut unverifiable = 0usize;
        for question in &session.questions {
            let recorded = session
                .answers
                .iter()
                .find(|answer| answer.question_id == question.question_id);
            let status = match recorded {
                None => {
                    unanswered += 1;
                    "unanswered"
                }
                Some(answer) => match question.local_self_check_key.as_ref() {
                    None => {
                        unverifiable += 1;
                        "unverifiable"
                    }
                    Some(key) => {
                        if answer_matches(question, answer, key) {
                            matched += 1;
                            "match"
                        } else {
                            mismatched += 1;
                            "mismatch"
                        }
                    }
                },
            };
            items.push(json!({
                "question_id": question.question_id,
                "status": status,
                "answered": recorded.is_some(),
                "key_available": question.local_self_check_key.is_some()
            }));
        }
        let results = json!({
            "authority": "local_self_check",
            "official_grade": Value::Null,
            "official_result": Value::Null,
            "checked_at_unix_ms": unix_ms()?,
            "items": items,
            "local_match_count": matched,
            "local_mismatch_count": mismatched,
            "local_unanswered_count": unanswered,
            "local_unverifiable_count": unverifiable,
            "completion_state": "local_practice_only",
            "completion_reported": false,
            "submission_state": "not_submitted"
        });
        let mut checked = session.clone();
        checked.results = Some(results);
        Ok(checked)
    }

    /// Apply an operator-supplied local key. It is the operator's own key, it
    /// is labelled as such, and it never becomes an official answer.
    pub(crate) fn apply_operator_key(
        questions: &mut [PracticeQuestion],
        key: Option<&Value>,
    ) -> Result<(), Error> {
        let Some(key) = key else {
            return Ok(());
        };
        let entries = key.as_array().ok_or_else(|| {
            invalid_input("a local answer key must be an array of keyed entries")
        })?;
        if entries.len() > MAX_ANSWERS {
            return Err(invalid_input("a local answer key carries too many entries"));
        }
        for entry in entries {
            let object = entry
                .as_object()
                .ok_or_else(|| invalid_input("a local answer key entry must be an object"))?;
            only_keys(object, &["question_id", "choices", "text"])?;
            let question_id = object
                .get("question_id")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid_input("a local answer key entry requires a question id"))?;
            let question = questions
                .iter_mut()
                .find(|question| question.question_id == question_id)
                .ok_or_else(|| {
                    invalid_input("a local answer key refers to an unknown question")
                })?;
            let choices = object.get("choices").and_then(Value::as_array);
            let text = object.get("text").and_then(Value::as_str);
            match (choices, text) {
                (Some(choices), None) => {
                    if question.kind != "choice" {
                        return Err(invalid_input(
                            "an option key needs a choice question",
                        ));
                    }
                    if choices.is_empty() || choices.len() > MAX_OPTIONS {
                        return Err(invalid_input(
                            "a local answer key carries an invalid option list",
                        ));
                    }
                    let mut normalized = Vec::with_capacity(choices.len());
                    for choice in choices {
                        let letter = choice
                            .as_str()
                            .ok_or_else(|| {
                                invalid_input("a local answer key option must be a string")
                            })?
                            .trim()
                            .to_ascii_uppercase();
                        let bytes = letter.as_bytes();
                        if bytes.len() != 1 || !bytes[0].is_ascii_uppercase() {
                            return Err(invalid_input(
                                "a local answer key option must be a single A-Z character",
                            ));
                        }
                        if normalized.contains(&letter) {
                            return Err(invalid_input("a local answer key option is repeated"));
                        }
                        normalized.push(letter);
                    }
                    normalized.sort();
                    question.local_self_check_key = Some(normalized);
                    question.key_source = "operator_supplied".to_owned();
                }
                (None, Some(text)) => {
                    if question.kind == "choice" {
                        return Err(invalid_input(
                            "a written key needs a written question",
                        ));
                    }
                    if text.trim().is_empty() || text.len() > MAX_ANSWER_BYTES {
                        return Err(invalid_input(
                            "a local answer key entry carries an invalid answer",
                        ));
                    }
                    question.local_self_check_key = Some(vec![text.to_owned()]);
                    question.key_source = "operator_supplied".to_owned();
                }
                _ => {
                    return Err(invalid_input(
                        "a local answer key entry needs exactly one of choices or text",
                    ))
                }
            }
        }
        Ok(())
    }

    /// Deterministic cloze questions over material the operator supplies. The
    /// hidden span is the operator's own material, never an upstream answer.
    pub(crate) fn generate_cloze_questions(
        material_text: &str,
        count: usize,
    ) -> Vec<PracticeQuestion> {
        let mut questions = Vec::new();
        for sentence in split_sentences(material_text) {
            if questions.len() >= count {
                break;
            }
            let words = word_ranges(&sentence);
            if words.len() < 4 {
                continue;
            }
            let mut chosen: Option<(usize, usize)> = None;
            let mut chosen_length = 0usize;
            for (start, end) in &words {
                let length = sentence[*start..*end].chars().count();
                if !(2..=24).contains(&length) {
                    continue;
                }
                if length > chosen_length {
                    chosen = Some((*start, *end));
                    chosen_length = length;
                }
            }
            let Some((start, end)) = chosen else {
                continue;
            };
            let key = sentence[start..end].to_owned();
            let mut prompt = String::with_capacity(sentence.len() + 4);
            prompt.push_str(&sentence[..start]);
            prompt.push_str("____");
            prompt.push_str(&sentence[end..]);
            questions.push(PracticeQuestion {
                question_id: format!("q{}", questions.len() + 1),
                kind: "cloze".to_owned(),
                prompt: collapse_whitespace(&prompt),
                options: None,
                blanks: None,
                chapter: None,
                question_type: None,
                local_self_check_key: Some(vec![key]),
                key_source: "local_material".to_owned(),
            });
        }
        questions
    }

    pub(crate) fn collapse_whitespace(value: &str) -> String {
        value.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn split_sentences(text: &str) -> Vec<String> {
        let mut sentences = Vec::new();
        let mut current = String::new();
        let mut characters = text.chars().peekable();
        while let Some(character) = characters.next() {
            current.push(character);
            let punctuation = matches!(
                character,
                '。' | '！' | '？' | '!' | '?' | ';' | '；' | '\n' | '\r'
            );
            let sentence_end = character == '.'
                && matches!(characters.peek(), None | Some(&' ') | Some(&'\t'));
            if punctuation || sentence_end {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    sentences.push(trimmed.to_owned());
                }
                current.clear();
            }
        }
        let trimmed = current.trim();
        if !trimmed.is_empty() {
            sentences.push(trimmed.to_owned());
        }
        sentences
    }

    /// Word ranges of a sentence. Alphanumeric runs, including CJK runs, are
    /// one word; every other character separates.
    fn word_ranges(sentence: &str) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        let mut start: Option<usize> = None;
        for (index, character) in sentence.char_indices() {
            if character.is_alphanumeric() {
                if start.is_none() {
                    start = Some(index);
                }
            } else if let Some(begin) = start.take() {
                ranges.push((begin, index));
            }
        }
        if let Some(begin) = start {
            ranges.push((begin, sentence.len()));
        }
        ranges
    }

    pub(crate) fn question_schema() -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["question_id","kind","prompt","options","blanks","chapter","question_type","local_self_check_key","key_source"],
            "properties":{
                "question_id":{"type":"string","minLength":1,"maxLength":128},
                "kind":{"enum":["cloze","choice","fill","other"]},
                "prompt":{"type":"string","maxLength":MAX_PROMPT_CHARS},
                "options":{"type":["array","null"],"maxItems":MAX_OPTIONS,"items":{"type":"string","minLength":1,"maxLength":MAX_OPTION_BYTES}},
                "blanks":{"type":["array","null"],"maxItems":MAX_OPTIONS,"items":{"type":"string","minLength":1,"maxLength":MAX_OPTION_BYTES}},
                "chapter":{"type":["integer","null"],"minimum":1},
                "question_type":{"type":["integer","null"],"enum":[1,2,null]},
                "local_self_check_key":{"type":["array","null"],"maxItems":MAX_OPTIONS,"items":{"type":"string","minLength":1,"maxLength":MAX_ANSWER_BYTES}},
                "key_source":{"enum":["local_material","operator_supplied","none"]}
            }
        })
    }

    pub(crate) fn recorded_answer_schema() -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["question_id","text","choices","recorded_at_unix_ms"],
            "properties":{
                "question_id":{"type":"string","minLength":1,"maxLength":128},
                "text":{"type":["string","null"],"maxLength":MAX_ANSWER_BYTES},
                "choices":{"type":["array","null"],"maxItems":MAX_OPTIONS,"items":{"type":"string","minLength":1,"maxLength":8}},
                "recorded_at_unix_ms":{"type":"integer","minimum":0}
            }
        })
    }

    pub(crate) fn answer_input_schema() -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["question_id"],
            "properties":{
                "question_id":{"type":"string","minLength":1,"maxLength":128},
                "text":{"type":"string","minLength":1,"maxLength":MAX_ANSWER_BYTES},
                "choices":{"type":"array","minItems":1,"maxItems":MAX_OPTIONS,"items":{"type":"string","minLength":1,"maxLength":8}}
            }
        })
    }

    pub(crate) fn operator_key_schema() -> Value {
        json!({
            "type":"array","maxItems":MAX_ANSWERS,
            "items":{
                "type":"object","additionalProperties":false,
                "required":["question_id"],
                "properties":{
                    "question_id":{"type":"string","minLength":1,"maxLength":128},
                    "choices":{"type":"array","minItems":1,"maxItems":MAX_OPTIONS,"items":{"type":"string","minLength":1,"maxLength":8}},
                    "text":{"type":"string","minLength":1,"maxLength":MAX_ANSWER_BYTES}
                }
            }
        })
    }

    pub(crate) fn scan_schema() -> Value {
        json!({
            "type":["object","null"],"additionalProperties":false,
            "required":["control_count","answer_attribute_names","answer_attribute_occurrences","response_state_attribute_occurrences","dropped_answer_text_fragments"],
            "properties":{
                "control_count":{"type":"integer","minimum":0},
                "answer_attribute_names":{"type":"array","maxItems":32,"items":{"type":"string","minLength":1}},
                "answer_attribute_occurrences":{"type":"integer","minimum":0},
                "response_state_attribute_occurrences":{"type":"integer","minimum":0},
                "dropped_answer_text_fragments":{"type":"integer","minimum":0}
            }
        })
    }

    pub(crate) fn session_schema(type_label: &str) -> Value {
        json!({
            "type":"object","additionalProperties":false,
            "required":["schema_version","type","result","session_id","authority","official_grade","official_result","submission_state","completion_reported","rights_reviewed","practice_source","questions","answers","results"],
            "properties":{
                "schema_version":{"const":1},
                "type":{"const":type_label},
                "result":{"const":"practice_session"},
                "session_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                "authority":{"const":"local_only","description":"A local practice session never carries official authority."},
                "official_grade":{"type":"null"},
                "official_result":{"type":"null"},
                "submission_state":{"const":"not_submitted"},
                "completion_reported":{"const":false},
                "rights_reviewed":{"type":"boolean"},
                "practice_source":{"type":"object","additionalProperties":false,
                    "required":["kind","origin","rights_reviewed","digest","scan"],
                    "properties":{
                        "kind":{"type":"string","minLength":1},
                        "origin":{"type":"string","minLength":1},
                        "rights_reviewed":{"type":"boolean"},
                        "digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                        "scan":scan_schema()
                    }
                },
                "questions":{"type":"array","minItems":1,"maxItems":MAX_QUESTIONS,"items":question_schema()},
                "answers":{"type":"array","maxItems":MAX_ANSWERS,"items":recorded_answer_schema()},
                "results":{"oneOf":[{"type":"null"},{"type":"object","additionalProperties":false,
                    "required":["authority","official_grade","official_result","checked_at_unix_ms","items","local_match_count","local_mismatch_count","local_unanswered_count","local_unverifiable_count","completion_state","completion_reported","submission_state"],
                    "properties":{
                        "authority":{"const":"local_self_check"},
                        "official_grade":{"type":"null"},
                        "official_result":{"type":"null"},
                        "checked_at_unix_ms":{"type":"integer","minimum":0},
                        "items":{"type":"array","maxItems":MAX_QUESTIONS,"items":{"type":"object","additionalProperties":false,
                            "required":["question_id","status","answered","key_available"],
                            "properties":{
                                "question_id":{"type":"string","minLength":1,"maxLength":128},
                                "status":{"enum":["match","mismatch","unanswered","unverifiable"]},
                                "answered":{"type":"boolean"},
                                "key_available":{"type":"boolean"}
                            }
                        }},
                        "local_match_count":{"type":"integer","minimum":0},
                        "local_mismatch_count":{"type":"integer","minimum":0},
                        "local_unanswered_count":{"type":"integer","minimum":0},
                        "local_unverifiable_count":{"type":"integer","minimum":0},
                        "completion_state":{"const":"local_practice_only"},
                        "completion_reported":{"const":false},
                        "submission_state":{"const":"not_submitted"}
                    }
                }]}
            }
        })
    }

    pub(crate) fn practice_schema(type_label: &str, generate_branches: Vec<Value>) -> Value {
        let mut branches = generate_branches;
        branches.push(json!({
            "type":"object","additionalProperties":false,
            "required":["action","session","answers"],
            "properties":{
                "action":{"const":"answer"},
                "session":session_schema(type_label),
                "answers":{"type":"array","minItems":1,"maxItems":MAX_ANSWERS,"items":answer_input_schema()}
            }
        }));
        branches.push(json!({
            "type":"object","additionalProperties":false,
            "required":["action","session"],
            "properties":{
                "action":{"const":"check"},
                "session":session_schema(type_label)
            }
        }));
        json!({
            "input":{"oneOf":branches},
            "options":{},
            "output":session_schema(type_label)
        })
    }
}

// ---------------------------------------------------------------- WE Learn

/// The source-reviewed WE Learn reference. The branch was read from the
/// upstream repository; the license reference is an operator attestation and
/// is published only bound to the license object of the admitted tree.
const SOURCE: learning::SourceSpec = learning::SourceSpec {
    owner: "Micraow",
    name: "WE-Learn-Answers",
    branch: "master",
};

const TYPE_LABEL: &str = "welearn_material_inventory";
const SEARCH_TYPE_LABEL: &str = "welearn_material_search";
const RAW_TYPE_LABEL: &str = "welearn_material_bytes";
const PRACTICE_TYPE_LABEL: &str = "welearn_practice_session";

/// The answer-bearing attributes the upstream answer-helper script reads.
/// Their values are never read here; only their names are reported.
const ANSWER_ATTRIBUTES: &[&str] = &[
    "data-solution",
    "data-answer",
    "data-answers",
    "data-correct",
    "data-correctanswer",
    "data-rightanswer",
    "answer",
    "correct",
];

/// A response-state attribute the upstream script writes on the option the
/// operator selected. It is never imported, so a practice set never starts
/// from a pre-existing completion state.
const RESPONSE_STATE_ATTRIBUTE: &str = "data-choiced";

/// Classify one repository path. The classification is path based and is
/// applied identically to the inventory and to every retrieval, so the
/// reviewed inventory is the only gate that admits bytes.
fn classify(path: &str) -> learning::MaterialClass {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if name.contains("answer")
        || lower.contains("/answers/")
        || lower.contains("/answer/")
        || learning::answer_path_component(path)
    {
        return learning::MaterialClass::AnswerMaterial;
    }
    if name.starts_with("license") || name.starts_with("copying") {
        return learning::MaterialClass::License;
    }
    if name.ends_with(".md") || name.ends_with(".txt") || name.ends_with(".rst") {
        return learning::MaterialClass::Documentation;
    }
    if name.ends_with(".js") || name.ends_with(".ts") || name.ends_with(".json") {
        return learning::MaterialClass::SourceCode;
    }
    if lower.contains("courseware") || lower.contains("material") {
        return learning::MaterialClass::CourseMaterial;
    }
    learning::MaterialClass::Other
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    query: String,
    rights_reviewed: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchInput {
    path: String,
    rights_reviewed: Option<bool>,
    tree_sha: Option<String>,
    blob_sha: Option<String>,
    mode: Option<String>,
    size: Option<u64>,
}

fn parse_search_input(input: &str) -> Result<SearchInput, Error> {
    if input.len() > learning::MAX_INPUT {
        return Err(learning::invalid_input("the search request is too large"));
    }
    let parsed: SearchInput = serde_json::from_str(input)
        .map_err(|_| learning::invalid_input("the search request is malformed"))?;
    if parsed.rights_reviewed != Some(true) {
        return Err(learning::authorization_required(
            "a material search requires an explicit rights-review attestation",
        ));
    }
    let query = parsed.query.trim();
    if query.is_empty() || query.len() > learning::MAX_QUERY_BYTES {
        return Err(learning::invalid_input("the search query is empty or too long"));
    }
    Ok(SearchInput {
        query: query.to_owned(),
        rights_reviewed: Some(true),
    })
}

fn parse_fetch_input(input: &str) -> Result<FetchInput, Error> {
    if input.len() > learning::MAX_INPUT {
        return Err(learning::invalid_input("the fetch request is too large"));
    }
    let parsed: FetchInput = serde_json::from_str(input)
        .map_err(|_| learning::invalid_input("the fetch request is malformed"))?;
    if parsed.rights_reviewed != Some(true) {
        return Err(learning::authorization_required(
            "a material download requires an explicit rights-review attestation",
        ));
    }
    if !learning::valid_path(&parsed.path) {
        return Err(learning::invalid_input(
            "the material path is not a normalized repository path",
        ));
    }
    let parsed = FetchInput {
        path: parsed.path,
        rights_reviewed: Some(true),
        tree_sha: parsed.tree_sha,
        blob_sha: parsed.blob_sha,
        mode: parsed.mode,
        size: parsed.size,
    };
    let provided = [parsed.tree_sha.is_some(), parsed.blob_sha.is_some(),
        parsed.mode.is_some(), parsed.size.is_some()];
    if provided.iter().any(|provided| *provided) && !provided.iter().all(|provided| *provided) {
        return Err(learning::invalid_input(
            "the rights-review attestation must carry the complete reviewed tree, blob, mode and size",
        ));
    }
    if parsed.tree_sha.is_none() {
        return Err(learning::authorization_required(
            "a material download requires the immutable tree, blob, mode and size the operator reviewed",
        ));
    }
    if let Some(tree_sha) = parsed.tree_sha.as_deref() {
        if !learning::valid_upstream_sha(tree_sha) {
            return Err(learning::invalid_input(
                "the reviewed tree identity is not a valid Git object SHA",
            ));
        }
    }
    if let Some(blob_sha) = parsed.blob_sha.as_deref() {
        if !learning::valid_upstream_sha(blob_sha) {
            return Err(learning::invalid_input(
                "the reviewed blob identity is not a valid Git object SHA",
            ));
        }
    }
    if let Some(mode) = parsed.mode.as_deref() {
        if !matches!(mode, "100644" | "100755") {
            return Err(learning::invalid_input(
                "only the reviewed mode of a regular file can be retrieved",
            ));
        }
    }
    Ok(parsed)
}

/// List the reviewed WE Learn material inventory. Offline is the default;
/// `online` permits exactly one governed tree request on a cache miss.
pub fn materials(input: &str, online: bool) -> Result<Value, Error> {
    let trimmed = input.trim();
    let value: Value = if trimmed.is_empty() {
        json!({})
    } else {
        serde_json::from_str(trimmed)
            .map_err(|_| learning::invalid_input("the materials request is malformed"))?
    };
    let object = value
        .as_object()
        .ok_or_else(|| learning::invalid_input("the materials request must be an object"))?;
    learning::only_keys(object, &[])?;
    let url = SOURCE.tree_url()?;
    learning::with_tree_response(&SOURCE, online, |response, identity| {
        learning::inventory_output(&SOURCE, TYPE_LABEL, &url, response, identity, &classify)
    })
}

/// Search the reviewed inventory. The rights-review attestation is required
/// before any cache or network admission.
pub fn search(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_search_input(input)?;
    let url = SOURCE.tree_url()?;
    learning::with_tree_response(&SOURCE, online, |response, identity| {
        learning::search_output(
            &SOURCE,
            SEARCH_TYPE_LABEL,
            &url,
            response,
            identity,
            &request.query,
            &classify,
        )
    })
}

/// The outcome of resolving one requested path against the reviewed
/// inventory. A refusal travels as an inner result so that the complete
/// verified tree is retained before the error is reported.
enum Admission {
    Classified {
        class: learning::MaterialClass,
        tree_sha: String,
        blob_sha: String,
        size: u64,
        license: Value,
    },
    Degraded(Value),
    Refused(Error),
}

/// Fetch the bytes of one reviewed material entry. The material class is
/// resolved from the reviewed inventory first, so an answer-bearing entry is
/// refused before any byte request is made.
pub fn fetch(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_fetch_input(input)?;
    let admission = learning::with_tree_response(&SOURCE, online, |response, identity| {
        match identity.tree() {
            Some(admitted) => {
                let tree_sha = admitted.tree_sha.as_str();
                let entries = admitted.entries.as_slice();
                let Some(entry) = entries.iter().find(|entry| entry.path == request.path) else {
                    return Ok(Admission::Refused(Error::new(
                        "path_not_in_inventory",
                        "the requested path is not present in the reviewed material inventory",
                    )));
                };
                let Some(size) = entry.size else {
                    return Ok(Admission::Refused(Error::new(
                        "path_not_in_inventory",
                        "the requested path is not present in the reviewed material inventory",
                    )));
                };
                let Some(mode) = entry.kind().filter(|kind| *kind == "file").map(|_| entry.mode.as_str()) else {
                    return Ok(Admission::Refused(learning::invalid_input(
                        "only regular inventory files can be retrieved",
                    )));
                };
                if request.tree_sha.as_deref() != Some(tree_sha)
                    || request.blob_sha.as_deref() != Some(entry.sha.as_str())
                    || request.mode.as_deref() != Some(mode)
                    || request.size != Some(size)
                {
                    return Ok(Admission::Refused(learning::authorization_required(
                        "the requested material does not match the reviewed immutable identity",
                    )));
                }
                let class = classify(&entry.path);
                if !class.retrieval_allowed()
                    || learning::blob_is_answer_material(entries, entry.sha.as_str(), &classify)
                {
                    return Ok(Admission::Refused(learning::answer_material_forbidden()));
                }
                Ok(Admission::Classified {
                    class,
                    tree_sha: tree_sha.to_owned(),
                    blob_sha: entry.sha.clone(),
                    size,
                    license: learning::verified_license(&SOURCE, entries),
                })
            }
            None => Ok(Admission::Degraded(
                learning::degraded_admission_output(
                    &SOURCE,
                    RAW_TYPE_LABEL,
                    &request.path,
                    response,
                    identity,
                    identity.tree_error().unwrap_or("upstream_parse"),
                    learning::Surface::Tree,
                )?,
            )),
        }
    })?;
    match admission {
        Admission::Degraded(output) => Ok(output),
        Admission::Refused(error) => Err(error),
        Admission::Classified { class, tree_sha, blob_sha, size, license } => {
            learning::with_raw_response(&SOURCE, &blob_sha, online, |response, identity| {
                learning::verified_blob_output(&SOURCE, RAW_TYPE_LABEL, &request.path, response, identity, class, &tree_sha, &blob_sha, &license, size)
            })
        }
    }
}

/// Local WE Learn practice. The session never carries an official grade, a
/// completion claim or a submission.
pub fn practice(input: &str) -> Result<Value, Error> {
    if input.len() > learning::MAX_PRACTICE_INPUT {
        return Err(learning::invalid_input("the practice request is too large"));
    }
    let value: Value = serde_json::from_str(input)
        .map_err(|_| learning::invalid_input("the practice request is malformed"))?;
    let object = value
        .as_object()
        .ok_or_else(|| learning::invalid_input("the practice request must be an object"))?;
    let action = object
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| learning::invalid_input("the practice request requires an action"))?;
    match action {
        "generate" => generate_practice(object),
        "answer" => {
            learning::only_keys(object, &["action", "session", "answers"])?;
            let session = parse_session(object)?;
            let answers = object
                .get("answers")
                .ok_or_else(|| learning::invalid_input("the answer action requires answers"))?;
            let answers: Vec<learning::AnswerInput> = serde_json::from_value(answers.clone())
                .map_err(|_| learning::invalid_input("the answers are malformed"))?;
            let recorded = learning::record_answers(&session, PRACTICE_TYPE_LABEL, &answers)?;
            serde_json::to_value(recorded)
                .map_err(|_| learning::invalid_input("the practice session is not serializable"))
        }
        "check" => {
            learning::only_keys(object, &["action", "session"])?;
            let session = parse_session(object)?;
            let checked = learning::check_session(&session, PRACTICE_TYPE_LABEL)?;
            serde_json::to_value(checked)
                .map_err(|_| learning::invalid_input("the practice session is not serializable"))
        }
        _ => Err(learning::invalid_input("the practice action is unknown")),
    }
}

fn parse_session(object: &Map<String, Value>) -> Result<learning::PracticeSession, Error> {
    let session = object
        .get("session")
        .ok_or_else(|| learning::invalid_input("the practice action requires a session"))?;
    serde_json::from_value(session.clone())
        .map_err(|_| learning::invalid_input("the practice session is malformed"))
}

fn generate_practice(object: &Map<String, Value>) -> Result<Value, Error> {
    learning::only_keys(
        object,
        &[
            "action",
            "mode",
            "material_text",
            "count",
            "practice_page_html",
            "local_answer_key",
            "rights_reviewed",
        ],
    )?;
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| learning::invalid_input("a practice generation mode is required"))?;
    let rights_reviewed = learning::optional_bool(object, "rights_reviewed")?;
    let (questions, practice_source): (Vec<learning::PracticeQuestion>, Value) = match mode {
        "cloze" => {
            learning::only_keys(
                object,
                &[
                    "action",
                    "mode",
                    "material_text",
                    "count",
                    "local_answer_key",
                    "rights_reviewed",
                ],
            )?;
            let material = object
                .get("material_text")
                .and_then(Value::as_str)
                .ok_or_else(|| learning::invalid_input("the cloze mode requires material_text"))?;
            if material.trim().is_empty() || material.len() > learning::MAX_MATERIAL_TEXT {
                return Err(learning::invalid_input("the material text is empty or too large"));
            }
            let count = object
                .get("count")
                .and_then(Value::as_u64)
                .ok_or_else(|| learning::invalid_input("the cloze mode requires a question count"))?;
            if count == 0 || count > learning::MAX_QUESTIONS as u64 {
                return Err(learning::invalid_input("the question count is out of range"));
            }
            let questions = learning::generate_cloze_questions(material, count as usize);
            let source = json!({
                "kind": "cloze",
                "origin": "operator_local_material",
                "rights_reviewed": rights_reviewed,
                "digest": learning::sha256_hex(material.as_bytes()),
                "scan": Value::Null
            });
            (questions, source)
        }
        "we_learn_page" => {
            learning::only_keys(
                object,
                &[
                    "action",
                    "mode",
                    "practice_page_html",
                    "local_answer_key",
                    "rights_reviewed",
                ],
            )?;
            let html = object
                .get("practice_page_html")
                .and_then(Value::as_str)
                .ok_or_else(|| learning::invalid_input("the page mode requires practice_page_html"))?;
            if html.trim().is_empty() || html.len() > learning::MAX_PRACTICE_PAGE_HTML {
                return Err(learning::invalid_input("the practice page is empty or too large"));
            }
            let (questions, scan) = questions_from_practice_page(html)?;
            let source = json!({
                "kind": "we_learn_page",
                "origin": "operator_local_capture",
                "rights_reviewed": rights_reviewed,
                "digest": learning::sha256_hex(html.as_bytes()),
                "scan": scan
            });
            (questions, source)
        }
        _ => return Err(learning::invalid_input("the practice generation mode is unknown")),
    };
    let mut questions = questions;
    learning::apply_operator_key(&mut questions, object.get("local_answer_key"))?;
    let session =
        learning::new_session(PRACTICE_TYPE_LABEL, practice_source, questions, rights_reviewed)?;
    serde_json::to_value(session)
        .map_err(|_| learning::invalid_input("the practice session is not serializable"))
}

/// What one reviewed practice page contributed, without any answer value.
#[derive(Debug, Default)]
struct PageScan {
    control_count: usize,
    answer_attribute_names: Vec<String>,
    answer_attribute_occurrences: usize,
    response_state_attribute_occurrences: usize,
    dropped_answer_text_fragments: usize,
}

impl PageScan {
    fn to_json(&self) -> Value {
        json!({
            "control_count": self.control_count,
            "answer_attribute_names": self.answer_attribute_names,
            "answer_attribute_occurrences": self.answer_attribute_occurrences,
            "response_state_attribute_occurrences": self.response_state_attribute_occurrences,
            "dropped_answer_text_fragments": self.dropped_answer_text_fragments
        })
    }
}

fn questions_from_practice_page(
    html: &str,
) -> Result<(Vec<learning::PracticeQuestion>, Value), Error> {
    let document = scraper::Html::parse_document(html);
    let tree = document.tree;
    let mut scan = PageScan::default();
    let mut controls: Vec<ego_tree::NodeId> = Vec::new();
    for node in tree.nodes() {
        let scraper::node::Node::Element(element) = node.value() else {
            continue;
        };
        for (local, _) in element.attrs() {
            if ANSWER_ATTRIBUTES.contains(&local) {
                scan.answer_attribute_occurrences += 1;
                if !scan
                    .answer_attribute_names
                    .iter()
                    .any(|existing| existing == local)
                {
                    scan.answer_attribute_names.push(local.to_owned());
                }
            } else if local == RESPONSE_STATE_ATTRIBUTE {
                scan.response_state_attribute_occurrences += 1;
            }
        }
        if element.attr("data-controltype").is_some() {
            controls.push(node.id());
        }
    }
    scan.control_count = controls.len();

    let mut questions: Vec<learning::PracticeQuestion> = Vec::new();
    let mut dropped = 0usize;
    for identifier in controls {
        let Some(node) = tree.get(identifier) else {
            continue;
        };
        let Some(element) = node.value().as_element() else {
            continue;
        };
        let Some(control_type) = element.attr("data-controltype") else {
            continue;
        };
        let control_type = learning::collapse_whitespace(control_type);
        if control_type.is_empty() || control_type.len() > 128 {
            continue;
        }
        let kind = if is_choice_control(&control_type) {
            "choice"
        } else if is_fill_control(&control_type) {
            "fill"
        } else {
            "other"
        };
        let descendants = descendant_elements(&node);
        let option_nodes: Vec<ego_tree::NodeRef<'_, scraper::node::Node>> = descendants
            .iter()
            .filter(|candidate| {
                candidate
                    .value()
                    .as_element()
                    .map(|element| element.name() == "li")
                    .unwrap_or(false)
            })
            .copied()
            .collect();
        let mut skip = std::collections::BTreeSet::new();
        let mut options: Vec<String> = Vec::new();
        let no_skip = std::collections::BTreeSet::new();
        for option in &option_nodes {
            let text = collect_text(option, &no_skip, &mut dropped);
            let text = strip_option_marker(&text);
            if !text.is_empty() && options.len() < learning::MAX_OPTIONS {
                options.push(text);
            }
        }
        for option in &option_nodes {
            skip.insert(option.id());
        }
        let own_text = collect_text(&node, &skip, &mut dropped);
        let prompt = if !own_text.trim().is_empty() {
            own_text
        } else {
            match node.parent() {
                Some(parent) => {
                    let text = collect_text(&parent, &skip, &mut dropped);
                    if text.chars().count() > learning::MAX_PROMPT_CHARS {
                        text.chars().take(learning::MAX_PROMPT_CHARS).collect()
                    } else {
                        text
                    }
                }
                None => String::new(),
            }
        };
        let blanks = if kind == "fill" {
            Some(collect_blanks(&descendants))
        } else {
            None
        };
        questions.push(learning::PracticeQuestion {
            question_id: format!("q{}", questions.len() + 1),
            kind: kind.to_owned(),
            prompt: learning::collapse_whitespace(&prompt),
            options: if kind == "choice" && !options.is_empty() {
                Some(options)
            } else {
                None
            },
            blanks,
            chapter: None,
            question_type: None,
            local_self_check_key: None,
            key_source: "none".to_owned(),
        });
        if questions.len() >= learning::MAX_QUESTIONS {
            break;
        }
    }
    scan.dropped_answer_text_fragments = dropped;
    Ok((questions, scan.to_json()))
}

fn is_choice_control(control_type: &str) -> bool {
    let lower = control_type.to_ascii_lowercase();
    lower.contains("choice") || lower.contains("tf") || lower.contains("radiobox")
}

fn is_fill_control(control_type: &str) -> bool {
    let lower = control_type.to_ascii_lowercase();
    lower.contains("filling") || lower.contains("writing")
}

fn descendant_elements<'a>(
    node: &ego_tree::NodeRef<'a, scraper::node::Node>,
) -> Vec<ego_tree::NodeRef<'a, scraper::node::Node>> {
    let mut found = Vec::new();
    let mut stack: Vec<ego_tree::NodeRef<'a, scraper::node::Node>> = node.children().collect();
    while let Some(current) = stack.pop() {
        if matches!(current.value(), scraper::node::Node::Element(_)) {
            found.push(current);
        }
        let children: Vec<ego_tree::NodeRef<'a, scraper::node::Node>> =
            current.children().collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    found
}

fn collect_blanks(descendants: &[ego_tree::NodeRef<'_, scraper::node::Node>]) -> Vec<String> {
    let mut blanks: Vec<String> = Vec::new();
    for descendant in descendants {
        let Some(element) = descendant.value().as_element() else {
            continue;
        };
        let name = element.name();
        if name != "input" && name != "textarea" {
            continue;
        }
        let label = element
            .attr("name")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("blank_{}", blanks.len() + 1));
        if !blanks.contains(&label) && blanks.len() < learning::MAX_OPTIONS {
            blanks.push(label);
        }
    }
    blanks
}

/// Collect the visible text of a subtree. Answer-bearing attribute values are
/// never read, the upstream helper's answer hint element is skipped, and any
/// text that spells out an answer is dropped.
fn collect_text(
    node: &ego_tree::NodeRef<'_, scraper::node::Node>,
    skip: &std::collections::BTreeSet<ego_tree::NodeId>,
    dropped: &mut usize,
) -> String {
    let mut out = String::new();
    walk_text(node, skip, dropped, &mut out);
    out
}

fn walk_text(
    node: &ego_tree::NodeRef<'_, scraper::node::Node>,
    skip: &std::collections::BTreeSet<ego_tree::NodeId>,
    dropped: &mut usize,
    out: &mut String,
) {
    match node.value() {
        scraper::node::Node::Text(text) => {
            let value: &str = &text.text;
            let trimmed = value.trim();
            if trimmed
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("answer:"))
            {
                *dropped += 1;
                return;
            }
            out.push_str(value);
        }
        scraper::node::Node::Element(element) => {
            if skip.contains(&node.id()) {
                return;
            }
            let name = element.name();
            if matches!(name, "script" | "style" | "noscript" | "template") {
                return;
            }
            if element.classes().any(|class| class == "wl-answer-helper-hint") {
                *dropped += 1;
                return;
            }
            for child in node.children() {
                walk_text(&child, skip, dropped, out);
            }
        }
        _ => {}
    }
}

fn strip_option_marker(text: &str) -> String {
    let trimmed = text.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 3 && bytes[0] == b'[' && bytes[2] == b']' && bytes[1].is_ascii_alphabetic() {
        return trimmed[3..].trim().to_owned();
    }
    trimmed.to_owned()
}

/// Machine-readable stdin/output contracts for CLI integration.
pub fn schema() -> Value {
    json!({
        "materials": {
            "input":{
                "type":"object","additionalProperties":false,"properties":{},"required":[],
                "description":"The reviewed source, branch and license are pinned; this request accepts no parameter. An empty input is accepted as this empty object."
            },
            "options":{"--online":"Permit one governed GitHub tree request on a cache miss; no automatic retry, refresh or pagination."},
            "output":learning::inventory_schema(TYPE_LABEL)
        },
        "search": {
            "input":{
                "type":"object","additionalProperties":false,"required":["query","rights_reviewed"],
                "properties":{
                    "query":{"type":"string","minLength":1,"maxLength":learning::MAX_QUERY_BYTES,"description":"A case-insensitive substring matched against the path and the title of each reviewed entry."},
                    "rights_reviewed":{"const":true,"description":"Required operator attestation. False or omitted fails before cache or network admission."}
                }
            },
            "options":{"--online":"Permit one governed GitHub tree request on a cache miss; no automatic retry or refresh."},
            "output":learning::search_schema(SEARCH_TYPE_LABEL)
        },
        "fetch": {
            "input":{
                "type":"object","additionalProperties":false,"required":["path","rights_reviewed","tree_sha","blob_sha","mode","size"],
                "properties":{
                    "path":{"type":"string","minLength":1,"maxLength":learning::MAX_PATH,"description":"An explicit normalized repository-relative path that is present in the reviewed inventory."},
                    "rights_reviewed":{"const":true,"description":"Required operator attestation. False or omitted fails before cache or network admission."},
                    "tree_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"The immutable root tree object the operator reviewed. It is compared with the verified admitted tree before any byte request."},
                    "blob_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"The immutable blob object the operator reviewed. It is compared with the admitted inventory entry before any byte request."},
                    "mode":{"enum":["100644","100755"],"description":"The reviewed entry mode. Only a regular file can be retrieved."},
                    "size":{"type":"integer","minimum":0,"description":"The reviewed byte length. The retrieved blob must have exactly this length."}
                }
            },
            "options":{"--online":"Permit the governed inventory lookup and the governed byte request on a cache miss; no automatic retry or redirect."},
            "output":learning::raw_schema(RAW_TYPE_LABEL)
        },
        "practice": {
            "input":learning::practice_schema(PRACTICE_TYPE_LABEL, vec![
                json!({
                    "type":"object","additionalProperties":false,
                    "required":["action","mode","material_text","count"],
                    "properties":{
                        "action":{"const":"generate"},
                        "mode":{"const":"cloze"},
                        "material_text":{"type":"string","minLength":1,"maxLength":learning::MAX_MATERIAL_TEXT,"description":"Local material the operator supplies; the cloze key is derived from this text only."},
                        "count":{"type":"integer","minimum":1,"maximum":learning::MAX_QUESTIONS},
                        "local_answer_key":learning::operator_key_schema(),
                        "rights_reviewed":{"type":"boolean","description":"The operator's own attestation that the supplied material may be used."}
                    }
                }),
                json!({
                    "type":"object","additionalProperties":false,
                    "required":["action","mode","practice_page_html"],
                    "properties":{
                        "action":{"const":"generate"},
                        "mode":{"const":"we_learn_page"},
                        "practice_page_html":{"type":"string","minLength":1,"maxLength":learning::MAX_PRACTICE_PAGE_HTML,"description":"A locally captured WE Learn practice page. Answer-bearing attributes are never read."},
                        "local_answer_key":learning::operator_key_schema(),
                        "rights_reviewed":{"type":"boolean"}
                    }
                })
            ]),
            "options":{},
            "output":learning::session_schema(PRACTICE_TYPE_LABEL)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CacheStatus, Response};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::collections::BTreeMap;

    fn response(url: &url::Url, body: &[u8], content_type: &str) -> Response {
        Response {
            url: url.as_str().to_owned(),
            status: 200,
            headers: BTreeMap::from([("content-type".to_owned(), content_type.to_owned())]),
            body: body.to_vec(),
            sha256: learning::sha256_hex(body),
            fetched_at_unix_ms: 1_700_000_000_000,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    fn tree_identity(url: &url::Url, body: &[u8], content_type: &str) -> learning::ObservedIdentity {
        learning::observed_identity(learning::Surface::Tree, url, body, Some(content_type))
    }

    fn raw_identity(url: &url::Url, body: &[u8], content_type: &str) -> learning::ObservedIdentity {
        learning::observed_identity(learning::Surface::Raw, url, body, Some(content_type))
    }

    /// A tree whose root object hash really covers the listed entries.
    const TREE: &[u8] = br#"{
        "sha":"4f9ade16a10867f7855a3e61c7fb3a1339c1abec",
        "url":"https://api.github.com/ignored",
        "truncated":false,
        "tree":[
            {"path":"LICENSE","mode":"100644","type":"blob","sha":"1123456789abcdef0123456789abcdef01234567","size":34523},
            {"path":"README.md","mode":"100644","type":"blob","sha":"2123456789abcdef0123456789abcdef01234567","size":2021},
            {"path":"welearn-answer-helper.user.js","mode":"100644","type":"blob","sha":"3123456789abcdef0123456789abcdef01234567","size":20266}
        ]
    }"#;

    #[test]
    fn inventory_lists_materials_and_refuses_answer_material() {
        let url = SOURCE.tree_url().unwrap();
        let identity = tree_identity(&url, TREE, "application/json; charset=utf-8");
        let output = learning::inventory_output(
            &SOURCE,
            TYPE_LABEL,
            &url,
            &response(&url, TREE, "application/json; charset=utf-8"),
            &identity,
            &classify,
        )
        .unwrap();
        assert_eq!(output["result"], "inventory_snapshot");
        assert_eq!(output["complete"], true);
        assert_eq!(output["entry_count"], 3);
        assert_eq!(output["entries"][0]["material_class"], "license");
        assert_eq!(output["entries"][1]["material_class"], "documentation");
        assert_eq!(output["entries"][2]["material_class"], "answer_material");
        assert_eq!(output["entries"][2]["retrieval_allowed"], false);
        assert_eq!(output["entries"][2]["mirror_allowed"], false);
        assert_eq!(output["entries"][1]["rights_reviewed"], false);
        assert_eq!(output["entries"][1]["rights_review_required"], true);
        assert_eq!(
            output["entries"][1]["license"]["operator_reference"],
            Value::Null
        );
        assert_eq!(output["license"]["independently_verified"], false);
        assert!(output["license"]["bound_license_blob_sha"].is_string());
        assert_eq!(output["fallback_reason"], Value::Null);
        assert_eq!(output["raw_evidence"], Value::Null);
    }

    #[test]
    fn immutable_blob_bytes_are_independently_verified() {
        // Git's well-known empty blob, not a copied upstream material.
        let sha = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
        let tree = "f93e3a1a1525fb5b91020da86e44810c87a2d7bc";
        let url = SOURCE.blob_url(sha).unwrap();
        assert!(url.as_str().ends_with(sha));
        assert!(!url.as_str().contains("master"));
        let identity = raw_identity(&url, b"", "application/octet-stream");
        let license = learning::verified_license(&SOURCE, &[]);
        let output = learning::verified_blob_output(&SOURCE, RAW_TYPE_LABEL, "README.md",
            &response(&url, b"", "application/octet-stream"),
            &identity,
            learning::MaterialClass::Documentation, tree, sha, &license, 0).unwrap();
        assert_eq!(output["result"], "raw_snapshot");
        assert_eq!(output["retrieval"]["verified_git_blob_sha"], sha);
        let vendor_identity = raw_identity(&url, b"", "application/vnd.github.raw+json");
        let vendor = learning::verified_blob_output(&SOURCE, RAW_TYPE_LABEL, "README.md",
            &response(&url, b"", "application/vnd.github.raw+json"),
            &vendor_identity,
            learning::MaterialClass::Documentation, tree, sha, &license, 0).unwrap();
        assert_eq!(vendor["result"], "raw_snapshot");
        assert_eq!(vendor["content_type"], "application/vnd.github.raw+json");
        assert_eq!(vendor["retrieval"]["verified_git_blob_sha"], sha);
        let replaced_identity = raw_identity(&url, b"changed branch bytes", "application/octet-stream");
        let replaced = learning::verified_blob_output(&SOURCE, RAW_TYPE_LABEL, "README.md",
            &response(&url, b"changed branch bytes", "application/octet-stream"),
            &replaced_identity,
            learning::MaterialClass::Documentation, tree, sha, &license, 16)
            .unwrap();
        assert_eq!(replaced["result"], "degraded");
        assert_eq!(replaced["fallback_reason"], "blob_identity_mismatch");
        assert_eq!(replaced["bytes"], Value::Null);
        assert_eq!(
            replaced["raw_evidence"]["data"],
            STANDARD.encode(b"changed branch bytes")
        );
    }

    #[test]
    fn a_blob_length_that_contradicts_the_inventory_is_refused() {
        let sha = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
        let tree = "f93e3a1a1525fb5b91020da86e44810c87a2d7bc";
        let url = SOURCE.blob_url(sha).unwrap();
        let identity = raw_identity(&url, b"", "application/octet-stream");
        let license = learning::verified_license(&SOURCE, &[]);
        let refused = learning::verified_blob_output(&SOURCE, RAW_TYPE_LABEL, "README.md",
            &response(&url, b"", "application/octet-stream"),
            &identity,
            learning::MaterialClass::Documentation, tree, sha, &license, 500)
            .unwrap();
        assert_eq!(refused["result"], "degraded");
        assert_eq!(refused["fallback_reason"], "blob_size_mismatch");
        assert_eq!(refused["bytes"], Value::Null);
    }

    #[test]
    fn a_tree_whose_objects_do_not_verify_is_never_admitted() {
        let url = SOURCE.tree_url().unwrap();
        // The empty tree with a listed README.md cannot be the root of that
        // listing: the root object hash does not cover the entry.
        let body = br#"{
            "sha":"4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "truncated":false,
            "tree":[
                {"path":"README.md","mode":"100644","type":"blob","sha":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391","size":0}
            ]
        }"#;
        let identity = tree_identity(&url, body, "application/json");
        assert!(identity.tree().is_none());
        let output = learning::inventory_output(&SOURCE, TYPE_LABEL, &url,
            &response(&url, body, "application/json"), &identity, &classify).unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["entries"], json!([]));
        assert_eq!(output["tree_sha"], Value::Null);
    }

    #[test]
    fn a_truncated_tree_is_never_admitted() {
        let url = SOURCE.tree_url().unwrap();
        let body = br#"{
            "sha":"4f9ade16a10867f7855a3e61c7fb3a1339c1abec",
            "truncated":true,
            "tree":[
                {"path":"LICENSE","mode":"100644","type":"blob","sha":"1123456789abcdef0123456789abcdef01234567","size":34523}
            ]
        }"#;
        let identity = tree_identity(&url, body, "application/json");
        assert!(identity.tree().is_none());
        assert_eq!(identity.tree_error(), Some("incomplete_tree"));
    }

    #[test]
    fn every_advertised_subtree_must_match_its_children() {
        let url = SOURCE.tree_url().unwrap();
        // The directory claims the empty-tree identity while listing a
        // descendant. No root identity can make that subtree proof valid.
        let body = br#"{
            "sha":"bbd69b1a62ef6a4258c2c2b9506951a791e141b8",
            "truncated":false,
            "tree":[
                {"path":"answers","mode":"040000","type":"tree","sha":"4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
                {"path":"answers/key.txt","mode":"100644","type":"blob","sha":"73d2307db42f448c677d732fb825d31afe5586ff","size":17}
            ]
        }"#;
        assert!(tree_identity(&url, body, "application/json").tree().is_none());
    }

    #[test]
    fn the_requested_vendor_json_tree_media_type_is_accepted() {
        let url = SOURCE.tree_url().unwrap();
        for mime in [
            "application/json",
            "application/vnd.github+json",
            "application/vnd.github+json; charset=utf-8",
        ] {
            let identity = tree_identity(&url, TREE, mime);
            assert!(identity.tree().is_some(), "{mime}");
        }
    }

    #[test]
    fn active_challenges_are_distinct_from_inert_source_and_prose() {
        for html in [
            "<form action='/captcha'><input name='code'></form>",
            "<iframe src='https://example.invalid/recaptcha'></iframe>",
            "<div class='cf-turnstile'></div>",
            "<input name='captcha'>",
            // A retained prefix is enough to observe the active widget;
            // transport still reports the independent read failure.
            "<html><form><input name='captcha'>partial",
        ] {
            assert_eq!(crate::html::assess_challenge_body(html.as_bytes(), Some("text/html"), true),
                crate::html::ChallengeAssessment::Detected, "{html}");
        }
        for html in [
            "<p>This course explains captcha and challenge protocols.</p>",
            "<!-- <input name='captcha'> -->",
            "<script>const html = '<input name=\"captcha\">';</script>",
            "<template><input name='captcha'></template>",
            "<input name='ordinary'>",
        ] {
            assert_eq!(crate::html::assess_challenge_body(html.as_bytes(), Some("text/html"), true),
                crate::html::ChallengeAssessment::Clear, "{html}");
        }
        assert!(crate::net::challenge_header("x-captcha", b"required"));
        assert_eq!(crate::html::assess_challenge_body(&[0xff, 0xfe], Some("text/html"), true),
            crate::html::ChallengeAssessment::Unreviewed);
    }

    #[test]
    fn observed_challenge_paces_but_never_latches() {
        use crate::governor::{Governor, Outcome, RequestKind};
        use std::os::unix::fs::DirBuilderExt;
        for (index, body, header, incomplete) in [
            (0, b"<input name='captcha'>".as_slice(), false, false),
            (1, b"ordinary".as_slice(), true, false),
            (2, b"<iframe src='/challenge'>".as_slice(), false, true),
        ] {
            let directory = std::env::temp_dir().join(format!("buaa-learning-challenge-{}-{}-{index}",
                std::process::id(), learning::unix_ms().unwrap()));
            std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let governor = Governor::isolated_for_test(&directory).unwrap();
            let lease = governor.try_acquire(RequestKind::Interactive).unwrap();
            let mut requests = 1;
            lease.finish(Outcome::Http { status: 200, retry_after: None,
                challenge: header || crate::html::assess_challenge_body(body, Some("text/html"), !incomplete)
                    == crate::html::ChallengeAssessment::Detected,
                network_failure: incomplete }).unwrap();
            if let Ok(second) = governor.try_acquire(RequestKind::Interactive) {
                requests += 1;
                second.finish_without_request().unwrap();
            }
            // Denied only by the request-interval gap; no safety latch.
            assert_eq!(requests, 1);
            assert!(!governor.status().unwrap().safety_latched);
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn cached_tri_state_refuses_before_processing() {
        use crate::governor::{Governor, RequestKind};
        use std::os::unix::fs::DirBuilderExt;
        for (index, body, mime, header, expected, latched) in [
            (0, b"ordinary material".as_slice(), "text/plain", false, None, false),
            (1, b"\xff\xfe".as_slice(), "text/html", false, Some("response_safety_unreviewed"), false),
            (2, b"<input name=captcha>".as_slice(), "text/html", false, Some("safety_latched"), true),
            (3, b"ordinary material".as_slice(), "text/plain", true, Some("safety_latched"), true),
            (4, b"\xff\x00binary".as_slice(), "application/vnd.github.raw+json", false, None, false),
            (5, b"\xff\x00binary".as_slice(), "application/octet-stream", false, None, false),
        ] {
            let directory = std::env::temp_dir().join(format!("buaa-learning-cache-{}-{}-{index}",
                std::process::id(), learning::unix_ms().unwrap()));
            std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let governor = Governor::isolated_for_test(&directory).unwrap();
            let lease = governor.try_acquire(RequestKind::Interactive).unwrap();
            let url = SOURCE.tree_url().unwrap();
            let mut retained = response(&url, body, mime);
            retained.cache_status = CacheStatus::Hit;
            if header { retained.headers.insert("cf-mitigated".into(), "challenge".into()); }
            let mut processed = false;
            let identity = learning::observed_identity(
                learning::Surface::Tree,
                &url,
                body,
                Some(mime),
            );
            let result = learning::process_cached(
                learning::Surface::Tree,
                &retained,
                &identity,
                learning::CacheAdmission::CookieReviewed,
                lease,
                |_, _| {
                    processed = true;
                    Ok(())
                },
            );
            assert_eq!(result.err().map(|error| error.code), expected);
            assert_eq!(processed, expected.is_none());
            assert!(!governor.status().unwrap().safety_latched, "{index}");
            let _ = latched;
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn initial_cached_challenges_refuse_without_reuse() {
        let url = SOURCE.tree_url().unwrap();
        for (body, mime, expected, _publish_flag) in [
            (b"<input name=captcha>".as_slice(), "text/html", Some("safety_latched"), true),
            (b"\xff\xfe".as_slice(), "text/html", Some("response_safety_unreviewed"), false),
            (b"ordinary".as_slice(), "text/plain", None, false),
        ] {
            let retained = response(&url, body, mime);
            let identity = tree_identity(&url, body, mime);
            let result = learning::review_initial_cache(
                learning::Surface::Tree, &url, &retained, &identity,
            );
            assert_eq!(result.err().map(|error| error.code), expected);
            let _ = _publish_flag;
        }
        // Headers remain authoritative even for an identity-bound source.
        let sha = learning::git_blob_sha(b"ordinary", 40);
        let url = SOURCE.blob_url(&sha).unwrap();
        let mut retained = response(&url, b"ordinary", "application/vnd.github.raw+json");
        retained.headers.insert("cf-mitigated".into(), "challenge".into());
        let identity = raw_identity(&url, b"ordinary", "application/vnd.github.raw+json");
        let error = learning::review_initial_cache(
            learning::Surface::Raw, &url, &retained, &identity,
        ).unwrap_err();
        assert_eq!(error.code, "safety_latched");
    }

    #[test]
    fn unsafe_raw_fallback_is_withheld_but_safe_evidence_remains_exact() {
        let url = SOURCE.tree_url().unwrap();
        for (body, mime, expected) in [
            (br#"{"token":"private-token"}"#.as_slice(), "application/json", "sensitive_response_withheld"),
            (br#"{"accessToken":"private-token"}"#.as_slice(), "application/vnd.github+json", "sensitive_response_withheld"),
            (br#"{"client_secret":"private-secret","client_secret":null}"#.as_slice(), "application/json", "sensitive_response_withheld"),
            (br#"{"to\u006ben":"private-token"}"#.as_slice(), "application/json", "sensitive_response_withheld"),
            (br#"{"cookie":"private-cookie"}"#.as_slice(), "application/json", "sensitive_response_withheld"),
            (b"<input name=password value=private-password>".as_slice(), "text/html", "sensitive_response_withheld"),
            (b"<input name=captcha value=private-answer>".as_slice(), "text/html", "safety_latched"),
            (b"\xff\xfe".as_slice(), "text/html", "response_safety_unreviewed"),
        ] {
            let identity = tree_identity(&url, body, mime);
            let error = learning::inventory_output(&SOURCE, TYPE_LABEL, &url,
                &response(&url, body, mime), &identity, &classify).unwrap_err();
            assert_eq!(error.code, expected);
            assert!(!format!("{error:?}").contains("private-"));
        }
        let body = br#"{"sha":"invalid","tree":[],"truncated":false}"#;
        let identity = tree_identity(&url, body, "application/json");
        let output = learning::inventory_output(&SOURCE, TYPE_LABEL, &url,
            &response(&url, body, "application/json"), &identity, &classify).unwrap();
        assert_eq!(output["raw_evidence"]["data"], STANDARD.encode(body));
        assert_eq!(output["retrieval"]["source_url"], url.as_str());
    }

    #[test]
    fn a_malformed_tree_degrades_with_the_original_bytes() {
        let url = SOURCE.tree_url().unwrap();
        let body = br#"{"sha":"not-a-digest","tree":[],"truncated":false}"#;
        let original = response(&url, body, "application/json");
        let identity = tree_identity(&url, body, "application/json");
        assert_eq!(identity.tree_error(), Some("upstream_parse"));
        let output = learning::inventory_output(&SOURCE, TYPE_LABEL, &url, &original, &identity, &classify).unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["fallback_reason"], "upstream_parse");
        assert_eq!(output["entries"], json!([]));
        let evidence = &output["raw_evidence"];
        assert_eq!(evidence["content_type"], "application/json");
        assert_eq!(evidence["byte_length"], body.len());
        assert_eq!(evidence["sha256"], learning::sha256_hex(body));
        assert_eq!(evidence["data"], STANDARD.encode(body));
        assert_eq!(evidence["fallback_reason"], "upstream_parse");

        let html = response(&url, b"<html>not a tree</html>", "text/html");
        let html_identity = tree_identity(&url, b"<html>not a tree</html>", "text/html");
        assert_eq!(html_identity.tree_error(), Some("unexpected_content"));
        let degraded = learning::inventory_output(&SOURCE, TYPE_LABEL, &url, &html, &html_identity, &classify).unwrap();
        assert_eq!(degraded["fallback_reason"], "unexpected_content");
        assert_eq!(degraded["raw_evidence"]["content_type"], "text/html");
    }

    #[test]
    fn the_rights_gate_precedes_any_admission() {
        let denied = parse_search_input(r#"{"query":"readme","rights_reviewed":false}"#)
            .err()
            .unwrap();
        assert_eq!(denied.code, "authorization_required");
        let missing = parse_search_input(r#"{"query":"readme"}"#).err().unwrap();
        assert_eq!(missing.code, "authorization_required");
        let refused = parse_fetch_input(r#"{"path":"README.md","rights_reviewed":false}"#)
            .err()
            .unwrap();
        assert_eq!(refused.code, "authorization_required");
        for path in ["", "/absolute", "../secret", "a/./b", "a//b", "a\\b"] {
            let request = json!({"path": path, "rights_reviewed": true}).to_string();
            assert_eq!(
                parse_fetch_input(&request).err().unwrap().code,
                "invalid_input",
                "path {path:?}"
            );
        }
        // A download must name the exact reviewed immutable object.
        let unattested = parse_fetch_input(r#"{"path":"README.md","rights_reviewed":true}"#)
            .err()
            .unwrap();
        assert_eq!(unattested.code, "authorization_required");
        let partial = parse_fetch_input(
            r#"{"path":"README.md","rights_reviewed":true,"tree_sha":"4f9ade16a10867f7855a3e61c7fb3a1339c1abec"}"#,
        )
        .err()
        .unwrap();
        assert_eq!(partial.code, "invalid_input");
        let accepted = parse_fetch_input(
            r#"{"path":"README.md","rights_reviewed":true,"tree_sha":"4f9ade16a10867f7855a3e61c7fb3a1339c1abec","blob_sha":"2123456789abcdef0123456789abcdef01234567","mode":"100644","size":2021}"#,
        )
        .unwrap();
        assert_eq!(accepted.path, "README.md");
        assert_eq!(accepted.mode.as_deref(), Some("100644"));
        let wrong_mode = parse_fetch_input(
            r#"{"path":"README.md","rights_reviewed":true,"tree_sha":"4f9ade16a10867f7855a3e61c7fb3a1339c1abec","blob_sha":"2123456789abcdef0123456789abcdef01234567","mode":"120000","size":2021}"#,
        )
        .err()
        .unwrap();
        assert_eq!(wrong_mode.code, "invalid_input");
    }

    #[test]
    fn a_rejected_blob_is_never_reusable_material() {
        let sha = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
        let tree = "f93e3a1a1525fb5b91020da86e44810c87a2d7bc";
        let url = SOURCE.blob_url(sha).unwrap();
        let identity = raw_identity(&url, b"changed branch bytes", "application/octet-stream");
        assert_ne!(identity.blob_sha(), Some(sha));
        let license = learning::verified_license(&SOURCE, &[]);
        let refused = learning::verified_blob_output(&SOURCE, RAW_TYPE_LABEL, "README.md",
            &response(&url, b"changed branch bytes", "application/octet-stream"),
            &identity,
            learning::MaterialClass::Documentation, tree, sha, &license, 16)
            .unwrap();
        assert_eq!(refused["result"], "degraded");
        assert_eq!(refused["fallback_reason"], "blob_identity_mismatch");
        assert_eq!(refused["bytes"], Value::Null);
    }

    #[test]
    fn a_raw_html_blob_is_reviewed_as_source_not_refused_as_a_mime_mismatch() {
        // Git's blob identity for these exact bytes.
        let body = b"<html><body>hello</body></html>";
        let sha = learning::git_blob_sha(body, 40);
        let url = SOURCE.blob_url(&sha).unwrap();
        let identity = raw_identity(&url, body, "application/vnd.github.raw+json");
        assert_eq!(identity.blob_sha(), Some(sha.as_str()));
        let license = learning::verified_license(&SOURCE, &[]);
        let output = learning::verified_blob_output(&SOURCE, RAW_TYPE_LABEL, "README.md",
            &response(&url, body, "application/vnd.github.raw+json"),
            &identity,
            learning::MaterialClass::Documentation,
            "f93e3a1a1525fb5b91020da86e44810c87a2d7bc",
            &sha,
            &license,
            body.len() as u64)
        .unwrap();
        assert_eq!(output["result"], "raw_snapshot");
        assert_eq!(output["content_type"], "application/vnd.github.raw+json");
    }

    #[test]
    fn a_root_level_answer_directory_is_answer_material() {
        assert_eq!(classify("answers/key.txt"), learning::MaterialClass::AnswerMaterial);
        assert_eq!(classify("docs/answers/key.txt"), learning::MaterialClass::AnswerMaterial);
        assert_eq!(classify("README.md"), learning::MaterialClass::Documentation);
        assert!(learning::answer_path_component("answers/key.txt"));
        assert!(learning::answer_path_component("docs/answers/key.txt"));
        assert!(!learning::answer_path_component("docs/answering-notes.md"));
    }

    #[test]
    fn an_answer_directory_in_the_admitted_tree_is_refused_as_material() {
        let url = SOURCE.tree_url().unwrap();
        // A root-level answers/ directory whose blob holds the answer text.
        let body = br#"{
            "sha":"bbd69b1a62ef6a4258c2c2b9506951a791e141b8",
            "truncated":false,
            "tree":[
                {"path":"answers","mode":"040000","type":"tree","sha":"d7affbb485d4324f70570e8730f5b764308313a2"},
                {"path":"answers/key.txt","mode":"100644","type":"blob","sha":"73d2307db42f448c677d732fb825d31afe5586ff","size":17}
            ]
        }"#;
        let identity = tree_identity(&url, body, "application/json");
        let admitted = identity.tree().expect("the tree verifies");
        assert_eq!(
            admitted.entries.iter().find(|entry| entry.path == "answers/key.txt")
                .map(|entry| entry.sha.as_str()),
            Some("73d2307db42f448c677d732fb825d31afe5586ff")
        );
        assert!(learning::blob_is_answer_material(
            &admitted.entries,
            "73d2307db42f448c677d732fb825d31afe5586ff",
            &classify
        ));
    }

    #[test]
    fn a_license_claim_is_bound_to_the_admitted_license_object() {
        let url = SOURCE.tree_url().unwrap();
        let identity = tree_identity(&url, TREE, "application/json");
        let admitted = identity.tree().expect("the tree verifies");
        let license = learning::verified_license(&SOURCE, &admitted.entries);
        assert_eq!(
            license["operator_reference"],
            Value::Null
        );
        assert_eq!(
            license["bound_license_blob_sha"],
            "1123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(license["independently_verified"], false);
        // A tree without a license object claims nothing.
        let unknown = learning::verified_license(&SOURCE, &[]);
        assert_eq!(unknown["operator_reference"], Value::Null);
        assert_eq!(unknown["bound_license_blob_sha"], Value::Null);
        assert_eq!(unknown["independently_verified"], false);
    }

    #[test]
    fn the_inventory_never_advertises_a_mutable_branch_url() {
        let url = SOURCE.tree_url().unwrap();
        let identity = tree_identity(&url, TREE, "application/json");
        let output = learning::inventory_output(&SOURCE, TYPE_LABEL, &url,
            &response(&url, TREE, "application/json"), &identity, &classify).unwrap();
        for entry in output["entries"].as_array().unwrap() {
            let advertised = entry["url"].as_str().unwrap_or("");
            assert!(!advertised.contains("/master/"), "{}", entry["path"]);
            if entry["retrieval_allowed"] == json!(true) {
                assert!(advertised.contains("/git/blobs/"), "{}", entry["path"]);
            } else {
                assert_eq!(entry["url"], Value::Null, "{}", entry["path"]);
            }
        }
    }

    #[test]
    fn a_blob_shared_with_an_answer_path_is_never_retrievable() {
        let answer_blob = "73d2307db42f448c677d732fb825d31afe5586ff";
        let url = SOURCE.tree_url().unwrap();
        // README.md and answers.txt are the same immutable blob.
        let body = br#"{
            "sha":"1e2537d36a947027bba1085f20727a9b1a626f3e",
            "truncated":false,
            "tree":[
                {"path":"README.md","mode":"100644","type":"blob","sha":"73d2307db42f448c677d732fb825d31afe5586ff","size":17},
                {"path":"answers.txt","mode":"100644","type":"blob","sha":"73d2307db42f448c677d732fb825d31afe5586ff","size":17}
            ]
        }"#;
        let identity = tree_identity(&url, body, "application/json");
        let admitted = identity.tree().expect("the tree verifies");
        assert!(learning::blob_is_answer_material(
            &admitted.entries,
            answer_blob,
            &classify
        ));
    }

    #[test]
    fn search_matches_metadata_only_and_never_content() {
        let url = SOURCE.tree_url().unwrap();
        let identity = tree_identity(&url, TREE, "application/json");
        let output = learning::search_output(
            &SOURCE,
            SEARCH_TYPE_LABEL,
            &url,
            &response(&url, TREE, "application/json"),
            &identity,
            "answer",
            &classify,
        )
        .unwrap();
        assert_eq!(output["result"], "search_snapshot");
        assert_eq!(output["match_count"], 1);
        assert_eq!(output["matches"][0]["path"], "welearn-answer-helper.user.js");
        assert_eq!(output["matches"][0]["retrieval_allowed"], false);
    }

    #[test]
    fn a_raw_snapshot_reports_the_observed_content_type_and_digest() {
        let path = "README.md";
        let body = b"fixture material";
        let sha = learning::git_blob_sha(body, 40);
        let url = SOURCE.blob_url(&sha).unwrap();
        let identity = raw_identity(&url, body, "text/plain; charset=utf-8");
        let license = learning::verified_license(&SOURCE, &[]);
        let output = learning::verified_blob_output(&SOURCE, RAW_TYPE_LABEL, path,
            &response(&url, body, "text/plain; charset=utf-8"),
            &identity,
            learning::MaterialClass::Documentation,
            "f93e3a1a1525fb5b91020da86e44810c87a2d7bc",
            &sha,
            &license,
            body.len() as u64)
        .unwrap();
        assert_eq!(output["result"], "raw_snapshot");
        assert_eq!(output["bytes"], STANDARD.encode(body));
        assert_eq!(output["byte_length"], body.len());
        assert_eq!(output["sha256"], learning::sha256_hex(body));
        assert_eq!(output["content_type"], "text/plain");

        // A byte-exact blob with a media type this client cannot admit keeps
        // its exact bytes as safe raw evidence and admits no material.
        let binary = b"\x00\x01";
        let binary_sha = learning::git_blob_sha(binary, 40);
        let binary_url = SOURCE.blob_url(&binary_sha).unwrap();
        let binary_identity = raw_identity(&binary_url, binary, "application/x-unknown-binary");
        let degraded = learning::verified_blob_output(&SOURCE, RAW_TYPE_LABEL, path,
            &response(&binary_url, binary, "application/x-unknown-binary"),
            &binary_identity,
            learning::MaterialClass::Documentation,
            "f93e3a1a1525fb5b91020da86e44810c87a2d7bc",
            &binary_sha,
            &license,
            binary.len() as u64)
        .unwrap();
        assert_eq!(degraded["result"], "degraded");
        assert_eq!(degraded["bytes"], Value::Null);
        assert_eq!(degraded["content_type"], Value::Null);
        assert_eq!(degraded["fallback_reason"], "unexpected_content");
        assert_eq!(
            degraded["raw_evidence"]["content_type"],
            "application/x-unknown-binary"
        );
        assert_eq!(degraded["raw_evidence"]["data"], STANDARD.encode(binary));
    }

    #[test]
    fn an_imported_practice_page_never_carries_an_answer_value() {
        let html = r#"<html><body>
            <div class="stem">Which hosts serve WE Learn courseware?</div>
            <ul data-controltype="Radio">
                <li data-solution="B">welearn.sflep.com</li>
                <li data-solution="A">centercourseware.sflep.com</li>
            </ul>
            <span class="wl-answer-helper-hint">Answer: B</span>
            </body></html>"#;
        let (questions, scan) = questions_from_practice_page(html).unwrap();
        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].kind, "choice");
        assert_eq!(questions[0].options.as_ref().unwrap().len(), 2);
        assert_eq!(questions[0].local_self_check_key, None);
        assert_eq!(questions[0].key_source, "none");
        let rendered = serde_json::to_string(&questions).unwrap();
        assert!(!rendered.contains("data-solution"));
        assert!(rendered.contains("welearn.sflep.com"));
        assert_eq!(scan["answer_attribute_occurrences"], 2);
        assert_eq!(scan["answer_attribute_names"][0], "data-solution");
        assert_eq!(scan["dropped_answer_text_fragments"], 1);
    }

    #[test]
    fn the_practice_session_never_claims_completion_or_an_official_grade() {
        let generated = practice(
            r#"{"action":"generate","mode":"cloze","material_text":"The gyroscope keeps a stable axis in flight. Angular momentum resists change of orientation.","count":2,"rights_reviewed":true}"#,
        )
        .unwrap();
        assert_eq!(generated["type"], PRACTICE_TYPE_LABEL);
        assert_eq!(generated["official_grade"], Value::Null);
        assert_eq!(generated["completion_reported"], false);
        assert_eq!(generated["submission_state"], "not_submitted");
        assert_eq!(generated["questions"].as_array().unwrap().len(), 2);

        let question_id = generated["questions"][0]["question_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let key = generated["questions"][0]["local_self_check_key"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let answered = practice(
            &json!({
                "action": "answer",
                "session": generated,
                "answers": [{"question_id": question_id, "text": key}]
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(answered["results"], Value::Null);
        assert_eq!(answered["answers"].as_array().unwrap().len(), 1);

        let checked = practice(&json!({"action": "check", "session": answered}).to_string()).unwrap();
        assert_eq!(checked["results"]["authority"], "local_self_check");
        assert_eq!(checked["results"]["official_grade"], Value::Null);
        assert_eq!(checked["results"]["local_match_count"], 1);
        assert_eq!(checked["results"]["local_unanswered_count"], 1);
        assert_eq!(checked["results"]["completion_reported"], false);
        assert_eq!(checked["results"]["completion_state"], "local_practice_only");
    }

    #[test]
    fn an_answer_bearing_session_is_refused() {
        let forged = json!({
            "schema_version": 1,
            "type": PRACTICE_TYPE_LABEL,
            "result": "practice_session",
            "session_id": "0000000000000000000000000000000000000000000000000000000000000000",
            "authority": "local_only",
            "official_grade": "A",
            "official_result": "passed",
            "submission_state": "not_submitted",
            "completion_reported": false,
            "rights_reviewed": false,
            "practice_source": {
                "kind": "cloze",
                "origin": "operator_local_material",
                "rights_reviewed": false,
                "digest": "0000000000000000000000000000000000000000000000000000000000000000",
                "scan": Value::Null
            },
            "questions": [{
                "question_id": "q1",
                "kind": "cloze",
                "prompt": "A prompt.",
                "options": Value::Null,
                "blanks": Value::Null,
                "local_self_check_key": ["answer"],
                "key_source": "local_material"
            }],
            "answers": [],
            "results": Value::Null
        });
        let refused = practice(&json!({"action": "check", "session": forged}).to_string())
            .err()
            .unwrap();
        assert_eq!(refused.code, "invalid_input");
    }

    #[test]
    fn the_schema_matches_the_accepted_sets() {
        let contract = schema();
        assert_eq!(
            contract["search"]["input"]["properties"]["rights_reviewed"]["const"],
            true
        );
        assert_eq!(
            contract["fetch"]["input"]["properties"]["rights_reviewed"]["const"],
            true
        );
        assert_eq!(
            contract["materials"]["output"]["properties"]["rights_reviewed"]["const"],
            false
        );
        assert!(contract["materials"]["output"]["oneOf"].is_array());
        assert!(contract["fetch"]["output"]["oneOf"].is_array());
        assert_eq!(
            contract["practice"]["input"]["oneOf"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
    }
}
