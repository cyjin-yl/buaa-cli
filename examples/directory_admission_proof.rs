//! Temporary native consumer of the real buaa_cli library (not the CLI).
//!
//! Install as examples/directory_admission_proof.rs beside the temporary
//! plumbing patch. Never use --test or global --cfg test. The integration owner
//! alone schedules builds/runs after reconciling bg268 and the source freeze.
//!
//! RED (baseline ebe6f823): --features directory-admission-proof
//! GREEN (candidate): --features directory-admission-proof-candidate
//!
//! Both builds use a NEW worktree-owned target, --locked --offline -j 1 and
//! scripts/cargo-locked under the existing agent-heavy foreground guardian,
//! preserving the existing 2 GiB ceiling. Suggested environment, not executed
//! by this artifact's author:
//! CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
//! CARGO_PROFILE_DEV_CODEGEN_UNITS=256 CARGO_TARGET_DIR="$PWD/target/directory-proof-{red,green}"
//! Run only the absolute executable from that build's Cargo artifact record.
//! Remove both proof features, example declaration/source and all feature-only
//! wrappers/cfg extensions afterward, then the parent builds the clean library
//! normally into another NEW worktree-owned target with the same guards.
//!
//! Usage: directory_admission_proof [--list] [CASE [SUBCASE]]
//! Every subcase is self-contained, so RED can select behavioral subcases.
//! No args runs exactly 57 subcases across the six named cases. All GREEN
//! assertions, not merely process launch, must complete; a zero-match filter,
//! panic, infrastructure failure, divergence, or wrong case count exits 1.
//! DIVERGENT marks an actually observed behavior differing from the candidate
//! contract; unrelated setup/network errors are FAIL, never behavioral RED.
//!
//! All resources are synthetic and private to fresh /tmp fixture roots. No
//! ordinary organizations::list(mode), HOME substitution, passwd-home cache,
//! production governor, campus endpoint, credential or existing private cache
//! is opened, even for a before/after snapshot.

use buaa_cli::governor::{Governor, RequestKind};
use buaa_cli::net::directory_proof as proof;
use buaa_cli::net::{ArchiveClient, CacheMode, Error};
use buaa_cli::organizations;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use fs2::FileExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;

type P<T = ()> = Result<T, String>;
const URL: &str = "https://www.buaa.edu.cn/jgsz/jxkyjg02.htm";
const ROBOTS: &str = "https://www.buaa.edu.cn/robots.txt";
const TARGET_PATH: &str = "/jgsz/jxkyjg02.htm";
const WAIT: Duration = Duration::from_secs(15);
const ALLOW: &[u8] = b"User-agent: *\nAllow: /\n";
const EXPECTED_SUBCASES: usize = 57;
const CASES: [&str; 6] = [
    "public-parser", "snapshot-scope", "safe-drift", "admission", "robots-policy", "governor",
];
const OPAQUE: &str = "opaque_fixture_7ac194";

const VALID: &str = concat!(
    "<!doctype html><html><title>Directory</title><body>",
    "<div class='kyjg-box'><div class='kyjg-tit'><h3>Group A</h3></div><div class='kyjg-bd'>",
    "<a href=' http://rse.buaa.edu.cn '>Alpha</a>",
    "<a class='xbt' href='https://hidden.buaa.edu.cn/'>Hidden</a>",
    "<a>Missing</a><a href='javascript:void(0)'>No page</a>",
    "</div></div>",
    "<div class='kyjg-box'><div class='kyjg-tit'><h3>Group B</h3></div><div class='kyjg-bd'>",
    "<a href='/relative'>Relative</a>",
    "<ul><li hidden><a href='https://zeta.buaa.edu.cn/'>Zeta</a></li></ul>",
    "</div></div></body></html>"
);

fn drift() -> Vec<u8> {
    concat!(
        "<!doctype html><html><title>Public page</title>\r\n<body>\r\n",
        "<p>北京航空航天大学&nbsp;&amp;  repeated   spaces</p>\r\n",
        "<script>var probe = 1;</script><!-- neutral rendering note -->\r\n",
        "</body></html>"
    ).as_bytes().to_vec()
}

fn one_member(parent: &str, child: &str) -> String {
    format!(
        "<html><title>D</title><div class='kyjg-box'><div class='kyjg-tit'><h3>G</h3></div><div class='kyjg-bd'><div {parent}><a {child} href='https://fixture.example/'>Member</a></div></div></div></html>"
    )
}

fn check(condition: bool, message: impl Into<String>) -> P {
    if condition { Ok(()) } else { Err(message.into()) }
}
fn delta(condition: bool, message: impl Into<String>) -> P {
    if condition { Ok(()) } else { Err(format!("DIVERGENT: {}", message.into())) }
}
fn code<T>(result: Result<T, Error>, expected: &str, divergent: bool) -> P {
    match result {
        Err(error) if error.code == expected => Ok(()),
        Err(error) => {
            let message = format!("expected error {expected}, received {}", error.code);
            // Only this known baseline difference is a behavioral error-code
            // RED. Transport/cache/governor failures are never substitutes
            // for the requested refusal or an expected successful fetch.
            if divergent && expected == "invalid_304" && error.code == "unavailable" {
                delta(false, message)
            } else {
                check(false, message)
            }
        }
        Ok(_) => {
            let message = format!("expected error {expected}, received success");
            if divergent { delta(false, message) } else { check(false, message) }
        }
    }
}
fn library<T>(result: Result<T, Error>) -> P<T> {
    result.map_err(|e| format!("library operation failed: {}", e.code))
}
fn sha(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }

#[derive(Clone)]
struct Request { at: Instant, head: String }
impl Request {
    fn path(&self) -> &str { self.head.split_whitespace().nth(1).unwrap_or_default() }
    fn header(&self, key: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(key).then(|| value.trim())
        })
    }
}

struct Reply { path: &'static str, status: u16, headers: String, body: Vec<u8> }
impl Reply {
    fn robots(status: u16, body: &[u8]) -> Self {
        Self { path: "/robots.txt", status, headers: String::new(), body: body.to_vec() }
    }
    fn target(status: u16, headers: &str, body: &[u8]) -> Self {
        Self { path: TARGET_PATH, status, headers: headers.to_owned(), body: body.to_vec() }
    }
}

/// Real TCP server, following net.rs's bounded request-head and nonblocking
/// listener pattern. Handler errors and thread panics propagate on join.
struct Server {
    address: SocketAddr,
    requests: mpsc::Receiver<Request>,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<P>>,
}
impl Server {
    fn new(mut handler: impl FnMut(&mut TcpStream, &Request) -> P + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind synthetic loopback server");
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));
        let (tx, requests) = mpsc::channel();
        let worker_stop = Arc::clone(&stop);
        let worker_count = Arc::clone(&count);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, peer)) => {
                        check(peer.ip().is_loopback(), "non-loopback fixture peer")?;
                        socket.set_read_timeout(Some(WAIT)).map_err(|e| e.to_string())?;
                        socket.set_write_timeout(Some(WAIT)).map_err(|e| e.to_string())?;
                        let mut bytes = Vec::new();
                        let mut byte = [0u8; 1];
                        while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 32 * 1024 {
                            match socket.read(&mut byte) {
                                Ok(1) => bytes.push(byte[0]),
                                _ => break,
                            }
                        }
                        check(bytes.ends_with(b"\r\n\r\n"), "incomplete/oversize request head")?;
                        let request = Request {
                            at: Instant::now(),
                            head: String::from_utf8(bytes).map_err(|e| e.to_string())?,
                        };
                        check(request.header("cookie").is_none(), "fixture transmitted Cookie")?;
                        worker_count.fetch_add(1, Ordering::SeqCst);
                        let _ = tx.send(request.clone());
                        handler(&mut socket, &request)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => return Err(format!("loopback accept failed: {error}")),
                }
            }
            Ok(())
        });
        Self { address, requests, count, stop, worker: Some(worker) }
    }
    fn script(replies: Vec<Reply>) -> Self {
        let mut replies = VecDeque::from(replies);
        Self::new(move |socket, request| {
            let reply = replies.pop_front().ok_or("unexpected extra request".to_owned())?;
            check(request.path() == reply.path, format!("unexpected request path {}", request.path()))?;
            send_reply(socket, &reply);
            Ok(())
        })
    }
    fn count(&self) -> usize { self.count.load(Ordering::SeqCst) }
    fn take(&self) -> P<Request> {
        self.requests.recv_timeout(WAIT).map_err(|_| "missing terminal loopback request receipt".to_owned())
    }
    fn finish(&mut self) -> P {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| "server thread panicked".to_owned())??;
        }
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            if thread::panicking() { eprintln!("server cleanup failure: {error}"); }
            else { panic!("server failed: {error}"); }
        }
    }
}
fn send_reply(socket: &mut TcpStream, reply: &Reply) {
    let headers = format!(
        "HTTP/1.1 {} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n{}\r\n",
        reply.status, reply.body.len(), reply.headers,
    );
    // Early-refusal clients may deliberately close without reading the body.
    let _ = socket.write_all(headers.as_bytes());
    let _ = socket.write_all(&reply.body);
}
fn open(fixture: &proof::ProofFixture, server: &Server, mode: CacheMode) -> P<ArchiveClient> {
    library(fixture.organizations_client(mode, server.address))
}
fn cache_path(fixture: &proof::ProofFixture, url: &str, current: bool) -> PathBuf {
    fixture.cache_directory().join(format!("{}{}.json", sha(url.as_bytes()), if current { ".v2" } else { "" }))
}
fn file_bytes(path: &Path) -> P<Vec<u8>> { std::fs::read(path).map_err(|e| format!("fixture file read: {e}")) }
fn body(record: &Value) -> P<Vec<u8>> {
    STANDARD.decode(record["body_base64"].as_str().ok_or("missing cached base64 body")?)
        .map_err(|_| "invalid cached base64 body".to_owned())
}
fn record(path: &Path, version: u8) -> P<Value> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    // SAFETY: geteuid has no preconditions.
    check(metadata.is_file() && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o7777 == 0o600 && metadata.nlink() == 1,
        "fixture cache is not one private regular file")?;
    let value: Value = serde_json::from_slice(&file_bytes(path)?).map_err(|e| e.to_string())?;
    let fields = ["version", "url", "status", "headers", "body_base64", "sha256",
        "fetched_at_unix_ms", "immutable", "revalidated_at_unix_ms", "revalidation_status", "etag", "last_modified"];
    check(value.as_object().is_some_and(|o| o.len() == fields.len() && fields.iter().all(|f| o.contains_key(*f))),
        "unexpected complete cache record shape")?;
    check(value["version"] == version, "wrong cache record version")?;
    check(value["sha256"] == sha(&body(&value)?), "independent cache body digest mismatch")?;
    Ok(value)
}
fn no_target_files(fixture: &proof::ProofFixture) -> P {
    check(!cache_path(fixture, URL, false).exists() && !cache_path(fixture, URL, true).exists(),
        "refused directory response left a cache entry")
}

/// Literal pre-change record, intentionally NOT saved through the candidate's
/// current-v2 producer. Used only for the legacy-cache cases, never to seed a
/// transport/persistence proof's observed directory response.
fn seed_v1(fixture: &proof::ProofFixture, content_type: Option<&str>, bytes: &[u8], opaque_headers: bool, immutable: bool) -> P<Vec<u8>> {
    let mut headers = serde_json::Map::new();
    if let Some(value) = content_type { headers.insert("content-type".into(), json!(value)); }
    let etag = if opaque_headers { format!("\"{OPAQUE}\"") } else { "\"legacy-validator\"".to_owned() };
    headers.insert("etag".into(), json!(etag.clone()));
    headers.insert("last-modified".into(), json!("Wed, 03 Jan 2024 03:04:05 GMT"));
    // A legacy record predates the fixture run: recovery must present a newer
    // fetch fact, never relabel the retained legacy capture time.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_millis() as u64;
    let fetched = now.saturating_sub(60_000);
    let value = json!({"version":1,"url":URL,"status":200,"headers":headers,
        "body_base64":STANDARD.encode(bytes),"sha256":sha(bytes),"fetched_at_unix_ms":fetched,
        "immutable":immutable,"revalidated_at_unix_ms":null,"revalidation_status":null,
        "etag":etag,"last_modified":"Wed, 03 Jan 2024 03:04:05 GMT"});
    let mut serialized = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    serialized.push(b'\n');
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(cache_path(fixture, URL, false)).map_err(|e| e.to_string())?;
    file.write_all(&serialized).and_then(|()| file.sync_all()).map_err(|e| e.to_string())?;
    Ok(serialized)
}
fn settled(fixture: &proof::ProofFixture) -> P<Governor> {
    let governor = library(fixture.isolated_governor())?;
    let status = governor.status().map_err(|e| format!("settled governor: {e}"))?;
    check(!status.safety_latched && status.consecutive_network_failures == 0 && status.cooldown_wait.is_zero(),
        "body/cookie refusal manufactured a latch or network-failure cooldown")?;
    check(status.request_interval == Duration::from_secs(5)
        && status.background_interval == Duration::from_secs(15 * 60), "fixture lowered safety defaults")?;
    Ok(governor)
}
fn fallback(value: &Value, bytes: &[u8], unknown: bool) -> P {
    check(value["type"] == "organization_directory" && value["entries"] == json!([]), "fallback type/entries")?;
    check(value["result"] == "fallback", "missing fallback result")?;
    check(value["authority"] == json!({"publisher":"北京航空航天大学","directory_label":"教学科研机构","source_url":URL}),
        "fallback authority")?;
    check(value["fallback_reason"] == if unknown { "organization_directory_provenance_unknown" } else { "organization_directory_selector_contract" },
        "wrong fallback reason")?;
    check(value["content_type"] == "text/html", "fallback MIME is not canonical public-safe text/html")?;
    check(value["raw_html_sha256"] == sha(bytes) && value["body_byte_length"] == bytes.len(), "fallback digest/length")?;
    check(value["retrieval"]["source_url"] == URL && value["retrieval"]["response_body_sha256"] == sha(bytes)
        && value["retrieval"]["response_body_byte_length"] == bytes.len(), "retrieval body/source facts")?;
    check(value["retrieval"]["http"] == json!({"status":200,"headers":{},"headers_withheld":true}),
        "fallback must withhold arbitrary captured header values")?;
    if unknown {
        check(value["raw_html"].is_null() && value["raw_withheld"] == true
            && value["raw_withheld_reason"] == "cookie_provenance_unavailable", "legacy raw disclosure")?;
        check(value.get("document_title").is_none() && value.get("categories").is_none(), "legacy disclosed structured strings")?;
        check(!value.to_string().contains(OPAQUE) && !value.to_string().contains(&STANDARD.encode(bytes)),
            "legacy output echoed opaque source/header payload")?;
    } else {
        check(value["raw_withheld"] == false && value["raw_withheld_reason"].is_null(), "safe raw remains withheld")?;
        let decoded = STANDARD.decode(value["raw_html"].as_str().ok_or("safe fallback lacks raw_html")?)
            .map_err(|_| "safe fallback base64 invalid".to_owned())?;
        check(decoded == bytes, "raw_html differs from complete original bytes")?;
    }
    Ok(())
}

struct Report {
    case_filter: Option<String>, sub_filter: Option<String>, list: bool,
    selected: usize, executed: usize, cases: BTreeSet<&'static str>, errors: usize,
}
impl Report {
    fn run(&mut self, case: &'static str, id: &'static str, run: impl FnOnce() -> P) {
        if self.case_filter.as_deref().is_some_and(|f| f != case) { return; }
        if self.sub_filter.as_deref().is_some_and(|f| f != id && f != format!("{case}/{id}")) { return; }
        self.selected += 1;
        self.cases.insert(case);
        if self.list { println!("SUBCASE {case}/{id}"); return; }
        self.executed += 1;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
            Ok(Ok(())) => println!("OK {case}/{id}"),
            Ok(Err(error)) => { self.errors += 1; println!("{} {case}/{id}: {}",
                if error.starts_with("DIVERGENT: ") { "DIVERGENT" } else { "FAIL" },
                error.strip_prefix("DIVERGENT: ").unwrap_or(&error)); }
            Err(_) => { self.errors += 1; println!("FAIL {case}/{id}: panic (not behavioral RED)"); }
        }
    }
}

fn public_parser(r: &mut Report) {
    let c = "public-parser";
    r.run(c, "relative-links", || {
        let parsed = library(organizations::parse_html(VALID.as_bytes()))?;
        let entries = serde_json::to_value(&parsed.entries).map_err(|e| e.to_string())?;
        check(parsed.title == "Directory" && parsed.categories == ["Group A", "Group B"], "title/categories")?;
        check(entries.as_array().map(Vec::len) == Some(6), "entry count")?;
        check(entries[0]["listed_href"] == " http://rse.buaa.edu.cn "
            && entries[0]["resolved_http_url"] == "http://rse.buaa.edu.cn/", "listed/resolved HTTP link")?;
        check(entries[1]["hidden_in_source"] == true && entries[2]["link_kind"] == "missing"
            && entries[3]["link_kind"] == "non_http" && entries[4]["resolved_http_url"] == "https://www.buaa.edu.cn/relative",
            "complete relative/hidden/missing/non-http link projection")
    });
    for (id, base) in [("active-base-foreign", "https://foreign.example/"), ("active-base-same-origin", "https://www.buaa.edu.cn/")] {
        r.run(c, id, || code(organizations::parse_html(format!("<base href='{base}'>{VALID}").as_bytes()), "unavailable", true));
    }
    r.run(c, "inert-bases", || {
        let text = format!("<template><base href='https://foreign.example/'></template><noscript><base href='https://foreign.example/'></noscript>{VALID}");
        let parsed = library(organizations::parse_html(text.as_bytes()))?;
        check(parsed.entries.len() == 6 && parsed.entries[4].resolved_http_url.as_deref() == Some("https://www.buaa.edu.cn/relative"),
            "inert bases changed source resolution")
    });
    r.run(c, "ancestor-hidden", || {
        for parent in ["hidden", "class='xbt'", "style='display:none'", "style='visibility:hidden'", "style='content-visibility:hidden'"] {
            let parsed = library(organizations::parse_html(one_member(parent, "").as_bytes()))?;
            delta(parsed.entries[0].hidden_in_source, format!("ancestor {parent} did not mark non-attributing"))?;
        }
        Ok(())
    });
    r.run(c, "hidden-token-negatives", || {
        for attr in ["class='xbtx'", "data-hidden='true'", "style='x-display:none'", "style='display:none2'", "style='visibility:visible'"] {
            let parsed = library(organizations::parse_html(one_member("", attr).as_bytes()))?;
            delta(!parsed.entries[0].hidden_in_source, format!("negative token {attr} marked hidden"))?;
        }
        Ok(())
    });
    r.run(c, "css-cascade", || {
        for (parent, child, hidden) in [
            ("style='display:/*comment*/none'", "style='display:block'", true),
            ("style='visibility:hidden'", "style='visibility:visible'", false),
            ("style='visibility:hidden !important'", "style='visibility:visible'", false),
            ("style='visibility:visible'", "style='visibility:hidden'", true),
            ("", "style='display:none;display:block'", false),
            ("", "style='display:none!important;display:block'", true),
            ("", "style='display:block;display:none2'", false),
            ("", "style='visibility:var(--x)'", true),
        ] {
            let parsed = library(organizations::parse_html(one_member(parent, child).as_bytes()))?;
            delta(parsed.entries[0].hidden_in_source == hidden, format!("CSS marker cascade mismatch: {parent} / {child}"))?;
        }
        Ok(())
    });
    r.run(c, "inert-payload-parser", || {
        let text = VALID.replace("</body>", "<script>var csrf_marker='x';</script><!-- <input type='password'> --></body>");
        let parsed = library(organizations::parse_html(text.as_bytes()))?;
        check(parsed.entries.len() == 6 && parsed.entries[0].name == "Alpha", "inactive text supplied parser member content")
    });
    r.run(c, "malformed-parser", || {
        for bytes in [Vec::new(), b"<title>Only title</title>".to_vec(), vec![b'x'; 2 * 1024 * 1024 + 1], vec![0xff]] {
            code(organizations::parse_html(&bytes), "unavailable", false)?;
        }
        Ok(())
    });
}

fn snapshot_scope(r: &mut Report) {
    let c = "snapshot-scope";
    r.run(c, "structured-membership", || {
        let fixture = proof::ProofFixture::new();
        let mut server = Server::script(vec![Reply::robots(404, b""),
            Reply::target(200, "Content-Type: TeXt/HtMl; charset=utf-8\r\n", VALID.as_bytes())]);
        let value = library(proof::list(&open(&fixture, &server, CacheMode::PreferCache)?))?;
        check(value["result"] == "directory_snapshot" && value["type"] == "organization_directory", "snapshot result")?;
        check(value["document_title"] == "Directory" && value["categories"] == json!(["Group A", "Group B"]), "snapshot title/categories")?;
        check(value["entries"].as_array().map(Vec::len) == Some(6)
            && value["completeness"]["entry_count"] == 6 && value["completeness"]["category_count"] == 2,
            "complete snapshot counts")?;
        let parsed = library(organizations::parse_html(VALID.as_bytes()))?;
        check(value["entries"] == serde_json::to_value(parsed.entries).map_err(|e| e.to_string())?, "complete parser/export entry agreement")?;
        check(value["authority"]["source_url"] == URL && value["retrieval"]["source_url"] == URL,
            "exact directory source URL")?;
        library(proof::attribute(&value, "Alpha", " http://rse.buaa.edu.cn ", "http://rse.buaa.edu.cn/"))?;
        code(proof::attribute(&value, "Hidden", "https://hidden.buaa.edu.cn/", "https://hidden.buaa.edu.cn/"), "unavailable", false)?;
        code(proof::attribute(&value, "Zeta", "https://zeta.buaa.edu.cn/", "https://zeta.buaa.edu.cn/"), "unavailable", true)?;
        code(proof::attribute(&json!({"entries":[]}), "Alpha", " http://rse.buaa.edu.cn ", "http://rse.buaa.edu.cn/"), "unavailable", false)?;
        check(server.count() == 2, "snapshot request count")?;
        server.finish()
    });
    r.run(c, "url-scope", || {
        let fixture = proof::ProofFixture::new();
        let mut server = Server::script(vec![]);
        code(fixture.organizations_client(CacheMode::PreferCache,
            SocketAddr::from(([127, 0, 0, 1], 0))), "invalid_input", false)?;
        code(fixture.organizations_client(CacheMode::PreferCache,
            SocketAddr::from(([192, 0, 2, 1], 8080))), "invalid_input", false)?;
        let client = open(&fixture, &server, CacheMode::PreferCache)?;
        for url in ["https://www.buaa.edu.cn/", "https://www.buaa.edu.cn/jgsz/jxkyjg02.htm?x=1",
            "https://foreign.example/jgsz/jxkyjg02.htm", "http://www.buaa.edu.cn/jgsz/jxkyjg02.htm"] {
            code(client.get(&Url::parse(url).map_err(|e| e.to_string())?, false, |_| Ok(())), "egress_denied", false)?;
        }
        check(server.count() == 0, "egress refusal issued a request")?;
        server.finish()
    });
    r.run(c, "schema", || {
        let schema = organizations::schema();
        let variants = schema["list"]["output"]["oneOf"].as_array();
        delta(variants.is_some(), "schema lacks snapshot/fallback alternatives")?;
        let variants = variants.unwrap();
        check(variants.len() == 2, "schema alternative count")?;
        let snapshot = variants.iter().find(|v| v["properties"]["result"]["const"] == "directory_snapshot");
        let fallback = variants.iter().find(|v| v["properties"]["result"]["const"] == "fallback");
        check(snapshot.is_some() && fallback.is_some(), "schema result alternatives")?;
        check(fallback.unwrap()["properties"]["entries"]["maxItems"] == 0, "fallback schema authorizes nonempty entries")
    });
}

fn safe_drift(r: &mut Report) {
    let c = "safe-drift";
    r.run(c, "original-retention-refresh", || {
        let bytes = drift();
        let fixture = proof::ProofFixture::new();
        let mut server = Server::script(vec![
            Reply::robots(404, b""),
            Reply::target(200, "Content-Type: text/html; charset=utf-8\r\nETag: \"proof-v1\"\r\n", &bytes),
            Reply::target(304, "ETag: \"proof-v2\"\r\n", b""),
            Reply::target(304, "Set-Cookie: synthetic=value\r\n", b""),
            Reply::target(200, "Content-Type: text/plain\r\n", &bytes),
        ]);
        let first = match proof::list(&open(&fixture, &server, CacheMode::PreferCache)?) {
            Ok(value) => value,
            Err(error) if error.code == "unavailable" => return delta(false, "safe selector drift failed instead of retaining raw fallback"),
            Err(error) => return Err(format!("initial fetch failed: {}", error.code)),
        };
        fallback(&first, &bytes, false)?;
        check(first["retrieval"]["cache_status"] == "miss" && first["retrieval"]["revalidation_status"].is_null(), "initial retrieval facts")?;
        let robots_request = server.take()?;
        let target_request = server.take()?;
        check(robots_request.path() == "/robots.txt" && target_request.path() == TARGET_PATH, "robots-first request order")?;
        check(target_request.at.duration_since(robots_request.at) >= Duration::from_secs(5), "governor did not preserve the five-second interval")?;
        let current = cache_path(&fixture, URL, true);
        delta(current.exists(), "fresh directory original not saved in current-v2 namespace")?;
        let saved = record(&current, 2)?;
        check(body(&saved)? == bytes && saved["url"] == URL && saved["status"] == 200
            && saved["headers"]["content-type"] == "text/html; charset=utf-8" && saved["etag"] == "\"proof-v1\"",
            "complete persisted body/HTTP/validator facts")?;
        check(saved == json!({"version":2,"url":URL,"status":200,
            "headers":{"content-type":"text/html; charset=utf-8","content-length":bytes.len().to_string(),"etag":"\"proof-v1\""},
            "body_base64":STANDARD.encode(&bytes),"sha256":sha(&bytes),
            "fetched_at_unix_ms":saved["fetched_at_unix_ms"],"immutable":false,
            "revalidated_at_unix_ms":null,"revalidation_status":null,"etag":"\"proof-v1\"","last_modified":null}),
            "whole initial cache record disagrees with the received response")?;
        check(first["retrieval"]["fetched_at_unix_ms"] == saved["fetched_at_unix_ms"], "fetch-time provenance mismatch")?;
        check(!cache_path(&fixture, URL, false).exists(), "fresh capture created legacy target file")?;
        let robots = record(&cache_path(&fixture, ROBOTS, false), 1)?;
        check(robots["status"] == 404 && body(&robots)?.is_empty(), "robots 404 not accepted/retained verbatim")?;

        let governor = settled(&fixture)?;
        let lock = std::fs::OpenOptions::new().read(true).write(true).open(fixture.governor_lock_path()).map_err(|e| e.to_string())?;
        FileExt::try_lock_exclusive(&lock).map_err(|e| format!("fixture lock busy: {e}"))?;
        check(governor.status().is_err(), "exclusive observer lock was not held")?;
        let mut hit_expected = first.clone();
        hit_expected["retrieval"]["cache_status"] = json!("hit");
        let offline = library(proof::list(&open(&fixture, &server, CacheMode::Offline)?))?;
        check(offline == hit_expected && server.count() == 2, "fresh-client Offline changed output or opened governor/network")?;
        FileExt::unlock(&lock).map_err(|e| e.to_string())?;
        drop(lock);

        let revalidated = library(proof::list(&open(&fixture, &server, CacheMode::Revalidate)?))?;
        let conditional = server.take()?;
        check(conditional.header("if-none-match") == Some("\"proof-v1\""), "current-v2 revalidation omitted original ETag")?;
        fallback(&revalidated, &bytes, false)?;
        check(revalidated["retrieval"]["cache_status"] == "revalidated"
            && revalidated["retrieval"]["revalidation_status"] == 304
            && revalidated["retrieval"]["revalidated_at_unix_ms"].is_u64()
            && revalidated["retrieval"]["fetched_at_unix_ms"] == first["retrieval"]["fetched_at_unix_ms"], "304 rewrote original fetch facts")?;
        let mut revalidation_expected = first.clone();
        revalidation_expected["retrieval"]["cache_status"] = json!("revalidated");
        revalidation_expected["retrieval"]["revalidation_status"] = json!(304);
        revalidation_expected["retrieval"]["revalidated_at_unix_ms"] = revalidated["retrieval"]["revalidated_at_unix_ms"].clone();
        check(revalidated == revalidation_expected, "304 changed original output beyond explicit validation facts")?;
        let saved_304 = record(&current, 2)?;
        check(body(&saved_304)? == bytes && saved_304["headers"] == saved["headers"]
            && saved_304["fetched_at_unix_ms"] == saved["fetched_at_unix_ms"]
            && saved_304["etag"] == "\"proof-v2\"", "304 failed original-byte/metadata carryforward")?;
        let mut expected_304_record = saved.clone();
        expected_304_record["revalidated_at_unix_ms"] = revalidated["retrieval"]["revalidated_at_unix_ms"].clone();
        expected_304_record["revalidation_status"] = json!(304);
        expected_304_record["etag"] = json!("\"proof-v2\"");
        check(saved_304 == expected_304_record, "304 changed other persisted original facts")?;

        let before_refusals = file_bytes(&current)?;
        code(proof::list(&open(&fixture, &server, CacheMode::Revalidate)?), "unavailable", false)?;
        let cookie_304_request = server.take()?;
        check(cookie_304_request.header("if-none-match") == Some("\"proof-v2\""), "current 304-cookie request validators")?;
        check(file_bytes(&current)? == before_refusals, "304-cookie refusal modified retained current file")?;
        settled(&fixture)?;
        code(proof::list(&open(&fixture, &server, CacheMode::Revalidate)?), "unavailable", false)?;
        let bad_refresh = server.take()?;
        check(bad_refresh.header("if-none-match") == Some("\"proof-v2\""), "refresh lost current validator")?;
        check(file_bytes(&current)? == before_refusals, "inadmissible same-byte MIME refresh overwrote current file")?;
        let last_hit = library(proof::list(&open(&fixture, &server, CacheMode::Offline)?))?;
        let mut last_expected = revalidated;
        last_expected["retrieval"]["cache_status"] = json!("hit");
        check(last_hit == last_expected && server.count() == 5, "refused refresh destroyed offline reuse or issued extra requests")?;
        server.finish()
    });
    r.run(c, "current-corrupt-no-legacy-fallback", || {
        let fixture = proof::ProofFixture::new();
        let mut server = Server::script(vec![]);
        let client = open(&fixture, &server, CacheMode::PreferCache)?;
        let old = seed_v1(&fixture, Some("text/html"), VALID.as_bytes(), false, false)?;
        let current = cache_path(&fixture, URL, true);
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&current).map_err(|e| e.to_string())?;
        file.write_all(b"not-json").map_err(|e| e.to_string())?;
        drop(file);
        code(proof::list(&client), "cache_invalid", true)?;
        check(file_bytes(&cache_path(&fixture, URL, false))? == old && file_bytes(&current)? == b"not-json", "corrupt-current refusal rewrote either cache file")?;
        check(server.count() == 0, "corrupt-current lookup requested the network")?;
        server.finish()
    });
}

fn refusal(r: &mut Report, id: &'static str, content_type: Option<&str>, extra: &str, bytes: Vec<u8>, divergent: bool) {
    r.run("admission", id, || {
        let fixture = proof::ProofFixture::new();
        let mut headers = content_type.map(|ct| format!("Content-Type: {ct}\r\n")).unwrap_or_default();
        headers.push_str(extra);
        let mut server = Server::script(vec![Reply::robots(404, b""), Reply::target(200, &headers, &bytes)]);
        let client = open(&fixture, &server, CacheMode::PreferCache)?;
        code(proof::list(&client), "unavailable", divergent)?;
        no_target_files(&fixture)?;
        code(proof::list(&open(&fixture, &server, CacheMode::Offline)?), "offline_miss", false)?;
        check(server.count() == 2, "admission refusal performed another request")?;
        settled(&fixture)?;
        server.finish()
    });
}

fn admission(r: &mut Report) {
    let with_selectors = |markup: &str| VALID.replace("</body>", &format!("{markup}</body>")).into_bytes();
    let without_selectors = |markup: &str| format!("<title>Public</title><body>{markup}</body>").into_bytes();
    refusal(r, "missing-content-type", None, "", VALID.as_bytes().to_vec(), true);
    refusal(r, "text-plain", Some("text/plain"), "", VALID.as_bytes().to_vec(), false);
    refusal(r, "text-html-unknown", Some("text/html-unknown"), "", VALID.as_bytes().to_vec(), true);
    refusal(r, "empty-body", Some("text/html"), "", vec![], false);
    refusal(r, "invalid-utf8", Some("text/html"), "", vec![0xff], false);
    refusal(r, "two-mib-plus-one", Some("text/html"), "", vec![b'x'; 2 * 1024 * 1024 + 1], false);
    refusal(r, "active-base-foreign", Some("text/html"), "", format!("<base href='https://foreign.example/'>{VALID}").into_bytes(), true);
    refusal(r, "active-base-same-origin", Some("text/html"), "", format!("<base href='https://www.buaa.edu.cn/'>{VALID}").into_bytes(), true);
    for (matching, plain, markup) in [
        ("password-matching", "password-no-selectors", "<form action='/login'><input type='password' name='password'></form>"),
        ("csrf-matching", "csrf-no-selectors", "<input type='hidden' name='csrf_token'>"),
        ("challenge-matching", "challenge-no-selectors", "<div id='cf-challenge-form'></div>"),
    ] {
        refusal(r, matching, Some("text/html"), "", with_selectors(markup), true);
        refusal(r, plain, Some("text/html"), "", without_selectors(markup), false);
    }
    refusal(r, "set-cookie", Some("text/html"), "Set-Cookie: synthetic=value\r\n", VALID.as_bytes().to_vec(), true);
    // Valid selectors prevent the old layout failure from concealing the new
    // complete-body privacy boundary; inert text alone is not safe raw data.
    refusal(r, "script-token", Some("text/html"), "", with_selectors("<script>var csrfFixtureToken='synthetic';</script>"), true);
    refusal(r, "comment-token", Some("text/html"), "", with_selectors("<!-- csrfFixtureToken=synthetic -->"), true);

    for (id, original) in [
        ("legacy-unknown-layout", VALID.replace("Directory", OPAQUE).replace("Alpha", OPAQUE).into_bytes()),
        ("legacy-unknown-drift", format!("<title>{OPAQUE}</title><p>{OPAQUE}</p>").into_bytes()),
    ] {
        r.run("admission", id, || {
            let fixture = proof::ProofFixture::new();
            let mut server = Server::script(vec![]);
            let client = open(&fixture, &server, CacheMode::PreferCache)?;
            let content_type = format!("text/html; note={OPAQUE}");
            let old = seed_v1(&fixture, Some(&content_type), &original, true, false)?;
            let value = match proof::list(&client) {
                Ok(value) => value,
                Err(error) if error.code == "unavailable" => return delta(false, "legacy Unknown did not return bounded metadata fallback"),
                Err(error) => return Err(format!("legacy lookup failed: {}", error.code)),
            };
            delta(value["result"] == "fallback", "legacy Unknown disclosed structured member data")?;
            fallback(&value, &original, true)?;
            check(value["retrieval"]["cache_status"] == "hit", "legacy hit facts")?;
            let offline = library(proof::list(&open(&fixture, &server, CacheMode::Offline)?))?;
            check(offline == value && server.count() == 0, "legacy cache hit auto-refetched or changed output")?;
            check(file_bytes(&cache_path(&fixture, URL, false))? == old && !cache_path(&fixture, URL, true).exists(), "legacy hit modified/promoted original file")?;
            server.finish()
        });
    }
    r.run("admission", "legacy-invalid-metadata", || {
        for content_type in [None, Some("text/plain"), Some("text/html-unknown")] {
            let fixture = proof::ProofFixture::new();
            let mut server = Server::script(vec![]);
            let client = open(&fixture, &server, CacheMode::PreferCache)?;
            let old = seed_v1(&fixture, content_type, VALID.as_bytes(), false, false)?;
            code(proof::list(&client), "unavailable", true)?;
            check(file_bytes(&cache_path(&fixture, URL, false))? == old && server.count() == 0, "legacy admission refusal changed file or requested source")?;
            server.finish()?;
        }
        Ok(())
    });
    r.run("admission", "legacy-stray-304", || {
        let fixture = proof::ProofFixture::new();
        let mut server = Server::script(vec![Reply::target(304, "ETag: \"new-validator\"\r\n", b"")]);
        let client = open(&fixture, &server, CacheMode::Revalidate)?;
        library(proof::seed_robots(&client, ALLOW))?;
        let original = drift();
        let old = seed_v1(&fixture, Some("text/html"), &original, false, false)?;
        code(proof::list(&client), "invalid_304", true)?;
        let request = server.take()?;
        delta(request.header("if-none-match").is_none() && request.header("if-modified-since").is_none(), "Unknown sent conditional validators")?;
        check(file_bytes(&cache_path(&fixture, URL, false))? == old && !cache_path(&fixture, URL, true).exists(), "stray 304 promoted/modified Unknown")?;
        let offline = library(proof::list(&open(&fixture, &server, CacheMode::Offline)?))?;
        fallback(&offline, &original, true)?;
        check(server.count() == 1, "stray 304 retried")?;
        server.finish()
    });
    r.run("admission", "legacy-fresh-200", || {
        // Different bytes and byte-identical fresh200 both establish only
        // the newly observed response's fact, never relabel the legacy file.
        for (legacy_body, immutable) in [
            (drift(), false),
            (VALID.as_bytes().to_vec(), false),
            // Immutable equal-body boundary: recovery still derives every
            // fact from the fresh response, not retained immutable metadata.
            (VALID.as_bytes().to_vec(), true),
        ] {
            let fixture = proof::ProofFixture::new();
            let mut server = Server::script(vec![Reply::target(200, "Content-Type: text/html\r\nETag: \"fresh-v2\"\r\nLast-Modified: Wed, 01 Oct 2025 00:00:00 GMT\r\n", VALID.as_bytes())]);
            let client = open(&fixture, &server, CacheMode::Revalidate)?;
            library(proof::seed_robots(&client, ALLOW))?;
            let old = seed_v1(&fixture, Some("text/html"), &legacy_body, false, immutable)?;
            let old_fetched = serde_json::from_slice::<Value>(&old).map_err(|e| e.to_string())?["fetched_at_unix_ms"].clone();
            let value = library(proof::list(&client))?;
            delta(value["result"] == "directory_snapshot", "explicit fresh200 recovery did not snapshot")?;
            let request = server.take()?;
            delta(request.header("if-none-match").is_none() && request.header("if-modified-since").is_none(), "Unknown refresh sent validators")?;
            delta(file_bytes(&cache_path(&fixture, URL, false))? == old, "fresh200 overwrote legacy file")?;
            let current_path = cache_path(&fixture, URL, true);
            delta(current_path.exists(), "fresh200 did not establish current namespace")?;
            let current = record(&current_path, 2)?;
            check(current == json!({"version":2,"url":URL,"status":200,
                "headers":{"content-type":"text/html","content-length":VALID.len().to_string(),"etag":"\"fresh-v2\"","last-modified":"Wed, 01 Oct 2025 00:00:00 GMT"},
                "body_base64":STANDARD.encode(VALID.as_bytes()),"sha256":sha(VALID.as_bytes()),
                "fetched_at_unix_ms":current["fetched_at_unix_ms"],"immutable":false,
                "revalidated_at_unix_ms":null,"revalidation_status":null,"etag":"\"fresh-v2\"","last_modified":"Wed, 01 Oct 2025 00:00:00 GMT"}),
                "fresh200 persisted facts copied legacy immutable metadata")?;
            check(value["retrieval"]["fetched_at_unix_ms"] == current["fetched_at_unix_ms"]
                && current["fetched_at_unix_ms"].as_u64().is_some_and(|ms| ms > old_fetched.as_u64().unwrap_or(u64::MAX)),
                "fresh200 recovery reused legacy fetch facts instead of new capture time")?;
            let hit = library(proof::list(&open(&fixture, &server, CacheMode::Offline)?))?;
            let mut expected = value;
            expected["retrieval"]["cache_status"] = json!("hit");
            check(hit == expected && server.count() == 1, "current namespace not preferred over legacy")?;
            server.finish()?;
        }
        Ok(())
    });
    for (id, headers) in [
        ("legacy-bad-mime-refresh", "Content-Type: text/plain\r\n"),
        ("legacy-cookie-refresh", "Content-Type: text/html\r\nSet-Cookie: synthetic=value\r\n"),
    ] {
        r.run("admission", id, || {
            // Mutable and immutable legacy records alike must not let a bad
            // equal-byte fresh response replace metadata or promote v1.
            for immutable in [false, true] {
                let fixture = proof::ProofFixture::new();
                let mut server = Server::script(vec![Reply::target(200, headers, VALID.as_bytes())]);
                let client = open(&fixture, &server, CacheMode::Revalidate)?;
                library(proof::seed_robots(&client, ALLOW))?;
                let old = seed_v1(&fixture, Some("text/html"), &drift(), false, immutable)?;
                code(proof::list(&client), "unavailable", true)?;
                let request = server.take()?;
                delta(request.header("if-none-match").is_none() && request.header("if-modified-since").is_none(), "Unknown bad refresh sent validators")?;
                check(file_bytes(&cache_path(&fixture, URL, false))? == old && !cache_path(&fixture, URL, true).exists(), "bad fresh response modified prior files")?;
                check(server.count() == 1, "bad refresh retried")?;
                settled(&fixture)?;
                server.finish()?;
            }
            Ok(())
        });
    }
    r.run("admission", "immutable-bad-mime-fresh-valid-same-bytes", || {
        // Immutable legacy record with inadmissible stale metadata, same bytes
        // arriving under valid fresh headers: recovery uses the fresh
        // response's headers/fetch facts only; the legacy file is untouched.
        let fixture = proof::ProofFixture::new();
        let mut server = Server::script(vec![Reply::target(200, "Content-Type: text/html\r\nETag: \"fresh-v2\"\r\nLast-Modified: Wed, 01 Oct 2025 00:00:00 GMT\r\n", VALID.as_bytes())]);
        let client = open(&fixture, &server, CacheMode::Revalidate)?;
        library(proof::seed_robots(&client, ALLOW))?;
        let old = seed_v1(&fixture, Some("text/plain"), VALID.as_bytes(), false, true)?;
        let old_json: Value = serde_json::from_slice(&old).map_err(|e| e.to_string())?;
        let value = library(proof::list(&client))?;
        delta(value["result"] == "directory_snapshot", "immutable equal-body fresh200 did not recover")?;
        let request = server.take()?;
        delta(request.header("if-none-match").is_none() && request.header("if-modified-since").is_none(), "immutable Unknown refresh sent validators")?;
        check(file_bytes(&cache_path(&fixture, URL, false))? == old, "immutable recovery rewrote legacy file")?;
        let current = record(&cache_path(&fixture, URL, true), 2)?;
        check(current == json!({"version":2,"url":URL,"status":200,
            "headers":{"content-type":"text/html","content-length":VALID.len().to_string(),"etag":"\"fresh-v2\"","last-modified":"Wed, 01 Oct 2025 00:00:00 GMT"},
            "body_base64":STANDARD.encode(VALID.as_bytes()),"sha256":sha(VALID.as_bytes()),
            "fetched_at_unix_ms":current["fetched_at_unix_ms"],"immutable":false,
            "revalidated_at_unix_ms":null,"revalidation_status":null,"etag":"\"fresh-v2\"","last_modified":"Wed, 01 Oct 2025 00:00:00 GMT"}),
            "immutable recovery retained stale metadata instead of the complete fresh response")?;
        check(current["fetched_at_unix_ms"].as_u64() > old_json["fetched_at_unix_ms"].as_u64()
            && value["retrieval"]["fetched_at_unix_ms"] == current["fetched_at_unix_ms"]
            && value["retrieval"]["cache_status"] == "miss", "immutable recovery reused legacy fetch facts")?;
        check(server.count() == 1, "immutable recovery request count")?;
        server.finish()
    });
    r.run("admission", "immutable-valid-fresh-bad-same-bytes", || {
        // Immutable legacy record with valid metadata, same bytes arriving
        // under inadmissible fresh headers: refuse without touching either
        // cache file; no later current-namespace promotion.
        for fresh_headers in [
            "Content-Type: text/plain\r\n",
            "Content-Type: text/html\r\nSet-Cookie: synthetic=value\r\n",
        ] {
            let fixture = proof::ProofFixture::new();
            let mut server = Server::script(vec![Reply::target(200, fresh_headers, VALID.as_bytes())]);
            let client = open(&fixture, &server, CacheMode::Revalidate)?;
            library(proof::seed_robots(&client, ALLOW))?;
            let old = seed_v1(&fixture, Some("text/html"), VALID.as_bytes(), false, true)?;
            code(proof::list(&client), "unavailable", true)?;
            let request = server.take()?;
            delta(request.header("if-none-match").is_none() && request.header("if-modified-since").is_none(), "immutable bad fresh response sent validators")?;
            check(file_bytes(&cache_path(&fixture, URL, false))? == old && !cache_path(&fixture, URL, true).exists(), "immutable bad fresh response modified cache files")?;
            check(server.count() == 1, "immutable bad fresh response retried")?;
            settled(&fixture)?;
            server.finish()?;
        }
        Ok(())
    });
    // Known-marker admission of retained metadata: a marker inside an
    // otherwise permitted header value must refuse before projection or
    // persistence, independent of Set-Cookie/challenge detection.
    for (id, headers) in [
        ("header-marker-content-type", "Content-Type: text/html; csrf_token=fixtureSecret42\r\n"),
        ("header-marker-etag", "Content-Type: text/html\r\nETag: \"csrf_token=fixtureSecret42\"\r\n"),
        ("header-marker-name", "Content-Type: text/html\r\nX-CSRF-Token: 1\r\n"),
    ] {
        r.run("admission", id, || {
            let fixture = proof::ProofFixture::new();
            let mut server = Server::script(vec![Reply::robots(404, b""), Reply::target(200, headers, VALID.as_bytes())]);
            let client = open(&fixture, &server, CacheMode::PreferCache)?;
            code(proof::list(&client), "unavailable", true)?;
            no_target_files(&fixture)?;
            check(server.count() == 2, "header-marker refusal request count")?;
            settled(&fixture)?;
            server.finish()
        });
    }
    r.run("admission", "header-marker-304", || {
        // A 304 carrying a known marker inside its updated validator must not
        // be admitted into the persisted current entry or output.
        let fixture = proof::ProofFixture::new();
        let mut server = Server::script(vec![
            Reply::robots(404, b""),
            Reply::target(200, "Content-Type: text/html\r\nETag: \"proof-v1\"\r\n", VALID.as_bytes()),
            Reply::target(304, "ETag: \"csrf_token=fixtureSecret42\"\r\n", b""),
        ]);
        let first = library(proof::list(&open(&fixture, &server, CacheMode::PreferCache)?))?;
        let current = cache_path(&fixture, URL, true);
        let legacy = cache_path(&fixture, URL, false);
        // In the baseline a fresh fetch persists to the legacy path; compare
        // whichever persisted target entry exists so classification stays
        // behavioral rather than missing-file infrastructure noise.
        let persisted = if current.exists() { &current } else { &legacy };
        delta(current.exists(), "fresh snapshot not saved in current-v2 namespace")?;
        let before = file_bytes(persisted)?;
        match proof::list(&open(&fixture, &server, CacheMode::Revalidate)?) {
            Err(error) if error.code == "unavailable" => {}
            Err(error) => return delta(false, format!("marker 304 received {} instead of unavailable", error.code)),
            Ok(_) => return delta(false, "marker 304 accepted"),
        }
        // Requests are receipts in arrival order: drain the robots lookup and
        // the first target fetch before the revalidation request.
        check(server.take()?.path() == "/robots.txt", "marker-304 robots receipt order")?;
        check(server.take()?.path() == TARGET_PATH, "marker-304 first target receipt order")?;
        let revalidation = server.take()?;
        check(revalidation.header("if-none-match") == Some("\"proof-v1\""), "marker-304 request validators")?;
        check(file_bytes(persisted)? == before, "marker 304 modified persisted entry")?;
        let hit = library(proof::list(&open(&fixture, &server, CacheMode::Offline)?))?;
        let mut expected = first;
        expected["retrieval"]["cache_status"] = json!("hit");
        check(hit == expected, "marker 304 altered retained output")?;
        check(!hit.to_string().contains("fixtureSecret42"), "marker 304 header value reached output")?;
        check(server.count() == 3, "marker 304 request count")?;
        settled(&fixture)?;
        server.finish()
    });
    // A bounded field/identifier token inside script or comment text is a
    // known-marker omission; whole-string equality over the buffer is not a
    // valid field scan. Valid selectors isolate the privacy boundary.
    refusal(r, "script-field-token", Some("text/html"), "", with_selectors("<script type='application/json'>{\"authenticity_token\":\"fixtureSecret42\"}</script>"), true);
    refusal(r, "comment-field-token", Some("text/html"), "", with_selectors("<!-- authenticity_token=fixtureSecret42 -->"), true);
    // Entity-encoded markers inside a parser-discarded duplicate attribute
    // escape a decoded-DOM scan; admission must screen decoded raw attribute
    // tokens before duplicate elimination. The literal twin is already caught.
    refusal(r, "encoded-duplicate-attribute", Some("text/html"), "", with_selectors("<p title=\"public\" title=\"c&#115;rfToken=fixtureSecret42\">Text</p>"), true);
    refusal(r, "literal-duplicate-attribute", Some("text/html"), "", with_selectors("<p title=\"public\" title=\"csrfToken=fixtureSecret42\">Text</p>"), true);
    // Placement-dependent bound: HTML parsing decodes named entities inside
    // attribute values and normal text before the DOM scan, so a decoded
    // whole-buffer needle is refused there. c&Tab;srf_token=x compacts to
    // csrftokenx (contains csrf); bare pa&shy;sswd compacts to passwd
    // (equality needle).
    refusal(r, "named-entity-decoded-attr-needle", Some("text/html"), "", with_selectors("<p title='c&Tab;srf_token=x'>Text</p>"), true);
    refusal(r, "named-entity-decoded-equality-needle", Some("text/html"), "", with_selectors("<p title='pa&shy;sswd'>Text</p>"), true);
    r.run("admission", "named-entity-needle-literal", || {
        // Entity-free raw zones (script/style/comment text) never decode
        // named entities: tokens stay split and the whole literal has no
        // needle, so these remain admissible. A needle-breaking =x suffix
        // keeps pa&shy;sswd=x admissible even inside a decoded attribute
        // (compacts to passwdx; passwd is equality-only).
        for markup in [
            "<p title='pa&shy;sswd=x'>Text</p>",
            "<script>c&Tab;srf_token=x;</script>",
            "<!-- c&Tab;srf_token=x -->",
        ] {
            let fixture = proof::ProofFixture::new();
            let markup = with_selectors(markup);
            let mut server = Server::script(vec![Reply::robots(404, b""),
                Reply::target(200, "Content-Type: text/html\r\n", &markup)]);
            let client = open(&fixture, &server, CacheMode::PreferCache)?;
            let value = match proof::list(&client) {
                Ok(value) => value,
                Err(error) if error.code == "unavailable" => return delta(false, "raw-zone named-entity splice was refused"),
                Err(error) => return Err(format!("named-entity fetch failed: {}", error.code)),
            };
            delta(value["result"] == "directory_snapshot", "named-entity literal did not snapshot")?;
            let current = cache_path(&fixture, URL, true);
            let legacy = cache_path(&fixture, URL, false);
            let persisted = if current.exists() { &current } else { &legacy };
            let saved = record(persisted, if current.exists() { 2 } else { 1 })?;
            check(body(&saved)? == markup, "named-entity literal persisted bytes")?;
            check(server.count() == 2, "named-entity literal request count")?;
            server.finish()?;
        }
        Ok(())
    });
}

fn robots_policy(r: &mut Report) {
    r.run("robots-policy", "retained-denial", || {
        const POLICY: &[u8] = b"User-agent: *\nDisallow: /jgsz/jxkyjg02.htm\n";
        let fixture = proof::ProofFixture::new();
        let mut server = Server::script(vec![Reply::robots(200, POLICY)]);
        let client = open(&fixture, &server, CacheMode::PreferCache)?;
        code(proof::list(&client), "robots_denied", false)?;
        let policy = record(&cache_path(&fixture, ROBOTS, false), 1)?;
        check(body(&policy)? == POLICY && policy["sha256"] == sha(POLICY), "robots retention bytes/hash")?;
        code(proof::list(&open(&fixture, &server, CacheMode::PreferCache)?), "robots_denied", false)?;
        code(proof::list(&open(&fixture, &server, CacheMode::Offline)?), "offline_miss", false)?;
        no_target_files(&fixture)?;
        check(server.count() == 1 && server.take()?.path() == "/robots.txt", "retained robots denial refetched or sent target request")?;
        server.finish()
    });
}

/// Owns every unblock and the worker join, including early assertion failure.
struct LeaseWorker {
    body_release: mpsc::SyncSender<()>, callback_release: mpsc::SyncSender<()>,
    worker: Option<JoinHandle<Result<Value, Error>>>,
}
impl LeaseWorker {
    fn join(&mut self) -> P<Result<Value, Error>> {
        let worker = self.worker.take().ok_or("lease worker already joined".to_owned())?;
        worker.join().map_err(|_| "lease worker panicked".to_owned())
    }
}
impl Drop for LeaseWorker {
    fn drop(&mut self) {
        let _ = self.body_release.try_send(());
        let _ = self.callback_release.try_send(());
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() && !thread::panicking() { panic!("lease cleanup worker panicked"); }
        }
    }
}

fn governor(r: &mut Report) {
    r.run("governor", "body-and-callback-lease", || {
        let fixture = proof::ProofFixture::new();
        // Open before worker starts: reopening during the lease would itself
        // fail and would not prove either of the requested competing probes.
        let governor = library(fixture.isolated_governor())?;
        let bytes = drift();
        let served = bytes.clone();
        let (body_started_tx, body_started_rx) = mpsc::sync_channel(1);
        let (body_release_tx, body_release_rx) = mpsc::sync_channel(1);
        let (callback_started_tx, callback_started_rx) = mpsc::sync_channel(1);
        let (callback_release_tx, callback_release_rx) = mpsc::sync_channel(1);
        let mut server = Server::new(move |socket, request| {
            check(request.path() == TARGET_PATH, "lease fixture fetched unexpected path")?;
            let split = served.len() / 2;
            let headers = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n", served.len());
            socket.write_all(headers.as_bytes()).and_then(|()| socket.write_all(&served[..split])).map_err(|e| e.to_string())?;
            body_started_tx.send(()).map_err(|e| e.to_string())?;
            body_release_rx.recv_timeout(WAIT).map_err(|_| "partial-body hold timed out".to_owned())?;
            socket.write_all(&served[split..]).map_err(|e| e.to_string())
        });
        let client = open(&fixture, &server, CacheMode::PreferCache)?;
        library(proof::seed_robots(&client, ALLOW))?;
        let url = library(proof::directory_url())?;
        let handle = thread::spawn(move || proof::get_for_proof(&client, &url, |response, admission| {
            let normalized = proof::normalize_response(response, admission);
            let _ = callback_started_tx.send(());
            // Even a baseline normalization refusal is held at the same
            // callback boundary before returning its actual result.
            if callback_release_rx.recv_timeout(WAIT).is_err() {
                return Err(Error::new("fixture_timeout", "callback hold timed out"));
            }
            normalized
        }));
        let mut worker = LeaseWorker { body_release: body_release_tx, callback_release: callback_release_tx, worker: Some(handle) };
        body_started_rx.recv_timeout(WAIT).map_err(|_| "partial body never arrived".to_owned())?;
        check(governor.try_acquire(RequestKind::Interactive).is_err() && governor.status().is_err(), "lease absent during partial body receipt")?;
        worker.body_release.send(()).map_err(|e| e.to_string())?;
        callback_started_rx.recv_timeout(WAIT).map_err(|_| "normalizer callback never reached".to_owned())?;
        check(governor.try_acquire(RequestKind::Interactive).is_err() && governor.status().is_err(), "lease absent inside actual normalizer callback")?;
        no_target_files(&fixture)?;
        worker.callback_release.send(()).map_err(|e| e.to_string())?;
        let result = worker.join()?;
        let value = match result {
            Ok(value) => value,
            Err(error) if error.code == "unavailable" => return delta(false, "held real normalizer did not return safe fallback"),
            Err(error) => return Err(format!("lease worker failed: {}", error.code)),
        };
        fallback(&value, &bytes, false)?;
        let saved = record(&cache_path(&fixture, URL, true), 2)?;
        check(body(&saved)? == bytes, "lease completion failed to persist original bytes")?;
        check(governor.status().is_ok() && server.count() == 1, "lease failed to settle or retried")?;
        server.finish()
    });
    for (id, status, headers, expected) in [
        ("status-401", 401, "", "safety_latched"),
        ("status-403", 403, "", "safety_latched"),
        ("header-challenge", 200, "cf-mitigated: challenge\r\n", "safety_latched"),
        ("retry-after-429", 429, "Retry-After: 60\r\n", "cooldown"),
    ] {
        r.run("governor", id, || {
            // The same observed HTTP/challenge/Retry-After outcome must keep
            // precedence even when an independent Set-Cookie is also present.
            for with_cookie in [false, true] {
                let fixture = proof::ProofFixture::new();
                let response_headers = format!("{headers}{}", if with_cookie { "Set-Cookie: synthetic=value\r\n" } else { "" });
                // No durable latch exists: a refused response does not block
                // the next acquisition. A follow-up list is re-admitted after
                // the ordinary request gap and observes the same refusal on a
                // second request; a retained cooldown still denies it before
                // any request is sent.
                let mut server = Server::script(vec![
                    Reply::target(status, &response_headers, b"<html></html>"),
                    Reply::target(status, &response_headers, b"<html></html>"),
                ]);
                let client = open(&fixture, &server, CacheMode::PreferCache)?;
                library(proof::seed_robots(&client, ALLOW))?;
                code(proof::list(&client), expected, false)?;
                no_target_files(&fixture)?;
                let governor = library(fixture.isolated_governor())?;
                let state = governor.status().map_err(|e| e.to_string())?;
                check(!state.authentication_armed, "fixture armed authentication")?;
                check(!state.safety_latched, "refused response manufactured a durable latch")?;
                if expected == "cooldown" { check(state.cooldown_wait >= Duration::from_secs(55), "Retry-After did not retain a near-60-second cooldown")?; }
                code(proof::list(&client), expected, false)?;
                check(server.count() == if expected == "cooldown" { 1 } else { 2 },
                    if expected == "cooldown" { "retained cooldown allowed another request" } else { "re-admitted refusal did not re-request" })?;
                server.finish()?;
            }
            Ok(())
        });
    }
}

fn main() {
    let mut list = false;
    let mut args = Vec::new();
    for arg in std::env::args().skip(1) {
        if arg == "--list" { list = true; } else { args.push(arg); }
    }
    if args.len() > 2 { eprintln!("usage: directory_admission_proof [--list] [CASE [SUBCASE]]"); std::process::exit(1); }
    let case_filter = args.first().filter(|a| a.as_str() != "all").cloned();
    let sub_filter = args.get(1).cloned();
    let all = case_filter.is_none() && sub_filter.is_none();
    let mut report = Report { case_filter, sub_filter, list, selected: 0, executed: 0, cases: BTreeSet::new(), errors: 0 };
    public_parser(&mut report);
    snapshot_scope(&mut report);
    safe_drift(&mut report);
    admission(&mut report);
    robots_policy(&mut report);
    governor(&mut report);
    if report.selected == 0 { eprintln!("FAIL no matching case/subcase"); std::process::exit(1); }
    if all && (report.selected != EXPECTED_SUBCASES || report.cases.len() != CASES.len()) {
        eprintln!("FAIL completeness: selected {}/{} subcases, {}/{} cases", report.selected, EXPECTED_SUBCASES, report.cases.len(), CASES.len());
        report.errors += 1;
    }
    println!("SUMMARY cases={}/6 subcases={} selected={} failures_or_divergences={}", report.cases.len(), report.executed, report.selected, report.errors);
    if !list && all && report.errors == 0 { println!("GREEN all 6 cases, all {EXPECTED_SUBCASES} named subcases complete"); }
    std::process::exit(i32::from(report.errors != 0));
}
