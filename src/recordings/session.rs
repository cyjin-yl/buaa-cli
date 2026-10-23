//! Governed classroom platform session acquisition.
//!
//! One deliberate authentication attempt per operator resume. The credential
//! arrives on protected stdin, never in argv, logs, cache or output. The
//! session cookie is kept in a private owner-only file and referenced by a
//! non-secret account fingerprint; the credential itself is never persisted.
use crate::governor::{Governor, RequestKind, RequestLease, ResumeAuthorization};
use crate::net::{CLASSROOM_ORIGIN, Error, acquire_kind};
use reqwest::Method;
use reqwest::blocking::{Client, Response};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, LOCATION, RETRY_AFTER, SET_COOKIE};
use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::Zeroizing;

const SSO_ORIGIN: &str = "https://sso.buaa.edu.cn";
const CLASSROOM_HOST: &str = "classroom.msa.buaa.edu.cn";
/// The single reviewed service the operator may authenticate for.
const CAS_SERVICE: &str = "https://yjapi.msa.buaa.edu.cn/casapi/index.php?forward=https%3A%2F%2Fclassroom.msa.buaa.edu.cn%2F&r=auth%2Flogin&tenant_code=21";
const ALLOWED_HOSTS: [&str; 3] = [
    "sso.buaa.edu.cn",
    "yjapi.msa.buaa.edu.cn",
    "classroom.msa.buaa.edu.cn",
];
const MAX_REDIRECTS: usize = 6;
const MAX_BODY: usize = 512 * 1024;
const MAX_INPUT: usize = 32 * 1024;
const MAX_COOKIE_BYTES: usize = 16 * 1024;
const MAX_STORED_SESSION_BYTES: usize = 512 * 1024;
const MAX_FIELD_BYTES: usize = 16 * 1024;
const MAX_COOKIE_COUNT: usize = 64;
const MAX_COOKIE_PATH: usize = 1024;
const MAX_COOKIE_AGE: u64 = 30 * 24 * 60 * 60;
const MAX_FORM_FIELDS: usize = 64;
const MAX_FORM_BYTES: usize = 64 * 1024;
const SESSION_DIRECTORY: &str = ".buaa-cli-classroom-session";
const RESUME_INTENT: &str = "RESUME CLASSROOM AUTH";
const TENANT_CODE: &str = "21";
static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn invalid() -> Error {
    Error::new("invalid_input", "Classroom session input is invalid.")
}

fn unavailable() -> Error {
    Error::new("unavailable", "Classroom session service is unavailable.")
}

fn rejected() -> Error {
    Error::new(
        "auth_latched",
        "Classroom authentication was rejected or indeterminate; explicit operator review is required.",
    )
}

fn challenge() -> Error {
    Error::new(
        "auth_latched",
        "Classroom authentication requires an interactive challenge; no challenge was bypassed.",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeInput<'a> {
    #[serde(borrow)]
    intent: std::borrow::Cow<'a, str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginInput<'a> {
    #[serde(default)]
    authorized: bool,
    #[serde(borrow)]
    username: std::borrow::Cow<'a, str>,
    #[serde(deserialize_with = "deserialize_secret")]
    password: Zeroizing<String>,
    verification: VerificationInput<'a>,
    #[serde(borrow)]
    intent: std::borrow::Cow<'a, str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationInput<'a> {
    #[serde(borrow)]
    course_id: std::borrow::Cow<'a, str>,
    #[serde(borrow)]
    sub_id: std::borrow::Cow<'a, str>,
}

fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn valid_secret(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn valid_numeric_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|value| value > 0)
}

/// A non-secret reference to one account's stored session.
fn account_fingerprint(username: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"buaa-cli:classroom-account:v1\0");
    hash.update((username.len() as u64).to_be_bytes());
    hash.update(username.as_bytes());
    format!("{:x}", hash.finalize())
}

/// Where one cookie may be sent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum Scope {
    /// Only the host that set it.
    Host(String),
    /// The reviewed classroom platform family, shared the way a browser
    /// shares a domain cookie between sibling hosts.
    Platform(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cookie {
    name: String,
    value: String,
    scope: Scope,
    path: String,
    expiry: Option<SystemTime>,
}

/// Domain- and path-scoped cookies. A cookie reaches only the hosts and paths
/// its own declaration allows, and the single sign-on credential never leaves
/// the sign-on host.
#[derive(Default)]
struct Jar {
    cookies: Vec<Cookie>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSession {
    version: u8,
    cookies: Vec<Cookie>,
}

#[derive(Serialize)]
struct StoredSessionRef<'a> {
    version: u8,
    cookies: &'a [&'a Cookie],
}

pub(crate) struct SessionCredentials<'a> {
    supplied: Option<&'a str>,
    stored: Jar,
}

impl<'a> SessionCredentials<'a> {
    pub(crate) fn load(cookie: Option<&'a str>, reference: Option<&str>) -> Result<Self, Error> {
        match (cookie, reference) {
            (Some(cookie), None) if crate::net::valid_session_cookie(cookie) => Ok(Self {
                supplied: Some(cookie),
                stored: Jar::default(),
            }),
            (None, Some(reference)) => {
                let directory = session_directory()?;
                Ok(Self {
                    supplied: None,
                    stored: stored_session_in(&directory, reference)?,
                })
            }
            _ => Err(invalid()),
        }
    }

    pub(crate) fn with_header<T>(
        &self,
        url: &Url,
        operation: impl FnOnce(&str, Option<SystemTime>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if url.scheme() != "https"
            || url.host_str() != Some(CLASSROOM_HOST)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        if let Some(cookie) = self.supplied {
            return operation(cookie, None);
        }
        let (cookie, expires) = self.stored.cookie_text(url).ok_or_else(|| Error::new(
            "unavailable", "No unexpired stored classroom cookie applies to this request; deliberate authentication is required."
        ))?;
        operation(&cookie, expires)
    }
}

fn classroom_scope(scope: &Scope) -> bool {
    match scope {
        Scope::Host(host) => host == CLASSROOM_HOST,
        Scope::Platform(domain) => {
            within_platform_family(domain) && domain_matches(domain, CLASSROOM_HOST)
        }
    }
}

/// The reviewed platform family whose session cookies are shared between the
/// forwarding service and the classroom platform.
const PLATFORM_FAMILY: &str = "msa.buaa.edu.cn";

fn domain_matches(domain: &str, host: &str) -> bool {
    let domain = domain.trim_start_matches('.').to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// A cookie may only be shared inside the reviewed platform family: its
/// domain must be that family or one of its subdomains. A broader domain, such
/// as the whole university domain, never widens a cookie's reach.
fn within_platform_family(domain: &str) -> bool {
    let domain = domain.trim_start_matches('.').to_ascii_lowercase();
    domain == PLATFORM_FAMILY || domain.ends_with(&format!(".{PLATFORM_FAMILY}"))
}

fn valid_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn valid_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value.bytes().all(|byte| {
            matches!(
                byte,
                0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e
            )
        })
}

fn cookie_path_matches(cookie_path: &str, request_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

fn parse_cookie_expiry(value: &str) -> Option<SystemTime> {
    let date = chrono::DateTime::parse_from_rfc2822(value.trim()).ok()?;
    let seconds = date.timestamp();
    if seconds < 0 {
        return Some(UNIX_EPOCH);
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(seconds).ok()?))
}

fn cookie_expired(expiry: Option<SystemTime>) -> bool {
    expiry.is_some_and(|value| value <= SystemTime::now())
}

fn cookie_expiry_too_far(expiry: Option<SystemTime>) -> bool {
    let Some(expiry) = expiry else {
        return false;
    };
    let Some(limit) = SystemTime::now().checked_add(Duration::from_secs(MAX_COOKIE_AGE)) else {
        return true;
    };
    expiry > limit
}

fn default_cookie_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(index) => request_path[..index].to_string(),
    }
}

impl Jar {
    fn absorb(&mut self, url: &Url, headers: &HeaderMap) -> Result<(), Error> {
        if !allowed(url) {
            return Err(invalid());
        }
        let Some(host) = url.host_str() else {
            return Err(invalid());
        };
        for value in headers.get_all(SET_COOKIE) {
            let text = value.to_str().map_err(|_| unavailable())?;
            let mut parts = text.split(';');
            let Some(pair) = parts.next() else {
                continue;
            };
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            if !valid_cookie_name(name)
                || value.len() > 4096
                || value
                    .bytes()
                    .any(|byte| byte == b';' || byte.is_ascii_control())
            {
                continue;
            }
            let mut domain: Option<String> = None;
            let mut path = default_cookie_path(url.path());
            let mut expires = None;
            let mut max_age_expiry = None;
            let mut invalid_attribute = false;
            let mut seen_domain = false;
            let mut seen_path = false;
            let mut seen_expires = false;
            let mut seen_max_age = false;
            for attribute in parts {
                let attribute = attribute.trim();
                let Some((key, attribute_value)) = attribute.split_once('=') else {
                    continue;
                };
                let key = key.trim();
                let attribute_value = attribute_value.trim();
                if key.eq_ignore_ascii_case("domain") {
                    if seen_domain {
                        invalid_attribute = true;
                        break;
                    }
                    seen_domain = true;
                    if attribute_value.is_empty()
                        || attribute_value.len() > 256
                        || attribute_value.chars().any(char::is_control)
                    {
                        invalid_attribute = true;
                        break;
                    }
                    domain = Some(attribute_value.to_string());
                } else if key.eq_ignore_ascii_case("path") {
                    if seen_path {
                        invalid_attribute = true;
                        break;
                    }
                    seen_path = true;
                    if !attribute_value.starts_with('/')
                        || attribute_value.len() > MAX_COOKIE_PATH
                        || attribute_value.chars().any(char::is_control)
                    {
                        invalid_attribute = true;
                        break;
                    }
                    path = attribute_value.to_string();
                } else if key.eq_ignore_ascii_case("expires") {
                    if seen_expires {
                        invalid_attribute = true;
                        break;
                    }
                    seen_expires = true;
                    let Some(value) = parse_cookie_expiry(attribute_value) else {
                        invalid_attribute = true;
                        break;
                    };
                    expires = Some(value);
                } else if key.eq_ignore_ascii_case("max-age") {
                    if seen_max_age {
                        invalid_attribute = true;
                        break;
                    }
                    seen_max_age = true;
                    let Ok(seconds) = attribute_value.parse::<i64>() else {
                        invalid_attribute = true;
                        break;
                    };
                    if seconds <= 0 {
                        max_age_expiry = Some(UNIX_EPOCH);
                    } else if u64::try_from(seconds).is_ok_and(|value| value > MAX_COOKIE_AGE) {
                        invalid_attribute = true;
                        break;
                    } else if let Ok(seconds) = u64::try_from(seconds) {
                        max_age_expiry =
                            SystemTime::now().checked_add(Duration::from_secs(seconds));
                    }
                }
            }
            let expiry = max_age_expiry.or(expires);
            if invalid_attribute || cookie_expiry_too_far(expiry) {
                continue;
            }
            // A declared domain must match the setter. Only the reviewed
            // platform family may share a cookie across hosts; every other
            // cookie, including the sign-on ticket, stays with its setter.
            let scope = match domain {
                Some(domain)
                    if domain_matches(&domain, host) && within_platform_family(&domain) =>
                {
                    Scope::Platform(domain.trim_start_matches('.').to_ascii_lowercase())
                }
                Some(domain) if domain_matches(&domain, host) => {
                    Scope::Host(host.to_ascii_lowercase())
                }
                Some(_) => continue,
                None => Scope::Host(host.to_ascii_lowercase()),
            };
            if cookie_expired(expiry) {
                self.cookies.retain(|cookie| {
                    !(cookie.name == name && cookie.scope == scope && cookie.path == path)
                });
                continue;
            }
            if !valid_cookie_value(value) {
                continue;
            }
            self.cookies.retain(|cookie| {
                !(cookie.name == name && cookie.scope == scope && cookie.path == path)
            });
            self.cookies.push(Cookie {
                name: name.to_string(),
                value: value.to_string(),
                scope,
                path,
                expiry,
            });
            if self.cookies.len() > MAX_COOKIE_COUNT {
                self.cookies.remove(0);
            }
        }
        Ok(())
    }

    fn cookie_text(&self, url: &Url) -> Option<(Zeroizing<String>, Option<SystemTime>)> {
        let host = url.host_str()?.to_ascii_lowercase();
        let mut text = Zeroizing::new(String::new());
        let mut expires = None;
        for cookie in &self.cookies {
            if cookie_expired(cookie.expiry) || !cookie_path_matches(&cookie.path, url.path()) {
                continue;
            }
            let permitted = match &cookie.scope {
                Scope::Host(scope) => *scope == host,
                Scope::Platform(domain) => host == *domain || host.ends_with(&format!(".{domain}")),
            };
            if !permitted {
                continue;
            }
            if let Some(expiry) = cookie.expiry {
                expires = Some(expires.map_or(expiry, |earliest: SystemTime| earliest.min(expiry)));
            }
            if !text.is_empty() {
                text.push_str("; ");
            }
            text.push_str(&cookie.name);
            text.push('=');
            text.push_str(&cookie.value);
        }
        if text.is_empty() || text.len() > MAX_COOKIE_BYTES {
            return None;
        }
        Some((text, expires))
    }

    fn header(&self, url: &Url) -> Option<HeaderValue> {
        let (text, _) = self.cookie_text(url)?;
        let mut header = HeaderValue::from_str(&text).ok()?;
        header.set_sensitive(true);
        Some(header)
    }
}
pub(crate) fn http_client() -> Result<Client, Error> {
    Client::builder()
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
        .connect_timeout(Duration::from_secs(10))
        .https_only(true)
        .build()
        .map_err(|_| unavailable())
}

fn allowed(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.fragment().is_none()
        && url
            .host_str()
            .is_some_and(|host| ALLOWED_HOSTS.contains(&host))
}

struct Hop {
    status: u16,
    url: Url,
    body: String,
    /// The server's own cooldown instruction, forwarded to the governor.
    retry_after: Option<String>,
    challenge: bool,
    content_type: Option<String>,
    redirected: bool,
}

/// One sanitized hop: host, path and status. No header value, body or
/// credential ever enters the trail.
#[derive(Clone)]
struct Trail {
    hops: Vec<String>,
}

impl Trail {
    fn new() -> Self {
        Trail { hops: Vec::new() }
    }

    fn record(&mut self, url: &Url, status: u16) {
        if self.hops.len() > MAX_REDIRECTS {
            return;
        }
        let host = url.host_str().unwrap_or("");
        let path = url.path();
        self.hops.push(format!("{host}{path} {status}"));
    }

    /// Record a redirect target. The query string is dropped: a CAS ticket is
    /// a credential and never belongs in a receipt.
    fn record_redirect(&mut self, from: &Url, to: &Url, status: u16) {
        if self.hops.len() >= MAX_REDIRECTS + 2 {
            return;
        }
        let from_host = from.host_str().unwrap_or("");
        let from_path = from.path();
        let to_host = to.host_str().unwrap_or("");
        let to_path = to.path();
        self.hops.push(format!(
            "{from_host}{from_path} {status} -> {to_host}{to_path}"
        ));
    }

    fn value(&self) -> Value {
        json!(self.hops)
    }
}

/// The query parameter names of the final classroom redirect. Values are
/// credentials (a single sign-on ticket) and never leave the process.
fn query_names(url: &Url) -> Value {
    let names: Vec<String> = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    json!(names)
}

/// Perform one request and follow the reviewed redirect chain by hand. A
/// redirect to any other host is refused rather than followed.
fn send(
    lease: &mut RequestLease<'_>,
    client: &Client,
    jar: &mut Jar,
    start: &Url,
    form: Option<&[(&str, &str)]>,
    trail: &mut Trail,
    initial: bool,
) -> Result<Hop, Error> {
    if form.is_some() && !pinned_login_route(start) {
        return Err(invalid());
    }
    let mut method = if form.is_some() {
        Method::POST
    } else {
        Method::GET
    };
    let mut url = start.clone();
    let mut form = form;
    let mut first = initial;
    let mut had_redirect = false;
    for _ in 0..=MAX_REDIRECTS {
        if !first {
            let reservation = lease.reserve_followup().map_err(|_| unavailable())?;
            if !reservation.cooldown_wait.is_zero() {
                return Err(unavailable());
            }
            if !reservation.request_wait.is_zero() {
                std::thread::sleep(reservation.request_wait);
            }
        }
        first = false;
        if !allowed(&url) {
            return Err(invalid());
        }
        let mut request = client.request(method.clone(), url.clone());
        if let Some(cookie) = jar.header(&url) {
            request = request.header(reqwest::header::COOKIE, cookie);
        }
        if form.is_some() {
            request = request.header(reqwest::header::REFERER, start.as_str());
        }
        if let Some(fields) = form {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in fields {
                serializer.append_pair(name, value);
            }
            request = request
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(serializer.finish());
        }
        let response = request.send().map_err(|_| unavailable())?;
        let status = response.status().as_u16();
        let challenged = response
            .headers()
            .iter()
            .any(|(name, value)| crate::net::challenge_header(name.as_str(), value.as_bytes()));
        let retry_after = match response.headers().get(RETRY_AFTER) {
            Some(value) => match value.to_str() {
                Ok(value) => Some(value.to_string()),
                Err(_) => {
                    if lease.observe_http(status, None, challenged).is_err() {
                        return Err(unavailable());
                    }
                    return Err(unavailable());
                }
            },
            None => None,
        };
        lease
            .observe_http(status, retry_after.as_deref(), challenged)
            .map_err(|_| unavailable())?;
        trail.record(&url, status);
        let content_type = match response.headers().get(CONTENT_TYPE) {
            Some(value) => Some(value.to_str().map_err(|_| unavailable())?.to_string()),
            None => None,
        };
        let location = response.headers().get(LOCATION).cloned();
        jar.absorb(&url, response.headers())?;
        let body = body_text(response)?;
        if (300..=399).contains(&status) {
            if challenged {
                return Ok(Hop {
                    status,
                    url,
                    body,
                    retry_after,
                    challenge: true,
                    content_type,
                    redirected: true,
                });
            }
            let location = match location {
                Some(location) => location.to_str().map_err(|_| unavailable())?.to_string(),
                None => return Err(unavailable()),
            };
            if location.trim().is_empty() {
                return Err(unavailable());
            }
            let next = url.join(&location).map_err(|_| invalid())?;
            if !allowed(&next) {
                return Err(invalid());
            }
            // A redirect cooldown is durable and terminates this attempt. It
            // is never slept through or bypassed inside the authentication
            // flow.
            if retry_after.is_some() {
                return Ok(Hop {
                    status,
                    url,
                    body,
                    retry_after,
                    challenge: challenged,
                    content_type,
                    redirected: true,
                });
            }
            trail.record_redirect(&url, &next, status);
            had_redirect = true;
            url = next;
            method = Method::GET;
            form = None;
            continue;
        }
        if location
            .as_ref()
            .is_some_and(|value| value.to_str().is_err())
        {
            return Err(unavailable());
        }
        return Ok(Hop {
            status,
            url,
            body,
            retry_after,
            challenge: challenged,
            content_type,
            redirected: had_redirect,
        });
    }
    Err(unavailable())
}

fn body_text(response: Response) -> Result<String, Error> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY as u64)
    {
        return Err(unavailable());
    }
    // The advertised length is not the read bound.
    let mut bytes = Vec::new();
    let mut limited = std::io::Read::take(response, (MAX_BODY + 1) as u64);
    limited.read_to_end(&mut bytes).map_err(|_| unavailable())?;
    if bytes.len() > MAX_BODY {
        return Err(unavailable());
    }
    String::from_utf8(bytes).map_err(|_| unavailable())
}

fn pinned_login_url() -> Result<Url, Error> {
    let mut url = Url::parse(SSO_ORIGIN).map_err(|_| invalid())?;
    url.set_path("/login");
    url.query_pairs_mut().append_pair("service", CAS_SERVICE);
    Ok(url)
}

fn pinned_login_route(url: &Url) -> bool {
    if url.scheme() != "https"
        || url.host_str() != Some("sso.buaa.edu.cn")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/login"
        || url.fragment().is_some()
    {
        return false;
    }
    match url.query() {
        None => true,
        Some(_) => {
            let mut pairs = url.query_pairs();
            let Some((name, value)) = pairs.next() else {
                return false;
            };
            name == "service" && value == CAS_SERVICE && pairs.next().is_none()
        }
    }
}

fn failed_code_body(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    value.get("code").is_some() && value.get("code").and_then(Value::as_i64) != Some(0)
}

fn final_response_is_admissible(
    final_host: &str,
    status: u16,
    body: &str,
    challenge: bool,
    retry_after: Option<&str>,
    class: FailureClass,
) -> bool {
    final_host == CLASSROOM_HOST
        && status == 200
        && !body.trim().is_empty()
        && !challenge
        && !body_contains_unverified_challenge_text(body)
        && retry_after.is_none()
        && !failed_code_body(body)
        && class == FailureClass::Unknown
}

fn response_id(value: Option<&Value>, expected: &str) -> bool {
    let expected = expected.parse::<u64>().ok();
    match value {
        Some(Value::String(value)) => {
            valid_numeric_id(value) && value.parse::<u64>().ok() == expected
        }
        Some(Value::Number(value)) => value.as_u64().is_some_and(|value| Some(value) == expected),
        _ => false,
    }
}

fn validate_identity_probe(
    hop: &Hop,
    expected_url: &Url,
    course_id: &str,
    sub_id: &str,
) -> Result<(), Error> {
    if hop.url != *expected_url
        || hop.status != 200
        || hop.redirected
        || hop.challenge
        || hop.retry_after.is_some()
        || hop.body.trim().is_empty()
        || !crate::net::classroom_json_mime(hop.content_type.as_deref())
    {
        return Err(rejected());
    }
    let value: Value = serde_json::from_str(&hop.body).map_err(|_| rejected())?;
    if value.get("code").and_then(Value::as_i64) != Some(0) {
        return Err(rejected());
    }
    let data = value
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(rejected)?;
    if !response_id(data.get("course_id"), course_id) || !response_id(data.get("sub_id"), sub_id) {
        return Err(rejected());
    }
    if let Some(tenant) = data.get("tenant_code").filter(|value| !value.is_null())
        && !response_id(Some(tenant), TENANT_CODE)
    {
        return Err(rejected());
    }
    Ok(())
}

/// Explicit HTML form ownership overrides DOM ancestry.
fn form_control_belongs_to(control: ElementRef<'_>, form: ElementRef<'_>) -> bool {
    if let Some(id) = control.value().attr("form") {
        return !id.is_empty() && form.value().attr("id") == Some(id);
    }
    control
        .ancestors()
        .filter_map(ElementRef::wrap)
        .find(|ancestor| ancestor.value().name() == "form")
        == Some(form)
}

fn strip_css_comments(value: &str) -> Option<std::borrow::Cow<'_, str>> {
    if !value.contains("/*") {
        return Some(std::borrow::Cow::Borrowed(value));
    }
    let mut result = String::with_capacity(value.len());
    let mut remaining = value;
    loop {
        let Some(start) = remaining.find("/*") else {
            result.push_str(remaining);
            break;
        };
        result.push_str(&remaining[..start]);
        let end = remaining[start + 2..].find("*/")?;
        result.push(' ');
        remaining = &remaining[start + 2 + end + 2..];
    }
    Some(std::borrow::Cow::Owned(result))
}

fn declaration_hides_element(property: &str, value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    let normalized = normalized.trim();
    let without_priority = if let Some(before_important) = normalized.strip_suffix("important") {
        if let Some(before_bang) = before_important.trim_end().strip_suffix('!') {
            before_bang.trim_end()
        } else {
            normalized
        }
    } else {
        normalized
    };
    match property {
        "display" => without_priority == "none",
        "visibility" => matches!(without_priority, "hidden" | "collapse"),
        "content-visibility" => without_priority == "hidden",
        _ => false,
    }
}

fn element_is_inert(control: ElementRef<'_>) -> bool {
    for element in std::iter::once(control).chain(control.ancestors().filter_map(ElementRef::wrap))
    {
        if matches!(
            element.value().name(),
            "script" | "style" | "template" | "noscript"
        ) || element.value().attr("hidden").is_some()
            || element.value().attr("inert").is_some()
        {
            return true;
        }
        if let Some(style) = element.value().attr("style") {
            let Some(style) = strip_css_comments(style) else {
                // Malformed CSS cannot prove that a marked control is visible.
                return true;
            };
            for declaration in style.split(';') {
                let Some((property, value)) = declaration.split_once(':') else {
                    continue;
                };
                let property = property.trim().to_ascii_lowercase();
                if declaration_hides_element(&property, value) {
                    return true;
                }
            }
        }
    }
    false
}

fn challenge_control_marker(control: ElementRef<'_>) -> bool {
    let element = control.value();
    if element.name() == "input"
        && element
            .attr("type")
            .is_some_and(|kind| kind.eq_ignore_ascii_case("hidden"))
    {
        return false;
    }
    [
        "name",
        "id",
        "class",
        "aria-label",
        "placeholder",
        "autocomplete",
        "title",
    ]
    .into_iter()
    .filter_map(|name| element.attr(name))
    .any(|value| {
        let lowered = value.to_ascii_lowercase();
        [
            "captcha",
            "challenge",
            "verificationcode",
            "verification-code",
            "verification_code",
            "verification code",
            "验证码",
            "校验码",
        ]
        .iter()
        .any(|marker| lowered.contains(marker))
    })
}

#[derive(Default)]
struct ParsedLoginForm {
    fields: BTreeMap<String, String>,
    has_active_challenge_control: bool,
}

/// The login form's own fields; a missing execution token is a refusal.
fn login_fields(html: &str) -> Result<ParsedLoginForm, Error> {
    let document = Html::parse_document(html);
    let form = Selector::parse("form").map_err(|_| invalid())?;
    let input =
        Selector::parse("input[name], select[name], textarea[name]").map_err(|_| invalid())?;
    let mut selected = None;
    for element in document.select(&form) {
        let mut fields = BTreeMap::new();
        let mut field_bytes = 0usize;
        for input in element.select(&input) {
            if !form_control_belongs_to(input, element) {
                continue;
            }
            let Some(name) = input.value().attr("name") else {
                continue;
            };
            let value = input.value().attr("value").unwrap_or("");
            if name.len() > 256 || value.len() > MAX_FIELD_BYTES {
                continue;
            }
            field_bytes = field_bytes
                .checked_add(name.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or_else(unavailable)?;
            if field_bytes > MAX_FORM_BYTES || fields.len() >= MAX_FORM_FIELDS {
                return Err(unavailable());
            }
            fields
                .entry(name.to_string())
                .or_insert_with(|| value.to_string());
        }
        if fields.contains_key("execution")
            && fields
                .keys()
                .any(|name| name.eq_ignore_ascii_case("password"))
        {
            if selected.is_some() {
                return Err(invalid());
            }
            let Some(action) = element.value().attr("action") else {
                return Err(invalid());
            };
            if action.len() > MAX_FIELD_BYTES || action.chars().any(char::is_control) {
                return Err(invalid());
            }
            let method = element.value().attr("method").unwrap_or("get");
            fields.insert("__action".to_string(), action.to_string());
            fields.insert("__method".to_string(), method.to_ascii_lowercase());
            selected = Some((fields, element));
        }
    }
    let (mut fields, form) = selected.ok_or_else(invalid)?;
    let controls = Selector::parse("input, select, textarea").map_err(|_| invalid())?;
    let challenge_controls =
        Selector::parse("input, select, textarea, button").map_err(|_| invalid())?;
    let fieldsets = Selector::parse("fieldset[disabled]").map_err(|_| invalid())?;
    let disabled_fieldsets: HashMap<_, _> = document
        .select(&fieldsets)
        .map(|fieldset| {
            let first_legend = fieldset
                .children()
                .filter_map(ElementRef::wrap)
                .find(|child| child.value().name() == "legend");
            (fieldset.id(), first_legend.map(|legend| legend.id()))
        })
        .collect();
    let effectively_disabled = |control: ElementRef<'_>| {
        if control.value().attr("disabled").is_some() {
            return true;
        }
        let mut legend_ancestors = HashSet::new();
        for ancestor in control.ancestors().filter_map(ElementRef::wrap) {
            if ancestor.value().name() == "legend" {
                legend_ancestors.insert(ancestor.id());
            }
            if let Some(first_legend) = disabled_fieldsets.get(&ancestor.id())
                && !first_legend.is_some_and(|legend| legend_ancestors.contains(&legend))
            {
                return true;
            }
        }
        false
    };
    let has_active_challenge_control = document.select(&challenge_controls).any(|control| {
        form_control_belongs_to(control, form)
            && !effectively_disabled(control)
            && !element_is_inert(control)
            && challenge_control_marker(control)
    });
    let mut username_seen = false;
    let mut password_seen = false;
    let extra_interaction = document.select(&controls).any(|control| {
        if !form_control_belongs_to(control, form) || effectively_disabled(control) {
            return false;
        }
        let name = control.value().attr("name").unwrap_or("");
        let kind = control.value().attr("type").unwrap_or("text");
        if control.value().name() != "input" {
            return true;
        }
        if name.eq_ignore_ascii_case("username") {
            let duplicate = username_seen;
            username_seen = true;
            return duplicate || !kind.eq_ignore_ascii_case("text");
        }
        if name.eq_ignore_ascii_case("password") {
            let duplicate = password_seen;
            password_seen = true;
            return duplicate || !kind.eq_ignore_ascii_case("password");
        }
        !["hidden", "submit", "button", "reset"]
            .iter()
            .any(|allowed| kind.eq_ignore_ascii_case(allowed))
    });
    if extra_interaction || !username_seen || !password_seen {
        fields.insert("__unreviewed_control".to_string(), String::new());
    }
    Ok(ParsedLoginForm {
        fields,
        has_active_challenge_control,
    })
}

/// Never omit an extra interactive step from the reviewed password flow.
/// A hidden captcha container alone is not an interactive control.
fn requires_challenge(fields: &ParsedLoginForm) -> bool {
    fields.has_active_challenge_control
}

fn requires_interaction_review(fields: &ParsedLoginForm) -> bool {
    fields.fields.contains_key("__unreviewed_control")
}

fn interaction_review_required() -> Error {
    Error::new(
        "auth_latched",
        "Classroom login flow encountered an unreviewed interaction and stopped for explicit operator review.",
    )
}

/// A sanitized class of an unsuccessful authentication. The page text is
/// never returned; only which known condition was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureClass {
    Challenge,
    UnsafeInteraction,
    CredentialRejected,
    ServiceInvalid,
    TicketRejected,
    IdentityUnverified,
    Unknown,
}

impl FailureClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "challenge_required",
            Self::UnsafeInteraction => "unreviewed_login_interaction",
            Self::CredentialRejected => "credential_rejected",
            Self::ServiceInvalid => "service_parameter_rejected",
            Self::TicketRejected => "single_sign_on_ticket_rejected",
            Self::IdentityUnverified => "application_identity_unverified",
            Self::Unknown => "unclassified",
        }
    }
}

fn classify(html: &str, fields: &ParsedLoginForm) -> FailureClass {
    if requires_challenge(fields) {
        return FailureClass::Challenge;
    }
    if requires_interaction_review(fields) {
        return FailureClass::UnsafeInteraction;
    }
    let lowered = html.to_lowercase();
    if lowered.contains("password")
        && (lowered.contains("incorrect")
            || lowered.contains("invalid")
            || lowered.contains("wrong")
            || lowered.contains("error"))
        || html.contains("密码错误")
        || html.contains("用户名或密码")
        || html.contains("账号不存在")
    {
        return FailureClass::CredentialRejected;
    }
    if lowered.contains("service")
        && (lowered.contains("invalid")
            || lowered.contains("not found")
            || lowered.contains("unsupported"))
    {
        return FailureClass::ServiceInvalid;
    }
    if lowered.contains("ticket")
        && (lowered.contains("invalid")
            || lowered.contains("expired")
            || lowered.contains("fail")
            || lowered.contains("error")
            || lowered.contains("未通过")
            || lowered.contains("失效"))
    {
        return FailureClass::TicketRejected;
    }
    FailureClass::Unknown
}

/// A body-text hit is only a success veto; it is never proof of an active challenge.
fn body_contains_unverified_challenge_text(html: &str) -> bool {
    let lowered = html.to_ascii_lowercase();
    lowered.contains("captcha")
        || lowered.contains("challenge")
        || lowered.contains("verification code")
        || html.contains("验证码")
}

fn session_directory() -> Result<File, Error> {
    let home = crate::governor::identity_home().map_err(|_| unavailable())?;
    let _home = crate::governor::open_directory(&home, false, false).map_err(|_| unavailable())?;
    crate::governor::open_directory(&home.join(SESSION_DIRECTORY), true, true)
        .map_err(|_| unavailable())
}

/// Preserve acquired cookie restrictions; never persist single sign-on cookies.
fn store_session(directory: &File, fingerprint: &str, jar: &Jar) -> Result<(), Error> {
    let cookies: Vec<&Cookie> = jar
        .cookies
        .iter()
        .filter(|cookie| classroom_scope(&cookie.scope))
        .collect();
    if cookies.is_empty() || cookies.len() > MAX_COOKIE_COUNT {
        return Err(unavailable());
    }
    let bytes = Zeroizing::new(
        serde_json::to_vec(&StoredSessionRef {
            version: 2,
            cookies: &cookies,
        })
        .map_err(|_| unavailable())?,
    );
    if bytes.len() > MAX_STORED_SESSION_BYTES {
        return Err(unavailable());
    }
    let name = format!("{fingerprint}.session");
    validate_existing_target(directory, &name)?;
    let (temporary_name, mut temporary) =
        crate::governor::create_temporary(directory).map_err(|_| unavailable())?;
    let result = (|| {
        crate::governor::validate_private_file(&temporary).map_err(|_| unavailable())?;
        temporary.write_all(&bytes).map_err(|_| unavailable())?;
        temporary.sync_all().map_err(|_| unavailable())?;
        let target = CString::new(name.as_str()).map_err(|_| unavailable())?;
        // SAFETY: both names are fixed single components in the pinned private
        // directory; the existing target was validated before replacement.
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_name.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err(unavailable());
        }
        directory.sync_all().map_err(|_| unavailable())
    })();
    if result.is_err() {
        // SAFETY: this name was exclusively created by create_temporary in the
        // same pinned directory.
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
    }
    result
}

fn validate_existing_target(directory: &File, name: &str) -> Result<(), Error> {
    match crate::governor::open_child(directory, name, libc::O_RDONLY) {
        Ok(file) => crate::governor::validate_private_file(&file).map_err(|_| unavailable()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(unavailable()),
    }
}

/// Record a sanitized, private account of an unsuccessful attempt. Only the
/// observed class and the host/status trail are kept; no page text, header
/// value or credential is written.
fn write_attempt_receipt(
    directory: &File,
    fingerprint: &str,
    class: FailureClass,
    trail: &Trail,
    query: Value,
) -> Result<(), Error> {
    let receipt = json!({
        "schema_version":1,"type":"classroom_session_attempt","result":"not_established",
        "classification":class.as_str(),
        "hops":trail.value(),
        "final_query_names":query,
        "authentication_attempts":1,
        "credential_persisted":false,
        "session_stored":false
    });
    let mut name = None;
    for _ in 0..16 {
        let sequence = RECEIPT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = format!(
            "{fingerprint}.attempt-{}-{sequence}.json",
            std::process::id()
        );
        // Receipt names are unique and are never opened with truncation. A
        // collision selects another bounded name rather than replacing an
        // earlier failed attempt.
        match crate::governor::open_child(directory, &candidate, libc::O_RDONLY) {
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                name = Some(candidate);
                break;
            }
            Err(_) => return Err(unavailable()),
        }
    }
    let Some(name) = name else {
        return Err(unavailable());
    };
    let (temporary_name, mut temporary) =
        crate::governor::create_temporary(directory).map_err(|_| unavailable())?;
    let result = (|| {
        crate::governor::validate_private_file(&temporary).map_err(|_| unavailable())?;
        serde_json::to_writer(&mut temporary, &receipt).map_err(|_| unavailable())?;
        temporary.write_all(b"\n").map_err(|_| unavailable())?;
        temporary.sync_all().map_err(|_| unavailable())?;
        let target = CString::new(name.as_str()).map_err(|_| unavailable())?;
        // SAFETY: both names are fixed single components in the pinned private
        // directory, and the destination was confirmed absent above.
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_name.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err(unavailable());
        }
        directory.sync_all().map_err(|_| unavailable())
    })();
    if result.is_err() {
        // SAFETY: this name was exclusively created by create_temporary.
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
    }
    result
}

/// Arm exactly one authentication attempt. No network request is made here.
pub fn resume(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: ResumeInput<'_> = serde_json::from_str(input).map_err(|_| invalid())?;
    if request.intent != RESUME_INTENT {
        return Err(invalid());
    }
    let governor = Governor::open().map_err(|_| unavailable())?;
    governor
        .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
        .map_err(|_| unavailable())?;
    Ok(json!({
        "schema_version":1,"type":"classroom_session_resume","result":"one_attempt_armed",
        "network_request_performed":false,"cooldown_cleared":false,
        "instruction":"invoke recordings session --online once with the typed LOGIN intent"
    }))
}

fn settle_failed_attempt(
    lease: RequestLease<'_>,
    fingerprint: &str,
    class: FailureClass,
    trail: &Trail,
    final_url: &Url,
    outcome: crate::governor::Outcome<'_>,
    error: Error,
) -> Error {
    let receipt = session_directory().and_then(|directory| {
        write_attempt_receipt(
            &directory,
            fingerprint,
            class,
            trail,
            query_names(final_url),
        )
    });
    let finished = lease.finish(outcome);
    if receipt.is_err() || finished.is_err() {
        unavailable()
    } else {
        error
    }
}

/// Acquire one classroom session for the operator's account.
pub fn login(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: LoginInput<'_> = serde_json::from_str(input).map_err(|_| invalid())?;
    if !request.authorized {
        return Err(Error::new(
            "permission",
            "Explicit authorization for one classroom authentication attempt is required.",
        ));
    }
    if !valid_secret(&request.username) || !valid_secret(&request.password) {
        return Err(invalid());
    }
    if !valid_numeric_id(&request.verification.course_id)
        || !valid_numeric_id(&request.verification.sub_id)
    {
        return Err(invalid());
    }
    if request.intent != format!("LOGIN {} classroom", request.username) {
        return Err(invalid());
    }

    // Construct and validate all fixed/local values before opening the
    // governor, constructing a client, or performing any I/O.
    let login_url = pinned_login_url()?;
    let classroom_url = Url::parse(CLASSROOM_ORIGIN).map_err(|_| invalid())?;
    let mut probe_url = classroom_url.clone();
    probe_url.set_path("/courseapi/v3/portal-home-setting/get-sub-info");
    probe_url
        .query_pairs_mut()
        .append_pair("sub_id", &request.verification.sub_id)
        .append_pair("course_id", &request.verification.course_id)
        .append_pair("tenant_code", TENANT_CODE);
    let fingerprint = account_fingerprint(&request.username);
    let governor = Governor::open().map_err(|_| unavailable())?;
    let client = http_client()?;
    let mut jar = Jar::default();

    // The lease is held across the whole attempt: every hop and every body is
    // processed before the outcome is recorded.
    let mut lease = acquire_kind(&governor, RequestKind::Authentication)?;
    let mut trail = Trail::new();

    let page = send(
        &mut lease, &client, &mut jar, &login_url, None, &mut trail, true,
    );
    let page = match page {
        Ok(page) => page,
        Err(error) => {
            return Err(settle_failed_attempt(
                lease,
                &fingerprint,
                FailureClass::Unknown,
                &trail,
                &login_url,
                crate::governor::Outcome::NetworkFailure,
                error,
            ));
        }
    };
    if page.url != login_url
        || page.status != 200
        || page.body.trim().is_empty()
        || page.challenge
        || page.redirected
        || page.retry_after.is_some()
    {
        let class = if page.challenge {
            FailureClass::Challenge
        } else {
            FailureClass::Unknown
        };
        let outcome = if page.challenge && (page.retry_after.is_some() || page.status >= 400) {
            crate::governor::Outcome::Http {
                status: page.status,
                retry_after: page.retry_after.as_deref(),
                challenge: true,
                network_failure: false,
            }
        } else if page.challenge {
            crate::governor::Outcome::CaptchaRequired
        } else if !(200..=299).contains(&page.status) {
            crate::governor::Outcome::Http {
                status: page.status,
                retry_after: page.retry_after.as_deref(),
                challenge: false,
                network_failure: false,
            }
        } else {
            crate::governor::Outcome::CredentialRejected
        };
        let error = if page.challenge {
            challenge()
        } else {
            rejected()
        };
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            class,
            &trail,
            &page.url,
            outcome,
            error,
        ));
    }
    let fields = match login_fields(&page.body) {
        Ok(fields) => fields,
        Err(error) => {
            return Err(settle_failed_attempt(
                lease,
                &fingerprint,
                FailureClass::CredentialRejected,
                &trail,
                &page.url,
                crate::governor::Outcome::CredentialRejected,
                error,
            ));
        }
    };
    if requires_challenge(&fields) {
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            FailureClass::Challenge,
            &trail,
            &page.url,
            crate::governor::Outcome::CaptchaRequired,
            challenge(),
        ));
    }
    if requires_interaction_review(&fields) {
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            FailureClass::UnsafeInteraction,
            &trail,
            &page.url,
            crate::governor::Outcome::CredentialRejected,
            interaction_review_required(),
        ));
    }
    let Some(execution) = fields
        .fields
        .get("execution")
        .filter(|value| !value.is_empty())
    else {
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            FailureClass::CredentialRejected,
            &trail,
            &page.url,
            crate::governor::Outcome::CredentialRejected,
            rejected(),
        ));
    };
    if fields.fields.get("__method").map(String::as_str) != Some("post") {
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            FailureClass::CredentialRejected,
            &trail,
            &page.url,
            crate::governor::Outcome::CredentialRejected,
            invalid(),
        ));
    }
    let Some(action) = fields.fields.get("__action") else {
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            FailureClass::CredentialRejected,
            &trail,
            &page.url,
            crate::governor::Outcome::CredentialRejected,
            invalid(),
        ));
    };
    let resolved = match page.url.join(action) {
        Ok(url) => url,
        Err(_) => {
            return Err(settle_failed_attempt(
                lease,
                &fingerprint,
                FailureClass::CredentialRejected,
                &trail,
                &page.url,
                crate::governor::Outcome::CredentialRejected,
                invalid(),
            ));
        }
    };
    if !pinned_login_route(&resolved) {
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            FailureClass::CredentialRejected,
            &trail,
            &page.url,
            crate::governor::Outcome::CredentialRejected,
            invalid(),
        ));
    }

    let username = request.username.as_ref();
    let password = request.password.as_str();
    let form = [
        ("username", username),
        ("password", password),
        (
            "type",
            fields
                .fields
                .get("type")
                .map(String::as_str)
                .unwrap_or("username_password"),
        ),
        ("execution", execution.as_str()),
        (
            "_eventId",
            fields
                .fields
                .get("_eventId")
                .map(String::as_str)
                .unwrap_or("submit"),
        ),
        (
            "submit",
            fields
                .fields
                .get("submit")
                .map(String::as_str)
                .unwrap_or("LOGIN"),
        ),
    ];

    let posted = send(
        &mut lease,
        &client,
        &mut jar,
        &login_url,
        Some(&form),
        &mut trail,
        false,
    );
    let posted = match posted {
        Ok(posted) => posted,
        Err(error) => {
            return Err(settle_failed_attempt(
                lease,
                &fingerprint,
                FailureClass::Unknown,
                &trail,
                &login_url,
                crate::governor::Outcome::NetworkFailure,
                error,
            ));
        }
    };
    let final_url = posted.url.clone();
    let final_host = final_url.host_str().unwrap_or("").to_string();
    let final_fields = login_fields(&posted.body).unwrap_or_default();
    let final_challenge = posted.challenge || requires_challenge(&final_fields);
    let final_class = if final_challenge {
        FailureClass::Challenge
    } else {
        classify(&posted.body, &final_fields)
    };
    let final_success_shape = final_response_is_admissible(
        &final_host,
        posted.status,
        &posted.body,
        final_challenge,
        posted.retry_after.as_deref(),
        final_class,
    );
    let classroom_header = jar.header(&probe_url);
    let sign_in_page = final_fields
        .fields
        .keys()
        .any(|name| name.eq_ignore_ascii_case("password"));
    if !final_success_shape || classroom_header.is_none() || sign_in_page {
        let class = final_class;
        let outcome = if (400..=599).contains(&posted.status) {
            crate::governor::Outcome::Http {
                status: posted.status,
                retry_after: posted.retry_after.as_deref(),
                challenge: final_challenge,
                network_failure: false,
            }
        } else if final_challenge {
            crate::governor::Outcome::CaptchaRequired
        } else {
            crate::governor::Outcome::CredentialRejected
        };
        let error = match class {
            FailureClass::Challenge => challenge(),
            FailureClass::UnsafeInteraction => interaction_review_required(),
            _ => rejected(),
        };
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            class,
            &trail,
            &final_url,
            outcome,
            error,
        ));
    }

    // Positive application admission is a separate fresh request held by the
    // same authentication lease. A classroom cookie and a 200 redirect alone
    // never establish a session or imply account identity/rights.
    let probe = send(
        &mut lease, &client, &mut jar, &probe_url, None, &mut trail, false,
    );
    let probe = match probe {
        Ok(probe) => probe,
        Err(error) => {
            return Err(settle_failed_attempt(
                lease,
                &fingerprint,
                FailureClass::IdentityUnverified,
                &trail,
                &probe_url,
                crate::governor::Outcome::NetworkFailure,
                error,
            ));
        }
    };
    if let Err(error) = validate_identity_probe(
        &probe,
        &probe_url,
        &request.verification.course_id,
        &request.verification.sub_id,
    ) {
        let class = if probe.challenge {
            FailureClass::Challenge
        } else {
            FailureClass::IdentityUnverified
        };
        let outcome = if probe.challenge && (probe.retry_after.is_some() || probe.status >= 400) {
            crate::governor::Outcome::Http {
                status: probe.status,
                retry_after: probe.retry_after.as_deref(),
                challenge: true,
                network_failure: false,
            }
        } else if probe.challenge {
            crate::governor::Outcome::CaptchaRequired
        } else if (400..=599).contains(&probe.status) {
            crate::governor::Outcome::Http {
                status: probe.status,
                retry_after: probe.retry_after.as_deref(),
                challenge: false,
                network_failure: false,
            }
        } else {
            crate::governor::Outcome::CredentialRejected
        };
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            class,
            &trail,
            &probe.url,
            outcome,
            if class == FailureClass::Challenge {
                challenge()
            } else {
                error
            },
        ));
    }

    let classroom_header = jar.header(&probe_url);
    let cookie = match classroom_header
        .as_ref()
        .and_then(|value| value.to_str().ok())
    {
        Some(cookie) => cookie.to_string(),
        None => {
            return Err(settle_failed_attempt(
                lease,
                &fingerprint,
                FailureClass::IdentityUnverified,
                &trail,
                &probe_url,
                crate::governor::Outcome::CredentialRejected,
                unavailable(),
            ));
        }
    };
    let classroom_names: Vec<String> = cookie
        .split(';')
        .filter_map(|pair| {
            pair.split_once('=')
                .map(|(name, _)| name.trim().to_string())
        })
        .collect();
    let directory = match session_directory() {
        Ok(directory) => directory,
        Err(error) => {
            return Err(
                if lease.finish(crate::governor::Outcome::Success).is_err() {
                    unavailable()
                } else {
                    error
                },
            );
        }
    };
    if let Err(error) = store_session(&directory, &fingerprint, &jar) {
        return Err(
            if lease.finish(crate::governor::Outcome::Success).is_err() {
                unavailable()
            } else {
                error
            },
        );
    }
    if lease.finish(crate::governor::Outcome::Success).is_err() {
        return Err(unavailable());
    }

    Ok(json!({
        "schema_version":1,"type":"classroom_session","result":"session_observed",
        "authorization":{"basis":"operator_attestation","media_rights_verified":false,"account_identity_verified":false},
        "account_fingerprint":fingerprint,
        "verification":{"scope":"selected_lesson_response","course_id":request.verification.course_id,"sub_id":request.verification.sub_id,"tenant_code":TENANT_CODE},
        "session":{"cookie_names":classroom_names,"storage":"private_owner_only_file","credential_persisted":false},
        "network":{"origin":SSO_ORIGIN,"method":"POST","authentication_attempts":1,"redirect_hosts":ALLOWED_HOSTS,"positive_probe":"get-sub-info"},
        "network_access":true,"catalog_modified":false
    }))
}

fn stored_session_in(directory: &File, fingerprint: &str) -> Result<Jar, Error> {
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let name = format!("{fingerprint}.session");
    let file = crate::governor::open_child(directory, &name, libc::O_RDONLY)
        .map_err(|_| Error::new("unavailable", "No stored classroom session exists."))?;
    crate::governor::validate_private_file(&file).map_err(|_| unavailable())?;
    let mut file = file;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut limited = std::io::Read::take(&mut file, (MAX_STORED_SESSION_BYTES + 1) as u64);
    limited.read_to_end(&mut bytes).map_err(|_| unavailable())?;
    if bytes.is_empty() || bytes.len() > MAX_STORED_SESSION_BYTES {
        return Err(unavailable());
    }
    let stored: StoredSession = serde_json::from_slice(&bytes).map_err(|_| Error::new(
        "unavailable", "Stored classroom session metadata is unsupported; deliberate authentication is required."
    ))?;
    if stored.version != 2
        || stored.cookies.is_empty()
        || stored.cookies.len() > MAX_COOKIE_COUNT
        || stored.cookies.iter().any(|cookie| {
            !valid_cookie_name(&cookie.name)
                || !valid_cookie_value(&cookie.value)
                || !classroom_scope(&cookie.scope)
                || !cookie.path.starts_with('/')
                || cookie.path.len() > MAX_COOKIE_PATH
                || cookie.path.chars().any(char::is_control)
                || cookie
                    .expiry
                    .is_some_and(|expiry| expiry.duration_since(UNIX_EPOCH).is_err())
        })
    {
        return Err(unavailable());
    }
    Ok(Jar {
        cookies: stored.cookies,
    })
}

pub fn schema() -> Value {
    json!({
        "resume":{
            "input":{"type":"object","additionalProperties":false,"required":["intent"],"properties":{
                "intent":{"const":RESUME_INTENT}
            }},
            "output":{"type":"object","properties":{
                "schema_version":{"const":1},"type":{"const":"classroom_session_resume"},
                "result":{"const":"one_attempt_armed"},"network_request_performed":{"const":false},
                "cooldown_cleared":{"const":false}
            }}
        },
        "login":{
            "input":{"type":"object","additionalProperties":false,"required":["authorized","username","password","verification","intent"],"properties":{
                "authorized":{"const":true},
                "username":{"type":"string","minLength":1,"maxLength":1024,"writeOnly":true},
                "password":{"type":"string","minLength":1,"maxLength":1024,"writeOnly":true},
                "verification":{"type":"object","additionalProperties":false,"required":["course_id","sub_id"],"properties":{
                    "course_id":{"type":"string","pattern":"^[0-9]{1,20}$","description":"Positive ASCII decimal u64 lesson ID."},
                    "sub_id":{"type":"string","pattern":"^[0-9]{1,20}$","description":"Positive ASCII decimal u64 lesson ID."}
                }},
                "intent":{"type":"string","minLength":1,"maxLength":2048,"description":"Exact typed intent: LOGIN <username> classroom."}
            }},
            "output":{"type":"object","properties":{
                "schema_version":{"const":1},"type":{"const":"classroom_session"},
                "result":{"const":"session_observed"},
                "authorization":{"type":"object","required":["basis","media_rights_verified","account_identity_verified"],"properties":{
                    "basis":{"const":"operator_attestation"},"media_rights_verified":{"const":false},"account_identity_verified":{"const":false}
                }},
                "account_fingerprint":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                "verification":{"type":"object","additionalProperties":false,"required":["scope","course_id","sub_id","tenant_code"],"properties":{
                    "scope":{"const":"selected_lesson_response"},"course_id":{"type":"string"},"sub_id":{"type":"string"},"tenant_code":{"const":TENANT_CODE}
                }},
                "network_access":{"const":true}
            }}
        },
        "description":"Governed classroom platform session acquisition. One deliberate authentication attempt per operator resume; the credential is read from protected stdin only, is never persisted and never appears in argv, logs, cache or output. The classroom-origin session cookie is kept in an owner-only private file and referenced by a non-secret account fingerprint. No automatic login refresh, fallback or retry; a rejection or challenge latches and is never bypassed."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    const REVIEWED_LOGIN_PAGE: &str = r#"<html><body>
    <form method="post" id="loginForm" action="login">
    <input name="username" type="text">
    <input name="password" type="password">
    <input name="submit" type="submit" value="LOGIN">
    <input name="type" type="hidden" value="username_password">
    <input name="execution" type="hidden" value="synthetic-execution-token">
    <input name="_eventId" type="hidden" value="submit">
    </form>
    <div class="form-group" style="display: none;" id="captchaParent">
    <span style="display: none;" id="captchaLabel">Validation Code</span>
    <div id="captchaDiv"></div>
    </div>
    </body></html>"#;

    fn temporary_directory(name: &str) -> (File, std::path::PathBuf) {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "buaa-cli-session-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("private test directory");
        let directory =
            crate::governor::open_directory(&path, true, true).expect("pinned directory");
        (directory, path)
    }

    fn assert_unreviewed_interaction(fields: &ParsedLoginForm) {
        assert!(requires_interaction_review(fields));
        assert!(!requires_challenge(fields));
        assert_eq!(classify("", fields), FailureClass::UnsafeInteraction);
        let error = interaction_review_required();
        assert_eq!(error.code, "auth_latched");
        assert!(error.message.contains("operator review"));
    }

    #[test]
    fn a_hidden_captcha_container_is_not_a_required_challenge() {
        let fields = login_fields(REVIEWED_LOGIN_PAGE).expect("login fields");
        assert!(!requires_challenge(&fields));
        assert!(body_contains_unverified_challenge_text(REVIEWED_LOGIN_PAGE));
        assert_eq!(
            classify(REVIEWED_LOGIN_PAGE, &fields),
            FailureClass::Unknown
        );
        let challenged = login_fields(
            r#"<form method="post" action="login"><input name="password"><input name="execution" value="token"><input name="captcha"></form>"#,
        )
        .expect("form");
        assert!(requires_challenge(&challenged));
        assert_eq!(classify("", &challenged), FailureClass::Challenge);
        assert!(!final_response_is_admissible(
            CLASSROOM_HOST,
            200,
            REVIEWED_LOGIN_PAGE,
            false,
            None,
            FailureClass::Unknown,
        ));
        assert!(final_response_is_admissible(
            CLASSROOM_HOST,
            200,
            "ordinary response",
            false,
            None,
            FailureClass::Unknown,
        ));
        assert!(!final_response_is_admissible(
            CLASSROOM_HOST,
            200,
            "interactive challenge",
            true,
            None,
            FailureClass::Unknown,
        ));

        for control in [
            r#"<input name="captcha" type="hidden" value="token">"#,
            r#"<input name="captcha" disabled>"#,
            r#"<span hidden><input name="captcha"></span>"#,
            r#"<span style="display: none"><input name="captcha"></span>"#,
            r#"<fieldset disabled><input name="captcha"></fieldset>"#,
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"));
            assert!(
                !requires_challenge(&login_fields(&page).unwrap()),
                "{control}"
            );
        }
        for style in [
            "display:none!important",
            "visibility:hidden !important",
            "display:none ! important",
            "display:none !/**/important",
            "visibility:hidden ! /* priority */ important",
            "display/**/:none ! important",
            "visibility/**/:hidden !/**/important",
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(r#"<input name="captcha" type="text" style="{style}"></form>"#),
            );
            assert_unreviewed_interaction(&login_fields(&page).unwrap());
        }
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<fieldset disabled><legend><input name="captcha"></legend></fieldset></form>"#,
        );
        assert!(requires_challenge(&login_fields(&page).unwrap()));
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<fieldset disabled><legend>caption</legend><legend><input name="captcha"></legend></fieldset></form>"#,
        );
        assert!(!requires_challenge(&login_fields(&page).unwrap()));
    }

    #[test]
    fn extra_login_controls_cannot_be_omitted_from_the_password_flow() {
        for control in [
            r#"<input name="unfamiliarStep">"#,
            r#"<select name="verification"><option>choose</option></select>"#,
            r#"<textarea name="answer"></textarea>"#,
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"));
            let fields = login_fields(&page).unwrap();
            assert_unreviewed_interaction(&fields);
        }
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="verificationCode" required></form>"#,
        );
        let fields = login_fields(&page).unwrap();
        assert!(requires_challenge(&fields));
        assert_eq!(classify("", &fields), FailureClass::Challenge);
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="csrf" type="hidden"><input name="disabledStep" disabled></form>"#,
        );
        let fields = login_fields(&page).unwrap();
        assert!(!requires_challenge(&fields));
        assert!(!requires_interaction_review(&fields));
    }

    #[test]
    fn login_safety_includes_external_and_unnamed_associated_controls() {
        let verification = format!(
            r#"{REVIEWED_LOGIN_PAGE}<input form="loginForm" name="verificationCode" required>"#
        );
        assert!(requires_challenge(&login_fields(&verification).unwrap()));
        for page in [
            format!(r#"{REVIEWED_LOGIN_PAGE}<textarea form="loginForm" required></textarea>"#),
            REVIEWED_LOGIN_PAGE.replace("</form>", "<input required></form>"),
        ] {
            let fields = login_fields(&page).unwrap();
            assert_unreviewed_interaction(&fields);
        }
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input form="other" name="captcha" required></form>"#,
        );
        assert!(!requires_challenge(&login_fields(&page).unwrap()));
        let page = format!(
            r#"{REVIEWED_LOGIN_PAGE}<form id="other"><input name="verificationCode" required></form>"#
        );
        assert!(!requires_challenge(&login_fields(&page).unwrap()));
    }

    #[test]
    fn credential_controls_are_unique_typed_elements_not_only_names() {
        for control in [
            r#"<input name="username" type="checkbox" required>"#,
            r#"<input name="username" type="text" required>"#,
            r#"<input name="password" type="password" required>"#,
        ] {
            let inside = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"));
            assert_unreviewed_interaction(&login_fields(&inside).unwrap());
            let outside = format!(
                "{REVIEWED_LOGIN_PAGE}{}",
                control.replace("<input ", "<input form=\"loginForm\" ")
            );
            assert_unreviewed_interaction(&login_fields(&outside).unwrap());
        }
        for (reviewed, changed) in [
            (
                r#"name="username" type="text""#,
                r#"name="username" type="checkbox" required"#,
            ),
            (
                r#"name="password" type="password""#,
                r#"name="password" type="text""#,
            ),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace(reviewed, changed);
            assert_unreviewed_interaction(&login_fields(&page).unwrap());
        }
    }

    #[test]
    fn credential_admission_respects_disabled_fieldsets_and_first_legend_exceptions() {
        let username = r#"<input name="username" type="text">"#;
        let password = r#"<input name="password" type="password">"#;
        let wrap = |open: &str, close: &str| {
            REVIEWED_LOGIN_PAGE
                .replace(username, &format!("{open}{username}"))
                .replace(password, &format!("{password}{close}"))
        };
        let page = wrap("<fieldset disabled>", "</fieldset>");
        assert_unreviewed_interaction(&login_fields(&page).unwrap());
        let page = wrap("<fieldset disabled><legend>", "</legend></fieldset>");
        let fields = login_fields(&page).unwrap();
        assert!(!requires_challenge(&fields));
        assert!(!requires_interaction_review(&fields));
        let page = wrap(
            "<fieldset disabled><legend>caption</legend><legend>",
            "</legend></fieldset>",
        );
        assert_unreviewed_interaction(&login_fields(&page).unwrap());
        let page = wrap(
            "<fieldset disabled><legend><fieldset disabled><legend>inner</legend>",
            "</fieldset></legend></fieldset>",
        );
        assert_unreviewed_interaction(&login_fields(&page).unwrap());
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            "<fieldset disabled><input name=\"extra\" required></fieldset></form>",
        );
        let fields = login_fields(&page).unwrap();
        assert!(!requires_challenge(&fields));
        assert!(!requires_interaction_review(&fields));
    }

    #[test]
    fn max_age_controls_cookie_deletion_and_lifetime_in_either_attribute_order() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let now = SystemTime::now();
        let future =
            chrono::DateTime::<chrono::Utc>::from(now + Duration::from_secs(86400)).to_rfc2822();
        for max_first in [false, true] {
            let attributes = |max_age| {
                if max_first {
                    format!("Max-Age={max_age}; Expires={future}")
                } else {
                    format!("Expires={future}; Max-Age={max_age}")
                }
            };
            for value in ["", "deleted"] {
                let mut jar = Jar::default();
                let mut initial = HeaderMap::new();
                initial.insert(
                    SET_COOKIE,
                    HeaderValue::from_static("session=original; Path=/"),
                );
                jar.absorb(&origin, &initial).unwrap();
                let mut deletion = HeaderMap::new();
                deletion.insert(
                    SET_COOKIE,
                    HeaderValue::from_str(&format!("session={value}; Path=/; {}", attributes(0)))
                        .unwrap(),
                );
                jar.absorb(&origin, &deletion).unwrap();
                assert!(jar.header(&origin).is_none());
            }
            let mut jar = Jar::default();
            let mut replacement = HeaderMap::new();
            replacement.insert(
                SET_COOKIE,
                HeaderValue::from_str(&format!("session=current; Path=/; {}", attributes(3600)))
                    .unwrap(),
            );
            jar.absorb(&origin, &replacement).unwrap();
            assert_eq!(jar.header(&origin).unwrap(), "session=current");
            let lifetime = jar.cookies[0].expiry.unwrap().duration_since(now).unwrap();
            assert!(lifetime >= Duration::from_secs(3500) && lifetime < Duration::from_secs(3700));
        }
    }

    #[test]
    fn cookies_follow_their_own_scope() {
        let mut jar = Jar::default();
        let sso = Url::parse("https://sso.buaa.edu.cn/login").expect("sso url");
        let yjapi = Url::parse("https://yjapi.msa.buaa.edu.cn/casapi/index.php").expect("url");
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("CASTGC=cas-ticket; Path=/; Domain=.buaa.edu.cn"),
        );
        jar.absorb(&sso, &headers).expect("sso cookie");

        let classroom = Url::parse("https://classroom.msa.buaa.edu.cn/livingroom").expect("url");
        // The sign-on credential never reaches another host.
        assert!(jar.header(&classroom).is_none());
        let sso_value = jar.header(&sso).expect("sso cookie header");
        assert_eq!(sso_value.to_str().expect("text"), "CASTGC=cas-ticket");

        // A platform-family domain cookie is shared with the classroom host.
        let mut platform_headers = HeaderMap::new();
        platform_headers.append(
            SET_COOKIE,
            HeaderValue::from_static("PHPSESSID=platform; Path=/; Domain=.msa.buaa.edu.cn"),
        );
        jar.absorb(&yjapi, &platform_headers)
            .expect("platform cookie");
        let sso_value = jar.header(&sso).expect("sso header");
        let sso_header = sso_value.to_str().expect("text");
        assert!(!sso_header.contains("PHPSESSID"));
        let classroom_value = jar.header(&classroom).expect("classroom header");
        assert_eq!(
            classroom_value.to_str().expect("text"),
            "PHPSESSID=platform"
        );

        // A host-only cookie stays with the host that set it.
        let mut host_only = HeaderMap::new();
        host_only.append(
            SET_COOKIE,
            HeaderValue::from_static("PHPSESSID=host-only; Path=/"),
        );
        let mut jar = Jar::default();
        jar.absorb(&yjapi, &host_only).expect("host cookie");
        assert!(jar.header(&classroom).is_none());
        assert!(jar.header(&yjapi).is_some());
    }

    #[test]
    fn a_broader_domain_never_widens_a_cookie() {
        let mut jar = Jar::default();
        let sso = Url::parse("https://sso.buaa.edu.cn/login").expect("sso url");
        let classroom = Url::parse("https://classroom.msa.buaa.edu.cn/").expect("url");
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("CAS=wide; Domain=.buaa.edu.cn"),
        );
        jar.absorb(&sso, &headers).expect("wide cookie");
        assert!(jar.header(&classroom).is_none());
        assert!(jar.header(&sso).is_some());
    }

    #[test]
    fn cookie_paths_and_expiry_never_widen_or_retain_stale_sessions() {
        let mut jar = Jar::default();
        let yjapi = Url::parse("https://yjapi.msa.buaa.edu.cn/casapi/login").expect("url");
        let classroom = Url::parse("https://classroom.msa.buaa.edu.cn/courseapi/v3").expect("url");
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("PHPSESSID=path-bound; Domain=.msa.buaa.edu.cn"),
        );
        jar.absorb(&yjapi, &headers).expect("cookie");
        assert!(jar.header(&classroom).is_none());

        let mut platform = HeaderMap::new();
        platform.append(
            SET_COOKIE,
            HeaderValue::from_static("PHPSESSID=platform; Domain=.msa.buaa.edu.cn; Path=/"),
        );
        jar.absorb(&yjapi, &platform).expect("platform cookie");
        assert!(jar.header(&classroom).is_some());

        let mut expired = HeaderMap::new();
        expired.append(
            SET_COOKIE,
            HeaderValue::from_static("PHPSESSID=gone; Domain=.msa.buaa.edu.cn; Path=/; Max-Age=0"),
        );
        jar.absorb(&yjapi, &expired).expect("expiry");
        assert!(jar.header(&classroom).is_none());
    }

    #[test]
    fn pinned_login_route_rejects_form_exfiltration_and_route_widening() {
        let page = pinned_login_url().expect("pinned login");
        assert!(pinned_login_route(&page));
        for action in [
            "https://evil.example/login",
            "https://sso.buaa.edu.cn/other",
            "https://sso.buaa.edu.cn/login?service=https%3A%2F%2Fevil.example%2F",
            "https://sso.buaa.edu.cn/login#fragment",
        ] {
            let action = Url::parse(action).expect("action");
            assert!(!pinned_login_route(&action), "{action}");
        }
        assert!(pinned_login_route(&page.join("login").expect("relative")));
    }

    #[test]
    fn identity_probe_requires_fresh_success_and_exact_lesson_ids() {
        let url = Url::parse(
            "https://classroom.msa.buaa.edu.cn/courseapi/v3/portal-home-setting/get-sub-info",
        )
        .expect("url");
        let hop = |body: &str| Hop {
            status: 200,
            url: url.clone(),
            body: body.to_string(),
            retry_after: None,
            challenge: false,
            content_type: Some("application/json; charset=utf-8".to_string()),
            redirected: false,
        };
        assert!(
            validate_identity_probe(
                &hop(r#"{"code":0,"data":{"course_id":"12","sub_id":"34"}}"#),
                &url,
                "12",
                "34"
            )
            .is_ok()
        );
        assert!(
            validate_identity_probe(
                &hop(r#"{"code":1,"data":{"course_id":"12","sub_id":"34"}}"#),
                &url,
                "12",
                "34"
            )
            .is_err()
        );
        assert!(
            validate_identity_probe(
                &hop(r#"{"code":0,"data":{"course_id":"12","sub_id":"35"}}"#),
                &url,
                "12",
                "34"
            )
            .is_err()
        );
        let mut observed_label = hop(r#"{"code":0,"data":{"course_id":"12","sub_id":"34"}}"#);
        for tenant in [json!(21), json!("21"), Value::Null] {
            let body =
                json!({"code":0,"data":{"course_id":"12","sub_id":"34","tenant_code":tenant}})
                    .to_string();
            assert!(validate_identity_probe(&hop(&body), &url, "12", "34").is_ok());
        }
        for tenant in [json!(22), json!("22"), json!(false), json!("")] {
            let body =
                json!({"code":0,"data":{"course_id":"12","sub_id":"34","tenant_code":tenant}})
                    .to_string();
            assert!(validate_identity_probe(&hop(&body), &url, "12", "34").is_err());
        }
        observed_label.content_type = Some("text/html; charset=UTF-8".to_string());
        assert!(validate_identity_probe(&observed_label, &url, "12", "34").is_ok());
        observed_label.challenge = true;
        assert!(validate_identity_probe(&observed_label, &url, "12", "34").is_err());
        observed_label.challenge = false;
        observed_label.url = Url::parse("https://example.invalid/identity").unwrap();
        assert!(validate_identity_probe(&observed_label, &url, "12", "34").is_err());
        observed_label.url = url.clone();
        observed_label.content_type = Some("application/octet-stream".to_string());
        assert!(validate_identity_probe(&observed_label, &url, "12", "34").is_err());
        observed_label.content_type = Some("application/json".to_string());
        observed_label.body.clear();
        assert!(validate_identity_probe(&observed_label, &url, "12", "34").is_err());
    }

    #[test]
    fn failed_code_body_cannot_look_like_a_successful_redirect() {
        assert!(failed_code_body(r#"{"code":401,"data":{}}"#));
        assert!(!failed_code_body(r#"{"code":0,"data":{}}"#));
        assert!(!failed_code_body("<html>classroom</html>"));
    }

    #[test]
    fn verification_ids_are_positive_bounded_ascii_u64_strings() {
        assert!(valid_numeric_id("1"));
        assert!(valid_numeric_id("0001"));
        assert!(valid_numeric_id("18446744073709551615"));
        assert!(!valid_numeric_id("0"));
        assert!(!valid_numeric_id("18446744073709551616"));
        assert!(!valid_numeric_id("１２"));
        assert!(!valid_numeric_id("123456789012345678901"));
    }

    #[test]
    fn only_the_reviewed_hosts_are_admitted() {
        for host in ALLOWED_HOSTS {
            let url = Url::parse(&format!("https://{host}/path")).expect("url");
            assert!(allowed(&url), "{host} must be admitted");
        }
        for candidate in [
            "http://sso.buaa.edu.cn/login",
            "https://user@sso.buaa.edu.cn/login",
            "https://sso.buaa.edu.cn:8443/login",
            "https://sso.buaa.edu.cn.evil.example/login",
            "https://sso.buaa.edu.cn/login#fragment",
            "https://example.invalid/login",
        ] {
            let url = Url::parse(candidate).expect("url");
            assert!(!allowed(&url), "{candidate} must be refused");
        }
    }

    #[test]
    fn the_account_fingerprint_is_stable_and_carries_no_credential() {
        let first = account_fingerprint("student");
        assert_eq!(first, account_fingerprint("student"));
        assert_ne!(first, account_fingerprint("other"));
        assert_eq!(first.len(), 64);
        assert!(!first.contains("student"));
    }

    #[test]
    fn a_wrong_typed_intent_is_refused_before_any_request() {
        let attempt = r#"{"authorized":true,"username":"student","password":"secret","intent":"LOGIN student"}"#;
        assert_eq!(
            login(attempt).expect_err("wrong intent").code,
            "invalid_input"
        );
        let arm = r#"{"intent":"RESUME GATEWAY AUTH"}"#;
        assert_eq!(resume(arm).expect_err("wrong intent").code, "invalid_input");
    }

    #[test]
    fn a_stored_session_round_trips_in_a_private_directory() {
        let (directory, path) = temporary_directory("round-trip");
        let fingerprint = account_fingerprint("student");
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let mut jar = Jar::default();
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("wide=app; Path=/; Max-Age=3600"),
        );
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static(
                "narrow=value; Path=/courseapi/v3/portal-home-setting; Max-Age=3600",
            ),
        );
        jar.absorb(&origin, &headers).unwrap();
        let expiry = jar.cookies[1].expiry;
        store_session(&directory, &fingerprint, &jar).expect("store");
        let loaded = stored_session_in(&directory, &fingerprint).expect("load");
        assert_eq!(loaded.cookies[1].expiry, expiry);
        let credentials = SessionCredentials {
            supplied: None,
            stored: loaded,
        };
        let probe = origin
            .join("/courseapi/v3/portal-home-setting/get-sub-info")
            .unwrap();
        let detail = origin
            .join("/courseapi/v3/multi-search/get-sub-detail")
            .unwrap();
        let transcript = origin.join("/courseapi/v3/web-socket").unwrap();
        assert_eq!(
            credentials
                .with_header(&probe, |header, _| Ok(header.to_owned()))
                .unwrap(),
            "wide=app; narrow=value"
        );
        for url in [&detail, &transcript] {
            assert_eq!(
                credentials
                    .with_header(url, |header, _| Ok(header.to_owned()))
                    .unwrap(),
                "wide=app"
            );
        }
        let mut expired = credentials.stored;
        for cookie in &mut expired.cookies {
            cookie.expiry = Some(UNIX_EPOCH);
        }
        store_session(&directory, &fingerprint, &expired).unwrap();
        let expired = SessionCredentials {
            supplied: None,
            stored: stored_session_in(&directory, &fingerprint).unwrap(),
        };
        assert!(
            expired
                .with_header::<()>(&probe, |_, _| panic!("expired cookie reached a request"))
                .is_err()
        );
        let metadata =
            std::fs::metadata(path.join(format!("{fingerprint}.session"))).expect("metadata");
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert!(stored_session_in(&directory, "not-a-fingerprint").is_err());
    }

    #[test]
    fn an_existing_hardlink_is_refused_before_session_replacement() {
        let (directory, path) = temporary_directory("hardlink");
        let fingerprint = account_fingerprint("student");
        let original = path.join("outside");
        std::fs::write(&original, b"JSESSIONID=other").expect("outside");
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600))
            .expect("private outside");
        let target = path.join(format!("{fingerprint}.session"));
        std::fs::hard_link(&original, &target).expect("hard link");
        let jar = Jar {
            cookies: vec![Cookie {
                name: "JSESSIONID".into(),
                value: "new".into(),
                scope: Scope::Host(CLASSROOM_HOST.into()),
                path: "/".into(),
                expiry: None,
            }],
        };
        assert!(store_session(&directory, &fingerprint, &jar).is_err());
        assert_eq!(std::fs::read(&original).expect("read"), b"JSESSIONID=other");
    }

    #[test]
    fn legacy_flat_sessions_are_not_promoted_to_unrestricted_cookies() {
        let (directory, path) = temporary_directory("legacy-flat");
        let fingerprint = account_fingerprint("student");
        let target = path.join(format!("{fingerprint}.session"));
        std::fs::write(&target, b"JSESSIONID=app").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(stored_session_in(&directory, &fingerprint).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"JSESSIONID=app");
    }

    #[test]
    fn a_failed_attempt_is_classified_without_echoing_the_page() {
        let fields = ParsedLoginForm::default();
        assert_eq!(
            classify("用户名或密码错误", &fields),
            FailureClass::CredentialRejected
        );
        assert_eq!(
            classify("service not found", &fields),
            FailureClass::ServiceInvalid
        );
        assert_eq!(classify("nothing notable", &fields), FailureClass::Unknown);
        assert_eq!(
            classify("CAS ticket invalid or expired", &fields),
            FailureClass::TicketRejected
        );
        let challenged = ParsedLoginForm {
            fields: BTreeMap::new(),
            has_active_challenge_control: true,
        };
        assert_eq!(classify("anything", &challenged), FailureClass::Challenge);
    }

    #[test]
    fn the_hop_trail_records_only_host_path_and_status() {
        let mut trail = Trail::new();
        let url = Url::parse("https://sso.buaa.edu.cn/login?service=secret").expect("url");
        trail.record(&url, 302);
        let recorded = trail.value().as_array().expect("hops").clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], json!("sso.buaa.edu.cn/login 302"));
        assert!(!recorded[0].as_str().expect("hop").contains("secret"));
    }

    #[test]
    fn a_redirect_trail_entry_drops_the_query_string() {
        let mut trail = Trail::new();
        let from = Url::parse("https://yjapi.msa.buaa.edu.cn/casapi/index.php").expect("url");
        let to =
            Url::parse("https://classroom.msa.buaa.edu.cn/?ticket=ST-secret-value").expect("url");
        trail.record_redirect(&from, &to, 302);
        let recorded = trail.value().as_array().expect("hops").clone();
        assert_eq!(
            recorded[0],
            json!("yjapi.msa.buaa.edu.cn/casapi/index.php 302 -> classroom.msa.buaa.edu.cn/")
        );
        assert!(
            !recorded[0]
                .as_str()
                .expect("hop")
                .contains("ST-secret-value")
        );
    }
}
