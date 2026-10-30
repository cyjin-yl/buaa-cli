//! Governed classroom platform session acquisition.
//!
//! One deliberate authentication attempt per operator resume. The credential
//! arrives on protected stdin, never in argv, logs, cache or output. The
//! session cookie is kept in a private owner-only file and referenced by a
//! non-secret account fingerprint; the credential itself is never persisted.
use crate::governor::{Governor, RequestKind, RequestLease, ResumeAuthorization};
use crate::net::{CLASSROOM_ORIGIN, Error, acquire_kind};
use ego_tree::NodeId;
use reqwest::Method;
use reqwest::blocking::{Client, Response};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, LOCATION, RETRY_AFTER, SET_COOKIE};
use scraper::{ElementRef, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod form_source;

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
const MAX_LOGIN_DOM_ELEMENTS: usize = 8192;
const MAX_LOGIN_DOM_DEPTH: usize = 256;
const MAX_LOGIN_TEXT_SUBTREE_SCANS: usize = 256;
const SESSION_DIRECTORY: &str = ".buaa-cli-classroom-session";
const RESUME_INTENT: &str = "RESUME CLASSROOM AUTH";
const INSPECT_INTENT: &str = "INSPECT CLASSROOM LOGIN";
const TENANT_CODE: &str = "21";
const REDACTED_NAME: &str = "redacted";
const CHALLENGE_TEXT_WINDOW: usize = 32;
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
        "Classroom authentication was rejected or indeterminate; review the attempt receipt, then run the explicit resume before one more attempt.",
    )
}

fn challenge() -> Error {
    Error::new(
        "auth_latched",
        "Classroom authentication requires an interactive challenge; no challenge was bypassed.",
    )
}

fn governor_state_unknown() -> Error {
    Error::new(
        "governor_unavailable",
        "The shared safety admission could not be completed; the pending outcome remains for offline review.",
    )
}

fn scoped_cookie_unusable() -> Error {
    Error::new(
        "scoped_cookie_unusable",
        "A selected classroom cookie expired or became invalid before transmission; no further request was sent.",
    )
}

fn finish_send_failure(lease: RequestLease<'_>, error: &Error) -> Result<(), String> {
    match error.code {
        "scoped_cookie_unusable" => lease.finish_without_request(),
        "safety_latched" => lease.finish(crate::governor::Outcome::SafetyObserved),
        _ => lease.finish(crate::governor::Outcome::NetworkFailure),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeInput<'a> {
    #[serde(borrow)]
    intent: std::borrow::Cow<'a, str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectInput<'a> {
    authorized: bool,
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

impl Scope {
    /// The delivery scope's domain is also the cookie identity unless a
    /// narrowed cookie overrides it with its canonical declared domain.
    fn domain(&self) -> &str {
        match self {
            Self::Host(domain) | Self::Platform(domain) => domain,
        }
    }
}

/// Version 3 adds the declared identity domain of narrowed cookies; earlier
/// versions cannot recover it and are refused instead of guessed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cookie {
    name: String,
    value: String,
    scope: Scope,
    path: String,
    expiry: Option<SystemTime>,
    #[serde(default)]
    secure: bool,
    #[serde(default)]
    http_only: bool,
    #[serde(default)]
    host_only: bool,
    #[serde(default)]
    path_explicit: bool,
    /// The canonical declared domain for cookie identity when a domain
    /// attribute outside the reviewed platform family was narrowed to the
    /// setter for delivery. Absent for host-only and platform-family
    /// cookies, whose identity is the delivery scope's domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    declared_domain: Option<String>,
}

impl Cookie {
    /// The canonical declared domain keys replacement, deletion and reload
    /// duplicates; the delivery scope only decides which hosts may receive
    /// the cookie. They differ only for narrowed cookies.
    fn identity_domain(&self) -> &str {
        self.declared_domain
            .as_deref()
            .unwrap_or_else(|| self.scope.domain())
    }
}

/// Domain- and path-scoped cookies. A cookie reaches only the hosts and paths
/// its own declaration allows, and the single sign-on credential never leaves
/// the sign-on host.
#[derive(Default)]
struct Jar {
    cookies: Vec<Cookie>,
}

enum ScopedCookies {
    Anonymous,
    Ready(Zeroizing<String>, Option<SystemTime>),
    Unusable,
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
    if value.len() > 4096 {
        return false;
    }
    let value = if value.starts_with('"') || value.ends_with('"') {
        let Some(value) = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        else {
            return false;
        };
        value
    } else {
        value
    };
    !value.contains('"')
        && value.bytes().all(|byte| {
            matches!(
                byte,
                0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e
            )
        })
}

fn valid_cookie_prefix(
    name: &str,
    secure: bool,
    http_only: bool,
    host_only: bool,
    path_explicit: bool,
    path: &str,
) -> bool {
    let secure_prefix =
        name.starts_with("__Secure-") || name.starts_with("__Host-") || name.starts_with("__Http-");
    let host_prefix = name.starts_with("__Host-");
    let http_prefix = name.starts_with("__Http-") || name.starts_with("__Host-Http-");
    (!secure_prefix || secure)
        && (!host_prefix || (host_only && path_explicit && path == "/"))
        && (!http_prefix || http_only)
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

fn cookie_date_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'\t' | 0x20..=0x2f | 0x3b..=0x40 | 0x5b..=0x60 | 0x7b..=0x7e
    )
}

fn cookie_date_number(token: &[u8], min_digits: usize, max_digits: usize) -> Option<u32> {
    if !(min_digits..=max_digits).contains(&token.len()) || !token.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        token
            .iter()
            .fold(0_u32, |value, byte| value * 10 + u32::from(*byte - b'0')),
    )
}

fn cookie_date_month(token: &[u8]) -> Option<u32> {
    let month = token.get(..3)?;
    if token.get(3).is_some_and(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if month.eq_ignore_ascii_case(b"jan") {
        Some(1)
    } else if month.eq_ignore_ascii_case(b"feb") {
        Some(2)
    } else if month.eq_ignore_ascii_case(b"mar") {
        Some(3)
    } else if month.eq_ignore_ascii_case(b"apr") {
        Some(4)
    } else if month.eq_ignore_ascii_case(b"may") {
        Some(5)
    } else if month.eq_ignore_ascii_case(b"jun") {
        Some(6)
    } else if month.eq_ignore_ascii_case(b"jul") {
        Some(7)
    } else if month.eq_ignore_ascii_case(b"aug") {
        Some(8)
    } else if month.eq_ignore_ascii_case(b"sep") {
        Some(9)
    } else if month.eq_ignore_ascii_case(b"oct") {
        Some(10)
    } else if month.eq_ignore_ascii_case(b"nov") {
        Some(11)
    } else if month.eq_ignore_ascii_case(b"dec") {
        Some(12)
    } else {
        None
    }
}

fn cookie_date_time_field(token: &[u8], offset: &mut usize) -> Option<u32> {
    let rest = token.get(*offset..)?;
    let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if !(1..=2).contains(&digits) {
        return None;
    }
    let value = rest[..digits]
        .iter()
        .fold(0_u32, |value, byte| value * 10 + u32::from(*byte - b'0'));
    *offset += digits;
    Some(value)
}

fn cookie_date_time(token: &[u8]) -> Option<(u32, u32, u32)> {
    let mut offset = 0;
    let hour = cookie_date_time_field(token, &mut offset)?;
    if token.get(offset) != Some(&b':') {
        return None;
    }
    offset += 1;
    let minute = cookie_date_time_field(token, &mut offset)?;
    if token.get(offset) != Some(&b':') {
        return None;
    }
    offset += 1;
    let second = cookie_date_time_field(token, &mut offset)?;
    if offset != token.len() {
        return None;
    }
    Some((hour, minute, second))
}

fn parse_cookie_expiry(value: &str) -> Option<SystemTime> {
    let mut time = None;
    let mut day = None;
    let mut month = None;
    let mut year = None;
    let bytes = value.as_bytes();
    let mut position = 0;
    while position < bytes.len() {
        while position < bytes.len() && cookie_date_delimiter(bytes[position]) {
            position += 1;
        }
        let token_start = position;
        while position < bytes.len() && !cookie_date_delimiter(bytes[position]) {
            position += 1;
        }
        let token = &bytes[token_start..position];
        if token.is_empty() {
            continue;
        }

        if time.is_none()
            && let Some(parsed) = cookie_date_time(token)
        {
            time = Some(parsed);
            continue;
        }
        if day.is_none()
            && let Some(parsed) = cookie_date_number(token, 1, 2)
        {
            day = Some(parsed);
            continue;
        }
        if month.is_none()
            && let Some(parsed) = cookie_date_month(token)
        {
            month = Some(parsed);
            continue;
        }
        if year.is_none()
            && let Some(parsed) = cookie_date_number(token, 2, 4)
        {
            year = Some(parsed);
            continue;
        }
    }

    let (hour, minute, second) = time?;
    let day = day?;
    let month = month?;
    let mut year = year?;
    if (70..=99).contains(&year) {
        year += 1900;
    } else if year <= 69 {
        year += 2000;
    }
    if !(1..=31).contains(&day) || year < 1601 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let date = chrono::NaiveDate::from_ymd_opt(year as i32, month, day)?
        .and_hms_opt(hour, minute, second)?;
    let seconds = date.and_utc().timestamp();
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
            self.cookies.retain(|cookie| !cookie_expired(cookie.expiry));
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
                || !valid_cookie_value(value)
            {
                continue;
            }
            let mut domain: Option<String> = None;
            let mut path = default_cookie_path(url.path());
            let mut expires = None;
            let mut max_age_expiry = None;
            let mut invalid_attribute = false;
            let mut invalid_expires = false;
            let mut seen_domain = false;
            let mut seen_path = false;
            let mut seen_expires = false;
            let mut seen_max_age = false;
            let mut secure = false;
            let mut http_only = false;
            for attribute in parts {
                let attribute = attribute.trim();
                let Some((key, attribute_value)) = attribute.split_once('=') else {
                    if attribute.eq_ignore_ascii_case("secure") {
                        secure = true;
                    } else if attribute.eq_ignore_ascii_case("httponly") {
                        http_only = true;
                    }
                    continue;
                };
                let key = key.trim();
                let attribute_value = attribute_value.trim();
                if key.eq_ignore_ascii_case("secure") {
                    secure = true;
                } else if key.eq_ignore_ascii_case("httponly") {
                    http_only = true;
                } else if key.eq_ignore_ascii_case("domain") {
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
                        invalid_expires = true;
                        continue;
                    };
                    expires = Some(value);
                } else if key.eq_ignore_ascii_case("max-age") {
                    if seen_max_age {
                        invalid_attribute = true;
                        break;
                    }
                    seen_max_age = true;
                    let (negative, digits) = match attribute_value.strip_prefix('-') {
                        Some(digits) => (true, digits),
                        None => (false, attribute_value),
                    };
                    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                        invalid_attribute = true;
                        break;
                    }
                    if negative {
                        max_age_expiry = Some(UNIX_EPOCH);
                    } else {
                        let Ok(seconds) = digits.parse::<u64>() else {
                            invalid_attribute = true;
                            break;
                        };
                        if seconds > MAX_COOKIE_AGE {
                            invalid_attribute = true;
                            break;
                        }
                        max_age_expiry = if seconds == 0 {
                            Some(UNIX_EPOCH)
                        } else {
                            SystemTime::now().checked_add(Duration::from_secs(seconds))
                        };
                    }
                }
            }
            let has_valid_max_age = max_age_expiry.is_some();
            let expiry = max_age_expiry.or(expires);
            if invalid_attribute
                || (invalid_expires && !has_valid_max_age)
                || cookie_expiry_too_far(expiry)
            {
                continue;
            }
            // A declared domain must match the setter. Only the reviewed
            // platform family may share a cookie across hosts; every other
            // cookie, including the sign-on ticket, stays with its setter.
            // A family-foreign declared domain is narrowed to the setter for
            // delivery while its canonical declaration remains the identity.
            let host_only = domain.is_none();
            let (scope, declared_domain) = match domain {
                Some(domain)
                    if domain_matches(&domain, host) && within_platform_family(&domain) =>
                {
                    (
                        Scope::Platform(domain.trim_start_matches('.').to_ascii_lowercase()),
                        None,
                    )
                }
                Some(domain) if domain_matches(&domain, host) => (
                    Scope::Host(host.to_ascii_lowercase()),
                    Some(domain.trim_start_matches('.').to_ascii_lowercase()),
                ),
                Some(_) => continue,
                None => (Scope::Host(host.to_ascii_lowercase()), None),
            };
            if !valid_cookie_prefix(name, secure, http_only, host_only, seen_path, &path) {
                continue;
            }
            if cookie_expired(expiry) {
                let identity_domain = declared_domain.as_deref().unwrap_or_else(|| scope.domain());
                self.cookies.retain(|cookie| {
                    !(cookie.name == name
                        && cookie.identity_domain() == identity_domain
                        && cookie.path == path)
                });
                continue;
            }
            let replacement = Cookie {
                name: name.to_string(),
                value: value.to_string(),
                scope,
                path,
                expiry,
                secure,
                http_only,
                host_only,
                path_explicit: seen_path,
                declared_domain,
            };
            if let Some(index) = self.cookies.iter().position(|cookie| {
                cookie.name == replacement.name
                    && cookie.identity_domain() == replacement.identity_domain()
                    && cookie.path == replacement.path
            }) {
                self.cookies[index] = replacement;
            } else {
                self.cookies.push(replacement);
                if self.cookies.len() > MAX_COOKIE_COUNT {
                    self.cookies.remove(0);
                }
            }
        }
        Ok(())
    }

    fn select_cookies(&self, url: &Url, reject_expired: bool) -> ScopedCookies {
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return ScopedCookies::Unusable;
        };
        let mut order = [usize::MAX; MAX_COOKIE_COUNT];
        let mut count = 0;
        for (index, cookie) in self.cookies.iter().enumerate() {
            if !cookie_path_matches(&cookie.path, url.path()) {
                continue;
            }
            let permitted = match &cookie.scope {
                Scope::Host(scope) => *scope == host,
                Scope::Platform(domain) => host == *domain
                    || host.strip_suffix(domain.as_str()).is_some_and(|prefix| prefix.ends_with('.')),
            };
            if !permitted {
                continue;
            }
            if cookie_expired(cookie.expiry) {
                if reject_expired {
                    return ScopedCookies::Unusable;
                }
                continue;
            }
            if count == order.len() {
                return ScopedCookies::Unusable;
            }
            let mut insert_at = count;
            while insert_at > 0 && self.cookies[order[insert_at - 1]].path.len() < cookie.path.len()
            {
                order[insert_at] = order[insert_at - 1];
                insert_at -= 1;
            }
            order[insert_at] = index;
            count += 1;
        }
        if count == 0 {
            return ScopedCookies::Anonymous;
        }
        let mut text = Zeroizing::new(String::new());
        let mut expires = None;
        for index in &order[..count] {
            let cookie = &self.cookies[*index];
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
            return ScopedCookies::Unusable;
        }
        ScopedCookies::Ready(text, expires)
    }

    fn cookie_text(&self, url: &Url) -> Option<(Zeroizing<String>, Option<SystemTime>)> {
        match self.select_cookies(url, false) {
            ScopedCookies::Ready(text, expiry) => Some((text, expiry)),
            ScopedCookies::Anonymous | ScopedCookies::Unusable => None,
        }
    }

    fn header(&self, url: &Url) -> Option<HeaderValue> {
        let (text, _) = self.cookie_text(url)?;
        let mut header = HeaderValue::from_str(&text).ok()?;
        header.set_sensitive(true);
        Some(header)
    }
}

const CSS_NAMED_COLORS: &str = "aliceblue:f0f8ff antiquewhite:faebd7 aqua:00ffff aquamarine:7fffd4 azure:f0ffff beige:f5f5dc bisque:ffe4c4 black:000000 blanchedalmond:ffebcd blue:0000ff blueviolet:8a2be2 brown:a52a2a burlywood:deb887 cadetblue:5f9ea0 chartreuse:7fff00 chocolate:d2691e coral:ff7f50 cornflowerblue:6495ed cornsilk:fff8dc crimson:dc143c cyan:00ffff darkblue:00008b darkcyan:008b8b darkgoldenrod:b8860b darkgray:a9a9a9 darkgreen:006400 darkgrey:a9a9a9 darkkhaki:bdb76b darkmagenta:8b008b darkolivegreen:556b2f darkorange:ff8c00 darkorchid:9932cc darkred:8b0000 darksalmon:e9967a darkseagreen:8fbc8f darkslateblue:483d8b darkslategray:2f4f4f darkslategrey:2f4f4f darkturquoise:00ced1 darkviolet:9400d3 deeppink:ff1493 deepskyblue:00bfff dimgray:696969 dimgrey:696969 dodgerblue:1e90ff firebrick:b22222 floralwhite:fffaf0 forestgreen:228b22 fuchsia:ff00ff gainsboro:dcdcdc ghostwhite:f8f8ff gold:ffd700 goldenrod:daa520 gray:808080 green:008000 greenyellow:adff2f grey:808080 honeydew:f0fff0 hotpink:ff69b4 indianred:cd5c5c indigo:4b0082 ivory:fffff0 khaki:f0e68c lavender:e6e6fa lavenderblush:fff0f5 lawngreen:7cfc00 lemonchiffon:fffacd lightblue:add8e6 lightcoral:f08080 lightcyan:e0ffff lightgoldenrodyellow:fafad2 lightgray:d3d3d3 lightgreen:90ee90 lightgrey:d3d3d3 lightpink:ffb6c1 lightsalmon:ffa07a lightseagreen:20b2aa lightskyblue:87cefa lightslategray:778899 lightslategrey:778899 lightsteelblue:b0c4de lightyellow:ffffe0 lime:00ff00 limegreen:32cd32 linen:faf0e6 magenta:ff00ff maroon:800000 mediumaquamarine:66cdaa mediumblue:0000cd mediumorchid:ba55d3 mediumpurple:9370db mediumseagreen:3cb371 mediumslateblue:7b68ee mediumspringgreen:00fa9a mediumturquoise:48d1cc mediumvioletred:c71585 midnightblue:191970 mintcream:f5fffa mistyrose:ffe4e1 moccasin:ffe4b5 navajowhite:ffdead navy:000080 oldlace:fdf5e6 olive:808000 olivedrab:6b8e23 orange:ffa500 orangered:ff4500 orchid:da70d6 palegoldenrod:eee8aa palegreen:98fb98 paleturquoise:afeeee palevioletred:db7093 papayawhip:ffefd5 peachpuff:ffdab9 peru:cd853f pink:ffc0cb plum:dda0dd powderblue:b0e0e6 purple:800080 rebeccapurple:663399 red:ff0000 rosybrown:bc8f8f royalblue:4169e1 saddlebrown:8b4513 salmon:fa8072 sandybrown:f4a460 seagreen:2e8b57 seashell:fff5ee sienna:a0522d silver:c0c0c0 skyblue:87ceeb slateblue:6a5acd slategray:708090 slategrey:708090 snow:fffafa springgreen:00ff7f steelblue:4682b4 tan:d2b48c teal:008080 thistle:d8bfd8 tomato:ff6347 turquoise:40e0d0 violet:ee82ee wheat:f5deb3 white:ffffff whitesmoke:f5f5f5 yellow:ffff00 yellowgreen:9acd32";

fn html_float(value: &str) -> Option<f64> {
    let bytes = value.as_bytes();
    let mut index = usize::from(bytes.first() == Some(&b'-'));
    bytes.get(index)?;
    let integer_start = index;
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    let integer_digits = index - integer_start;
    let mut fraction_digits = 0;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        fraction_digits = index - fraction_start;
        if fraction_digits == 0 {
            return None;
        }
    }
    if integer_digits == 0 && fraction_digits == 0 {
        return None;
    }
    if bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b'e' | b'E'))
    {
        index += 1;
        if bytes
            .get(index)
            .is_some_and(|byte| matches!(byte, b'+' | b'-'))
        {
            index += 1;
        }
        let exponent_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == exponent_start {
            return None;
        }
    }
    (index == bytes.len())
        .then(|| value.parse::<f64>().ok())
        .flatten()
        .filter(|number| number.is_finite())
}

fn trim_css_whitespace(value: &str) -> &str {
    value.trim_matches(|character| {
        matches!(
            character,
            ' ' | '\t' | '\n' | '\r' | '\u{000c}' | '\u{0001}'
        )
    })
}

const CSS_COLOR_COMMENT_SEPARATOR: u8 = 0x01;

fn css_whitespace(byte: u8) -> bool {
    byte.is_ascii_whitespace() || byte == 0x0c
}

fn css_color_token_separator(byte: u8) -> bool {
    css_whitespace(byte) || byte == CSS_COLOR_COMMENT_SEPARATOR
}

fn css_math_operator_has_whitespace(bytes: &[u8], index: usize) -> bool {
    let mut before = index;
    while before > 0 && bytes[before - 1] == CSS_COLOR_COMMENT_SEPARATOR {
        before -= 1;
    }
    let mut after = index + 1;
    while bytes.get(after) == Some(&CSS_COLOR_COMMENT_SEPARATOR) {
        after += 1;
    }
    before > 0
        && css_whitespace(bytes[before - 1])
        && bytes.get(after).is_some_and(|byte| css_whitespace(*byte))
}

fn decimal_component(value: &str, scale: f64) -> Option<f64> {
    let value = trim_css_whitespace(value);
    let value = css_math_expression(value)?;
    match value.unit {
        CssMathUnit::Number => Some(value.value),
        CssMathUnit::Percentage => Some(value.value * (scale / 100.0)),
        CssMathUnit::Angle => None,
    }
}

fn css_color_component(value: &str, scale: f64) -> Option<f64> {
    if value.eq_ignore_ascii_case("none") {
        Some(0.0)
    } else {
        decimal_component(value, scale)
    }
}

fn css_color_component_preserving_nan(value: &str, scale: f64) -> Option<f64> {
    if value.eq_ignore_ascii_case("none") {
        return Some(0.0);
    }
    let value = css_math_expression_preserving_nan(trim_css_whitespace(value))?;
    match value.unit {
        CssMathUnit::Number => Some(value.value),
        CssMathUnit::Percentage => Some(value.value * (scale / 100.0)),
        CssMathUnit::Angle => None,
    }
}

fn css_number(value: &str) -> Option<f64> {
    let bytes = value.as_bytes();
    let mut index = usize::from(
        bytes
            .first()
            .is_some_and(|byte| matches!(byte, b'+' | b'-')),
    );
    let integer_start = index;
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    let integer_digits = index - integer_start;
    let mut fraction_digits = 0;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        fraction_digits = index - fraction_start;
        if fraction_digits == 0 {
            return None;
        }
    }
    if integer_digits == 0 && fraction_digits == 0 {
        return None;
    }
    if bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b'e' | b'E'))
    {
        index += 1;
        if bytes
            .get(index)
            .is_some_and(|byte| matches!(byte, b'+' | b'-'))
        {
            index += 1;
        }
        let exponent_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == exponent_start {
            return None;
        }
    }
    (index == bytes.len())
        .then(|| value.parse::<f64>().ok())
        .flatten()
        // Native CSS literals have a finite float range; computed results and
        // the explicit infinity keyword retain their separate semantics.
        .map(|value| value.clamp(-f64::from(f32::MAX), f64::from(f32::MAX)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CssMathUnit {
    Number,
    Percentage,
    Angle,
}

#[derive(Clone, Copy)]
struct CssMathValue {
    value: f64,
    unit: CssMathUnit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CssMathFunction {
    Calc,
    Min,
    Max,
    Clamp,
    Abs,
    Sign,
    Round,
    Mod,
    Rem,
    Pow,
    Sqrt,
    Hypot,
    Log,
    Exp,
    Sin,
    Cos,
    Tan,
    Asin,
    Acos,
    Atan,
    Atan2,
}

#[derive(Clone, Copy)]
enum CssRoundStrategy {
    Nearest,
    Up,
    Down,
    ToZero,
}

#[derive(Clone, Copy)]
enum CssMathOperator {
    Add,
    Subtract,
    Multiply,
    Divide,
    Positive,
    Negative,
}

impl CssMathOperator {
    fn precedence(self) -> u8 {
        match self {
            Self::Add | Self::Subtract => 1,
            Self::Multiply | Self::Divide => 2,
            Self::Positive | Self::Negative => 3,
        }
    }

    fn is_unary(self) -> bool {
        matches!(self, Self::Positive | Self::Negative)
    }
}

#[derive(Clone, Copy)]
struct CssMathFrame {
    function: Option<CssMathFunction>,
    group: bool,
    values_start: usize,
    expression_start: usize,
    operators_start: usize,
    expecting_operand: bool,
    allow_arithmetic: bool,
    round_strategy: Option<CssRoundStrategy>,
    round_strategy_pending: bool,
}

fn css_math_function(name: &str) -> Option<CssMathFunction> {
    Some(if name.eq_ignore_ascii_case("calc") {
        CssMathFunction::Calc
    } else if name.eq_ignore_ascii_case("min") {
        CssMathFunction::Min
    } else if name.eq_ignore_ascii_case("max") {
        CssMathFunction::Max
    } else if name.eq_ignore_ascii_case("clamp") {
        CssMathFunction::Clamp
    } else if name.eq_ignore_ascii_case("abs") {
        CssMathFunction::Abs
    } else if name.eq_ignore_ascii_case("sign") {
        CssMathFunction::Sign
    } else if name.eq_ignore_ascii_case("round") {
        CssMathFunction::Round
    } else if name.eq_ignore_ascii_case("mod") {
        CssMathFunction::Mod
    } else if name.eq_ignore_ascii_case("rem") {
        CssMathFunction::Rem
    } else if name.eq_ignore_ascii_case("pow") {
        CssMathFunction::Pow
    } else if name.eq_ignore_ascii_case("sqrt") {
        CssMathFunction::Sqrt
    } else if name.eq_ignore_ascii_case("hypot") {
        CssMathFunction::Hypot
    } else if name.eq_ignore_ascii_case("log") {
        CssMathFunction::Log
    } else if name.eq_ignore_ascii_case("exp") {
        CssMathFunction::Exp
    } else if name.eq_ignore_ascii_case("sin") {
        CssMathFunction::Sin
    } else if name.eq_ignore_ascii_case("cos") {
        CssMathFunction::Cos
    } else if name.eq_ignore_ascii_case("tan") {
        CssMathFunction::Tan
    } else if name.eq_ignore_ascii_case("asin") {
        CssMathFunction::Asin
    } else if name.eq_ignore_ascii_case("acos") {
        CssMathFunction::Acos
    } else if name.eq_ignore_ascii_case("atan") {
        CssMathFunction::Atan
    } else if name.eq_ignore_ascii_case("atan2") {
        CssMathFunction::Atan2
    } else {
        return None;
    })
}

fn css_round_strategy(name: &str) -> Option<CssRoundStrategy> {
    if name.eq_ignore_ascii_case("nearest") {
        Some(CssRoundStrategy::Nearest)
    } else if name.eq_ignore_ascii_case("up") {
        Some(CssRoundStrategy::Up)
    } else if name.eq_ignore_ascii_case("down") {
        Some(CssRoundStrategy::Down)
    } else if name.eq_ignore_ascii_case("to-zero") {
        Some(CssRoundStrategy::ToZero)
    } else {
        None
    }
}

fn css_math_result(value: f64, unit: CssMathUnit) -> Option<CssMathValue> {
    Some(CssMathValue { value, unit })
}

fn css_math_function_value(
    function: CssMathFunction,
    arguments: &[CssMathValue],
    round_strategy: Option<CssRoundStrategy>,
) -> Option<CssMathValue> {
    let first = *arguments.first()?;
    match function {
        CssMathFunction::Calc => (arguments.len() == 1).then_some(first),
        CssMathFunction::Min | CssMathFunction::Max => {
            let mut result = first;
            for argument in &arguments[1..] {
                if argument.unit != first.unit {
                    return None;
                }
                result.value = if result.value.is_nan() || argument.value.is_nan() {
                    f64::NAN
                } else if matches!(function, CssMathFunction::Min) {
                    result.value.min(argument.value)
                } else {
                    result.value.max(argument.value)
                };
            }
            Some(result)
        }
        CssMathFunction::Clamp => {
            if arguments.len() != 3
                || arguments[1].unit != first.unit
                || arguments[2].unit != first.unit
            {
                return None;
            }
            css_math_result(
                if arguments.iter().any(|argument| argument.value.is_nan()) {
                    f64::NAN
                } else {
                    first.value.max(arguments[1].value.min(arguments[2].value))
                },
                first.unit,
            )
        }
        CssMathFunction::Abs => (arguments.len() == 1).then(|| CssMathValue {
            value: first.value.abs(),
            unit: first.unit,
        }),
        CssMathFunction::Sign => {
            if arguments.len() != 1 {
                return None;
            }
            let sign = if first.value.is_nan() {
                f64::NAN
            } else if first.value > 0.0 {
                1.0
            } else if first.value < 0.0 {
                -1.0
            } else {
                first.value
            };
            Some(CssMathValue {
                value: sign,
                unit: CssMathUnit::Number,
            })
        }
        CssMathFunction::Round => {
            if !(1..=2).contains(&arguments.len()) {
                return None;
            }
            let step = if let Some(step) = arguments.get(1) {
                if step.unit != first.unit {
                    return None;
                }
                step.value
            } else {
                if first.unit != CssMathUnit::Number {
                    return None;
                }
                1.0
            };
            let step = step.abs();
            let strategy = round_strategy.unwrap_or(CssRoundStrategy::Nearest);
            // Chromium resolves an infinite step before anything else: the only
            // multiples of an infinite step are 0 and ±∞, so the value is snapped
            // onto that lattice before its own infinity is considered.
            if step.is_infinite() {
                if first.value.is_infinite() {
                    return css_math_result(f64::NAN, first.unit);
                }
                // Rounding up never lowers the value, so a positive value (and an
                // unordered NaN value, which compares false against everything)
                // lands on +∞, while a negative value lands on 0.
                let rounds_up = first.value > 0.0 || first.value.is_nan();
                let rounded = match strategy {
                    CssRoundStrategy::Up if rounds_up => f64::INFINITY,
                    CssRoundStrategy::Down if first.value < 0.0 => f64::NEG_INFINITY,
                    _ => 0.0f64.copysign(first.value),
                };
                return css_math_result(rounded, first.unit);
            }
            if step == 0.0 {
                return css_math_result(f64::NAN, first.unit);
            }
            // An infinite value survives a NaN step: the step never reaches it.
            if first.value.is_infinite() {
                return css_math_result(first.value, first.unit);
            }
            if step.is_nan() || first.value.is_nan() {
                return css_math_result(f64::NAN, first.unit);
            }
            let quotient = first.value / step;
            let rounded = match strategy {
                CssRoundStrategy::Nearest => {
                    let lower = quotient.floor();
                    let fraction = quotient - lower;
                    let rounded = if fraction < 0.5 { lower } else { lower + 1.0 };
                    if rounded == 0.0 && quotient.is_sign_negative() {
                        -0.0
                    } else {
                        rounded
                    }
                }
                CssRoundStrategy::Up => quotient.ceil(),
                CssRoundStrategy::Down => quotient.floor(),
                CssRoundStrategy::ToZero => quotient.trunc(),
            };
            css_math_result(rounded * step, first.unit)
        }
        CssMathFunction::Mod | CssMathFunction::Rem => {
            if arguments.len() != 2 || arguments[1].unit != first.unit {
                return None;
            }
            let divisor = arguments[1].value;
            let remainder = if divisor.is_infinite() && first.value.is_finite() {
                if matches!(function, CssMathFunction::Mod)
                    && first.value.is_sign_negative() != divisor.is_sign_negative()
                {
                    f64::NAN
                } else {
                    first.value
                }
            } else if matches!(function, CssMathFunction::Rem) {
                first.value % divisor
            } else {
                let mut remainder = first.value.rem_euclid(divisor.abs());
                if remainder == 0.0 {
                    remainder = 0.0f64.copysign(divisor);
                } else if divisor.is_sign_negative() {
                    remainder -= divisor.abs();
                }
                remainder
            };
            css_math_result(remainder, first.unit)
        }
        CssMathFunction::Pow => {
            if arguments.len() != 2
                || first.unit != CssMathUnit::Number
                || arguments[1].unit != CssMathUnit::Number
            {
                return None;
            }
            css_math_result(first.value.powf(arguments[1].value), CssMathUnit::Number)
        }
        CssMathFunction::Sqrt => {
            if arguments.len() != 1 || first.unit != CssMathUnit::Number {
                return None;
            }
            css_math_result(first.value.sqrt(), CssMathUnit::Number)
        }
        CssMathFunction::Hypot => {
            let mut result = first.value.abs();
            let mut infinite = first.value.is_infinite();
            let mut nan = first.value.is_nan();
            for argument in &arguments[1..] {
                if argument.unit != first.unit {
                    return None;
                }
                infinite |= argument.value.is_infinite();
                nan |= argument.value.is_nan();
                result = result.hypot(argument.value);
            }
            // IEEE 754-2019 hypot: an infinite argument outranks a NaN argument.
            let result = if infinite {
                f64::INFINITY
            } else if nan {
                f64::NAN
            } else {
                result
            };
            css_math_result(result, first.unit)
        }
        CssMathFunction::Log => {
            if !(1..=2).contains(&arguments.len()) || first.unit != CssMathUnit::Number {
                return None;
            }
            if let Some(base) = arguments.get(1) {
                if base.unit != CssMathUnit::Number {
                    return None;
                }
                // Chromium evaluates log(x, base) as ln(x) / ln(base) without
                // special-casing the base: a base of 1 divides by zero and a base
                // of 0 divides by -∞, while a negative base has no logarithm.
                css_math_result(first.value.ln() / base.value.ln(), CssMathUnit::Number)
            } else {
                css_math_result(first.value.ln(), CssMathUnit::Number)
            }
        }
        CssMathFunction::Exp => {
            if arguments.len() != 1 || first.unit != CssMathUnit::Number {
                return None;
            }
            css_math_result(first.value.exp(), CssMathUnit::Number)
        }
        CssMathFunction::Sin | CssMathFunction::Cos | CssMathFunction::Tan => {
            if arguments.len() != 1 {
                return None;
            }
            let radians = match first.unit {
                CssMathUnit::Number => first.value,
                CssMathUnit::Angle => first.value.to_radians(),
                CssMathUnit::Percentage => return None,
            };
            let value = match function {
                CssMathFunction::Sin => radians.sin(),
                CssMathFunction::Cos => radians.cos(),
                CssMathFunction::Tan => radians.tan(),
                _ => unreachable!(),
            };
            css_math_result(value, CssMathUnit::Number)
        }
        CssMathFunction::Asin | CssMathFunction::Acos | CssMathFunction::Atan => {
            if arguments.len() != 1 || first.unit != CssMathUnit::Number {
                return None;
            }
            let radians = match function {
                CssMathFunction::Asin => first.value.asin(),
                CssMathFunction::Acos => first.value.acos(),
                CssMathFunction::Atan => first.value.atan(),
                _ => unreachable!(),
            };
            css_math_result(radians.to_degrees(), CssMathUnit::Angle)
        }
        CssMathFunction::Atan2 => {
            if arguments.len() != 2
                || arguments[1].unit != first.unit
                || !matches!(first.unit, CssMathUnit::Number | CssMathUnit::Angle)
            {
                return None;
            }
            css_math_result(
                first.value.atan2(arguments[1].value).to_degrees(),
                CssMathUnit::Angle,
            )
        }
    }
}

fn css_math_operator_value(
    values: &mut Vec<CssMathValue>,
    values_start: usize,
    operator: CssMathOperator,
) -> Option<()> {
    if operator.is_unary() {
        if values.len() <= values_start {
            return None;
        }
        let last = values.len().checked_sub(1)?;
        let value = values.get_mut(last)?;
        if matches!(operator, CssMathOperator::Negative) {
            value.value = -value.value;
        }
        return Some(());
    }
    if values.len() < values_start.checked_add(2)? {
        return None;
    }
    let right = values.pop()?;
    let left = values.pop()?;
    let result = match operator {
        CssMathOperator::Add | CssMathOperator::Subtract => {
            if left.unit != right.unit {
                return None;
            }
            let value = if matches!(operator, CssMathOperator::Add) {
                left.value + right.value
            } else {
                left.value - right.value
            };
            css_math_result(value, left.unit)?
        }
        CssMathOperator::Multiply => {
            let unit = match (left.unit, right.unit) {
                (CssMathUnit::Number, unit) | (unit, CssMathUnit::Number) => unit,
                _ => return None,
            };
            css_math_result(left.value * right.value, unit)?
        }
        CssMathOperator::Divide => {
            let unit = match (left.unit, right.unit) {
                (unit, CssMathUnit::Number) => unit,
                (left_unit, right_unit) if left_unit == right_unit => CssMathUnit::Number,
                _ => return None,
            };
            css_math_result(left.value / right.value, unit)?
        }
        CssMathOperator::Positive | CssMathOperator::Negative => return None,
    };
    values.push(result);
    Some(())
}

fn css_math_finish_expression(
    values: &mut Vec<CssMathValue>,
    operators: &mut Vec<CssMathOperator>,
    frame: CssMathFrame,
) -> Option<()> {
    if frame.expecting_operand {
        return None;
    }
    while operators.len() > frame.operators_start {
        css_math_operator_value(values, frame.expression_start, operators.pop()?)?;
    }
    (values.len() == frame.expression_start.checked_add(1)?).then_some(())
}

fn css_math_expression(value: &str) -> Option<CssMathValue> {
    css_math_expression_with_nan_policy(value, true)
}

fn css_math_expression_preserving_nan(value: &str) -> Option<CssMathValue> {
    css_math_expression_with_nan_policy(value, false)
}

fn css_math_expression_with_nan_policy(value: &str, map_nan_to_zero: bool) -> Option<CssMathValue> {
    if let Some(number) = css_number(value) {
        return Some(CssMathValue {
            value: number,
            unit: CssMathUnit::Number,
        });
    }
    if let Some(number) = value.strip_suffix('%') {
        return Some(CssMathValue {
            value: css_number(number)?,
            unit: CssMathUnit::Percentage,
        });
    }
    for (suffix, scale) in [
        ("grad", 0.9),
        ("turn", 360.0),
        ("deg", 1.0),
        ("rad", 180.0 / std::f64::consts::PI),
    ] {
        if let Some(start) = value.len().checked_sub(suffix.len())
            && value.get(start..)?.eq_ignore_ascii_case(suffix)
        {
            return Some(CssMathValue {
                value: css_number(value.get(..start)?)? * scale,
                unit: CssMathUnit::Angle,
            });
        }
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    let mut values = Vec::new();
    let mut operators = Vec::new();
    let mut frames = vec![CssMathFrame {
        function: None,
        group: false,
        values_start: 0,
        expression_start: 0,
        operators_start: 0,
        expecting_operand: true,
        allow_arithmetic: false,
        round_strategy: None,
        round_strategy_pending: false,
    }];

    while index < bytes.len() {
        if css_color_token_separator(bytes[index]) {
            index += 1;
            continue;
        }
        let frame = *frames.last()?;
        let byte = bytes[index];
        if byte.is_ascii_digit() || byte == b'.' {
            if !frame.expecting_operand {
                return None;
            }
            let number_end = css_number_token_end(bytes, index)?;
            let number = css_number(value.get(index..number_end)?)?;
            index = number_end;
            let (number, unit) = match bytes.get(index) {
                Some(&b'%') => {
                    index += 1;
                    (number, CssMathUnit::Percentage)
                }
                Some(byte) if byte.is_ascii_alphabetic() => {
                    let unit_start = index;
                    while bytes.get(index).is_some_and(u8::is_ascii_alphabetic) {
                        index += 1;
                    }
                    let suffix = value.get(unit_start..index)?;
                    let (value, unit) = if suffix.eq_ignore_ascii_case("deg") {
                        (number, CssMathUnit::Angle)
                    } else if suffix.eq_ignore_ascii_case("grad") {
                        (number * 0.9, CssMathUnit::Angle)
                    } else if suffix.eq_ignore_ascii_case("turn") {
                        (number * 360.0, CssMathUnit::Angle)
                    } else if suffix.eq_ignore_ascii_case("rad") {
                        (number.to_degrees(), CssMathUnit::Angle)
                    } else {
                        return None;
                    };
                    (value, unit)
                }
                _ => (number, CssMathUnit::Number),
            };
            let number = css_math_result(number, unit)?;
            values.push(number);
            frames.last_mut()?.expecting_operand = false;
            continue;
        }
        if byte.is_ascii_alphabetic() {
            if !frame.expecting_operand {
                return None;
            }
            let start = index;
            while bytes
                .get(index)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            {
                index += 1;
            }
            let name = value.get(start..index)?;
            if bytes.get(index) != Some(&b'(')
                && frame.allow_arithmetic
                && (frame.function != Some(CssMathFunction::Round)
                    || css_round_strategy(name).is_none())
            {
                let constant = if name.eq_ignore_ascii_case("pi") {
                    std::f64::consts::PI
                } else if name.eq_ignore_ascii_case("e") {
                    std::f64::consts::E
                } else if name.eq_ignore_ascii_case("infinity") {
                    f64::INFINITY
                } else if name.eq_ignore_ascii_case("nan") {
                    f64::NAN
                } else {
                    return None;
                };
                values.push(CssMathValue {
                    value: constant,
                    unit: CssMathUnit::Number,
                });
                frames.last_mut()?.expecting_operand = false;
                continue;
            }
            if frame.function == Some(CssMathFunction::Round)
                && frame.values_start == frame.expression_start
                && values.len() == frame.values_start
                && frame.round_strategy.is_none()
                && let Some(strategy) = css_round_strategy(name)
            {
                let mut separator = index;
                while bytes
                    .get(separator)
                    .is_some_and(|byte| css_color_token_separator(*byte))
                {
                    separator += 1;
                }
                if bytes.get(separator) == Some(&b',') {
                    let active = frames.last_mut()?;
                    active.round_strategy = Some(strategy);
                    active.round_strategy_pending = true;
                    index = separator;
                    continue;
                }
            }
            if bytes.get(index) != Some(&b'(') {
                return None;
            }
            let function = css_math_function(name)?;
            index += 1;
            frames.push(CssMathFrame {
                function: Some(function),
                group: false,
                values_start: values.len(),
                expression_start: values.len(),
                operators_start: operators.len(),
                expecting_operand: true,
                allow_arithmetic: true,
                round_strategy: None,
                round_strategy_pending: false,
            });
            continue;
        }
        match byte {
            b'(' => {
                if !frame.expecting_operand || !frame.allow_arithmetic {
                    return None;
                }
                index += 1;
                frames.push(CssMathFrame {
                    function: None,
                    group: true,
                    values_start: values.len(),
                    expression_start: values.len(),
                    operators_start: operators.len(),
                    expecting_operand: true,
                    allow_arithmetic: true,
                    round_strategy: None,
                    round_strategy_pending: false,
                });
            }
            b')' => {
                if frames.len() == 1 || frame.expecting_operand || frame.round_strategy_pending {
                    return None;
                }
                css_math_finish_expression(&mut values, &mut operators, frame)?;
                if frame.group {
                    if frame.function.is_some()
                        || values.len() != frame.values_start.checked_add(1)?
                    {
                        return None;
                    }
                } else {
                    let function = frame.function?;
                    let result = css_math_function_value(
                        function,
                        values.get(frame.values_start..values.len())?,
                        frame.round_strategy,
                    )?;
                    values.truncate(frame.values_start);
                    values.push(result);
                }
                frames.pop()?;
                let parent = frames.last_mut()?;
                if !parent.expecting_operand {
                    return None;
                }
                parent.expecting_operand = false;
                index += 1;
            }
            b',' => {
                frame.function?;
                if frame.round_strategy_pending {
                    if !frame.expecting_operand {
                        return None;
                    }
                    let active = frames.last_mut()?;
                    active.round_strategy_pending = false;
                    active.expression_start = values.len();
                } else {
                    if frame.expecting_operand || frame.function == Some(CssMathFunction::Calc) {
                        return None;
                    }
                    css_math_finish_expression(&mut values, &mut operators, frame)?;
                    let active = frames.last_mut()?;
                    active.expression_start = values.len();
                    active.expecting_operand = true;
                }
                index += 1;
            }
            b'+' | b'-' | b'*' | b'/' => {
                let operator = if matches!(byte, b'+' | b'-') && frame.expecting_operand {
                    let signed_number = bytes
                        .get(index + 1)
                        .is_some_and(|next| next.is_ascii_digit() || *next == b'.');
                    let negative_infinity = byte == b'-'
                        && value
                            .get(index + 1..index + 9)
                            .is_some_and(|name| name.eq_ignore_ascii_case("infinity"));
                    if !signed_number && !negative_infinity {
                        return None;
                    }
                    if byte == b'+' {
                        CssMathOperator::Positive
                    } else {
                        CssMathOperator::Negative
                    }
                } else {
                    if frame.expecting_operand || !frame.allow_arithmetic {
                        return None;
                    }
                    match byte {
                        b'+' | b'-' if !css_math_operator_has_whitespace(bytes, index) => {
                            return None;
                        }
                        b'+' => CssMathOperator::Add,
                        b'-' => CssMathOperator::Subtract,
                        b'*' => CssMathOperator::Multiply,
                        b'/' => CssMathOperator::Divide,
                        _ => return None,
                    }
                };
                if !operator.is_unary() {
                    while operators.len() > frame.operators_start {
                        let previous = *operators.last()?;
                        if previous.precedence() > operator.precedence()
                            || previous.precedence() == operator.precedence()
                                && !operator.is_unary()
                        {
                            css_math_operator_value(
                                &mut values,
                                frame.expression_start,
                                operators.pop()?,
                            )?;
                        } else {
                            break;
                        }
                    }
                }
                operators.push(operator);
                frames.last_mut()?.expecting_operand = true;
                index += 1;
            }
            _ => return None,
        }
    }

    if frames.len() != 1 {
        return None;
    }
    let frame = *frames.first()?;
    css_math_finish_expression(&mut values, &mut operators, frame)?;
    if values.len() != 1 {
        return None;
    }
    let mut result = values[0];
    if map_nan_to_zero && result.value.is_nan() {
        result.value = 0.0;
    }
    Some(result)
}

fn css_number_token_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    let integer_start = index;
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    let integer_digits = index - integer_start;
    let mut fraction_digits = 0;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        fraction_digits = index - fraction_start;
        if fraction_digits == 0 {
            return None;
        }
    }
    if integer_digits == 0 && fraction_digits == 0 {
        return None;
    }
    if bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b'e' | b'E'))
    {
        index += 1;
        if bytes
            .get(index)
            .is_some_and(|byte| matches!(byte, b'+' | b'-'))
        {
            index += 1;
        }
        let exponent_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == exponent_start {
            return None;
        }
    }
    Some(index)
}

fn css_hue(value: &str) -> Option<f64> {
    if value.eq_ignore_ascii_case("none") {
        return Some(0.0);
    }
    let hue = css_math_expression(trim_css_whitespace(value))?;
    let hue = match hue.unit {
        CssMathUnit::Number | CssMathUnit::Angle => hue.value,
        CssMathUnit::Percentage => return None,
    };
    Some(if hue.is_finite() { hue } else { 0.0 })
}

struct CssOuterSyntax {
    commas: [usize; 3],
    comma_count: usize,
    slash: Option<usize>,
}

fn css_outer_syntax(value: &str) -> Option<CssOuterSyntax> {
    let mut result = CssOuterSyntax {
        commas: [0; 3],
        comma_count: 0,
        slash: None,
    };
    let mut parentheses = 0_usize;
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'(' => parentheses = parentheses.checked_add(1)?,
            b')' => {
                parentheses = parentheses.checked_sub(1)?;
            }
            b',' if parentheses == 0 => {
                let comma_index = result.comma_count;
                let comma = result.commas.get_mut(comma_index)?;
                *comma = index;
                result.comma_count = comma_index + 1;
            }
            b'/' if parentheses == 0 && result.slash.replace(index).is_some() => {
                return None;
            }
            _ => {}
        }
    }
    (parentheses == 0).then_some(result)
}

fn css_outer_whitespace_components<const N: usize>(value: &str) -> Option<([&str; N], usize)> {
    let bytes = value.as_bytes();
    let mut components = [""; N];
    let mut count = 0;
    let mut start = None;
    let mut parentheses = 0_usize;
    for index in 0..=bytes.len() {
        let at_end = index == bytes.len();
        if !at_end {
            match bytes[index] {
                b'(' => parentheses = parentheses.checked_add(1)?,
                b')' => {
                    parentheses = parentheses.checked_sub(1)?;
                }
                _ => {}
            }
        }
        if parentheses == 0 && (at_end || css_color_token_separator(bytes[index])) {
            if let Some(start) = start.take() {
                if count == N {
                    return None;
                }
                components[count] = value.get(start..index)?;
                count += 1;
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    (parentheses == 0).then_some((components, count))
}

fn css_components(contents: &str) -> Option<([&str; 3], Option<&str>, bool)> {
    let outer = css_outer_syntax(contents)?;
    if outer.comma_count > 0 {
        if outer.slash.is_some() {
            return None;
        }
        let field_count = outer.comma_count + 1;
        let mut fields = [""; 4];
        let mut start = 0;
        for (index, field) in fields.iter_mut().take(field_count).enumerate() {
            let end = if index < outer.comma_count {
                outer.commas[index]
            } else {
                contents.len()
            };
            *field = trim_css_whitespace(contents.get(start..end)?);
            start = end.checked_add(1)?;
        }
        let channels = [fields[0], fields[1], fields[2]];
        if channels.iter().any(|value| value.is_empty()) {
            return None;
        }
        return Some((channels, (field_count == 4).then_some(fields[3]), true));
    }
    let (channels, alpha) = match outer.slash {
        Some(slash) => (
            contents.get(..slash)?,
            Some(trim_css_whitespace(contents.get(slash + 1..)?)),
        ),
        None => (contents, None),
    };
    let (components, count) = css_outer_whitespace_components::<3>(channels)?;
    (count == 3).then_some((components, alpha, false))
}

fn valid_css_alpha(value: &str, comma_syntax: bool) -> bool {
    let value = trim_css_whitespace(value);
    if value.eq_ignore_ascii_case("none") {
        return !comma_syntax;
    }
    css_math_expression(value)
        .is_some_and(|value| matches!(value.unit, CssMathUnit::Number | CssMathUnit::Percentage))
}

fn rgb_component(value: &str) -> Option<(f64, bool)> {
    if value.eq_ignore_ascii_case("none") {
        return Some((0.0, false));
    }
    let value = css_math_expression(trim_css_whitespace(value))?;
    match value.unit {
        CssMathUnit::Number => Some((value.value, false)),
        CssMathUnit::Percentage => Some((value.value * 255.0 / 100.0, true)),
        CssMathUnit::Angle => None,
    }
}

fn color_byte(value: f64) -> u8 {
    value.clamp(0.0, 255.0).round() as u8
}

fn rgb_color(red: f64, green: f64, blue: f64) -> String {
    format!(
        "#{:02x}{:02x}{:02x}",
        color_byte(red),
        color_byte(green),
        color_byte(blue)
    )
}

fn chromium_rgb_color(red: f32, green: f32, blue: f32) -> String {
    let byte = |value: f32| (value * 255.0 + 0.5).clamp(0.0, 255.0).trunc() as u8;
    format!("#{:02x}{:02x}{:02x}", byte(red), byte(green), byte(blue))
}

fn css_rgb_color(value: &str) -> Option<String> {
    let open = value.find('(')?;
    let function = &value[..open];
    if !function.eq_ignore_ascii_case("rgb") && !function.eq_ignore_ascii_case("rgba") {
        return None;
    }
    let contents = value[open + 1..].strip_suffix(')')?;
    let (components, alpha, comma_syntax) = css_components(contents)?;
    if alpha.is_some_and(|alpha| !valid_css_alpha(alpha, comma_syntax))
        || comma_syntax
            && components
                .iter()
                .any(|component| component.eq_ignore_ascii_case("none"))
    {
        return None;
    }
    let (red, percent) = rgb_component(components[0])?;
    let (green, green_percent) = rgb_component(components[1])?;
    let (blue, blue_percent) = rgb_component(components[2])?;
    if comma_syntax && (percent != green_percent || green_percent != blue_percent) {
        return None;
    }
    Some(rgb_color(red, green, blue))
}

fn css_hsl_color(value: &str) -> Option<String> {
    let open = value.find('(')?;
    let function = &value[..open];
    if !function.eq_ignore_ascii_case("hsl") && !function.eq_ignore_ascii_case("hsla") {
        return None;
    }
    let contents = value[open + 1..].strip_suffix(')')?;
    let (components, alpha, comma_syntax) = css_components(contents)?;
    if alpha.is_some_and(|alpha| !valid_css_alpha(alpha, comma_syntax))
        || comma_syntax
            && components
                .iter()
                .any(|component| component.eq_ignore_ascii_case("none"))
    {
        return None;
    }
    let hue = css_hue(components[0])?;
    let percentage_component = |value| {
        if !comma_syntax {
            return css_color_component(value, 100.0);
        }
        let value = css_math_expression(value)?;
        (value.unit == CssMathUnit::Percentage).then_some(value.value)
    };
    let saturation = (percentage_component(components[1])? as f32 / 100.0).clamp(0.0, 1.0);
    let lightness = (percentage_component(components[2])? as f32 / 100.0).clamp(0.0, 1.0);
    let hue = hue.rem_euclid(360.0) as f32;
    if saturation == 0.0 {
        return Some(chromium_rgb_color(lightness, lightness, lightness));
    }
    let a = saturation * lightness.min(1.0 - lightness);
    let channel = |n: f32| {
        let k = (n + hue / 30.0) % 12.0;
        lightness - a * (k - 3.0).min(9.0 - k).clamp(-1.0, 1.0)
    };
    Some(chromium_rgb_color(channel(0.0), channel(8.0), channel(4.0)))
}

fn hwb_rgb(hue: f64, whiteness: f64, blackness: f64) -> (f64, f64, f64) {
    let hue = hue.rem_euclid(360.0) / 60.0;
    let (red, green, blue) = match hue.floor() as u8 {
        0 => (1.0, hue, 0.0),
        1 => (2.0 - hue, 1.0, 0.0),
        2 => (0.0, 1.0, hue - 2.0),
        3 => (0.0, 4.0 - hue, 1.0),
        4 => (hue - 4.0, 0.0, 1.0),
        _ => (1.0, 0.0, 6.0 - hue),
    };
    let sum = whiteness + blackness;
    if sum >= 1.0 {
        let gray = if sum == 0.0 { 0.0 } else { whiteness / sum };
        (gray, gray, gray)
    } else {
        let factor = 1.0 - sum;
        (
            red * factor + whiteness,
            green * factor + whiteness,
            blue * factor + whiteness,
        )
    }
}

fn css_hwb_color(value: &str) -> Option<String> {
    let open = value.find('(')?;
    if !value[..open].eq_ignore_ascii_case("hwb") {
        return None;
    }
    let contents = value[open + 1..].strip_suffix(')')?;
    let (components, alpha, comma_syntax) = css_components(contents)?;
    if comma_syntax || alpha.is_some_and(|alpha| !valid_css_alpha(alpha, comma_syntax)) {
        return None;
    }
    let (red, green, blue) = hwb_rgb(
        css_hue(components[0])?,
        (css_color_component(components[1], 100.0)? / 100.0).max(0.0),
        (css_color_component(components[2], 100.0)? / 100.0).max(0.0),
    );
    Some(rgb_color(red * 255.0, green * 255.0, blue * 255.0))
}

fn xyz_d65_to_srgb(x: f64, y: f64, z: f64) -> String {
    rgb_color(
        srgb_encode(3.240_969_941_9 * x - 1.537_383_177_6 * y - 0.498_610_760_3 * z) * 255.0,
        srgb_encode(-0.969_243_636_3 * x + 1.875_967_501_5 * y + 0.041_555_057_4 * z) * 255.0,
        srgb_encode(0.055_630_079_7 * x - 0.203_976_958_9 * y + 1.056_971_514_2 * z) * 255.0,
    )
}

fn xyz_d50_to_srgb(x: f64, y: f64, z: f64) -> String {
    let d65_x = 0.955_576_6 * x - 0.023_039_3 * y + 0.063_163_6 * z;
    let d65_y = -0.028_289_5 * x + 1.009_941_6 * y + 0.021_007_7 * z;
    let d65_z = 0.012_298_2 * x - 0.020_483_0 * y + 1.329_909_8 * z;
    xyz_d65_to_srgb(d65_x, d65_y, d65_z)
}

fn lab_inverse(value: f64) -> f64 {
    let cube = value * value * value;
    if cube > 216.0 / 24_389.0 {
        cube
    } else {
        (116.0 * value - 16.0) / (24_389.0 / 27.0)
    }
}

fn lab_to_srgb(lightness: f64, a: f64, b: f64) -> String {
    let fy = (lightness + 16.0) / 116.0;
    let fx = fy + a / 500.0;
    let fz = fy - b / 200.0;
    xyz_d50_to_srgb(
        0.964_22 * lab_inverse(fx),
        lab_inverse(fy),
        0.825_21 * lab_inverse(fz),
    )
}

fn css_lab_color(value: &str, expected_function: &str) -> Option<String> {
    let open = value.find('(')?;
    if !value[..open].eq_ignore_ascii_case(expected_function) {
        return None;
    }
    let contents = value[open + 1..].strip_suffix(')')?;
    let (components, alpha, comma_syntax) = css_components(contents)?;
    if comma_syntax || alpha.is_some_and(|alpha| !valid_css_alpha(alpha, comma_syntax)) {
        return None;
    }
    let lightness = css_color_component(components[0], 100.0)?;
    if !lightness.is_finite() {
        return None;
    }
    let lightness = lightness.clamp(0.0, 100.0);
    let (a, b) = if expected_function.eq_ignore_ascii_case("lch") {
        let chroma = css_color_component(components[1], 150.0)?.max(0.0);
        let hue = css_hue(components[2])?.to_radians();
        (chroma * hue.cos(), chroma * hue.sin())
    } else {
        (
            css_color_component(components[1], 125.0)?,
            css_color_component(components[2], 125.0)?,
        )
    };
    if !a.is_finite() || !b.is_finite() {
        return None;
    }
    Some(lab_to_srgb(lightness, a, b))
}

fn oklab_to_srgb(lightness: f64, a: f64, b: f64) -> String {
    let l = (lightness + 0.396_337_777_4 * a + 0.215_803_757_3 * b).powi(3);
    let m = (lightness - 0.105_561_345_8 * a - 0.063_854_172_8 * b).powi(3);
    let s = (lightness - 0.089_484_177_5 * a - 1.291_485_548_0 * b).powi(3);
    rgb_color(
        srgb_encode(4.076_741_662_1 * l - 3.307_711_591_3 * m + 0.230_969_929_2 * s) * 255.0,
        srgb_encode(-1.268_438_004_6 * l + 2.609_757_401_1 * m - 0.341_319_396_5 * s) * 255.0,
        srgb_encode(-0.004_196_086_3 * l - 0.703_418_614_7 * m + 1.707_614_701_0 * s) * 255.0,
    )
}

fn css_oklab_color(value: &str, expected_function: &str) -> Option<String> {
    let open = value.find('(')?;
    if !value[..open].eq_ignore_ascii_case(expected_function) {
        return None;
    }
    let contents = value[open + 1..].strip_suffix(')')?;
    let (components, alpha, comma_syntax) = css_components(contents)?;
    if comma_syntax || alpha.is_some_and(|alpha| !valid_css_alpha(alpha, comma_syntax)) {
        return None;
    }
    let lightness = css_color_component(components[0], 1.0)?;
    if !lightness.is_finite() {
        return None;
    }
    let lightness = lightness.clamp(0.0, 1.0);
    let (a, b) = if expected_function.eq_ignore_ascii_case("oklch") {
        let chroma = css_color_component(components[1], 0.4)?.max(0.0);
        let hue = css_hue(components[2])?.to_radians();
        (chroma * hue.cos(), chroma * hue.sin())
    } else {
        (
            css_color_component(components[1], 0.4)?,
            css_color_component(components[2], 0.4)?,
        )
    };
    if !a.is_finite() || !b.is_finite() {
        return None;
    }
    Some(oklab_to_srgb(lightness, a, b))
}

fn srgb_encode(linear: f64) -> f64 {
    let sign = linear.signum();
    let magnitude = linear.abs();
    sign * if magnitude <= 0.003_130_8 {
        12.92 * magnitude
    } else {
        1.055 * magnitude.powf(1.0 / 2.4) - 0.055
    }
}

#[derive(Clone, Copy)]
struct ChromiumTransferFunction {
    g: f32,
    a: f32,
    b: f32,
    c: f32,
    d: f32,
    e: f32,
    f: f32,
}

const CHROMIUM_SRGB_TRANSFER: ChromiumTransferFunction = ChromiumTransferFunction {
    g: 2.4,
    a: (1.0_f64 / 1.055_f64) as f32,
    b: (0.055_f64 / 1.055_f64) as f32,
    c: (1.0_f64 / 12.92_f64) as f32,
    d: 0.04045,
    e: 0.0,
    f: 0.0,
};

fn chromium_transfer_eval(transfer: &ChromiumTransferFunction, value: f32) -> f32 {
    let sign = if value < 0.0 { -1.0 } else { 1.0 };
    let magnitude = value.abs();
    if magnitude <= transfer.d {
        return sign * (transfer.c * magnitude + transfer.f);
    }
    let base = transfer.a * magnitude + transfer.b;
    // std::max(base, 0) preserves a NaN base; f32::max would replace it with 0.
    let base = if base < 0.0 { 0.0 } else { base };
    if transfer.g == 1.0 {
        sign * (base + transfer.e)
    } else {
        sign * (base.powf(transfer.g) + transfer.e)
    }
}

fn chromium_inverse_srgb_transfer() -> ChromiumTransferFunction {
    let source = CHROMIUM_SRGB_TRANSFER;
    let mut inverse = ChromiumTransferFunction {
        g: 1.0 / source.g,
        a: source.a.powf(-source.g),
        b: 0.0,
        c: 1.0 / source.c,
        d: source.c * source.d + source.f,
        e: -source.b / source.a,
        f: -source.f / source.c,
    };
    inverse.b = -inverse.a * source.e;
    if inverse.a * inverse.d + inverse.b < 0.0 {
        inverse.b = -inverse.a * inverse.d;
    }
    let mut s = chromium_transfer_eval(&source, 1.0);
    let sign = if s < 0.0 { -1.0 } else { 1.0 };
    s *= sign;
    if s < inverse.d {
        inverse.f = 1.0 - sign * inverse.c * s;
    } else {
        inverse.e = 1.0 - sign * (inverse.a * s + inverse.b).powf(inverse.g);
    }
    inverse
}

const CHROMIUM_SRGB_TO_XYZ_D50: [[f32; 3]; 3] = [
    [
        0x6fa2 as f32 / 65536.0,
        0x6299 as f32 / 65536.0,
        0x24a0 as f32 / 65536.0,
    ],
    [
        0x38f5 as f32 / 65536.0,
        0xb785 as f32 / 65536.0,
        0x0f84 as f32 / 65536.0,
    ],
    [
        0x0390 as f32 / 65536.0,
        0x18da as f32 / 65536.0,
        0xb6cf as f32 / 65536.0,
    ],
];

const CHROMIUM_DISPLAY_P3_TO_XYZ_D50: [[f32; 3]; 3] = [
    [0.515102, 0.291965, 0.157153],
    [0.241182, 0.692236, 0.0665819],
    [-0.00104941, 0.0418818, 0.784378],
];

const fn invert_color_matrix(matrix: [[f32; 3]; 3]) -> [[f32; 3]; 3] {
    let a00 = matrix[0][0] as f64;
    let a01 = matrix[1][0] as f64;
    let a02 = matrix[2][0] as f64;
    let a10 = matrix[0][1] as f64;
    let a11 = matrix[1][1] as f64;
    let a12 = matrix[2][1] as f64;
    let a20 = matrix[0][2] as f64;
    let a21 = matrix[1][2] as f64;
    let a22 = matrix[2][2] as f64;
    let b0 = a00 * a11 - a01 * a10;
    let b1 = a00 * a12 - a02 * a10;
    let b2 = a01 * a12 - a02 * a11;
    let b3 = a20;
    let b4 = a21;
    let b5 = a22;
    let determinant = b0 * b5 - b1 * b4 + b2 * b3;
    assert!(determinant != 0.0);
    let inverse_determinant = 1.0 / determinant;
    let b0 = b0 * inverse_determinant;
    let b1 = b1 * inverse_determinant;
    let b2 = b2 * inverse_determinant;
    let b3 = b3 * inverse_determinant;
    let b4 = b4 * inverse_determinant;
    let b5 = b5 * inverse_determinant;
    [
        [
            (a11 * b5 - a12 * b4) as f32,
            (a12 * b3 - a10 * b5) as f32,
            (a10 * b4 - a11 * b3) as f32,
        ],
        [
            (a02 * b4 - a01 * b5) as f32,
            (a00 * b5 - a02 * b3) as f32,
            (a01 * b3 - a00 * b4) as f32,
        ],
        [b2 as f32, -b1 as f32, b0 as f32],
    ]
}

const CHROMIUM_SRGB_FROM_XYZ_D50: [[f32; 3]; 3] = invert_color_matrix(CHROMIUM_SRGB_TO_XYZ_D50);

fn chromium_matrix_apply(matrix: &[[f32; 3]; 3], vector: [f32; 3]) -> [f32; 3] {
    [
        matrix[0][0] * vector[0] + matrix[0][1] * vector[1] + matrix[0][2] * vector[2],
        matrix[1][0] * vector[0] + matrix[1][1] * vector[1] + matrix[1][2] * vector[2],
        matrix[2][0] * vector[0] + matrix[2][1] * vector[1] + matrix[2][2] * vector[2],
    ]
}

fn signed_power(value: f64, exponent: f64) -> f64 {
    value.signum() * value.abs().powf(exponent)
}

fn rec2020_decode(value: f64) -> f64 {
    const ALPHA: f64 = 1.099_296_826_809_44;
    const BETA: f64 = 0.018_053_968_510_807;
    let sign = value.signum();
    let magnitude = value.abs();
    if magnitude < 4.5 * BETA {
        sign * magnitude / 4.5
    } else {
        sign * ((magnitude + ALPHA - 1.0) / ALPHA).powf(1.0 / 0.45)
    }
}

fn css_color_space_value(value: &str) -> Option<String> {
    let open = value.find('(')?;
    if !value[..open].eq_ignore_ascii_case("color") {
        return None;
    }
    let contents = value[open + 1..].strip_suffix(')')?;
    let outer = css_outer_syntax(contents)?;
    if outer.comma_count > 0 {
        return None;
    }
    let (channel_text, alpha) = match outer.slash {
        Some(slash) => (
            contents.get(..slash)?,
            Some(trim_css_whitespace(contents.get(slash + 1..)?)),
        ),
        None => (contents, None),
    };
    let (components, count) = css_outer_whitespace_components::<4>(channel_text)?;
    if count != 4 || alpha.is_some_and(|alpha| !valid_css_alpha(alpha, false)) {
        return None;
    }
    let [color_space, red, green, blue] = components;
    if color_space.eq_ignore_ascii_case("display-p3") {
        let red = css_color_component_preserving_nan(red, 1.0)?;
        let green = css_color_component_preserving_nan(green, 1.0)?;
        let blue = css_color_component_preserving_nan(blue, 1.0)?;
        let decoded = [red as f32, green as f32, blue as f32]
            .map(|channel| chromium_transfer_eval(&CHROMIUM_SRGB_TRANSFER, channel));
        let xyz = chromium_matrix_apply(&CHROMIUM_DISPLAY_P3_TO_XYZ_D50, decoded);
        let linear = chromium_matrix_apply(&CHROMIUM_SRGB_FROM_XYZ_D50, xyz);
        let inverse = chromium_inverse_srgb_transfer();
        let [red, green, blue] = linear.map(|channel| chromium_transfer_eval(&inverse, channel));
        return Some(chromium_rgb_color(red, green, blue));
    }
    let red = css_color_component(red, 1.0)?;
    let green = css_color_component(green, 1.0)?;
    let blue = css_color_component(blue, 1.0)?;
    if color_space.eq_ignore_ascii_case("srgb") {
        return Some(rgb_color(red * 255.0, green * 255.0, blue * 255.0));
    }
    if color_space.eq_ignore_ascii_case("srgb-linear") {
        return Some(rgb_color(
            srgb_encode(red) * 255.0,
            srgb_encode(green) * 255.0,
            srgb_encode(blue) * 255.0,
        ));
    }
    if color_space.eq_ignore_ascii_case("a98-rgb") {
        let red = signed_power(red, 563.0 / 256.0);
        let green = signed_power(green, 563.0 / 256.0);
        let blue = signed_power(blue, 563.0 / 256.0);
        return Some(xyz_d65_to_srgb(
            0.576_730_9 * red + 0.185_554_0 * green + 0.188_185_2 * blue,
            0.297_376_9 * red + 0.627_349_1 * green + 0.075_274_1 * blue,
            0.027_034_3 * red + 0.070_687_2 * green + 0.991_108_5 * blue,
        ));
    }
    if color_space.eq_ignore_ascii_case("prophoto-rgb") {
        let decode = |value: f64| {
            let sign = value.signum();
            let magnitude = value.abs();
            sign * if magnitude < 16.0 / 512.0 {
                magnitude / 16.0
            } else {
                magnitude.powf(1.8)
            }
        };
        let red = decode(red);
        let green = decode(green);
        let blue = decode(blue);
        return Some(xyz_d50_to_srgb(
            0.797_766_644_9 * red + 0.135_181_297_4 * green + 0.031_347_734_1 * blue,
            0.288_074_828_8 * red + 0.711_835_234_2 * green + 0.000_089_936_9 * blue,
            0.825_104_602_5 * blue,
        ));
    }
    if color_space.eq_ignore_ascii_case("rec2020") {
        let red = rec2020_decode(red);
        let green = rec2020_decode(green);
        let blue = rec2020_decode(blue);
        return Some(xyz_d65_to_srgb(
            0.636_958_048_3 * red + 0.144_616_903_6 * green + 0.168_880_975_2 * blue,
            0.262_700_212_0 * red + 0.677_998_071_5 * green + 0.059_301_716_5 * blue,
            0.028_072_693_0 * green + 1.060_985_057_7 * blue,
        ));
    }
    if color_space.eq_ignore_ascii_case("xyz-d50") {
        return Some(xyz_d50_to_srgb(red, green, blue));
    }
    if color_space.eq_ignore_ascii_case("xyz") || color_space.eq_ignore_ascii_case("xyz-d65") {
        return Some(xyz_d65_to_srgb(red, green, blue));
    }
    None
}

fn strip_css_color_comments(value: &str) -> std::borrow::Cow<'_, str> {
    if !value.contains("/*") {
        if value.contains(CSS_COLOR_COMMENT_SEPARATOR as char) {
            let mut result = String::with_capacity(value.len());
            append_css_color_source(&mut result, value);
            return std::borrow::Cow::Owned(result);
        }
        return std::borrow::Cow::Borrowed(value);
    }
    let mut result = String::with_capacity(value.len());
    let mut remaining = value;
    loop {
        let Some(start) = remaining.find("/*") else {
            append_css_color_source(&mut result, remaining);
            break;
        };
        append_css_color_source(&mut result, &remaining[..start]);
        let comment_start = start + 2;
        let Some(end) = remaining[comment_start..].find("*/") else {
            result.push(' ');
            break;
        };
        result.push(CSS_COLOR_COMMENT_SEPARATOR as char);
        remaining = &remaining[comment_start + end + 2..];
    }
    std::borrow::Cow::Owned(result)
}

fn append_css_color_source(result: &mut String, source: &str) {
    let mut remaining = source;
    while let Some(separator) = remaining.find(CSS_COLOR_COMMENT_SEPARATOR as char) {
        result.push_str(&remaining[..separator]);
        result.push('\u{0002}');
        remaining = &remaining[separator + 1..];
    }
    result.push_str(remaining);
}

fn css_color_value(value: &str) -> String {
    // A literal U+0001 in the source is not CSS whitespace. Escape it before
    // trimming so a source marker cannot be mistaken for a comment boundary.
    let mut escaped;
    let source = if value.contains(CSS_COLOR_COMMENT_SEPARATOR as char) {
        escaped = String::with_capacity(value.len());
        append_css_color_source(&mut escaped, value);
        escaped.as_str()
    } else {
        value
    };
    let raw = trim_css_whitespace(source);
    let has_comment = raw.contains("/*");
    let tokenized = strip_css_color_comments(raw);
    let tokenized = trim_css_whitespace(tokenized.as_ref());
    if has_comment && !tokenized.starts_with('#') && !tokenized.contains('(') {
        return "#000000".to_owned();
    }
    let unclosed_blocks = tokenized
        .bytes()
        .try_fold(0_usize, |depth, byte| match byte {
            b'(' => depth.checked_add(1),
            b')' => depth.checked_sub(1),
            _ => Some(depth),
        });
    let completed_function = (unclosed_blocks == Some(1)).then(|| format!("{tokenized})"));
    let value = completed_function.as_deref().unwrap_or(tokenized);
    if let Some(hex) = value.strip_prefix('#') {
        let expanded = match hex.len() {
            3 | 4 => {
                let bytes = hex.as_bytes();
                if !bytes.iter().all(u8::is_ascii_hexdigit) {
                    return "#000000".to_owned();
                }
                return format!(
                    "#{0}{0}{1}{1}{2}{2}",
                    (bytes[0] as char).to_ascii_lowercase(),
                    (bytes[1] as char).to_ascii_lowercase(),
                    (bytes[2] as char).to_ascii_lowercase(),
                );
            }
            6 | 8 if hex.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
                hex[..6].to_ascii_lowercase()
            }
            _ => return "#000000".to_owned(),
        };
        return format!("#{expanded}");
    }
    if let Some(color) = CSS_NAMED_COLORS.split_ascii_whitespace().find_map(|entry| {
        let (name, hex) = entry.split_once(':')?;
        name.eq_ignore_ascii_case(value).then_some(hex)
    }) {
        return format!("#{color}");
    }
    css_rgb_color(value)
        .or_else(|| css_hsl_color(value))
        .or_else(|| css_hwb_color(value))
        .or_else(|| css_lab_color(value, "lab"))
        .or_else(|| css_lab_color(value, "lch"))
        .or_else(|| css_oklab_color(value, "oklab"))
        .or_else(|| css_oklab_color(value, "oklch"))
        .or_else(|| css_color_space_value(value))
        .unwrap_or_else(|| "#000000".to_owned())
}

#[derive(Clone, Copy)]
struct DecimalNumber {
    coefficient: i128,
    scale: i32,
}

fn decimal_number(value: &str) -> Option<DecimalNumber> {
    let bytes = value.as_bytes();
    let exponent_start = bytes
        .iter()
        .position(|byte| matches!(byte, b'e' | b'E'))
        .unwrap_or(bytes.len());
    let exponent = if exponent_start < bytes.len() {
        value.get(exponent_start + 1..)?.parse::<i32>().ok()?
    } else {
        0
    };
    let significand = value.get(..exponent_start)?.as_bytes();
    let negative = significand.first() == Some(&b'-');
    let mut index = usize::from(negative);
    let mut coefficient = 0_i128;
    let mut fractional_digits = 0_i32;
    let mut after_decimal = false;
    let mut digit_count = 0;
    while let Some(byte) = significand.get(index) {
        match byte {
            b'.' if !after_decimal => after_decimal = true,
            b'0'..=b'9' => {
                coefficient = coefficient
                    .checked_mul(10)?
                    .checked_add(i128::from(byte - b'0'))?;
                digit_count += 1;
                if after_decimal {
                    fractional_digits = fractional_digits.checked_add(1)?;
                }
            }
            _ => return None,
        }
        index += 1;
    }
    if digit_count == 0 {
        return None;
    }
    let mut scale = fractional_digits.checked_sub(exponent)?;
    if scale < 0 {
        let shift = u32::try_from(scale.checked_neg()?).ok()?;
        coefficient = coefficient.checked_mul(10_i128.checked_pow(shift)?)?;
        scale = 0;
    }
    if negative {
        coefficient = coefficient.checked_neg()?;
    }
    while scale > 0 && coefficient % 10 == 0 {
        coefficient /= 10;
        scale -= 1;
    }
    Some(DecimalNumber { coefficient, scale })
}

fn decimal_from_f64(value: f64) -> Option<DecimalNumber> {
    value
        .is_finite()
        .then(|| value.to_string())
        .and_then(|value| decimal_number(&value))
}

fn decimal_scaled(value: DecimalNumber, scale: i32) -> Option<i128> {
    let shift = scale.checked_sub(value.scale)?;
    let shift = u32::try_from(shift).ok()?;
    if value.coefficient == 0 {
        return Some(0);
    }
    value.coefficient.checked_mul(10_i128.checked_pow(shift)?)
}

fn decimal_value_as_f64(coefficient: i128, scale: i32) -> Option<f64> {
    if !(-308..=308).contains(&scale) {
        return None;
    }
    if coefficient == 0 {
        return Some(0.0);
    }

    // Parse the exact decimal coefficient and exponent once. Casting the
    // coefficient before dividing by a power of ten can round twice.
    let mut reversed_digits = [0_u8; 39];
    let mut magnitude = coefficient.unsigned_abs();
    let mut digit_count = 0;
    while magnitude != 0 {
        reversed_digits[digit_count] = b'0' + (magnitude % 10) as u8;
        magnitude /= 10;
        digit_count += 1;
    }
    let exponent = i32::try_from(digit_count - 1).ok()?.checked_sub(scale)?;
    let mut decimal = [0_u8; 64];
    let mut decimal_len = 0;
    if coefficient < 0 {
        decimal[decimal_len] = b'-';
        decimal_len += 1;
    }
    decimal[decimal_len] = reversed_digits[digit_count - 1];
    decimal_len += 1;
    if digit_count > 1 {
        decimal[decimal_len] = b'.';
        decimal_len += 1;
        for digit in reversed_digits[..digit_count - 1].iter().rev() {
            decimal[decimal_len] = *digit;
            decimal_len += 1;
        }
    }
    decimal[decimal_len] = b'e';
    decimal_len += 1;
    if exponent < 0 {
        decimal[decimal_len] = b'-';
        decimal_len += 1;
    } else {
        decimal[decimal_len] = b'+';
        decimal_len += 1;
    }
    let mut reversed_exponent = [0_u8; 10];
    let mut exponent_magnitude = exponent.unsigned_abs();
    let mut exponent_len = 0;
    while exponent_magnitude != 0 {
        reversed_exponent[exponent_len] = b'0' + (exponent_magnitude % 10) as u8;
        exponent_magnitude /= 10;
        exponent_len += 1;
    }
    if exponent_len == 0 {
        reversed_exponent[0] = b'0';
        exponent_len = 1;
    }
    for digit in reversed_exponent[..exponent_len].iter().rev() {
        decimal[decimal_len] = *digit;
        decimal_len += 1;
    }
    let value = std::str::from_utf8(&decimal[..decimal_len])
        .ok()?
        .parse::<f64>()
        .ok()?;
    value.is_finite().then_some(value)
}

fn decimal_midpoint(minimum: f64, maximum: f64) -> Option<DecimalNumber> {
    let minimum = decimal_from_f64(minimum)?;
    let maximum = decimal_from_f64(maximum)?;
    let scale = minimum.scale.max(maximum.scale);
    let minimum = decimal_scaled(minimum, scale)?;
    let maximum = decimal_scaled(maximum, scale)?;
    let half_sum = minimum.div_euclid(2).checked_add(maximum.div_euclid(2))?;
    let remainder = minimum.rem_euclid(2) + maximum.rem_euclid(2);
    if remainder == 1 {
        Some(DecimalNumber {
            coefficient: half_sum.checked_mul(10)?.checked_add(5)?,
            scale: scale.checked_add(1)?,
        })
    } else {
        Some(DecimalNumber {
            coefficient: half_sum.checked_add(remainder / 2)?,
            scale,
        })
    }
}

fn decimal_step_value(
    minimum: f64,
    maximum: f64,
    base: f64,
    step: f64,
    value: Option<f64>,
) -> Option<f64> {
    let base = decimal_from_f64(base)?;
    let step = decimal_from_f64(step)?;
    let value = match value {
        Some(value) => decimal_from_f64(value)?,
        None => decimal_midpoint(minimum, maximum)?,
    };
    // Only local arithmetic needs a common decimal scale. A distant bound
    // must not force an otherwise exact decimal tie through binary division.
    let scale = base.scale.max(step.scale).max(value.scale);
    let base = decimal_scaled(base, scale)?;
    let step = decimal_scaled(step, scale)?;
    let value = decimal_scaled(value, scale)?;
    if step <= 0 {
        return None;
    }
    let offset = value.checked_sub(base)?;
    let quotient = offset.div_euclid(step);
    let remainder = offset.rem_euclid(step);
    let nearest_step = if remainder >= step - remainder {
        quotient.checked_add(1)?
    } else {
        quotient
    };
    let candidate = base.checked_add(nearest_step.checked_mul(step)?)?;
    let rounded = decimal_value_as_f64(candidate, scale)?;
    let in_range = if rounded < minimum {
        candidate.checked_add(step)?
    } else if rounded > maximum {
        candidate.checked_sub(step)?
    } else {
        return Some(rounded);
    };
    let rounded = decimal_value_as_f64(in_range, scale)?;
    if rounded >= minimum && rounded <= maximum {
        Some(rounded)
    } else {
        // No aligned step is available within the bounds.
        decimal_value_as_f64(value, scale)
    }
}

fn snap_near_integer(value: f64) -> f64 {
    const MAX_EXACT_INTEGER: f64 = 9_007_199_254_740_992.0;
    if !value.is_finite() || value.abs() >= MAX_EXACT_INTEGER {
        return value;
    }
    let nearest = value.round();
    let tolerance = 2.0 * f64::EPSILON * value.abs().max(1.0);
    if (value - nearest).abs() <= tolerance {
        nearest
    } else {
        value
    }
}

fn overflow_safe_range_step_value(
    minimum: f64,
    maximum: f64,
    base: f64,
    step: f64,
    value: f64,
) -> Option<f64> {
    let local_position = (value - base) / step;
    if local_position.is_finite() {
        let lower_step = local_position.floor();
        let fraction = local_position - lower_step;
        let nearest_step = if fraction >= 0.5 {
            lower_step + 1.0
        } else {
            lower_step
        };
        let candidate = base + nearest_step * step;
        if candidate.is_finite() && candidate >= minimum && candidate <= maximum {
            return Some(candidate);
        }
    }

    let scale = minimum
        .abs()
        .max(maximum.abs())
        .max(base.abs())
        .max(step.abs())
        .max(value.abs());
    if !scale.is_finite() || scale == 0.0 {
        return Some(value);
    }
    let normalized_minimum = minimum / scale;
    let normalized_maximum = maximum / scale;
    let normalized_base = base / scale;
    let normalized_step = step / scale;
    let normalized_value = value / scale;
    if normalized_step == 0.0 {
        return None;
    }
    let minimum_step =
        snap_near_integer((normalized_minimum - normalized_base) / normalized_step).ceil();
    let maximum_step =
        snap_near_integer((normalized_maximum - normalized_base) / normalized_step).floor();
    let value_position = (normalized_value - normalized_base) / normalized_step;
    let value_floor = value_position.floor();
    let value_fraction = value_position - value_floor;
    let value_step = if value_fraction >= 0.5 {
        value_floor + 1.0
    } else {
        value_floor
    };
    if !minimum_step.is_finite()
        || !maximum_step.is_finite()
        || !value_step.is_finite()
        || minimum_step > maximum_step
    {
        return Some(value);
    }
    let steps = value_step.clamp(minimum_step, maximum_step);
    let candidate = (normalized_base + steps * normalized_step) * scale;
    candidate
        .is_finite()
        .then_some(candidate.clamp(minimum, maximum))
}

fn range_number_string(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }
    use std::fmt::Write as _;

    // Chromium range controls serialize with 15 significant decimal digits;
    // keep this separate from the exact step calculation above.
    let mut output = String::with_capacity(32);
    let _ = write!(&mut output, "{value:.14e}");
    let Some(exponent_index) = output.find('e') else {
        return value.to_string();
    };
    let Ok(exponent) = output[exponent_index + 1..].parse::<i32>() else {
        return value.to_string();
    };
    output.truncate(exponent_index);
    while output.ends_with('0') {
        output.pop();
    }
    if output.ends_with('.') {
        output.pop();
    }

    if !(-6..21).contains(&exponent) {
        let _ = write!(&mut output, "e{exponent:+}");
        return output;
    }

    let sign_len = usize::from(output.starts_with('-'));
    if output.as_bytes().get(sign_len + 1) == Some(&b'.') {
        output.remove(sign_len + 1);
    }
    let digit_count = output.len() - sign_len;
    let decimal_position = exponent + 1;
    if decimal_position <= 0 {
        output.insert_str(sign_len, "0.");
        for _ in 0..-decimal_position {
            output.insert(sign_len + 2, '0');
        }
    } else if decimal_position as usize >= digit_count {
        for _ in digit_count..decimal_position as usize {
            output.push('0');
        }
    } else {
        output.insert(sign_len + decimal_position as usize, '.');
    }
    output
}

fn range_value(control: ElementRef<'_>, source: &str) -> Result<String, Error> {
    let source_value = html_float(source);
    let source_minimum = control.value().attr("min").and_then(html_float);
    let minimum = source_minimum.unwrap_or(0.0);
    let maximum = control
        .value()
        .attr("max")
        .and_then(html_float)
        .unwrap_or(100.0)
        .max(minimum);
    let mut value = source_value
        .unwrap_or_else(|| minimum / 2.0 + maximum / 2.0)
        .clamp(minimum, maximum);
    let step = control.value().attr("step");
    if !step.is_some_and(|step| step.eq_ignore_ascii_case("any")) {
        let step = step
            .and_then(html_float)
            .filter(|step| *step > 0.0)
            .unwrap_or(1.0);
        let base = source_minimum.or(source_value).unwrap_or(0.0);
        if let Some(decimal_value) =
            decimal_step_value(minimum, maximum, base, step, source_value.map(|_| value))
        {
            value = decimal_value;
        } else if let Some(scaled_value) =
            overflow_safe_range_step_value(minimum, maximum, base, step, value)
        {
            value = scaled_value;
        } else {
            return Err(unavailable());
        }
    }
    Ok(range_number_string(value))
}

fn valid_year_modulo_400(year: &str) -> Option<u16> {
    if year.len() < 4 || !year.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut modulo = 0_u16;
    let mut nonzero = false;
    for byte in year.bytes() {
        modulo = (modulo * 10 + u16::from(byte - b'0')) % 400;
        nonzero |= byte != b'0';
    }
    nonzero.then_some(modulo)
}

fn valid_date_parts(value: &str) -> Option<(u16, u8, u8)> {
    let (year, rest) = value.split_once('-')?;
    let (month, day) = rest.split_once('-')?;
    let year = valid_year_modulo_400(year)?;
    if month.len() != 2
        || day.len() != 2
        || !month.bytes().all(|byte| byte.is_ascii_digit())
        || !day.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let month = month.parse::<u8>().ok()?;
    let day = day.parse::<u8>().ok()?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (day > 0 && day <= days).then_some((year, month, day))
}

fn valid_week_value(value: &str) -> bool {
    let Some((year, week)) = value.split_once("-W") else {
        return false;
    };
    let Some(year_mod) = valid_year_modulo_400(year) else {
        return false;
    };
    if week.len() != 2 || !week.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Ok(week) = week.parse::<u8>() else {
        return false;
    };
    let preceding = (year_mod + 399) % 400;
    let leap = year_mod % 4 == 0 && (year_mod % 100 != 0 || year_mod == 0);
    let days = u32::from(preceding) * 365 + u32::from(preceding) / 4 - u32::from(preceding) / 100
        + u32::from(preceding) / 400;
    let january_first = days % 7;
    let has_week_53 = january_first == 3 || (leap && january_first == 2);
    week >= 1 && week <= if has_week_53 { 53 } else { 52 }
}

fn valid_time_value(value: &str) -> bool {
    let mut parts = value.split(':');
    let (Some(hour), Some(minute), second) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if parts.next().is_some()
        || hour.len() != 2
        || minute.len() != 2
        || !hour.bytes().all(|byte| byte.is_ascii_digit())
        || !minute.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(hour) = hour.parse::<u8>() else {
        return false;
    };
    let Ok(minute) = minute.parse::<u8>() else {
        return false;
    };
    if hour > 23 || minute > 59 {
        return false;
    }
    let Some(second) = second else {
        return true;
    };
    let (second, fraction) = second.split_once('.').unwrap_or((second, ""));
    if second.len() != 2
        || !second.bytes().all(|byte| byte.is_ascii_digit())
        || value_has_empty_time_fraction(value)
        || fraction.len() > 3
        || (!fraction.is_empty() && !fraction.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    second.parse::<u8>().is_ok_and(|second| second <= 59)
}

fn value_has_empty_time_fraction(value: &str) -> bool {
    value
        .split_once('.')
        .is_some_and(|(_, fraction)| fraction.is_empty())
}

fn normalize_datetime_local(value: &str) -> Option<String> {
    let (date, time) = value.split_once('T').or_else(|| value.split_once(' '))?;
    valid_date_parts(date)?;
    if !valid_time_value(time) {
        return None;
    }
    let mut parts = time.split(':');
    let hour = parts.next()?;
    let minute = parts.next()?;
    let Some(second) = parts.next() else {
        return Some(format!("{date}T{hour}:{minute}"));
    };
    let (second, fraction) = second.split_once('.').unwrap_or((second, ""));
    let fraction_is_zero = fraction.is_empty() || fraction.bytes().all(|byte| byte == b'0');
    if second == "00" && fraction_is_zero {
        return Some(format!("{date}T{hour}:{minute}"));
    }
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        return Some(format!("{date}T{hour}:{minute}:{second}"));
    }
    Some(format!("{date}T{hour}:{minute}:{second}.{fraction}"))
}

fn remove_line_breaks(value: &str) -> std::borrow::Cow<'_, str> {
    if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        std::borrow::Cow::Owned(
            value
                .chars()
                .filter(|character| !matches!(character, '\r' | '\n'))
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

/// Preserve the browser's initial value sanitization for successful inputs.
fn input_submission_value<'a>(
    control: ElementRef<'a>,
    kind: &str,
) -> Result<std::borrow::Cow<'a, str>, Error> {
    let source = control.value().attr("value").unwrap_or("");
    if kind.eq_ignore_ascii_case("range") {
        return Ok(std::borrow::Cow::Owned(range_value(control, source)?));
    }
    if kind.eq_ignore_ascii_case("color") {
        return Ok(std::borrow::Cow::Owned(css_color_value(source)));
    }
    if kind.eq_ignore_ascii_case("number") {
        return Ok(if html_float(source).is_some() {
            std::borrow::Cow::Borrowed(source)
        } else {
            std::borrow::Cow::Borrowed("")
        });
    }
    if kind.eq_ignore_ascii_case("date") {
        return Ok(if valid_date_parts(source).is_some() {
            std::borrow::Cow::Borrowed(source)
        } else {
            std::borrow::Cow::Borrowed("")
        });
    }
    if kind.eq_ignore_ascii_case("month") {
        let valid = source.split_once('-').is_some_and(|(year, month)| {
            valid_year_modulo_400(year).is_some()
                && month.len() == 2
                && month.bytes().all(|byte| byte.is_ascii_digit())
                && month
                    .parse::<u8>()
                    .is_ok_and(|month| (1..=12).contains(&month))
        });
        return Ok(if valid {
            std::borrow::Cow::Borrowed(source)
        } else {
            std::borrow::Cow::Borrowed("")
        });
    }
    if kind.eq_ignore_ascii_case("week") {
        return Ok(if valid_week_value(source) {
            std::borrow::Cow::Borrowed(source)
        } else {
            std::borrow::Cow::Borrowed("")
        });
    }
    if kind.eq_ignore_ascii_case("time") {
        return Ok(if valid_time_value(source) {
            std::borrow::Cow::Borrowed(source)
        } else {
            std::borrow::Cow::Borrowed("")
        });
    }
    if kind.eq_ignore_ascii_case("datetime-local") {
        return Ok(normalize_datetime_local(source)
            .map(std::borrow::Cow::Owned)
            .unwrap_or(std::borrow::Cow::Borrowed("")));
    }
    let text = if kind.eq_ignore_ascii_case("hidden") {
        std::borrow::Cow::Borrowed(
            if control
                .value()
                .attr("name")
                .is_some_and(|name| name.eq_ignore_ascii_case("_charset_"))
            {
                "UTF-8"
            } else {
                source
            },
        )
    } else {
        remove_line_breaks(source)
    };
    if kind.eq_ignore_ascii_case("email") {
        if control.value().attr("multiple").is_some() {
            let normalized = text
                .split(',')
                .map(|address| {
                    address.trim_matches(|character: char| character.is_ascii_whitespace())
                })
                .collect::<Vec<_>>()
                .join(",");
            return Ok(std::borrow::Cow::Owned(normalized));
        }
        let trimmed = text.trim_matches(|character: char| character.is_ascii_whitespace());
        if trimmed.len() != text.len() {
            return Ok(std::borrow::Cow::Owned(trimmed.to_owned()));
        }
    }
    if kind.eq_ignore_ascii_case("url") {
        let trimmed = text.trim_matches(|character: char| character.is_ascii_whitespace());
        if trimmed.len() != text.len() {
            return Ok(std::borrow::Cow::Owned(trimmed.to_owned()));
        }
    }
    Ok(text)
}

fn normalize_textarea_value(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                normalized.push_str("\r\n");
            }
            '\n' => normalized.push_str("\r\n"),
            _ => normalized.push(character),
        }
    }
    normalized
}

fn form_urlencoded_body(fields: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        let name = if name.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            std::borrow::Cow::Owned(normalize_textarea_value(name))
        } else {
            std::borrow::Cow::Borrowed(*name)
        };
        let value = if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            std::borrow::Cow::Owned(normalize_textarea_value(value))
        } else {
            std::borrow::Cow::Borrowed(*value)
        };
        serializer.append_pair(name.as_ref(), value.as_ref());
    }
    serializer.finish()
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

/// One sanitized hop: host, allowlisted route label and status. Unrecognized
/// paths are replaced with a fixed label; no header value, body or credential
/// ever enters the trail.
#[derive(Clone)]
struct Trail {
    hops: Vec<String>,
}

fn receipt_route(url: &Url) -> &'static str {
    match (url.host_str(), url.path()) {
        (Some("sso.buaa.edu.cn"), "/login") => "/login",
        (Some("yjapi.msa.buaa.edu.cn"), "/casapi/index.php") => "/casapi/index.php",
        (Some(CLASSROOM_HOST), "/") => "/",
        (Some(CLASSROOM_HOST), "/courseapi/v3/portal-home-setting/get-sub-info") => {
            "/courseapi/v3/portal-home-setting/get-sub-info"
        }
        _ => "<unknown-route>",
    }
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
        let route = receipt_route(url);
        self.hops.push(format!("{host}{route} {status}"));
    }

    /// Record a redirect with allowlisted routes only. Query strings and
    /// unrecognized paths can contain credentials and never enter a receipt.
    fn record_redirect(&mut self, from: &Url, to: &Url, status: u16) {
        if self.hops.len() >= MAX_REDIRECTS + 2 {
            return;
        }
        let from_host = from.host_str().unwrap_or("");
        let from_route = receipt_route(from);
        let to_host = to.host_str().unwrap_or("");
        let to_route = receipt_route(to);
        self.hops.push(format!(
            "{from_host}{from_route} {status} -> {to_host}{to_route}"
        ));
    }

    fn value(&self) -> Value {
        json!(self.hops)
    }
}

/// Only fixed query-name labels leave the process. Bare tokens and encoded
/// keys can themselves be credentials; never decode or retain arbitrary keys.
fn query_names(url: &Url) -> Value {
    let names: Vec<&'static str> = url
        .query()
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter(|pair| !pair.is_empty())
        .map(
            |pair| match pair.split_once('=').map_or(pair, |(key, _)| key) {
                "ticket" => "ticket",
                _ => "<unknown-query-name>",
            },
        )
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
    form: Option<(&[(&str, &str)], &Url)>,
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
        // Snapshot the scoped cookie and its earliest expiry before any
        // pacing or request-start admission. The zeroizing buffer stays local.
        let cookie_snapshot = match jar.select_cookies(&url, true) {
            ScopedCookies::Anonymous => None,
            ScopedCookies::Ready(cookie, expiry) => Some((cookie, expiry)),
            ScopedCookies::Unusable => return Err(scoped_cookie_unusable()),
        };
        if !first {
            let reservation = lease.reserve_followup().map_err(|error| match error {
                crate::governor::FollowupError::Governor(_) => governor_state_unknown(),
            })?;
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
        enum SessionStart {
            CookieUnusable,
            Sent(Result<Response, reqwest::Error>),
        }
        let response = match lease.start_request(|| {
            if cookie_snapshot.as_ref().is_some_and(|(_, expiry)|cookie_expired(*expiry)) {
                return SessionStart::CookieUnusable;
            }
            let mut request = client.request(method.clone(), url.clone()).timeout(Duration::from_secs(30));
            if let Some((cookie, _)) = &cookie_snapshot {
                let Ok(mut header) = HeaderValue::from_str(cookie.as_str()) else {
                    return SessionStart::CookieUnusable;
                };
                header.set_sensitive(true);
                request = request.header(reqwest::header::COOKIE, header);
            }
            if let Some((_, referer)) = form {
                request = request.header(reqwest::header::REFERER, referer.as_str());
            }
            if let Some((fields, _)) = form {
                request = request
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(form_urlencoded_body(fields));
            }
            SessionStart::Sent(request.send())
        }) {
            Ok(SessionStart::Sent(Ok(response))) => response,
            Ok(SessionStart::Sent(Err(_))) => return Err(unavailable()),
            Ok(SessionStart::CookieUnusable) => return Err(scoped_cookie_unusable()),
            Err(crate::governor::FollowupError::Governor(_)) => return Err(governor_state_unknown()),
        };
        let status = response.status().as_u16();
        let challenged = response
            .headers()
            .iter()
            .any(|(name, value)| crate::net::challenge_header(name.as_str(), value.as_bytes()));
        let retry_after_result = response
            .headers()
            .get(RETRY_AFTER)
            .map(|value| value.to_str().map(str::to_owned).map_err(|_| unavailable()))
            .transpose();
        let observed_result = lease.observe_http_many(
            status,
            response.headers().get_all(RETRY_AFTER).iter().map(|value|value.to_str().ok()),
            challenged,
        );
        if observed_result.is_err() {
            drop(response);
            return Err(governor_state_unknown());
        }
        trail.record(&url, status);
        let all_content_types = response.headers().get_all(CONTENT_TYPE);
        let mut content_types = all_content_types.iter();
        let content_type_result = match (content_types.next(), content_types.next()) {
            (None, _) => Ok(None),
            (Some(value), None) => value.to_str().map(str::to_owned).map(Some).map_err(|_| unavailable()),
            (Some(_), Some(_)) => Err(unavailable()),
        };
        let location = response.headers().get(LOCATION).cloned();
        let cookies_result = jar.absorb(&url, response.headers());
        let body_result = body_text(response);
        let retry_after = retry_after_result?;
        let content_type = content_type_result?;
        cookies_result?;
        let body = body_result?;
        let location_result = location
            .map(|value| value.to_str().map(str::to_owned).map_err(|_| unavailable()))
            .transpose();
        let location = location_result?;
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
                Some(location) => location,
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
        // Dropping the owned response terminates its unread body before the
        // caller can finish the request lease.
        drop(response);
        return Err(unavailable());
    }
    // The advertised length is not the read bound.
    let mut bytes = Vec::new();
    let mut limited = std::io::Read::take(response, (MAX_BODY + 1) as u64);
    limited.read_to_end(&mut bytes).map_err(|_| unavailable())?;
    if bytes.len() > MAX_BODY {
        // The bounded read has intentionally not consumed an unbounded tail.
        drop(limited);
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
    unverified_challenge_text: bool,
    retry_after: Option<&str>,
    class: FailureClass,
) -> bool {
    final_host == CLASSROOM_HOST
        && status == 200
        && !body.trim().is_empty()
        && !challenge
        && !unverified_challenge_text
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

fn identity_probe_interaction(hop: &Hop) -> Option<FailureClass> {
    match login_content_type_label(hop.content_type.as_deref()) {
        Some("text/html") => {}
        Some("application/xhtml+xml") => return Some(FailureClass::UnsafeInteraction),
        _ => return None,
    }
    let fields = match login_fields(&hop.body, LoginSourceScope::FinalResponse) {
        Ok(fields) => fields,
        Err(_) => return Some(FailureClass::UnsafeInteraction),
    };
    if requires_challenge(&fields) {
        Some(FailureClass::Challenge)
    } else if requires_interaction_review(&fields) || fields.has_password_control {
        Some(FailureClass::UnsafeInteraction)
    } else {
        None
    }
}

/// An explicit reference uses the first document element with that ID, not
/// an arbitrary later form. Otherwise the nearest ancestor form owns it.
fn form_control_owner<'a>(
    control: ElementRef<'a>,
    first_elements_by_id: &HashMap<&'a str, ElementRef<'a>>,
) -> Option<ElementRef<'a>> {
    if let Some(id) = control.value().attr("form") {
        return first_elements_by_id.get(id).copied().filter(|element| {
            crate::html::is_html_element(*element) && element.value().name() == "form"
        });
    }
    control
        .ancestors()
        .filter_map(ElementRef::wrap)
        .find(|ancestor| {
            crate::html::is_html_element(*ancestor) && ancestor.value().name() == "form"
        })
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
        if crate::html::is_inert_context(element)
            || element.value().attr("hidden").is_some()
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

const CHALLENGE_MARKERS: [&str; 8] = [
    "captcha",
    "challenge",
    "verificationcode",
    "verification-code",
    "verification_code",
    "verification code",
    "验证码",
    "校验码",
];
const ACTIVE_TEXT_MARKERS: [&str; 24] = [
    "captcha",
    "challenge",
    "verificationcode",
    "verification-code",
    "verification_code",
    "verification code",
    "验证码",
    "校验码",
    "password",
    "incorrect",
    "invalid",
    "wrong",
    "error",
    "密码错误",
    "用户名或密码",
    "账号不存在",
    "service",
    "not found",
    "unsupported",
    "ticket",
    "expired",
    "fail",
    "未通过",
    "失效",
];

const ACTIVE_TEXT_CHALLENGE_MASK: u32 = (1 << 8) - 1;
const ACTIVE_TEXT_PASSWORD: usize = 8;
const ACTIVE_TEXT_CREDENTIAL_ERRORS: u32 =
    (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 15);
const ACTIVE_TEXT_CREDENTIAL_MESSAGES: u32 = (1 << 13) | (1 << 14) | (1 << 15);
const ACTIVE_TEXT_SERVICE: usize = 16;
const ACTIVE_TEXT_SERVICE_ERRORS: u32 = (1 << 10) | (1 << 17) | (1 << 18);
const ACTIVE_TEXT_TICKET: usize = 19;
const ACTIVE_TEXT_TICKET_ERRORS: u32 =
    (1 << 10) | (1 << 12) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);

#[derive(Clone, Copy, Default)]
struct ActiveTextFacts(u32);

impl ActiveTextFacts {
    fn contains(self, bit: usize) -> bool {
        self.0 & (1 << bit) != 0
    }

    fn intersects(self, mask: u32) -> bool {
        self.0 & mask != 0
    }

    fn has_challenge_marker(self) -> bool {
        self.intersects(ACTIVE_TEXT_CHALLENGE_MASK)
    }
}

fn challenge_marker_matches(value: &str) -> bool {
    CHALLENGE_MARKERS.iter().any(|marker| {
        value
            .as_bytes()
            .windows(marker.len())
            .any(|window| window.eq_ignore_ascii_case(marker.as_bytes()))
    })
}

/// Labels may split a marker with whitespace or across active text nodes.
/// Compare borrowed characters without retaining or copying input values.
fn challenge_label_marker_matches(value: &str) -> bool {
    value.char_indices().any(|(start, character)| {
        !character.is_whitespace()
            && CHALLENGE_MARKERS.iter().any(|marker| {
                let mut label = value[start..]
                    .chars()
                    .filter(|character| !character.is_whitespace());
                marker
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .all(|expected| {
                        label
                            .next()
                            .is_some_and(|actual| actual.eq_ignore_ascii_case(&expected))
                    })
            })
    })
}

fn challenge_text_window_matches(
    buffer: &[char; CHALLENGE_TEXT_WINDOW],
    cursor: usize,
    retained: usize,
    marker: &str,
) -> bool {
    let marker_length = marker
        .chars()
        .filter(|character| !character.is_whitespace())
        .count();
    if marker_length == 0 || marker_length > retained {
        return false;
    }
    let start = (cursor + CHALLENGE_TEXT_WINDOW - marker_length) % CHALLENGE_TEXT_WINDOW;
    let mut offset = 0;
    marker
        .chars()
        .filter(|character| !character.is_whitespace())
        .all(|expected| {
            let matches =
                buffer[(start + offset) % CHALLENGE_TEXT_WINDOW].eq_ignore_ascii_case(&expected);
            offset += 1;
            matches
        })
}

fn inert_text_element(element: ElementRef<'_>) -> bool {
    element.value().attr("inert").is_some()
}

fn scan_active_text(element: ElementRef<'_>) -> ActiveTextFacts {
    let mut buffer = ['\0'; CHALLENGE_TEXT_WINDOW];
    let mut cursor = 0;
    let mut retained = 0;
    let mut facts = ActiveTextFacts::default();
    crate::html::visit_active_text(element, inert_text_element, |text| {
        for character in text.chars().filter(|character| !character.is_whitespace()) {
            buffer[cursor] = character;
            cursor = (cursor + 1) % CHALLENGE_TEXT_WINDOW;
            retained = (retained + 1).min(CHALLENGE_TEXT_WINDOW);
            for (index, marker) in ACTIVE_TEXT_MARKERS.iter().enumerate() {
                if challenge_text_window_matches(&buffer, cursor, retained, marker) {
                    facts.0 |= 1_u32 << index;
                }
            }
        }
        false
    });
    facts
}

/// Structural/protocol markers retain their active-challenge meaning.
fn challenge_control_marker(control: ElementRef<'_>) -> bool {
    let element = control.value();
    if element.name() == "input"
        && element
            .attr("type")
            .is_some_and(|kind| kind.eq_ignore_ascii_case("hidden"))
    {
        return false;
    }
    ["name", "id", "class", "autocomplete"]
        .into_iter()
        .filter_map(|name| element.attr(name))
        .any(challenge_marker_matches)
}

/// Read source cue attributes, button labels and button-like input values. Button
/// descendants use the shared active-text walk, which joins split text nodes
/// while excluding script/style/template/noscript payloads. The extracted text
/// is transient and is never added to form state or rejected-control metadata.
fn challenge_control_label_marker(
    control: ElementRef<'_>,
    text_subtree_scans: &mut usize,
) -> Result<bool, Error> {
    let element = control.value();
    let one_time_code = element.attr("autocomplete").is_some_and(|value| {
        value
            .split_ascii_whitespace()
            .any(|token| token.eq_ignore_ascii_case("one-time-code"))
    });
    if labelable_control(control) && one_time_code {
        return Ok(true);
    }
    if labelable_control(control)
        && ["aria-label", "placeholder", "title"]
            .into_iter()
            .filter_map(|name| element.attr(name))
            .any(challenge_label_marker_matches)
    {
        return Ok(true);
    }
    if element.name() == "button" {
        *text_subtree_scans += 1;
        if *text_subtree_scans > MAX_LOGIN_TEXT_SUBTREE_SCANS {
            return Err(unavailable());
        }
        return Ok(scan_active_text(control).has_challenge_marker());
    }
    if element.name() == "input"
        && element.attr("type").is_some_and(|kind| {
            ["submit", "button", "reset"]
                .iter()
                .any(|allowed| kind.eq_ignore_ascii_case(allowed))
        })
    {
        return Ok(element
            .attr("value")
            .is_some_and(challenge_label_marker_matches));
    }
    Ok(false)
}

fn labelable_control(control: ElementRef<'_>) -> bool {
    if !crate::html::is_html_element(control) {
        return false;
    }
    match control.value().name() {
        "button" | "meter" | "output" | "progress" | "select" | "textarea" => true,
        "input" => !control
            .value()
            .attr("type")
            .is_some_and(|kind| kind.eq_ignore_ascii_case("hidden")),
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LoginSourceScope {
    CredentialForm,
    FinalResponse,
}

#[derive(Clone, Copy)]
enum CredentialRole {
    Username,
    Password,
}

#[derive(Clone, Copy)]
struct CredentialDirectionEntry {
    field_index: usize,
    role: CredentialRole,
}

#[derive(Default)]
struct ParsedLoginForm {
    fields: Vec<(String, String)>,
    credential_direction_entries: Vec<CredentialDirectionEntry>,
    action: String,
    method: String,
    active_text_facts: ActiveTextFacts,
    has_password_control: bool,
    has_active_challenge_control: bool,
    has_unverified_challenge_text: bool,
    interaction_reason: Option<&'static str>,
    first_rejected_control: Option<RejectedControl>,
}

/// Only fixed structural labels: never retain unknown names, values or action URLs.
#[derive(Serialize)]
struct RejectedControl {
    tag: &'static str,
    name: Option<&'static str>,
    input_type: &'static str,
    required: bool,
    checked: bool,
    inline_hidden_or_inert: bool,
    own_inert: bool,
    reviewed_protocol_value: bool,
    challenge_marker: bool,
}

impl RejectedControl {
    fn observe(control: ElementRef<'_>, challenge_marker: bool) -> Self {
        let name = control.value().attr("name").map(|name| match name {
            "username" => "username",
            "password" => "password",
            "type" => "type",
            "execution" => "execution",
            "_eventId" => "_eventId",
            "submit" => "submit",
            _ => REDACTED_NAME,
        });
        let kind = control.value().attr("type").unwrap_or_else(|| {
            if control.value().name() == "button" {
                "submit"
            } else {
                "text"
            }
        });
        Self {
            tag: match control.value().name() {
                "button" => "button",
                "select" => "select",
                "textarea" => "textarea",
                _ => "input",
            },
            name,
            input_type: [
                "text", "password", "checkbox", "radio", "file", "hidden", "submit", "button",
                "reset", "email", "number", "tel", "search", "url",
            ]
            .into_iter()
            .find(|known| kind.eq_ignore_ascii_case(known))
            .unwrap_or("other"),
            required: control.value().attr("required").is_some(),
            checked: control.value().attr("checked").is_some(),
            inline_hidden_or_inert: element_is_inert(control),
            own_inert: control.value().attr("inert").is_some(),
            reviewed_protocol_value: reviewed_protocol_value_matches(control),
            challenge_marker,
        }
    }
}

/// CSS (including hidden attributes) cannot prove noninteraction without a
/// cascade. Structural inertness cannot be undone by stylesheet overrides.
fn structurally_inert(control: ElementRef<'_>) -> bool {
    std::iter::once(control)
        .chain(control.ancestors().filter_map(ElementRef::wrap))
        .any(|element| {
            crate::html::is_inert_context(element) || element.value().attr("inert").is_some()
        })
}

/// Keep the reviewed protocol comparison only as sanitized inspection metadata.
fn reviewed_protocol_value_matches(control: ElementRef<'_>) -> bool {
    let value = control.value().attr("value").unwrap_or("");
    match control.value().attr("name") {
        Some("type") => value == "username_password",
        Some("_eventId") => value == "submit",
        Some("submit") => value == "LOGIN",
        Some("execution") => {
            !value.is_empty()
                && value.len() <= MAX_FIELD_BYTES
                && !value.chars().any(char::is_control)
        }
        _ => false,
    }
}

/// Check only the reviewed source login submitter; never synthesize its value.
fn reviewed_login_submitter(control: ElementRef<'_>) -> bool {
    let element = control.value();
    crate::html::is_html_element(control)
        && element.name() == "input"
        && element
            .attr("type")
            .is_some_and(|kind| kind.eq_ignore_ascii_case("submit"))
        && element.attr("name") == Some("submit")
        && element.attr("value") == Some("LOGIN")
}

fn push_login_field(
    fields: &mut Vec<(String, String)>,
    field_bytes: &mut usize,
    name: &str,
    value: &str,
) -> Result<(), Error> {
    push_login_field_owned(fields, field_bytes, name, value.to_string())
}

fn push_login_field_owned(
    fields: &mut Vec<(String, String)>,
    field_bytes: &mut usize,
    name: &str,
    value: String,
) -> Result<(), Error> {
    if name.len() > 256 || value.len() > MAX_FIELD_BYTES || fields.len() >= MAX_FORM_FIELDS {
        return Err(unavailable());
    }
    *field_bytes = (*field_bytes)
        .checked_add(name.len())
        .and_then(|total| total.checked_add(value.len()))
        .ok_or_else(unavailable)?;
    if *field_bytes > MAX_FORM_BYTES {
        return Err(unavailable());
    }
    fields.push((name.to_string(), value));
    Ok(())
}

fn credential_role(name: &str) -> Option<CredentialRole> {
    if name.eq_ignore_ascii_case("username") {
        Some(CredentialRole::Username)
    } else if name.eq_ignore_ascii_case("password") {
        Some(CredentialRole::Password)
    } else {
        None
    }
}

fn is_auto_directionality_form_control(control: ElementRef<'_>) -> bool {
    match control.value().name() {
        "textarea" => true,
        "input" => !control.value().attr("type").is_some_and(|kind| {
            [
                "checkbox",
                "radio",
                "file",
                "image",
                "number",
                "range",
                "color",
                "date",
                "datetime-local",
                "month",
                "week",
                "time",
            ]
            .iter()
            .any(|ineligible| kind.eq_ignore_ascii_case(ineligible))
        }),
        _ => false,
    }
}

fn form_control_dirname(control: ElementRef<'_>) -> Option<&str> {
    if !is_auto_directionality_form_control(control) {
        return None;
    }
    control
        .value()
        .attr("dirname")
        .filter(|dirname| !dirname.is_empty())
}

fn directionality_attribute_state(element: ElementRef<'_>) -> Option<&'static str> {
    if !crate::html::is_html_element(element) {
        return None;
    }
    let direction = element.value().attr("dir")?;
    if direction.eq_ignore_ascii_case("ltr") {
        Some("ltr")
    } else if direction.eq_ignore_ascii_case("rtl") {
        Some("rtl")
    } else if direction.eq_ignore_ascii_case("auto") {
        Some("auto")
    } else {
        None
    }
}

fn first_strong_direction(value: &str) -> Option<&'static str> {
    use icu_properties::props::BidiClass;

    let bidi_classes = icu_properties::CodePointMapData::<BidiClass>::new();
    value
        .chars()
        .find_map(|character| match bidi_classes.get(character) {
            BidiClass::LeftToRight => Some("ltr"),
            BidiClass::RightToLeft | BidiClass::ArabicLetter => Some("rtl"),
            _ => None,
        })
}

fn auto_directionality(
    element: ElementRef<'_>,
    form_control_value: Option<&str>,
) -> Option<&'static str> {
    if is_auto_directionality_form_control(element) {
        let value = form_control_value.unwrap_or("");
        return if value.is_empty() {
            None
        } else {
            Some(first_strong_direction(value).unwrap_or("ltr"))
        };
    }

    let root_id = element.id();
    let mut direction = None;
    crate::html::visit_text(
        element,
        |descendant| {
            descendant.id() != root_id
                && crate::html::is_html_element(descendant)
                && (matches!(
                    descendant.value().name(),
                    "bdi" | "script" | "style" | "template" | "textarea"
                ) || directionality_attribute_state(descendant).is_some())
        },
        |text| {
            direction = first_strong_direction(text);
            direction.is_some()
        },
    );
    direction
}

fn control_directionality(control: ElementRef<'_>, value: &str) -> &'static str {
    for element in std::iter::once(control).chain(control.ancestors().filter_map(ElementRef::wrap))
    {
        if let Some(direction) = directionality_attribute_state(element) {
            return if direction == "auto" {
                auto_directionality(element, (element.id() == control.id()).then_some(value))
                    .unwrap_or("ltr")
            } else {
                direction
            };
        }
        if crate::html::is_html_element(element) {
            if element.id() == control.id()
                && element.value().name() == "input"
                && element
                    .value()
                    .attr("type")
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("tel"))
            {
                return "ltr";
            }
            if element.value().name() == "bdi" {
                return auto_directionality(element, None).unwrap_or("ltr");
            }
        }
    }
    "ltr"
}

fn push_login_control_field(
    fields: &mut Vec<(String, String)>,
    field_bytes: &mut usize,
    credential_direction_entries: &mut Vec<CredentialDirectionEntry>,
    control: ElementRef<'_>,
    name: &str,
    value: std::borrow::Cow<'_, str>,
) -> Result<bool, Error> {
    let dirname = form_control_dirname(control);
    let credential_collision = dirname.and_then(credential_role).is_some();
    let direction = if credential_collision {
        None
    } else {
        dirname.map(|_| control_directionality(control, value.as_ref()))
    };
    let dynamic_role =
        if direction.is_some() && directionality_attribute_state(control) == Some("auto") {
            credential_role(name)
        } else {
            None
        };

    match value {
        std::borrow::Cow::Borrowed(value) => {
            push_login_field(fields, field_bytes, name, value)?;
        }
        std::borrow::Cow::Owned(value) => {
            push_login_field_owned(fields, field_bytes, name, value)?;
        }
    }
    if let (Some(dirname), Some(direction)) = (dirname, direction) {
        let field_index = fields.len();
        push_login_field(fields, field_bytes, dirname, direction)?;
        if let Some(role) = dynamic_role {
            credential_direction_entries.push(CredentialDirectionEntry { field_index, role });
        }
    }
    Ok(credential_collision)
}

fn option_is_disabled(option: ElementRef<'_>) -> bool {
    option.value().attr("disabled").is_some()
        || option
            .parent()
            .and_then(ElementRef::wrap)
            .is_some_and(|parent| {
                crate::html::is_html_element(parent)
                    && parent.value().name() == "optgroup"
                    && parent.value().attr("disabled").is_some()
            })
}

fn option_value(option: ElementRef<'_>) -> String {
    if let Some(value) = option.value().attr("value") {
        return value.to_string();
    }
    let mut value = String::new();
    let mut pending_space = false;
    crate::html::visit_active_text(
        option,
        |_| false,
        |text| {
            for character in text.chars() {
                if matches!(character, ' ' | '\t' | '\n' | '\r' | '\u{000C}') {
                    pending_space |= !value.is_empty();
                } else {
                    if pending_space {
                        value.push(' ');
                        pending_space = false;
                    }
                    value.push(character);
                }
            }
            false
        },
    );
    value
}

/// The source size is an unsigned integer prefix; the reflected DOM getter
/// can report zero for large sizes that still suppress implicit selection.
fn select_has_implicit_default(control: ElementRef<'_>) -> bool {
    let size = control.value().attr("size").and_then(|value| {
        let value = value.trim_start_matches(['\t', '\n', '\u{000c}', '\r', ' ']);
        let value = value.strip_prefix('+').unwrap_or(value);
        let end = value
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(value.len());
        value[..end].parse::<u32>().ok()
    });
    size.unwrap_or(0) <= 1
}

// Page membership and disabled-state facts remain available when credential
// form admission fails. Both projections borrow one bounded source parse.
struct LoginDocument<'a> {
    document: &'a scraper::Html,
    form_associations: &'a [form_source::FormAssociation],
    controls: Selector,
    first_elements_by_id: HashMap<&'a str, ElementRef<'a>>,
    disabled_fieldsets: HashMap<NodeId, Option<NodeId>>,
    has_active_base_href: bool,
    active_text_facts: ActiveTextFacts,
}

impl<'a> LoginDocument<'a> {
    fn new(
        document: &'a scraper::Html,
        form_associations: &'a [form_source::FormAssociation],
    ) -> Result<Self, Error> {
        let all_elements = Selector::parse("*").map_err(|_| invalid())?;
        let mut has_active_base_href = false;
        for (index, element) in document.select(&all_elements).enumerate() {
            if index >= MAX_LOGIN_DOM_ELEMENTS
                || element.ancestors().take(MAX_LOGIN_DOM_DEPTH + 1).count() > MAX_LOGIN_DOM_DEPTH
            {
                return Err(unavailable());
            }
            // Document membership, not prose inertness, decides base activity:
            // an HTML base beneath a foreign script/style ancestor is still a
            // live document member (its integration point keeps it in the tree)
            // and changes the form's effective action, exactly like the bases
            // `first_elements_by_id` admits below. Only actual HTML template
            // contents are a separate fragment.
            if crate::html::is_html_element(element)
                && element.value().name() == "base"
                && element.value().attr("href").is_some()
                && !element
                    .ancestors()
                    .filter_map(ElementRef::wrap)
                    .any(|ancestor| {
                        crate::html::is_html_element(ancestor)
                            && ancestor.value().name() == "template"
                    })
            {
                has_active_base_href = true;
            }
            if crate::html::is_html_element(element)
                && element.value().name() == "template"
                && element.value().attr("shadowrootmode").is_some_and(|mode| {
                    let mode = mode.trim_matches(['\t', '\n', '\u{000c}', '\r', ' ']);
                    mode.eq_ignore_ascii_case("open") || mode.eq_ignore_ascii_case("closed")
                })
                && !element
                    .ancestors()
                    .filter_map(ElementRef::wrap)
                    .any(|ancestor| {
                        crate::html::is_html_element(ancestor)
                            && ancestor.value().name() == "template"
                    })
            {
                // HTML parsing does not attach declarative shadow roots. Their
                // contents can be active in the browser, so no document facts are
                // trusted until a shadow-aware parser exists. Ordinary HTML
                // template contents remain inert; foreign templates do not.
                return Err(unavailable());
            }
        }
        let active_text_facts = scan_active_text(document.root_element());
        let controls = Selector::parse("input, select, textarea, button").map_err(|_| invalid())?;
        let mut first_elements_by_id = HashMap::new();
        let document_root = document.root_element();
        for element in std::iter::once(document_root)
            .chain(document_root.descendants().filter_map(ElementRef::wrap))
        {
            // Text inactivity does not remove document-tree ID membership. Only
            // HTML template contents belong to a separate document fragment.
            if element
                .ancestors()
                .filter_map(ElementRef::wrap)
                .any(|ancestor| {
                    crate::html::is_html_element(ancestor) && ancestor.value().name() == "template"
                })
            {
                continue;
            }
            if let Some(id) = element.value().attr("id")
                && !id.is_empty()
            {
                first_elements_by_id.entry(id).or_insert(element);
            }
        }
        let fieldsets = Selector::parse("fieldset[disabled]").map_err(|_| invalid())?;
        let disabled_fieldsets: HashMap<_, _> = document
            .select(&fieldsets)
            .filter(|fieldset| crate::html::is_html_element(*fieldset))
            .map(|fieldset| {
                let first_legend = fieldset
                    .children()
                    .filter_map(ElementRef::wrap)
                    .find(|child| {
                        crate::html::is_html_element(*child) && child.value().name() == "legend"
                    });
                (fieldset.id(), first_legend.map(|legend| legend.id()))
            })
            .collect();
        Ok(Self {
            document,
            form_associations,
            controls,
            first_elements_by_id,
            disabled_fieldsets,
            has_active_base_href,
            active_text_facts,
        })
    }

    fn effectively_disabled(&self, control: ElementRef<'_>) -> bool {
        if control.value().attr("disabled").is_some() {
            return true;
        }
        let mut legend_ancestors = HashSet::new();
        for ancestor in control.ancestors().filter_map(ElementRef::wrap) {
            if ancestor.value().name() == "legend" {
                legend_ancestors.insert(ancestor.id());
            }
            if let Some(first_legend) = self.disabled_fieldsets.get(&ancestor.id())
                && !first_legend.is_some_and(|legend| legend_ancestors.contains(&legend))
            {
                return true;
            }
        }
        false
    }

    fn has_active_challenge_control(&self) -> bool {
        self.document.select(&self.controls).any(|control| {
            crate::html::is_html_element(control)
                && !crate::html::inert_element(control)
                && challenge_control_marker(control)
                && !element_is_inert(control)
                && !self.effectively_disabled(control)
        })
    }
}

/// Collect the selected credential form, or inspect all final-response controls
/// without requiring the original credential/execution form to remain present.
fn login_fields(html: &str, scope: LoginSourceScope) -> Result<ParsedLoginForm, Error> {
    let (document, form_associations) = form_source::parse_document(html);
    let source = LoginDocument::new(&document, &form_associations)?;
    login_document_fields(&source, scope)
}

fn login_document_fields(
    source: &LoginDocument<'_>,
    scope: LoginSourceScope,
) -> Result<ParsedLoginForm, Error> {
    let document = source.document;
    let form_associations = source.form_associations;
    let controls = &source.controls;
    let first_elements_by_id = &source.first_elements_by_id;
    let active_text_facts = source.active_text_facts;
    let has_unverified_challenge_text = active_text_facts.has_challenge_marker();
    let label_selector = Selector::parse("label").map_err(|_| invalid())?;
    let document_root = document.root_element();

    let form = match scope {
        LoginSourceScope::CredentialForm => {
            // Include external associations and disabled controls later rejected
            // as missing successful credential state.
            let form_selector = Selector::parse("form").map_err(|_| invalid())?;
            let forms: Vec<_> = document
                .select(&form_selector)
                .filter(|form| {
                    crate::html::is_html_element(*form) && !crate::html::inert_element(*form)
                })
                .collect();
            let mut form_indices_by_node = HashMap::new();
            for (index, form) in forms.iter().copied().enumerate() {
                form_indices_by_node.insert(form.id(), index);
            }
            let mut form_roles = vec![(false, false); forms.len()];
            for control in document.select(controls) {
                if !crate::html::is_html_element(control)
                    || crate::html::inert_element(control)
                    || !matches!(control.value().name(), "input" | "select" | "textarea")
                {
                    continue;
                }
                let name = control.value().attr("name");
                let has_execution = name == Some("execution");
                let has_password = name.is_some_and(|name| name.eq_ignore_ascii_case("password"));
                if !has_execution && !has_password {
                    continue;
                }
                if let Some(owner) = form_control_owner(control, first_elements_by_id)
                    && let Some(&index) = form_indices_by_node.get(&owner.id())
                {
                    form_roles[index].0 |= has_execution;
                    form_roles[index].1 |= has_password;
                }
            }
            let mut selected = None;
            for (index, (has_execution, has_password)) in form_roles.iter().enumerate() {
                if *has_execution && *has_password {
                    if selected.is_some() {
                        return Err(invalid());
                    }
                    selected = Some(index);
                }
            }
            let form = forms[selected.ok_or_else(invalid)?];
            // Parser associations are historical source facts: html5ever may
            // later reparent either node during table adoption-agency steps,
            // so the callback is never used as an unconditional final owner.
            // It is only trusted when it exactly matches the final ownership
            // admission can represent (explicit first-document-ID reference,
            // or unambiguous nearest ancestor form); any other surviving
            // association selected for this form is refused below.
            Some(form)
        }
        LoginSourceScope::FinalResponse => None,
    };
    for association in form_associations {
        let (Some(control), Some(owner)) = (
            document
                .tree
                .get(association.control)
                .and_then(ElementRef::wrap),
            document
                .tree
                .get(association.form)
                .and_then(ElementRef::wrap),
        ) else {
            // The parser recorded a node that the finished document no
            // longer holds; final ownership cannot be reconstructed.
            return Err(unavailable());
        };
        if crate::html::is_html_element(control) && control.value().name() == "img" {
            // Historical image/form associations do not create submission
            // entries. Unlike listed controls, an img's form attribute cannot
            // override ownership, so it cannot veto this submission set.
            continue;
        }
        if scope == LoginSourceScope::CredentialForm && form.is_some_and(|form| form == owner) {
            let representable = form_control_owner(control, first_elements_by_id)
                .is_some_and(|current| current == owner);
            if !representable {
                // The source parser associated this control with the selected
                // form, but neither its explicit reference nor its final
                // ancestry identifies that form; the effective submission set
                // cannot be reconstructed from the finished DOM.
                return Err(unavailable());
            }
        } else if scope == LoginSourceScope::FinalResponse
            && form_control_owner(control, first_elements_by_id)
                .is_some_and(|current| current == owner)
        {
            // A control this scope actually collects is still parser-owned by
            // the recorded form; the matching final owner is representable.
        } else {
            // Parser association involving forms this scope does not select
            // or collect cannot change the admitted submission set.
        }
    }
    if form.is_some() && source.has_active_base_href {
        // The request builder has no source-base input; do not resolve relative
        // form actions against page.url while an active HTML base can override it.
        return Err(invalid());
    }
    let (action, method) = if let Some(form) = form {
        let Some(action) = form.value().attr("action") else {
            return Err(invalid());
        };
        if action.len() > MAX_FIELD_BYTES || action.chars().any(char::is_control) {
            return Err(invalid());
        }
        if form.value().attr("enctype").is_some_and(|encoding| {
            encoding.eq_ignore_ascii_case("multipart/form-data")
                || encoding.eq_ignore_ascii_case("text/plain")
        }) {
            // `send` constructs only application/x-www-form-urlencoded bodies.
            return Err(invalid());
        }
        (
            action.to_string(),
            form.value()
                .attr("method")
                .unwrap_or("get")
                .to_ascii_lowercase(),
        )
    } else {
        (String::new(), String::new())
    };

    let mut associated_challenge_labels = HashSet::new();
    let mut text_subtree_scans = 0;
    for label in document.select(&label_selector) {
        if !crate::html::is_html_element(label) {
            continue;
        }
        let target = if let Some(id) = label.value().attr("for") {
            first_elements_by_id
                .get(id)
                .copied()
                .filter(|control| labelable_control(*control))
        } else {
            label
                .descendants()
                .filter_map(ElementRef::wrap)
                .find(|control| {
                    !crate::html::inert_element(*control) && labelable_control(*control)
                })
        };
        if let Some(target) = target
            && !source.effectively_disabled(target)
            && !structurally_inert(label)
        {
            text_subtree_scans += 1;
            if text_subtree_scans > MAX_LOGIN_TEXT_SUBTREE_SCANS {
                return Err(unavailable());
            }
            if scan_active_text(label).has_challenge_marker() {
                associated_challenge_labels.insert(target.id());
            }
        }
    }

    // Radio checkedness follows source parsing order even if foster parenting
    // changes tree order; successful-entry serialization below uses tree order.
    let mut checked_radios = HashMap::new();
    if let Some(form) = form {
        for control in document.select(controls) {
            if crate::html::is_html_element(control)
                && !crate::html::inert_element(control)
                && control.value().name() == "input"
                && control
                    .value()
                    .attr("type")
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("radio"))
                && control.value().attr("checked").is_some()
                && let Some(name) = control.value().attr("name").filter(|name| !name.is_empty())
                && form_control_owner(control, first_elements_by_id) == Some(form)
            {
                checked_radios.insert(name, control.id());
            }
        }
    }

    let option_selector = form
        .map(|_| Selector::parse("option").map_err(|_| invalid()))
        .transpose()?;
    let mut fields = Vec::new();
    let mut field_bytes = 0usize;
    let mut credential_direction_entries = Vec::new();
    let mut has_active_challenge_control = false;
    let mut username_seen = false;
    let mut password_seen = false;
    let mut interaction_reason = None;
    let mut first_rejected_control = None;
    let mut reviewed_submitter_seen = false;
    for control in document_root.select(controls) {
        if !crate::html::is_html_element(control) {
            continue;
        }
        if form.is_none() && !password_seen && !structurally_inert(control) {
            let element = control.value();
            password_seen = element
                .attr("name")
                .is_some_and(|name| name.eq_ignore_ascii_case("password"))
                || (element.name() == "input"
                    && element
                        .attr("type")
                        .is_some_and(|kind| kind.eq_ignore_ascii_case("password")));
        }
        if crate::html::inert_element(control) || source.effectively_disabled(control) {
            continue;
        }
        let owned_by_selected_form =
            form.is_none_or(|form| form_control_owner(control, first_elements_by_id) == Some(form));

        let challenge = challenge_control_marker(control);
        has_active_challenge_control |= challenge && !element_is_inert(control);
        let control_label_challenge = if challenge {
            false
        } else {
            challenge_control_label_marker(control, &mut text_subtree_scans)?
        };
        let label_challenge = !challenge
            && (control_label_challenge || associated_challenge_labels.contains(&control.id()));
        if (challenge || label_challenge)
            && !structurally_inert(control)
            && interaction_reason.is_none()
        {
            interaction_reason = Some("unreviewed_challenge_control");
            first_rejected_control = Some(RejectedControl::observe(
                control,
                challenge || label_challenge,
            ));
        }

        if form.is_none() || !owned_by_selected_form {
            continue;
        }
        let name = control.value().attr("name").filter(|name| !name.is_empty());
        let element = control.value();
        let kind = element.attr("type").unwrap_or("text");
        let name = match name {
            Some(name) => name,
            None => continue,
        };
        let credential_reason = if name.eq_ignore_ascii_case("username") {
            let duplicate = username_seen;
            username_seen = true;
            if duplicate {
                Some("duplicate_username_control")
            } else if element.name() != "input" || !kind.eq_ignore_ascii_case("text") {
                Some("wrong_username_type")
            } else {
                None
            }
        } else if name.eq_ignore_ascii_case("password") {
            let duplicate = password_seen;
            password_seen = true;
            if duplicate {
                Some("duplicate_password_control")
            } else if element.name() != "input" || !kind.eq_ignore_ascii_case("password") {
                Some("wrong_password_type")
            } else {
                None
            }
        } else {
            None
        };
        if let Some(reason) = credential_reason
            && interaction_reason.is_none()
        {
            interaction_reason = Some(reason);
            first_rejected_control = Some(RejectedControl::observe(
                control,
                challenge || label_challenge,
            ));
        }

        match element.name() {
            "input" => {
                if kind.eq_ignore_ascii_case("button")
                    || kind.eq_ignore_ascii_case("reset")
                    || kind.eq_ignore_ascii_case("image")
                    || kind.eq_ignore_ascii_case("file")
                {
                    continue;
                }
                if kind.eq_ignore_ascii_case("submit") {
                    if reviewed_login_submitter(control) {
                        if ["formaction", "formmethod", "formenctype"]
                            .into_iter()
                            .any(|name| element.attr(name).is_some())
                        {
                            return Err(invalid());
                        }
                        if reviewed_submitter_seen {
                            return Err(invalid());
                        }
                        reviewed_submitter_seen = true;
                        let value = input_submission_value(control, "submit")?;
                        let collision = push_login_control_field(
                            &mut fields,
                            &mut field_bytes,
                            &mut credential_direction_entries,
                            control,
                            name,
                            value,
                        )?;
                        if collision && interaction_reason.is_none() {
                            interaction_reason = Some("credential_dirname_collision");
                            first_rejected_control = Some(RejectedControl::observe(
                                control,
                                challenge || label_challenge,
                            ));
                        }
                    }
                    continue;
                }
                let checkbox = kind.eq_ignore_ascii_case("checkbox");
                let radio = kind.eq_ignore_ascii_case("radio");
                if (checkbox && element.attr("checked").is_none())
                    || (radio && checked_radios.get(name) != Some(&control.id()))
                {
                    continue;
                }
                let value = if checkbox || radio {
                    std::borrow::Cow::Borrowed(element.attr("value").unwrap_or("on"))
                } else {
                    input_submission_value(control, kind)?
                };
                let collision = push_login_control_field(
                    &mut fields,
                    &mut field_bytes,
                    &mut credential_direction_entries,
                    control,
                    name,
                    value,
                )?;
                if collision && interaction_reason.is_none() {
                    interaction_reason = Some("credential_dirname_collision");
                    first_rejected_control = Some(RejectedControl::observe(
                        control,
                        challenge || label_challenge,
                    ));
                }
            }
            "textarea" => {
                let source = control.text().collect::<String>();
                if !source.is_empty()
                    && element
                        .attr("wrap")
                        .is_some_and(|wrap| wrap.eq_ignore_ascii_case("hard"))
                {
                    // Hard-wrap submission text depends on rendered line
                    // breaks, not just cols or the API/source text value.
                    if interaction_reason.is_none() {
                        interaction_reason = Some("layout_dependent_textarea");
                        first_rejected_control = Some(RejectedControl::observe(
                            control,
                            challenge || label_challenge,
                        ));
                    }
                    continue;
                }
                let value = normalize_textarea_value(&source);
                let collision = push_login_control_field(
                    &mut fields,
                    &mut field_bytes,
                    &mut credential_direction_entries,
                    control,
                    name,
                    std::borrow::Cow::Owned(value),
                )?;
                if collision && interaction_reason.is_none() {
                    interaction_reason = Some("credential_dirname_collision");
                    first_rejected_control = Some(RejectedControl::observe(
                        control,
                        challenge || label_challenge,
                    ));
                }
            }
            "select" => {
                let option_selector = option_selector.as_ref().ok_or_else(invalid)?;
                if element.attr("multiple").is_some() {
                    for option in control
                        .select(option_selector)
                        .filter(|option| !crate::html::inert_element(*option))
                    {
                        if option.value().attr("selected").is_some() && !option_is_disabled(option)
                        {
                            let value = option_value(option);
                            push_login_field_owned(&mut fields, &mut field_bytes, name, value)?;
                        }
                    }
                } else {
                    let mut selected_option = None;
                    let mut first_enabled_option = None;
                    for option in control
                        .select(option_selector)
                        .filter(|option| !crate::html::inert_element(*option))
                    {
                        if first_enabled_option.is_none() && !option_is_disabled(option) {
                            first_enabled_option = Some(option);
                        }
                        if option.value().attr("selected").is_some() {
                            selected_option = Some(option);
                        }
                    }
                    let selected_option = selected_option.or_else(|| {
                        if select_has_implicit_default(control) {
                            first_enabled_option
                        } else {
                            None
                        }
                    });
                    if let Some(option) = selected_option
                        && !option_is_disabled(option)
                    {
                        let value = option_value(option);
                        push_login_field_owned(&mut fields, &mut field_bytes, name, value)?;
                    }
                }
            }
            _ => {}
        }
    }
    if form.is_some() && interaction_reason.is_none() && (!username_seen || !password_seen) {
        interaction_reason = Some(if !username_seen {
            "missing_username_control"
        } else {
            "missing_password_control"
        });
    }
    Ok(ParsedLoginForm {
        fields,
        credential_direction_entries,
        action,
        method,
        active_text_facts,
        has_password_control: password_seen,
        has_active_challenge_control,
        has_unverified_challenge_text,
        interaction_reason,
        first_rejected_control,
    })
}

/// Never omit an extra interactive step from the reviewed password flow.
/// A hidden captcha container alone is not an interactive control.
fn requires_challenge(fields: &ParsedLoginForm) -> bool {
    fields.has_active_challenge_control
}

fn requires_interaction_review(fields: &ParsedLoginForm) -> bool {
    fields.interaction_reason.is_some() || fields.has_unverified_challenge_text
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
    SafetyObservation,
    ScopedCookieUnusable,
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
            Self::SafetyObservation => "cached_safety_observation",
            Self::ScopedCookieUnusable => "scoped_cookie_unusable",
            Self::UnsafeInteraction => "unreviewed_login_interaction",
            Self::CredentialRejected => "credential_rejected",
            Self::ServiceInvalid => "service_parameter_rejected",
            Self::TicketRejected => "single_sign_on_ticket_rejected",
            Self::IdentityUnverified => "application_identity_unverified",
            Self::Unknown => "unclassified",
        }
    }
}

fn classify(fields: &ParsedLoginForm) -> FailureClass {
    if requires_challenge(fields) {
        return FailureClass::Challenge;
    }
    if requires_interaction_review(fields) {
        return FailureClass::UnsafeInteraction;
    }
    let text = fields.active_text_facts;
    if (text.contains(ACTIVE_TEXT_PASSWORD) && text.intersects(ACTIVE_TEXT_CREDENTIAL_ERRORS))
        || text.intersects(ACTIVE_TEXT_CREDENTIAL_MESSAGES)
    {
        return FailureClass::CredentialRejected;
    }
    if text.contains(ACTIVE_TEXT_SERVICE) && text.intersects(ACTIVE_TEXT_SERVICE_ERRORS) {
        return FailureClass::ServiceInvalid;
    }
    if text.contains(ACTIVE_TEXT_TICKET) && text.intersects(ACTIVE_TEXT_TICKET_ERRORS) {
        return FailureClass::TicketRejected;
    }
    FailureClass::Unknown
}

fn session_directory() -> Result<File, Error> {
    let home = crate::governor::identity_home().map_err(|_| unavailable())?;
    let _home = crate::governor::open_directory(&home, false, false).map_err(|_| unavailable())?;
    crate::governor::open_directory(&home.join(SESSION_DIRECTORY), true, true)
        .map_err(|_| unavailable())
}

/// Preserve acquired cookie restrictions; never persist single sign-on
/// cookies. Version 3 additionally retains the canonical declared domain of
/// narrowed cookies for their identity.
fn store_session(directory: &File, fingerprint: &str, jar: &Jar) -> Result<(), Error> {
    let cookies: Vec<&Cookie> = jar
        .cookies
        .iter()
        .filter(|cookie| classroom_scope(&cookie.scope))
        .collect();
    if cookies.is_empty() || cookies.len() > MAX_COOKIE_COUNT {
        return Err(unavailable());
    }
    if cookies.iter().any(|cookie| {
        !valid_cookie_prefix(
            &cookie.name,
            cookie.secure,
            cookie.http_only,
            cookie.host_only,
            cookie.path_explicit,
            &cookie.path,
        )
    }) {
        return Err(unavailable());
    }
    let bytes = Zeroizing::new(
        serde_json::to_vec(&StoredSessionRef {
            version: 3,
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
/// observed class and the host/status/allowlisted-route trail are kept; no
/// page text, header value or credential is written.
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

/// Validate durable governor state. No network request is made here and no
/// arming is required — authentication attempts are always admitted.
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
        "schema_version":1,"type":"classroom_session_resume","result":"no_latch_required",
        "network_request_performed":false,"cooldown_cleared":false,
        "instruction":"invoke recordings session --online with the typed LOGIN intent"
    }))
}

/// Read the pinned initial login flow only. Takes an authentication lease,
/// never submits credentials, and records challenge facts per request.
pub fn inspect(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: InspectInput<'_> = serde_json::from_str(input).map_err(|_| invalid())?;
    if request.intent != INSPECT_INTENT {
        return Err(invalid());
    }
    if !request.authorized {
        return Err(Error::new(
            "permission",
            "Explicit login-page inspection authorization is required.",
        ));
    }
    let url = pinned_login_url()?;
    let governor = Governor::open().map_err(|_| unavailable())?;
    let client = http_client()?;
    let mut jar = Jar::default();
    let mut lease = acquire_kind(&governor, RequestKind::Authentication)?;
    let mut trail = Trail::new();
    let page = match send(&mut lease, &client, &mut jar, &url, None, &mut trail, true) {
        Ok(page) => page,
        Err(error) => {
            if error.code == "governor_unavailable" { return Err(error); }
            finish_send_failure(lease, &error).map_err(|_| unavailable())?;
            return Err(error);
        }
    };
    finish_login_inspection(lease, &page, &url)
}

/// Diagnose why a reviewed login page is refused, without spending an
/// authentication attempt. It reads the pinned initial login page once,
/// submits no credential, stores no session and makes no credential
/// judgment. Clean responses do not latch the account; real challenges and
/// authentication-denial HTTP statuses retain normal governor handling.
/// It still takes a governed
/// request lease, so repeated diagnoses cannot outpace the shared request
/// policy the way an ungated read would.
pub fn diagnose(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: InspectInput<'_> = serde_json::from_str(input).map_err(|_| invalid())?;
    if request.intent != INSPECT_INTENT {
        return Err(invalid());
    }
    if !request.authorized {
        return Err(Error::new(
            "permission",
            "Explicit login-page diagnosis authorization is required.",
        ));
    }
    let url = pinned_login_url()?;
    let governor = Governor::open().map_err(|_| unavailable())?;
    let client = http_client()?;
    let mut jar = Jar::default();
    let mut lease = acquire_kind(&governor, RequestKind::Interactive)?;
    let mut trail = Trail::new();
    let page = match send(&mut lease, &client, &mut jar, &url, None, &mut trail, true) {
        Ok(page) => page,
        Err(error) => {
            if error.code == "governor_unavailable" { return Err(error); }
            finish_send_failure(lease, &error).map_err(|_| unavailable())?;
            return Err(error);
        }
    };
    let mut output = finish_login_inspection(lease, &page, &url)?;
    output["type"] = json!("classroom_login_diagnosis");
    output["network_request_performed"] = json!(true);
    Ok(output)
}

// Both credential-free readers keep their request lease through the complete
// page inspection, then settle only observed HTTP/challenge facts.
fn finish_login_inspection(
    lease: RequestLease<'_>,
    page: &Hop,
    expected: &Url,
) -> Result<Value, Error> {
    let mut output = login_inspection(page, expected);
    let challenged = page.challenge || output["active_challenge_control"].as_bool() == Some(true);
    lease.finish(crate::governor::Outcome::Http {
            status: page.status,
            retry_after: page.retry_after.as_deref(),
            challenge: challenged,
            network_failure: false,
        })
        .map_err(|_| unavailable())?;
    output["safety_latched"] = json!(false);
    Ok(output)
}

fn login_content_type_label(content_type: Option<&str>) -> Option<&'static str> {
    content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .and_then(|value| {
            [
                "text/html",
                "application/xhtml+xml",
                "application/json",
                "text/plain",
                "application/octet-stream",
            ]
            .into_iter()
            .find(|known| value.eq_ignore_ascii_case(known))
        })
}

fn final_response_fields(response: &Hop) -> Result<ParsedLoginForm, Error> {
    match login_content_type_label(response.content_type.as_deref()) {
        Some("text/html") => login_fields(&response.body, LoginSourceScope::FinalResponse),
        Some("application/json") => serde_json::from_str::<serde::de::IgnoredAny>(&response.body)
            .map(|_| ParsedLoginForm::default())
            .map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

fn unadmitted_response_outcome<'a>(
    status: u16,
    retry_after: Option<&'a str>,
    challenge: bool,
) -> crate::governor::Outcome<'a> {
    if (400..=599).contains(&status) || retry_after.is_some() && !(200..=299).contains(&status) {
        crate::governor::Outcome::Http {
            status,
            retry_after,
            challenge,
            network_failure: false,
        }
    } else if challenge {
        crate::governor::Outcome::CaptchaRequired
    } else {
        crate::governor::Outcome::CredentialRejected
    }
}

fn final_response_parse_failure<'a>(
    response: &'a Hop,
    parse_error: Error,
) -> (FailureClass, crate::governor::Outcome<'a>, Error) {
    let class = if response.challenge {
        FailureClass::Challenge
    } else {
        FailureClass::UnsafeInteraction
    };
    let outcome = unadmitted_response_outcome(
        response.status,
        response.retry_after.as_deref(),
        response.challenge,
    );
    let error = if response.challenge {
        challenge()
    } else {
        parse_error
    };
    (class, outcome, error)
}

fn identity_probe_failure<'a>(
    probe: &'a Hop,
    interaction_class: FailureClass,
) -> (FailureClass, crate::governor::Outcome<'a>, Error) {
    let challenge_present = probe.challenge || interaction_class == FailureClass::Challenge;
    let class = if challenge_present {
        FailureClass::Challenge
    } else {
        interaction_class
    };
    let outcome = unadmitted_response_outcome(
        probe.status,
        probe.retry_after.as_deref(),
        challenge_present,
    );
    let error = if challenge_present {
        challenge()
    } else {
        interaction_review_required()
    };
    (class, outcome, error)
}

fn login_inspection(page: &Hop, expected: &Url) -> Value {
    let mime = login_content_type_label(page.content_type.as_deref());
    let mut output = json!({
        "schema_version":1,"type":"classroom_login_inspection","result":"inspected",
        "http_status":page.status,"content_type":mime,"body_bytes":page.body.len(),
        "response_challenge":page.challenge,"redirected":page.redirected,
        "password_submissions":0,"session_stored":false,"safety_latched":false,
        "static_html_only":true,"active_challenge_control":false,
        "form":null,"fallback_reason":null
    });
    let unexpected_response = page.url != *expected || page.status != 200 || page.redirected;
    if unexpected_response {
        output["fallback_reason"] = json!("unexpected_login_response");
    }
    if !matches!(mime, Some("text/html")) {
        if !unexpected_response {
            output["fallback_reason"] = json!("unexpected_login_content_type");
        }
        return output;
    }
    let (document, form_associations) = form_source::parse_document(&page.body);
    let source = match LoginDocument::new(&document, &form_associations) {
        Ok(source) => source,
        Err(_) => {
            if !unexpected_response {
                output["fallback_reason"] = json!("login_form_not_admitted");
            }
            return output;
        }
    };
    if unexpected_response {
        // Response/form admission cannot erase independently observed page
        // challenges. MIME, DOM budgets and shadow-root admission still gate
        // every fact, and an unexpected response never admits credentials.
        output["active_challenge_control"] = json!(source.has_active_challenge_control());
        return output;
    }
    match login_document_fields(&source, LoginSourceScope::CredentialForm) {
        Ok(form) => {
            output["active_challenge_control"] = json!(form.has_active_challenge_control);
            output["form"] = json!({
                "interaction_review_required":requires_interaction_review(&form),
                "interaction_reason":form.interaction_reason,
                "first_rejected_control":form.first_rejected_control
            });
        }
        Err(_) => {
            output["active_challenge_control"] = json!(source.has_active_challenge_control());
            output["fallback_reason"] = json!("login_form_not_admitted");
        }
    }
    output
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
    if error.code == "governor_unavailable" {
        drop(lease);
        return error;
    }
    let (class, outcome) = match error.code {
        "safety_latched" => (FailureClass::SafetyObservation, crate::governor::Outcome::SafetyObserved),
        "scoped_cookie_unusable" => (FailureClass::ScopedCookieUnusable, outcome),
        _ => (class, outcome),
    };
    let receipt = session_directory().and_then(|directory| {
        write_attempt_receipt(
            &directory,
            fingerprint,
            class,
            trail,
            query_names(final_url),
        )
    });
    let finished = if error.code == "scoped_cookie_unusable" {
        lease.finish_without_request()
    } else {
        lease.finish(outcome)
    };
    if receipt.is_err() || finished.is_err() {
        unavailable()
    } else {
        error
    }
}

/// Preserve only the number of cookies in non-secret output, never their names.
fn classroom_cookie_names(cookie: &str) -> Vec<&'static str> {
    cookie
        .split(';')
        .filter_map(|pair| pair.split_once('=').map(|_| REDACTED_NAME))
        .collect()
}

fn login_form_values<'a>(
    form: &'a ParsedLoginForm,
    username: &'a str,
    password: &'a str,
) -> Vec<(&'a str, &'a str)> {
    let mut direction_entry_index = 0;
    form.fields
        .iter()
        .enumerate()
        .map(|(field_index, (name, value))| {
            if let Some(entry) = form
                .credential_direction_entries
                .get(direction_entry_index)
                .filter(|entry| entry.field_index == field_index)
            {
                direction_entry_index += 1;
                let credential = match entry.role {
                    CredentialRole::Username => username,
                    CredentialRole::Password => password,
                };
                return (
                    name.as_str(),
                    first_strong_direction(credential).unwrap_or("ltr"),
                );
            }
            let value = match credential_role(name) {
                Some(CredentialRole::Username) => username,
                Some(CredentialRole::Password) => password,
                None => value.as_str(),
            };
            (name.as_str(), value)
        })
        .collect()
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
    let page_mime = login_content_type_label(page.content_type.as_deref());
    if page.url != login_url
        || page.status != 200
        || page.body.trim().is_empty()
        || !matches!(page_mime, Some("text/html"))
        || page.challenge
        || page.redirected
        || page.retry_after.is_some()
    {
        let class = if page.challenge {
            FailureClass::Challenge
        } else if page_mime == Some("application/xhtml+xml") {
            FailureClass::UnsafeInteraction
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
            &page.url,
            outcome,
            error,
        ));
    }
    let fields = match login_fields(&page.body, LoginSourceScope::CredentialForm) {
        Ok(fields) => fields,
        Err(error) => {
            return Err(settle_failed_attempt(
                lease,
                &fingerprint,
                FailureClass::UnsafeInteraction,
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
    if !fields
        .fields
        .iter()
        .any(|(name, value)| name == "execution" && !value.is_empty())
    {
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
    if !fields.method.eq_ignore_ascii_case("post") {
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            FailureClass::UnsafeInteraction,
            &trail,
            &page.url,
            crate::governor::Outcome::CredentialRejected,
            invalid(),
        ));
    }
    let resolved = match page.url.join(&fields.action) {
        Ok(url) => url,
        Err(_) => {
            return Err(settle_failed_attempt(
                lease,
                &fingerprint,
                FailureClass::UnsafeInteraction,
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
            FailureClass::UnsafeInteraction,
            &trail,
            &page.url,
            crate::governor::Outcome::CredentialRejected,
            invalid(),
        ));
    }

    let form = login_form_values(
        &fields,
        request.username.as_ref(),
        request.password.as_str(),
    );

    let posted = send(
        &mut lease,
        &client,
        &mut jar,
        &resolved,
        Some((&form, &page.url)),
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
    let final_fields = match final_response_fields(&posted) {
        Ok(fields) => fields,
        Err(error) => {
            let (class, outcome, error) = final_response_parse_failure(&posted, error);
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
    };
    let final_challenge = posted.challenge || requires_challenge(&final_fields);
    let final_class = if final_challenge {
        FailureClass::Challenge
    } else {
        classify(&final_fields)
    };
    let final_success_shape = final_response_is_admissible(
        &final_host,
        posted.status,
        &posted.body,
        final_challenge,
        final_fields.has_unverified_challenge_text,
        posted.retry_after.as_deref(),
        final_class,
    );
    let classroom_header = jar.header(&probe_url);
    if !final_success_shape || classroom_header.is_none() || final_fields.has_password_control {
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
    if let Some(class) = identity_probe_interaction(&probe) {
        let (class, outcome, error) = identity_probe_failure(&probe, class);
        return Err(settle_failed_attempt(
            lease,
            &fingerprint,
            class,
            &trail,
            &probe.url,
            outcome,
            error,
        ));
    }
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
    let classroom_names = classroom_cookie_names(&cookie);
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
    lease
        .finish(crate::governor::Outcome::Success)
        .map_err(|_| unavailable())?;

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
    let mut cookie_identities = HashSet::new();
    if stored.version != 3
        || stored.cookies.is_empty()
        || stored.cookies.len() > MAX_COOKIE_COUNT
        || stored.cookies.iter().any(|cookie| {
            !valid_cookie_name(&cookie.name)
                || !valid_cookie_value(&cookie.value)
                || !classroom_scope(&cookie.scope)
                || !valid_cookie_prefix(
                    &cookie.name,
                    cookie.secure,
                    cookie.http_only,
                    cookie.host_only,
                    cookie.path_explicit,
                    &cookie.path,
                )
                || cookie.scope.domain().starts_with('.')
                || cookie
                    .scope
                    .domain()
                    .bytes()
                    .any(|byte| byte.is_ascii_uppercase())
                // A narrowed cookie's declared identity domain must be the
                // canonical declaration its setter could actually have
                // absorbed: a host-only flag, a platform delivery scope, an
                // in-family declaration, foreign or otherwise malformed
                // spelling all reject rather than guess an identity.
                || cookie
                    .declared_domain
                    .as_ref()
                    .is_some_and(|declared| {
                        cookie.host_only
                            || !matches!(cookie.scope, Scope::Host(_))
                            || declared.is_empty()
                            || declared.len() > 256
                            || declared.chars().any(char::is_control)
                            || declared.starts_with('.')
                            || declared.bytes().any(|byte| byte.is_ascii_uppercase())
                            || within_platform_family(declared)
                            || !domain_matches(declared, cookie.scope.domain())
                    })
                || !cookie.path.starts_with('/')
                || cookie.path.len() > MAX_COOKIE_PATH
                || cookie.path.chars().any(char::is_control)
                || cookie
                    .expiry
                    .is_some_and(|expiry| expiry.duration_since(UNIX_EPOCH).is_err())
                || !cookie_identities.insert((
                    cookie.name.as_str(),
                    cookie.identity_domain(),
                    cookie.path.as_str(),
                ))
        })
    {
        return Err(unavailable());
    }
    drop(cookie_identities);
    Ok(Jar {
        cookies: stored.cookies,
    })
}

pub fn schema() -> Value {
    json!({
        "inspect":{
            "input":{"type":"object","additionalProperties":false,"required":["authorized","intent"],"properties":{
                "authorized":{"const":true},"intent":{"const":INSPECT_INTENT}
            }},
            "output":{"type":"object","properties":{
                "type":{"const":"classroom_login_inspection"},"password_submissions":{"const":0},
                "session_stored":{"const":false},"safety_latched":{"type":"boolean"},
                "active_challenge_control":{"type":"boolean"}
            }}
        },
        "diagnose":{
            "input":{"type":"object","additionalProperties":false,"required":["authorized","intent"],"properties":{
                "authorized":{"const":true},"intent":{"const":INSPECT_INTENT}
            }},
            "output":{"type":"object","properties":{
                "type":{"const":"classroom_login_diagnosis"},"password_submissions":{"const":0},
                "session_stored":{"const":false},"network_request_performed":{"const":true},
                "safety_latched":{"type":"boolean"},
                "active_challenge_control":{"type":"boolean"},
                "form":{"type":["object","null"],"properties":{
                    "interaction_reason":{"type":["string","null"]}
                }}
            }}
        },
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

    #[test]
    fn overflowing_css_literals_are_finite_before_color_math() {
        assert_native_color_submissions(&[
            ("rgb(1e999 30 40)", "#ff1e28"),
            ("rgb(-1e999 30 40)", "#001e28"),
            ("rgb(calc(100 + 1e999 * 0) 30 40)", "#641e28"),
            ("rgb(calc(100 + 1e999 / 1e999) 30 40)", "#651e28"),
            ("rgb(calc(100 + 1e999 / 1e37) 30 40)", "#861e28"),
            ("rgb(calc(100 + 1e999 / 1e308) 30 40)", "#651e28"),
            ("rgb(calc(100 + 1e20 * 1e20 / 1e38) 30 40)", "#c81e28"),
            ("rgb(calc(100 + infinity * 0) 30 40)", "#001e28"),
        ]);
    }

    #[test]
    fn infinite_hypot_operands_take_native_precedence_over_nan() {
        assert_native_color_submissions(&[
            ("rgb(calc(100 + hypot(NaN, infinity)) 30 40)", "#ff1e28"),
            ("rgb(calc(100 + hypot(infinity, NaN)) 30 40)", "#ff1e28"),
            ("rgb(calc(100 + hypot(-infinity, NaN)) 30 40)", "#ff1e28"),
            ("rgb(calc(100 + hypot(NaN, 1)) 30 40)", "#001e28"),
        ]);
    }

    #[test]
    fn logarithm_boundary_bases_preserve_native_submitted_channels() {
        assert_native_color_submissions(&[
            ("rgb(calc(100 + log(1, 0)) 30 40)", "#641e28"),
            ("rgb(calc(100 + log(10, -0)) 30 40)", "#641e28"),
            ("rgb(calc(100 + log(10, 1)) 30 40)", "#ff1e28"),
            ("rgb(calc(100 + log(infinity, 1)) 30 40)", "#ff1e28"),
            ("rgb(calc(100 + log(0, 0)) 30 40)", "#001e28"),
            ("rgb(calc(100 + log(-1, 1)) 30 40)", "#001e28"),
        ]);
    }

    #[test]
    fn infinite_round_operands_keep_native_nan_precedence() {
        assert_native_color_submissions(&[
            (
                "rgb(calc(100 + round(nearest, NaN, infinity)) 30 40)",
                "#641e28",
            ),
            ("rgb(calc(100 + round(up, NaN, infinity)) 30 40)", "#ff1e28"),
            (
                "rgb(calc(100 + round(down, NaN, -infinity)) 30 40)",
                "#641e28",
            ),
            (
                "rgb(calc(100 + round(to-zero, NaN, infinity)) 30 40)",
                "#641e28",
            ),
            (
                "rgb(calc(100 + round(nearest, infinity, NaN)) 30 40)",
                "#ff1e28",
            ),
            ("rgb(calc(100 + round(up, infinity, NaN)) 30 40)", "#ff1e28"),
        ]);
    }

    #[test]
    fn native_hsl_channel_precision_survives_color_submission() {
        assert_native_color_submissions(&[
            ("hsl(100 80% 50%)", "#5ee619"),
            ("hsl(190 80% 50%)", "#19c3e6"),
            ("hsl(145 80% 50%)", "#19e66f"),
        ]);
    }

    #[test]
    fn native_display_p3_conversion_preserves_boundary_channels() {
        assert_native_color_submissions(&[
            ("color(display-p3 .49998 .49998 .49998)", "#7f8080"),
            ("color(display-p3 .50002 .50002 .50002)", "#7f8080"),
            ("color(display-p3 .5 .2 .1)", "#8a2c0e"),
        ]);
    }

    #[test]
    fn native_nonfinite_color_channels_follow_calc_admission() {
        assert_native_color_submissions(&[
            ("color(display-p3 NaN .2 .1)", "#000000"),
            ("color(display-p3 .5 NaN .1)", "#000000"),
            ("color(display-p3 .5 .2 NaN)", "#000000"),
            ("color(display-p3 calc(NaN) .2 .1)", "#000000"),
            ("color(display-p3 .5 calc(NaN) .1)", "#000000"),
            ("color(display-p3 .5 .2 calc(NaN))", "#000000"),
            ("color(display-p3 infinity .2 .1)", "#000000"),
            ("color(display-p3 .5 -infinity .1)", "#000000"),
            ("hsl(NaN 80% 50%)", "#000000"),
            ("hsl(0 NaN 50%)", "#000000"),
            ("hsl(0 80% NaN)", "#000000"),
            ("hsl(0 calc(NaN) 50%)", "#808080"),
            ("hsl(0 80% calc(NaN))", "#000000"),
        ]);
    }

    fn assert_native_color_submissions(cases: &[(&str, &str)]) {
        for (source, expected) in cases {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(r#"<input name="theme" type="color" value="{source}"></form>"#),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert_eq!(
                fields
                    .fields
                    .iter()
                    .find(|(name, _)| name == "theme")
                    .map(|(_, value)| value.as_str()),
                Some(*expected),
                "{source}"
            );
        }
    }

    #[test]
    fn dimensional_round_without_interval_is_rejected_but_numeric_default_is_retained() {
        assert_native_color_submissions(&[
            ("hsl(round(120deg) 100% 50%)", "#000000"),
            ("rgb(round(10) 30 40)", "#0a1e28"),
        ]);
    }

    #[test]
    fn nearest_round_preserves_negative_zero_and_negative_values() {
        assert_native_color_submissions(&[
            ("rgb(calc(1 / round(-0)) 30 40)", "#001e28"),
            ("rgb(calc(1 / round(-0.1)) 30 40)", "#001e28"),
            ("rgb(calc(255 + round(-1.1) * 10) 30 40)", "#f51e28"),
            ("rgb(round(0.49999999999999994) 30 40)", "#001e28"),
            (
                "rgb(calc(round(4503599627370497) - 4503599627370497) 30 40)",
                "#001e28",
            ),
            (
                "rgb(calc(100 + sign(round(0.9000000000000001, 0.1) - 0.9000000000000001) * 100) 30 40)",
                "#001e28",
            ),
            ("rgb(round(10, infinity) 30 40)", "#001e28"),
        ]);
    }

    #[test]
    fn modulo_zero_takes_the_divisors_sign() {
        assert_native_color_submissions(&[
            ("rgb(calc(1 / mod(-0, 1)) 30 40)", "#ff1e28"),
            ("rgb(calc(1 / mod(-0, -1)) 30 40)", "#001e28"),
        ]);
    }

    #[test]
    fn comments_do_not_create_math_operator_whitespace() {
        assert_native_color_submissions(&[
            ("rgb(calc(200/**/+/**/55) 30 40)", "#000000"),
            ("rgb(calc(200 + 55) 30 40)", "#ff1e28"),
            ("rgb(200/**/ 30 40)", "#c81e28"),
            ("/*x*/rgb(255 0 0)", "#ff0000"),
            ("rgb(255 0 0)/*x*/", "#ff0000"),
            ("\u{0001}#ff0000", "#000000"),
            ("#ff0000\u{0001}", "#000000"),
        ]);
    }

    #[test]
    fn mathematical_domain_results_do_not_invalidate_other_color_channels() {
        assert_native_color_submissions(&[
            ("rgb(sqrt(-1) 30 40)", "#001e28"),
            ("rgb(log(0) 30 40)", "#001e28"),
            ("rgb(log(-1) 30 40)", "#001e28"),
            ("rgb(mod(10, 0) 30 40)", "#001e28"),
            ("rgb(rem(10, 0) 30 40)", "#001e28"),
            ("rgb(round(10, 0) 30 40)", "#001e28"),
        ]);
    }

    #[test]
    fn nonfinite_css_round_intervals_preserve_native_submitted_colors() {
        assert_native_color_submissions(&[
            ("rgb(round(up, 10, infinity) 30 40)", "#ff1e28"),
            ("rgb(calc(1 / round(10, infinity)) 30 40)", "#ff1e28"),
            ("rgb(calc(-1 / round(-10, infinity)) 30 40)", "#ff1e28"),
            ("rgb(calc(-1 / round(up, -10, infinity)) 30 40)", "#ff1e28"),
            ("rgb(calc(1 / round(down, 10, infinity)) 30 40)", "#ff1e28"),
            (
                "rgb(calc(-255 * sign(round(down, -10, infinity))) 30 40)",
                "#ff1e28",
            ),
            (
                "rgb(calc(-1 / round(to-zero, -10, infinity)) 30 40)",
                "#ff1e28",
            ),
            ("rgb(round(up, 10, -infinity) 30 40)", "#ff1e28"),
            ("rgb(round(up, 10, -3) 30 40)", "#0c1e28"),
        ]);
    }

    #[test]
    fn nonfinite_css_mod_divisors_preserve_native_submitted_colors() {
        assert_native_color_submissions(&[
            ("rgb(calc(100 + mod(-10, -infinity)) 30 40)", "#5a1e28"),
            ("rgb(calc(100 + mod(10, infinity)) 30 40)", "#6e1e28"),
            ("rgb(calc(100 + mod(-10, infinity)) 30 40)", "#001e28"),
            ("rgb(calc(100 + mod(10, -infinity)) 30 40)", "#001e28"),
            ("rgb(calc(1 / mod(0, infinity)) 30 40)", "#ff1e28"),
            ("rgb(calc(-1 / mod(-0, -infinity)) 30 40)", "#ff1e28"),
            ("rgb(calc(100 + mod(-0, infinity)) 30 40)", "#001e28"),
            ("rgb(calc(100 + mod(0, -infinity)) 30 40)", "#001e28"),
            ("rgb(calc(100 + rem(-10, infinity)) 30 40)", "#5a1e28"),
            ("rgb(calc(100 + rem(10, -infinity)) 30 40)", "#6e1e28"),
        ]);
    }

    #[test]
    fn one_argument_hypot_preserves_its_nonnegative_magnitude() {
        assert_native_color_submissions(&[("rgb(hypot(-255) 30 40)", "#ff1e28")]);
    }

    #[test]
    fn signed_zero_from_sign_remains_observable_in_later_arithmetic() {
        assert_native_color_submissions(&[("rgb(calc(1 / sign(-0)) 30 40)", "#001e28")]);
    }

    #[test]
    fn mathematical_signs_follow_native_token_boundaries() {
        assert_native_color_submissions(&[
            ("rgb(calc(- -255) 30 40)", "#000000"),
            ("rgb(calc(- 255) 30 40)", "#000000"),
            ("rgb(calc(-(255)) 30 40)", "#000000"),
            ("rgb(calc(-pi * -40) 30 40)", "#000000"),
            ("rgb(calc(-infinity) 30 40)", "#001e28"),
            ("hsl(atan2(100%, 100%) 100% 50%)", "#000000"),
        ]);
    }

    #[test]
    fn outer_color_eof_completion_does_not_complete_unclosed_inner_math() {
        assert_native_color_submissions(&[
            ("rgb(calc(255) 0 0", "#ff0000"),
            ("rgb(calc(1 + 2 * 3) 0 0", "#070000"),
            ("rgb(calc(255 / 2", "#000000"),
        ]);
    }

    #[test]
    fn disabled_optgroup_inheritance_stops_at_the_option_parent() {
        for (source, expected) in [
            (
                r#"<optgroup disabled><select name="choice"><option selected value="keep">Keep</option></select></optgroup>"#,
                Some("keep"),
            ),
            (
                r#"<select name="choice"><optgroup disabled><option selected value="keep">Keep</option></optgroup></select>"#,
                None,
            ),
            (
                r#"<select name="choice"><option selected disabled value="keep">Keep</option></select>"#,
                None,
            ),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{source}</form>"));
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert_eq!(
                fields
                    .fields
                    .iter()
                    .find(|(name, _)| name == "choice")
                    .map(|(_, value)| value.as_str()),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn absolute_css_math_channels_preserve_native_submitted_colors() {
        for (source, expected) in [
            ("rgb(calc(255) 0 0)", "#ff0000"),
            ("rgb(calc(255 / 2) 0 0)", "#800000"),
            ("rgb(min(255, 300) 0 0)", "#ff0000"),
            ("rgb(clamp(0, 255, 300) 0 0)", "#ff0000"),
            ("rgb(calc(50% + 50%) 0 0)", "#ff0000"),
            ("rgb(calc(255 + 0%) 0 0)", "#000000"),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(r#"<input name="theme" type="color" value="{source}"></form>"#),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert_eq!(
                fields
                    .fields
                    .iter()
                    .find(|(name, _)| name == "theme")
                    .map(|(_, value)| value.as_str()),
                Some(expected),
                "{source}"
            );
        }
    }

    #[test]
    fn absolute_css_math_groups_units_and_nested_delimiters_reach_submission() {
        for (source, expected) in [
            ("rgb(calc((20 + 5) * 2) 0 0)", "#320000"),
            ("rgb(calc(20 + 5 * 2) 0 0)", "#1e0000"),
            ("rgb(calc((50% + 25%) / 3) 0 0)", "#400000"),
            (
                "rgb(min(calc(255 / 2), 200) 0 0 / max(25%, 50%))",
                "#800000",
            ),
            ("rgb(calc(sqrt(16) + pow(2, 2)) 0 0)", "#080000"),
            ("color(srgb calc(50% + 50%) 0 0)", "#ff0000"),
            ("hsl(calc(atan(1) + 45deg) 100% 50%)", "#80ff00"),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(r#"<input name="theme" type="color" value="{source}"></form>"#),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert_eq!(
                fields
                    .fields
                    .iter()
                    .find(|(name, _)| name == "theme")
                    .map(|(_, value)| value.as_str()),
                Some(expected),
                "{source}"
            );
        }

        let mut nested = String::with_capacity(5_000);
        for _ in 0..512 {
            nested.push_str("calc(");
        }
        nested.push_str("255");
        for _ in 0..512 {
            nested.push(')');
        }
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            &format!(r#"<input name="theme" type="color" value="rgb({nested} 0 0)"></form>"#),
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert_eq!(
            fields
                .fields
                .iter()
                .find(|(name, _)| name == "theme")
                .map(|(_, value)| value.as_str()),
            Some("#ff0000")
        );
    }

    #[test]
    fn css_math_constants_and_nonfinite_results_follow_native_submission() {
        for (source, expected) in [
            ("rgb(calc(pi * 40) 0 0)", "#7e0000"),
            ("rgb(calc(e * 40) 0 0)", "#6d0000"),
            ("rgb(calc(infinity) 30 40)", "#ff1e28"),
            ("rgb(calc(-infinity) 30 40)", "#001e28"),
            ("rgb(calc(NaN) 30 40)", "#001e28"),
            ("rgb(calc(0 / 0) 30 40)", "#001e28"),
            ("rgb(calc(1 / 0) 30 40)", "#ff1e28"),
            ("rgb(calc(infinity - infinity) 30 40)", "#001e28"),
            ("rgb(calc(min(NaN, 255)) 30 40)", "#001e28"),
            ("rgb(calc(max(NaN, 255)) 30 40)", "#001e28"),
            ("rgb(calc(clamp(0, NaN, 255)) 30 40)", "#001e28"),
            ("rgb(calc(sign(NaN)) 30 40)", "#001e28"),
            ("hsl(calc(infinity) 100% 50%)", "#ff0000"),
            ("hsl(calc(-infinity) 100% 50%)", "#ff0000"),
            ("hsl(calc(NaN) 100% 50%)", "#ff0000"),
            ("hsl(15, calc(100% + 100%), 50%)", "#ff4000"),
            ("hwb(0 calc(infinity) 0%)", "#000000"),
            ("hwb(0 calc(infinity) calc(infinity))", "#000000"),
            ("lab(calc(infinity) 0 0)", "#000000"),
            ("oklab(calc(infinity) 0 0)", "#000000"),
            ("lab(50% calc(infinity) 0)", "#000000"),
            ("color(srgb calc(infinity) 0.1 0.2)", "#ff1a33"),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(r#"<input name="theme" type="color" value="{source}"></form>"#),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert_eq!(
                fields
                    .fields
                    .iter()
                    .find(|(name, _)| name == "theme")
                    .map(|(_, value)| value.as_str()),
                Some(expected),
                "{source}"
            );
        }
    }

    #[test]
    fn lab_family_lightness_is_clamped_before_native_color_conversion() {
        for (source, expected) in [
            ("oklab(200% 0 100%)", "#ffe100"),
            ("oklab(100% 0 100%)", "#ffe100"),
            ("oklab(-100% 0 100%)", "#003d00"),
            ("oklab(0% 0 100%)", "#003d00"),
            ("lab(200% 100% 100%)", "#ff4d00"),
            ("lab(100% 100% 100%)", "#ff4d00"),
            ("lab(-100% 100% 100%)", "#7e0000"),
            ("lab(0% 100% 100%)", "#7e0000"),
            ("lch(200% 100% 30)", "#ff3579"),
            ("lch(100% 100% 30)", "#ff3579"),
            ("oklch(200% 100% 30)", "#ff3306"),
            ("oklch(100% 100% 30)", "#ff3306"),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(r#"<input name="theme" type="color" value="{source}"></form>"#),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert_eq!(
                fields
                    .fields
                    .iter()
                    .find(|(name, _)| name == "theme")
                    .map(|(_, value)| value.as_str()),
                Some(expected),
                "{source}"
            );
        }
    }

    #[test]
    fn xhtml_cannot_be_admitted_under_html_parser_semantics() {
        let mut response = Hop {
            status: 200,
            url: Url::parse(CLASSROOM_ORIGIN).unwrap(),
            body: r#"<html xmlns="http://www.w3.org/1999/xhtml"><head><script src="/app.js"/></head><body><input name="captcha"/></body></html>"#.to_owned(),
            retry_after: None,
            challenge: false,
            content_type: Some("application/xhtml+xml; charset=UTF-8".to_owned()),
            redirected: false,
        };
        let parse_error = match final_response_fields(&response) {
            Err(error) => error,
            Ok(_) => panic!("XHTML must not be parsed under HTML semantics"),
        };
        let (class, _, error) = final_response_parse_failure(&response, parse_error);
        assert_eq!(class, FailureClass::UnsafeInteraction);
        assert_ne!(error.message, challenge().message);
        assert_eq!(
            identity_probe_interaction(&response),
            Some(FailureClass::UnsafeInteraction)
        );
        response.url = pinned_login_url().unwrap();
        response.body = REVIEWED_LOGIN_PAGE.to_owned();
        let inspection = login_inspection(&response, &response.url);
        assert_eq!(
            inspection["fallback_reason"],
            "unexpected_login_content_type"
        );
    }

    #[test]
    fn declarative_shadow_roots_cannot_hide_active_challenges() {
        for mode in ["open", "closed"] {
            let shadow = format!(
                r#"<div><template shadowrootmode="{mode}"><input name="captcha"></template></div>"#
            );
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("</form>{shadow}"));
            for scope in [
                LoginSourceScope::CredentialForm,
                LoginSourceScope::FinalResponse,
            ] {
                assert!(
                    login_fields(&page, scope).is_err(),
                    "unreviewed {mode} shadow source was admitted"
                );
            }
            let response = Hop {
                status: 200,
                url: Url::parse(CLASSROOM_ORIGIN).unwrap(),
                body: page.clone(),
                retry_after: None,
                challenge: false,
                content_type: Some("text/html".to_owned()),
                redirected: false,
            };
            assert_eq!(
                identity_probe_interaction(&response),
                Some(FailureClass::UnsafeInteraction)
            );
            let parse_error = match final_response_fields(&response) {
                Err(error) => error,
                Ok(_) => panic!("declarative shadow roots must be refused"),
            };
            let (class, _, error) = final_response_parse_failure(&response, parse_error);
            assert_eq!(class, FailureClass::UnsafeInteraction);
            assert_ne!(error.message, challenge().message);
            let login_url = pinned_login_url().unwrap();
            let inspection = login_inspection(
                &Hop {
                    url: login_url.clone(),
                    ..response
                },
                &login_url,
            );
            assert!(inspection["form"].is_null());
            assert_eq!(inspection["fallback_reason"], "login_form_not_admitted");
        }

        let ordinary_template = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<template><template shadowrootmode="open"><input name="captcha"></template></template></form>"#,
        );
        let fields = login_fields(&ordinary_template, LoginSourceScope::CredentialForm)
            .expect("ordinary HTML template content remains inert");
        assert!(!requires_challenge(&fields));
        assert!(!requires_interaction_review(&fields));

        let foreign_template = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<svg><template><foreignObject><div><template shadowrootmode="open"><input name="captcha"></template></div></foreignObject></template></svg></form>"#,
        );
        assert!(
            login_fields(&foreign_template, LoginSourceScope::CredentialForm).is_err(),
            "a foreign SVG template must not hide a potential HTML shadow root"
        );
    }

    fn inspect_supplied_page(html: &str) -> Value {
        let url = pinned_login_url().unwrap();
        let page = Hop {
            status: 200,
            url: url.clone(),
            body: html.to_owned(),
            retry_after: None,
            challenge: false,
            content_type: Some("text/html; charset=UTF-8".into()),
            redirected: false,
        };
        login_inspection(&page, &url)
    }

    #[test]
    fn challenge_only_page_latches_both_credential_free_readers() {
        let cases = [
            ("<form><input name=\"captcha\"></form>", true),
            ("<input name=\"captcha\">", true),
            (
                "<form><input name=password><input name=execution><input name=captcha></form>",
                true,
            ),
            (
                "<fieldset disabled><legend><input name=captcha></legend></fieldset>",
                true,
            ),
            ("<input name=captcha disabled>", false),
            ("<input name=captcha type=hidden>", false),
            ("<div inert><input name=captcha></div>", false),
            ("<input name=captcha style=\"display:none\">", false),
            ("<template><input name=captcha></template>", false),
            ("<fieldset disabled><input name=captcha></fieldset>", false),
            ("<svg><textarea name=captcha></textarea></svg>", false),
            ("<label>Verification code<input name=answer></label>", false),
        ];
        for kind in [RequestKind::Authentication, RequestKind::Interactive] {
            for (index, (html, active)) in cases.iter().enumerate() {
                let (_directory, path) =
                    temporary_directory(&format!("challenge-only-inspection-{kind:?}-{index}"));
                let governor = Governor::isolated_for_test(&path).unwrap();
                if kind == RequestKind::Authentication {
                    governor
                        .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                        .unwrap();
                }
                let mut lease = governor.try_acquire(kind).unwrap();
                lease.observe_http(200, Some("30"), false).unwrap();
                let url = pinned_login_url().unwrap();
                let page = Hop {
                    status: 200,
                    url: url.clone(),
                    body: (*html).to_owned(),
                    retry_after: Some("30".to_owned()),
                    challenge: false,
                    content_type: Some("text/html".to_owned()),
                    redirected: false,
                };
                let output = finish_login_inspection(lease, &page, &url).unwrap();
                assert!(output["form"].is_null());
                assert_eq!(output["active_challenge_control"], *active, "{html}");
                let status = governor.status().unwrap();
                assert_eq!(status.safety_latched, false);
                assert!(!status.authentication_armed);
                assert!(!status.cooldown_wait.is_zero());
            }
        }
    }

    #[test]
    fn redirected_or_unsuccessful_html_challenges_latch_both_readers() {
        for kind in [RequestKind::Authentication, RequestKind::Interactive] {
            for (index, (code, redirected, moved)) in [
                (200, true, false),
                (200, false, true),
                (200, true, true),
                (500, false, false),
            ]
            .into_iter()
            .enumerate()
            {
                let (_directory, path) = temporary_directory(&format!(
                    "unexpected-challenge-inspection-{kind:?}-{index}"
                ));
                let governor = Governor::isolated_for_test(&path).unwrap();
                if kind == RequestKind::Authentication {
                    governor
                        .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                        .unwrap();
                }
                let mut lease = governor.try_acquire(kind).unwrap();
                lease.observe_http(code, Some("30"), false).unwrap();
                let expected = pinned_login_url().unwrap();
                let page = Hop {
                    status: code,
                    url: if moved {
                        expected.join("challenge").unwrap()
                    } else {
                        expected.clone()
                    },
                    body: "<input name=captcha>".into(),
                    retry_after: Some("30".into()),
                    challenge: false,
                    content_type: Some("text/html".into()),
                    redirected,
                };
                let output = finish_login_inspection(lease, &page, &expected).unwrap();
                assert!(output["form"].is_null());
                assert_eq!(output["fallback_reason"], "unexpected_login_response");
                assert_eq!(output["active_challenge_control"], true);
                assert_eq!(output["safety_latched"], false);
                let status = governor.status().unwrap();
                assert!(!status.safety_latched);
                assert!(!status.authentication_armed);
                assert!(!status.cooldown_wait.is_zero());
            }
        }
    }

    #[test]
    fn inspection_reports_the_latch_committed_for_each_request_kind() {
        for kind in [RequestKind::Authentication, RequestKind::Interactive] {
            for code in [200, 302, 401, 403, 429, 500] {
                let (_directory, path) =
                    temporary_directory(&format!("inspection-settlement-{kind:?}-{code}"));
                let governor = Governor::isolated_for_test(&path).unwrap();
                if kind == RequestKind::Authentication {
                    governor
                        .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                        .unwrap();
                }
                let mut lease = governor.try_acquire(kind).unwrap();
                lease.observe_http(code, None, false).unwrap();
                let url = pinned_login_url().unwrap();
                let page = Hop {
                    status: code,
                    url: url.clone(),
                    body: "<p>Service response</p>".into(),
                    retry_after: None,
                    challenge: false,
                    content_type: Some("text/html".into()),
                    redirected: false,
                };
                let output = finish_login_inspection(lease, &page, &url).unwrap();
                assert_eq!(output["safety_latched"], false, "{kind:?}/{code}");
                assert_eq!(governor.status().unwrap().safety_latched, false);
                assert!(!governor.status().unwrap().authentication_armed);
            }
        }
    }

    #[test]
    fn login_inspection_requires_explicit_html_before_parsing_form_markup() {
        let url = pinned_login_url().unwrap();
        let mut page = Hop {
            status: 200,
            url: url.clone(),
            body: REVIEWED_LOGIN_PAGE.to_owned(),
            retry_after: None,
            challenge: false,
            content_type: None,
            redirected: false,
        };
        for mime in [
            None,
            Some("application/json"),
            Some("text/plain"),
            Some("application/octet-stream"),
            Some("application/xhtml+xml"),
            Some("text/html-other"),
        ] {
            page.content_type = mime.map(str::to_owned);
            let output = login_inspection(&page, &url);
            assert!(output["form"].is_null(), "{mime:?}");
            assert_eq!(output["fallback_reason"], "unexpected_login_content_type");
            if mime == Some("application/xhtml+xml") {
                assert_eq!(output["content_type"], "application/xhtml+xml");
            }
        }
        page.content_type = Some("text/html; charset=UTF-8".to_owned());
        let output = login_inspection(&page, &url);
        assert!(output["fallback_reason"].is_null());
        assert_eq!(output["form"]["interaction_review_required"], false);
        assert_eq!(output["active_challenge_control"], false);
    }

    #[test]
    fn inspection_redacts_unrecognized_mime_subtypes_from_serialized_output() {
        let url = pinned_login_url().unwrap();
        let mut page = Hop {
            status: 200,
            url: url.clone(),
            body: REVIEWED_LOGIN_PAGE.replace("synthetic-execution-token", "ST-private-ticket"),
            retry_after: None,
            challenge: false,
            content_type: Some("application/ST-private-ticket".into()),
            redirected: false,
        };
        let output = login_inspection(&page, &url);
        assert!(!output.to_string().contains("ST-private-ticket"));
        assert!(output["content_type"].is_null());
        page.content_type = Some(" TEXT/HTML ; charset=ST-private-ticket".into());
        let output = login_inspection(&page, &url);
        assert_eq!(output["content_type"], "text/html");
        assert!(!output.to_string().contains("ST-private-ticket"));
    }

    #[test]
    fn inspection_identifies_first_owned_enabled_rejection_without_values() {
        let html = REVIEWED_LOGIN_PAGE
            .replace(
                "</form>",
                r#"
            <fieldset disabled><input name="disabledChoice" type="checkbox"></fieldset>
            <input name="foreignChoice" form="other" type="checkbox">
            <input name="rememberMe" type="checkbox" value="private-control-value" required autocomplete="captcha">
            <input name="laterChoice" type="checkbox"></form>"#,
            )
            .replace("synthetic-execution-token", "private-execution-value");
        let result = inspect_supplied_page(&html);
        assert_eq!(
            result["form"]["interaction_reason"],
            "unreviewed_challenge_control"
        );
        let control = &result["form"]["first_rejected_control"];
        assert_eq!(control["name"], "redacted");
        assert_eq!(control["input_type"], "checkbox");
        assert_eq!(control["required"], true);
        assert_eq!(control["checked"], false);
        assert_eq!(result["active_challenge_control"], true);
        let serialized = result.to_string();
        assert!(!serialized.contains("private-control-value"));
        assert!(!serialized.contains("private-execution-value"));
    }

    #[test]
    fn inspection_reports_protocol_value_as_boolean_for_challenge_controls() {
        for (value, expected_match) in [("synthetic-execution-token", true), ("", false)] {
            let original =
                r#"<input name="execution" type="hidden" value="synthetic-execution-token">"#;
            let replacement = format!(
                r#"<input name="execution" type="text" value="{value}" autocomplete="captcha">"#
            );
            let page = REVIEWED_LOGIN_PAGE.replace(original, &replacement);
            let result = inspect_supplied_page(&page);
            assert_eq!(result["form"]["interaction_review_required"], true);
            let control = &result["form"]["first_rejected_control"];
            assert_eq!(control["name"], "execution");
            assert_eq!(control["reviewed_protocol_value"], expected_match);
            assert_eq!(control["own_inert"], false);
            let serialized = serde_json::to_string(&result).expect("serialize inspection");
            if !value.is_empty() {
                assert!(!serialized.contains(value), "{serialized}");
            }
        }
        let page = REVIEWED_LOGIN_PAGE.replace(
            r#"<input name="username" type="text">"#,
            r#"<input name="username" type="checkbox" inert>"#,
        );
        let result = inspect_supplied_page(&page);
        let control = &result["form"]["first_rejected_control"];
        assert_eq!(control["name"], "username");
        assert_eq!(control["own_inert"], true);
    }

    #[test]
    fn inspection_preserves_first_legend_exception_and_external_ownership() {
        let html = format!(
            "{}{}",
            REVIEWED_LOGIN_PAGE,
            r#"
            <fieldset disabled><legend>
            <textarea form="loginForm" name="firstLegend" required autocomplete="captcha">private-text</textarea>
            </legend><input form="loginForm" name="disabledLater" type="checkbox"></fieldset>"#
        );
        let result = inspect_supplied_page(&html);
        let control = &result["form"]["first_rejected_control"];
        assert_eq!(control["tag"], "textarea");
        assert_eq!(control["name"], "redacted");
        assert!(!result.to_string().contains("private-text"));
    }

    #[test]
    fn inspection_redacts_unreviewed_control_names_from_serialized_output() {
        let html = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="ST-private-ticket" type="checkbox" value="synthetic-control-value" required autocomplete="captcha"></form>"#,
        );
        let result = inspect_supplied_page(&html);
        let serialized = serde_json::to_string(&result).expect("serialize inspection");
        assert!(!serialized.contains("ST-private-ticket"));
        assert!(!serialized.contains("synthetic-control-value"));
        let control = &result["form"]["first_rejected_control"];
        assert_eq!(control["name"], "redacted");
        assert_eq!(control["input_type"], "checkbox");
        assert!(control["required"].as_bool().unwrap());
    }

    #[test]
    fn successful_session_cookie_name_projection_redacts_names_and_values() {
        let cookie_header =
            "ST-private-ticket=synthetic-ticket-value; SSO_nonce=synthetic-nonce-value";
        let names = classroom_cookie_names(cookie_header);
        let output = json!({"session":{"cookie_names":names}});
        let serialized = serde_json::to_string(&output).expect("serialize session projection");
        for secret in [
            "ST-private-ticket",
            "synthetic-ticket-value",
            "SSO_nonce",
            "synthetic-nonce-value",
        ] {
            assert!(!serialized.contains(secret), "{secret}: {serialized}");
        }
        assert_eq!(
            output["session"]["cookie_names"],
            json!(["redacted", "redacted"])
        );

        let classroom = Url::parse("https://classroom.msa.buaa.edu.cn/courseapi/v3").unwrap();
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("ST-private-ticket=synthetic-ticket-value; Path=/"),
        );
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("SSO_nonce=synthetic-nonce-value; Path=/"),
        );
        let mut jar = Jar::default();
        jar.absorb(&classroom, &headers).unwrap();
        assert_eq!(
            jar.header(&classroom).unwrap().to_str().unwrap(),
            cookie_header
        );
    }

    #[test]
    fn inspection_distinguishes_wrong_credentials_missing_controls_and_parse_refusal() {
        let wrong = inspect_supplied_page(&REVIEWED_LOGIN_PAGE.replace(
            "name=\"username\" type=\"text\"",
            "name=\"username\" type=\"hidden\"",
        ));
        assert_eq!(wrong["form"]["interaction_reason"], "wrong_username_type");
        let missing = inspect_supplied_page(
            &REVIEWED_LOGIN_PAGE.replace("<input name=\"username\" type=\"text\">", ""),
        );
        assert_eq!(
            missing["form"]["interaction_reason"],
            "missing_username_control"
        );
        assert!(missing["form"]["first_rejected_control"].is_null());
        let unavailable = inspect_supplied_page("<html>private-auth-body</html>");
        assert_eq!(unavailable["fallback_reason"], "login_form_not_admitted");
        assert!(!unavailable.to_string().contains("private-auth-body"));
    }

    #[test]
    fn inspection_rejects_credentials_and_missing_authority_before_io() {
        for input in [
            r#"{"authorized":true,"intent":"INSPECT CLASSROOM LOGIN","password":"synthetic"}"#,
            r#"{"authorized":true,"intent":"LOGIN synthetic classroom"}"#,
        ] {
            assert_eq!(inspect(input).unwrap_err().code, "invalid_input");
        }
        assert_eq!(
            inspect(r#"{"authorized":false,"intent":"INSPECT CLASSROOM LOGIN"}"#)
                .unwrap_err()
                .code,
            "permission"
        );
    }

    #[test]
    fn uncertain_challenge_controls_cannot_pass_both_admission_gates() {
        for tag in [
            r#"<button id="captcha" STYLE>Solve challenge</button>"#,
            r#"<input id="captcha" type="submit" STYLE>"#,
            r#"<input id="captcha" type="button" STYLE>"#,
            r#"<input id="captcha" type="reset" STYLE>"#,
        ] {
            for style in ["display:none;display:block", "/*", "display:none"] {
                let control = tag.replace("STYLE", &format!(r#"style="{style}""#));
                let page = format!(
                    "<style>#captcha {{ display:block !important }}</style>{}",
                    REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"))
                );
                let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
                assert!(
                    requires_interaction_review(&fields) || requires_challenge(&fields),
                    "{control}"
                );
                assert_eq!(
                    fields.first_rejected_control.as_ref().unwrap().tag,
                    if tag.starts_with("<button") {
                        "button"
                    } else {
                        "input"
                    }
                );
            }
        }
    }

    #[test]
    fn displayed_challenge_labels_require_review_without_leaking_label_text() {
        for control in [
            r#"<button type="button">Solve CAPTCHA private-button-label</button>"#,
            r#"<button type="button">Solve CAP<span>TCHA</span> private-split-label</button>"#,
            r#"<button type="button">Solve <span>CAPTCHA</span> private-split-label</button>"#,
            r#"<input type="submit" value="Solve CAPTCHA private-submit-value">"#,
            r#"<input type="button" value="Solve CAPTCHA private-button-value">"#,
            r#"<input type="reset" value="Solve CAPTCHA private-reset-value">"#,
            r#"<input type="button" value="Get verification&nbsp;code private-nbsp-value">"#,
            r#"<input type="button" value="Get verification   code private-spaced-value">"#,
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"));
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert!(requires_interaction_review(&fields), "{control}");
            // Displayed labels are only a reason to stop for review, not proof
            // that the server has established an active CAPTCHA challenge.
            assert!(!requires_challenge(&fields), "{control}");
            let rejected = fields.first_rejected_control.as_ref().unwrap();
            assert!(rejected.challenge_marker, "{control}");

            let inspected = inspect_supplied_page(&page).to_string();
            assert!(!inspected.contains("private-"), "{control}");
            assert!(!inspected.contains("Solve CAPTCHA"), "{control}");
        }
    }

    #[test]
    fn challenge_label_scan_respects_css_ownership_and_benign_controls() {
        for style in ["display:none;display:block", "/*", "display:none"] {
            let control = format!(
                r#"<button id="label-only" style="{style}">Solve CAPTCHA private-css-label</button>"#
            );
            let page = format!(
                "<style>#label-only {{ display:block !important }}</style>{}",
                REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"))
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert!(requires_interaction_review(&fields), "{style}");
            assert!(!requires_challenge(&fields), "{style}");
        }

        for control in [
            r#"<button type="button">Continue</button>"#,
            r#"<button type="button">Continue<script>Solve CAPTCHA</script><style>challenge</style><template>captcha</template><noscript>verification code</noscript></button>"#,
            r#"<button type="button">Continue<span inert>CAPTCHA</span></button>"#,
            r#"<label inert for="answer">验证码</label><input id="answer" name="answer">"#,
            r#"<div inert><label for="answer">CAPTCHA</label></div><input id="answer" name="answer">"#,
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"));
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert!(!requires_interaction_review(&fields), "{control}");
            assert!(!requires_challenge(&fields), "{control}");
        }
        let disabled_prompt = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<button type="button" disabled>Solve CAPTCHA</button></form>"#,
        );
        let fields = login_fields(&disabled_prompt, LoginSourceScope::CredentialForm).unwrap();
        assert!(requires_interaction_review(&fields));
        assert!(!requires_challenge(&fields));

        let foreign_form_challenge = format!(
            r#"{REVIEWED_LOGIN_PAGE}<form id="other"><button type="button">Solve CAPTCHA</button></form>"#
        );
        let fields =
            login_fields(&foreign_form_challenge, LoginSourceScope::CredentialForm).unwrap();
        assert!(requires_interaction_review(&fields));
        assert!(!requires_challenge(&fields));

        let externally_owned = format!(
            r#"{REVIEWED_LOGIN_PAGE}<button type="button" form="loginForm">Solve CAPTCHA</button>"#
        );
        let fields = login_fields(&externally_owned, LoginSourceScope::CredentialForm).unwrap();
        assert!(requires_interaction_review(&fields));
        assert!(!requires_challenge(&fields));

        let ignored_values = REVIEWED_LOGIN_PAGE
            .replace(
                r#"<input name="username" type="text">"#,
                r#"<input name="username" type="text" value="private CAPTCHA username">"#,
            )
            .replace(
                r#"<input name="password" type="password">"#,
                r#"<input name="password" type="password" value="private CAPTCHA password">"#,
            )
            .replace(
                "</form>",
                r#"<input name="ignored" type="hidden" value="private CAPTCHA hidden"></form>"#,
            );
        let fields = login_fields(&ignored_values, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_interaction_review(&fields));
        assert!(!requires_challenge(&fields));
        let inspected = inspect_supplied_page(&ignored_values).to_string();
        assert!(!inspected.contains("private CAPTCHA"));
    }

    #[test]
    fn reviewed_submitter_overrides_are_not_admitted_for_credential_submission() {
        let ordinary = login_fields(REVIEWED_LOGIN_PAGE, LoginSourceScope::CredentialForm)
            .expect("the reviewed submitter without overrides remains admitted");
        assert_eq!(ordinary.method, "post");
        assert!(
            ordinary
                .fields
                .iter()
                .any(|(name, value)| name == "submit" && value == "LOGIN")
        );

        for override_attribute in [
            r#"formmethod="get""#,
            r#"formaction="/unreviewed""#,
            r#"formenctype="multipart/form-data""#,
        ] {
            let submitter = format!(
                r#"<input name="submit" type="submit" value="LOGIN" {override_attribute}>"#
            );
            let page = REVIEWED_LOGIN_PAGE.replace(
                r#"<input name="submit" type="submit" value="LOGIN">"#,
                &submitter,
            );
            assert!(
                login_fields(&page, LoginSourceScope::CredentialForm).is_err(),
                "a selected submitter with {override_attribute} changes request semantics"
            );
        }
    }

    #[test]
    fn active_base_href_is_not_ignored_for_login_action_admission() {
        let active_base = REVIEWED_LOGIN_PAGE.replace(
            "<html><body>",
            r#"<html><head><base href="/unreviewed/"></head><body>"#,
        );
        assert!(
            login_fields(&active_base, LoginSourceScope::CredentialForm).is_err(),
            "the relative login action must not be admitted against the response URL alone"
        );

        let inert_bases = REVIEWED_LOGIN_PAGE.replace(
            "</body>",
            r#"<template><base href="/template/"></template><svg><base href="/foreign/" /></svg></body>"#,
        );
        let fields = login_fields(&inert_bases, LoginSourceScope::CredentialForm)
            .expect("template and foreign-namespace bases are not active HTML bases");
        assert_eq!(fields.action, "login");
    }

    #[test]
    fn foreign_style_ancestor_cannot_hide_an_active_base_from_credential_admission() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "<html><body>",
            r#"<html><body><svg><style><foreignObject><base href="https://example.invalid/unreviewed/"></foreignObject></style></svg>"#,
        );
        assert!(
            login_fields(&page, LoginSourceScope::CredentialForm).is_err(),
            "a document-tree HTML base beneath a foreign style ancestor changes the relative login action"
        );
    }

    #[test]
    fn login_form_encoding_must_match_urlencoded_request_construction() {
        let default_encoding = login_fields(REVIEWED_LOGIN_PAGE, LoginSourceScope::CredentialForm)
            .expect("the default form encoding is URL-encoded");
        assert_eq!(default_encoding.method, "post");

        let explicit_urlencoded = REVIEWED_LOGIN_PAGE.replace(
            r#"<form method="post" id="loginForm" action="login">"#,
            r#"<form method="post" id="loginForm" action="login" enctype="application/x-www-form-urlencoded">"#,
        );
        assert!(login_fields(&explicit_urlencoded, LoginSourceScope::CredentialForm).is_ok());

        for encoding in ["multipart/form-data", "text/plain"] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                r#"<form method="post" id="loginForm" action="login">"#,
                &format!(
                    r#"<form method="post" id="loginForm" action="login" enctype="{encoding}">"#
                ),
            );
            assert!(
                login_fields(&page, LoginSourceScope::CredentialForm).is_err(),
                "unsupported effective encoding {encoding} must be refused"
            );
        }
    }

    #[test]
    fn non_submitting_images_cannot_override_credential_form_ownership() {
        for image in [
            "<img>",
            "<img form=missing>",
            "<img form=other name=image value=not-submitted>",
        ] {
            let page = format!(
                "<form id=f method=post action=login><input name=username value=user>\
                 <input name=password type=password value=secret>\
                 <input name=execution type=hidden value=token>\
                 <input name=nonce type=hidden value=keep>{image}</form><form id=other></form>"
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            let expected = [
                ("username", "user"),
                ("password", "secret"),
                ("execution", "token"),
                ("nonce", "keep"),
            ];
            assert_eq!(
                fields
                    .fields
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
                    .collect::<Vec<_>>(),
                expected,
                "{image}"
            );
            assert!(!requires_challenge(&fields));
            assert!(!requires_interaction_review(&fields));
        }
    }

    #[test]
    fn parser_associated_table_controls_are_not_silently_omitted() {
        let parser_associated_form = r#"<form id="f" method="post" action="login"><input form="f" name="username" type="text"><input form="f" name="password" type="password"><input form="f" name="execution" type="hidden" value="token"><input type="hidden" name="nonce" value="keep"></form>"#;
        for (context, before, after) in [
            ("table", "<table>", "</table>"),
            ("tbody", "<table><tbody>", "</tbody></table>"),
            ("thead", "<table><thead>", "</thead></table>"),
            ("tfoot", "<table><tfoot>", "</tfoot></table>"),
            ("tr", "<table><tbody><tr>", "</tr></tbody></table>"),
            ("colgroup", "<table><colgroup>", "</colgroup></table>"),
        ] {
            let page = format!("{before}{parser_associated_form}{after}");
            assert!(
                login_fields(&page, LoginSourceScope::CredentialForm).is_err(),
                "parser-established ownership in {context} must fail closed"
            );
        }

        let ordinary_form = r#"<form id="f" method="post" action="login"><input name="username" type="text"><input name="password" type="password"><input name="execution" type="hidden" value="token"><input type="hidden" name="nonce" value="keep"></form>"#;
        for (context, before, after) in [
            ("td", "<table><tbody><tr><td>", "</td></tr></tbody></table>"),
            ("caption", "<table><caption>", "</caption></table>"),
        ] {
            let page = format!(
                "{before}{ordinary_form}{after}<input form=\"f\" name=\"external\" value=\"associated\">"
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).expect(
                "ordinary cell/caption forms and explicit external controls remain supported",
            );
            for (name, value) in [("nonce", "keep"), ("external", "associated")] {
                assert!(
                    fields.fields.iter().any(|(field_name, field_value)| {
                        field_name == name && field_value == value
                    }),
                    "successful control {name} must retain its {context} form owner"
                );
            }
        }
    }

    #[test]
    fn foster_parented_parser_association_cannot_silently_omit_a_successful_control() {
        let page = r#"<table><div><form id="f" method="post" action="login"><input form="f" name="username" type="text"><input form="f" name="password" type="password"><input form="f" name="execution" type="hidden" value="token"><input type="hidden" name="nonce" value="keep"></form></div></table>"#;
        assert!(
            login_fields(page, LoginSourceScope::CredentialForm).is_err(),
            "parser-associated nonce must not disappear when foster parenting separates it from the selected form"
        );
    }

    #[test]
    fn ordered_successful_controls_preserve_names_values_and_form_ownership() {
        let page = r#"<form method="POST" id="loginForm" action="login">
            <input name="username" type="text" value="source-user">
            <input name="__action" type="text" value="ordinary-action" required>
            <input name="__method" value="ordinary-method">
            <input name="__unreviewed_control" type="text" value="ordinary-review-key">
            <input name="numeric" type="number" value="42">
            <input name="email" type="email" value="student@example.test">
            <input name="hiddenOrdinary" type="hidden" value="hidden-value">
            <input name="duplicate" value="first"><input name="duplicate" value="second">
            <input name="unchecked" type="checkbox" value="no">
            <input name="checked" type="checkbox" checked>
            <input name="radio" type="radio" value="selected" checked>
            <textarea name="notes">default text</textarea>
            <select name="choice"><option>  default   label </option><option value="unused">Unused</option></select>
            <select name="multiple" multiple><option value="one" selected>One</option><option value="disabled" selected disabled>Disabled</option><option value="two" selected>Two</option></select>
            <input name="password" type="password" value="source-password">
            <input name="type" type="text" value="username_password">
            <input name="execution" type="text" value="source-token">
            <input name="submit" type="submit" value="LOGIN">
            <input name="resetAction" type="reset" value="reset">
            <input name="buttonAction" type="button" value="button">
            <input name="imageAction" type="image" value="image">
            <input name="otherSubmit" type="submit" value="not-selected">
            <input name="noValueSubmit" type="submit">
            <button name="buttonSubmit" type="submit" value="not-selected">Continue</button>
            <input name="upload" type="file">
            <fieldset disabled>
                <input name="disabledField" value="not-submitted">
                <legend><input name="firstLegend" value="submitted"></legend>
                <legend><input name="secondLegend" value="not-submitted"></legend>
            </fieldset>
        </form>
        <input form="loginForm" name="external" value="associated">
        <form id="other"><input name="foreign" value="not-associated"></form>"#;
        let fields =
            login_fields(page, LoginSourceScope::CredentialForm).expect("source login form");
        assert_eq!(fields.action, "login");
        assert_eq!(fields.method, "post");
        assert!(!requires_interaction_review(&fields));
        assert!(!requires_challenge(&fields));
        assert_eq!(
            fields.fields,
            vec![
                ("username".into(), "source-user".into()),
                ("__action".into(), "ordinary-action".into()),
                ("__method".into(), "ordinary-method".into()),
                ("__unreviewed_control".into(), "ordinary-review-key".into()),
                ("numeric".into(), "42".into()),
                ("email".into(), "student@example.test".into()),
                ("hiddenOrdinary".into(), "hidden-value".into()),
                ("duplicate".into(), "first".into()),
                ("duplicate".into(), "second".into()),
                ("checked".into(), "on".into()),
                ("radio".into(), "selected".into()),
                ("notes".into(), "default text".into()),
                ("choice".into(), "default label".into()),
                ("multiple".into(), "one".into()),
                ("multiple".into(), "two".into()),
                ("password".into(), "source-password".into()),
                ("type".into(), "username_password".into()),
                ("execution".into(), "source-token".into()),
                ("submit".into(), "LOGIN".into()),
                ("firstLegend".into(), "submitted".into()),
                ("external".into(), "associated".into()),
            ]
        );

        let without_submitter =
            REVIEWED_LOGIN_PAGE.replace(r#"<input name="submit" type="submit" value="LOGIN">"#, "");
        let fields = login_fields(&without_submitter, LoginSourceScope::CredentialForm)
            .expect("form without submitter");
        assert!(!fields.fields.iter().any(|(name, _)| name == "submit"));
    }

    #[test]
    fn associated_challenge_labels_require_review_without_confirming_captcha() {
        for control in [
            r#"<label for="answer">验证码</label><input id="answer" name="answer" required>"#,
            r#"<label>验 <span>证</span> 码<input name="answer"></label>"#,
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"));
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert_unreviewed_interaction(&fields);
            let rejected = fields.first_rejected_control.as_ref().unwrap();
            assert!(rejected.challenge_marker);
            assert_eq!(rejected.name, Some(REDACTED_NAME));
            let output = inspect_supplied_page(&page).to_string();
            assert!(!output.contains("验证码"));
        }
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input id="answer" name="answer"></form><label for="answer">Verification code</label>"#,
        );
        assert_unreviewed_interaction(
            &login_fields(&page, LoginSourceScope::CredentialForm).unwrap(),
        );

        for (control, review_required) in [
            (
                r#"<label for="answer">Ordinary<script>CAPTCHA</script><style>challenge</style><template>验证码</template></label><input id="answer" name="answer">"#,
                false,
            ),
            (
                r#"<label for="answer">验证码</label><input id="answer" name="answer" type="hidden">"#,
                true,
            ),
            (
                r#"<label for="answer">验证码</label><input id="answer" name="answer" disabled>"#,
                true,
            ),
            (
                r#"<div id="answer"></div><label for="answer">验证码</label><input id="answer" name="answer">"#,
                true,
            ),
            (r#"<label inert>验证码<input name="answer"></label>"#, false),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"));
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert_eq!(
                requires_interaction_review(&fields),
                review_required,
                "{control}"
            );
            assert!(!requires_challenge(&fields), "{control}");
        }
    }

    #[test]
    fn explicit_form_ownership_uses_the_first_document_element_with_the_id() {
        let shadowed = REVIEWED_LOGIN_PAGE
            .replace("<html><body>", r#"<html><body><div id="loginForm"></div>"#)
            .replace(
                r#"name="password" type="password""#,
                r#"name="password" type="password" form="loginForm""#,
            );
        assert!(login_fields(&shadowed, LoginSourceScope::CredentialForm).is_err());

        let nested = REVIEWED_LOGIN_PAGE
            .replace("<html><body>", r#"<html><body><div id="loginForm"></div>"#)
            .replace(
                "</form>",
                r#"</form><input form="loginForm" name="unowned" value="not-submitted">"#,
            );
        let fields = login_fields(&nested, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_interaction_review(&fields));
        assert!(!fields.fields.iter().any(|(name, _)| name == "unowned"));

        let duplicates = r#"<form id="shared" method="post" action="login"></form>
            <form id="shared" method="post" action="ignored"></form>
            <input form="shared" name="username" type="text">
            <input form="shared" name="password" type="password">
            <input form="shared" name="execution" value="source-token">"#;
        let fields = login_fields(duplicates, LoginSourceScope::CredentialForm).unwrap();
        assert_eq!(fields.action, "login");
        assert_eq!(
            fields.fields,
            vec![
                ("username".into(), "".into()),
                ("password".into(), "".into()),
                ("execution".into(), "source-token".into()),
            ]
        );
    }

    #[test]
    fn foster_parented_duplicate_ids_follow_document_tree_order() {
        let page = r#"<html><body><table>
            <form id="loginForm" method="post" action="login"></form>
            <div id="loginForm"></div>
        </table>
        <input form="loginForm" name="username" type="text">
        <input form="loginForm" name="password" type="password">
        <input form="loginForm" name="execution" value="source-token">
        </body></html>"#;
        assert!(login_fields(page, LoginSourceScope::CredentialForm).is_err());
    }

    #[test]
    fn successful_controls_and_radio_groups_follow_document_tree_order() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"</form><table><tbody><tr><td><input form="loginForm" name="ordered" value="cell"><input form="loginForm" name="choice" type="radio" checked value="cell-radio"></td></tr></tbody><input form="loginForm" name="ordered" value="foster"><input form="loginForm" name="choice" type="radio" checked value="foster-radio"></table>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        let ordered: Vec<_> = fields
            .fields
            .iter()
            .filter(|(name, _)| name == "ordered")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(ordered, ["foster", "cell"]);
        assert!(
            fields
                .fields
                .iter()
                .any(|(name, value)| name == "choice" && value == "foster-radio")
        );
        assert!(
            !fields
                .fields
                .iter()
                .any(|(name, value)| name == "choice" && value == "cell-radio")
        );
    }

    #[test]
    fn duplicate_reviewed_login_submitters_fail_closed() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="submit" type="submit" value="LOGIN"></form>"#,
        );
        assert!(login_fields(&page, LoginSourceScope::CredentialForm).is_err());
    }

    #[test]
    fn single_select_size_does_not_invent_listbox_choices() {
        for (size, expected) in [
            ("0", vec!["first"]),
            ("1", vec!["first"]),
            ("2", vec![]),
            ("+2", vec![]),
            (" 2 ", vec![]),
            ("2junk", vec![]),
            ("2147483648", vec![]),
            ("4294967296", vec!["first"]),
            ("\u{00a0}2", vec!["first"]),
        ] {
            let control = format!(
                r#"<select name="choice" size="{size}"><option value="first">First</option><option value="second">Second</option></select>"#
            );
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"));
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            let choices: Vec<_> = fields
                .fields
                .iter()
                .filter(|(name, _)| name == "choice")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(choices, expected, "size={size}");
        }
        let page = REVIEWED_LOGIN_PAGE.replace("</form>", r#"<select name="choice" size="2"><option value="first">First</option><option value="second" selected>Second</option></select></form>"#);
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(
            fields
                .fields
                .iter()
                .any(|(name, value)| name == "choice" && value == "second")
        );
        assert!(
            !fields
                .fields
                .iter()
                .any(|(name, value)| name == "choice" && value == "first")
        );
    }

    #[test]
    fn radio_groups_use_last_source_checkedness_including_disabled_members() {
        for (controls, expected) in [
            (
                r#"<input type="radio" name="choice" value="first" checked><input type="radio" name="choice" value="second" checked>"#,
                vec!["second"],
            ),
            (
                r#"<input type="radio" name="choice" value="first" checked><input type="radio" name="choice" value="second" checked disabled>"#,
                vec![],
            ),
            (
                r#"<input type="radio" name="choice" value="first" checked><fieldset disabled><input type="radio" name="choice" value="second" checked></fieldset>"#,
                vec![],
            ),
            (
                r#"<input type="radio" name="choice" value="first" checked><input type="radio" name="choice" value="second">"#,
                vec!["first"],
            ),
            (
                r#"<input type="radio" name="choice" value="first" checked><input type="radio" name="choice" value="foreign" checked form="other">"#,
                vec!["first"],
            ),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{controls}</form>"));
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            let choices: Vec<_> = fields
                .fields
                .iter()
                .filter(|(name, _)| name == "choice")
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(choices, expected, "{controls}");
        }
    }

    #[test]
    fn login_field_budgets_refuse_source_data_instead_of_dropping_it() {
        let oversized_value = "x".repeat(MAX_FIELD_BYTES + 1);
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            &format!(r#"<input name="tooLarge" value="{oversized_value}"></form>"#),
        );
        assert!(
            matches!(login_fields(&page, LoginSourceScope::CredentialForm), Err(error) if error.code == "unavailable")
        );

        let too_many = (0..MAX_FORM_FIELDS)
            .map(|_| r#"<input name="repeated" value="x">"#)
            .collect::<String>();
        let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{too_many}</form>"));
        assert!(
            matches!(login_fields(&page, LoginSourceScope::CredentialForm), Err(error) if error.code == "unavailable")
        );

        let large_value = "x".repeat(14 * 1024);
        let over_budget = (0..5)
            .map(|index| format!(r#"<input name="extra{index}" value="{large_value}">"#))
            .collect::<String>();
        let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{over_budget}</form>"));
        assert!(
            matches!(login_fields(&page, LoginSourceScope::CredentialForm), Err(error) if error.code == "unavailable")
        );
    }

    #[test]
    fn login_dom_element_and_depth_budgets_fail_closed() {
        let depth = MAX_LOGIN_DOM_DEPTH + 1;
        let deeply_nested = format!(
            "{}<span></span>{}",
            "<section>".repeat(depth),
            "</section>".repeat(depth)
        );
        assert!(matches!(
            login_fields(&deeply_nested, LoginSourceScope::CredentialForm),
            Err(error) if error.code == "unavailable"
        ));

        let too_many_elements = format!(
            "<main>{}</main>",
            "<span></span>".repeat(MAX_LOGIN_DOM_ELEMENTS + 1)
        );
        assert!(matches!(
            login_fields(&too_many_elements, LoginSourceScope::CredentialForm),
            Err(error) if error.code == "unavailable"
        ));

        let repeated_labels = format!(
            "{}<button id=\"label-target\">Continue</button>",
            r#"<label for="label-target">ordinary</label>"#
                .repeat(MAX_LOGIN_TEXT_SUBTREE_SCANS + 1)
        );
        let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{repeated_labels}</form>"));
        assert!(matches!(
            login_fields(&page, LoginSourceScope::CredentialForm),
            Err(error) if error.code == "unavailable"
        ));
    }

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

    #[test]
    fn selected_cookie_expiring_during_pacing_prevents_the_next_post() {
        use std::io::Write;
        use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let (worker_stopped, worker_requests) = (Arc::clone(&stopped), Arc::clone(&requests));
        let worker = std::thread::spawn(move || {
            while !worker_stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        worker_requests.fetch_add(1, Ordering::SeqCst);
                        let _ = socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        let (_directory, path) = temporary_directory("cookie-expires-before-fenced-post");
        let governor = Governor::isolated_for_test(&path).unwrap();
        governor.resume_authentication(ResumeAuthorization::ExplicitUserRequest).unwrap();
        let mut lease = governor.try_acquire(RequestKind::Authentication).unwrap();
        let url = pinned_login_url().unwrap();
        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, HeaderValue::from_static("sid=synthetic; Path=/; Max-Age=1"));
        let mut jar = Jar::default();
        jar.absorb(&url, &headers).unwrap();
        let proxy = reqwest::Proxy::all(format!("http://{address}")).unwrap();
        let client = Client::builder().https_only(true).proxy(proxy).build().unwrap();
        let fields = [("username", "synthetic"), ("password", "synthetic")];
        let mut trail = Trail::new();
        let result = send(&mut lease, &client, &mut jar, &url, Some((&fields, &url)), &mut trail, false);
        stopped.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        let error = result.err().expect("expired cookie must refuse the next request");
        assert_eq!(error.code, "scoped_cookie_unusable");
        finish_send_failure(lease, &error).unwrap();
        let status = governor.status().unwrap();
        assert!(!status.safety_latched);
        assert_eq!(status.consecutive_network_failures, 0);
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn expired_scoped_cookie_refusal_preserves_interactive_governor_state() {
        let (_directory, path) = temporary_directory("already-expired-scoped-cookie");
        let governor = Governor::isolated_for_test(&path).unwrap();
        governor.resume_authentication(ResumeAuthorization::ExplicitUserRequest).unwrap();
        let mut lease = governor.try_acquire(RequestKind::Interactive).unwrap();
        let url = pinned_login_url().unwrap();
        let other = Url::parse("https://classroom.msa.buaa.edu.cn/").unwrap();
        let mut jar = Jar::default();
        assert!(matches!(jar.select_cookies(&url, true), ScopedCookies::Anonymous));
        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, HeaderValue::from_static("sid=synthetic; Path=/; Max-Age=60"));
        jar.absorb(&url, &headers).unwrap();
        jar.cookies[0].expiry = Some(UNIX_EPOCH);
        assert!(matches!(jar.select_cookies(&other, true), ScopedCookies::Anonymous));
        assert!(matches!(jar.select_cookies(&url, true), ScopedCookies::Unusable));
        let proxy = reqwest::Proxy::all("http://127.0.0.1:1").unwrap();
        let client = Client::builder().https_only(true).proxy(proxy).build().unwrap();
        let mut trail = Trail::new();
        let error = send(&mut lease, &client, &mut jar, &url, None, &mut trail, true)
            .err().expect("an expired applicable cookie must refuse the request");
        assert_eq!(error.code, "scoped_cookie_unusable");
        finish_send_failure(lease, &error).unwrap();
        let status = governor.status().unwrap();
        assert!(!status.safety_latched);
        assert!(!status.authentication_armed);
        assert_eq!(status.consecutive_network_failures, 0);
    }

    fn assert_unreviewed_interaction(fields: &ParsedLoginForm) {
        assert!(requires_interaction_review(fields));
        assert!(!requires_challenge(fields));
        assert_eq!(classify(fields), FailureClass::UnsafeInteraction);
        let error = interaction_review_required();
        assert_eq!(error.code, "auth_latched");
    }

    #[test]
    fn a_hidden_captcha_container_is_not_a_required_challenge() {
        let fields = login_fields(REVIEWED_LOGIN_PAGE, LoginSourceScope::CredentialForm)
            .expect("login fields");
        assert!(!requires_challenge(&fields));
        assert_eq!(classify(&fields), FailureClass::Unknown);
        let challenged = login_fields(r#"<form method="post" action="login"><input name="password"><input name="execution" value="token"><input name="captcha"></form>"#, LoginSourceScope::CredentialForm)
        .expect("form");
        assert!(requires_challenge(&challenged));
        assert_eq!(classify(&challenged), FailureClass::Challenge);
        let final_fields = login_fields(REVIEWED_LOGIN_PAGE, LoginSourceScope::FinalResponse)
            .expect("final page fields");
        assert!(!final_fields.has_unverified_challenge_text);
        assert!(final_fields.has_password_control);
        assert!(final_response_is_admissible(
            CLASSROOM_HOST,
            200,
            "ordinary response",
            false,
            false,
            None,
            FailureClass::Unknown,
        ));
        assert!(!final_response_is_admissible(
            CLASSROOM_HOST,
            200,
            "interactive challenge",
            true,
            false,
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
                !requires_challenge(
                    &login_fields(&page, LoginSourceScope::CredentialForm).unwrap()
                ),
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
            assert_unreviewed_interaction(
                &login_fields(&page, LoginSourceScope::CredentialForm).unwrap(),
            );
        }
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<fieldset disabled><legend><input name="captcha"></legend></fieldset></form>"#,
        );
        assert!(requires_challenge(
            &login_fields(&page, LoginSourceScope::CredentialForm).unwrap()
        ));
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<fieldset disabled><legend>caption</legend><legend><input name="captcha"></legend></fieldset></form>"#,
        );
        assert!(!requires_challenge(
            &login_fields(&page, LoginSourceScope::CredentialForm).unwrap()
        ));
    }

    #[test]
    fn ordinary_login_controls_are_preserved_without_review() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="unfamiliarStep" value="source-value">
               <select name="verification"><option>choose</option></select>
               <textarea name="answer">source answer</textarea>
               <input name="requiredOrdinary" required value="required-value"></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_challenge(&fields));
        assert!(!requires_interaction_review(&fields));
        for expected in [
            ("unfamiliarStep", "source-value"),
            ("verification", "choose"),
            ("answer", "source answer"),
            ("requiredOrdinary", "required-value"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| (name.as_str(), value.as_str()) == expected),
                "{expected:?}"
            );
        }

        let color_tokens = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r##"<input name="rgbFunctionSpace" type="color" value="rgb (1, 2, 3)"><input name="hslFunctionSpace" type="color" value="hsl (0 100% 50%)"><input name="colorFunctionSpace" type="color" value="color (srgb 1 0 0)"><input name="hslUpperAngle" type="color" value="hsl(120DEG 100% 50%)"><input name="colorNonePercent" type="color" value="rgb(255 0 0 / none%)"><input name="colorNoneAlpha" type="color" value="rgb(255 0 0 / none)"></form>"##,
        );
        let fields = login_fields(&color_tokens, LoginSourceScope::CredentialForm).unwrap();
        for expected in [
            ("rgbFunctionSpace", "#000000"),
            ("hslFunctionSpace", "#000000"),
            ("colorFunctionSpace", "#000000"),
            ("hslUpperAngle", "#00ff00"),
            ("colorNonePercent", "#000000"),
            ("colorNoneAlpha", "#ff0000"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| { (name.as_str(), value.as_str()) == expected }),
                "{expected:?} in {:?}",
                fields.fields
            );
        }
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="verificationCode" required></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(requires_challenge(&fields));
        assert_eq!(classify(&fields), FailureClass::Challenge);
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="csrf" type="hidden"><input name="disabledStep" disabled></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_challenge(&fields));
        assert!(!requires_interaction_review(&fields));
    }

    #[test]
    fn datalist_descendant_controls_follow_observed_browser_formdata() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<datalist><input name="datalistUser" value="source-user"><input name="datalistPassword" type="password" value="source-password"><input name="datalistOrdinary" value="fallback-value"></datalist></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm)
            .expect("browser-submitted credentials stay eligible");
        for expected in [
            ("datalistUser", "source-user"),
            ("datalistPassword", "source-password"),
            ("datalistOrdinary", "fallback-value"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| { (name.as_str(), value.as_str()) == expected })
            );
        }

        let credentials_in_datalist = r#"<form id="login" method="post" action="login"><input name="execution" value="token"><datalist><input name="username" type="text" value="source-user"><input name="password" type="password" value="source-password"></datalist></form>"#;
        let fields = login_fields(credentials_in_datalist, LoginSourceScope::CredentialForm)
            .expect("Chromium FormData includes datalist descendant credential controls");
        assert!(!requires_interaction_review(&fields));
        assert!(
            fields
                .fields
                .iter()
                .any(|(name, value)| { name == "username" && value == "source-user" })
        );
        assert!(
            fields
                .fields
                .iter()
                .any(|(name, value)| { name == "password" && value == "source-password" })
        );
    }

    #[test]
    fn initial_input_values_match_observed_chromium_formdata_sanitization() {
        assert_eq!(css_color_value("rgb(1, 2, 3)"), "#010203");
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r##"<input name="rangeDefault" type="range"><input name="rangeClamp" type="range" min="10" max="20" value="99"><input name="rangeStep" type="range" min="0" max="100" step="10" value="25"><input name="colorDefault" type="color"><input name="colorName" type="color" value="red"><input name="colorHex" type="color" value="#AABBCC"><input name="colorShort" type="color" value="#ABC"><input name="colorAlpha" type="color" value="#AABBCCDD"><input name="colorRgb" type="color" value="rgb(1, 2, 3)"><input name="colorHsl" type="color" value="hsl(0, 100%, 50%)"><input name="colorP3" type="color" value="color(display-p3 1 0 0)"><input name="colorInvalid" type="color" value="not-a-color"><input name="textLines" type="text" value="a&#10;b"><input name="emailTrim" type="email" value="  user@example.test  "><input name="emailList" type="email" multiple value=" a@example.test , b@example.test "><input name="urlLines" type="url" value="https://a.example.test/&#10;b"><input name="numberInvalid" type="number" value="1e"><input name="dateInvalid" type="date" value="2026-02-30"><input name="monthValid" type="month" value="2026-04"><input name="weekValid" type="week" value="2026-W43"><input name="timeValid" type="time" value="13:45"><input name="timeInvalid" type="time" value="24:00"><input name="datetimeValid" type="datetime-local" value="2026-10-24T13:45"><textarea name="textareaLines">first&#10;second</textarea></form>"##,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        for expected in [
            ("rangeDefault", "50"),
            ("rangeClamp", "20"),
            ("rangeStep", "30"),
            ("colorDefault", "#000000"),
            ("colorName", "#ff0000"),
            ("colorHex", "#aabbcc"),
            ("colorShort", "#aabbcc"),
            ("colorAlpha", "#aabbcc"),
            ("colorRgb", "#010203"),
            ("colorHsl", "#ff0000"),
            ("colorP3", "#ff0000"),
            ("colorInvalid", "#000000"),
            ("textLines", "ab"),
            ("emailTrim", "user@example.test"),
            ("emailList", "a@example.test,b@example.test"),
            ("urlLines", "https://a.example.test/b"),
            ("numberInvalid", ""),
            ("dateInvalid", ""),
            ("monthValid", "2026-04"),
            ("weekValid", "2026-W43"),
            ("timeValid", "13:45"),
            ("timeInvalid", ""),
            ("datetimeValid", "2026-10-24T13:45"),
            ("textareaLines", "first\r\nsecond"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| { (name.as_str(), value.as_str()) == expected }),
                "{expected:?} in {:?}",
                fields.fields
            );
        }

        let hidden_page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="hiddenLines" type="hidden" value="left&#10;right"></form>"#,
        );
        let hidden = login_fields(&hidden_page, LoginSourceScope::CredentialForm).unwrap();
        assert!(
            hidden
                .fields
                .iter()
                .any(|(name, value)| { name == "hiddenLines" && value == "left\nright" })
        );

        let boundary_page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r##"<input name="numberTrailingDot" type="number" value="1."><input name="timeEmptyFraction" type="time" value="13:45:00."><input name="timeLongFraction" type="time" value="13:45:00.1234"><input name="colorRgbExtra" type="color" value="rgb(1 2 3 4)"><input name="colorRgbAlpha" type="color" value="rgb(1 2 3 / 50%)"><input name="colorRgbaAlpha" type="color" value="rgba(1, 2, 3, 0.5)"><input name="colorHslExtra" type="color" value="hsl(0 100% 50% 2)"><input name="colorHslAlpha" type="color" value="hsl(0 100% 50% / 0.5)"><input name="colorP3Extra" type="color" value="color(display-p3 1 0 0 0.5)"><input name="colorP3Alpha" type="color" value="color(display-p3 1 0 0 / 0.5)"></form>"##,
        );
        let fields = login_fields(&boundary_page, LoginSourceScope::CredentialForm).unwrap();
        for expected in [
            ("numberTrailingDot", ""),
            ("timeEmptyFraction", ""),
            ("timeLongFraction", ""),
            ("colorRgbExtra", "#000000"),
            ("colorRgbAlpha", "#010203"),
            ("colorRgbaAlpha", "#010203"),
            ("colorHslExtra", "#000000"),
            ("colorHslAlpha", "#ff0000"),
            ("colorP3Extra", "#000000"),
            ("colorP3Alpha", "#ff0000"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| { (name.as_str(), value.as_str()) == expected }),
                "{expected:?} in {:?}",
                fields.fields
            );
        }

        let browser_boundaries = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r##"<input name="rangeStepBase" type="range" step="10" value="25"><input name="rangeStepBound" type="range" min="0" max="10" step="6" value="10"><input name="urlTrim" type="url" value="  https://example.test/path  "><input name="datePlus" type="date" value="2026-+1-02"><input name="monthPlus" type="month" value="2026-+1"><input name="weekPlus" type="week" value="2026-W+1"><input name="datetimeSpace" type="datetime-local" value="2026-10-24 13:45:00.000"><input name="datetimeFraction" type="datetime-local" value="2026-10-24T13:45:10.500"><input name="rgbMixed" type="color" value="rgb(100% 0 0)"><input name="rgbTrailingDot" type="color" value="rgb(1., 2, 3)"></form>"##,
        );
        let fields = login_fields(&browser_boundaries, LoginSourceScope::CredentialForm).unwrap();
        for expected in [
            ("rangeStepBase", "25"),
            ("rangeStepBound", "6"),
            ("urlTrim", "https://example.test/path"),
            ("datePlus", ""),
            ("monthPlus", ""),
            ("weekPlus", ""),
            ("datetimeSpace", "2026-10-24T13:45"),
            ("datetimeFraction", "2026-10-24T13:45:10.5"),
            ("rgbMixed", "#ff0000"),
            ("rgbTrailingDot", "#000000"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| { (name.as_str(), value.as_str()) == expected }),
                "{expected:?} in {:?}",
                fields.fields
            );
        }

        let css_color4 = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r##"<input name="hwbGreen" type="color" value="hwb(120 0% 0%)"><input name="labRed" type="color" value="lab(54.29 80.82 69.88)"><input name="lchRed" type="color" value="lch(54.29 106.84 40.85)"><input name="oklabRed" type="color" value="oklab(0.62796 0.22486 0.12585)"><input name="oklchRed" type="color" value="oklch(0.628 0.258 29.2)"><input name="p3Extended" type="color" value="color(display-p3 2 0 0)"><input name="a98Red" type="color" value="color(a98-rgb 1 0 0)"><input name="prophotoRed" type="color" value="color(prophoto-rgb 1 0 0)"><input name="rec2020Red" type="color" value="color(rec2020 1 0 0)"><input name="xyzD50" type="color" value="color(xyz-d50 0.436 0.222 0.014)"><input name="xyzD65" type="color" value="color(xyz-d65 0.412 0.213 0.019)"><input name="rgbHalfPercent" type="color" value="rgb(50% 0 0)"></form>"##,
        );
        let fields = login_fields(&css_color4, LoginSourceScope::CredentialForm).unwrap();
        for expected in [
            ("hwbGreen", "#00ff00"),
            ("labRed", "#ff0000"),
            ("lchRed", "#ff0000"),
            ("oklabRed", "#ff0000"),
            ("oklchRed", "#ff0000"),
            ("p3Extended", "#ff0000"),
            ("a98Red", "#ff0000"),
            ("prophotoRed", "#ff0000"),
            ("rec2020Red", "#ff0000"),
            ("xyzD50", "#ff0001"),
            ("xyzD65", "#ff0300"),
            ("rgbHalfPercent", "#800000"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| { (name.as_str(), value.as_str()) == expected }),
                "{expected:?} in {:?}",
                fields.fields
            );
        }
    }

    #[test]
    fn alpha_enabled_color_values_match_current_chromium_formdata() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r##"<input name="alphaAttributeHex" type="color" alpha value="#12345680"><input name="alphaAttributeFunction" type="color" alpha value="rgb(1 2 3 / 50%)"></form>"##,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(
            fields
                .fields
                .iter()
                .any(|(name, value)| name == "alphaAttributeHex" && value == "#123456")
        );
        assert!(
            fields
                .fields
                .iter()
                .any(|(name, value)| name == "alphaAttributeFunction" && value == "#010203")
        );
    }

    #[test]
    fn css_color_edge_cases_match_chromium_formdata() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r##"<input name="lchNegative" type="color" value="lch(50 -40 0)"><input name="lchZero" type="color" value="lch(50 0 0)"><input name="oklchNegative" type="color" value="oklch(0.5 -0.1 0)"><input name="oklchZero" type="color" value="oklch(0.5 0 0)"><input name="rgbaCommaNone" type="color" value="rgba(255, 0, 0, none)"><input name="rgbCommaNone" type="color" value="rgb(255, 0, 0, none)"><input name="hslCommaNone" type="color" value="hsl(0, 100%, 50%, none)"><input name="hslCommaMissing" type="color" value="hsl(0, none, 50%)"><input name="hwbCommaMissing" type="color" value="hwb(0, none, 0%)"><input name="hslMissingSat" type="color" value="hsl(0 none 50%)"><input name="hwbMissingWhite" type="color" value="hwb(0 none 0%)"><input name="rgbSpaceNone" type="color" value="rgb(255 0 0 / none)"><input name="rgbNbspChannel" type="color" value="rgb(&#160;255, 0, 0)"><input name="hslNbspSaturation" type="color" value="hsl(0 &#160;100% 50%)"><input name="labNbspLightness" type="color" value="lab(&#160;54.29 80.82 69.88)"><input name="rgbNbspAlpha" type="color" value="rgb(255 0 0 / &#160;0.5)"><input name="colorNbspAlpha" type="color" value="color(display-p3 1 0 0 / &#160;0.5)"><input name="p3Negative" type="color" value="color(display-p3 -1 0 0)"></form>"##,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        for expected in [
            ("lchNegative", "#777777"),
            ("lchZero", "#777777"),
            ("oklchNegative", "#636363"),
            ("oklchZero", "#636363"),
            ("rgbaCommaNone", "#000000"),
            ("rgbCommaNone", "#000000"),
            ("hslCommaNone", "#000000"),
            ("hslCommaMissing", "#000000"),
            ("hwbCommaMissing", "#000000"),
            ("hslMissingSat", "#808080"),
            ("hwbMissingWhite", "#ff0000"),
            ("rgbSpaceNone", "#ff0000"),
            ("rgbNbspChannel", "#000000"),
            ("hslNbspSaturation", "#000000"),
            ("labNbspLightness", "#000000"),
            ("rgbNbspAlpha", "#000000"),
            ("colorNbspAlpha", "#000000"),
            ("p3Negative", "#003a26"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| { (name.as_str(), value.as_str()) == expected }),
                "{expected:?} in {:?}",
                fields.fields
            );
        }
    }

    #[test]
    fn hwb_preserves_unbounded_ratios_without_changing_native_hsl_clamping() {
        for (source, expected) in [
            ("hwb(0 200% 100%)", "#aaaaaa"),
            ("hwb(0 100% 200%)", "#555555"),
            ("hsl(15 200% 50%)", "#ff4000"),
            ("hsl(15, 200%, 50%)", "#ff4000"),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(r#"<input name="theme" type="color" value="{source}"></form>"#),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert!(
                login_form_values(&fields, "student", "synthetic-password")
                    .contains(&("theme", expected)),
                "{source}"
            );
        }
    }

    #[test]
    fn modern_hsl_hwb_numeric_components_use_percentage_reference_units() {
        for (source, expected) in [
            ("hsl(0 100 50)", "#ff0000"),
            ("hwb(120 0 0)", "#00ff00"),
            ("hsl(120 100% 50)", "#00ff00"),
            ("hsl(0, 100, 50)", "#000000"),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(r#"<input name="theme" type="color" value="{source}"></form>"#),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert!(
                login_form_values(&fields, "student", "synthetic-password")
                    .contains(&("theme", expected)),
                "{source}"
            );
        }
    }

    #[test]
    fn hard_wrapped_textareas_require_review_without_guessing_layout() {
        for wrap in ["hard", "HARD"] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(
                    r#"<textarea name="notes" wrap="{wrap}" cols="2">abcdef</textarea></form>"#
                ),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert!(requires_interaction_review(&fields));
            assert!(!requires_challenge(&fields));
            assert_eq!(fields.interaction_reason, Some("layout_dependent_textarea"));
            assert!(!fields.fields.iter().any(|(name, _)| name == "notes"));
        }
        for (control, expected) in [
            (
                r#"<textarea name="notes" wrap="soft" cols="2">abcdef</textarea>"#,
                Some("abcdef"),
            ),
            (
                r#"<textarea name="notes" wrap="off" cols="2">abcdef</textarea>"#,
                Some("abcdef"),
            ),
            (
                r#"<textarea name="notes" wrap="hard" cols="2"></textarea>"#,
                Some(""),
            ),
            (
                r#"<textarea name="notes" wrap="hard" cols="2" disabled>abcdef</textarea>"#,
                None,
            ),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"));
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert!(!requires_interaction_review(&fields));
            let values = login_form_values(&fields, "student", "synthetic-password");
            match expected {
                Some(value) => assert!(values.contains(&("notes", value))),
                None => assert!(!values.iter().any(|(name, _)| *name == "notes")),
            }
        }
    }

    #[test]
    fn css_comments_are_removed_before_color_tokenization() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r##"<input name="commentBetween" type="color" value="rgb(255 /*note*/ 0 0)"><input name="commentBoundary" type="color" value="rgb(255/**/0 0)"><input name="commentSlash" type="color" value="rgb(255 /* / */ 0 0)"><input name="commentNameSeparator" type="color" value="rgb/**/(255 0 0)"><input name="namedCommentEof" type="color" value="red/*note"><input name="namedCommentClosed" type="color" value="red/*note*/"><input name="hexCommentEof" type="color" value="#ff0000/*note"><input name="functionCommentEof" type="color" value="rgb(255 0 0)/*note"><input name="functionInsideCommentEof" type="color" value="rgb(255 0 0 /*note"></form>"##,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        for (name, expected) in [
            ("commentBetween", "#ff0000"),
            ("commentBoundary", "#ff0000"),
            ("commentSlash", "#ff0000"),
            ("commentNameSeparator", "#000000"),
            ("namedCommentEof", "#000000"),
            ("namedCommentClosed", "#000000"),
            ("hexCommentEof", "#ff0000"),
            ("functionCommentEof", "#ff0000"),
            ("functionInsideCommentEof", "#ff0000"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(field, value)| (field.as_str(), value.as_str()) == (name, expected)),
                "{name:?}={expected:?} in {:?}",
                fields.fields
            );
        }
    }

    #[test]
    fn foreign_namespaces_cannot_own_login_forms_or_credentials() {
        let foreign_form = r#"<svg><form id="loginForm" method="post" action="login"/></svg><input form="loginForm" name="username" type="text" value="source-user"><input form="loginForm" name="password" type="password" value="source-password"><input form="loginForm" name="execution" value="source-token">"#;
        assert!(login_fields(foreign_form, LoginSourceScope::CredentialForm).is_err());

        let foreign_first_id = r#"<svg><g id="loginForm"></g></svg><form id="loginForm" method="post" action="login"></form><input form="loginForm" name="username" type="text"><input form="loginForm" name="password" type="password"><input form="loginForm" name="execution" value="source-token">"#;
        assert!(login_fields(foreign_first_id, LoginSourceScope::CredentialForm).is_err());

        let foreign_control = r#"<form id="loginForm" method="post" action="login"><input name="password" type="password"><input name="execution" value="source-token"></form><svg><input form="loginForm" name="username" type="text" value="foreign-user"/></svg>"#;
        let fields = login_fields(foreign_control, LoginSourceScope::CredentialForm).unwrap();
        assert_eq!(fields.interaction_reason, Some("missing_username_control"));
        assert!(!fields.fields.iter().any(|(name, _)| name == "username"));
    }

    #[test]
    fn foreign_svg_template_and_noscript_do_not_hide_live_challenges() {
        for (open, close) in [
            (
                "<svg><template><foreignObject>",
                "</foreignObject></template></svg>",
            ),
            (
                "<svg><noscript><foreignObject>",
                "</foreignObject></noscript></svg>",
            ),
        ] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(
                    r#"{open}<input name="captcha" required value="synthetic">{close}</form>"#
                ),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert!(fields.has_active_challenge_control);
            assert!(requires_challenge(&fields));
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| { name == "captcha" && value == "synthetic" })
            );
        }

        let html_template = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<template><input name="captcha" required value="inert"></template></form>"#,
        );
        let fields = login_fields(&html_template, LoginSourceScope::CredentialForm).unwrap();
        assert!(!fields.has_active_challenge_control);
        assert!(!fields.fields.iter().any(|(name, _)| name == "captcha"));
    }

    #[test]
    fn document_ids_below_foreign_script_and_style_block_external_form_ownership() {
        for container in ["script", "style"] {
            let page = format!(
                r#"<svg><{container}><g id="loginForm"></g></{container}></svg><form id="loginForm" method="post" action="login"></form><input form="loginForm" name="username" type="text"><input form="loginForm" name="password" type="password"><input form="loginForm" name="execution" value="source-token">"#
            );
            assert!(
                login_fields(&page, LoginSourceScope::CredentialForm).is_err(),
                "foreign {container} retains document ID membership"
            );
        }
        let page = r#"<template><span id="loginForm"></span></template><form id="loginForm" method="post" action="login"></form><input form="loginForm" name="username" type="text"><input form="loginForm" name="password" type="password"><input form="loginForm" name="execution" value="source-token">"#;
        let fields = login_fields(page, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_interaction_review(&fields));
        assert_eq!(
            login_form_values(&fields, "student", "synthetic-password"),
            [
                ("username", "student"),
                ("password", "synthetic-password"),
                ("execution", "source-token"),
            ]
        );
    }

    #[test]
    fn hidden_charset_entries_use_the_actual_submission_encoding() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input type="hidden" name="_charset_" value="ISO-8859-1"><input type="hidden" name="_CHARSET_"><input type="text" name="_charset_" value="ordinary"><input name="notes" value="中文"></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        let values = login_form_values(&fields, "student", "synthetic-password");
        let body = form_urlencoded_body(&values);
        let submitted = url::form_urlencoded::parse(body.as_bytes()).collect::<Vec<_>>();
        let charset = submitted
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("_charset_"))
            .map(|(name, value)| (name.as_ref(), value.as_ref()))
            .collect::<Vec<_>>();
        assert_eq!(
            charset,
            [
                ("_charset_", "UTF-8"),
                ("_CHARSET_", "UTF-8"),
                ("_charset_", "ordinary"),
            ]
        );
        assert!(
            submitted
                .iter()
                .any(|(name, value)| name == "notes" && value == "中文")
        );
    }

    #[test]
    fn range_default_midpoint_preserves_decimal_ties() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="defaultTie" type="range" min="0.1" max="0.7" step="0.6"><input name="invalidValueTie" type="range" min="0.1" max="0.7" step="0.6" value="invalid"></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        let values = login_form_values(&fields, "student", "synthetic-password");
        for name in ["defaultTie", "invalidValueTie"] {
            assert!(values.contains(&(name, "0.7")), "{name} in {values:?}");
        }
    }

    #[test]
    fn range_local_decimal_ties_do_not_depend_on_a_distant_bound() {
        for maximum in ["1", "1e308"] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(
                    r#"<input name="localTie" type="range" min="0" max="{maximum}" step="0.1" value="0.35"></form>"#
                ),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            let values = login_form_values(&fields, "student", "synthetic-password");
            assert!(
                values.contains(&("localTie", "0.4")),
                "max={maximum}: {values:?}"
            );
        }
    }

    #[test]
    fn range_high_precision_and_local_step_underflow_match_chromium_formdata() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="rangeDoubleRound" type="range" min="0" max="1000000000000000" step="0.5" value="900719925474099.5"><input name="rangeTinyStep" type="range" min="0" max="1e308" step="1e-20" value="6e-21"></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        for expected in [
            ("rangeDoubleRound", "900719925474100"),
            ("rangeTinyStep", "1e-20"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| (name.as_str(), value.as_str()) == expected),
                "{expected:?} in {:?}",
                fields.fields
            );
        }
    }

    #[test]
    fn range_zero_exponent_decimal_conversion_matches_chromium_formdata() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="rangeZeroExponent" type="range" min="0" max="10" step="0.1" value="1.15"></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(
            fields
                .fields
                .iter()
                .any(|(name, value)| name == "rangeZeroExponent" && value == "1.2")
        );
    }

    #[test]
    fn dirname_entries_follow_successful_form_order_and_directionality() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r##"<div dir="rtl"><input name="dirText" type="text" value="source" dirname="dirText.dir"><input name="dirDefaultType" value="default" dirname="dirDefaultType.dir"><input name="dirInvalidType" type="unknown" value="unknown" dirname="dirInvalidType.dir"><input name="dirSearch" type="search" value="query" dirname="dirSearch.dir"><input name="dirUrl" type="url" value="https://example.test/" dirname="dirUrl.dir"><input name="dirTel" type="tel" value="123" dirname="dirTel.dir"><input name="dirTelExplicit" type="tel" value="123" dir="rtl" dirname="dirTelExplicit.dir"><input name="dirEmail" type="email" value="a@example.test" dirname="dirEmail.dir"><input name="dirPassword" type="password" value="secret" dirname="dirPassword.dir"><input name="dirHidden" type="hidden" value="hidden" dirname="dirHidden.dir"><input name="dirNumber" type="number" value="3" dirname="dirNumber.dir"><input name="dirRange" type="range" min="0" max="10" value="3" dirname="dirRange.dir"><input name="dirColor" type="color" value="#123456" dirname="dirColor.dir"><input name="dirDate" type="date" value="2026-10-25" dirname="dirDate.dir"><input name="dirCheckbox" type="checkbox" checked dirname="dirCheckbox.dir"><input name="dirRadio" type="radio" checked dirname="dirRadio.dir"><textarea name="dirTextarea" dirname="dirTextarea.dir">source</textarea></div><input name="autoHebrew" type="text" value="אabc" dir="auto" dirname="autoHebrew.dir"><input name="autoLatin" type="text" value="abcא" dir="auto" dirname="autoLatin.dir"><input name="autoHidden" type="hidden" value="אabc" dir="auto" dirname="autoHidden.dir"></form>"##,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        let has_adjacent = |name: &str, value: &str, dir_name: &str, dir: &str| {
            fields.fields.windows(2).any(|pair| {
                (pair[0].0.as_str(), pair[0].1.as_str()) == (name, value)
                    && (pair[1].0.as_str(), pair[1].1.as_str()) == (dir_name, dir)
            })
        };
        for expected in [
            ("dirText", "source", "dirText.dir", "rtl"),
            ("dirDefaultType", "default", "dirDefaultType.dir", "rtl"),
            ("dirInvalidType", "unknown", "dirInvalidType.dir", "rtl"),
            ("dirSearch", "query", "dirSearch.dir", "rtl"),
            ("dirUrl", "https://example.test/", "dirUrl.dir", "rtl"),
            ("dirTel", "123", "dirTel.dir", "ltr"),
            ("dirTelExplicit", "123", "dirTelExplicit.dir", "rtl"),
            ("dirEmail", "a@example.test", "dirEmail.dir", "rtl"),
            ("dirPassword", "secret", "dirPassword.dir", "rtl"),
            ("dirHidden", "hidden", "dirHidden.dir", "rtl"),
            ("dirTextarea", "source", "dirTextarea.dir", "rtl"),
            ("autoHebrew", "אabc", "autoHebrew.dir", "rtl"),
            ("autoLatin", "abcא", "autoLatin.dir", "ltr"),
            ("autoHidden", "אabc", "autoHidden.dir", "rtl"),
        ] {
            assert!(
                has_adjacent(expected.0, expected.1, expected.2, expected.3),
                "{expected:?} in {:?}",
                fields.fields
            );
        }
        for name in [
            "dirNumber",
            "dirRange",
            "dirColor",
            "dirDate",
            "dirCheckbox",
            "dirRadio",
        ] {
            let companion = format!("{name}.dir");
            assert!(!fields.fields.iter().any(|(field, _)| field == &companion));
        }
    }

    #[test]
    fn auto_dirname_credential_entries_follow_overridden_values() {
        let page = r#"<form method="post" action="login"><input type="hidden" name="execution" value="source-token"><input type="text" name="username" dir="auto" dirname="username.dir"><input type="password" name="password" dir="auto" dirname="password.dir"><input type="submit" name="submit" value="LOGIN"></form>"#;
        let fields = login_fields(page, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_interaction_review(&fields));
        let values = login_form_values(&fields, "אlice", "secret");
        for expected in [
            ("username", "אlice"),
            ("username.dir", "rtl"),
            ("password", "secret"),
            ("password.dir", "ltr"),
        ] {
            assert!(values.contains(&expected), "{expected:?} in {values:?}");
        }
    }

    #[test]
    fn dirname_auto_includes_noscript_text_without_admitting_challenge_prose() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<div dir="auto"><noscript>א CAPTCHA</noscript><input name="notes" value="source" dirname="notes.dir"></div></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_interaction_review(&fields));
        assert!(!requires_challenge(&fields));
        let values = login_form_values(&fields, "student", "synthetic-password");
        assert!(
            values
                .windows(2)
                .any(|pair| pair == [("notes", "source"), ("notes.dir", "rtl")])
        );
    }

    #[test]
    fn credential_role_collisions_from_dirname_require_review() {
        for role in ["USERNAME", "PASSWORD"] {
            let page = REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                &format!(r#"<input name="notes" type="text" dirname="{role}"></form>"#),
            );
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert_eq!(
                fields.interaction_reason,
                Some("credential_dirname_collision")
            );
            assert!(requires_interaction_review(&fields));
            assert_eq!(
                fields
                    .fields
                    .iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case(role))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn template_implicit_label_targets_the_first_live_control() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<label><template><input name="template-decoy"></template>Verification code<input name="live-answer" required></label></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert_eq!(
            fields.interaction_reason,
            Some("unreviewed_challenge_control")
        );
        assert!(requires_interaction_review(&fields));
        let rejected = fields.first_rejected_control.as_ref().unwrap();
        assert_eq!(rejected.tag, "input");
        assert!(rejected.challenge_marker);
    }

    #[test]
    fn range_decimal_step_alignment_matches_chromium_formdata() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input name="rangeDecimalBound" type="range" min="0" max="0.3" step="0.1" value="0.3"><input name="rangeDecimalAlignment" type="range" min="0" max="1" step="0.1" value="0.26"><input name="rangeDecimalTie" type="range" min="0" max="1" step="0.1" value="0.25"><input name="rangeBelowMidpoint" type="range" min="0" max="1e308" step="1e308" value="4.999999999999999e307"><input name="rangeSingleValue" type="range" min="99.99999999999999" max="99.99999999999999" value="99.99999999999999"><input name="rangeExtreme" type="range" min="-1e308" max="1e308" step="1e308" value="6e307"></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        for expected in [
            ("rangeDecimalBound", "0.3"),
            ("rangeDecimalAlignment", "0.3"),
            ("rangeDecimalTie", "0.3"),
            ("rangeBelowMidpoint", "0"),
            // Chromium's FormData oracle serializes this near-boundary source
            // range as 100; preserve the observed native result exactly.
            ("rangeSingleValue", "100"),
            ("rangeExtreme", "1e+308"),
        ] {
            assert!(
                fields
                    .fields
                    .iter()
                    .any(|(name, value)| { (name.as_str(), value.as_str()) == expected }),
                "{expected:?} in {:?}",
                fields.fields
            );
        }
    }

    #[test]
    fn split_initial_text_requires_review_before_credential_post() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            "</form><main>verification-<span>code</span> required</main>",
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_challenge(&fields));
        assert!(requires_interaction_review(&fields));
        assert_eq!(classify(&fields), FailureClass::UnsafeInteraction);
        let inspection = inspect_supplied_page(&page);
        assert_eq!(inspection["active_challenge_control"], false);
        assert_eq!(inspection["form"]["interaction_review_required"], true);
        assert!(inspection["form"]["first_rejected_control"].is_null());
    }

    #[test]
    fn every_supported_challenge_text_marker_vetoes_without_confirming_controls() {
        for marker in CHALLENGE_MARKERS {
            let text = format!("Enter {marker}");
            let fields = login_fields(&text, LoginSourceScope::FinalResponse).unwrap();
            assert!(!requires_challenge(&fields), "{marker}");
            assert!(fields.has_unverified_challenge_text, "{marker}");
            assert_eq!(classify(&fields), FailureClass::UnsafeInteraction);
            assert!(!final_response_is_admissible(
                CLASSROOM_HOST,
                200,
                &text,
                false,
                fields.has_unverified_challenge_text,
                None,
                FailureClass::UnsafeInteraction,
            ));
        }
    }

    #[test]
    fn split_active_response_text_is_review_only_and_vetoes_admission() {
        for body in [
            "<main>CAP<span>TCHA</span></main>",
            "<main>请输入校<span>验码</span></main>",
            "<main>verification-<span>code</span></main>",
            "<main>verification<span>code</span></main>",
        ] {
            let fields = login_fields(body, LoginSourceScope::FinalResponse).unwrap();
            assert!(!requires_challenge(&fields));
            assert!(fields.has_unverified_challenge_text);
            assert_eq!(classify(&fields), FailureClass::UnsafeInteraction);
            assert!(!final_response_is_admissible(
                CLASSROOM_HOST,
                200,
                body,
                false,
                fields.has_unverified_challenge_text,
                None,
                classify(&fields),
            ));
        }
    }

    #[test]
    fn login_safety_includes_external_and_unnamed_associated_controls() {
        let verification = format!(
            r#"{REVIEWED_LOGIN_PAGE}<input form="loginForm" name="verificationCode" required>"#
        );
        assert!(requires_challenge(
            &login_fields(&verification, LoginSourceScope::CredentialForm).unwrap()
        ));
        for page in [
            format!(
                r#"{REVIEWED_LOGIN_PAGE}<textarea form="loginForm" name="externalNotes" required>source note</textarea>"#
            ),
            REVIEWED_LOGIN_PAGE.replace("</form>", "<input required></form>"),
        ] {
            let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
            assert!(!requires_interaction_review(&fields));
            assert!(!requires_challenge(&fields));
        }
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<input form="other" name="captcha" required></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(requires_challenge(&fields));
        let page = format!(
            r#"{REVIEWED_LOGIN_PAGE}<form id="other"><input name="verificationCode" required></form>"#
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(requires_challenge(&fields));
    }

    #[test]
    fn template_forms_and_controls_cannot_supply_credentials_or_payload() {
        let template_only = r#"<template><form method="post" action="login"><input name="username" type="text"><input name="password" type="password"><input name="execution" value="token"></form></template>"#;
        assert!(login_fields(template_only, LoginSourceScope::CredentialForm).is_err());

        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r#"<template><input name="password" type="password" value="template-secret"><input name="templateExtra" value="not-submitted"></template><div inert><input name="inertOrdinary" value="source-value"></div></form>"#,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_interaction_review(&fields));
        assert!(!requires_challenge(&fields));
        assert!(!fields.fields.iter().any(|(name, value)| {
            name == "templateExtra" || name == "password" && value == "template-secret"
        }));
        assert!(
            fields
                .fields
                .iter()
                .any(|(name, value)| name == "inertOrdinary" && value == "source-value")
        );

        let template_execution = REVIEWED_LOGIN_PAGE.replace(
            r#"<input name="execution" type="hidden" value="synthetic-execution-token">"#,
            r#"<select name="execution"><template><option selected value="template-token">Token</option></template></select>"#,
        );
        let fields = login_fields(&template_execution, LoginSourceScope::CredentialForm).unwrap();
        assert!(
            !fields
                .fields
                .iter()
                .any(|(name, value)| name == "execution" && !value.is_empty())
        );
    }

    #[test]
    fn template_options_do_not_override_selected_or_derived_option_text() {
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            r##"<select name="choice"><template><option selected value="template">Template</option></template><option value="visible" selected>Visible</option></select><select name="label"><option selected>Visible<script>hidden script</script><template>hidden template</template> label</option></select></form>"##,
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(
            fields
                .fields
                .iter()
                .any(|(name, value)| name == "choice" && value == "visible")
        );
        assert!(
            fields
                .fields
                .iter()
                .any(|(name, value)| name == "label" && value == "Visible label")
        );
    }

    #[test]
    fn credential_controls_are_unique_typed_elements_not_only_names() {
        for control in [
            r#"<input name="username" type="checkbox" required>"#,
            r#"<input name="username" type="text" required>"#,
            r#"<input name="password" type="password" required>"#,
        ] {
            let inside = REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>"));
            assert_unreviewed_interaction(
                &login_fields(&inside, LoginSourceScope::CredentialForm).unwrap(),
            );
            let outside = format!(
                "{REVIEWED_LOGIN_PAGE}{}",
                control.replace("<input ", "<input form=\"loginForm\" ")
            );
            assert_unreviewed_interaction(
                &login_fields(&outside, LoginSourceScope::CredentialForm).unwrap(),
            );
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
            assert_unreviewed_interaction(
                &login_fields(&page, LoginSourceScope::CredentialForm).unwrap(),
            );
        }
        let required_credentials = REVIEWED_LOGIN_PAGE
            .replace(
                r#"name="username" type="text""#,
                r#"name="username" type="text" required"#,
            )
            .replace(
                r#"name="password" type="password""#,
                r#"name="password" type="password" required"#,
            );
        assert!(!requires_interaction_review(
            &login_fields(&required_credentials, LoginSourceScope::CredentialForm).unwrap()
        ));
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
        assert_unreviewed_interaction(
            &login_fields(&page, LoginSourceScope::CredentialForm).unwrap(),
        );
        let page = wrap("<fieldset disabled><legend>", "</legend></fieldset>");
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_challenge(&fields));
        assert!(!requires_interaction_review(&fields));
        let page = wrap(
            "<fieldset disabled><legend>caption</legend><legend>",
            "</legend></fieldset>",
        );
        assert_unreviewed_interaction(
            &login_fields(&page, LoginSourceScope::CredentialForm).unwrap(),
        );
        let page = wrap(
            "<fieldset disabled><legend><fieldset disabled><legend>inner</legend>",
            "</fieldset></legend></fieldset>",
        );
        assert_unreviewed_interaction(
            &login_fields(&page, LoginSourceScope::CredentialForm).unwrap(),
        );
        let page = REVIEWED_LOGIN_PAGE.replace(
            "</form>",
            "<fieldset disabled><input name=\"extra\" required></fieldset></form>",
        );
        let fields = login_fields(&page, LoginSourceScope::CredentialForm).unwrap();
        assert!(!requires_challenge(&fields));
        assert!(!requires_interaction_review(&fields));
    }

    #[test]
    fn final_response_scans_secondary_challenges_without_credential_form_identity() {
        for body in [
            r#"<form method="post" action="/login"><label>CAP<span>TCHA</span><input name="answer"></label></form>"#,
            r#"<label for="answer">CAP<span>TCHA</span></label><form id="secondary"><input id="answer" name="answer"></form>"#,
            r#"<label for="answer">CAP<span>TCHA</span></label><input id="answer" name="answer">"#,
        ] {
            let fields = login_fields(body, LoginSourceScope::FinalResponse)
                .expect("secondary response controls are analyzed without credentials");
            assert!(!fields.has_password_control);
            assert!(!requires_challenge(&fields));
            assert!(requires_interaction_review(&fields));
            let class = classify(&fields);
            assert_eq!(class, FailureClass::UnsafeInteraction);
            assert!(!final_response_is_admissible(
                CLASSROOM_HOST,
                200,
                body,
                false,
                fields.has_unverified_challenge_text,
                None,
                class,
            ));
        }
        for body in [
            "<main>Course</main>",
            r#"<form><input name="query" required></form>"#,
            r#"<template><label>CAP<span>TCHA</span><input name="answer"></label></template>"#,
            "<script>CAPTCHA challenge</script>",
            "<style>verification-code</style>",
            "<noscript>校验码</noscript>",
        ] {
            let fields = login_fields(body, LoginSourceScope::FinalResponse)
                .expect("ordinary application response does not require a login form");
            assert!(!fields.has_password_control);
            assert!(!requires_challenge(&fields));
            assert!(!requires_interaction_review(&fields));
            assert!(final_response_is_admissible(
                CLASSROOM_HOST,
                200,
                body,
                false,
                fields.has_unverified_challenge_text,
                None,
                classify(&fields),
            ));
        }
        let disabled_prompt = r#"<form><fieldset disabled><label>CAP<span>TCHA</span><input name="answer"></label></fieldset></form>"#;
        let disabled_fields =
            login_fields(disabled_prompt, LoginSourceScope::FinalResponse).unwrap();
        assert!(!requires_challenge(&disabled_fields));
        assert!(requires_interaction_review(&disabled_fields));
        assert_eq!(classify(&disabled_fields), FailureClass::UnsafeInteraction);
        assert!(!final_response_is_admissible(
            CLASSROOM_HOST,
            200,
            disabled_prompt,
            false,
            disabled_fields.has_unverified_challenge_text,
            None,
            FailureClass::UnsafeInteraction,
        ));

        let inert_prompt =
            r#"<div inert><label>CAP<span>TCHA</span><input name="answer"></label></div>"#;
        let inert_fields = login_fields(inert_prompt, LoginSourceScope::FinalResponse).unwrap();
        assert!(!requires_challenge(&inert_fields));
        assert!(!requires_interaction_review(&inert_fields));
        assert!(final_response_is_admissible(
            CLASSROOM_HOST,
            200,
            inert_prompt,
            false,
            inert_fields.has_unverified_challenge_text,
            None,
            FailureClass::Unknown,
        ));
        for body in [
            r#"<form><input name="password" type="password"></form>"#,
            r#"<input type="password">"#,
            r#"<input name="password" type="text">"#,
        ] {
            let fields = login_fields(body, LoginSourceScope::FinalResponse)
                .expect("remaining password controls are observed without execution metadata");
            assert!(fields.has_password_control);
        }
    }

    #[test]
    fn cookie_identity_ignores_host_only_flag_for_replacement_deletion_and_reload() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let set = |jar: &mut Jar, value: &str, domain: &str, max_age: u32| {
            let mut headers = HeaderMap::new();
            headers.insert(
                SET_COOKIE,
                HeaderValue::from_str(&format!("sid={value}; Path=/; Max-Age={max_age}{domain}"))
                    .unwrap(),
            );
            jar.absorb(&origin, &headers).unwrap();
        };
        for (old_domain, new_domain) in [
            ("", "; Domain=classroom.msa.buaa.edu.cn"),
            ("; Domain=classroom.msa.buaa.edu.cn", ""),
        ] {
            for replacement in ["", "new"] {
                let mut jar = Jar::default();
                set(&mut jar, "old", old_domain, 3600);
                set(&mut jar, replacement, new_domain, 3600);
                assert_eq!(
                    jar.header(&origin).unwrap().to_str().unwrap(),
                    format!("sid={replacement}")
                );
                set(&mut jar, "", old_domain, 0);
                assert!(jar.header(&origin).is_none());
            }
        }

        let mut old_jar = Jar::default();
        set(&mut old_jar, "old", "", 3600);
        let mut duplicate = old_jar.cookies[0].clone();
        duplicate.scope = Scope::Platform(CLASSROOM_HOST.to_owned());
        duplicate.value = "new".to_owned();
        old_jar.cookies.push(duplicate);
        let (directory, _) = temporary_directory("duplicate-cookie-identity");
        let fingerprint = account_fingerprint("student");
        store_session(&directory, &fingerprint, &old_jar).expect("write old ambiguous snapshot");
        assert!(stored_session_in(&directory, &fingerprint).is_err());
    }

    #[test]
    fn cookie_identity_keeps_distinct_host_and_parent_domain_through_narrowed_delivery() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let set = |jar: &mut Jar, value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(SET_COOKIE, HeaderValue::from_str(value).unwrap());
            jar.absorb(&origin, &headers).unwrap();
        };

        // A host-only cookie and a foreign-family parent-domain cookie stay
        // distinct identities even though the parent domain is narrowed to
        // the setter for delivery; replacing one never touches the other.
        let mut jar = Jar::default();
        set(&mut jar, "sid=host; Path=/; Max-Age=3600");
        set(
            &mut jar,
            "sid=parent; Path=/; Domain=buaa.edu.cn; Max-Age=3600",
        );
        assert_eq!(jar.cookies.len(), 2);
        assert_eq!(jar.cookies[0].value, "host");
        assert_eq!(jar.cookies[1].value, "parent");
        assert_eq!(
            jar.header(&origin).unwrap().to_str().unwrap(),
            "sid=host; sid=parent"
        );
        set(&mut jar, "sid=host2; Path=/; Max-Age=3600");
        assert_eq!(jar.cookies.len(), 2);
        assert_eq!(jar.cookies[0].value, "host2");
        assert_eq!(
            jar.header(&origin).unwrap().to_str().unwrap(),
            "sid=host2; sid=parent"
        );

        // Deleting the parent-domain identity never deletes the host cookie,
        // which still reaches actual requests afterwards.
        set(&mut jar, "sid=; Path=/; Domain=buaa.edu.cn; Max-Age=0");
        assert_eq!(jar.cookies.len(), 1);
        assert_eq!(jar.cookies[0].value, "host2");
        assert_eq!(jar.header(&origin).unwrap().to_str().unwrap(), "sid=host2");

        // Host-only and Domain declarations for the same canonical domain
        // remain one identity for replacement and deletion.
        set(
            &mut jar,
            "sid=canonical; Path=/; Domain=classroom.msa.buaa.edu.cn; Max-Age=3600",
        );
        assert_eq!(jar.cookies.len(), 1);
        assert_eq!(jar.cookies[0].value, "canonical");
        set(&mut jar, "sid=; Path=/; Max-Age=0");
        assert!(jar.cookies.is_empty());
        assert!(jar.header(&origin).is_none());

        // Private storage preserves both distinct identities and their
        // narrowed delivery through a reload.
        let mut jar = Jar::default();
        set(&mut jar, "sid=host; Path=/; Max-Age=3600");
        set(
            &mut jar,
            "sid=parent; Path=/; Domain=buaa.edu.cn; Max-Age=3600",
        );
        let (directory, _) = temporary_directory("narrowed-parent-domain-identity");
        let fingerprint = account_fingerprint("student");
        store_session(&directory, &fingerprint, &jar).expect("store narrowed identities");
        let loaded =
            stored_session_in(&directory, &fingerprint).expect("reload narrowed identities");
        assert_eq!(loaded.cookies.len(), 2);
        assert_eq!(loaded.cookies[0].value, "host");
        assert_eq!(loaded.cookies[1].value, "parent");
        assert_eq!(
            loaded.header(&origin).unwrap().to_str().unwrap(),
            "sid=host; sid=parent"
        );

        // A narrowed cookie keeps its narrowed delivery after reload: its
        // declared parent domain never widens delivery to a sibling host.
        let yjapi = Url::parse("https://yjapi.msa.buaa.edu.cn/").unwrap();
        assert!(loaded.header(&yjapi).is_none());

        // Reload fails closed on anything the setter could not have produced:
        // legacy version-2 snapshots, noncanonical or foreign declared
        // domains and duplicate narrowed identities.
        let (directory, path) = temporary_directory("narrowed-declared-validation");
        let fingerprint = account_fingerprint("student");
        let target = path.join(format!("{fingerprint}.session"));
        let write_snapshot = |version: u8, cookies: &[Cookie]| {
            let refs: Vec<&Cookie> = cookies.iter().collect();
            let bytes = serde_json::to_vec(&StoredSessionRef {
                version,
                cookies: &refs,
            })
            .unwrap();
            std::fs::write(&target, bytes).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write_snapshot(2, &[jar.cookies[0].clone()]);
        assert!(stored_session_in(&directory, &fingerprint).is_err());
        let narrowed = jar.cookies[1].clone();
        for declared in [
            Some(String::new()),
            Some(".buaa.edu.cn".to_owned()),
            Some("BUAA.edu.cn".to_owned()),
            Some("msa.buaa.edu.cn".to_owned()),
            Some("evil.example".to_owned()),
        ] {
            let mut forged = narrowed.clone();
            forged.declared_domain = declared;
            write_snapshot(3, &[jar.cookies[0].clone(), forged.clone()]);
            assert!(
                stored_session_in(&directory, &fingerprint).is_err(),
                "{:?}",
                forged.declared_domain
            );
        }
        let mut duplicate = narrowed.clone();
        duplicate.value = "other".to_owned();
        write_snapshot(3, &[narrowed, duplicate]);
        assert!(stored_session_in(&directory, &fingerprint).is_err());
    }

    #[test]
    fn cookie_headers_prioritize_longest_paths_and_preserve_creation_order() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let mut jar = Jar::default();
        let mut headers = HeaderMap::new();
        for value in [
            "sid=wide; Path=/",
            "left=one; Path=/",
            "sid=scoped; Path=/courseapi",
            "right=two; Path=/",
        ] {
            headers.append(SET_COOKIE, HeaderValue::from_static(value));
        }
        jar.absorb(&origin, &headers).unwrap();
        let scoped = origin.join("/courseapi/v3/probe").unwrap();
        assert_eq!(
            jar.header(&scoped).unwrap().to_str().unwrap(),
            "sid=scoped; sid=wide; left=one; right=two"
        );

        let (directory, _) = temporary_directory("cookie-order-round-trip");
        let fingerprint = account_fingerprint("student");
        store_session(&directory, &fingerprint, &jar).unwrap();
        let mut credentials = SessionCredentials {
            supplied: None,
            stored: stored_session_in(&directory, &fingerprint).unwrap(),
        };
        assert_eq!(
            credentials
                .with_header(&scoped, |header, _| Ok(header.to_owned()))
                .unwrap(),
            "sid=scoped; sid=wide; left=one; right=two"
        );

        let mut replacement = HeaderMap::new();
        replacement.insert(
            SET_COOKIE,
            HeaderValue::from_static("left=replaced; Path=/; Max-Age=3600"),
        );
        credentials.stored.absorb(&origin, &replacement).unwrap();
        assert_eq!(
            credentials
                .stored
                .header(&origin)
                .unwrap()
                .to_str()
                .unwrap(),
            "sid=wide; left=replaced; right=two"
        );
    }

    #[test]
    fn final_password_veto_is_independent_of_successful_control_disabledness() {
        for body in [
            r#"<form><input name="password" type="password" disabled></form>"#,
            r#"<form><fieldset disabled><input type="password"></fieldset></form>"#,
            r#"<form><fieldset disabled><legend>Caption</legend><input name="password" type="text"></fieldset></form>"#,
        ] {
            let fields = login_fields(body, LoginSourceScope::FinalResponse).unwrap();
            assert!(fields.has_password_control);
        }
        for body in [
            r#"<template><input name="password" type="password" disabled></template>"#,
            r#"<div inert><input name="password" type="password" disabled></div>"#,
        ] {
            let fields = login_fields(body, LoginSourceScope::FinalResponse).unwrap();
            assert!(!fields.has_password_control);
        }
    }

    #[test]
    fn auxiliary_challenge_labels_require_review_not_confirmed_challenge() {
        for attribute in ["aria-label", "placeholder", "title"] {
            let control = format!(r#"<input name="answer" {attribute}="Verification code">"#);
            for (scope, page) in [
                (
                    LoginSourceScope::CredentialForm,
                    REVIEWED_LOGIN_PAGE.replace("</form>", &format!("{control}</form>")),
                ),
                (LoginSourceScope::FinalResponse, control),
            ] {
                let fields = login_fields(&page, scope).unwrap();
                assert!(!requires_challenge(&fields));
                assert!(requires_interaction_review(&fields));
                assert_eq!(classify(&fields), FailureClass::UnsafeInteraction);
            }
        }
        let fields = login_fields(
            &REVIEWED_LOGIN_PAGE.replace(
                "</form>",
                r#"<input name="otp" autocomplete="one-time-code" required></form>"#,
            ),
            LoginSourceScope::CredentialForm,
        )
        .unwrap();
        assert!(!requires_challenge(&fields));
        assert!(requires_interaction_review(&fields));
        assert_eq!(classify(&fields), FailureClass::UnsafeInteraction);
        let fields = login_fields(
            r#"<form><input name="otp" autocomplete="one-time-code" required></form>"#,
            LoginSourceScope::FinalResponse,
        )
        .unwrap();
        assert!(!requires_challenge(&fields));
        assert!(requires_interaction_review(&fields));
        assert_eq!(classify(&fields), FailureClass::UnsafeInteraction);
        for (scope, page) in [
            (
                LoginSourceScope::CredentialForm,
                REVIEWED_LOGIN_PAGE.replace(
                    "</form>",
                    r#"<input type="hidden" name="otp" autocomplete="one-time-code"></form>"#,
                ),
            ),
            (
                LoginSourceScope::FinalResponse,
                r#"<input type="hidden" name="otp" autocomplete="one-time-code">"#.to_owned(),
            ),
        ] {
            let fields = login_fields(&page, scope).unwrap();
            assert!(!requires_challenge(&fields));
            assert!(!requires_interaction_review(&fields));
        }
    }

    #[test]
    fn an_empty_cookie_replaces_the_old_token_and_round_trips_privately() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let mut jar = Jar::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("sid=old; Path=/; Max-Age=3600"),
        );
        jar.absorb(&origin, &headers).unwrap();
        assert_eq!(jar.header(&origin).unwrap().to_str().unwrap(), "sid=old");
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("sid=; Path=/; Max-Age=3600"),
        );
        jar.absorb(&origin, &headers).unwrap();
        assert_eq!(jar.header(&origin).unwrap().to_str().unwrap(), "sid=");

        let (directory, _) = temporary_directory("empty-cookie-replacement");
        let fingerprint = account_fingerprint("student");
        store_session(&directory, &fingerprint, &jar).expect("store empty replacement");
        let credentials = SessionCredentials {
            supplied: None,
            stored: stored_session_in(&directory, &fingerprint).expect("load empty replacement"),
        };
        assert_eq!(
            credentials
                .with_header(&origin, |header, _| Ok(header.to_owned()))
                .unwrap(),
            "sid="
        );

        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("sid=; Path=/; Max-Age=0"),
        );
        jar.absorb(&origin, &headers).unwrap();
        assert!(jar.header(&origin).is_none());
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
    fn max_age_deletes_seeded_cookie_below_i64_min_with_optional_expires() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let future =
            chrono::DateTime::<chrono::Utc>::from(SystemTime::now() + Duration::from_secs(86400))
                .to_rfc2822();
        let max_age = "-9223372036854775809";
        for attributes in [
            format!("Max-Age={max_age}"),
            format!("Max-Age={max_age}; Expires={future}"),
            format!("Expires={future}; Max-Age={max_age}"),
        ] {
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
                HeaderValue::from_str(&format!("session=replaced; Path=/; {attributes}")).unwrap(),
            );
            jar.absorb(&origin, &deletion).unwrap();
            assert!(jar.header(&origin).is_none(), "{attributes}");
        }
    }

    #[test]
    fn malformed_and_over_cap_positive_max_age_preserve_seeded_cookie() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        for max_age in ["1.5".to_string(), (MAX_COOKIE_AGE + 1).to_string()] {
            let mut jar = Jar::default();
            let mut initial = HeaderMap::new();
            initial.insert(
                SET_COOKIE,
                HeaderValue::from_static("session=original; Path=/"),
            );
            jar.absorb(&origin, &initial).unwrap();

            let mut replacement = HeaderMap::new();
            replacement.insert(
                SET_COOKIE,
                HeaderValue::from_str(&format!("session=replaced; Path=/; Max-Age={max_age}"))
                    .unwrap(),
            );
            jar.absorb(&origin, &replacement).unwrap();
            assert_eq!(
                jar.header(&origin).unwrap(),
                "session=original",
                "{max_age}"
            );
        }
    }

    #[test]
    fn max_age_deletes_seeded_cookie_despite_invalid_expires_in_either_order() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        for max_first in [false, true] {
            let attributes = if max_first {
                "Max-Age=0; Expires=not-a-date"
            } else {
                "Expires=not-a-date; Max-Age=0"
            };
            let mut jar = Jar::default();
            let mut initial = HeaderMap::new();
            initial.insert(SET_COOKIE, HeaderValue::from_static("sid=original; Path=/"));
            jar.absorb(&origin, &initial).unwrap();
            let mut deletion = HeaderMap::new();
            deletion.insert(
                SET_COOKIE,
                HeaderValue::from_str(&format!("sid=; Path=/; {attributes}")).unwrap(),
            );
            jar.absorb(&origin, &deletion).unwrap();
            assert!(jar.header(&origin).is_none());
        }
    }

    #[test]
    fn rfc6265_cookie_dates_delete_seeded_credentials_only_when_calendar_valid() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        for (date, deletes) in [
            // RFC 6265's asctime form, and non-RFC-2822 forms that exercise
            // hyphen delimiters and two-digit year mapping to 1970 and 2000.
            ("Thu Jan 01 00:00:00 1970", true),
            ("Thursday, 01-Jan-70 00:00:00 GMT", true),
            ("01-Jan-00 00:00:00 GMT", true),
            // Invalid calendar fields, missing fields and years before 1601
            // must not be interpreted as credential-deletion instructions.
            ("Thu Jan 32 00:00:00 1970", false),
            ("Thu Feb 29 00:00:00 1970", false),
            ("Thu Jan 01 24:00:00 1970", false),
            ("Thu Jan 01 00:00:60 1970", false),
            ("Thu, 01junk Jan 1970 00:00:00 GMT", false),
            ("Thu, 01 Jan 1970junk 00:00:00 GMT", false),
            ("Thu, 01 Jan 1970 00:00:00junk GMT", false),
            ("Thu Foo 01 00:00:00 1970", false),
            ("Thu Jan3 01 00:00:00 1970", false),
            ("Thu Jan 01 00:00:00 1600", false),
            ("Thu Jan 01 1970", false),
        ] {
            let mut jar = Jar::default();
            let mut initial = HeaderMap::new();
            initial.insert(SET_COOKIE, HeaderValue::from_static("sid=original; Path=/"));
            jar.absorb(&origin, &initial).unwrap();

            let mut deletion = HeaderMap::new();
            deletion.insert(
                SET_COOKIE,
                HeaderValue::from_str(&format!("sid=; Path=/; Expires={date}")).unwrap(),
            );
            jar.absorb(&origin, &deletion).unwrap();

            if deletes {
                assert!(jar.header(&origin).is_none(), "{date}");
            } else {
                assert_eq!(jar.header(&origin).unwrap(), "sid=original", "{date}");
            }
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
    fn sso_domain_cookie_remains_confined_and_overlong_replacement_is_rejected() {
        let sso = Url::parse("https://sso.buaa.edu.cn/login").unwrap();
        let callback = Url::parse("https://yjapi.msa.buaa.edu.cn/casapi/index.php").unwrap();
        let mut jar = Jar::default();
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("opaque_session=old; Domain=buaa.edu.cn; Path=/; Max-Age=3600"),
        );
        jar.absorb(&sso, &headers).unwrap();
        assert_eq!(jar.header(&sso).unwrap(), "opaque_session=old");
        assert!(jar.header(&callback).is_none());

        let mut overlong = HeaderMap::new();
        overlong.append(
            SET_COOKIE,
            HeaderValue::from_static(
                "opaque_session=new; Domain=buaa.edu.cn; Path=/; Max-Age=34560000",
            ),
        );
        jar.absorb(&sso, &overlong).unwrap();
        assert_eq!(jar.header(&sso).unwrap(), "opaque_session=old");
        assert!(jar.header(&callback).is_none());
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
    fn cookie_prefix_requirements_apply_on_set_and_private_reload() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let mut headers = HeaderMap::new();
        for value in [
            "__Secure-missing=bad; Path=/",
            "__Secure-valid=secure; Secure; Path=/",
            "__Host-domain=bad; Secure; Domain=classroom.msa.buaa.edu.cn; Path=/",
            "__Host-path=bad; Secure; Path=/courseapi",
            "__Host-default=bad; Secure",
            "__Host-valid=host; Secure; Path=/",
            "__Http-missing=bad; Secure; Path=/",
            "__Http-valid=http; Secure; HttpOnly; Path=/",
            "__Host-Http-valid=hosthttp; Secure; HttpOnly; Path=/",
        ] {
            headers.append(SET_COOKIE, HeaderValue::from_static(value));
        }
        let mut jar = Jar::default();
        jar.absorb(&origin, &headers).unwrap();
        let expected = "__Secure-valid=secure; __Host-valid=host; __Http-valid=http; __Host-Http-valid=hosthttp";
        assert_eq!(jar.header(&origin).unwrap().to_str().unwrap(), expected);

        let (directory, _) = temporary_directory("cookie-prefix-round-trip");
        let fingerprint = account_fingerprint("student");
        store_session(&directory, &fingerprint, &jar).expect("store valid prefixes");
        let credentials = SessionCredentials {
            supplied: None,
            stored: stored_session_in(&directory, &fingerprint).expect("load valid prefixes"),
        };
        assert_eq!(
            credentials
                .with_header(&origin, |header, _| Ok(header.to_owned()))
                .unwrap(),
            expected
        );

        let invalid = Cookie {
            name: "__Host-forged".into(),
            value: "token".into(),
            scope: Scope::Host(CLASSROOM_HOST.into()),
            path: "/".into(),
            expiry: None,
            secure: false,
            http_only: false,
            host_only: true,
            path_explicit: false,
            declared_domain: None,
        };
        let (directory, path) = temporary_directory("cookie-prefix-forged-snapshot");
        let fingerprint = account_fingerprint("student");
        let bytes = serde_json::to_vec(&StoredSessionRef {
            version: 3,
            cookies: &[&invalid],
        })
        .unwrap();
        let target = path.join(format!("{fingerprint}.session"));
        std::fs::write(&target, bytes).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(stored_session_in(&directory, &fingerprint).is_err());
    }

    #[test]
    fn expired_cookie_positions_cannot_evict_or_reorder_fresh_sessions() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let mut jar = Jar::default();
        let mut initial = HeaderMap::new();
        for index in 0..MAX_COOKIE_COUNT {
            let name = if index == 0 {
                "sid".to_owned()
            } else {
                format!("expired{index}")
            };
            initial.append(
                SET_COOKIE,
                HeaderValue::from_str(&format!("{name}=old; Path=/")).unwrap(),
            );
        }
        jar.absorb(&origin, &initial).unwrap();
        for cookie in &mut jar.cookies {
            cookie.expiry = Some(UNIX_EPOCH);
        }
        let mut fresh = HeaderMap::new();
        fresh.append(
            SET_COOKIE,
            HeaderValue::from_static("sid=fresh; Path=/; Max-Age=3600"),
        );
        fresh.append(
            SET_COOKIE,
            HeaderValue::from_static("aux=1; Path=/; Max-Age=3600"),
        );
        jar.absorb(&origin, &fresh).unwrap();
        assert_eq!(jar.header(&origin).unwrap(), "sid=fresh; aux=1");

        let mut jar = Jar::default();
        let mut initial = HeaderMap::new();
        initial.append(SET_COOKIE, HeaderValue::from_static("sid=old; Path=/"));
        initial.append(
            SET_COOKIE,
            HeaderValue::from_static("sid=domain; Domain=.msa.buaa.edu.cn; Path=/"),
        );
        jar.absorb(&origin, &initial).unwrap();
        jar.cookies[0].expiry = Some(UNIX_EPOCH);
        let mut fresh = HeaderMap::new();
        fresh.append(SET_COOKIE, HeaderValue::from_static("sid=fresh; Path=/"));
        jar.absorb(&origin, &fresh).unwrap();
        assert_eq!(jar.header(&origin).unwrap(), "sid=domain; sid=fresh");
    }

    #[test]
    fn quoted_cookie_values_round_trip_and_unpaired_quotes_preserve_old_value() {
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let mut jar = Jar::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("sid=\"token\"; Path=/"),
        );
        jar.absorb(&origin, &headers).unwrap();
        assert_eq!(
            jar.header(&origin).unwrap().to_str().unwrap(),
            "sid=\"token\""
        );

        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("sid=\"rotated\"; Path=/"),
        );
        jar.absorb(&origin, &headers).unwrap();
        headers.insert(SET_COOKIE, HeaderValue::from_static("sid=\"broken; Path=/"));
        jar.absorb(&origin, &headers).unwrap();
        assert_eq!(
            jar.header(&origin).unwrap().to_str().unwrap(),
            "sid=\"rotated\""
        );
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("sid=\"broken; Path=/; Max-Age=0"),
        );
        jar.absorb(&origin, &headers).unwrap();
        assert_eq!(
            jar.header(&origin).unwrap().to_str().unwrap(),
            "sid=\"rotated\""
        );

        let (directory, _) = temporary_directory("quoted-cookie-round-trip");
        let fingerprint = account_fingerprint("student");
        store_session(&directory, &fingerprint, &jar).unwrap();
        assert_eq!(
            stored_session_in(&directory, &fingerprint)
                .unwrap()
                .header(&origin)
                .unwrap()
                .to_str()
                .unwrap(),
            "sid=\"rotated\""
        );
    }

    #[test]
    fn url_shaped_cookie_values_are_kept_like_the_browser_does() {
        // RFC 6265 cookie-octet ranges already include ':' and '/'. A URL-
        // shaped value must survive the same bounded admission as other
        // values without relaxing the cookie grammar.
        let origin = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let mut jar = Jar::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("route=https://backend.example.test:8443; Path=/"),
        );
        jar.absorb(&origin, &headers).unwrap();
        assert_eq!(
            jar.header(&origin).unwrap().to_str().unwrap(),
            "route=https://backend.example.test:8443"
        );

        for invalid in [
            "route=value with spaces; Path=/",
            "route=value\\with\\slashes; Path=/",
            "route=value,other; Path=/",
        ] {
            headers.insert(SET_COOKIE, HeaderValue::from_str(invalid).unwrap());
            jar.absorb(&origin, &headers).unwrap();
            assert_eq!(
                jar.header(&origin).unwrap().to_str().unwrap(),
                "route=https://backend.example.test:8443"
            );
        }

        let (directory, _) = temporary_directory("url-shaped-cookie-round-trip");
        let fingerprint = account_fingerprint("student");
        store_session(&directory, &fingerprint, &jar).unwrap();
        assert_eq!(
            stored_session_in(&directory, &fingerprint)
                .unwrap()
                .header(&origin)
                .unwrap()
                .to_str()
                .unwrap(),
            "route=https://backend.example.test:8443"
        );
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
    fn html_typed_identity_probe_cannot_hide_challenge_controls_in_valid_json() {
        let url = Url::parse(
            "https://classroom.msa.buaa.edu.cn/courseapi/v3/portal-home-setting/get-sub-info",
        )
        .unwrap();
        for (body, expected) in [
            (
                r#"{"code":0,"data":{"course_id":"12","sub_id":"34"},"html":"<input name='captcha'>"}"#,
                Some(FailureClass::Challenge),
            ),
            (
                r#"{"code":0,"data":{"course_id":"12","sub_id":"34"},"html":"<input name='otp' autocomplete='one-time-code'>"}"#,
                Some(FailureClass::UnsafeInteraction),
            ),
            (
                r#"{"code":0,"data":{"course_id":"12","sub_id":"34"},"html":"<main>CAP<span>TCHA</span></main>"}"#,
                Some(FailureClass::UnsafeInteraction),
            ),
            (
                r#"{"code":0,"data":{"course_id":"12","sub_id":"34"}}"#,
                None,
            ),
        ] {
            let hop = Hop {
                status: 200,
                url: url.clone(),
                body: body.to_owned(),
                retry_after: None,
                challenge: false,
                content_type: Some("text/html; charset=UTF-8".to_owned()),
                redirected: false,
            };
            assert_eq!(identity_probe_interaction(&hop), expected);
            if expected.is_none() {
                assert!(validate_identity_probe(&hop, &url, "12", "34").is_ok());
            }
        }
        let mut declared_json = Hop {
            status: 200,
            url: url.clone(),
            body: r#"{"code":0,"data":{"course_id":"12","sub_id":"34"},"html":"<input name='captcha'>"}"#.to_owned(),
            retry_after: None,
            challenge: false,
            content_type: Some("application/json".to_owned()),
            redirected: false,
        };
        assert_eq!(identity_probe_interaction(&declared_json), None);
        declared_json.content_type = Some("application/xhtml+xml; charset=UTF-8".to_owned());
        assert_eq!(
            identity_probe_interaction(&declared_json),
            Some(FailureClass::UnsafeInteraction)
        );
    }

    #[test]
    fn final_post_response_parsing_respects_declared_mime() {
        let url = Url::parse(CLASSROOM_ORIGIN).unwrap();
        let body = r#"{"code":0,"data":{"course_id":"12","sub_id":"34"},"example":"<input name='captcha'>"}"#;
        let mut response = Hop {
            status: 200,
            url,
            body: body.to_owned(),
            retry_after: None,
            challenge: false,
            content_type: Some("text/html; charset=UTF-8".to_owned()),
            redirected: false,
        };
        let html = final_response_fields(&response).unwrap();
        assert!(requires_challenge(&html));
        response.content_type = Some("application/json; charset=UTF-8".to_owned());
        let json_response = final_response_fields(&response).unwrap();
        assert!(!requires_challenge(&json_response));
        assert!(!requires_interaction_review(&json_response));
        assert!(final_response_is_admissible(
            CLASSROOM_HOST,
            200,
            &response.body,
            false,
            false,
            None,
            FailureClass::Unknown,
        ));
        response.body = "<main>CAPTCHA</main>".to_owned();
        assert!(final_response_fields(&response).is_err());
        response.body = r#""<main>CAPTCHA</main>""#.to_owned();
        let json_string = final_response_fields(&response).unwrap();
        assert!(!requires_challenge(&json_string));
        assert!(!requires_interaction_review(&json_string));
        assert!(final_response_is_admissible(
            CLASSROOM_HOST,
            200,
            &response.body,
            false,
            false,
            None,
            FailureClass::Unknown,
        ));
        for mime in [None, Some("text/plain"), Some("application/octet-stream")] {
            response.content_type = mime.map(str::to_owned);
            assert!(final_response_fields(&response).is_err(), "{mime:?}");
        }
    }

    #[test]
    fn final_response_parse_refusal_reports_confirmed_header_challenge() {
        let response = Hop {
            status: 403,
            url: Url::parse(CLASSROOM_ORIGIN).unwrap(),
            body: "challenge body".to_owned(),
            retry_after: Some("0".to_owned()),
            challenge: true,
            content_type: Some("text/plain".to_owned()),
            redirected: false,
        };
        let parse_error = match final_response_fields(&response) {
            Err(error) => error,
            Ok(_) => panic!("unsupported MIME must refuse form parsing"),
        };
        let (class, outcome, error) = final_response_parse_failure(&response, parse_error);
        assert_eq!(class, FailureClass::Challenge);
        assert!(matches!(
            outcome,
            crate::governor::Outcome::Http {
                status: 403,
                retry_after: Some("0"),
                challenge: true,
                network_failure: false,
            }
        ));
        assert_eq!(error.message, challenge().message);
    }

    #[test]
    fn probe_header_challenge_overrides_text_only_interaction_review() {
        let probe = Hop {
            status: 200,
            url: Url::parse(CLASSROOM_ORIGIN).unwrap(),
            body: "CAPTCHA".to_owned(),
            retry_after: None,
            challenge: true,
            content_type: Some("text/html".to_owned()),
            redirected: false,
        };
        let interaction = identity_probe_interaction(&probe)
            .expect("active text marker requires interaction review");
        assert_eq!(interaction, FailureClass::UnsafeInteraction);
        let (class, outcome, error) = identity_probe_failure(&probe, interaction);
        assert_eq!(class, FailureClass::Challenge);
        assert!(matches!(outcome, crate::governor::Outcome::CaptchaRequired));
        assert_eq!(error.message, challenge().message);
    }

    #[test]
    fn unadmitted_2xx_retry_after_response_clears_without_latch() {
        let (_directory, path) = temporary_directory("unadmitted-2xx-retry-after");
        let governor = Governor::isolated_for_test(&path).expect("isolated governor");
        governor
            .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
            .expect("one authentication attempt");
        let mut lease = governor
            .try_acquire(RequestKind::Authentication)
            .expect("authentication lease");
        lease
            .observe_http(200, Some("0"), false)
            .expect("retain response cooldown");
        lease
            .finish(unadmitted_response_outcome(200, Some("0"), false))
            .expect("finish refused response");
        let status = governor.status().expect("governor status");
        assert!(!status.safety_latched);
        assert!(!status.authentication_armed);
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
            "narrow=value; wide=app"
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
                secure: false,
                http_only: false,
                host_only: true,
                path_explicit: false,
                declared_domain: None,
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
        let classify_page = |body| {
            let fields = login_fields(body, LoginSourceScope::FinalResponse).unwrap();
            classify(&fields)
        };
        assert_eq!(
            classify_page("用户名或密码错误"),
            FailureClass::CredentialRejected
        );
        assert_eq!(
            classify_page("service not found"),
            FailureClass::ServiceInvalid
        );
        assert_eq!(classify_page("nothing notable"), FailureClass::Unknown);
        assert_eq!(
            classify_page("CAS ticket invalid or expired"),
            FailureClass::TicketRejected
        );
        assert_eq!(
            classify_page("<script>Password error</script>"),
            FailureClass::Unknown
        );
        let challenged = ParsedLoginForm {
            fields: Vec::new(),
            has_active_challenge_control: true,
            ..ParsedLoginForm::default()
        };
        assert_eq!(classify(&challenged), FailureClass::Challenge);
    }

    #[test]
    fn the_hop_trail_preserves_known_host_routes_and_status() {
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

    #[test]
    fn login_form_values_override_only_credentials_and_preserve_source_pairs() {
        let form = ParsedLoginForm {
            fields: vec![
                ("userNAME".to_owned(), "source-user".to_owned()),
                ("username_note".to_owned(), "keep-user-note".to_owned()),
                ("password".to_owned(), "source-password".to_owned()),
                ("password_hint".to_owned(), "keep-password-hint".to_owned()),
                ("__extra".to_owned(), "keep-extra".to_owned()),
                ("execution".to_owned(), "first-token".to_owned()),
                ("execution".to_owned(), "second-token".to_owned()),
            ],
            ..ParsedLoginForm::default()
        };

        assert_eq!(
            login_form_values(&form, "synthetic-user", "synthetic-password"),
            [
                ("userNAME", "synthetic-user"),
                ("username_note", "keep-user-note"),
                ("password", "synthetic-password"),
                ("password_hint", "keep-password-hint"),
                ("__extra", "keep-extra"),
                ("execution", "first-token"),
                ("execution", "second-token"),
            ]
        );
    }

    #[test]
    fn urlencoded_form_body_normalizes_line_endings_in_names_and_values() {
        assert_eq!(
            form_urlencoded_body(&[
                ("hidden\nname", "left\nright"),
                ("check", "one\ntwo"),
                ("note", "line1\r\nline2"),
            ]),
            "hidden%0D%0Aname=left%0D%0Aright&check=one%0D%0Atwo&note=line1%0D%0Aline2"
        );
    }

    #[test]
    fn attempt_receipt_readback_redacts_path_matrix_and_query_key_credentials() {
        let (directory, path) = temporary_directory("attempt-route-redaction");
        let fingerprint = account_fingerprint("student");
        let from = Url::parse("https://yjapi.msa.buaa.edu.cn/casapi/index.php").expect("from");
        let redirect = Url::parse(
            "https://classroom.msa.buaa.edu.cn/login;jsessionid=redirect-matrix-secret?ticket=redirect-query-secret&ST-private-ticket&%53T-encoded-private-ticket=value-secret",
        )
        .expect("redirect");
        let direct = Url::parse(
            "https://classroom.msa.buaa.edu.cn/courseapi/v3/portal-home-setting/get-sub-info;jsessionid=direct-matrix-secret?sub_id=private-id",
        )
        .expect("direct");
        let mut trail = Trail::new();
        trail.record_redirect(&from, &redirect, 302);
        trail.record(&direct, 200);
        write_attempt_receipt(
            &directory,
            &fingerprint,
            FailureClass::Unknown,
            &trail,
            query_names(&redirect),
        )
        .expect("write receipt");

        let receipt_prefix = format!("{fingerprint}.attempt-{}-", std::process::id());
        let receipt_path = std::fs::read_dir(&path)
            .expect("read receipt directory")
            .map(|entry| entry.expect("receipt entry").path())
            .find(|candidate| {
                candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&receipt_prefix))
            })
            .expect("receipt file");
        let bytes = std::fs::read_to_string(receipt_path).expect("read receipt bytes");
        let receipt: Value = serde_json::from_str(&bytes).expect("parse receipt");

        assert_eq!(
            receipt["hops"],
            json!([
                "yjapi.msa.buaa.edu.cn/casapi/index.php 302 -> classroom.msa.buaa.edu.cn<unknown-route>",
                "classroom.msa.buaa.edu.cn<unknown-route> 200"
            ])
        );
        assert_eq!(
            receipt["final_query_names"],
            json!(["ticket", "<unknown-query-name>", "<unknown-query-name>"])
        );
        for marker in [
            "redirect-matrix-secret",
            "direct-matrix-secret",
            "redirect-query-secret",
            "ST-private-ticket",
            "encoded-private-ticket",
            "value-secret",
            "private-id",
        ] {
            assert!(!bytes.contains(marker), "receipt leaked {marker}");
        }
    }
}
