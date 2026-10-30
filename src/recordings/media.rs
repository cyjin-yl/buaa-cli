//! Governed classroom recording-media acquisition and native-track binding.
//!
//! Lesson metadata is read through the fixed classroom source profile.  The
//! recording URL is admitted from that response and is then fetched without a
//! classroom cookie.  A full media copy is only published after its complete
//! MP4 body, digest, owner-only file and receipt have all been verified.

use crate::governor::{self, Governor, Outcome, RequestKind};
use crate::net::{
    CLASSROOM_ORIGIN, CacheMode, CacheStatus, ClassroomClient, Error, Response as SourceResponse,
    valid_session_cookie,
};
use chrono::{Datelike, FixedOffset, NaiveDate, TimeZone, Utc};
use reqwest::Method;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

use super::session::{SessionCredentials, http_client};

const SUB_INFO_PATH: &str = "/courseapi/v3/portal-home-setting/get-sub-info";
const SUB_DETAIL_PATH: &str = "/courseapi/v3/multi-search/get-sub-detail";
/// The reviewed recording-resource host the platform declares.
const MEDIA_HOST: &str = "resource.msa.buaa.edu.cn";
const MAX_INPUT: usize = 32 * 1024;
const MAX_SOURCE_BODY: usize = 1024 * 1024;
const MAX_URL: usize = 16 * 1024;
const MAX_PATH: usize = 4096;
const MAX_COOKIE: usize = 16 * 1024;
const DEFAULT_RANGE_BYTES: u64 = 1024 * 1024;
const MAX_RANGE_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_FULL_BUDGET: u64 = 4 * 1024 * 1024 * 1024;
const MAX_FULL_BUDGET: u64 = 8 * 1024 * 1024 * 1024;
const MEDIA_CHUNK: usize = 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 16 * 1024;
const TEMP_SEQUENCE_START: u64 = 1;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(TEMP_SEQUENCE_START);

fn invalid() -> Error {
    Error::new("invalid_input", "Classroom media input is invalid.")
}

fn unavailable() -> Error {
    Error::new("unavailable", "Classroom media service is unavailable.")
}

fn denied() -> Error {
    Error::new(
        "permission",
        "Explicit authorization for this classroom media read is required.",
    )
}

fn rejected() -> Error {
    Error::new(
        "auth_latched",
        "Classroom media session was rejected or indeterminate; explicit operator review is required.",
    )
}

fn source_layout() -> Error {
    Error::new(
        "invalid_input",
        "Classroom recording source layout is unsupported.",
    )
}

fn source_binding() -> Error {
    Error::new(
        "source_binding",
        "Classroom recording source identity does not match the selected lesson.",
    )
}

fn media_invalid() -> Error {
    Error::new(
        "invalid_media",
        "Classroom recording media framing or container is unsupported.",
    )
}

fn body_too_large() -> Error {
    Error::new(
        "body_too_large",
        "Classroom media exceeds the requested byte budget.",
    )
}

fn body_incomplete() -> Error {
    Error::new(
        "body_incomplete",
        "Classroom media body is shorter than its declared length.",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection<'a> {
    #[serde(borrow)]
    course_id: Cow<'a, str>,
    #[serde(borrow)]
    sub_id: Cow<'a, str>,
    #[serde(borrow, default)]
    tenant_code: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeTrack {
    segments: u64,
    last_end_ms: u64,
    #[serde(default)]
    derived_sha256: Option<String>,
    #[serde(default)]
    resource_guid_status: Option<String>,
    #[serde(default)]
    resource_guid: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input<'a> {
    #[serde(default)]
    authorized: bool,
    #[serde(borrow, default)]
    selection: Option<Selection<'a>>,
    #[serde(borrow, default)]
    cookie: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    session_ref: Option<Cow<'a, str>>,
    #[serde(default)]
    native_track: Option<NativeTrack>,
    #[serde(borrow, default)]
    fetch: Option<Cow<'a, str>>,
    #[serde(default)]
    byte_budget: Option<u64>,
    #[serde(borrow, default)]
    private_dir: Option<Cow<'a, str>>,
}

struct PrivateTarget {
    directory: File,
    display: PathBuf,
}

struct Preflight {
    mode: &'static str,
    budget: u64,
    private: Option<PrivateTarget>,
}

fn decimal_id(value: &str) -> Option<u64> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok().filter(|value| *value > 0)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn contains_ascii_ignore_case(value: &str, needle: &[u8]) -> bool {
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn validate_path_text(value: &str) -> Result<PathBuf, Error> {
    if value.is_empty()
        || value.len() > MAX_PATH
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(invalid());
    }
    Ok(path)
}

fn preflight(request: &Input<'_>) -> Result<Preflight, Error> {
    if !request.authorized {
        return Err(denied());
    }
    let selection = request.selection.as_ref().ok_or_else(invalid)?;
    if decimal_id(&selection.course_id).is_none() || decimal_id(&selection.sub_id).is_none() {
        return Err(invalid());
    }
    if let Some(tenant) = selection.tenant_code.as_deref()
        && tenant != "21"
    {
        return Err(invalid());
    }
    if let Some(track) = request.native_track.as_ref() {
        if track.segments == 0 {
            return Err(invalid());
        }
        if let Some(hash) = track.derived_sha256.as_deref()
            && !lower_hex(hash, 64)
        {
            return Err(invalid());
        }
        if let Some(status) = track.resource_guid_status.as_deref()
            && !matches!(
                status,
                "absent_in_native_track" | "native_declared_not_media_verified"
            )
        {
            return Err(invalid());
        }
        if let Some(guid) = track.resource_guid.as_deref()
            && (guid.len() > 256 || guid.chars().any(char::is_control))
        {
            return Err(invalid());
        }
    }

    if request.cookie.is_some() == request.session_ref.is_some() {
        return Err(invalid());
    }
    if let Some(cookie) = request.cookie.as_deref()
        && !valid_session_cookie(cookie)
    {
        return Err(invalid());
    }
    if let Some(reference) = request.session_ref.as_deref()
        && !lower_hex(reference, 64)
    {
        return Err(invalid());
    }

    let mode = match request.fetch.as_deref().unwrap_or("head") {
        "head" => "head",
        "full" => "full",
        _ => return Err(invalid()),
    };
    let max_budget = if mode == "head" {
        MAX_RANGE_BYTES
    } else {
        MAX_FULL_BUDGET
    };
    let default_budget = if mode == "head" {
        DEFAULT_RANGE_BYTES
    } else {
        DEFAULT_FULL_BUDGET
    };
    let budget = request.byte_budget.unwrap_or(default_budget);
    if budget == 0 || budget > max_budget {
        return Err(invalid());
    }

    // Validate every private path before reading a stored session or opening a
    // network client.  The returned descriptor remains the authority for all
    // later media and receipt operations.
    let private_path = request
        .private_dir
        .as_deref()
        .map(validate_path_text)
        .transpose()?;
    if mode == "full" && private_path.is_none() {
        return Err(invalid());
    }
    let private = private_path
        .map(|path| {
            let directory = governor::open_directory(&path, false, true).map_err(|_| invalid())?;
            Ok(PrivateTarget {
                directory,
                display: path,
            })
        })
        .transpose()?;

    Ok(Preflight {
        mode,
        budget,
        private,
    })
}

fn value_id(value: &Value) -> Option<u64> {
    match value {
        Value::String(value) => decimal_id(value),
        Value::Number(value) => value.as_u64().filter(|value| *value > 0),
        _ => None,
    }
}

fn id_matches(value: Option<&Value>, expected: &str) -> bool {
    value.and_then(value_id) == decimal_id(expected)
}

/// A source response is admitted only for the exact requested URL, HTTP 200,
/// and the platform's successful numeric application code.  Ordinary endpoint
/// layout errors are returned as the inner result so the admitted response
/// remains available for offline repair; a selected-identity binding error,
/// auth page or failed application code is an outer error and is therefore
/// never cached as a successful selected source.
fn process_source<T>(
    response: &SourceResponse,
    expected_url: &str,
    validate: impl FnOnce(&Value) -> Result<T, Error>,
) -> Result<Result<T, Error>, Error> {
    if response.url != expected_url || response.status != 200 {
        return Err(rejected());
    }
    if response
        .headers
        .iter()
        .any(|(name, value)| crate::net::challenge_header(name, value.as_bytes()))
    {
        return Err(rejected());
    }
    if response.body.is_empty() {
        return Err(rejected());
    }
    if response.body.len() > MAX_SOURCE_BODY {
        return Err(unavailable());
    }
    if !crate::net::classroom_json_mime(response.headers.get("content-type").map(String::as_str)) {
        return Err(rejected());
    }
    let value: Value = serde_json::from_slice(&response.body).map_err(|_| rejected())?;
    if value.get("code").and_then(Value::as_i64) != Some(0) {
        return Err(rejected());
    }
    match validate(&value) {
        Err(error) if error.code == "source_binding" => Err(error),
        result => Ok(result),
    }
}

/// Validate the flat lesson response and bind all selected identity fields.
fn lesson_facts(value: &Value, selection: &Selection<'_>) -> Result<Value, Error> {
    let data = value
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(source_layout)?;
    let tenant = selection.tenant_code.as_deref().unwrap_or("21");
    for (name, expected) in [
        ("course_id", selection.course_id.as_ref()),
        ("sub_id", selection.sub_id.as_ref()),
    ] {
        match data.get(name) {
            None | Some(Value::Null) => return Err(source_layout()),
            Some(actual) if !id_matches(Some(actual), expected) => {
                return Err(source_binding());
            }
            Some(_) => {}
        }
    }
    // Tenant code was not part of every reviewed get-sub-info response.  A
    // declared value must agree, while an omitted value remains missing.
    if let Some(actual) = data.get("tenant_code").filter(|value| !value.is_null())
        && !id_matches(Some(actual), tenant)
    {
        return Err(source_binding());
    }
    let fact = |name: &str| data.get(name).cloned().unwrap_or(Value::Null);
    Ok(json!({
        "course_id":fact("course_id"),
        "sub_id":fact("sub_id"),
        "tenant_code":fact("tenant_code"),
        "resource_guid":fact("resource_guid"),
        "resource_id":fact("resource_id"),
        "sub_type":fact("sub_type"),
        "sub_status":fact("sub_status"),
        "start_at":fact("start_at"),
        "end_at":fact("end_at"),
        "duration":fact("duration"),
    }))
}

fn positive_value(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(value)) => value.as_u64().filter(|value| *value > 0),
        Some(Value::String(value)) => value.parse::<u64>().ok().filter(|value| *value > 0),
        _ => None,
    }
}

struct MediaDeclaration {
    declared_url: String,
    url: Url,
    duration_seconds: u64,
}

fn playback_facts(value: &Value, selection: &Selection<'_>) -> Result<MediaDeclaration, Error> {
    let data = value
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(source_layout)?;
    // Some platform revisions repeat identity in the detail object.  When
    // present, every repeated identity must agree; the exact request URL is
    // still the binding when a revision omits these optional fields.
    if data.get("course_id").is_some_and(|value| !value.is_null())
        && !id_matches(data.get("course_id"), &selection.course_id)
    {
        return Err(source_binding());
    }
    if data.get("sub_id").is_some_and(|value| !value.is_null())
        && !id_matches(data.get("sub_id"), &selection.sub_id)
    {
        return Err(source_binding());
    }
    let tenant = selection.tenant_code.as_deref().unwrap_or("21");
    if data
        .get("tenant_code")
        .is_some_and(|value| !value.is_null())
        && !id_matches(data.get("tenant_code"), tenant)
    {
        return Err(source_binding());
    }
    let content = data
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(source_layout)?;
    let declared_url = content
        .get("playback")
        .and_then(Value::as_object)
        .and_then(|playback| playback.get("url"))
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty() && url.len() <= MAX_URL)
        .ok_or_else(source_layout)?;
    // URL admission deliberately happens in this source callback, before the
    // source response is retained and before any media request is possible.
    let url = admitted_media_url(declared_url).map_err(|_| source_layout())?;
    let duration_seconds = positive_value(
        content
            .get("save_playback")
            .and_then(Value::as_object)
            .and_then(|save| save.get("contents_duration")),
    )
    .ok_or_else(source_layout)?;
    Ok(MediaDeclaration {
        declared_url: declared_url.to_string(),
        url,
        duration_seconds,
    })
}

/// The media URL is admitted only when it is the exact URL the platform
/// declared, over HTTPS, on the reviewed recording-resource host.
fn admitted_media_url(declared: &str) -> Result<Url, Error> {
    if declared.is_empty()
        || declared.len() > MAX_URL
        || declared.contains('\0')
        || declared.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let url = Url::parse(declared).map_err(|_| invalid())?;
    // Url::parse may normalize dot segments, default ports, host casing or
    // percent escapes.  The platform declaration is an exact source binding;
    // accepting a normalized alias would fetch a URL other than the bytes it
    // declared.  Encoded dot/slash separators are rejected before parsing as
    // well, since they can alter path-segment interpretation.
    if url.as_str() != declared
        || contains_ascii_ignore_case(declared, b"%2e")
        || contains_ascii_ignore_case(declared, b"%2f")
        || contains_ascii_ignore_case(declared, b"%5c")
    {
        return Err(invalid());
    }
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.host_str() != Some(MEDIA_HOST)
        || !url.path().starts_with("/play/")
        || url.path().contains("//")
        || url.path().contains("/./")
        || url.path().contains("/../")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    let mut segments = url.path_segments().ok_or_else(invalid)?;
    if segments.next() != Some("play") {
        return Err(invalid());
    }
    let mut path_tail = 0;
    for segment in segments {
        if segment.is_empty() || segment == "." || segment == ".." || segment.contains('/') {
            return Err(invalid());
        }
        path_tail += 1;
    }
    if path_tail == 0 {
        return Err(invalid());
    }
    Ok(url)
}

fn path_date(url: &Url) -> Option<String> {
    url.path_segments()?
        .filter(|segment| !segment.is_empty())
        .find_map(|segment| {
            if segment.len() != 10
                || !segment
                    .bytes()
                    .enumerate()
                    .all(|(index, byte)| match index {
                        4 | 7 => byte == b'-',
                        _ => byte.is_ascii_digit(),
                    })
            {
                return None;
            }
            let date = NaiveDate::parse_from_str(segment, "%Y-%m-%d").ok()?;
            let formatted = date.format("%Y-%m-%d").to_string();
            (formatted.len() == 10).then_some(formatted)
        })
}

fn unix_day(start_at: &Value) -> Option<String> {
    let seconds = start_at.as_i64().or_else(|| {
        start_at
            .as_str()
            .and_then(|text| text.trim().parse::<i64>().ok())
    })?;
    let utc = Utc.timestamp_opt(seconds, 0).single()?;
    // Asia/Shanghai is UTC+08:00 for the platform's reviewed lesson data.
    let shanghai = utc.with_timezone(&FixedOffset::east_opt(8 * 60 * 60)?);
    let year = shanghai.year();
    if !(0..=9999).contains(&year) {
        return None;
    }
    let formatted = shanghai.format("%Y-%m-%d").to_string();
    (formatted.len() == 10).then_some(formatted)
}

fn response_challenged(response: &reqwest::blocking::Response) -> bool {
    response
        .headers()
        .iter()
        .any(|(name, value)| crate::net::challenge_header(name.as_str(), value.as_bytes()))
}

fn ambiguous_content_type(response: &reqwest::blocking::Response) -> bool {
    let all = response.headers().get_all(reqwest::header::CONTENT_TYPE);
    let mut values = all.iter();
    let Some(first) = values.next() else {
        return false;
    };
    let Ok(first) = first.to_str() else {
        return true;
    };
    values.any(|value| match value.to_str() {
        Ok(value) => !value.trim().eq_ignore_ascii_case(first.trim()),
        Err(_) => true,
    })
}

fn header_text(
    response: &reqwest::blocking::Response,
    name: &reqwest::header::HeaderName,
) -> Result<Option<String>, Error> {
    response
        .headers()
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| media_invalid())
        })
        .transpose()
}

fn decimal_header(value: Option<&str>) -> Result<u64, Error> {
    let value = value.ok_or_else(media_invalid)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(media_invalid());
    }
    value.parse::<u64>().map_err(|_| media_invalid())
}

fn content_length(response: &reqwest::blocking::Response) -> Result<u64, Error> {
    let values = response.headers().get_all(reqwest::header::CONTENT_LENGTH);
    let mut values = values.iter();
    let first = values.next().ok_or_else(media_invalid)?;
    let length = decimal_header(Some(first.to_str().map_err(|_| media_invalid())?))?;
    for value in values {
        let value = decimal_header(Some(value.to_str().map_err(|_| media_invalid())?))?;
        if value != length {
            return Err(media_invalid());
        }
    }
    if response.content_length() != Some(length) {
        return Err(media_invalid());
    }
    Ok(length)
}

fn has_transfer_encoding(response: &reqwest::blocking::Response) -> Result<bool, Error> {
    for value in response
        .headers()
        .get_all(reqwest::header::TRANSFER_ENCODING)
    {
        if !value
            .to_str()
            .map_err(|_| media_invalid())?
            .trim()
            .is_empty()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Parse only a complete `bytes first-last/total` range with decimal fields.
fn parse_content_range(value: Option<&str>) -> Option<(u64, u64, u64)> {
    let value = value?;
    let rest = value.strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    if total.is_empty() || total.contains('/') {
        return None;
    }
    let (first, last) = range.split_once('-')?;
    if first.is_empty() || last.is_empty() || first.contains('-') || last.contains('-') {
        return None;
    }
    if !first.bytes().all(|byte| byte.is_ascii_digit())
        || !last.bytes().all(|byte| byte.is_ascii_digit())
        || !total.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((first.parse().ok()?, last.parse().ok()?, total.parse().ok()?))
}

fn identity_encoding(response: &reqwest::blocking::Response) -> Result<bool, Error> {
    for value in response
        .headers()
        .get_all(reqwest::header::CONTENT_ENCODING)
    {
        if !value
            .to_str()
            .map_err(|_| media_invalid())?
            .trim()
            .eq_ignore_ascii_case("identity")
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn acceptable_media_mime(mime: &str) -> bool {
    matches!(mime, "video/mp4" | "application/octet-stream")
}

fn media_content_type(response: &reqwest::blocking::Response) -> Result<(String, String), Error> {
    let raw = header_text(response, &reqwest::header::CONTENT_TYPE)?.ok_or_else(media_invalid)?;
    let mime = raw
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_lowercase();
    if !acceptable_media_mime(&mime) {
        return Err(media_invalid());
    }
    Ok((raw, mime))
}

fn valid_mp4_ftyp(prefix: &[u8], total: u64) -> bool {
    if prefix.len() < 12 || &prefix[4..8] != b"ftyp" {
        return false;
    }
    let box_size = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as u64;
    box_size >= 16 && box_size <= total
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MediaReceipt {
    version: u8,
    url: String,
    http_status: u16,
    content_type: String,
    container: String,
    bytes: u64,
    sha256: String,
    complete_body: bool,
}

fn storage_names(url: &Url) -> (String, String) {
    let digest = Sha256::digest(url.as_str().as_bytes());
    let key = format!("{:x}", digest);
    (
        format!("recording-{key}.mp4"),
        format!("recording-{key}.receipt.json"),
    )
}

fn open_existing(directory: &File, name: &str) -> Result<Option<File>, Error> {
    match governor::open_child(directory, name, libc::O_RDONLY) {
        Ok(file) => {
            governor::validate_private_file(&file).map_err(|_| unavailable())?;
            Ok(Some(file))
        }
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(_) => Err(unavailable()),
    }
}

fn read_receipt(mut file: File) -> Result<MediaReceipt, Error> {
    let length = file.metadata().map_err(|_| unavailable())?.len();
    if length == 0 || length > MAX_RECEIPT_BYTES {
        return Err(unavailable());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length).map_err(|_| unavailable())?);
    let mut limited = (&mut file).take(MAX_RECEIPT_BYTES + 1);
    limited.read_to_end(&mut bytes).map_err(|_| unavailable())?;
    if bytes.len() as u64 != length || bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(unavailable());
    }
    serde_json::from_slice(&bytes).map_err(|_| unavailable())
}

fn validate_receipt(receipt: &MediaReceipt, url: &Url, budget: u64) -> Result<(), Error> {
    let receipt_mime = receipt
        .content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_lowercase();
    if receipt.version != 1
        || receipt.url != url.as_str()
        || receipt.http_status != 200
        || receipt.container != "mp4"
        || !receipt.complete_body
        || receipt.bytes == 0
        || receipt.bytes > budget
        || !lower_hex(&receipt.sha256, 64)
        || !acceptable_media_mime(&receipt_mime)
    {
        return Err(unavailable());
    }
    Ok(())
}

/// Bind an already-open replay descriptor's identity to a private local receipt.
/// Neither this local record nor the digest authenticates the remote source.
pub(crate) fn verify_replay_receipt(
    directory: &File,
    receipt_name: &str,
    media_name: &str,
    length: u64,
    sha256: &str,
    budget: u64,
) -> Result<(), Error> {
    let file = open_existing(directory, receipt_name)?.ok_or_else(unavailable)?;
    let receipt = read_receipt(file)?;
    let url = admitted_media_url(&receipt.url).map_err(|_| unavailable())?;
    validate_receipt(&receipt, &url, budget)?;
    let (expected_media, expected_receipt) = storage_names(&url);
    if media_name != expected_media
        || receipt_name != expected_receipt
        || receipt.bytes != length
        || receipt.sha256 != sha256
    {
        return Err(unavailable());
    }
    Ok(())
}

fn read_verified_file(file: &mut File, expected: u64) -> Result<(String, Vec<u8>), Error> {
    let mut remaining = expected;
    let mut hash = Sha256::new();
    let mut prefix = Vec::with_capacity(16);
    let mut buffer = vec![0_u8; MEDIA_CHUNK];
    while remaining > 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = file
            .read(&mut buffer[..wanted])
            .map_err(|_| unavailable())?;
        if read == 0 {
            return Err(body_incomplete());
        }
        hash.update(&buffer[..read]);
        if prefix.len() < 16 {
            let take = (16 - prefix.len()).min(read);
            prefix.extend_from_slice(&buffer[..take]);
        }
        remaining -= read as u64;
    }
    // A one-byte bounded probe proves that an owner-only cached file has no
    // trailing bytes beyond the receipt's complete length.
    let mut extra = [0_u8; 1];
    if file.read(&mut extra).map_err(|_| unavailable())? != 0 {
        return Err(body_too_large());
    }
    if !valid_mp4_ftyp(&prefix, expected) {
        return Err(media_invalid());
    }
    Ok((format!("{:x}", hash.finalize()), prefix))
}

fn cached_media(target: &PrivateTarget, url: &Url, budget: u64) -> Result<Option<Value>, Error> {
    let (media_name, receipt_name) = storage_names(url);
    let media = open_existing(&target.directory, &media_name)?;
    let receipt = open_existing(&target.directory, &receipt_name)?;
    let (mut media, receipt) = match (media, receipt) {
        (Some(media), Some(receipt)) => (media, receipt),
        (media, receipt) => {
            if media.is_some() || receipt.is_some() {
                return Err(unavailable());
            }
            return Ok(None);
        }
    };
    let receipt = read_receipt(receipt)?;
    validate_receipt(&receipt, url, budget)?;
    if media.metadata().map_err(|_| unavailable())?.len() != receipt.bytes {
        return Err(body_incomplete());
    }
    let (digest, _) = read_verified_file(&mut media, receipt.bytes)?;
    if digest != receipt.sha256 {
        return Err(unavailable());
    }
    let stored_path = target.display.join(&media_name);
    Ok(Some(json!({
        "mode":"full_body",
        "cache_reused":true,
        "http_status":receipt.http_status,
        "content_type":receipt.content_type,
        "bytes_read":receipt.bytes,
        "sha256":receipt.sha256,
        "hash_scope":"entire_media_body_bytes",
        "declared_content_length":receipt.bytes,
        "complete_body":true,
        "stored_path":stored_path.to_string_lossy().to_string(),
        "media_bytes_verified":true,
    })))
}

struct StagingFile {
    directory: File,
    name: CString,
    file: File,
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        // SAFETY: directory is pinned and name is a single component created
        // exclusively by this process in that directory.
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
        }
    }
}

fn create_staging(directory: &File, kind: &str) -> Result<StagingFile, Error> {
    for _ in 0..8 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".recording-{kind}-{}-{sequence}.part", std::process::id());
        let file = match governor::open_child(
            directory,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        ) {
            Ok(file) => file,
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(_) => return Err(unavailable()),
        };
        governor::validate_private_file(&file).map_err(|_| unavailable())?;
        return Ok(StagingFile {
            directory: directory.try_clone().map_err(|_| unavailable())?,
            name: CString::new(name).map_err(|_| invalid())?,
            file,
        });
    }
    Err(unavailable())
}

fn unlink_named(directory: &File, name: &str) -> Result<(), Error> {
    let name = CString::new(name).map_err(|_| invalid())?;
    // SAFETY: directory is pinned and name is a single component.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(unavailable());
        }
    }
    Ok(())
}

fn publish_staging(directory: &File, staging: &StagingFile, final_name: &str) -> Result<(), Error> {
    let final_name = CString::new(final_name).map_err(|_| invalid())?;
    // linkat is an atomic no-replace publication: an existing final or a
    // hardlink cannot be truncated or silently replaced.
    // SAFETY: both descriptors are pinned directories and both names are
    // single components; the source was created with O_EXCL in this directory.
    if unsafe {
        libc::linkat(
            directory.as_raw_fd(),
            staging.name.as_ptr(),
            directory.as_raw_fd(),
            final_name.as_ptr(),
            0,
        )
    } != 0
    {
        return Err(unavailable());
    }
    // Remove only the source name we just linked.  The final file now has one
    // link, owner-only permissions and the staging guard can never expose it
    // as a completed path before this point.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), staging.name.as_ptr(), 0) } != 0 {
        let _ = unlink_named(directory, final_name.to_str().unwrap_or(""));
        return Err(unavailable());
    }
    Ok(())
}

fn stream_full_response(
    response: reqwest::blocking::Response,
    target: &PrivateTarget,
    url: &Url,
    budget: u64,
    content_type: String,
    declared_length: u64,
) -> Result<Value, Error> {
    if declared_length == 0 {
        return Err(media_invalid());
    }
    if declared_length > budget {
        return Err(body_too_large());
    }
    let (media_name, receipt_name) = storage_names(url);
    let mut staging = create_staging(&target.directory, "media")?;
    let limit = declared_length.checked_add(1).ok_or_else(body_too_large)?;
    let mut limited = response.take(limit);
    let mut buffer = vec![0_u8; MEDIA_CHUNK];
    let mut prefix = Vec::with_capacity(16);
    let mut hash = Sha256::new();
    let mut written = 0_u64;
    loop {
        // `remaining` includes one bounded sentinel byte.  The media file
        // itself is never allocated from the remote Content-Length.
        let remaining = limit.saturating_sub(written);
        if remaining == 0 {
            return Err(body_too_large());
        }
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = limited
            .read(&mut buffer[..wanted])
            .map_err(|_| unavailable())?;
        if read == 0 {
            break;
        }
        if written.saturating_add(read as u64) > declared_length {
            return Err(body_too_large());
        }
        staging
            .file
            .write_all(&buffer[..read])
            .map_err(|_| unavailable())?;
        hash.update(&buffer[..read]);
        if prefix.len() < 16 {
            let take = (16 - prefix.len()).min(read);
            prefix.extend_from_slice(&buffer[..take]);
        }
        written += read as u64;
    }
    drop(limited);
    if written != declared_length {
        return Err(body_incomplete());
    }
    if !valid_mp4_ftyp(&prefix, written) {
        return Err(media_invalid());
    }
    staging.file.sync_all().map_err(|_| unavailable())?;
    let digest = format!("{:x}", hash.finalize());
    let receipt = MediaReceipt {
        version: 1,
        url: url.as_str().to_string(),
        http_status: 200,
        content_type: content_type.clone(),
        container: "mp4".to_string(),
        bytes: written,
        sha256: digest.clone(),
        complete_body: true,
    };
    let receipt_bytes = serde_json::to_vec(&receipt).map_err(|_| unavailable())?;
    if receipt_bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(unavailable());
    }
    let mut receipt_staging = create_staging(&target.directory, "receipt")?;
    receipt_staging
        .file
        .write_all(&receipt_bytes)
        .map_err(|_| unavailable())?;
    receipt_staging.file.sync_all().map_err(|_| unavailable())?;

    // Publish the receipt first.  A crash can then leave only an orphan
    // receipt (which cache admission rejects), never a media-looking final
    // file without its complete receipt.
    publish_staging(&target.directory, &receipt_staging, &receipt_name)?;
    if let Err(error) = publish_staging(&target.directory, &staging, &media_name) {
        let _ = unlink_named(&target.directory, &receipt_name);
        let _ = target.directory.sync_all();
        return Err(error);
    }
    target.directory.sync_all().map_err(|_| unavailable())?;
    let stored_path = target.display.join(&media_name);
    Ok(json!({
        "mode":"full_body",
        "cache_reused":false,
        "http_status":200,
        "content_type":content_type,
        "bytes_read":written,
        "sha256":digest,
        "hash_scope":"entire_media_body_bytes",
        "declared_content_length":declared_length,
        "complete_body":true,
        "stored_path":stored_path.to_string_lossy().to_string(),
        "media_bytes_verified":true,
    }))
}

/// Read the media under one governor lease.  The lease is finished only after
/// the response has been consumed or cancelled and a full verified copy plus
/// receipt has been durably published.
fn read_media(
    client: &Client,
    url: &Url,
    mode: &str,
    budget: u64,
    private: Option<&PrivateTarget>,
) -> Result<Value, Error> {
    if mode == "full" {
        let target = private.ok_or_else(invalid)?;
        if let Some(cached) = cached_media(target, url, budget)? {
            return Ok(cached);
        }
    }

    let governor = Governor::open().map_err(|_| unavailable())?;
    download_media(client, &governor, url, mode, budget, private)
}

fn download_media(
    client: &Client,
    governor: &Governor,
    url: &Url,
    mode: &str,
    budget: u64,
    private: Option<&PrivateTarget>,
) -> Result<Value, Error> {
    let mut lease = crate::net::acquire_kind(governor, RequestKind::Interactive)?;
    let mut status = None;
    let mut retry_after = None;
    let mut challenge = false;
    let mut body_failure = false;
    let mut governor_failure = false;
    let result = (|| {
        let mut request = client
            .request(Method::GET, url.clone())
            .header(
                reqwest::header::ACCEPT,
                "video/mp4,application/octet-stream",
            )
            .header(reqwest::header::ACCEPT_ENCODING, "identity");
        if mode == "head" {
            let last = budget.checked_sub(1).ok_or_else(invalid)?;
            request = request.header(reqwest::header::RANGE, format!("bytes=0-{last}"));
        }
        let response = match lease.start_request(|| request.send()) {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => return Err(unavailable()),
            Err(governor::FollowupError::Governor(_)) => {
                governor_failure = true;
                return Err(unavailable());
            }
        };
        status = Some(response.status().as_u16());
        retry_after = response.headers().get_all(reqwest::header::RETRY_AFTER)
            .iter().find_map(|value| value.to_str().ok()).map(str::to_owned);
        challenge = response_challenged(&response);
        if lease
            .observe_http_many(
                response.status().as_u16(),
                response.headers().get_all(reqwest::header::RETRY_AFTER)
                    .iter().map(|value| value.to_str().ok()),
                challenge,
            )
            .is_err()
        {
            governor_failure = true;
            return Err(unavailable());
        }
        if matches!(status, Some(401 | 403)) {
            drop(response);
            return Err(rejected());
        }
        if status == Some(429) {
            drop(response);
            return Err(Error::new("rate_limited", "Classroom media request was rate limited."));
        }
        if challenge {
            drop(response);
            return Err(rejected());
        }
        // Ambiguous media framing is unreviewed, not evidence of a challenge.
        // Cancel the body after observing status and every Retry-After field.
        if ambiguous_content_type(&response) {
            drop(response);
            body_failure = true;
            return Err(media_invalid());
        }

        if mode == "head" {
            // A server that ignored Range is rejected before any bulk body
            // allocation.  Every range/header condition is checked first.
            if status != Some(206) {
                drop(response);
                return Err(unavailable());
            }
            let mut ranges = response.headers().get_all(reqwest::header::CONTENT_RANGE)
                .iter().map(|value| value.to_str().ok().and_then(|value| parse_content_range(Some(value))));
            let range = ranges.next().flatten();
            let range = range.filter(|first| ranges.all(|value| value == Some(*first)));
            let Some((first, last, total)) = range else {
                drop(response);
                body_failure = true;
                return Err(media_invalid());
            };
            if first != 0 || last.checked_add(1) != Some(budget) || last >= total {
                drop(response);
                body_failure = true;
                return Err(media_invalid());
            }
            if has_transfer_encoding(&response).map_err(|_| media_invalid())? {
                drop(response);
                body_failure = true;
                return Err(media_invalid());
            }
            let response_length = match content_length(&response) {
                Ok(length) => length,
                Err(error) => {
                    drop(response);
                    body_failure = true;
                    return Err(error);
                }
            };
            if response_length != budget {
                drop(response);
                body_failure = true;
                return Err(media_invalid());
            }
            let (content_type, _) = match media_content_type(&response) {
                Ok(value) => value,
                Err(error) => {
                    drop(response);
                    body_failure = true;
                    return Err(error);
                }
            };
            if !identity_encoding(&response).map_err(|_| media_invalid())? {
                drop(response);
                body_failure = true;
                return Err(media_invalid());
            }
            let limit = budget.checked_add(1).ok_or_else(body_too_large)?;
            let mut limited = response.take(limit);
            let mut body =
                Vec::with_capacity(usize::try_from(limit).map_err(|_| body_too_large())?);
            if limited.read_to_end(&mut body).is_err() {
                drop(limited);
                body_failure = true;
                return Err(unavailable());
            }
            drop(limited);
            if body.len() as u64 != budget {
                body_failure = true;
                return Err(if body.len() as u64 > budget {
                    body_too_large()
                } else {
                    body_incomplete()
                });
            }
            let digest = format!("{:x}", Sha256::digest(&body));
            return Ok(json!({
                "mode":"bounded_prefix",
                "cache_reused":false,
                "http_status":206,
                "content_type":content_type,
                "bytes_read":body.len(),
                "sha256":digest,
                "hash_scope":"bounded_media_prefix_bytes",
                "declared_content_length":total,
                "response_content_length":response_length,
                "complete_body":false,
                "media_bytes_verified":false,
            }));
        }

        if status != Some(200)
            || response
                .headers()
                .contains_key(reqwest::header::CONTENT_RANGE)
        {
            drop(response);
            body_failure = status == Some(200);
            return Err(unavailable());
        }
        if !identity_encoding(&response).map_err(|_| media_invalid())? {
            drop(response);
            body_failure = true;
            return Err(media_invalid());
        }
        if has_transfer_encoding(&response).map_err(|_| media_invalid())? {
            drop(response);
            body_failure = true;
            return Err(media_invalid());
        }
        let (content_type, _) = match media_content_type(&response) {
            Ok(value) => value,
            Err(error) => {
                drop(response);
                body_failure = true;
                return Err(error);
            }
        };
        let declared_length = match content_length(&response) {
            Ok(length) => length,
            Err(error) => {
                drop(response);
                body_failure = true;
                return Err(error);
            }
        };
        if declared_length == 0 || declared_length > budget {
            drop(response);
            body_failure = true;
            return Err(if declared_length > budget {
                body_too_large()
            } else {
                media_invalid()
            });
        }
        let target = private.ok_or_else(invalid)?;
        let result =
            stream_full_response(response, target, url, budget, content_type, declared_length);
        if result.is_err() {
            body_failure = true;
        }
        result
    })();

    // An indeterminate governor write must retain its pending reservation;
    // it is not evidence that an HTTP request failed on the network.
    if governor_failure {
        return result;
    }
    let outcome = if result.is_ok() {
        Outcome::Success
    } else if let Some(status) = status {
        Outcome::Http {
            status,
            // All fields were observed; retain a representative field so a
            // valid 429 deadline does not acquire the missing-header floor.
            retry_after: retry_after.as_deref(),
            challenge,
            network_failure: body_failure || (!challenge && (200..=299).contains(&status)),
        }
    } else {
        Outcome::NetworkFailure
    };
    // There is exactly one finish funnel.  A durable finish failure is not
    // hidden behind the primary result.
    lease.finish(outcome).map_err(|_| unavailable())?;
    result
}

/// Acquire one recording media object for one selected lesson and bind it to
/// the supplied native-track assertion without inferring identity from that
/// assertion's duration, date or caller hash.
pub fn online(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: Input<'_> = serde_json::from_str(input).map_err(|_| invalid())?;
    let preflight = preflight(&request)?;

    // All input and private-directory checks are complete before this read.
    let credentials =
        SessionCredentials::load(request.cookie.as_deref(), request.session_ref.as_deref())?;

    let selection = request.selection.as_ref().ok_or_else(invalid)?;
    let tenant = selection.tenant_code.as_deref().unwrap_or("21");
    let mut network_access = false;
    let mut source_objects_fetched = false;
    let mut lesson_retrieval = Value::Null;
    let mut detail_retrieval = Value::Null;
    let mut info_url = Url::parse(CLASSROOM_ORIGIN).map_err(|_| invalid())?;
    info_url.set_path(SUB_INFO_PATH);
    info_url
        .query_pairs_mut()
        .append_pair("course_id", &selection.course_id)
        .append_pair("sub_id", &selection.sub_id)
        .append_pair("tenant_code", tenant);
    let lesson = credentials.with_header(&info_url, |cookie, expires| {
        let classroom = ClassroomClient::open(CacheMode::PreferCache, cookie, expires)?;
        classroom.get_source(&info_url, |response| {
            let access = source_access(response);
            network_access |= access.0;
            source_objects_fetched |= access.1;
            lesson_retrieval = source_retrieval(response);
            process_source(response, info_url.as_str(), |value| {
                lesson_facts(value, selection)
            })
        })
    })??;

    let mut detail_url = Url::parse(CLASSROOM_ORIGIN).map_err(|_| invalid())?;
    detail_url.set_path(SUB_DETAIL_PATH);
    detail_url
        .query_pairs_mut()
        .append_pair("sub_id", &selection.sub_id);
    let declaration = credentials.with_header(&detail_url, |cookie, expires| {
        let classroom = ClassroomClient::open(CacheMode::PreferCache, cookie, expires)?;
        classroom.get_source(&detail_url, |response| {
            let access = source_access(response);
            network_access |= access.0;
            source_objects_fetched |= access.1;
            detail_retrieval = source_retrieval(response);
            process_source(response, detail_url.as_str(), |value| {
                playback_facts(value, selection)
            })
        })
    })??;

    // A separate cookie-free client is used for the reviewed media host.
    let media_client = http_client()?;
    let media = read_media(
        &media_client,
        &declaration.url,
        preflight.mode,
        preflight.budget,
        preflight.private.as_ref(),
    )?;
    let media_bytes_verified = media
        .get("complete_body")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let media_fetched = media.get("cache_reused").and_then(Value::as_bool) != Some(true);
    network_access |= media_fetched;
    source_objects_fetched |= media_fetched;
    let native = request.native_track.as_ref();
    let native_resource_status = native.map(|track| {
        track.resource_guid_status.as_deref().unwrap_or(
            if track.resource_guid.as_deref().unwrap_or("").is_empty() {
                "absent_in_native_track"
            } else {
                "native_declared_not_media_verified"
            },
        )
    });
    let media_day = path_date(&declaration.url);
    let lesson_day = unix_day(&lesson["start_at"]);

    Ok(json!({
        "schema_version":1,"type":"recording_media","result":"media_observed",
        "authorization":{"basis":"operator_attestation","media_rights_verified":false},
        "selection":{"course_id":selection.course_id,"sub_id":selection.sub_id,"tenant_code":tenant},
        "lesson":lesson,
        "source_retrieval":{"lesson":lesson_retrieval,"recording":detail_retrieval},
        "media":{"url":declaration.declared_url,"host":MEDIA_HOST,"duration_seconds":declaration.duration_seconds,"path_date":media_day,"complete_body":media_bytes_verified,"bytes":media},
        "native_track":native.map(|track| json!({
            "segments":track.segments,"last_end_ms":track.last_end_ms,
            "derived_sha256":track.derived_sha256,
            "resource_guid_status":native_resource_status,
            "resource_guid_declared":track.resource_guid.as_deref().map(|value| !value.is_empty()).unwrap_or(false),
            "association":"operator_assertion_only"
        })),
        "binding":{
            "basis":"platform_declared_lesson_identity",
            "native_track_association":"operator_assertion_only",
            "observations":{"lesson_start_date":lesson_day,"media_path_date":media_day},
            "checks":{"native_track_supplied":native.is_some()},
            "media_bytes_verified":media_bytes_verified,
            "decoder_verified":false,
            "media_rights_verified":false,
            "notes":"The native track is an operator assertion only. Duration, dates and caller-provided hashes are not used to certify media identity, synchronization or origin; a missing native resource identifier remains missing."
        },
        "network_access":network_access,"source_objects_fetched":source_objects_fetched,"catalog_modified":false
    }))
}

fn source_access(response: &SourceResponse) -> (bool, bool) {
    let network = response.cache_status != CacheStatus::Hit;
    (
        network,
        network && response.revalidation_status != Some(304),
    )
}

fn source_retrieval(response: &SourceResponse) -> Value {
    json!({
        "source_url":response.url,"http_status":response.status,
        "body_sha256":response.sha256,"body_bytes":response.body.len(),
        "fetched_at_unix_ms":response.fetched_at_unix_ms,
        "cache_status":response.cache_status,
        "revalidated_at_unix_ms":response.revalidated_at_unix_ms,
        "revalidation_status":response.revalidation_status
    })
}

pub fn schema() -> Value {
    json!({
        "input":{"type":"object","additionalProperties":false,"required":["authorized","selection"],"oneOf":[{"required":["cookie"]},{"required":["session_ref"]}],"allOf":[{"if":{"required":["fetch"],"properties":{"fetch":{"const":"full"}}},"then":{"required":["private_dir"],"properties":{"byte_budget":{"maximum":MAX_FULL_BUDGET}}}},{"if":{"required":["fetch"],"properties":{"fetch":{"const":"head"}}},"then":{"properties":{"byte_budget":{"maximum":MAX_RANGE_BYTES}}}},{"if":{"not":{"required":["fetch"]}},"then":{"properties":{"byte_budget":{"maximum":MAX_RANGE_BYTES}}}}],"properties":{
            "authorized":{"const":true},
            "cookie":{"type":"string","minLength":1,"maxLength":MAX_COOKIE,"writeOnly":true},
            "session_ref":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "selection":{"type":"object","additionalProperties":false,"required":["course_id","sub_id"],"properties":{
                "course_id":{"type":"string","pattern":"^[1-9][0-9]{0,19}$"},
                "sub_id":{"type":"string","pattern":"^[1-9][0-9]{0,19}$"},
                "tenant_code":{"const":"21"}
            }},
            "native_track":{"type":"object","additionalProperties":false,"required":["segments","last_end_ms"],"properties":{
                "segments":{"type":"integer","minimum":1},
                "last_end_ms":{"type":"integer","minimum":0},
                "derived_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                "resource_guid_status":{"enum":["absent_in_native_track","native_declared_not_media_verified"]},
                "resource_guid":{"type":"string","maxLength":256}
            }},
            "fetch":{"enum":["head","full"]},
            "byte_budget":{"type":"integer","minimum":1,"maximum":MAX_FULL_BUDGET},
            "private_dir":{"type":"string","minLength":1,"maxLength":MAX_PATH}
        }},
        "output":{"type":"object","properties":{
            "schema_version":{"const":1},"type":{"const":"recording_media"},"result":{"const":"media_observed"},
            "authorization":{"type":"object","properties":{"media_rights_verified":{"const":false}}},
            "media":{"type":"object","properties":{"complete_body":{"type":"boolean"},"bytes":{"type":"object","properties":{"complete_body":{"type":"boolean"},"media_bytes_verified":{"type":"boolean"}}}}},
            "binding":{"type":"object","properties":{"media_bytes_verified":{"type":"boolean"},"decoder_verified":{"const":false},"media_rights_verified":{"const":false}}}
        }},
        "description":"Governed classroom recording-media acquisition. Fixed classroom source APIs admit the selected course/sub/tenant identity and the exact HTTPS recording URL before the cookie-free media read. Prefix reads use a strict zero-based Content-Range; full reads require positive consistent framing, identity encoding, an MP4 ftyp box, exact EOF and a complete owner-only file plus receipt. Native-track fields remain operator assertions; byte integrity, decoder capability and media rights are separate claims."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    const DECLARED: &str = "https://resource.msa.buaa.edu.cn/play/1/fixture/2026-01-02/sample.mp4";
    const MP4: &[u8] = b"\0\0\0\x18ftypisom\0\0\0\0isommp42";

    struct TransferFixture {
        root: PathBuf,
        private: PrivateTarget,
        governor: Governor,
    }

    impl TransferFixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "buaa-media-transfer-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            let display = root.join("media");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&display)
                .unwrap();
            let private = PrivateTarget {
                directory: governor::open_directory(&display, false, true).unwrap(),
                display,
            };
            let governor = Governor::isolated_for_test(&root.join("governor")).unwrap();
            Self {
                root,
                private,
                governor,
            }
        }
    }

    impl Drop for TransferFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn raw_reply(status: u16, headers: &str, declared: usize, body: &[u8]) -> Vec<u8> {
        let mut bytes = format!(
            "HTTP/1.1 {status} Synthetic\r\nConnection: close\r\nContent-Length: {declared}\r\n{headers}\r\n"
        ).into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    fn serve_once(reply: Vec<u8>) -> (Client, Url, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "loopback request did not arrive");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("loopback accept: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                assert_eq!(socket.read(&mut byte).unwrap(), 1);
                request.push(byte[0]);
                assert!(request.len() <= 16 * 1024);
            }
            // Early-response refusal is allowed to close this connection.
            let _ = socket.write_all(&reply);
            String::from_utf8(request).unwrap()
        });
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let url = Url::parse(&format!("http://{address}/synthetic.mp4")).unwrap();
        (client, url, server)
    }

    #[test]
    fn full_media_accepts_budget_equality_and_reuse_rechecks_every_byte() {
        let fixture = TransferFixture::new();
        let (client, url, server) = serve_once(raw_reply(
            200,
            "Content-Type: video/mp4\r\n",
            MP4.len(),
            MP4,
        ));
        let output = download_media(
            &client,
            &fixture.governor,
            &url,
            "full",
            MP4.len() as u64,
            Some(&fixture.private),
        )
        .unwrap();
        assert_eq!(output["bytes_read"], MP4.len());
        assert_eq!(output["sha256"], format!("{:x}", Sha256::digest(MP4)));
        assert_eq!(output["complete_body"], true);
        let request = server.join().unwrap().to_ascii_lowercase();
        assert!(!request.contains("cookie:"));
        assert!(!request.contains("authorization:"));
        let (media_name, _) = storage_names(&url);
        let path = fixture.private.display.join(&media_name);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        let cached = cached_media(&fixture.private, &url, MP4.len() as u64)
            .unwrap()
            .unwrap();
        assert_eq!(cached["cache_reused"], true);
        assert_eq!(cached["sha256"], output["sha256"]);
        let mut changed = MP4.to_vec();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(path, changed).unwrap();
        assert!(cached_media(&fixture.private, &url, MP4.len() as u64).is_err());
    }

    #[test]
    fn rejected_full_responses_never_publish_completed_media() {
        for (status, headers, declared, body, budget) in [
            (200, "Content-Type: video/mp4\r\n", 0, &b""[..], 32),
            (200, "Content-Type: text/html\r\n", MP4.len(), MP4, 32),
            (
                200,
                "Content-Type: application/octet-stream\r\n",
                18,
                &b"<html>error</html>"[..],
                32,
            ),
            (
                206,
                "Content-Type: video/mp4\r\nContent-Range: bytes 0-23/24\r\n",
                MP4.len(),
                MP4,
                32,
            ),
            (
                200,
                "Content-Type: video/mp4\r\nContent-Encoding: gzip\r\n",
                MP4.len(),
                MP4,
                32,
            ),
            (
                200,
                "Content-Type: video/mp4\r\n",
                MP4.len(),
                &MP4[..16],
                32,
            ),
            (200, "Content-Type: video/mp4\r\n", MP4.len(), MP4, 23),
        ] {
            let fixture = TransferFixture::new();
            let (client, url, server) = serve_once(raw_reply(status, headers, declared, body));
            assert!(
                download_media(
                    &client,
                    &fixture.governor,
                    &url,
                    "full",
                    budget,
                    Some(&fixture.private)
                )
                .is_err()
            );
            server.join().unwrap();
            let (media_name, receipt_name) = storage_names(&url);
            assert!(
                open_existing(&fixture.private.directory, &media_name)
                    .unwrap()
                    .is_none()
            );
            assert!(
                open_existing(&fixture.private.directory, &receipt_name)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn prefix_reads_require_the_requested_zero_based_range() {
        for (status, extra, declared, body) in [
            (200, "", 16, &MP4[..16]),
            (206, "", 16, &MP4[..16]),
            (206, "Content-Range: bytes 16-31/32\r\n", 16, &MP4[..16]),
            (206, "Content-Range: bytes 0-15/1\r\n", 16, &MP4[..16]),
            (
                206,
                "Content-Range: bytes 0-18446744073709551615/18446744073709551615\r\n",
                16,
                &MP4[..16],
            ),
            (206, "Content-Range: bytes 0-15/24\r\n", 15, &MP4[..15]),
            (206, "Content-Range: bytes 0-15/24\r\n", 16, &MP4[..15]),
        ] {
            let fixture = TransferFixture::new();
            let headers = format!("Content-Type: video/mp4\r\n{extra}");
            let (client, url, server) = serve_once(raw_reply(status, &headers, declared, body));
            assert!(download_media(&client, &fixture.governor, &url, "head", 16, None).is_err());
            server.join().unwrap();
        }
        let fixture = TransferFixture::new();
        let (client, url, server) = serve_once(raw_reply(
            206,
            "Content-Type: video/mp4\r\nContent-Range: bytes 0-15/24\r\n",
            16,
            &MP4[..16],
        ));
        let output = download_media(&client, &fixture.governor, &url, "head", 16, None).unwrap();
        assert_eq!(output["bytes_read"], 16);
        assert_eq!(output["declared_content_length"], 24);
        assert_eq!(
            output["sha256"],
            format!("{:x}", Sha256::digest(&MP4[..16]))
        );
        assert_eq!(output["complete_body"], false);
        let request = server.join().unwrap().to_ascii_lowercase();
        assert!(request.contains("range: bytes=0-15\r\n"));
        assert!(!request.contains("cookie:"));
    }

    #[test]
    fn successful_media_keeps_retry_after_in_the_shared_state() {
        for full in [false, true] {
            let fixture = TransferFixture::new();
            let (status, headers, body, mode, budget) = if full {
                (
                    200,
                    "Content-Type: video/mp4\r\nRetry-After: 1\r\nRetry-After: 3600\r\nRetry-After: 2\r\n",
                    MP4,
                    "full",
                    MP4.len() as u64,
                )
            } else {
                (
                    206,
                    "Content-Type: video/mp4\r\nContent-Range: bytes 0-15/24\r\nRetry-After: 1\r\nRetry-After: 3600\r\nRetry-After: 2\r\n",
                    &MP4[..16],
                    "head",
                    16,
                )
            };
            let (client, url, server) = serve_once(raw_reply(status, headers, body.len(), body));
            let output = download_media(
                &client,
                &fixture.governor,
                &url,
                mode,
                budget,
                full.then_some(&fixture.private),
            )
            .unwrap();
            assert_eq!(output["bytes_read"], body.len());
            server.join().unwrap();
            assert!(fixture.governor.status().unwrap().cooldown_wait > Duration::from_secs(3590));
        }
    }

    #[test]
    fn conflicting_media_content_types_refuse_without_inventing_a_challenge() {
        let fixture = TransferFixture::new();
        let (client, url, server) = serve_once(raw_reply(
            200,
            "Content-Type: video/mp4\r\nContent-Type: text/html\r\nRetry-After: 3600\r\nRetry-After: 1\r\n",
            MP4.len(),
            MP4,
        ));
        assert!(download_media(
            &client,
            &fixture.governor,
            &url,
            "full",
            32,
            Some(&fixture.private),
        ).is_err());
        server.join().unwrap();
        let status = fixture.governor.status().unwrap();
        assert!(!status.safety_latched);
        assert!(status.cooldown_wait > Duration::from_secs(3590));
        assert_eq!(std::fs::read_dir(&fixture.private.display).unwrap().count(), 0);
    }

    #[test]
    fn unauthorized_media_with_ambiguous_type_records_real_status() {
        let fixture = TransferFixture::new();
        let (client, url, server) = serve_once(raw_reply(
            401,
            "Content-Type: video/mp4\r\nContent-Type: text/html\r\n",
            MP4.len(),
            MP4,
        ));
        assert!(download_media(
            &client,
            &fixture.governor,
            &url,
            "full",
            32,
            Some(&fixture.private),
        ).is_err());
        server.join().unwrap();
        assert!(!fixture.governor.status().unwrap().safety_latched);
        assert_eq!(std::fs::read_dir(&fixture.private.display).unwrap().count(), 0);
    }

    #[test]
    fn media_status_refusals_precede_ambiguous_framing() {
        for (status, code) in [(401, "auth_latched"), (403, "auth_latched"), (429, "rate_limited")] {
            let fixture = TransferFixture::new();
            let (client, url, server) = serve_once(raw_reply(
                status,
                "Content-Type: video/mp4\r\nContent-Type: text/html\r\nRetry-After: 60\r\n",
                MP4.len(),
                MP4,
            ));
            let error = download_media(&client, &fixture.governor, &url, "head", 16, None).unwrap_err();
            assert_eq!(error.code, code);
            server.join().unwrap();
            let state = fixture.governor.status().unwrap();
            assert_eq!(state.safety_latched, false);
            assert!(state.cooldown_wait > Duration::from_secs(50));
            assert!(state.cooldown_wait <= Duration::from_secs(61));
            assert_eq!(std::fs::read_dir(&fixture.private.display).unwrap().count(), 0);
        }
    }

    #[test]
    fn prefix_media_checks_every_content_range_field() {
        for second in ["bytes 0-15/25", "invalid"] {
            let fixture = TransferFixture::new();
            let headers = format!(
                "Content-Type: video/mp4\r\nContent-Range: bytes 0-15/24\r\nContent-Range: {second}\r\n"
            );
            let (client, url, server) = serve_once(raw_reply(206, &headers, 16, &MP4[..16]));
            let error = download_media(&client, &fixture.governor, &url, "head", 16, None).unwrap_err();
            assert_eq!(error.code, "invalid_media");
            server.join().unwrap();
            assert!(!fixture.governor.status().unwrap().safety_latched);
        }
    }

    #[test]
    fn rejected_media_keeps_challenge_and_retry_after_in_the_shared_state() {
        let fixture = TransferFixture::new();
        let (client, url, server) = serve_once(raw_reply(429, "Retry-After: 3600\r\n", 0, b""));
        assert!(download_media(&client, &fixture.governor, &url, "head", 16, None).is_err());
        server.join().unwrap();
        assert!(fixture.governor.status().unwrap().cooldown_wait > Duration::from_secs(3590));

        let fixture = TransferFixture::new();
        let (client, url, server) = serve_once(raw_reply(
            200,
            "X-Challenge: required\r\nContent-Type: video/mp4\r\n",
            MP4.len(),
            MP4,
        ));
        assert!(
            download_media(
                &client,
                &fixture.governor,
                &url,
                "full",
                32,
                Some(&fixture.private)
            )
            .is_err()
        );
        server.join().unwrap();
        assert!(!fixture.governor.status().unwrap().safety_latched);
    }

    #[test]
    fn only_the_reviewed_recording_host_and_path_are_admitted() {
        assert!(admitted_media_url(DECLARED).is_ok());
        for candidate in [
            "http://resource.msa.buaa.edu.cn/play/1/a.mp4",
            "https://evil.example/play/1/a.mp4",
            "https://resource.msa.buaa.edu.cn.evil.example/play/1/a.mp4",
            "https://user@resource.msa.buaa.edu.cn/play/1/a.mp4",
            "https://resource.msa.buaa.edu.cn:8443/play/1/a.mp4",
            "https://resource.msa.buaa.edu.cn:443/play/1/a.mp4",
            "https://resource.msa.buaa.edu.cn/other/1/a.mp4",
            "https://resource.msa.buaa.edu.cn/play/1/a.mp4?token=1",
            "https://resource.msa.buaa.edu.cn/play/1/../a.mp4",
            "https://resource.msa.buaa.edu.cn/play/1/%2e%2e/a.mp4",
        ] {
            assert!(admitted_media_url(candidate).is_err(), "{candidate}");
        }
    }

    #[test]
    fn strict_ranges_reject_overflow_and_wrong_intervals() {
        assert_eq!(
            parse_content_range(Some("bytes 0-1023/4096")),
            Some((0, 1023, 4096))
        );
        assert_eq!(
            parse_content_range(Some("bytes 1-1023/4096")),
            Some((1, 1023, 4096))
        );
        for value in [
            "bytes 0-1023/*",
            "bytes 0-1023/",
            "bytes 0-1023/4096 ",
            "bytes 0--1/4096",
            "bytes 0-18446744073709551616/4096",
        ] {
            assert_eq!(parse_content_range(Some(value)), None, "{value}");
        }
    }

    #[test]
    fn mp4_ftyp_is_required_even_for_octet_stream() {
        let prefix = b"\0\0\0\x18ftypisom\0\0\0\0";
        assert!(valid_mp4_ftyp(prefix, 24));
        assert!(!valid_mp4_ftyp(b"<html>not media</html>", 22));
        assert!(!valid_mp4_ftyp(b"application/octet-stream", 24));
    }

    #[test]
    fn calendar_conversion_is_bounded_and_shanghai_based() {
        assert_eq!(
            unix_day(&json!(1_792_062_000)).as_deref(),
            Some("2026-10-15")
        );
        assert_eq!(unix_day(&json!(0)).as_deref(), Some("1970-01-01"));
        assert_eq!(unix_day(&json!(i64::MAX)).as_deref(), None);
        assert_eq!(unix_day(&json!(i64::MIN)).as_deref(), None);
    }

    #[test]
    fn path_dates_require_a_real_calendar_date() {
        let url = admitted_media_url(DECLARED).expect("declared URL");
        assert_eq!(path_date(&url).as_deref(), Some("2026-01-02"));
        let invalid = admitted_media_url(
            "https://resource.msa.buaa.edu.cn/play/1/fixture/2026-02-31/sample.mp4",
        )
        .expect("path remains an admitted URL");
        assert_eq!(path_date(&invalid), None);
    }
}
