//! Governed BUAA SRun gateway operations.
//! Credentials are accepted only through bounded JSON stdin and are never stored.
mod crypto;

use crate::governor::{self, Governor, Outcome, RequestKind, ResumeAuthorization};
use crate::net::{self, CacheMode, Error};
use fs2::FileExt;
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::Zeroize;

const BASE: &str = "https://gw.buaa.edu.cn";
const CHALLENGE_PATH: &str = "/cgi-bin/get_challenge";
const PORTAL_PATH: &str = "/cgi-bin/srun_portal";
const USAGE_PATH: &str = "/cgi-bin/rad_user_info";
const MAX_INPUT: usize = 16 * 1024;
const MAX_BODY: u64 = 512 * 1024;
const MAX_CACHE: u64 = 64 * 1024;
const CACHE_FILE: &str = "usage.json";
static CALLBACK: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginInput {
    username: String,
    password: String,
    ip: String,
    ac_id: u32,
    intent: String,
}

impl Drop for LoginInput {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutPlanInput {
    username: String,
    ip: String,
    ac_id: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutCommitInput {
    username: String,
    ip: String,
    ac_id: u32,
    operation_id: String,
    plan_hash: String,
    intent: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeInput {
    intent: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ChallengeResponse {
    challenge: Option<String>,
    error: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct PortalResponse {
    error: String,
    res: String,
    online_ip: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct UsageResponse {
    online_ip: String,
    error: String,
    bytes_in: Option<u64>,
    bytes_out: Option<u64>,
    all_bytes: Option<u64>,
    sum_bytes: Option<u64>,
    remain_seconds: Option<u64>,
    sum_seconds: Option<u64>,
    user_balance: Option<f64>,
    wallet_balance: Option<f64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UsageRecord {
    version: u8,
    fetched_at_unix_ms: u64,
    response_body_sha256: String,
    online: bool,
    online_ip: Option<String>,
    bytes_in: Option<u64>,
    bytes_out: Option<u64>,
    all_bytes: Option<u64>,
    sum_bytes: Option<u64>,
    remain_seconds: Option<u64>,
    sum_seconds: Option<u64>,
    user_balance: Option<f64>,
    wallet_balance: Option<f64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LogoutReceipt {
    version: u8,
    account_fingerprint: String,
    operation_id: String,
    plan_hash: String,
    requested_ip: String,
    server_online_ip: Option<String>,
    fetched_at_unix_ms: u64,
    response_body_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LogoutUnknown {
    version: u8,
    account_fingerprint: String,
    operation_id: String,
    plan_hash: String,
    created_at_unix_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LogoutResolvedUnknown {
    version: u8,
    account_fingerprint: String,
    operation_id: String,
    plan_hash: String,
    created_at_unix_ms: u64,
    recovery_hash: String,
    resolved_at_unix_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutRecoveryInput {
    username: String,
    ip: String,
    ac_id: u32,
    operation_id: String,
    plan_hash: String,
    recovery_hash: String,
    intent: String,
}

#[derive(Clone, Copy)]
enum AppOutcome {
    Http,
    CredentialRejected,
    AccountLocked,
}

struct Processed<T> {
    result: Result<T, Error>,
    outcome: AppOutcome,
}

struct ResponseMeta {
    fetched_at_unix_ms: u64,
    body_sha256: String,
}

struct GatewayTransport {
    governor: Governor,
    client: Client,
    #[cfg(test)]
    route: Option<std::net::SocketAddr>,
}

fn invalid() -> Error {
    Error::new("invalid_input", "gateway request is invalid")
}
fn unavailable() -> Error {
    Error::new("unavailable", "gateway response is unavailable")
}
fn rejected() -> Error {
    Error::new(
        "auth_latched",
        "gateway authentication was rejected; explicit operator review is required",
    )
}

fn unix_ms() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or_else(unavailable)
}

fn validate_identity(username: &str, ip: &str, ac_id: u32) -> Result<(), Error> {
    if username.is_empty()
        || username.chars().count() > 256
        || username.chars().any(char::is_control)
        || ip.parse::<Ipv4Addr>().is_err()
        || ac_id == 0
        || ac_id > 1_000_000
    {
        return Err(invalid());
    }
    Ok(())
}

fn parse_jsonp(callback: &str, body: &[u8]) -> Result<Value, Error> {
    let text = std::str::from_utf8(body).map_err(|_| unavailable())?;
    let payload = text
        .strip_prefix(callback)
        .and_then(|value| value.strip_prefix('('))
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(unavailable)?;
    serde_json::from_str(payload).map_err(|_| unavailable())
}

impl GatewayTransport {
    fn open() -> Result<Self, Error> {
        let client = Client::builder()
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
            .timeout(Duration::from_secs(30))
            .user_agent("buaa-cli/0.1 gateway")
            .build()
            .map_err(|_| unavailable())?;
        Ok(Self {
            governor: Governor::open().map_err(|_| unavailable())?,
            client,
            #[cfg(test)]
            route: None,
        })
    }

    fn request_url(&self, original: &Url) -> Url {
        #[cfg(test)]
        if let Some(address) = self.route {
            let mut routed = original.clone();
            routed.set_scheme("http").expect("test HTTP scheme");
            routed
                .set_host(Some(&address.ip().to_string()))
                .expect("test loopback host");
            routed
                .set_port(Some(address.port()))
                .expect("test loopback port");
            return routed;
        }
        original.clone()
    }

    fn request_jsonp<T>(
        &self,
        kind: RequestKind,
        path: &str,
        parameters: Vec<(&str, String)>,
        process: impl FnOnce(&Value, &ResponseMeta) -> Processed<T>,
    ) -> Result<T, Error> {
        self.request_jsonp_with_preflight(kind, path, parameters, || Ok(()), process)
    }

    fn request_jsonp_with_preflight<T>(
        &self,
        kind: RequestKind,
        path: &str,
        mut parameters: Vec<(&str, String)>,
        before_send: impl FnOnce() -> Result<(), Error>,
        process: impl FnOnce(&Value, &ResponseMeta) -> Processed<T>,
    ) -> Result<T, Error> {
        if !matches!(path, CHALLENGE_PATH | PORTAL_PATH | USAGE_PATH) {
            return Err(Error::new("permission", "gateway route is not allowlisted"));
        }
        let callback = format!(
            "buaa_{}_{}",
            unix_ms()?,
            CALLBACK.fetch_add(1, Ordering::Relaxed)
        );
        parameters.push(("callback", callback.clone()));
        let mut original = Url::parse(BASE).map_err(|_| unavailable())?;
        original.set_path(path);
        {
            let mut query = original.query_pairs_mut();
            for (key, value) in parameters {
                query.append_pair(key, &value);
            }
        }
        let lease = net::acquire_kind(&self.governor, kind)?;
        if let Err(error) = before_send() {
            lease.finish_without_request().map_err(|_| unavailable())?;
            return Err(error);
        }
        let mut response = match self
            .client
            .get(self.request_url(&original))
            .header("Accept-Encoding", "identity")
            .send()
        {
            Ok(response) => response,
            Err(_) => {
                lease
                    .finish(Outcome::NetworkFailure)
                    .map_err(|_| unavailable())?;
                return Err(unavailable());
            }
        };
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let challenge_header = response
            .headers()
            .get_all("cf-mitigated")
            .iter()
            .any(|value| value.as_bytes().eq_ignore_ascii_case(b"challenge"));
        let mut body = Vec::new();
        let read = response.by_ref().take(MAX_BODY + 1).read_to_end(&mut body);
        let network_failure = read.is_err();
        let too_large = body.len() as u64 > MAX_BODY;
        let processed = if network_failure || too_large || !(200..300).contains(&status) {
            None
        } else {
            let parsed = parse_jsonp(&callback, &body);
            Some(match (parsed, unix_ms()) {
                (Ok(value), Ok(fetched_at_unix_ms)) => process(
                    &value,
                    &ResponseMeta {
                        fetched_at_unix_ms,
                        body_sha256: format!("{:x}", Sha256::digest(&body)),
                    },
                ),
                (Err(error), _) => Processed {
                    result: Err(error),
                    outcome: AppOutcome::Http,
                },
                (_, Err(error)) => Processed {
                    result: Err(error),
                    outcome: AppOutcome::Http,
                },
            })
        };
        drop(response);
        let application_outcome = processed
            .as_ref()
            .map(|value| value.outcome)
            .unwrap_or(AppOutcome::Http);
        let application_latch = matches!(
            application_outcome,
            AppOutcome::CredentialRejected | AppOutcome::AccountLocked
        );
        let indeterminate_authentication = kind == RequestKind::Authentication
            && processed.as_ref().is_none_or(|value| value.result.is_err());
        let outcome = Outcome::Http {
            status,
            retry_after: retry_after.as_deref(),
            challenge: challenge_header || application_latch || indeterminate_authentication,
            network_failure,
        };
        lease.finish(outcome).map_err(|_| unavailable())?;
        if challenge_header || matches!(status, 401 | 403) {
            return Err(rejected());
        }
        if status == 429 {
            return Err(Error::new("rate_limited", "gateway requested a cooldown"));
        }
        if network_failure || too_large || !(200..300).contains(&status) {
            return Err(unavailable());
        }
        processed.expect("processed successful HTTP body").result
    }
}

fn open_cache_directory() -> Result<File, Error> {
    let home = governor::identity_home().map_err(|_| unavailable())?;
    let _home = governor::open_directory(&home, false, false).map_err(|_| unavailable())?;
    governor::open_directory(&home.join(".buaa-cli-gateway-cache"), true, true)
        .map_err(|_| unavailable())
}

fn validate_usage(record: &UsageRecord) -> Result<(), Error> {
    if record.version != 1
        || record.response_body_sha256.len() != 64
        || !record
            .response_body_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || record
            .online_ip
            .as_ref()
            .is_some_and(|value| value.parse::<IpAddr>().is_err())
        || [record.user_balance, record.wallet_balance]
            .into_iter()
            .flatten()
            .any(|value| !value.is_finite() || value < 0.0)
    {
        return Err(unavailable());
    }
    Ok(())
}

fn load_usage(directory: &File) -> Result<Option<UsageRecord>, Error> {
    let file = match governor::open_child(directory, CACHE_FILE, libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    governor::validate_private_file(&file).map_err(|_| unavailable())?;
    let mut bytes = Vec::new();
    file.take(MAX_CACHE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() as u64 > MAX_CACHE {
        return Err(unavailable());
    }
    let record: UsageRecord = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
    validate_usage(&record)?;
    Ok(Some(record))
}

fn save_usage(directory: &File, record: &UsageRecord) -> Result<(), Error> {
    validate_usage(record)?;
    match governor::open_child(directory, CACHE_FILE, libc::O_RDONLY) {
        Ok(file) => governor::validate_private_file(&file).map_err(|_| unavailable())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(unavailable()),
    }
    let (temporary_name, mut temporary) =
        governor::create_temporary(directory).map_err(|_| unavailable())?;
    let result = (|| {
        serde_json::to_writer(&mut temporary, record).map_err(|_| unavailable())?;
        temporary.write_all(b"\n").map_err(|_| unavailable())?;
        temporary.sync_all().map_err(|_| unavailable())?;
        let target = CString::new(CACHE_FILE).map_err(|_| unavailable())?;
        // SAFETY: both names are fixed single components in the pinned directory.
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
        // SAFETY: temporary was exclusively created in this directory.
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
    }
    result
}

fn logout_account_fingerprint(username: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"buaa-cli:gateway-logout-account:v1\0");
    hash.update((username.len() as u64).to_be_bytes());
    hash.update(username.as_bytes());
    format!("{:x}", hash.finalize())
}

fn logout_plan_hash(username: &str, ip: &str, ac_id: u32, operation_id: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"buaa-cli:gateway-logout-plan:v2\0");
    for value in [username.as_bytes(), ip.as_bytes(), operation_id.as_bytes()] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.update(ac_id.to_be_bytes());
    format!("{:x}", hash.finalize())
}

fn new_logout_operation_id() -> Result<String, Error> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|_| unavailable())?;
    let mut operation_id = String::with_capacity(32);
    for byte in random {
        operation_id.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        operation_id.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    Ok(operation_id)
}

fn username_hash(username: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"buaa-cli:gateway-username:v1\0");
    hash.update(username.as_bytes());
    format!("{:x}", hash.finalize())
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_operation_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn receipt_name(plan_hash: &str) -> Result<String, Error> {
    if !valid_hash(plan_hash) {
        return Err(invalid());
    }
    Ok(format!("logout-{plan_hash}.json"))
}

fn account_lock_name(account_fingerprint: &str) -> Result<String, Error> {
    if !valid_hash(account_fingerprint) {
        return Err(invalid());
    }
    Ok(format!("logout-account-{account_fingerprint}.lock"))
}

fn unknown_barrier_name(account_fingerprint: &str) -> Result<String, Error> {
    if !valid_hash(account_fingerprint) {
        return Err(invalid());
    }
    Ok(format!("logout-unknown-{account_fingerprint}.json"))
}

fn resolved_operation_name(plan_hash: &str) -> Result<String, Error> {
    if !valid_hash(plan_hash) {
        return Err(invalid());
    }
    Ok(format!("logout-resolved-{plan_hash}.json"))
}

fn logout_unknown_error() -> Error {
    Error::new(
        "unknown_outcome",
        "gateway logout outcome is unknown; offline operator resolution is required",
    )
}

fn lock_logout_account(directory: &File, account_fingerprint: &str) -> Result<File, Error> {
    let name = account_lock_name(account_fingerprint)?;
    let file = governor::open_child(directory, &name, libc::O_RDWR | libc::O_CREAT)
        .map_err(|_| unavailable())?;
    governor::validate_private_file(&file).map_err(|_| unavailable())?;
    FileExt::lock_exclusive(&file).map_err(|_| unavailable())?;
    Ok(file)
}

fn save_private_json<T: Serialize>(directory: &File, name: &str, value: &T) -> Result<(), Error> {
    if name.is_empty() || name.contains('/') {
        return Err(unavailable());
    }
    match governor::open_child(directory, name, libc::O_RDONLY) {
        Ok(file) => governor::validate_private_file(&file).map_err(|_| unavailable())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(unavailable()),
    }
    let (temporary_name, mut temporary) =
        governor::create_temporary(directory).map_err(|_| unavailable())?;
    let result = (|| {
        serde_json::to_writer(&mut temporary, value).map_err(|_| unavailable())?;
        temporary.write_all(b"\n").map_err(|_| unavailable())?;
        temporary.sync_all().map_err(|_| unavailable())?;
        let target = CString::new(name).map_err(|_| unavailable())?;
        // SAFETY: both names are validated single components in the pinned directory.
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
        // SAFETY: temporary was exclusively created in this directory.
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
    }
    result
}

fn load_private_json<T: DeserializeOwned>(
    directory: &File,
    name: &str,
) -> Result<Option<T>, Error> {
    let file = match governor::open_child(directory, name, libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    governor::validate_private_file(&file).map_err(|_| unavailable())?;
    let mut bytes = Vec::new();
    file.take(MAX_CACHE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() as u64 > MAX_CACHE {
        return Err(unavailable());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| unavailable())
}

fn validate_logout_unknown(record: &LogoutUnknown, expected_account: &str) -> Result<(), Error> {
    if record.version != 1
        || record.account_fingerprint != expected_account
        || !valid_hash(&record.account_fingerprint)
        || !valid_operation_id(&record.operation_id)
        || !valid_hash(&record.plan_hash)
    {
        return Err(unavailable());
    }
    Ok(())
}

fn load_logout_unknown(
    directory: &File,
    account_fingerprint: &str,
) -> Result<Option<LogoutUnknown>, Error> {
    let name = unknown_barrier_name(account_fingerprint)?;
    let Some(record) = load_private_json(directory, &name)? else {
        return Ok(None);
    };
    validate_logout_unknown(&record, account_fingerprint)?;
    Ok(Some(record))
}

fn save_logout_unknown(directory: &File, record: &LogoutUnknown) -> Result<(), Error> {
    validate_logout_unknown(record, &record.account_fingerprint)?;
    let name = unknown_barrier_name(&record.account_fingerprint)?;
    if load_logout_unknown(directory, &record.account_fingerprint)?.is_some() {
        return Err(logout_unknown_error());
    }
    save_private_json(directory, &name, record)
}

fn clear_logout_unknown(
    directory: &File,
    account_fingerprint: &str,
    operation_id: &str,
    plan_hash: &str,
) -> Result<(), Error> {
    let record =
        load_logout_unknown(directory, account_fingerprint)?.ok_or_else(logout_unknown_error)?;
    if record.operation_id != operation_id || record.plan_hash != plan_hash {
        return Err(logout_unknown_error());
    }
    let name =
        CString::new(unknown_barrier_name(account_fingerprint)?).map_err(|_| unavailable())?;
    // SAFETY: the exact barrier name is a single component in the pinned directory.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(unavailable());
    }
    directory.sync_all().map_err(|_| unavailable())
}

fn logout_recovery_hash_fields(
    account_fingerprint: &str,
    operation_id: &str,
    plan_hash: &str,
    created_at_unix_ms: u64,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"buaa-cli:gateway-logout-recovery:v1\0");
    for value in [
        account_fingerprint.as_bytes(),
        operation_id.as_bytes(),
        plan_hash.as_bytes(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.update(created_at_unix_ms.to_be_bytes());
    format!("{:x}", hash.finalize())
}

fn logout_recovery_hash(record: &LogoutUnknown) -> String {
    logout_recovery_hash_fields(
        &record.account_fingerprint,
        &record.operation_id,
        &record.plan_hash,
        record.created_at_unix_ms,
    )
}

fn validate_resolved_unknown(
    record: &LogoutResolvedUnknown,
    account_fingerprint: &str,
    operation_id: &str,
    plan_hash: &str,
) -> Result<(), Error> {
    if record.version != 1
        || record.account_fingerprint != account_fingerprint
        || record.operation_id != operation_id
        || record.plan_hash != plan_hash
        || !valid_hash(&record.account_fingerprint)
        || !valid_operation_id(&record.operation_id)
        || !valid_hash(&record.plan_hash)
        || record.recovery_hash
            != logout_recovery_hash_fields(
                &record.account_fingerprint,
                &record.operation_id,
                &record.plan_hash,
                record.created_at_unix_ms,
            )
    {
        return Err(unavailable());
    }
    Ok(())
}

fn load_resolved_unknown(
    directory: &File,
    account_fingerprint: &str,
    operation_id: &str,
    plan_hash: &str,
) -> Result<Option<LogoutResolvedUnknown>, Error> {
    let name = resolved_operation_name(plan_hash)?;
    let Some(record) = load_private_json(directory, &name)? else {
        return Ok(None);
    };
    validate_resolved_unknown(&record, account_fingerprint, operation_id, plan_hash)?;
    Ok(Some(record))
}

fn save_resolved_unknown(directory: &File, record: &LogoutResolvedUnknown) -> Result<(), Error> {
    validate_resolved_unknown(
        record,
        &record.account_fingerprint,
        &record.operation_id,
        &record.plan_hash,
    )?;
    let name = resolved_operation_name(&record.plan_hash)?;
    if let Some(existing) = load_private_json::<LogoutResolvedUnknown>(directory, &name)? {
        validate_resolved_unknown(
            &existing,
            &record.account_fingerprint,
            &record.operation_id,
            &record.plan_hash,
        )?;
        if existing.recovery_hash == record.recovery_hash
            && existing.created_at_unix_ms == record.created_at_unix_ms
        {
            return Ok(());
        }
        return Err(logout_unknown_error());
    }
    save_private_json(directory, &name, record)
}

fn validate_receipt(
    receipt: &LogoutReceipt,
    expected_account: &str,
    expected_operation: &str,
    expected_plan: &str,
) -> Result<(), Error> {
    if receipt.version != 2
        || receipt.account_fingerprint != expected_account
        || receipt.operation_id != expected_operation
        || receipt.plan_hash != expected_plan
        || !valid_hash(&receipt.account_fingerprint)
        || !valid_operation_id(&receipt.operation_id)
        || !valid_hash(&receipt.plan_hash)
        || receipt.requested_ip.parse::<Ipv4Addr>().is_err()
        || receipt
            .server_online_ip
            .as_ref()
            .is_some_and(|value| value.parse::<Ipv4Addr>().is_err())
        || !valid_hash(&receipt.response_body_sha256)
    {
        return Err(unavailable());
    }
    Ok(())
}

fn load_logout_receipt(
    directory: &File,
    plan_hash: &str,
    account_fingerprint: &str,
    operation_id: &str,
) -> Result<Option<LogoutReceipt>, Error> {
    let name = receipt_name(plan_hash)?;
    let Some(receipt) = load_private_json(directory, &name)? else {
        return Ok(None);
    };
    validate_receipt(&receipt, account_fingerprint, operation_id, plan_hash)?;
    Ok(Some(receipt))
}

fn save_logout_receipt(directory: &File, receipt: &LogoutReceipt) -> Result<(), Error> {
    validate_receipt(
        receipt,
        &receipt.account_fingerprint,
        &receipt.operation_id,
        &receipt.plan_hash,
    )?;
    let name = receipt_name(&receipt.plan_hash)?;
    save_private_json(directory, &name, receipt)
}

fn logout_receipt_value(receipt: LogoutReceipt, idempotency: &str) -> Value {
    json!({
        "schema_version":1,"type":"gateway_logout","result":"disconnected",
        "plan_hash":receipt.plan_hash,"operation_id":receipt.operation_id,
        "requested_ip":receipt.requested_ip,"server_online_ip":receipt.server_online_ip,
        "server_reported_success":true,
        "provenance":{"source_url":format!("{BASE}{PORTAL_PATH}"),"fetched_at_unix_ms":receipt.fetched_at_unix_ms,"response_body_sha256":receipt.response_body_sha256},
        "automatic_retry":false,"idempotency":idempotency
    })
}

fn usage_value(record: UsageRecord, cache_status: &str) -> Value {
    json!({
        "schema_version":1,"type":"gateway_usage","result":"usage_snapshot",
        "online":record.online,"online_ip":record.online_ip,
        "traffic":{"bytes_in":record.bytes_in,"bytes_out":record.bytes_out,"all_bytes":record.all_bytes,"sum_bytes":record.sum_bytes},
        "time":{"remain_seconds":record.remain_seconds,"sum_seconds":record.sum_seconds},
        "balance":{"user":record.user_balance,"wallet":record.wallet_balance},
        "provenance":{"source_url":format!("{BASE}{USAGE_PATH}"),"fetched_at_unix_ms":record.fetched_at_unix_ms,"response_body_sha256":record.response_body_sha256,"cache_status":cache_status},
        "redacted_fields":["user_name","real_name","user_mac"],
        "polling_policy":"interactive_only; scheduled/background callers must enforce >=15 minutes"
    })
}
fn usage_from(
    mode: CacheMode,
    directory: &File,
    online: impl FnOnce() -> Result<Value, Error>,
) -> Result<Value, Error> {
    if mode != CacheMode::Revalidate {
        if let Some(record) = load_usage(directory)? {
            return Ok(usage_value(record, "hit"));
        }
        if mode == CacheMode::Offline {
            return Err(Error::new(
                "offline_miss",
                "gateway usage is not in the private cache",
            ));
        }
    }
    online()
}

fn usage_online(transport: &GatewayTransport, directory: &File) -> Result<Value, Error> {
    transport.request_jsonp(
        RequestKind::Interactive,
        USAGE_PATH,
        Vec::new(),
        |value, meta| {
            let parsed: UsageResponse = match serde_json::from_value(value.clone()) {
                Ok(value) => value,
                Err(_) => {
                    return Processed {
                        result: Err(unavailable()),
                        outcome: AppOutcome::Http,
                    };
                }
            };
            if parsed.error != "ok" {
                return Processed {
                    result: Err(unavailable()),
                    outcome: AppOutcome::Http,
                };
            }
            let record = UsageRecord {
                version: 1,
                fetched_at_unix_ms: meta.fetched_at_unix_ms,
                response_body_sha256: meta.body_sha256.clone(),
                online: true,
                online_ip: if parsed.online_ip.is_empty() {
                    None
                } else {
                    Some(parsed.online_ip)
                },
                bytes_in: parsed.bytes_in,
                bytes_out: parsed.bytes_out,
                all_bytes: parsed.all_bytes,
                sum_bytes: parsed.sum_bytes,
                remain_seconds: parsed.remain_seconds,
                sum_seconds: parsed.sum_seconds,
                user_balance: parsed.user_balance,
                wallet_balance: parsed.wallet_balance,
            };
            let result = save_usage(directory, &record).map(|_| usage_value(record, "miss"));
            Processed {
                result,
                outcome: AppOutcome::Http,
            }
        },
    )
}

pub fn usage(mode: CacheMode) -> Result<Value, Error> {
    let directory = open_cache_directory()?;
    usage_from(mode, &directory, || {
        let transport = GatewayTransport::open()?;
        usage_online(&transport, &directory)
    })
}

pub fn resume_auth(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: ResumeInput = serde_json::from_str(input).map_err(|_| invalid())?;
    if request.intent != "RESUME GATEWAY AUTH" {
        return Err(invalid());
    }
    let governor = Governor::open().map_err(|_| unavailable())?;
    governor
        .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
        .map_err(|_| unavailable())?;
    Ok(json!({
        "schema_version":1,"type":"gateway_auth_resume","result":"one_attempt_armed",
        "network_request_performed":false,"cooldown_cleared":false,
        "instruction":"invoke gateway login --online once with typed LOGIN intent"
    }))
}

fn parse_login(input: &str) -> Result<LoginInput, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: LoginInput = serde_json::from_str(input).map_err(|_| invalid())?;
    validate_identity(&request.username, &request.ip, request.ac_id)?;
    if request.password.is_empty()
        || request.password.chars().count() > 1024
        || request.password.chars().any(char::is_control)
        || request.intent != format!("LOGIN {} {}", request.username, request.ip)
    {
        return Err(invalid());
    }
    Ok(request)
}

fn login_with(mut request: LoginInput, transport: &GatewayTransport) -> Result<Value, Error> {
    let state = transport.governor.status().map_err(|_| unavailable())?;
    if state.safety_latched {
        return Err(Error::new(
            "auth_latched",
            "shared request safety is latched",
        ));
    }
    if !state.authentication_armed {
        return Err(Error::new(
            "permission",
            "gateway login requires a deliberate gateway resume-auth command",
        ));
    }
    let challenge: String = transport.request_jsonp(
        RequestKind::Interactive,
        CHALLENGE_PATH,
        vec![
            ("username", request.username.clone()),
            ("ip", request.ip.clone()),
        ],
        |value, _| {
            let parsed: ChallengeResponse = match serde_json::from_value(value.clone()) {
                Ok(value) => value,
                Err(_) => {
                    return Processed {
                        result: Err(unavailable()),
                        outcome: AppOutcome::Http,
                    };
                }
            };
            match parsed
                .challenge
                .filter(|value| !value.is_empty() && value.len() <= 256)
            {
                Some(value) if parsed.error.is_empty() || parsed.error == "ok" => Processed {
                    result: Ok(value),
                    outcome: AppOutcome::Http,
                },
                _ => Processed {
                    result: Err(rejected()),
                    outcome: AppOutcome::AccountLocked,
                },
            }
        },
    )?;
    let material = crypto::derive(
        &request.username,
        &request.password,
        &request.ip,
        request.ac_id,
        &challenge,
    )
    .map_err(|_| unavailable())?;
    request.password.zeroize();
    // The separately armed one-shot permission is consumed only by this final
    // credential submission, never by challenge acquisition or an auto-retry.
    let password = format!("{{MD5}}{}", material.hmd5);
    let requested_ip = request.ip.clone();
    let parameters = vec![
        ("action", "login".to_owned()),
        ("username", request.username.clone()),
        ("password", password),
        ("ip", request.ip.clone()),
        ("ac_id", request.ac_id.to_string()),
        ("n", "200".to_owned()),
        ("type", "1".to_owned()),
        ("os", "Linux".to_owned()),
        ("name", "Linux".to_owned()),
        ("double_stack", "0".to_owned()),
        ("info", material.info),
        ("chksum", material.checksum),
    ];
    transport.request_jsonp(RequestKind::Authentication, PORTAL_PATH, parameters, |value, meta| {
        let parsed: PortalResponse = match serde_json::from_value(value.clone()) {
            Ok(value) => value,
            Err(_) => return Processed { result: Err(unavailable()), outcome: AppOutcome::CredentialRejected },
        };
        if parsed.error == "ok" && parsed.res == "ok" {
            let server_online_ip = if parsed.online_ip.is_empty() {
                None
            } else {
                match parsed.online_ip.parse::<Ipv4Addr>() {
                    Ok(value) => Some(value.to_string()),
                    Err(_) => return Processed { result: Err(unavailable()), outcome: AppOutcome::Http },
                }
            };
            let ip_matches_request = server_online_ip.as_deref().map(|value| value == requested_ip);
            Processed {
                result: Ok(json!({
                    "schema_version":1,"type":"gateway_login","result":"connected",
                    "requested_ip":requested_ip,"server_online_ip":server_online_ip,
                    "ip_matches_request":ip_matches_request,"server_reported_success":true,
                    "provenance":{"source_url":format!("{BASE}{PORTAL_PATH}"),"fetched_at_unix_ms":meta.fetched_at_unix_ms,"response_body_sha256":meta.body_sha256},
                    "authentication_attempts":1,"automatic_retry":false
                })),
                outcome: AppOutcome::Http,
            }
        } else {
            Processed { result: Err(rejected()), outcome: AppOutcome::CredentialRejected }
        }
    })
}

pub fn login(input: &str) -> Result<Value, Error> {
    let request = parse_login(input)?;
    let transport = GatewayTransport::open()?;
    login_with(request, &transport)
}

pub fn plan_logout(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: LogoutPlanInput = serde_json::from_str(input).map_err(|_| invalid())?;
    validate_identity(&request.username, &request.ip, request.ac_id)?;
    let operation_id = new_logout_operation_id()?;
    let plan_hash = logout_plan_hash(&request.username, &request.ip, request.ac_id, &operation_id);
    Ok(json!({
        "schema_version":1,"type":"gateway_logout_plan","result":"planned",
        "operation_id":operation_id,"plan_hash":plan_hash,
        "username_sha256":username_hash(&request.username),
        "requested_ip":request.ip,"ac_id":request.ac_id,
        "required_intent":format!("COMMIT GATEWAY LOGOUT {plan_hash}"),
        "network_request_performed":false,"immutable_plan":true
    }))
}

fn plan_logout_recovery_from(request: LogoutPlanInput, directory: &File) -> Result<Value, Error> {
    let account_fingerprint = logout_account_fingerprint(&request.username);
    let _operation_lock = lock_logout_account(directory, &account_fingerprint)?;
    let Some(record) = load_logout_unknown(directory, &account_fingerprint)? else {
        return Ok(json!({
            "schema_version":1,"type":"gateway_logout_recovery_plan",
            "result":"no_unknown_outcome","operation_id":null,"plan_hash":null,
            "recovery_hash":null,"remote_state":null,"required_intent":null,
            "network_request_performed":false,"immutable_plan":false
        }));
    };
    if logout_plan_hash(
        &request.username,
        &request.ip,
        request.ac_id,
        &record.operation_id,
    ) != record.plan_hash
    {
        return Err(invalid());
    }
    let recovery_hash = logout_recovery_hash(&record);
    Ok(json!({
        "schema_version":1,"type":"gateway_logout_recovery_plan",
        "result":"review_required","operation_id":record.operation_id,
        "plan_hash":record.plan_hash,"recovery_hash":recovery_hash,
        "remote_state":"unknown",
        "required_intent":format!("RESOLVE UNKNOWN GATEWAY LOGOUT {recovery_hash}"),
        "network_request_performed":false,"immutable_plan":true
    }))
}

pub fn plan_logout_recovery(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: LogoutPlanInput = serde_json::from_str(input).map_err(|_| invalid())?;
    validate_identity(&request.username, &request.ip, request.ac_id)?;
    let directory = open_cache_directory()?;
    plan_logout_recovery_from(request, &directory)
}

fn parse_logout_recovery_commit(input: &str) -> Result<LogoutRecoveryInput, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: LogoutRecoveryInput = serde_json::from_str(input).map_err(|_| invalid())?;
    validate_identity(&request.username, &request.ip, request.ac_id)?;
    if !valid_operation_id(&request.operation_id)
        || !valid_hash(&request.plan_hash)
        || !valid_hash(&request.recovery_hash)
        || logout_plan_hash(
            &request.username,
            &request.ip,
            request.ac_id,
            &request.operation_id,
        ) != request.plan_hash
        || request.intent != format!("RESOLVE UNKNOWN GATEWAY LOGOUT {}", request.recovery_hash)
    {
        return Err(invalid());
    }
    Ok(request)
}

fn logout_recovery_value(
    operation_id: String,
    plan_hash: String,
    recovery_hash: String,
    idempotency: &str,
) -> Value {
    json!({
        "schema_version":1,"type":"gateway_logout_recovery",
        "result":"unknown_resolved","operation_id":operation_id,
        "plan_hash":plan_hash,"recovery_hash":recovery_hash,
        "remote_state":"unknown","resolution":"offline_operator_review",
        "network_request_performed":false,"automatic_retry":false,
        "idempotency":idempotency
    })
}

fn resolve_logout_recovery_from(
    request: LogoutRecoveryInput,
    directory: &File,
) -> Result<Value, Error> {
    let account_fingerprint = logout_account_fingerprint(&request.username);
    let _operation_lock = lock_logout_account(directory, &account_fingerprint)?;
    if let Some(record) = load_logout_unknown(directory, &account_fingerprint)? {
        let recovery_hash = logout_recovery_hash(&record);
        if record.operation_id != request.operation_id
            || record.plan_hash != request.plan_hash
            || recovery_hash != request.recovery_hash
        {
            return Err(invalid());
        }
        let resolved = LogoutResolvedUnknown {
            version: 1,
            account_fingerprint: account_fingerprint.clone(),
            operation_id: record.operation_id.clone(),
            plan_hash: record.plan_hash.clone(),
            created_at_unix_ms: record.created_at_unix_ms,
            recovery_hash: recovery_hash.clone(),
            resolved_at_unix_ms: unix_ms()?,
        };
        save_resolved_unknown(directory, &resolved)?;
        clear_logout_unknown(
            directory,
            &account_fingerprint,
            &request.operation_id,
            &request.plan_hash,
        )?;
        return Ok(logout_recovery_value(
            request.operation_id,
            request.plan_hash,
            recovery_hash,
            "resolved",
        ));
    }
    if let Some(resolved) = load_resolved_unknown(
        directory,
        &account_fingerprint,
        &request.operation_id,
        &request.plan_hash,
    )? && resolved.recovery_hash == request.recovery_hash
    {
        return Ok(logout_recovery_value(
            resolved.operation_id,
            resolved.plan_hash,
            resolved.recovery_hash,
            "idempotent_hit",
        ));
    }
    Err(logout_unknown_error())
}

pub fn resolve_logout_recovery(input: &str) -> Result<Value, Error> {
    let request = parse_logout_recovery_commit(input)?;
    let directory = open_cache_directory()?;
    resolve_logout_recovery_from(request, &directory)
}

fn parse_logout_commit(input: &str) -> Result<LogoutCommitInput, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: LogoutCommitInput = serde_json::from_str(input).map_err(|_| invalid())?;
    validate_identity(&request.username, &request.ip, request.ac_id)?;
    if !valid_operation_id(&request.operation_id) {
        return Err(invalid());
    }
    let expected = logout_plan_hash(
        &request.username,
        &request.ip,
        request.ac_id,
        &request.operation_id,
    );
    if request.plan_hash != expected
        || request.intent != format!("COMMIT GATEWAY LOGOUT {expected}")
    {
        return Err(invalid());
    }
    Ok(request)
}

fn commit_logout_with(
    request: LogoutCommitInput,
    transport: &GatewayTransport,
    directory: &File,
) -> Result<Value, Error> {
    let plan_hash = request.plan_hash.clone();
    let operation_id = request.operation_id.clone();
    let account_fingerprint = logout_account_fingerprint(&request.username);
    let requested_ip = request.ip.clone();
    let unknown = LogoutUnknown {
        version: 1,
        account_fingerprint: account_fingerprint.clone(),
        operation_id: operation_id.clone(),
        plan_hash: plan_hash.clone(),
        created_at_unix_ms: unix_ms()?,
    };
    let parameters = vec![
        ("action", "logout".to_owned()),
        ("username", request.username),
        ("ip", request.ip),
        ("ac_id", request.ac_id.to_string()),
    ];
    let result = transport.request_jsonp_with_preflight(
        RequestKind::Interactive,
        PORTAL_PATH,
        parameters,
        || save_logout_unknown(directory, &unknown),
        |value, meta| {
            let parsed: PortalResponse = match serde_json::from_value(value.clone()) {
                Ok(value) => value,
                Err(_) => {
                    return Processed {
                        result: Err(unavailable()),
                        outcome: AppOutcome::Http,
                    };
                }
            };
            if parsed.error == "ok" && parsed.res == "ok" {
                let server_online_ip = if parsed.online_ip.is_empty() {
                    None
                } else {
                    match parsed.online_ip.parse::<Ipv4Addr>() {
                        Ok(value) => Some(value.to_string()),
                        Err(_) => {
                            return Processed {
                                result: Err(unavailable()),
                                outcome: AppOutcome::Http,
                            };
                        }
                    }
                };
                let receipt = LogoutReceipt {
                    version: 2,
                    account_fingerprint: account_fingerprint.clone(),
                    operation_id: operation_id.clone(),
                    plan_hash: plan_hash.clone(),
                    requested_ip: requested_ip.clone(),
                    server_online_ip,
                    fetched_at_unix_ms: meta.fetched_at_unix_ms,
                    response_body_sha256: meta.body_sha256.clone(),
                };
                let result = save_logout_receipt(directory, &receipt)
                    .and_then(|_| {
                        clear_logout_unknown(
                            directory,
                            &account_fingerprint,
                            &operation_id,
                            &plan_hash,
                        )
                    })
                    .map(|_| logout_receipt_value(receipt, "committed"));
                Processed {
                    result,
                    outcome: AppOutcome::Http,
                }
            } else {
                Processed {
                    result: Err(Error::new("unavailable", "gateway logout was not accepted")),
                    outcome: AppOutcome::Http,
                }
            }
        },
    );
    if result.is_err() {
        match load_logout_unknown(directory, &account_fingerprint) {
            Ok(Some(record))
                if record.operation_id == operation_id && record.plan_hash == plan_hash =>
            {
                return Err(logout_unknown_error());
            }
            Err(_) => return Err(logout_unknown_error()),
            _ => {}
        }
    }
    result
}

fn commit_logout_from(
    request: LogoutCommitInput,
    directory: &File,
    commit: impl FnOnce(LogoutCommitInput) -> Result<Value, Error>,
) -> Result<Value, Error> {
    let account_fingerprint = logout_account_fingerprint(&request.username);
    // This per-account operation lock serializes the receipt recheck and mutation
    // boundary. It supplements, but never replaces or bypasses, the shared governor.
    let _operation_lock = lock_logout_account(directory, &account_fingerprint)?;
    let unknown = load_logout_unknown(directory, &account_fingerprint)?;
    if unknown.is_some() {
        return Err(logout_unknown_error());
    }
    if load_resolved_unknown(
        directory,
        &account_fingerprint,
        &request.operation_id,
        &request.plan_hash,
    )?
    .is_some()
    {
        return Err(logout_unknown_error());
    }
    if let Some(receipt) = load_logout_receipt(
        directory,
        &request.plan_hash,
        &account_fingerprint,
        &request.operation_id,
    )? {
        return Ok(logout_receipt_value(receipt, "idempotent_hit"));
    }
    commit(request)
}

pub fn commit_logout(input: &str) -> Result<Value, Error> {
    let request = parse_logout_commit(input)?;
    let directory = open_cache_directory()?;
    commit_logout_from(request, &directory, |request| {
        let transport = GatewayTransport::open()?;
        commit_logout_with(request, &transport, &directory)
    })
}

pub fn schema() -> Value {
    let ip = json!({"type":"string","format":"ipv4"});
    let usage_ip =
        json!({"anyOf":[{"type":"string","format":"ipv4"},{"type":"string","format":"ipv6"}]});
    let nullable_u64 = json!({"type":["integer","null"],"minimum":0});
    let nullable_number = json!({"type":["number","null"],"minimum":0});
    let provenance = json!({"type":"object","additionalProperties":false,"required":["source_url","fetched_at_unix_ms","response_body_sha256"],"properties":{"source_url":{"type":"string"},"fetched_at_unix_ms":{"type":"integer","minimum":0},"response_body_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}}});
    let usage_provenance = json!({"type":"object","additionalProperties":false,"required":["source_url","fetched_at_unix_ms","response_body_sha256","cache_status"],"properties":{"source_url":{"const":"https://gw.buaa.edu.cn/cgi-bin/rad_user_info"},"fetched_at_unix_ms":{"type":"integer","minimum":0},"response_body_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"cache_status":{"enum":["hit","miss"]}}});
    let no_control = r"^[^\u0000-\u001F\u007F-\u009F]*$";
    let identity = json!({"username":{"type":"string","minLength":1,"maxLength":256},"ip":ip.clone(),"ac_id":{"type":"integer","minimum":1,"maximum":1000000}});
    json!({
        "resume-auth":{
            "input":{"type":"object","additionalProperties":false,"required":["intent"],"x-maxInputBytes":16384,"properties":{"intent":{"const":"RESUME GATEWAY AUTH"}}},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","network_request_performed","cooldown_cleared","instruction"],"properties":{"schema_version":{"const":1},"type":{"const":"gateway_auth_resume"},"result":{"const":"one_attempt_armed"},"network_request_performed":{"const":false},"cooldown_cleared":{"const":false},"instruction":{"type":"string"}}}
        },
        "usage":{
            "input":{"type":"null"},"options":{"--online":"cache miss read","--refresh":"explicit live read"},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","online","online_ip","traffic","time","balance","provenance","redacted_fields","polling_policy"],"properties":{"schema_version":{"const":1},"type":{"const":"gateway_usage"},"result":{"const":"usage_snapshot"},"online":{"type":"boolean"},"online_ip":{"anyOf":[usage_ip,{"type":"null"}]},"traffic":{"type":"object","additionalProperties":false,"required":["bytes_in","bytes_out","all_bytes","sum_bytes"],"properties":{"bytes_in":nullable_u64.clone(),"bytes_out":nullable_u64.clone(),"all_bytes":nullable_u64.clone(),"sum_bytes":nullable_u64.clone()}},"time":{"type":"object","additionalProperties":false,"required":["remain_seconds","sum_seconds"],"properties":{"remain_seconds":nullable_u64.clone(),"sum_seconds":nullable_u64}},"balance":{"type":"object","additionalProperties":false,"required":["user","wallet"],"properties":{"user":nullable_number.clone(),"wallet":nullable_number}},"provenance":usage_provenance,"redacted_fields":{"const":["user_name","real_name","user_mac"]},"polling_policy":{"const":"interactive_only; scheduled/background callers must enforce >=15 minutes"}}}
        },
        "login":{
            "input":{"type":"object","additionalProperties":false,"required":["username","password","ip","ac_id","intent"],"x-maxInputBytes":16384,"properties":{"username":{"allOf":[identity["username"].clone(),{"pattern":no_control}]},"password":{"type":"string","minLength":1,"maxLength":1024,"pattern":no_control,"writeOnly":true},"ip":identity["ip"].clone(),"ac_id":identity["ac_id"].clone(),"intent":{"type":"string","description":"Exactly LOGIN <username> <ip>."}}},"options":{"--online":{"const":true},"prerequisite":"gateway resume-auth"},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","requested_ip","server_online_ip","ip_matches_request","server_reported_success","provenance","authentication_attempts","automatic_retry"],"properties":{"schema_version":{"const":1},"type":{"const":"gateway_login"},"result":{"const":"connected"},"requested_ip":ip.clone(),"server_online_ip":{"anyOf":[ip.clone(),{"type":"null"}]},"ip_matches_request":{"type":["boolean","null"]},"server_reported_success":{"const":true},"provenance":provenance.clone(),"authentication_attempts":{"const":1},"automatic_retry":{"const":false}}}
        },
        "logout-plan":{
            "input":{"type":"object","additionalProperties":false,"required":["username","ip","ac_id"],"x-maxInputBytes":16384,"properties":{"username":{"allOf":[identity["username"].clone(),{"pattern":no_control}]},"ip":identity["ip"].clone(),"ac_id":identity["ac_id"].clone()}},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","operation_id","plan_hash","username_sha256","requested_ip","ac_id","required_intent","network_request_performed","immutable_plan"],"properties":{"schema_version":{"const":1},"type":{"const":"gateway_logout_plan"},"result":{"const":"planned"},"operation_id":{"type":"string","pattern":"^[0-9a-f]{32}$"},"plan_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"username_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"requested_ip":ip.clone(),"ac_id":identity["ac_id"].clone(),"required_intent":{"type":"string"},"network_request_performed":{"const":false},"immutable_plan":{"const":true}}}
        },
        "logout-recovery-plan":{
            "input":{"type":"object","additionalProperties":false,"required":["username","ip","ac_id"],"x-maxInputBytes":16384,"properties":{"username":{"allOf":[identity["username"].clone(),{"pattern":no_control}]},"ip":identity["ip"].clone(),"ac_id":identity["ac_id"].clone()}},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","operation_id","plan_hash","recovery_hash","remote_state","required_intent","network_request_performed","immutable_plan"],"properties":{"schema_version":{"const":1},"type":{"const":"gateway_logout_recovery_plan"},"result":{"enum":["no_unknown_outcome","review_required"]},"operation_id":{"type":["string","null"],"pattern":"^[0-9a-f]{32}$"},"plan_hash":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"},"recovery_hash":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"},"remote_state":{"anyOf":[{"const":"unknown"},{"type":"null"}]},"required_intent":{"type":["string","null"]},"network_request_performed":{"const":false},"immutable_plan":{"type":"boolean"}}}
        },
        "logout-commit":{
            "input":{"type":"object","additionalProperties":false,"required":["username","ip","ac_id","operation_id","plan_hash","intent"],"x-maxInputBytes":16384,"properties":{"username":{"allOf":[identity["username"].clone(),{"pattern":no_control}]},"ip":identity["ip"].clone(),"ac_id":identity["ac_id"].clone(),"operation_id":{"type":"string","pattern":"^[0-9a-f]{32}$"},"plan_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"intent":{"type":"string","description":"Exactly COMMIT GATEWAY LOGOUT <plan_hash>."}}},"options":{"--online":{"const":true},"prerequisite":"gateway logout-plan"},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","operation_id","plan_hash","requested_ip","server_online_ip","server_reported_success","provenance","automatic_retry","idempotency"],"properties":{"schema_version":{"const":1},"type":{"const":"gateway_logout"},"result":{"const":"disconnected"},"operation_id":{"type":"string","pattern":"^[0-9a-f]{32}$"},"plan_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"requested_ip":ip.clone(),"server_online_ip":{"anyOf":[ip.clone(),{"type":"null"}]},"server_reported_success":{"const":true},"provenance":provenance.clone(),"automatic_retry":{"const":false},"idempotency":{"enum":["committed","idempotent_hit"]}}}
        },
        "logout-recovery-commit":{
            "input":{"type":"object","additionalProperties":false,"required":["username","ip","ac_id","operation_id","plan_hash","recovery_hash","intent"],"x-maxInputBytes":16384,"properties":{"username":{"allOf":[identity["username"].clone(),{"pattern":no_control}]},"ip":identity["ip"].clone(),"ac_id":identity["ac_id"].clone(),"operation_id":{"type":"string","pattern":"^[0-9a-f]{32}$"},"plan_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"recovery_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"intent":{"type":"string","description":"Exactly RESOLVE UNKNOWN GATEWAY LOGOUT <recovery_hash>."}}},"options":{"--offline":{"const":true},"network_request_performed":false,"prerequisite":"gateway logout-recovery-plan"},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","operation_id","plan_hash","recovery_hash","remote_state","resolution","network_request_performed","automatic_retry","idempotency"],"properties":{"schema_version":{"const":1},"type":{"const":"gateway_logout_recovery"},"result":{"const":"unknown_resolved"},"operation_id":{"type":"string","pattern":"^[0-9a-f]{32}$"},"plan_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"recovery_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"remote_state":{"const":"unknown"},"resolution":{"const":"offline_operator_review"},"network_request_performed":{"const":false},"automatic_retry":{"const":false},"idempotency":{"enum":["resolved","idempotent_hit"]}}}
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs::{self, DirBuilder};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "buaa-gateway-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn cache(&self) -> File {
            governor::open_directory(&self.0.join("cache"), true, true).unwrap()
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
        count: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }
    impl Server {
        fn new(mut handler: impl FnMut(&mut TcpStream, &str, usize) + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let (sender, requests) = mpsc::channel();
            let count = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let worker_count = Arc::clone(&count);
            let worker_stop = Arc::clone(&stop);
            let worker = thread::spawn(move || {
                while !worker_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            socket
                                .set_read_timeout(Some(Duration::from_secs(5)))
                                .unwrap();
                            let mut request = Vec::new();
                            let mut byte = [0u8];
                            while !request.ends_with(b"\r\n\r\n") && request.len() < 64 * 1024 {
                                match socket.read(&mut byte) {
                                    Ok(1) => request.push(byte[0]),
                                    _ => break,
                                }
                            }
                            let request = String::from_utf8(request).unwrap();
                            let index = worker_count.fetch_add(1, Ordering::SeqCst);
                            sender.send((Instant::now(), request.clone())).unwrap();
                            handler(&mut socket, &request, index);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("loopback gateway failed: {error}"),
                    }
                }
            });
            Self {
                address,
                requests,
                count,
                stop,
                worker: Some(worker),
            }
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
    fn callback_and_query(request: &str) -> (String, BTreeMap<String, String>) {
        let target = request
            .lines()
            .next()
            .unwrap()
            .split_ascii_whitespace()
            .nth(1)
            .unwrap();
        let url = Url::parse(&format!("http://fixture{target}")).unwrap();
        let query: BTreeMap<_, _> = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        (query["callback"].clone(), query)
    }
    fn reply(socket: &mut TcpStream, request: &str, value: Value) {
        let (callback, _) = callback_and_query(request);
        let body = format!("{callback}({value})");
        write!(socket, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    }
    fn reply_malformed(socket: &mut TcpStream, request: &str) {
        let (callback, _) = callback_and_query(request);
        let body = format!("{callback}(not-json)");
        write!(socket, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    }
    fn transport_at(governor_dir: &Path, address: std::net::SocketAddr) -> GatewayTransport {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .http1_only()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        GatewayTransport {
            governor: Governor::isolated_for_test(governor_dir).unwrap(),
            client,
            route: Some(address),
        }
    }
    fn transport(fixture: &Fixture, server: &Server) -> GatewayTransport {
        transport_at(&fixture.0.join("governor"), server.address)
    }
    #[test]
    fn preflight_failure_releases_lease_without_sending() {
        let fixture = Fixture::new();
        let server = Server::new(|_, _, _| panic!("preflight failure sent a request"));
        let transport = transport(&fixture, &server);
        let result: Result<(), Error> = transport.request_jsonp_with_preflight(
            RequestKind::Interactive,
            PORTAL_PATH,
            vec![("action", "logout".into())],
            || Err(invalid()),
            |_, _| panic!("preflight failure processed a response"),
        );
        assert_eq!(result.unwrap_err().code, "invalid_input");
        assert_eq!(server.count.load(Ordering::SeqCst), 0);
        thread::sleep(Duration::from_millis(5_100));
        let lease = transport
            .governor
            .try_acquire(RequestKind::Interactive)
            .unwrap();
        lease.finish_without_request().unwrap();
        assert_eq!(server.count.load(Ordering::SeqCst), 0);
    }
    #[test]
    #[ignore = "spawned by the cross-process logout idempotency test"]
    fn logout_process_worker() {
        let Ok(input) = std::env::var("BUAA_GATEWAY_LOGOUT_TEST_INPUT") else {
            return;
        };
        let cache_path = PathBuf::from(std::env::var_os("BUAA_GATEWAY_LOGOUT_TEST_CACHE").unwrap());
        let governor_path =
            PathBuf::from(std::env::var_os("BUAA_GATEWAY_LOGOUT_TEST_GOVERNOR").unwrap());
        let address = std::env::var("BUAA_GATEWAY_LOGOUT_TEST_ADDRESS")
            .unwrap()
            .parse()
            .unwrap();
        let ready_path = PathBuf::from(std::env::var_os("BUAA_GATEWAY_LOGOUT_TEST_READY").unwrap());
        let cache = governor::open_directory(&cache_path, false, true).unwrap();
        let delay_ms: u64 = std::env::var("BUAA_GATEWAY_LOGOUT_TEST_DELAY_MS")
            .unwrap_or_else(|_| "0".into())
            .parse()
            .unwrap();
        fs::write(ready_path, b"ready").unwrap();
        let request = parse_logout_commit(&input).unwrap();
        let result = commit_logout_from(request, &cache, |request| {
            if delay_ms > 0 {
                thread::sleep(Duration::from_millis(delay_ms));
            }
            let transport = transport_at(&governor_path, address);
            commit_logout_with(request, &transport, &cache)
        })
        .unwrap();
        println!(
            "LOGOUT_WORKER_RESULT={}",
            result["idempotency"].as_str().unwrap()
        );
    }
    fn spawn_logout_process(
        input: &str,
        cache_path: &Path,
        governor_path: &Path,
        address: std::net::SocketAddr,
        ready_path: &Path,
        delay_ms: u64,
    ) -> Child {
        let module = module_path!();
        let module = module.strip_prefix("buaa_cli::").unwrap_or(module);
        let test_filter = format!("{module}::logout_process_worker");
        Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(test_filter)
            .arg("--ignored")
            .arg("--nocapture")
            .env("BUAA_GATEWAY_LOGOUT_TEST_INPUT", input)
            .env("BUAA_GATEWAY_LOGOUT_TEST_CACHE", cache_path)
            .env("BUAA_GATEWAY_LOGOUT_TEST_GOVERNOR", governor_path)
            .env("BUAA_GATEWAY_LOGOUT_TEST_ADDRESS", address.to_string())
            .env("BUAA_GATEWAY_LOGOUT_TEST_READY", ready_path)
            .env("BUAA_GATEWAY_LOGOUT_TEST_DELAY_MS", delay_ms.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    #[test]
    fn usage_read_is_cached_and_redacts_identity_fields() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, request, _| {
            reply(
                socket,
                request,
                json!({
                    "error":"ok","online_ip":"10.0.0.2","bytes_in":10,"bytes_out":20,
                    "sum_bytes":30,"remain_seconds":40,"user_balance":1.5,
                    "user_name":"private-user","real_name":"private-name","user_mac":"private-mac"
                }),
            )
        });
        let cache = fixture.cache();
        let transport = transport(&fixture, &server);
        let first = usage_from(CacheMode::PreferCache, &cache, || {
            usage_online(&transport, &cache)
        })
        .unwrap();
        assert_eq!(first["traffic"]["sum_bytes"], 30);
        assert_eq!(first["provenance"]["cache_status"], "miss");
        let encoded = serde_json::to_string(&first).unwrap();
        assert!(
            !encoded.contains("private-user")
                && !encoded.contains("private-name")
                && !encoded.contains("private-mac")
        );
        let second = usage_from(CacheMode::Offline, &cache, || {
            panic!("cache hit attempted network")
        })
        .unwrap();
        assert_eq!(second["provenance"]["cache_status"], "hit");
        assert_eq!(server.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn login_and_logout_plan_commit_are_governed_without_plaintext_password() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, request, index| {
            assert!(!request.contains("synthetic-secret"));
            assert!(!request.to_ascii_lowercase().contains("cookie:"));
            let (_, query) = callback_and_query(request);
            match index {
                0 => reply(
                    socket,
                    request,
                    json!({"error":"ok","res":"ok","challenge":"0123456789abcdef0123456789abcdef"}),
                ),
                1 => {
                    assert_eq!(query["action"], "login");
                    assert!(query["password"].starts_with("{MD5}"));
                    assert!(query["info"].starts_with("{SRBX1}"));
                    assert_eq!(query["chksum"].len(), 40);
                    reply(
                        socket,
                        request,
                        json!({"error":"ok","res":"ok","online_ip":"10.0.0.2"}),
                    );
                }
                2 => {
                    assert_eq!(query["action"], "logout");
                    assert!(!query.contains_key("password"));
                    reply(
                        socket,
                        request,
                        json!({"error":"ok","res":"ok","online_ip":"10.0.0.2"}),
                    );
                }
                _ => panic!("unexpected gateway request"),
            }
        });
        let transport = transport(&fixture, &server);
        let unarmed = parse_login(r#"{"username":"student","password":"synthetic-secret","ip":"10.0.0.2","ac_id":62,"intent":"LOGIN student 10.0.0.2"}"#).unwrap();
        assert_eq!(
            login_with(unarmed, &transport).unwrap_err().code,
            "permission"
        );
        assert_eq!(server.count.load(Ordering::SeqCst), 0);
        transport
            .governor
            .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
            .unwrap();
        let login = parse_login(r#"{"username":"student","password":"synthetic-secret","ip":"10.0.0.2","ac_id":62,"intent":"LOGIN student 10.0.0.2"}"#).unwrap();
        let output = login_with(login, &transport).unwrap();
        assert_eq!(output["authentication_attempts"], 1);
        assert_eq!(output["requested_ip"], "10.0.0.2");
        assert_eq!(output["server_online_ip"], "10.0.0.2");
        assert_eq!(output["ip_matches_request"], true);
        let status = transport.governor.status().unwrap();
        assert!(!status.safety_latched && !status.authentication_armed);
        let cache = fixture.cache();
        let plan = plan_logout(r#"{"username":"student","ip":"10.0.0.2","ac_id":62}"#).unwrap();
        assert!(plan["username_sha256"].as_str().is_some());
        assert!(!serde_json::to_string(&plan).unwrap().contains("student"));
        let commit_input = json!({
            "username":"student","ip":"10.0.0.2","ac_id":62,
            "operation_id":plan["operation_id"],
            "plan_hash":plan["plan_hash"],"intent":plan["required_intent"]
        })
        .to_string();
        let commit = parse_logout_commit(&commit_input).unwrap();
        let committed = commit_logout_from(commit, &cache, |request| {
            commit_logout_with(request, &transport, &cache)
        })
        .unwrap();
        assert_eq!(committed["idempotency"], "committed");
        let repeat = parse_logout_commit(&commit_input).unwrap();
        let repeated = commit_logout_from(repeat, &cache, |_| {
            panic!("idempotent hit attempted network")
        })
        .unwrap();
        assert_eq!(repeated["idempotency"], "idempotent_hit");
        let observations: Vec<_> = server.requests.try_iter().collect();
        assert_eq!(observations.len(), 3);
        assert!(
            observations
                .windows(2)
                .all(|pair| pair[1].0.duration_since(pair[0].0) >= Duration::from_secs(5))
        );
    }

    #[test]
    fn logout_plan_creates_a_fresh_operation_identity() {
        let input = r#"{"username":"student","ip":"10.0.0.2","ac_id":62}"#;
        let first = plan_logout(input).unwrap();
        let second = plan_logout(input).unwrap();
        assert_ne!(first["operation_id"], second["operation_id"]);
        assert_ne!(first["plan_hash"], second["plan_hash"]);
        assert_eq!(first["network_request_performed"], false);
        assert_eq!(first["immutable_plan"], true);
    }
    #[test]
    fn each_fresh_logout_plan_sends_once_and_reuses_only_its_receipt() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let server = Server::new(|socket, request, _| {
            reply(
                socket,
                request,
                json!({"error":"ok","res":"ok","online_ip":"10.0.0.2"}),
            )
        });
        let transport = transport(&fixture, &server);
        let plan_input = r#"{"username":"student","ip":"10.0.0.2","ac_id":62}"#;
        let first_plan = plan_logout(plan_input).unwrap();
        let first_input = json!({
            "username":"student","ip":"10.0.0.2","ac_id":62,
            "operation_id":first_plan["operation_id"],"plan_hash":first_plan["plan_hash"],
            "intent":first_plan["required_intent"]
        })
        .to_string();
        let first = commit_logout_from(
            parse_logout_commit(&first_input).unwrap(),
            &cache,
            |request| commit_logout_with(request, &transport, &cache),
        )
        .unwrap();
        assert_eq!(first["idempotency"], "committed");
        assert_eq!(
            commit_logout_from(
                parse_logout_commit(&first_input).unwrap(),
                &cache,
                |_| panic!("same logout plan sent twice"),
            )
            .unwrap()["idempotency"],
            "idempotent_hit"
        );
        assert_eq!(server.count.load(Ordering::SeqCst), 1);

        thread::sleep(Duration::from_millis(5_100));
        let second_plan = plan_logout(plan_input).unwrap();
        assert_ne!(first_plan["operation_id"], second_plan["operation_id"]);
        assert_ne!(first_plan["plan_hash"], second_plan["plan_hash"]);
        let second_input = json!({
            "username":"student","ip":"10.0.0.2","ac_id":62,
            "operation_id":second_plan["operation_id"],"plan_hash":second_plan["plan_hash"],
            "intent":second_plan["required_intent"]
        })
        .to_string();
        let second = commit_logout_from(
            parse_logout_commit(&second_input).unwrap(),
            &cache,
            |request| commit_logout_with(request, &transport, &cache),
        )
        .unwrap();
        assert_eq!(second["idempotency"], "committed");
        assert_eq!(second["operation_id"], second_plan["operation_id"]);
        assert_eq!(
            commit_logout_from(
                parse_logout_commit(&second_input).unwrap(),
                &cache,
                |_| panic!("second logout plan sent twice"),
            )
            .unwrap()["idempotency"],
            "idempotent_hit"
        );
        let observations: Vec<_> = server.requests.try_iter().collect();
        assert_eq!(observations.len(), 2);
        assert!(observations[1].0.duration_since(observations[0].0) >= Duration::from_secs(5));
    }

    #[test]
    fn receipt_persistence_failure_keeps_unknown_logout_barrier() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let plan = plan_logout(r#"{"username":"student","ip":"10.0.0.2","ac_id":62}"#).unwrap();
        let input = json!({
            "username":"student","ip":"10.0.0.2","ac_id":62,
            "operation_id":plan["operation_id"],"plan_hash":plan["plan_hash"],
            "intent":plan["required_intent"]
        })
        .to_string();
        let receipt_path = fixture
            .0
            .join("cache")
            .join(receipt_name(plan["plan_hash"].as_str().unwrap()).unwrap());
        let server = Server::new(move |socket, request, _| {
            DirBuilder::new().mode(0o700).create(&receipt_path).unwrap();
            reply(
                socket,
                request,
                json!({"error":"ok","res":"ok","online_ip":"10.0.0.2"}),
            );
        });
        let transport = transport(&fixture, &server);
        let error = commit_logout_from(parse_logout_commit(&input).unwrap(), &cache, |request| {
            commit_logout_with(request, &transport, &cache)
        })
        .unwrap_err();
        assert_eq!(error.code, "unknown_outcome");
        assert!(
            load_logout_unknown(&cache, &logout_account_fingerprint("student"))
                .unwrap()
                .is_some()
        );
        assert_eq!(
            commit_logout_from(parse_logout_commit(&input).unwrap(), &cache, |_| panic!(
                "failed receipt persistence was retried"
            ),)
            .unwrap_err()
            .code,
            "unknown_outcome"
        );
        assert_eq!(server.count.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn unknown_logout_outcome_requires_explicit_offline_resolution() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let plan_input = r#"{"username":"student","ip":"10.0.0.2","ac_id":62}"#;
        let plan = plan_logout(plan_input).unwrap();
        let commit_input = json!({
            "username":"student","ip":"10.0.0.2","ac_id":62,
            "operation_id":plan["operation_id"],"plan_hash":plan["plan_hash"],
            "intent":plan["required_intent"]
        })
        .to_string();
        let server = Server::new(|socket, request, _| reply_malformed(socket, request));
        let transport = transport(&fixture, &server);
        let error = commit_logout_from(
            parse_logout_commit(&commit_input).unwrap(),
            &cache,
            |request| commit_logout_with(request, &transport, &cache),
        )
        .unwrap_err();
        assert_eq!(error.code, "unknown_outcome");
        assert_eq!(server.count.load(Ordering::SeqCst), 1);

        let mismatched_identity =
            serde_json::from_str(r#"{"username":"student","ip":"10.0.0.3","ac_id":62}"#).unwrap();
        assert_eq!(
            plan_logout_recovery_from(mismatched_identity, &cache)
                .unwrap_err()
                .code,
            "invalid_input"
        );
        let plan_request: LogoutPlanInput = serde_json::from_str(plan_input).unwrap();
        let recovery_plan = plan_logout_recovery_from(plan_request, &cache).unwrap();
        assert_eq!(recovery_plan["result"], "review_required");
        assert_eq!(recovery_plan["remote_state"], "unknown");
        assert_eq!(recovery_plan["network_request_performed"], false);
        assert_eq!(recovery_plan["immutable_plan"], true);
        let recovery_input = json!({
            "username":"student","ip":"10.0.0.2","ac_id":62,
            "operation_id":recovery_plan["operation_id"],
            "plan_hash":recovery_plan["plan_hash"],
            "recovery_hash":recovery_plan["recovery_hash"],
            "intent":recovery_plan["required_intent"]
        })
        .to_string();
        let resolved = resolve_logout_recovery_from(
            parse_logout_recovery_commit(&recovery_input).unwrap(),
            &cache,
        )
        .unwrap();
        assert_eq!(resolved["resolution"], "offline_operator_review");
        assert_eq!(resolved["remote_state"], "unknown");
        assert_eq!(resolved["network_request_performed"], false);
        assert_eq!(resolved["automatic_retry"], false);
        assert_eq!(resolved["idempotency"], "resolved");
        let repeated = resolve_logout_recovery_from(
            parse_logout_recovery_commit(&recovery_input).unwrap(),
            &cache,
        )
        .unwrap();
        assert_eq!(repeated["idempotency"], "idempotent_hit");
        assert_eq!(
            commit_logout_from(
                parse_logout_commit(&commit_input).unwrap(),
                &cache,
                |_| panic!("resolved unknown logout was retried"),
            )
            .unwrap_err()
            .code,
            "unknown_outcome"
        );
        let after_resolution =
            plan_logout_recovery_from(serde_json::from_str(plan_input).unwrap(), &cache).unwrap();
        assert_eq!(after_resolution["result"], "no_unknown_outcome");
        assert_eq!(server.count.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn account_unknown_barrier_and_resolved_tombstone_precede_receipts() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let plan_input = r#"{"username":"student","ip":"10.0.0.2","ac_id":62}"#;
        let prior_plan = plan_logout(plan_input).unwrap();
        let uncertain_plan = plan_logout(plan_input).unwrap();
        let account_fingerprint = logout_account_fingerprint("student");
        let store_receipt = |plan: &Value| {
            save_logout_receipt(
                &cache,
                &LogoutReceipt {
                    version: 2,
                    account_fingerprint: account_fingerprint.clone(),
                    operation_id: plan["operation_id"].as_str().unwrap().to_owned(),
                    plan_hash: plan["plan_hash"].as_str().unwrap().to_owned(),
                    requested_ip: "10.0.0.2".into(),
                    server_online_ip: Some("10.0.0.2".into()),
                    fetched_at_unix_ms: unix_ms().unwrap(),
                    response_body_sha256: "a".repeat(64),
                },
            )
            .unwrap();
        };
        store_receipt(&prior_plan);
        store_receipt(&uncertain_plan);
        let uncertain_operation = uncertain_plan["operation_id"].as_str().unwrap().to_owned();
        let uncertain_hash = uncertain_plan["plan_hash"].as_str().unwrap().to_owned();
        save_logout_unknown(
            &cache,
            &LogoutUnknown {
                version: 1,
                account_fingerprint: account_fingerprint.clone(),
                operation_id: uncertain_operation.clone(),
                plan_hash: uncertain_hash.clone(),
                created_at_unix_ms: unix_ms().unwrap(),
            },
        )
        .unwrap();
        let commit_input = |plan: &Value| {
            json!({
                "username":"student","ip":"10.0.0.2","ac_id":62,
                "operation_id":plan["operation_id"],"plan_hash":plan["plan_hash"],
                "intent":plan["required_intent"]
            })
            .to_string()
        };
        assert_eq!(
            commit_logout_from(
                parse_logout_commit(&commit_input(&prior_plan)).unwrap(),
                &cache,
                |_| panic!("account-level unknown barrier was bypassed"),
            )
            .unwrap_err()
            .code,
            "unknown_outcome"
        );

        let recovery_plan =
            plan_logout_recovery_from(serde_json::from_str(plan_input).unwrap(), &cache).unwrap();
        let recovery_input = json!({
            "username":"student","ip":"10.0.0.2","ac_id":62,
            "operation_id":uncertain_operation,"plan_hash":uncertain_hash,
            "recovery_hash":recovery_plan["recovery_hash"],
            "intent":recovery_plan["required_intent"]
        })
        .to_string();
        resolve_logout_recovery_from(
            parse_logout_recovery_commit(&recovery_input).unwrap(),
            &cache,
        )
        .unwrap();
        assert_eq!(
            commit_logout_from(
                parse_logout_commit(&commit_input(&uncertain_plan)).unwrap(),
                &cache,
                |_| panic!("resolved unknown operation was replayed"),
            )
            .unwrap_err()
            .code,
            "unknown_outcome"
        );
        assert_eq!(
            commit_logout_from(
                parse_logout_commit(&commit_input(&prior_plan)).unwrap(),
                &cache,
                |_| panic!("existing completed operation was sent again"),
            )
            .unwrap()["idempotency"],
            "idempotent_hit"
        );
    }

    #[test]
    fn concurrent_logout_commits_share_receipt_across_processes() {
        let fixture = Fixture::new();
        let cache_path = fixture.0.join("cache");
        let _cache = governor::open_directory(&cache_path, true, true).unwrap();
        let governor_path = fixture.0.join("governor");
        let plan = plan_logout(r#"{"username":"student","ip":"10.0.0.2","ac_id":62}"#).unwrap();
        let input = json!({
            "username":"student","ip":"10.0.0.2","ac_id":62,
            "operation_id":plan["operation_id"],"plan_hash":plan["plan_hash"],
            "intent":plan["required_intent"]
        })
        .to_string();
        let (release_tx, release_rx) = mpsc::channel();
        let (started_tx, started_rx) = mpsc::channel();
        let server = Server::new(move |socket, request, index| {
            assert!(!request.contains("password"));
            if index == 0 {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(60)).unwrap();
            }
            reply(
                socket,
                request,
                json!({"error":"ok","res":"ok","online_ip":"10.0.0.2"}),
            );
        });
        let first_ready = fixture.0.join("first.ready");
        let second_ready = fixture.0.join("second.ready");
        let first = spawn_logout_process(
            &input,
            &cache_path,
            &governor_path,
            server.address,
            &first_ready,
            0,
        );
        // This post-miss delay exceeds the global request gap if the account lock is absent.
        let first_reached_server = started_rx.recv_timeout(Duration::from_secs(10)).is_ok();
        let mut second = spawn_logout_process(
            &input,
            &cache_path,
            &governor_path,
            server.address,
            &second_ready,
            6_500,
        );
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        while !second_ready.exists() && Instant::now() < ready_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let second_started = second_ready.exists();
        if second_started {
            let wait_deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < wait_deadline {
                if second.try_wait().unwrap().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        let second_waited_for_first = second.try_wait().unwrap().is_none();
        let _ = release_tx.send(());
        let first_output = first.wait_with_output().unwrap();
        let second_output = second.wait_with_output().unwrap();
        let first_stdout = String::from_utf8_lossy(&first_output.stdout);
        let second_stdout = String::from_utf8_lossy(&second_output.stdout);
        assert!(first_reached_server);
        assert!(second_started);
        assert!(second_waited_for_first);
        assert!(first_output.status.success(), "{first_stdout}");
        assert!(second_output.status.success(), "{second_stdout}");
        assert!(
            first_stdout.contains("LOGOUT_WORKER_RESULT=committed"),
            "{first_stdout}"
        );
        assert!(
            second_stdout.contains("LOGOUT_WORKER_RESULT=idempotent_hit"),
            "{second_stdout}"
        );
        assert_eq!(server.count.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn credential_rejection_consumes_one_auth_attempt_and_latches() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, request, _| {
            reply(socket, request, json!({"error":"rejected","res":"failed"}))
        });
        let transport = transport(&fixture, &server);
        transport
            .governor
            .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
            .unwrap();
        let result: Result<(), Error> = transport.request_jsonp(
            RequestKind::Authentication,
            PORTAL_PATH,
            vec![("action", "login".into())],
            |_, _| Processed {
                result: Err(rejected()),
                outcome: AppOutcome::CredentialRejected,
            },
        );
        assert_eq!(result.unwrap_err().code, "auth_latched");
        let status = transport.governor.status().unwrap();
        assert!(status.safety_latched && !status.authentication_armed);
        assert_eq!(server.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn malformed_successful_authentication_response_keeps_latch() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, request, _| {
            let (callback, _) = callback_and_query(request);
            let body = format!("{callback}(<html>challenge</html>)");
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let transport = transport(&fixture, &server);
        transport
            .governor
            .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
            .unwrap();
        let result: Result<(), Error> = transport.request_jsonp(
            RequestKind::Authentication,
            PORTAL_PATH,
            vec![("action", "login".into())],
            |_, _| panic!("malformed response reached application processor"),
        );
        assert_eq!(result.unwrap_err().code, "unavailable");
        let status = transport.governor.status().unwrap();
        assert!(status.safety_latched && !status.authentication_armed);
    }

    #[test]
    fn invalid_typed_intent_is_rejected_before_transport_construction() {
        let error = match parse_login(
            r#"{"username":"private-user","password":"private-password","ip":"10.0.0.2","ac_id":62,"intent":"LOGIN wrong"}"#,
        ) {
            Err(error) => error,
            Ok(_) => panic!("invalid intent was accepted"),
        };
        assert_eq!(error.code, "invalid_input");
        assert!(!error.message.contains("private"));
        let plan = plan_logout(r#"{"username":"student","ip":"10.0.0.2","ac_id":62}"#).unwrap();
        let bad_commit = json!({
            "username":"student","ip":"10.0.0.2","ac_id":62,
            "operation_id":plan["operation_id"],
            "plan_hash":plan["plan_hash"],"intent":"COMMIT GATEWAY LOGOUT wrong"
        })
        .to_string();
        assert!(parse_logout_commit(&bad_commit).is_err());
        let long_username = "学".repeat(257);
        let long_input = json!({"username":long_username,"password":"x","ip":"10.0.0.2","ac_id":62,"intent":format!("LOGIN {} 10.0.0.2", "学".repeat(257))}).to_string();
        assert_eq!(
            parse_login(&long_input).err().unwrap().code,
            "invalid_input"
        );
        let contract = schema();
        assert_eq!(contract["resume-auth"]["input"]["x-maxInputBytes"], 16384);
        assert_eq!(
            contract["login"]["input"]["properties"]["password"]["maxLength"],
            1024
        );
        assert!(contract["login"]["input"]["properties"]["password"]["pattern"].is_string());
        assert_eq!(
            contract["usage"]["output"]["properties"]["provenance"]["additionalProperties"],
            false
        );
        assert_eq!(
            contract["usage"]["output"]["properties"]["provenance"]["properties"]["cache_status"]["enum"],
            json!(["hit", "miss"])
        );
        assert!(
            contract["logout-plan"]["output"]["properties"]["plan_hash"]["pattern"].is_string()
        );
        assert_eq!(
            contract["logout-commit"]["output"]["properties"]["idempotency"]["enum"],
            json!(["committed", "idempotent_hit"])
        );
        assert!(
            contract["logout-plan"]["output"]["properties"]["operation_id"]["pattern"].is_string()
        );
        assert!(
            contract["logout-commit"]["input"]["required"]
                .as_array()
                .unwrap()
                .contains(&json!("operation_id"))
        );
        assert_eq!(
            contract["logout-recovery-plan"]["output"]["properties"]["network_request_performed"]["const"],
            false
        );
        assert_eq!(
            contract["logout-recovery-commit"]["options"]["--offline"]["const"],
            true
        );
        assert_eq!(
            contract["logout-recovery-commit"]["output"]["properties"]["remote_state"]["const"],
            "unknown"
        );
    }
}
