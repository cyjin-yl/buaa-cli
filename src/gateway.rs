//! Governed BUAA SRun gateway operations.
//! Credentials are accepted only through bounded JSON stdin and are never stored.
mod crypto;

use crate::governor::{self, Governor, Outcome, RequestKind, ResumeAuthorization};
use crate::net::{self, CacheMode, Error};
use reqwest::blocking::Client;
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
    plan_hash: String,
    requested_ip: String,
    server_online_ip: Option<String>,
    fetched_at_unix_ms: u64,
    response_body_sha256: String,
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
        mut parameters: Vec<(&str, String)>,
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

fn logout_plan_hash(username: &str, ip: &str, ac_id: u32) -> String {
    let mut hash = Sha256::new();
    hash.update(b"buaa-cli:gateway-logout-plan:v1\0");
    for value in [username.as_bytes(), ip.as_bytes()] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.update(ac_id.to_be_bytes());
    format!("{:x}", hash.finalize())
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

fn receipt_name(plan_hash: &str) -> Result<String, Error> {
    if !valid_hash(plan_hash) {
        return Err(invalid());
    }
    Ok(format!("logout-{plan_hash}.json"))
}

fn validate_receipt(receipt: &LogoutReceipt, expected: &str) -> Result<(), Error> {
    if receipt.version != 1
        || receipt.plan_hash != expected
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

fn load_logout_receipt(directory: &File, plan_hash: &str) -> Result<Option<LogoutReceipt>, Error> {
    let name = receipt_name(plan_hash)?;
    let file = match governor::open_child(directory, &name, libc::O_RDONLY) {
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
    let receipt: LogoutReceipt = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
    validate_receipt(&receipt, plan_hash)?;
    Ok(Some(receipt))
}

fn save_logout_receipt(directory: &File, receipt: &LogoutReceipt) -> Result<(), Error> {
    validate_receipt(receipt, &receipt.plan_hash)?;
    let name = receipt_name(&receipt.plan_hash)?;
    match governor::open_child(directory, &name, libc::O_RDONLY) {
        Ok(file) => governor::validate_private_file(&file).map_err(|_| unavailable())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(unavailable()),
    }
    let (temporary_name, mut temporary) =
        governor::create_temporary(directory).map_err(|_| unavailable())?;
    let result = (|| {
        serde_json::to_writer(&mut temporary, receipt).map_err(|_| unavailable())?;
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

fn logout_receipt_value(receipt: LogoutReceipt, idempotency: &str) -> Value {
    json!({
        "schema_version":1,"type":"gateway_logout","result":"disconnected",
        "plan_hash":receipt.plan_hash,"requested_ip":receipt.requested_ip,
        "server_online_ip":receipt.server_online_ip,"server_reported_success":true,
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
    let plan_hash = logout_plan_hash(&request.username, &request.ip, request.ac_id);
    Ok(json!({
        "schema_version":1,"type":"gateway_logout_plan","result":"planned",
        "plan_hash":plan_hash,"username_sha256":username_hash(&request.username),
        "requested_ip":request.ip,"ac_id":request.ac_id,
        "required_intent":format!("COMMIT GATEWAY LOGOUT {plan_hash}"),
        "network_request_performed":false,"immutable_plan":true
    }))
}

fn parse_logout_commit(input: &str) -> Result<LogoutCommitInput, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: LogoutCommitInput = serde_json::from_str(input).map_err(|_| invalid())?;
    validate_identity(&request.username, &request.ip, request.ac_id)?;
    let expected = logout_plan_hash(&request.username, &request.ip, request.ac_id);
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
    let requested_ip = request.ip.clone();
    let parameters = vec![
        ("action", "logout".to_owned()),
        ("username", request.username),
        ("ip", request.ip),
        ("ac_id", request.ac_id.to_string()),
    ];
    transport.request_jsonp(
        RequestKind::Interactive,
        PORTAL_PATH,
        parameters,
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
                    version: 1,
                    plan_hash: plan_hash.clone(),
                    requested_ip: requested_ip.clone(),
                    server_online_ip,
                    fetched_at_unix_ms: meta.fetched_at_unix_ms,
                    response_body_sha256: meta.body_sha256.clone(),
                };
                let result = save_logout_receipt(directory, &receipt)
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
    )
}

fn commit_logout_from(
    request: LogoutCommitInput,
    directory: &File,
    commit: impl FnOnce(LogoutCommitInput) -> Result<Value, Error>,
) -> Result<Value, Error> {
    if let Some(receipt) = load_logout_receipt(directory, &request.plan_hash)? {
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
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","plan_hash","username_sha256","requested_ip","ac_id","required_intent","network_request_performed","immutable_plan"],"properties":{"schema_version":{"const":1},"type":{"const":"gateway_logout_plan"},"result":{"const":"planned"},"plan_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"username_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"requested_ip":ip.clone(),"ac_id":identity["ac_id"].clone(),"required_intent":{"type":"string"},"network_request_performed":{"const":false},"immutable_plan":{"const":true}}}
        },
        "logout-commit":{
            "input":{"type":"object","additionalProperties":false,"required":["username","ip","ac_id","plan_hash","intent"],"x-maxInputBytes":16384,"properties":{"username":{"allOf":[identity["username"].clone(),{"pattern":no_control}]},"ip":identity["ip"].clone(),"ac_id":identity["ac_id"].clone(),"plan_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"intent":{"type":"string","description":"Exactly COMMIT GATEWAY LOGOUT <plan_hash>."}}},"options":{"--online":{"const":true},"prerequisite":"gateway logout-plan"},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","plan_hash","requested_ip","server_online_ip","server_reported_success","provenance","automatic_retry","idempotency"],"properties":{"schema_version":{"const":1},"type":{"const":"gateway_logout"},"result":{"const":"disconnected"},"plan_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"requested_ip":ip,"server_online_ip":{"anyOf":[{"type":"string","format":"ipv4"},{"type":"null"}]},"server_reported_success":{"const":true},"provenance":provenance,"automatic_retry":{"const":false},"idempotency":{"enum":["committed","idempotent_hit"]}}}
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
    use std::path::PathBuf;
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
    fn transport(fixture: &Fixture, server: &Server) -> GatewayTransport {
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
            governor: Governor::isolated_for_test(&fixture.0.join("governor")).unwrap(),
            client,
            route: Some(server.address),
        }
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
    }
}
