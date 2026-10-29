//! Independent, read-only Smart BUAA services. Secrets are stdin-only inputs;
//! they are never persisted. Returned raw evidence is private caller-owned data.
//! CAS/browser authentication is deliberately not reconstructed here.
use crate::{governor::{Governor, Outcome}, net::{self, Error}};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use md5::Md5;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read};
use zeroize::Zeroizing;

const LIMIT: u64 = 8 * 1024 * 1024;
const PREFIX: &str = "c640ca392cd45fb3a55b00a63a86c618";
const MOBILE: &str = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Mobile Safari/537.36";

// Deliberately neither Debug, Clone nor Serialize: credentials must not enter
// generic Value trees, diagnostics or accidental ordinary String copies.
struct Secret(Zeroizing<String>);
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self,D::Error> {
        String::deserialize(deserializer).map(|s|Self(Zeroizing::new(s)))
    }
}
impl std::ops::Deref for Secret {
    type Target = str;
    fn deref(&self) -> &str { self.0.as_str() }
}

struct SecretBody { bytes: Zeroizing<Vec<u8>>, offset: usize }
impl Read for SecretBody {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = buffer.len().min(self.bytes.len()-self.offset);
        buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset+count]);
        self.offset += count;
        Ok(count)
    }
}

#[derive(Deserialize)]
#[serde(tag = "service", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Exams { enabled: bool, cookie: Secret, term_code: String },
    Classrooms { enabled: bool, cookie: Secret, campus_id: i64, date: String },
    Library { enabled: bool, token: Secret, query: LibraryQuery },
    Cgyy { enabled: bool, app_key: String, access_token: Secret, query: CgyyQuery },
    Running { enabled: bool, uid: Secret, token: Secret, query: RunningQuery },
}

impl Request {
    fn contains_secret_bytes(&self, bytes: &[u8]) -> bool {
        fn contains(bytes: &[u8], value: &str) -> bool {
            net::carries_secret(bytes,value)
        }
        fn contains_cookie(bytes: &[u8], cookie: &str) -> bool {
            contains(bytes, cookie) || cookie.split(';').filter_map(|part|part.split_once('='))
                .any(|(_, value)| {
                    let value = value.trim();
                    contains(bytes,value) || value.strip_prefix('"').and_then(|v|v.strip_suffix('"'))
                        .is_some_and(|unquoted|contains(bytes,unquoted))
                })
        }
        fn contains_form_value(bytes: &[u8], value: &str) -> bool {
            // Neither the literal credential nor its supported encoded forms
            // can fit in a shorter candidate. Avoid re-encoding it per scalar.
            if bytes.len() < value.len() { return false; }
            if contains(bytes,value) { return true; }
            // Running transmits these values with form_urlencoded. An echo of
            // that reversible wire representation is still a credential.
            let encoded = Zeroizing::new(url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>());
            contains(bytes,&encoded)
        }
        match self {
            Self::Exams{cookie,..}|Self::Classrooms{cookie,..} => contains_cookie(bytes,cookie),
            Self::Library{token,..} => contains(bytes,token),
            Self::Cgyy{access_token,..} => contains(bytes,access_token),
            Self::Running{uid,token,..} => contains_form_value(bytes,uid)||contains_form_value(bytes,token),
        }
    }

    fn response_contains_secret(&self, bytes: &[u8]) -> bool {
        if self.contains_secret_bytes(bytes) { return true; }
        // JSON permits arbitrary escapes in values and keys. Decode only
        // strings containing escapes, keeping each temporary zeroized.
        let mut cursor = 0;
        while cursor < bytes.len() {
            if bytes[cursor] != b'"' { cursor += 1; continue; }
            let opening = cursor;
            cursor += 1;
            let mut escaped = false;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'\\' => { escaped = true; cursor = cursor.saturating_add(2); },
                    b'"' => break,
                    _ => cursor += 1,
                }
            }
            if cursor >= bytes.len() { break; }
            if escaped && let Ok(value) = serde_json::from_slice::<String>(&bytes[opening..=cursor]) {
                let value = Zeroizing::new(value);
                if self.contains_secret_bytes(value.as_bytes()) { return true; }
            }
            cursor += 1;
        }
        false
    }

    fn output_contains_numeric_secret(&self, value: &Value) -> bool {
        match value {
            Value::Number(_) => net::json_scalar_matches(value, |bytes| self.contains_secret_bytes(bytes)),
            Value::Array(values) => values.iter().any(|value| self.output_contains_numeric_secret(value)),
            Value::Object(fields) => fields.values().any(|value| self.output_contains_numeric_secret(value)),
            _ => false,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum LibraryQuery {
    Login { cas: Secret },
    Premises { day: String },
    Areas { premises_ids: Vec<String>, date: String },
    Times { id: String },
    Seats { id: String, day: String, start_time: String, end_time: String },
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum CgyyQuery {
    Venues,
    PurposeTypes,
    DayInfo { search_date: String, venue_site_id: u32 },
    Orders { page: u32, size: u32 },
    OrderDetail { id: u32 },
    LockCode,
    Login { sso_token: Secret },
    ManageLogin { cookie: Secret },
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RunningQuery {
    Categories,
    Items { classify_id: String },
    Count { classify_id: String, user_id: String },
    Records { classify_id: String, user_id: String, page: u32, limit: u32 },
}

fn error(code: &'static str, message: &'static str) -> Error { Error::new(code, message) }
fn invalid() -> Error { error("invalid_input", "smart input does not match the selected service contract") }
fn valid_date(s: &str) -> bool {
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .is_ok_and(|d| d.format("%Y-%m-%d").to_string() == s)
}
fn secret(s: &str) -> Result<(), Error> {
    if s.is_empty() || s.len() > 16384 || s.chars().any(char::is_control) { Err(invalid()) } else { Ok(()) }
}
fn date(s: &str) -> Result<(), Error> { if valid_date(s) { Ok(()) } else { Err(invalid()) } }

/// Upstream CgyySigner.kt: slash-prefixed API path (without server base),
/// sorted raw key+value pairs without separators, UTF-8; empty/nonprimitive
/// values and metadata keys are excluded. GET callers inject nocache first.
pub fn sign(path: &str, parameters: &BTreeMap<String, Value>, timestamp: &str) -> String {
    format!("{:x}",Md5::digest(canonical_input(path,parameters,timestamp).as_bytes()))
}

pub fn canonical_input(path: &str, parameters: &BTreeMap<String, Value>, timestamp: &str) -> String {
    let mut canonical = String::from(PREFIX);
    if !path.starts_with('/') { canonical.push('/'); }
    canonical.push_str(path);
    for (key,value) in parameters {
        if ["gmtCreate","gmtModified","creator","modifier","id","_index","_rowKey"].contains(&key.as_str()) { continue; }
        let primitive = match value {
            Value::String(s) if !s.is_empty() => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => continue,
        };
        canonical.push_str(key); canonical.push_str(&primitive);
    }
    for part in [timestamp," ",PREFIX] { canonical.push_str(part); }
    canonical
}

#[derive(Clone, Copy)]
enum Service { Exams, Classrooms, Library, Cgyy, Running }
impl Service {
    fn name(self) -> &'static str { match self {
        Self::Exams => "exams", Self::Classrooms => "classrooms",
        Self::Library => "library", Self::Cgyy => "cgyy", Self::Running => "running",
    }}
}

#[derive(Clone, Copy)]
enum Source { Network, OperatorSupplied, Disabled }

fn with_source(mut output: Value, source: Source) -> Value {
    let (name,performed) = match source {
        Source::Network => ("network",true),
        Source::OperatorSupplied => ("operator_supplied",false),
        Source::Disabled => ("disabled",false),
    };
    output["source"] = json!(name);
    output["network_performed"] = json!(performed);
    output
}

fn withheld(service: Service, status: u16, content_type: Option<&str>, bytes: &[u8], reason: &'static str) -> Value {
    // Parameters are untrusted response data and can themselves contain a
    // credential. Retain only a safe MIME essence in a withheld receipt.
    let essence = content_type.and_then(|value|value.split(';').next()).map(str::trim)
        .filter(|value| !value.is_empty() && value.bytes().all(|b|
            b.is_ascii_alphanumeric() || matches!(b,b'/'|b'.'|b'+'|b'-'|b'_')));
    json!({"service":service.name(),"result":"sensitive_response_withheld","fallback_reason":reason,
        "http_status":status,"raw_evidence_withheld":true,"content_type":essence,
        "content_type_parameters_withheld":content_type.is_some_and(|value|Some(value)!=essence),
        "byte_length":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes))})
}

fn admit_content(service: Service, status: u16, content_type: Option<&str>, bytes: &[u8], kind: &str, issues_session_cookie: bool) -> Value {
    if issues_session_cookie {
        // Even the MIME essence can echo the newly issued credential.
        let mut output=withheld(service,status,None,bytes,"session_cookie_issued");
        output["content_type_parameters_withheld"]=json!(content_type.is_some());
        output
    } else {
        parse(service,status,content_type,bytes,kind)
    }
}

/// Check projected numbers before releasing the original request lease. JSON
/// can serialize an exponent using a different spelling from the wire bytes.
fn admit_checked_json(request: &Request, service: Service, status: u16, content_type: Option<&str>, bytes: &[u8], kind: &str) -> Value {
    let output = admit_content(service, status, content_type, bytes, kind, false);
    // HTTP status, byte length and other refusal metadata are generated here,
    // not echoed source fields. Preserve independent session-denial results.
    let source_value = match output.get("result").and_then(Value::as_str) {
        Some("ok") => output.get("data"),
        Some("business_error") => output.get("upstream_code"),
        _ => None,
    };
    if source_value.is_some_and(|value| request.output_contains_numeric_secret(value)) {
        withheld(service, status, content_type, bytes, "credential_echo")
    } else {
        output
    }
}

// Inspect JSON member names before allocation into a generic Value. Decode
// escaped keys in a zeroizing buffer so escaped names cannot bypass admission.
fn unsafe_member_names(bytes: &[u8]) -> Option<&'static str> {
    fn credential_key(key: &str) -> bool {
        ["token","access_token","refresh_token","id_token","sso_token","cas",
         "cookie","set-cookie","authorization","cgauthorization","password","passwd","sessionid",
         "session_id","ticket","execution","csrf","_csrf","csrf_token","csrftoken",
         "secret","credential","api_key","client_secret"]
            .iter().any(|name|key.eq_ignore_ascii_case(name))
    }
    let mut credential = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' { i += 1; continue; }
        let opening = i;
        i += 1;
        let start = i;
        let mut escaped = false;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => { escaped = true; i = i.saturating_add(2); },
                b'"' => break,
                _ => i += 1,
            }
        }
        if i >= bytes.len() { return Some("credential_field"); }
        let end = i;
        i += 1;
        let mut next = i;
        while bytes.get(next).is_some_and(u8::is_ascii_whitespace) { next += 1; }
        if bytes.get(next) != Some(&b':') { continue; }
        if escaped {
            let Ok(key) = serde_json::from_slice::<String>(&bytes[opening..=end]) else { return Some("credential_field"); };
            let key = Zeroizing::new(key);
            if key.as_str() == "$serde_json::private::RawValue" { return Some("unreviewed_representation"); }
            credential |= credential_key(&key);
        } else if let Ok(key) = std::str::from_utf8(&bytes[start..end]) {
            if key == "$serde_json::private::RawValue" { return Some("unreviewed_representation"); }
            credential |= credential_key(key);
        }
    }
    credential.then_some("credential_field")
}

fn session_expired(message: &str) -> bool {
    ["登录失效", "请重新登录", "未登录"].iter().any(|s| message.contains(s))
}

// Classify known session rejection independently from output withholding.
// RawValue borrows unrelated credential-bearing JSON rather than cloning it.
fn response_denies_session(service: Service, bytes: &[u8]) -> bool {
    if std::str::from_utf8(bytes).is_err() { return false; }
    struct Envelope<'a> {
        code: Option<&'a serde_json::value::RawValue>,
        message: Option<&'a serde_json::value::RawValue>,
        msg: Option<&'a serde_json::value::RawValue>,
        m: Option<&'a serde_json::value::RawValue>,
    }
    impl<'de> Deserialize<'de> for Envelope<'de> {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self,D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Envelope<'de>;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a JSON response object")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value,A::Error> {
                    let mut result = Envelope {code:None,message:None,msg:None,m:None};
                    while let Some(key) = map.next_key::<String>()? {
                        let key = Zeroizing::new(key);
                        match key.as_str() {
                            "code" => result.code = Some(map.next_value()?),
                            "message" => result.message = Some(map.next_value()?),
                            "msg" => result.msg = Some(map.next_value()?),
                            "m" => result.m = Some(map.next_value()?),
                            _ => { map.next_value::<serde::de::IgnoredAny>()?; },
                        }
                    }
                    Ok(result)
                }
            }
            deserializer.deserialize_map(Visitor)
        }
    }
    let Ok(envelope) = serde_json::from_slice::<Envelope<'_>>(bytes) else { return false; };
    if matches!(service,Service::Running)
        && envelope.code.is_some_and(|code|serde_json::from_str::<i64>(code.get()).is_ok_and(|value|value == -98))
    {
        return true;
    }
    if matches!(service,Service::Exams|Service::Classrooms|Service::Library|Service::Cgyy)
        && let Some(message) = envelope.message.or(envelope.msg).or(envelope.m)
        && let Ok(message) = serde_json::from_str::<String>(message.get())
    {
        let message = Zeroizing::new(message);
        return session_expired(&message);
    }
    false
}

struct ResponseOutcome<'a> {
    status: u16,
    retry_after: Option<&'a str>,
    challenge: bool,
    incomplete: bool,
    service: Service,
    body: &'a [u8],
}

fn finish_response(
    mut lease: crate::governor::RequestLease<'_>,
    facts: ResponseOutcome<'_>,
) -> Result<(), Error> {
    // A complete, recognized JSON denial remains authoritative even when MIME
    // ambiguity prevents exposing or otherwise admitting the response.
    let denied = !facts.incomplete && response_denies_session(facts.service,facts.body);
    if denied {
        // Application-level authentication rejection is distinct from a CAPTCHA;
        // retain the actual HTTP/cooldown facts before latching the denial.
        lease.observe_http(facts.status,facts.retry_after,facts.challenge)
            .map_err(|_|error("governor_error","cannot persist smart response facts"))?;
        lease.finish(Outcome::CredentialRejected)
            .map_err(|_|error("governor_error","cannot settle smart session denial"))
    } else {
        lease.finish(Outcome::Http{status:facts.status,retry_after:facts.retry_after,
            challenge:facts.challenge,network_failure:facts.incomplete})
            .map_err(|_|error("governor_error","cannot settle smart request"))
    }
}

// Validate envelopes before projecting. Preserve all upstream fields rather
// than manufacturing absent dates, counts, seat availability or account roles.
fn parse(service: Service, status: u16, content_type: Option<&str>, bytes: &[u8], kind: &str) -> Value {
    // Even offline auth bodies can contain tickets/tokens. Never turn them into
    // generic Values or raw diagnostic evidence.
    if matches!(kind,"login"|"manage_login") {
        return json!({"service":service.name(),"result":"unsupported","reason":"authentication exchange disabled pending Authentication-lease, deliberate-resume and known-outcome proof","write_operations_performed":false});
    }
    if !(200..300).contains(&status) {
        return withheld(service,status,content_type,bytes,"http_status_unsafe_response");
    }
    if let Some(reason) = unsafe_member_names(bytes) {
        return withheld(service,status,content_type,bytes,reason);
    }
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
        return withheld(service,status,content_type,bytes,"invalid_json_authenticated_response");
    };
    let message = v.get("message").or_else(||v.get("msg")).or_else(||v.get("m")).and_then(Value::as_str).unwrap_or("");
    let code = v.get("code");
    if (matches!(service,Service::Exams|Service::Classrooms|Service::Library|Service::Cgyy) && session_expired(message))
        || (matches!(service,Service::Running) && code == Some(&json!(-98))) {
        let mut out = withheld(service,status,content_type,bytes,"session_expired");
        out["result"] = json!("session_expired");
        return out;
    }
    let success = match service {
        Service::Exams => code == Some(&json!("0")),
        Service::Classrooms => v.get("e").and_then(Value::as_i64) == Some(0),
        Service::Library => matches!(code.and_then(Value::as_i64),Some(0|1)),
        Service::Cgyy => code.and_then(Value::as_i64) == Some(200),
        Service::Running => code.and_then(Value::as_i64) == Some(1),
    };
    if !success {
        let mut out = withheld(service,status,content_type,bytes,"business_error_or_unknown_envelope");
        out["result"] = json!("business_error");
        // Exam rejection is authoritative, including graduate-account refusal.
        out["upstream_code"] = code.cloned().or_else(||v.get("e").cloned()).unwrap_or(Value::Null);
        out["upstream_message"] = json!(message);
        return out;
    }
    let data = match service {
        Service::Exams => v.get("datas").filter(|x| x.is_array()).cloned(),
        Service::Classrooms => v.pointer("/d/list").filter(|x|x.is_object()).and_then(|buildings| {
            let mut rows = Vec::new();
            for (building, rooms) in buildings.as_object()? {
                for room in rooms.as_array()? {
                    let mut row = room.as_object()?.clone();
                    let periods = room.get("kxsds")?.as_str()?;
                    let mut parsed = Vec::new();
                    if !periods.is_empty() {
                        for item in periods.split(',') {
                            parsed.push(item.trim().parse::<u32>().ok()?);
                        }
                    }
                    row.insert("building".into(),json!(building));
                    row.insert("free_periods".into(),json!(parsed));
                    rows.push(Value::Object(row));
                }
            }
            Some(json!(rows))
        }),
        Service::Library => match kind {
            "premises" => v.pointer("/data/list").filter(|x|x.is_array()).cloned(),
            "areas" => v.pointer("/data/area").filter(|x|x.is_array()).cloned(),
            "times" => v.pointer("/data/date/list").filter(|x|x.is_array()).cloned(),
            "seats" => v.pointer("/data/list").and_then(Value::as_array).and_then(|seats| {
                seats.iter().map(|seat| {
                    let mut row = seat.as_object()?.clone();
                    let status = seat.get("status")?.as_str()?;
                    row.insert("available".into(),json!(status == "1"));
                    Some(Value::Object(row))
                }).collect::<Option<Vec<_>>>().map(|x|json!(x))
            }),
            _ => None,
        },
        Service::Cgyy => if kind == "venues" { v.pointer("/data/content").filter(|x|x.is_array()).cloned() }
        else { v.get("data").cloned() },
        Service::Running => if kind == "count" {
            v.get("result").filter(|x|x.is_object()).cloned()
        } else {
            v.pointer("/result/list").filter(|x|x.is_array()).map(|list|json!({"list":list,"total":v.pointer("/result/total")}))
        },
    };
    match data {
        Some(data) => json!({"service":service.name(),"result":"ok","data":data,"write_operations_performed":false}),
        None => withheld(service,status,content_type,bytes,"unrecognized_data_shape"),
    }
}

/// Execute exactly one read request. `online=false` always refuses network;
/// each service has its own mandatory enabled flag. Inputs must arrive on stdin
/// at the CLI boundary. No automatic login, refresh, pagination or retry occurs.
pub fn read(input: &str, online: bool) -> Result<Value, Error> {
    if input.len() > 65536 { return Err(invalid()); }
    let input = Zeroizing::new(input.to_owned());
    let request: Request = serde_json::from_str(&input).map_err(|_|invalid())?;
    let enabled = match &request {
        Request::Exams{enabled,..}|Request::Classrooms{enabled,..}|Request::Library{enabled,..}|
        Request::Cgyy{enabled,..}|Request::Running{enabled,..} => *enabled,
    };
    if !enabled { return Ok(with_source(json!({"result":"disabled","write_operations_performed":false}),Source::Disabled)); }
    if matches!(&request,Request::Library{query:LibraryQuery::Login{..},..}
        |Request::Cgyy{query:CgyyQuery::Login{..}|CgyyQuery::ManageLogin{..},..}) {
        return Err(error("authentication_exchange_blocked","authentication exchanges require proven Authentication lease, deliberate resume, credential rejection and unknown-outcome settlement; no request sent"));
    }
    if !online { return Err(error("online_required","smart reads require explicit online permission; no cache is claimed")); }
    let client = Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never()).referer(false).no_proxy()
        .timeout(std::time::Duration::from_secs(45)).build()
        .map_err(|_|error("network_error","cannot initialize smart HTTPS client"))?;
    let (service, kind, builder) = match &request {
        Request::Exams{cookie,term_code,..} => {
            secret(cookie)?; secret(term_code)?;
            (Service::Exams,"exams",client.get("https://byxt.buaa.edu.cn/jwapp/sys/homeapp/api/home/student/exams.do")
                .query(&[("termCode",term_code)]).header("Cookie",&**cookie)
                .header("Accept","*/*").header("X-Requested-With","XMLHttpRequest")
                .header("Referer","https://byxt.buaa.edu.cn/jwapp/sys/homeapp/index.html"))
        },
        Request::Classrooms{cookie,campus_id,date:day,..} => {
            secret(cookie)?; date(day)?;
            (Service::Classrooms,"rooms",client.get("https://app.buaa.edu.cn/buaafreeclass/wap/default/search1")
                .query(&[("xqid",campus_id.to_string()),("floorid",String::new()),("date",day.clone())])
                .header("Cookie",&**cookie).header("User-Agent",MOBILE).header("X-Requested-With","XMLHttpRequest")
                .header("Referer","https://app.buaa.edu.cn/site/classRoomQuery/index"))
        },
        Request::Library{token,query,..} => {
            if !matches!(query,LibraryQuery::Login{..}) { secret(token)?; }
            let (path,kind,body) = match query {
                LibraryQuery::Login{cas} => { let _ = &**cas; return Err(error("authentication_exchange_blocked","CAS exchange disabled; no request sent")); },
                LibraryQuery::Premises{day} => { date(day)?; ("space/pcTopFor","premises",json!({"day":day})) },
                LibraryQuery::Areas{premises_ids,date:day} => {
                    date(day)?; if premises_ids.is_empty() || premises_ids.iter().any(|x|x.is_empty()) { return Err(invalid()); }
                    ("space/pick","areas",json!({"premisesIds":premises_ids,"categoryIds":[],"storeyIds":[],"boutiqueIds":[],"date":day}))
                },
                LibraryQuery::Times{id} => { secret(id)?; ("Space/map","times",json!({"id":id})) },
                LibraryQuery::Seats{id,day,start_time,end_time} => {
                    secret(id)?; date(day)?; secret(start_time)?; secret(end_time)?;
                    ("Space/seat","seats",json!({"id":id,"day":day,"label_id":[],"start_time":start_time,"end_time":end_time,"begdate":"","enddate":""}))
                },
            };
            let mut builder = client.post(format!("https://booking.lib.buaa.edu.cn/v4/{path}"));
            if kind != "login" {
                let mut authorization = Zeroizing::new(String::from("bearer"));
                authorization.push_str(token);
                builder = builder.header("Authorization",authorization.as_str());
            }
            (Service::Library,kind,builder.header("Content-Type","application/json").body(body.to_string()))
        },
        Request::Running{uid,token,query,..} => {
            secret(uid)?; secret(token)?;
            let mut form = BTreeMap::new();
            let (path,kind) = match query {
                RunningQuery::Categories => ("Front/Clockin/Classify/getList","categories"),
                RunningQuery::Items{classify_id} => {
                    secret(classify_id)?;
                    form.extend([("classify_id",classify_id.clone()),("page","1".into()),("limit","1000".into())]);
                    ("Front/Clockin/Item/getList","items")
                },
                RunningQuery::Count{classify_id,user_id} => {
                    secret(classify_id)?; secret(user_id)?;
                    form.extend([("classify_id",classify_id.clone()),("user_id",user_id.clone())]);
                    ("Front/Clockin/Clockin/getCount","count")
                },
                RunningQuery::Records{classify_id,user_id,page,limit} => {
                    secret(classify_id)?; secret(user_id)?;
                    if *page == 0 || *limit == 0 || *limit > 1000 { return Err(invalid()); }
                    form.extend([("classify_id",classify_id.clone()),("user_id",user_id.clone()),("page",page.to_string()),("limit",limit.to_string())]);
                    ("Front/Clockin/Clockin/getList","records")
                },
            };
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("uid",uid).append_pair("token",token).extend_pairs(form.iter());
            let mut body = Zeroizing::new(serializer.finish());
            let length = body.len();
            let body = reqwest::blocking::Body::sized(SecretBody {
                bytes: Zeroizing::new(std::mem::take(&mut *body).into_bytes()), offset: 0,
            },length as u64);
            (Service::Running,kind,client.post(format!("https://ygdk.buaa.edu.cn/api/{path}"))
                .header("X-Requested-With","XMLHttpRequest")
                .header("Content-Type","application/x-www-form-urlencoded; charset=UTF-8").body(body))
        },
        Request::Cgyy{app_key,access_token,query,..} => {
            secret(app_key)?;
            let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map_err(|_|error("clock_error","system clock precedes epoch"))?.as_millis().to_string();
            let (kind,builder) = match query {
            CgyyQuery::Venues|CgyyQuery::PurposeTypes|CgyyQuery::DayInfo{..}|CgyyQuery::Orders{..}|CgyyQuery::OrderDetail{..}|CgyyQuery::LockCode => {
            secret(access_token)?;
            let (path,kind,mut params) = match query {
                CgyyQuery::Venues => ("/api/front/website/venues".to_owned(),"venues",BTreeMap::from([
                    ("page".to_owned(),json!(-1)),("size".to_owned(),json!(-1)),("reservationRoleId".to_owned(),json!(3))])),
                CgyyQuery::PurposeTypes => ("/api/codes".into(),"purpose_types",BTreeMap::new()),
                CgyyQuery::DayInfo{search_date,venue_site_id} => {
                    date(search_date)?;
                    ("/api/reservation/day/info".into(),"day_info",BTreeMap::from([("searchDate".into(),json!(search_date)),("venueSiteId".into(),json!(venue_site_id))]))
                },
                CgyyQuery::Orders{page,size} => {
                    if *size == 0 || *size > 1000 { return Err(invalid()); }
                    ("/api/orders/mine".into(),"orders",BTreeMap::from([("page".into(),json!(page)),("size".into(),json!(size))]))
                },
                CgyyQuery::OrderDetail{id} => (format!("/api/orders/{id}"),"order_detail",BTreeMap::new()),
                CgyyQuery::LockCode => ("/api/orders/lock/code".into(),"lock_code",BTreeMap::new()),
                _ => return Err(invalid()),
            };
            params.insert("nocache".into(),json!(timestamp));
            let signature = sign(&path,&params,&timestamp);
            let wire: Vec<_> = params.iter().map(|(key,value)|(key,value.as_str().map(str::to_owned).unwrap_or_else(||value.to_string()))).collect();
            (kind,client.get(format!("https://cgyy.buaa.edu.cn/venue-zhjs-server{path}"))
                .query(&wire)
                .header("app-key",app_key).header("timestamp",&timestamp).header("sign",signature)
                .header("cgAuthorization",&**access_token)
                .header("Referer","https://cgyy.buaa.edu.cn/venue-zhjs/mobileReservation"))
            },
            CgyyQuery::Login{sso_token} => {
                let _ = &**sso_token;
                return Err(error("authentication_exchange_blocked","CGYY business login disabled; no request sent"));
            },
            CgyyQuery::ManageLogin{cookie} => {
                let _ = &**cookie;
                return Err(error("authentication_exchange_blocked","CGYY manage login disabled; no request sent"));
            },
            };
            (Service::Cgyy,kind,builder.header("Accept","application/json, text/plain, */*"))
        },
    };
    // Build before admission so malformed credential headers never consume a request.
    let mut http_request = builder.timeout(std::time::Duration::from_secs(45))
        .header("Accept-Encoding","identity").build().map_err(|_|invalid())?;
    for name in ["cookie","authorization","cgauthorization"] {
        if let Some(value) = http_request.headers_mut().get_mut(name) { value.set_sensitive(true); }
    }
    let governor = Governor::open().map_err(|_|error("governor_error","shared governor unavailable"))?;
    let mut lease = net::acquire(&governor)?;
    // Admission may wait for the shared cooldown. Sign only after that wait,
    // otherwise the timestamp can be stale before the request is transmitted.
    if matches!(service,Service::Cgyy) && kind != "manage_login" {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map(|d|d.as_millis().to_string());
        let timestamp = match now {
            Ok(t) => t,
            Err(_) => {
                lease.finish_without_request().map_err(|_|error("governor_error","cannot release admission"))?;
                return Err(error("clock_error","system clock precedes epoch"));
            },
        };
        let mut params: BTreeMap<String,Value> = http_request.url().query_pairs()
            .map(|(k,v)|(k.into_owned(),json!(v.into_owned()))).collect();
        if http_request.method() == reqwest::Method::GET {
            params.insert("nocache".into(),json!(timestamp));
            http_request.url_mut().query_pairs_mut().clear().extend_pairs(params.iter().map(|(k,v)|(k.as_str(),v.as_str().unwrap_or(""))));
        }
        let path = http_request.url().path().strip_prefix("/venue-zhjs-server").unwrap_or(http_request.url().path());
        let signature = sign(path,&params,&timestamp);
        // Generated decimal/hex strings are always valid HTTP header values.
        let headers = http_request.headers_mut();
        match (reqwest::header::HeaderValue::from_str(&timestamp),reqwest::header::HeaderValue::from_str(&signature)) {
            (Ok(t),Ok(s)) => { headers.insert("timestamp",t); headers.insert("sign",s); },
            _ => {
                lease.finish_without_request().map_err(|_|error("governor_error","cannot release admission"))?;
                return Err(invalid());
            },
        }
    }
    let mut response = match lease.start_request(|| client.execute(http_request)) {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => {
            lease.finish(Outcome::NetworkFailure).map_err(|_|error("governor_error","cannot settle smart request"))?;
            return Err(error("network_error","smart request failed; no automatic retry"));
        },
        Err(crate::governor::FollowupError::CachedChallenge) => {
            lease.finish(Outcome::SafetyObserved).map_err(|_|error("governor_error","cannot settle cached safety observation"))?;
            return Err(error("safety_latched","A retained account-safety observation prevented the request."));
        },
        Err(crate::governor::FollowupError::Governor(_)) => {
            return Err(error("governor_error","request safety admission failed; pending outcome retained"));
        },
    };
    let status = response.status().as_u16();
    let issues_session_cookie = net::issues_session_cookie(response.headers());
    let retry = response.headers().get_all("retry-after").iter().find_map(|x|x.to_str().ok()).map(str::to_owned);
    let content_types = response.headers().get_all("content-type");
    let mut content_types = content_types.iter();
    let content_type = match (content_types.next(),content_types.next()) {
        (Some(value),None) => value.to_str().ok().map(str::to_owned),
        _ => None,
    };
    let header_challenge = response.headers().iter().any(|(k,v)|net::challenge_header(k.as_str(),v.as_bytes()));
    // Commit header facts before consuming a body that may fail or be cut short.
    lease.observe_http_many(status,response.headers().get_all("retry-after").iter().map(|value|value.to_str().ok()),header_challenge)
        .map_err(|_|error("governor_error","cannot persist smart response headers"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    let read_result = response.by_ref().take(LIMIT+1).read_to_end(&mut bytes);
    let incomplete = read_result.is_err() || bytes.len() as u64 > LIMIT;
    let assessment = crate::html::assess_challenge_body(&bytes,content_type.as_deref(),!incomplete);
    let challenge = header_challenge || assessment == crate::html::ChallengeAssessment::Detected;
    let metadata_echo = content_type.as_deref().is_some_and(|value|request.response_contains_secret(value.as_bytes()));
    let safe_content_type = if metadata_echo { None } else { content_type.as_deref() };
    let result = if read_result.is_err() {
        Err(error("network_error","smart response body read failed"))
    } else if bytes.len() as u64 > LIMIT {
        Err(error("body_limit","smart response exceeds bounded body limit"))
    } else if issues_session_cookie {
        Ok(admit_content(service,status,safe_content_type,&bytes,kind,true))
    } else if request.response_contains_secret(&bytes) || metadata_echo {
        Ok(withheld(service,status,safe_content_type,&bytes,"credential_echo"))
    } else if assessment == crate::html::ChallengeAssessment::Unreviewed && !challenge {
        Ok(withheld(service,status,content_type.as_deref(),&bytes,"response_safety_unreviewed"))
    } else if challenge || content_type.is_none()
        || !content_type.as_deref().is_some_and(|t|t.split(';').next().is_some_and(|t|t.eq_ignore_ascii_case("application/json")||t.to_ascii_lowercase().ends_with("+json")))
    {
        let mut out = withheld(service,status,content_type.as_deref(),&bytes,if challenge {"challenge_requires_human"} else {"unknown_content_type"});
        if challenge { out["challenge_required"] = json!(true); }
        Ok(out)
    } else { Ok(admit_checked_json(&request,service,status,content_type.as_deref(),&bytes,kind)) };
    drop(response);
    finish_response(lease,ResponseOutcome {status,retry_after:retry.as_deref(),challenge,
        incomplete,service,body:&bytes})?;
    result.map(|output|with_source(output,Source::Network))
}

/// No write endpoints are implemented. Missing owner photos or confirmation
/// always refuse before any upload; even confirmed requests remain unsupported
/// until immutable preview, idempotency and postcondition are implemented.
pub fn reject_write(owner_photo_present: bool, confirmed: bool) -> Result<Value, Error> {
    if !owner_photo_present { return Err(error("owner_photo_required","real owner-provided photograph required; synthetic attendance is prohibited")); }
    if !confirmed { return Err(error("confirmation_required","explicit owner confirmation required")); }
    Err(error("unsupported","reservation, seat selection and attendance writes are not implemented"))
}

/// Explicitly offline re-reader for operator-supplied private evidence. Status,
/// MIME and bytes are caller claims, never proof of a campus request or cache
/// admission. Even successful parsing retains that distinction in the output.
pub fn reread(service: &str, kind: &str, status: u16, content_type: Option<&str>, base64: &str) -> Result<Value, Error> {
    let service = match service { "exams"=>Service::Exams,"classrooms"=>Service::Classrooms,"library"=>Service::Library,"cgyy"=>Service::Cgyy,"running"=>Service::Running,_=>return Err(invalid()) };
    if base64.len() as u64 > (LIMIT+2)/3*4 { return Err(invalid()); }
    let bytes = Zeroizing::new(STANDARD.decode(base64).map_err(|_|invalid())?);
    if bytes.len() as u64 > LIMIT { return Err(invalid()); }
    Ok(with_source(parse(service,status,content_type,&bytes,kind),Source::OperatorSupplied))
}

pub fn schema() -> Value {
    // Schema describes serde's accepted structural input; semantic validation
    // (dates, bounded records and nonempty credentials) is documented separately.
    fn object(fields: Vec<(&str,Value)>) -> Value {
        let required: Vec<_> = fields.iter().map(|(k,_)|*k).collect();
        let properties: serde_json::Map<String,Value> = fields.into_iter().map(|(k,v)|(k.into(),v)).collect();
        json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
    }
    fn string() -> Value { json!({"type":"string"}) }
    fn op(name: &str, mut fields: Vec<(&str,Value)>) -> Value { fields.push(("operation",json!({"const":name}))); object(fields) }
    fn service(name: &str, mut fields: Vec<(&str,Value)>) -> Value {
        fields.extend([("service",json!({"const":name})),("enabled",json!({"type":"boolean"}))]); object(fields)
    }
    let library = json!({"oneOf":[
        op("login",vec![("cas",string())]),
        op("premises",vec![("day",string())]),
        op("areas",vec![("premises_ids",json!({"type":"array","items":{"type":"string"}})),("date",string())]),
        op("times",vec![("id",string())]),
        op("seats",vec![("id",string()),("day",string()),("start_time",string()),("end_time",string())])]});
    let running = json!({"oneOf":[op("categories",vec![]),op("items",vec![("classify_id",string())]),
        op("count",vec![("classify_id",string()),("user_id",string())]),
        op("records",vec![("classify_id",string()),("user_id",string()),("page",json!({"type":"integer","minimum":0,"maximum":4294967295u64})),("limit",json!({"type":"integer","minimum":0,"maximum":4294967295u64}))])]});
    json!({"input":{"oneOf":[
        service("exams",vec![("cookie",string()),("term_code",string())]),
        service("classrooms",vec![("cookie",string()),("campus_id",json!({"type":"integer","minimum":i64::MIN,"maximum":i64::MAX})),("date",string())]),
        service("library",vec![("token",string()),("query",library)]),
        service("cgyy",vec![("app_key",string()),("access_token",string()),("query",json!({"oneOf":[
            op("venues",vec![]),op("purpose_types",vec![]),op("lock_code",vec![]),
            op("day_info",vec![("search_date",string()),("venue_site_id",json!({"type":"integer","minimum":0,"maximum":4294967295u64}))]),
            op("orders",vec![("page",json!({"type":"integer","minimum":0,"maximum":4294967295u64})),("size",json!({"type":"integer","minimum":0,"maximum":4294967295u64}))]),
            op("order_detail",vec![("id",json!({"type":"integer","minimum":0,"maximum":4294967295u64}))]),
            op("login",vec![("sso_token",string())]),op("manage_login",vec![("cookie",string())])]}))]),
        service("running",vec![("uid",string()),("token",string()),("query",running)])]},
        "output":{"type":"object","required":["result","source","network_performed"],"oneOf":[
            {"properties":{"source":{"const":"network"},"network_performed":{"const":true}}},
            {"properties":{"source":{"const":"operator_supplied"},"network_performed":{"const":false}}},
            {"properties":{"source":{"const":"disabled"},"network_performed":{"const":false}}}],
            "properties":{"result":{"enum":["ok","disabled","unsupported","unstructured","business_error","session_expired","sensitive_response_withheld"]},"source":{"enum":["network","operator_supplied","disabled"]},"network_performed":{"type":"boolean"},"service":{"enum":["exams","classrooms","library","cgyy","running"]},"data":{},"raw_evidence_withheld":{"const":true},"raw_evidence":{"type":"object","required":["encoding","data","content_type","byte_length","sha256"],"properties":{"encoding":{"const":"base64"},"data":{"type":"string"},"content_type":{"type":["string","null"]},"byte_length":{"type":"integer"},"sha256":{"type":"string"}}}}},
        "provenance":"network means an actual request completed in this invocation; reread always operator_supplied, including caller-supplied HTTP status and MIME; no cache implementation or cache provenance is claimed",
        "authentication":"stdin-only established cookie or token; library CAS exchange and CGYY manage/business exchanges are blocked before transport pending Authentication lease, deliberate resume and known-outcome proof; existing authenticated reads only",
        "writes":"unsupported; never uploads or fabricates attendance photographs",
        "cgyy_app_key":"8fceb735082b5a529312040b58ea780b",
        "unknown":["campus id enumeration"],
        "validation":"enabled requests require nonempty control-free credentials; strict YYYY-MM-DD dates; records page >= 1 and limit 1..1000; no null fields"})
}

// These fixed synthetic scenarios stop before transport and governor work.
#[cfg(test)]
mod numeric_library_regression {
    use super::*;

    const BODY: &[u8] = br#"{"code":1,"data":{"list":[{"n":1e3}]}}"#;
    const SAFE_BODY: &[u8] = br#"{"code":1,"data":{"list":[{"n":42}]}}"#;
    const MIME: &str = "application/json";

    fn numeric_request() -> Request {
        serde_json::from_str(r#"{"service":"library","enabled":true,"token":"1000.0","query":{"operation":"premises","day":"2026-10-28"}}"#).unwrap()
    }

    fn unrelated_request() -> Request {
        serde_json::from_str(r#"{"service":"library","enabled":true,"token":"unrelated-secret","query":{"operation":"premises","day":"2026-10-28"}}"#).unwrap()
    }

    fn admit(request: &Request, body: &[u8]) -> Value {
        assert!(matches!(request, Request::Library { enabled:true, query:LibraryQuery::Premises { day }, .. } if day == "2026-10-28"));
        assert!(body.len() as u64 <= LIMIT);
        assert_eq!(crate::html::assess_challenge_body(body, Some(MIME), true), crate::html::ChallengeAssessment::Clear);
        let metadata_echo = request.response_contains_secret(MIME.as_bytes());
        assert!(!metadata_echo);
        // Under the established fixed preconditions (complete JSON, no issued
        // cookie or challenge), these are the screening/projection branches in
        // read. Do not attach Network provenance to a synthetic observation.
        if request.response_contains_secret(body) || metadata_echo {
            withheld(Service::Library, 200, Some(MIME), body, "credential_echo")
        } else {
            admit_checked_json(request, Service::Library, 200, Some(MIME), body, "premises")
        }
    }

    #[test]
    pub(super) fn normalized_numeric_credential_is_withheld() {
        let result = admit(&numeric_request(), BODY);
        assert_eq!(result, json!({
            "service":"library", "result":"sensitive_response_withheld",
            "fallback_reason":"credential_echo", "http_status":200,
            "raw_evidence_withheld":true, "content_type":"application/json",
            "content_type_parameters_withheld":false, "byte_length":BODY.len(),
            "sha256":format!("{:x}", Sha256::digest(BODY))
        }));
        assert!(!result.to_string().contains("1000.0"));
    }

    #[test]
    pub(super) fn numeric_credential_controls() {
        let expected = json!({"service":"library", "result":"ok",
            "data":[{"n":1000.0}], "write_operations_performed":false});
        assert_eq!(admit(&unrelated_request(), BODY), expected);
        assert_eq!(admit(&numeric_request(), SAFE_BODY), json!({"service":"library",
            "result":"ok", "data":[{"n":42}], "write_operations_performed":false}));
        assert!(!response_denies_session(Service::Library, BODY));
    }

    #[test]
    pub(super) fn independent_denial_remains_recognized() {
        let body = "{\"code\":1,\"message\":\"请重新登录\",\"data\":{\"list\":[{\"n\":1e3}]}}".as_bytes();
        // finish_response uses this independently of the withheld projection;
        // classification only is exercised here, not governor settlement.
        assert!(response_denies_session(Service::Library, body));
        let result = admit(&numeric_request(), body);
        assert_eq!(result["raw_evidence_withheld"], true);
        assert!(result.get("data").is_none());
        assert!(result.get("raw_evidence").is_none());
        assert!(!result.to_string().contains("1000.0"));
        assert_eq!(result["fallback_reason"], "session_expired");
    }

    #[test]
    pub(super) fn generated_http_status_does_not_hide_session_denial() {
        let request: Request = serde_json::from_str(r#"{"service":"library","enabled":true,"token":"200","query":{"operation":"premises","day":"2026-10-28"}}"#).unwrap();
        let body = "{\"code\":1,\"message\":\"请重新登录\",\"data\":{\"list\":[]}}".as_bytes();
        assert!(response_denies_session(Service::Library, body));
        let result = admit(&request, body);
        assert_eq!(result["result"], "session_expired");
        assert_eq!(result["fallback_reason"], "session_expired");
        assert_eq!(result["http_status"], 200);
        assert_eq!(result["raw_evidence_withheld"], true);
    }

    #[test]
    pub(super) fn source_business_error_number_is_still_screened() {
        let body = br#"{"code":1e3,"message":"ordinary"}"#;
        let result = admit(&numeric_request(), body);
        assert_eq!(result["result"], "sensitive_response_withheld");
        assert_eq!(result["fallback_reason"], "credential_echo");
        assert!(result.get("upstream_code").is_none());
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn exam_business_rejection() {
        let out = parse(Service::Exams,200,None,br#"{"code":"9","msg":"graduate accounts unsupported","datas":[]}"#,"exams");
        assert_eq!(out["result"],"business_error");
        assert_eq!(out["raw_evidence_withheld"],true);
    }
    #[test] fn running_wire_credentials_are_withheld_even_in_json_escapes() {
        // Synthetic wire echoes, not observed campus responses.
        let request: Request = serde_json::from_str(r#"{"service":"running","enabled":true,"uid":"synthetic user","token":"abc+/=","query":{"operation":"categories"}}"#).unwrap();
        for body in [
            br#"{"code":0,"message":"abc%2B%2F%3D"}"#.as_slice(),
            br#"{"code":0,"message":"abc\u00252B%2F%3D"}"#.as_slice(),
            br#"{"code":0,"message":"synthetic+user"}"#.as_slice(),
        ] {
            assert!(request.response_contains_secret(body));
            let output = withheld(Service::Running,200,Some("application/json"),body,"credential_echo");
            assert!(output.get("upstream_message").is_none());
            assert!(output.get("raw_evidence").is_none());
        }
        assert!(!request.response_contains_secret(br#"{"code":0,"message":"business refusal"}"#));
    }
    #[test] fn cookie_service_explicit_denials_latch_with_retry_after() {
        use std::os::unix::fs::DirBuilderExt;
        // Synthetic instances of existing envelopes and denial markers only.
        for (service,body,kind) in [
            (Service::Exams,"{\"code\":\"9\",\"msg\":\"请重新登录\"}","exams"),
            (Service::Classrooms,"{\"e\":1,\"m\":\"未登录\"}","rooms"),
        ] {
            let root=std::env::temp_dir().join(format!("buaa-smart-cookie-denial-{}-{}-{}",
                service.name(),std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
            std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let governor=Governor::isolated_for_test(&root).unwrap();
            let lease=governor.try_acquire(crate::governor::RequestKind::Interactive).unwrap();
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::SET_COOKIE,"x=q".parse().unwrap());
            let output = admit_content(service,200,Some("application/json"),body.as_bytes(),kind,
                net::issues_session_cookie(&headers));
            assert_eq!(output["fallback_reason"],"session_cookie_issued");
            assert!(output.get("data").is_none());
            assert!(output.get("upstream_message").is_none());
            finish_response(lease,ResponseOutcome {status:200,retry_after:Some("60"),challenge:false,
                incomplete:false,service,body:body.as_bytes()}).unwrap();
            let state=governor.status().unwrap();
            assert!(state.safety_latched);
            assert!(!state.authentication_armed);
            assert!(state.cooldown_until_boottime_ms > state.next_request_boottime_ms);
            assert!(!response_denies_session(service,br#"{"code":"9","e":1,"msg":"business refusal"}"#));
            drop(governor);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[test] fn opaque_cookie_content_is_withheld_but_safe_content_remains_useful() {
        let body = br#"{"code":200,"data":{"content":[{"id":7,"venueName":"q","siteList":[]}]}}"#;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::SET_COOKIE,"x=q".parse().unwrap());
        let output = admit_content(Service::Cgyy,200,Some("application/json"),body,"venues",
            net::issues_session_cookie(&headers));
        assert_eq!(output["fallback_reason"],"session_cookie_issued");
        assert!(output.get("data").is_none());
        assert!(output.get("upstream_message").is_none());
        assert!(output.get("raw_evidence").is_none());
        let metadata_echo=admit_content(Service::Cgyy,200,Some("application/freshopaque123; proof=freshopaque123"),body,"venues",true);
        assert_eq!(metadata_echo["fallback_reason"],"session_cookie_issued");
        assert!(metadata_echo["content_type"].is_null());
        assert_eq!(metadata_echo["content_type_parameters_withheld"],true);
        assert!(!metadata_echo.to_string().contains("freshopaque123"));
        headers.clear();
        let safe = admit_content(Service::Cgyy,200,Some("application/json"),body,"venues",
            net::issues_session_cookie(&headers));
        assert_eq!(safe["result"],"ok");
        assert_eq!(safe["data"][0]["id"],7);
    }
    #[test] fn classroom_periods() {
        let out = parse(Service::Classrooms,200,Some("application/json"),br#"{"e":0,"m":"","d":{"list":{"A":[{"id":1,"floorid":2,"name":"101","kxsds":"1,3, 5"}]}}}"#,"rooms");
        assert_eq!(out["data"][0]["free_periods"],json!([1,3,5]));
    }
    #[test] fn seat_status_is_literal_string() {
        let out = parse(Service::Library,200,None,br#"{"code":1,"data":{"list":[{"id":1,"status":"1"},{"id":2,"status":"0"}]}}"#,"seats");
        assert_eq!(out["data"][0]["available"],true);
        assert_eq!(out["data"][1]["available"],false);
        assert_eq!(parse(Service::Library,200,None,br#"{"code":7,"data":{}}"#,"seats")["result"],"business_error");
    }
    #[test] fn expired_sessions() {
        assert_eq!(parse(Service::Running,200,None,br#"{"code":-98}"#,"categories")["result"],"session_expired");
        assert_eq!(parse(Service::Library,200,None,"{\"code\":1,\"message\":\"请重新登录\"}".as_bytes(),"seats")["result"],"session_expired");
    }
    #[test] fn cgyy_envelope_and_authentication_tokens() {
        assert_eq!(parse(Service::Cgyy,200,None,br#"{"code":200,"data":{"content":[{"id":7,"venueName":"room","siteList":[]}]}}"#,"venues")["data"][0]["id"],7);
        assert_eq!(parse(Service::Cgyy,200,None,br#"{"code":500,"message":"failure"}"#,"venues")["result"],"business_error");
        assert_eq!(parse(Service::Library,200,None,br#"{"code":0,"data":{"member":{"token":"synthetic"}}}"#,"login")["result"],"unsupported");
        assert_eq!(parse(Service::Cgyy,200,None,br#"{"code":200,"data":{"token":{"access_token":"synthetic"}}}"#,"login")["result"],"unsupported");
    }
    #[test] fn authentication_is_blocked_before_transport_even_offline() {
        for input in [
            r#"{"service":"library","enabled":true,"token":"","query":{"operation":"login","cas":"private-ticket"}}"#,
            r#"{"service":"cgyy","enabled":true,"app_key":"public","access_token":"","query":{"operation":"login","sso_token":"private-ticket"}}"#,
            r#"{"service":"cgyy","enabled":true,"app_key":"public","access_token":"","query":{"operation":"manage_login","cookie":"private-cookie"}}"#,
        ] {
            let failure = read(input,false).unwrap_err();
            assert_eq!(failure.code,"authentication_exchange_blocked");
        }
        let request: Request = serde_json::from_str(r#"{"service":"exams","enabled":true,"term_code":"2026","cookie":"private-cookie"}"#).unwrap();
        assert!(request.response_contains_secret(b"upstream echoed private-cookie"));
        let out = parse(Service::Library,200,None,br#"{"code":0,"data":{"token":"private-token"}}"#,"premises");
        assert_eq!(out["result"],"sensitive_response_withheld");
        assert!(!out.to_string().contains("private-token"));
        assert!(out.get("raw_evidence").is_none());
    }
    #[test] fn signature_material_vector() {
        // Synthetic upstream-formula vector independently computed with Python
        // hashlib; not an observed campus response.
        let mut params = BTreeMap::from([("page".into(),json!(-1)),("size".into(),json!(-1)),
            ("reservationRoleId".into(),json!(3)),("nocache".into(),json!("1700000000000"))]);
        assert_eq!(sign("/api/front/website/venues",&params,"1700000000000"),"76e3f52710020a03872b6bb2fafcdc6a");
        params.insert("id".into(),json!(99)); params.insert("empty".into(),json!(""));
        params.insert("array".into(),json!([1]));
        assert_eq!(sign("api/front/website/venues",&params,"1700000000000"),"76e3f52710020a03872b6bb2fafcdc6a");
    }
    #[test] fn no_bogus_attendance() {
        assert_eq!(reject_write(false,true).unwrap_err().code,"owner_photo_required");
        assert_eq!(reject_write(true,false).unwrap_err().code,"confirmation_required");
        assert_eq!(reject_write(true,true).unwrap_err().code,"unsupported");
    }
    #[test] fn independent_disabled_service() {
        assert_eq!(read(r#"{"service":"exams","enabled":false,"cookie":"","term_code":""}"#,false).unwrap()["result"],"disabled");
        assert!(read(r#"{"service":"exams","enabled":false,"cookie":null,"term_code":""}"#,false).is_err());
    }
    #[test] fn fallback_roundtrip() {
        let bytes = b"not JSON";
        let out = parse(Service::Exams,200,None,bytes,"exams");
        assert_eq!(out["raw_evidence_withheld"],true);
        let supplied = reread("exams","exams",200,None,&STANDARD.encode(bytes)).unwrap();
        assert_eq!(supplied,with_source(out,Source::OperatorSupplied));
        assert_eq!(supplied["source"],"operator_supplied");
        assert_eq!(supplied["network_performed"],false);
    }
    #[test] fn reserved_raw_value_members_are_unreviewed_at_any_depth() {
        for body in [
            br#"{"$serde_json::private::RawValue":"{\"token\":\"fresh-secret\"}"}"#.as_slice(),
            br#"{"code":1,"result":{"$serde_json::private::RawValue":"{\"token\":\"fresh-secret\"}"}}"#,
            br#"{"code":1,"result":{"items":[{"other":0,"$serde_json::private::Raw\u0056alue":"{\"token\":\"fresh-secret\"}"}]}}"#,
            br#"{"code":1,"result":{"token":"fresh-secret","\u0024serde_json::private::RawValue":"{}"}}"#,
        ] {
            let out = parse(Service::Running,200,Some("application/json"),body,"count");
            assert_eq!(out["result"],"sensitive_response_withheld");
            assert_eq!(out["fallback_reason"],"unreviewed_representation");
            assert_eq!(out["raw_evidence_withheld"],true);
            assert!(out.get("raw_evidence").is_none());
            assert!(out.get("data").is_none());
            assert!(out.get("challenge_required").is_none());
            assert!(!out.to_string().contains("fresh-secret"));
            assert!(!response_denies_session(Service::Running,body));
        }
    }
    #[test] fn raw_value_text_is_safe_as_a_string_value() {
        let body = br#"{"code":1,"result":{"count":2,"text":"$serde_json::private::RawValue","quoted":"\"$serde_json::private::RawValue\": {}"}}"#;
        let out = parse(Service::Running,200,Some("application/json"),body,"count");
        assert_eq!(out["result"],"ok");
        assert_eq!(out["data"]["count"],2);
        assert_eq!(out["data"]["text"],"$serde_json::private::RawValue");
        let duplicate = parse(Service::Running,200,Some("application/json"),
            br#"{"code":-98,"code":1,"result":{"count":2}}"#,"count");
        assert_eq!(duplicate["result"],"ok");
        assert_eq!(duplicate["data"]["count"],2);
        let credential = parse(Service::Running,200,Some("application/json"),
            br#"{"code":1,"result":{"\u0074oken":"fresh-secret"}}"#,"count");
        assert_eq!(credential["fallback_reason"],"credential_field");
        assert!(!credential.to_string().contains("fresh-secret"));
    }
    #[test] fn challenge_and_secrets_never_become_raw_evidence() {
        for bytes in [br#"{"access_token":"fresh-secret"}"#.as_slice(),br#"{new token invalid json"#] {
            let out = parse(Service::Library,200,None,bytes,"seats");
            assert_eq!(out["result"],"sensitive_response_withheld");
            assert!(out.get("raw_evidence").is_none());
            assert!(!out.to_string().contains("fresh-secret"));
        }
        let out = parse(Service::Library,503,None,br#"{"token":"new-secret"}"#,"seats");
        assert_eq!(out["result"],"sensitive_response_withheld");
        assert!(!out.to_string().contains("new-secret"));
        let escaped = parse(Service::Library,200,Some("application/json"),
            br#"{"code":0,"data":{"list":[{"\u0074oken":"new-secret"}]}}"#,"premises");
        assert_eq!(escaped["result"],"sensitive_response_withheld");
        assert!(!escaped.to_string().contains("new-secret"));
        let request: Request = serde_json::from_str(r#"{"service":"exams","enabled":true,"term_code":"2026","cookie":"sid=private-value; other=other-value"}"#).unwrap();
        assert!(request.response_contains_secret(b"upstream echoed private-value"));
        assert!(request.response_contains_secret(br#"{"message":"\u0070rivate-value"}"#));
        let quoted: Request = serde_json::from_str(r#"{"service":"exams","enabled":true,"term_code":"2026","cookie":"sid=\"synthetic-secret\""}"#).unwrap();
        assert!(quoted.response_contains_secret(br#"{"echo":"\u0073ynthetic-secret"}"#));
        let library: Request = serde_json::from_str(r#"{"service":"library","enabled":true,"token":"synthetic-secret","query":{"operation":"premises","day":"2026-10-28"}}"#).unwrap();
        assert!(library.response_contains_secret(br#"{"code":0,"data":{"list":[{"echo":"\u0073ynthetic-secret"}]}}"#));
        let cgyy = parse(Service::Cgyy,200,Some("application/json"),
            br#"{"code":200,"data":{"\u0063gAuthorization":"fresh-secret"}}"#,"order_detail");
        assert_eq!(cgyy["result"],"sensitive_response_withheld");
        assert!(!cgyy.to_string().contains("fresh-secret"));
        let denial = br#"{"code":-98,"token":"replacement-secret"}"#;
        assert!(response_denies_session(Service::Running,denial));
        assert!(response_denies_session(Service::Running,br#"{"code":1,"code":-98}"#));
        assert!(!response_denies_session(Service::Running,br#"{"code":-98,"code":1}"#));
        assert_eq!(parse(Service::Running,200,Some("application/json"),denial,"count")["result"],"sensitive_response_withheld");
        let metadata = withheld(Service::Exams,200,Some("application/json; sessionid=private-value"),b"{}","unsafe_metadata");
        assert_eq!(metadata["content_type"],"application/json");
        assert!(!metadata.to_string().contains("private-value"));
        let partial = serde_json::to_string(&withheld(Service::Exams,403,None,b"upstream session=private-part refresh=brand-new","partial_cookie_echo")).unwrap();
        assert!(!partial.contains("private-part")&&!partial.contains("brand-new"));
    }

    #[test] fn withheld_session_denial_still_latches_and_preserves_cooldown() {
        use std::os::unix::fs::DirBuilderExt;
        let root=std::env::temp_dir().join(format!("buaa-smart-denial-{}-{}",
            std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let governor=Governor::isolated_for_test(&root).unwrap();
        let mut lease=governor.try_acquire(crate::governor::RequestKind::Interactive).unwrap();
        lease.observe_http(200,Some("60"),false).unwrap();
        let body=br#"{"code":-98,"token":"replacement-secret"}"#;
        assert_eq!(parse(Service::Running,200,Some("application/json"),body,"count")["result"],"sensitive_response_withheld");
        finish_response(lease,ResponseOutcome {status:200,retry_after:Some("60"),challenge:false,
            incomplete:false,service:Service::Running,body}).unwrap();
        let status=governor.status().unwrap();
        assert!(status.safety_latched);
        assert!(!status.authentication_armed);
        assert!(status.cooldown_until_boottime_ms > status.next_request_boottime_ms);
        drop(governor);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test] fn missing_mime_does_not_hide_a_complete_session_denial() {
        use std::os::unix::fs::DirBuilderExt;
        let root=std::env::temp_dir().join(format!("buaa-smart-mime-denial-{}-{}",
            std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let governor=Governor::isolated_for_test(&root).unwrap();
        let lease=governor.try_acquire(crate::governor::RequestKind::Interactive).unwrap();
        let body=br#"{"code":1,"code":-98}"#;
        assert_eq!(crate::html::assess_challenge_body(body,None,true),crate::html::ChallengeAssessment::Unreviewed);
        assert_eq!(parse(Service::Running,200,None,body,"count")["result"],"session_expired");
        finish_response(lease,ResponseOutcome {status:200,retry_after:None,challenge:false,
            incomplete:false,service:Service::Running,body}).unwrap();
        assert!(governor.status().unwrap().safety_latched);
        drop(governor);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test] fn supplied_success_never_claims_network_observation() {
        let bytes = br#"{"code":"0","datas":[]}"#;
        let supplied = reread("exams","exams",200,Some("application/json"),&STANDARD.encode(bytes)).unwrap();
        assert_eq!(supplied["result"],"ok");
        assert_eq!(supplied["source"],"operator_supplied");
        assert_eq!(supplied["network_performed"],false);
        // Synthetic test of the live terminal annotation, not a real request.
        let live_shape = with_source(parse(Service::Exams,200,Some("application/json"),bytes,"exams"),Source::Network);
        assert_eq!(live_shape["data"],supplied["data"]);
        assert_eq!(live_shape["source"],"network");
        assert_eq!(live_shape["network_performed"],true);
        assert_ne!(live_shape,supplied);
        let rejected = reread("library","login",200,None,&STANDARD.encode(br#"{"token":"private"}"#)).unwrap();
        assert_eq!(rejected["result"],"unsupported");
        assert_eq!(rejected["source"],"operator_supplied");
        assert_eq!(rejected["network_performed"],false);
    }
}
