//! Read-only library seat availability and the caller's bookings. The caller
//! supplies an invocation-only token through JSON stdin; this module never logs
//! in, refreshes credentials, reserves a seat or cancels a booking.
use crate::{
    governor::{Governor, Outcome},
    net::{self, Error},
};
use reqwest::{blocking::Client, header::HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::{io::Read, time::Duration};
use zeroize::{Zeroize, Zeroizing};

const ORIGIN: &str = "https://booking.lib.buaa.edu.cn";
const REFERER: &str = "https://booking.lib.buaa.edu.cn/";
const BODY_LIMIT: usize = 8 * 1024 * 1024;
const TOKEN_LIMIT: usize = 8192;
// GlobalSign GCC R3 DV TLS CA 2020, distributed by Yiki21/iclass_buaa_tui
// (GPL-3.0): https://github.com/Yiki21/iclass_buaa_tui/blob/main/assets/certs/globalsign-gcc-r3-dv-tls-ca-2020.pem
// Only the public certificate is reused; no upstream implementation is copied.
const INTERMEDIATE: &[u8] =
    include_bytes!("../assets/certs/globalsign-gcc-r3-dv-tls-ca-2020.pem");

fn invalid() -> Error {
    Error::new("invalid_input", "invalid libbook input; consult libbook schema")
}

#[derive(Clone, Copy, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Libraries,
    Areas,
    Area,
    Seats,
    Bookings,
}

impl Operation {
    const ALL: [Self; 5] = [Self::Libraries, Self::Areas, Self::Area, Self::Seats, Self::Bookings];

    fn name(self) -> &'static str {
        match self {
            Self::Libraries => "libraries",
            Self::Areas => "areas",
            Self::Area => "area",
            Self::Seats => "seats",
            Self::Bookings => "bookings",
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Libraries => "/v4/space/pcTopFor",
            Self::Areas => "/v4/space/pick",
            Self::Area => "/v4/Space/map",
            Self::Seats => "/v4/Space/seat",
            Self::Bookings => "/v4/member/seat",
        }
    }

    fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Libraries => &["day"],
            Self::Areas => &["library_id", "day"],
            Self::Area => &["area_id"],
            Self::Seats => &["area_id", "day", "start", "end"],
            Self::Bookings => &["page", "size"],
        }
    }
}

/// Serde structs also accept positional arrays by default. Every input object,
/// including payload and session, goes through this map-only deserializer.
fn object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, access: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(access))
        }
    }
    deserializer.deserialize_map(Visitor(std::marker::PhantomData))
}

fn parse_object<'de, T: Deserialize<'de>>(input: &'de str) -> Result<T, Error> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = object(&mut deserializer).map_err(|_| invalid())?;
    deserializer.end().map_err(|_| invalid())?;
    Ok(value)
}

fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

fn session<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Session>, D::Error> {
    object(deserializer).map(Some)
}

fn secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

// No Debug, Clone or Serialize implementation: credentials stay in the caller's
// stdin allocation and this zeroizing field, never in an output JSON value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    #[serde(deserialize_with = "secret")]
    token: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input<'a> {
    operation: Operation,
    #[serde(default, borrow, deserialize_with = "present")]
    payload: Option<&'a RawValue>,
}

type Text = String;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    #[serde(default, deserialize_with = "session")]
    session: Option<Session>,
    #[serde(default, deserialize_with = "present")]
    day: Option<Text>,
    #[serde(default, deserialize_with = "present")]
    library_id: Option<Text>,
    #[serde(default, deserialize_with = "present")]
    area_id: Option<Text>,
    #[serde(default, deserialize_with = "present")]
    start: Option<Text>,
    #[serde(default, deserialize_with = "present")]
    end: Option<Text>,
    #[serde(default, deserialize_with = "present")]
    page: Option<u32>,
    #[serde(default, deserialize_with = "present")]
    size: Option<u32>,
}

fn valid_day(day: &str) -> bool {
    day.len() == 10
        && day.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        })
        && day.as_bytes()[..4] != *b"0000"
        && chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d").is_ok()
}

fn valid_time(time: &str) -> bool {
    let bytes = time.as_bytes();
    bytes.len() == 5
        && bytes[2] == b':'
        && [0, 1, 3, 4].iter().all(|&i| bytes[i].is_ascii_digit())
        && bytes[..2] <= b"23"[..]
        && bytes[3..] <= b"59"[..]
}

fn validate_token(token: &str) -> Result<(), Error> {
    if token.is_empty()
        || token.len() > TOKEN_LIMIT
        || !token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
    {
        return Err(invalid());
    }
    Ok(())
}

fn authorization(token: &str) -> Result<HeaderValue, Error> {
    validate_token(token)?;
    let value = Zeroizing::new(format!("bearer{token}"));
    let mut header = HeaderValue::from_str(&value).map_err(|_| invalid())?;
    header.set_sensitive(true);
    Ok(header)
}

impl Payload {
    fn validate(&self, operation: Operation) -> Result<(), Error> {
        let fields = [
            ("day", self.day.is_some()),
            ("library_id", self.library_id.is_some()),
            ("area_id", self.area_id.is_some()),
            ("start", self.start.is_some()),
            ("end", self.end.is_some()),
            ("page", self.page.is_some()),
            ("size", self.size.is_some()),
        ];
        if fields.iter().any(|(field, present)| *present && !operation.fields().contains(field))
            || self.day.as_deref().is_some_and(|day| !valid_day(day))
            || self.library_id.as_deref().is_some_and(str::is_empty)
            || self.area_id.as_deref().is_some_and(str::is_empty)
            || self.start.as_deref().is_some_and(|time| !valid_time(time))
            || self.end.as_deref().is_some_and(|time| !valid_time(time))
            || matches!((&self.start, &self.end), (Some(start), Some(end)) if start >= end)
            || self.page.is_some_and(|page| page == 0)
            || self.size == Some(0)
        {
            return Err(invalid());
        }
        if let Some(session) = &self.session {
            validate_token(&session.token)?;
        }
        Ok(())
    }

    fn body(&self, operation: Operation) -> Result<Value, Error> {
        fn required(value: &Option<String>) -> Result<&str, Error> {
            value.as_deref().ok_or_else(invalid)
        }
        Ok(match operation {
            Operation::Libraries => json!({"day":required(&self.day)?}),
            Operation::Areas => json!({
                "premisesIds": required(&self.library_id)?, "date": required(&self.day)?,
                "categoryIds": [], "storeyIds": [], "boutiqueIds": [],
            }),
            Operation::Area => json!({"id":required(&self.area_id)?}),
            Operation::Seats => json!({
                "id": required(&self.area_id)?, "day": required(&self.day)?, "label_id": [],
                "start_time": required(&self.start)?, "end_time": required(&self.end)?,
                "begdate": "", "enddate": "",
            }),
            Operation::Bookings => json!({"page":self.page.ok_or_else(invalid)?,"size":self.size.ok_or_else(invalid)?}),
        })
    }
}

fn endpoint(path: &str) -> Result<url::Url, Error> {
    if !Operation::ALL.iter().any(|operation| operation.path() == path) {
        return Err(Error::new("unsupported", "only the five fixed library read endpoints are allowed"));
    }
    url::Url::parse(&format!("{ORIGIN}{path}"))
        .map_err(|_| Error::new("transport", "cannot construct library endpoint"))
}

/// Strict response JSON with zeroizing failure paths. Duplicate members may
/// otherwise overwrite a credential echo before the decoded tree is screened.
struct PrivateJson(Value);
impl<'de> Deserialize<'de> for PrivateJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PrivateJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate object members")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut result = PrivateJson(Value::Object(serde_json::Map::new()));
                while let Some(key) = access.next_key::<String>()? {
                    let mut key = Zeroizing::new(key);
                    let object = result.0.as_object_mut().expect("object");
                    if object.contains_key(key.as_str()) {
                        return Err(serde::de::Error::custom("duplicate JSON member"));
                    }
                    let mut value = access.next_value::<PrivateJson>()?;
                    object.insert(std::mem::take(&mut *key), std::mem::take(&mut value.0));
                }
                Ok(result)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut result = PrivateJson(Value::Array(Vec::new()));
                while let Some(mut value) = access.next_element::<PrivateJson>()? {
                    result.0.as_array_mut().expect("array").push(std::mem::take(&mut value.0));
                }
                Ok(result)
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(PrivateJson(Value::String(value.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(PrivateJson(Value::String(value)))
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(PrivateJson(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(PrivateJson(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(PrivateJson(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(PrivateJson(Value::from(value)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(PrivateJson(Value::Null))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
impl Drop for PrivateJson {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(wipe),
                Value::Object(values) => {
                    for (mut key, mut value) in std::mem::take(values) {
                        key.zeroize();
                        wipe(&mut value);
                    }
                }
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

fn private_response(value: &Value, token: &str) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            key.eq_ignore_ascii_case("token")
                || net::sensitive_text_marker(key)
                || net::carries_secret(key.as_bytes(), token)
                || private_response(value, token)
        }),
        Value::Array(values) => values.iter().any(|value| private_response(value, token)),
        Value::String(text) => net::carries_secret(text.as_bytes(), token),
        _ => net::json_scalar_matches(value, |bytes| net::carries_secret(bytes, token)),
    }
}

fn fallback(reason: &'static str) -> Value {
    // Account-scoped unrecognized bytes are not safe public raw evidence.
    json!({"result":"fallback","fallback_reason":reason,
        "raw_evidence":{"raw_withheld":true,"raw_withheld_reason":"authenticated_response_not_exportable"}})
}

fn parse_response(operation: Operation, status: u16, body: &[u8], token: &str) -> Result<Value, Error> {
    let http_success = (200..300).contains(&status);
    if status == 401 {
        return Ok(json!({"result":"session_expired"}));
    }
    if net::carries_secret(body, token) {
        return Err(Error::new("sensitive_response_withheld", "library response contains credential material"));
    }
    let mut document = match serde_json::from_slice::<PrivateJson>(body) {
        Ok(value) => value,
        Err(_) if http_success => return Ok(fallback("invalid_json_contract")),
        Err(_) => return Ok(json!({"result":"upstream_error"})),
    };
    if private_response(&document.0, token) {
        return Err(Error::new("sensitive_response_withheld", "library response contains credential material"));
    }
    match document.0.get("code").and_then(Value::as_i64) {
        Some(401) => return Ok(json!({"result":"session_expired"})),
        _ if !http_success => return Ok(json!({"result":"upstream_error"})),
        Some(0) => {}
        Some(_) => return Ok(json!({"result":"upstream_error"})),
        None => return Ok(fallback("missing_business_code")),
    }
    let Some(data) = document.0.get_mut("data") else {
        return Ok(fallback("missing_response_data"));
    };
    if operation == Operation::Area {
        return Ok(if data.is_object() {
            let mut output = json!({"result":"success"});
            output["response"] = std::mem::take(data);
            output
        } else {
            fallback("invalid_area_contract")
        });
    }
    let total = if operation == Operation::Bookings {
        match data.get("total").and_then(Value::as_u64) {
            Some(total) => Some(total),
            None => return Ok(fallback("missing_booking_total")),
        }
    } else {
        None
    };
    let rows = match operation {
        Operation::Libraries => data.get_mut("list"),
        Operation::Areas => {
            if data.get("area").is_some_and(Value::is_array) {
                data.get_mut("area")
            } else {
                data.get_mut("list")
            }
        }
        Operation::Seats => {
            if data.is_array() {
                Some(data)
            } else {
                data.get_mut("list")
            }
        }
        Operation::Bookings => data.get_mut("data"),
        Operation::Area => unreachable!(),
    };
    let Some(Value::Array(rows)) = rows else {
        return Ok(fallback("missing_row_list"));
    };
    if !rows.iter().all(Value::is_object) || total.is_some_and(|total| total < rows.len() as u64) {
        return Ok(fallback("invalid_row_list"));
    }
    let mut output = json!({"result":if rows.is_empty() {"empty"} else {"success"}});
    output["entries"] = Value::Array(std::mem::take(rows));
    if let Some(total) = total {
        output["total"] = total.into();
    }
    Ok(output)
}

struct LibbookClient {
    http: Client,
    governor: Governor,
}

impl LibbookClient {
    fn http() -> Result<Client, Error> {
        let certificate = reqwest::Certificate::from_pem(INTERMEDIATE)
            .map_err(|_| Error::new("transport", "invalid pinned library intermediate certificate"))?;
        Client::builder()
            .add_root_certificate(certificate)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::new("transport", "cannot initialize library HTTPS client"))
    }

    fn open() -> Result<Self, Error> {
        Ok(Self {
            http: Self::http()?,
            governor: Governor::open()
                .map_err(|_| Error::new("governor_denied", "cannot open shared governor"))?,
        })
    }

    fn request(http: &Client, operation: Operation, token: &str, body: &Value) -> Result<reqwest::blocking::Request, Error> {
        http.post(endpoint(operation.path())?)
            .header(reqwest::header::AUTHORIZATION, authorization(token)?)
            .header(reqwest::header::REFERER, REFERER)
            .header(reqwest::header::ORIGIN, REFERER)
            .json(body)
            .build()
            .map_err(|_| Error::new("transport", "cannot construct library HTTPS request"))
    }

    fn read(&self, operation: Operation, token: &str, body: &Value) -> Result<Value, Error> {
        let request = Self::request(&self.http, operation, token, body)?;
        let mut lease = net::acquire(&self.governor)?;
        let mut response = match lease.start_request(|| self.http.execute(request))
            .map_err(|_| Error::new("governor_denied", "library request admission unavailable"))? {
            Ok(response) => response,
            Err(_) => {
                lease.finish(Outcome::NetworkFailure)
                    .map_err(|_| Error::new("governor_denied", "cannot settle library request"))?;
                return Err(Error::new("network_error", "library HTTPS request failed; no retry"));
            }
        };
        let status = response.status().as_u16();
        let retry_after = response.headers().get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()).map(str::to_owned);
        let content_type = response.headers().get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()).map(str::to_owned);
        let header_challenge = response.headers().iter()
            .any(|(key, value)| net::challenge_header(key.as_str(), value.as_bytes()));
        lease.observe_http_many(status, response.headers().get_all(reqwest::header::RETRY_AFTER)
            .iter().map(|value| value.to_str().ok()), header_challenge)
            .map_err(|_| Error::new("governor_denied", "cannot persist library response status"))?;
        let mut cookies = net::IssuedCookies::new();
        for declaration in response.headers().get_all(reqwest::header::SET_COOKIE) {
            cookies.absorb(declaration.to_str().ok());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        let read = response.by_ref().take(BODY_LIMIT as u64 + 1).read_to_end(&mut bytes);
        let network_failure = read.is_err() || bytes.len() > BODY_LIMIT;
        drop(response);
        let assessment = crate::html::assess_challenge_body(&bytes, content_type.as_deref(), !network_failure);
        let challenge = header_challenge || assessment == crate::html::ChallengeAssessment::Detected;
        let result = if status == 401 {
            parse_response(operation, status, &[], token)
        } else if status == 429 {
            Err(Error::new("rate_limited", "library request was rate limited"))
        } else if challenge {
            Err(Error::new("challenge_requires_human", "library challenge requires human review"))
        } else if network_failure {
            Err(Error::new("network_error", "library response is incomplete or too large"))
        } else if cookies.echoed(&bytes) {
            Err(Error::new("sensitive_response_withheld", "library response contains issued credentials"))
        } else if !net::classroom_json_mime(content_type.as_deref()) {
            if (200..300).contains(&status) {
                Ok(fallback("unexpected_content_type"))
            } else {
                Ok(json!({"result":"upstream_error"}))
            }
        } else {
            parse_response(operation, status, &bytes, token).and_then(|value| {
                if cookies.echoed_value(&value) {
                    Err(Error::new("sensitive_response_withheld", "library response contains issued credentials"))
                } else {
                    Ok(value)
                }
            })
        };
        // Keep the lease through parsing and credential admission.
        lease.finish(Outcome::Http { status, retry_after: retry_after.as_deref(), challenge, network_failure })
            .map_err(|_| Error::new("governor_denied", "cannot settle library response"))?;
        result
    }
}

/// All operation failures use the same typed, credential-free result envelope
/// as checkin. Offline execution never constructs a client or opens a governor.
pub fn run(input: &str, online: bool) -> Result<Value, Error> {
    let result = (|| -> Result<Value, Error> {
        let input: Input<'_> = parse_object(input)?;
        let payload: Payload = input.payload.map(|value| parse_object(value.get()))
            .transpose()?.unwrap_or_default();
        payload.validate(input.operation)?;
        if !online {
            return Ok(json!({"result":"unsupported","reason":"online_required","network_performed":false}));
        }
        let session = payload.session.as_ref().ok_or_else(invalid)?;
        let body = payload.body(input.operation)?;
        let mut value = LibbookClient::open()?.read(input.operation, &session.token, &body)?;
        value["operation"] = input.operation.name().into();
        value["network_performed"] = true.into();
        Ok(value)
    })();
    let mut value = match result {
        Ok(value) => value,
        Err(error) => json!({"result":if error.code == "unsupported" {"unsupported"} else {"blocked"},"reason":error.code}),
    };
    value["write_performed"] = false.into();
    Ok(value)
}

fn input_schema(online: bool) -> Value {
    let variants: Vec<_> = Operation::ALL
        .into_iter().map(|operation| {
            let mut properties = serde_json::Map::new();
            properties.insert("session".into(), json!({"type":"object","additionalProperties":false,"required":["token"],
                "properties":{"token":{"type":"string","minLength":1,"maxLength":TOKEN_LIMIT,"pattern":"^[A-Za-z0-9._~+/=-]+$"}}}));
            for field in operation.fields() {
                let schema = match *field {
                    "day" => json!({"type":"string","format":"date","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"}),
                    "start" | "end" => json!({"type":"string","pattern":"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$"}),
                    "page" | "size" => json!({"type":"integer","minimum":1,"maximum":u32::MAX}),
                    _ => json!({"type":"string","minLength":1}),
                };
                properties.insert((*field).into(), schema);
            }
            let mut required = Vec::new();
            if online {
                required.push("session");
                required.extend_from_slice(operation.fields());
            }
            json!({"type":"object","additionalProperties":false,
                "required":if online {vec!["operation","payload"]} else {vec!["operation"]},
                "properties":{"operation":{"const":operation.name()},"payload":{"type":"object",
                    "additionalProperties":false,"properties":properties,"required":required}}})
        }).collect();
    json!({"$schema":"https://json-schema.org/draft/2020-12/schema","oneOf":variants})
}

pub fn schema() -> Value {
    json!({"module":"libbook","state":"partial-live-verified","read_only":true,
        "input":input_schema(false),"online_input":input_schema(true),
        "network":"Explicit --online, one shared governor lease, one fixed HTTPS POST, no redirect or retry",
        "authentication":"Caller-supplied payload.session.token through protected JSON stdin; never echoed, stored or refreshed",
        "endpoints":Operation::ALL.map(Operation::path),
        "validation":"Gregorian YYYY-MM-DD; HH:MM start strictly before end on the same day; positive integer page and size",
        "output":{"type":"object","required":["result","write_performed"],"properties":{
            "result":{"enum":["success","empty","session_expired","upstream_error","fallback","blocked","unsupported"]},
            "write_performed":{"const":false},"entries":{"type":"array","items":{"type":"object"}},
            "total":{"type":"integer","minimum":0},"response":{"type":"object"},"reason":{"type":"string"},
            "operation":{"enum":["libraries","areas","area","seats","bookings"]},"network_performed":{"type":"boolean"},
            "fallback_reason":{"type":"string"},"raw_evidence":{"type":"object"}},"additionalProperties":false}})
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "synthetic.library.credential";

    fn parse(operation: Operation, value: Value) -> Value {
        parse_response(operation, 200, &serde_json::to_vec(&value).unwrap(), TOKEN).unwrap()
    }

    #[test]
    fn libraries_preserve_nested_floor_availability() {
        let value = parse(Operation::Libraries, json!({"code":0,"message":"操作成功","data":{"list":[
            {"id":"library-1","name":"测试馆","total_num":200,"free_num":50,"children":[
                {"id":"floor-2","name":"二层","total_num":100,"free_num":25}]}]}}));
        assert_eq!(value["result"], "success");
        assert_eq!(value["entries"][0]["free_num"], 50);
        assert_eq!(value["entries"][0]["children"][0]["total_num"], 100);
    }

    #[test]
    fn areas_accept_area_rows() {
        let value = parse(Operation::Areas, json!({"code":0,"data":{"area":[{"id":"area-1","areaName":"阅览区"}]}}));
        assert_eq!(value["entries"][0]["areaName"], "阅览区");
    }

    #[test]
    fn areas_accept_list_rows() {
        let value = parse(Operation::Areas, json!({"code":0,"data":{"list":[{"id":"area-1","name":"阅览区"}]}}));
        assert_eq!(value["entries"][0]["name"], "阅览区");
    }

    #[test]
    fn area_preserves_available_dates_and_segments() {
        let data = json!({"id":"area-1","date":["2026-11-20"],"segment":[{"start":"08:00","end":"22:00"}]});
        let value = parse(Operation::Area, json!({"code":0,"data":data}));
        assert_eq!(value["response"], data);
    }

    #[test]
    fn seats_preserve_status_and_coordinates() {
        let rows = json!([{"seat_no":"001","status":1,"statusName":"空闲","x":12.5,"y":40},
            {"name":"002","status":2,"statusName":"已预约","x":30,"y":40}]);
        let value = parse(Operation::Seats, json!({"code":0,"data":rows}));
        assert_eq!(value["entries"], rows);
    }

    #[test]
    fn seats_accept_list_wrapper() {
        let value = parse(Operation::Seats, json!({"code":0,"data":{"list":[{"seat_no":"003","status":0,"x":0,"y":1}]}}));
        assert_eq!(value["entries"][0]["seat_no"], "003");
    }

    #[test]
    fn bookings_preserve_rows_and_source_total() {
        let rows = json!([{"id":"booking-1","seat_no":"001","day":"2026-11-20",
            "segment_start":"08:00","segment_end":"09:00","statusName":"已预约"}]);
        let value = parse(Operation::Bookings, json!({"code":0,"data":{"data":rows,"total":7}}));
        assert_eq!(value["entries"], rows);
        assert_eq!(value["total"], 7);
    }

    #[test]
    fn empty_rows_are_not_a_parser_failure() {
        for operation in [Operation::Libraries, Operation::Areas, Operation::Seats, Operation::Bookings] {
            let data = match operation {
                Operation::Bookings => json!({"data":[],"total":0}),
                Operation::Seats => json!([]),
                _ => json!({"list":[]}),
            };
            assert_eq!(parse(operation, json!({"code":0,"data":data}))["result"], "empty");
        }
    }

    #[test]
    fn authorization_prefix_has_no_space_and_is_sensitive() {
        let header = authorization(TOKEN).unwrap();
        assert_eq!(header.to_str().unwrap(), "bearersynthetic.library.credential");
        assert!(header.is_sensitive());
        for token in ["", "a b", "a\nb", "a\rb", "a:b", "汉字"] {
            assert!(authorization(token).is_err());
        }
        assert!(authorization(&"x".repeat(TOKEN_LIMIT + 1)).is_err());
    }

    #[test]
    fn actual_request_uses_the_reviewed_post_headers_and_body() {
        let http = LibbookClient::http().unwrap();
        let body = json!({"day":"2026-11-20"});
        let request = LibbookClient::request(&http, Operation::Libraries, TOKEN, &body).unwrap();
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().as_str(), "https://booking.lib.buaa.edu.cn/v4/space/pcTopFor");
        assert_eq!(request.headers()[reqwest::header::AUTHORIZATION], "bearersynthetic.library.credential");
        assert!(request.headers()[reqwest::header::AUTHORIZATION].is_sensitive());
        assert_eq!(request.headers()[reqwest::header::ORIGIN], REFERER);
        assert_eq!(request.headers()[reqwest::header::REFERER], REFERER);
        assert_eq!(request.headers()[reqwest::header::CONTENT_TYPE], "application/json");
        assert_eq!(serde_json::from_slice::<Value>(request.body().unwrap().as_bytes().unwrap()).unwrap(), body);
    }

    #[test]
    fn endpoints_admit_only_five_exact_read_paths() {
        for operation in [Operation::Libraries, Operation::Areas, Operation::Area, Operation::Seats, Operation::Bookings] {
            let url = endpoint(operation.path()).unwrap();
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some("booking.lib.buaa.edu.cn"));
            assert_eq!(url.path(), operation.path());
        }
        for path in ["/v4/login/user", "/v4/Space/book", "/v4/member/cancel", "/v4/space/map",
            "/v4/Space/seat?delete=1", "/v4/Space/%73eat", "https://example.org/v4/Space/seat", "/v4/Space/../member/seat"] {
            assert_eq!(endpoint(path).unwrap_err().code, "unsupported");
        }
    }

    #[test]
    fn business_errors_are_classified_without_upstream_message() {
        let value = parse(Operation::Libraries, json!({"code":400,"message":"untrusted server text","data":{}}));
        assert_eq!(value, json!({"result":"upstream_error"}));
        assert_eq!(parse(Operation::Libraries, json!({"code":401,"message":"expired"}))["result"], "session_expired");
    }

    #[test]
    fn http_or_business_401_classifies_session_expiry() {
        assert_eq!(parse_response(Operation::Libraries, 401, b"", TOKEN).unwrap()["result"], "session_expired");
        assert_eq!(parse_response(Operation::Libraries, 403, br#"{"code":401}"#, TOKEN).unwrap()["result"], "session_expired");
        assert_eq!(parse_response(Operation::Libraries, 403, br#"{"code":0,"data":{"list":[]}}"#, TOKEN).unwrap()["result"], "upstream_error");
    }

    #[test]
    fn offline_without_session_has_no_network_and_no_write() {
        for operation in ["libraries", "areas", "area", "seats", "bookings"] {
            let value = run(&json!({"operation":operation,"payload":{}}).to_string(), false).unwrap();
            assert_eq!(value, json!({"result":"unsupported","reason":"online_required","network_performed":false,"write_performed":false}));
        }
    }

    #[test]
    fn strict_input_rejects_unknown_duplicate_and_positional_fields() {
        for input in [
            r#"[]"#, r#"["libraries",{}]"#, r#"{"operation":"libraries","extra":1}"#,
            r#"{"operation":"libraries","operation":"libraries"}"#,
            r#"{"operation":"libraries","payload":[]}"#,
            r#"{"operation":"libraries","payload":null}"#,
            r#"{"operation":"libraries","payload":{"unknown":1}}"#,
            r#"{"operation":"libraries","payload":{"day":"2026-11-20","day":"2026-11-21"}}"#,
            r#"{"operation":"libraries","payload":{"session":["opaque"]}}"#,
            r#"{"operation":"libraries","payload":{"session":{"token":"one","token":"two"}}}"#,
            r#"{"operation":"libraries","payload":{"session":{"token":123}}}"#,
            r#"{"operation":"libraries","payload":{"session":null}}"#,
            r#"{"operation":"libraries","payload":{"day":null}}"#,
            r#"{"operation":"libraries"} {}"#,
            r#"{"operation":"cancel","payload":{}}"#,
        ] {
            assert_eq!(run(input, false).unwrap()["reason"], "invalid_input", "{input}");
        }
    }

    #[test]
    fn payload_validation_enforces_operation_dates_times_and_pagination() {
        for input in [
            json!({"operation":"libraries","payload":{"day":"2026-02-29"}}),
            json!({"operation":"libraries","payload":{"day":"2026-2-20"}}),
            json!({"operation":"libraries","payload":{"day":"0000-01-01"}}),
            json!({"operation":"area","payload":{"area_id":""}}),
            json!({"operation":"area","payload":{"day":"2026-11-20"}}),
            json!({"operation":"seats","payload":{"start":"24:00"}}),
            json!({"operation":"seats","payload":{"start":"09:60"}}),
            json!({"operation":"seats","payload":{"start":"10:00","end":"09:00"}}),
            json!({"operation":"seats","payload":{"start":"09:00","end":"09:00"}}),
            json!({"operation":"bookings","payload":{"page":0}}),
            json!({"operation":"bookings","payload":{"size":0}}),
            json!({"operation":"bookings","payload":{"page":1.5}}),
        ] {
            assert_eq!(run(&input.to_string(), false).unwrap()["reason"], "invalid_input");
        }
        assert!(valid_day("2028-02-29"));
    }

    #[test]
    fn request_bodies_match_the_read_protocol() {
        let payload: Payload = parse_object(r#"{"day":"2026-11-20","library_id":"lib-1","area_id":"area-1","start":"08:00","end":"09:00","page":2,"size":10}"#).unwrap();
        assert_eq!(payload.body(Operation::Libraries).unwrap(), json!({"day":"2026-11-20"}));
        assert_eq!(payload.body(Operation::Areas).unwrap(), json!({
            "premisesIds": "lib-1", "date": "2026-11-20", "categoryIds": [], "storeyIds": [], "boutiqueIds": [],
        }));
        assert_eq!(payload.body(Operation::Area).unwrap(), json!({"id":"area-1"}));
        assert_eq!(payload.body(Operation::Seats).unwrap(), json!({
            "id": "area-1", "day": "2026-11-20", "label_id": [], "start_time": "08:00",
            "end_time": "09:00", "begdate": "", "enddate": "",
        }));
        assert_eq!(payload.body(Operation::Bookings).unwrap(), json!({"page":2,"size":10}));
        assert_eq!(Payload::default().body(Operation::Bookings).unwrap_err().code, "invalid_input");
    }

    #[test]
    fn missing_online_session_or_arguments_refuses_before_client() {
        let value = run(r#"{"operation":"libraries","payload":{"day":"2026-11-20"}}"#, true).unwrap();
        assert_eq!(value["reason"], "invalid_input");
        let value = run(&json!({"operation":"seats","payload":{"session":{"token":TOKEN}}}).to_string(), true).unwrap();
        assert_eq!(value["reason"], "invalid_input");
        assert!(!value.to_string().contains(TOKEN));
    }

    #[test]
    fn response_never_exports_literal_encoded_or_decoded_token() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        for text in [TOKEN.to_owned(), STANDARD.encode(TOKEN), TOKEN.replace('.', "%2E")] {
            let bytes = serde_json::to_vec(&json!({"code":0,"data":{"list":[{"name":text}]}})).unwrap();
            assert_eq!(parse_response(Operation::Libraries, 200, &bytes, TOKEN).unwrap_err().code, "sensitive_response_withheld");
        }
        let escaped = br#"{"code":0,"data":{"list":[{"name":"\u0073ynthetic.library.credential"}]}}"#;
        assert_eq!(parse_response(Operation::Libraries, 200, escaped, TOKEN).unwrap_err().code, "sensitive_response_withheld");
        let value = run(&json!({"operation":"libraries","payload":{"session":{"token":TOKEN}}}).to_string(), false).unwrap();
        assert!(!value.to_string().contains(TOKEN));
    }

    #[test]
    fn response_with_new_member_token_is_withheld() {
        let body = br#"{"code":0,"data":{"list":[],"member":{"token":"new-issued-credential"}}}"#;
        assert_eq!(parse_response(Operation::Libraries, 200, body, TOKEN).unwrap_err().code, "sensitive_response_withheld");
    }

    #[test]
    fn malformed_and_duplicate_responses_withhold_raw_bytes() {
        for bytes in [
            br#"{"code":0,"code":400,"data":{"list":[]}}"#.as_slice(),
            br#"{"code":0,"data":{"list":[{"name":"first","name":"last"}]}}"#,
            br#"{"code":0,"data":{"list":[]}} trailing"#,
            br#"<html>unrecognized private response</html>"#,
        ] {
            let value = parse_response(Operation::Libraries, 200, bytes, TOKEN).unwrap();
            assert_eq!(value["result"], "fallback");
            assert_eq!(value["raw_evidence"]["raw_withheld"], true);
            assert!(value["raw_evidence"].get("data").is_none());
        }
    }

    #[test]
    fn malformed_rows_and_missing_booking_total_do_not_fabricate_results() {
        for (operation, data) in [
            (Operation::Libraries, json!({"list":"unexpected"})),
            (Operation::Areas, json!({"list":[null]})),
            (Operation::Area, json!([])),
            (Operation::Seats, json!({})),
            (Operation::Bookings, json!({"data":[]})),
            (Operation::Bookings, json!({"data":[{"id":"one"}],"total":0})),
        ] {
            assert_eq!(parse(operation, json!({"code":0,"data":data}))["result"], "fallback");
        }
    }

    #[test]
    fn pinned_certificate_is_parsed_by_the_actual_client() {
        let certificate = openssl::x509::X509::from_pem(INTERMEDIATE).unwrap();
        let name = certificate.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next().unwrap().data().to_string().unwrap();
        assert_eq!(name, "GlobalSign GCC R3 DV TLS CA 2020");
        assert!(LibbookClient::http().is_ok());
    }

    #[test]
    fn schema_declares_all_operations_and_online_session_requirements() {
        let schema = schema();
        assert_eq!(schema["read_only"], true);
        let variants = schema["online_input"]["oneOf"].as_array().unwrap();
        assert_eq!(variants.len(), 5);
        for variant in variants {
            let payload = &variant["properties"]["payload"];
            assert!(payload["required"].as_array().unwrap().contains(&json!("session")));
            assert_eq!(payload["properties"]["session"]["additionalProperties"], false);
        }
    }
}
