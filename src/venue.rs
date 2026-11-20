//! Read-only seminar-room availability and personal reservations. The caller
//! supplies an existing access token through stdin; no login, refresh or writes.
use crate::{
    governor::{Governor, Outcome},
    net::{self, Error},
    smart::sign,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::NaiveDate;
use reqwest::{blocking::Client, header::HeaderValue};
use serde::{Deserialize, de::MapAccess};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const ORIGIN: &str = "https://cgyy.buaa.edu.cn";
const SERVER: &str = "/venue-zhjs-server";
const APP_KEY: &str = "8fceb735082b5a529312040b58ea780b";
const REFERER: &str = "https://cgyy.buaa.edu.cn/venue-zhjs/mobileReservation";
const BODY_LIMIT: u64 = 8 * 1024 * 1024;

fn invalid() -> Error {
    Error::new("invalid_input", "expected a valid venue operation and strict JSON payload")
}

// Derived structs also accept JSON sequences unless their caller explicitly
// requires a map. Apply the same object-only boundary to every input layer.
fn object<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON object")
        }
        fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(access))
        }
    }
    deserializer.deserialize_map(Visitor(std::marker::PhantomData))
}

fn optional_session<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Session>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Option<Session>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("session object or null")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            object(deserializer).map(Some)
        }
    }
    deserializer.deserialize_option(Visitor)
}

fn secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

// Deliberately neither Debug nor Serialize: a session must never be output.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    #[serde(deserialize_with = "secret")]
    access_token: Zeroizing<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Venues,
    Orders,
    Day,
    Codes,
}
impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::Venues => "venues",
            Self::Orders => "orders",
            Self::Day => "day",
            Self::Codes => "codes",
        }
    }
    fn path(self) -> &'static str {
        match self {
            Self::Venues => "/api/front/website/venues",
            Self::Orders => "/api/orders/mine",
            Self::Day => "/api/reservation/day/info",
            Self::Codes => "/api/codes",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunInput {
    operation: Operation,
    #[serde(default, deserialize_with = "object")]
    payload: RunPayload,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunPayload {
    #[serde(default, deserialize_with = "optional_session")]
    session: Option<Session>,
    page: Option<u32>,
    size: Option<u16>,
    venue_site_id: Option<u64>,
    date: Option<String>,
    code_key: Option<String>,
}
impl RunPayload {
    fn validate(&self) -> Result<(), Error> {
        if self.size.is_some_and(|size| !(1..=1000).contains(&size))
            || self.venue_site_id == Some(0)
            || self.date.as_ref().is_some_and(|date| {
                date.len() != 10
                    || !date.bytes().enumerate().all(|(i, byte)| {
                        if matches!(i, 4 | 7) { byte == b'-' } else { byte.is_ascii_digit() }
                    })
                    || NaiveDate::parse_from_str(date, "%Y-%m-%d").is_err()
            })
            || self.code_key.as_ref().is_some_and(|key| {
                key.is_empty() || key.chars().count() > 200 || key.chars().any(char::is_control)
            })
            || self.session.as_ref().is_some_and(|session| {
                session.access_token.is_empty()
                    || session.access_token.len() > 8192
                    || !session.access_token.bytes().all(|byte| byte.is_ascii_graphic())
            })
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn parameters(&self, operation: Operation) -> Result<BTreeMap<String, Value>, Error> {
        Ok(match operation {
            Operation::Venues => BTreeMap::new(),
            Operation::Orders => BTreeMap::from([
                ("page".into(), Value::String(self.page.unwrap_or(1).to_string())),
                ("size".into(), Value::String(self.size.unwrap_or(10).to_string())),
            ]),
            Operation::Day => BTreeMap::from([
                ("searchDate".into(), Value::String(self.date.as_ref().ok_or_else(invalid)?.clone())),
                ("venueSiteId".into(), Value::String(self.venue_site_id.ok_or_else(invalid)?.to_string())),
            ]),
            Operation::Codes => BTreeMap::from([
                ("codeKey".into(), Value::String(self.code_key.as_ref().ok_or_else(invalid)?.clone())),
            ]),
        })
    }
}

// Private response trees reject duplicate members, and wipe both discarded
// credentials and temporary strings even when deserialization fails midway.
struct PrivateValue(Value);
impl<'de> Deserialize<'de> for PrivateValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PrivateValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON value")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::Null))
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::from(value)))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::from(value)))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::from(value)))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::String(value.into())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::String(value)))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut result = PrivateValue(Value::Array(Vec::new()));
                while let Some(mut value) = access.next_element::<PrivateValue>()? {
                    result.0.as_array_mut().unwrap().push(std::mem::take(&mut value.0));
                }
                Ok(result)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut result = PrivateValue(Value::Object(serde_json::Map::new()));
                while let Some(key) = access.next_key::<String>()? {
                    let mut key = Zeroizing::new(key);
                    let values = result.0.as_object_mut().unwrap();
                    if values.contains_key(key.as_str()) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let mut value = access.next_value::<PrivateValue>()?;
                    values.insert(std::mem::take(&mut *key), std::mem::take(&mut value.0));
                }
                Ok(result)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
impl Drop for PrivateValue {
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

fn marked(bytes: &[u8]) -> bool {
    [
        "token", "cookie", "password", "ticket", "authorization", "session",
        "csrf", "secret", "loginname", "login_name", "credential", "bearer",
        "execution", "nonce", "jwt",
    ].iter().any(|marker| {
        bytes.windows(marker.len()).any(|part| part.eq_ignore_ascii_case(marker.as_bytes()))
    })
}

fn private_value(value: &Value, secret: Option<&str>) -> bool {
    let sensitive = |bytes: &[u8]| {
        marked(bytes) || secret.is_some_and(|secret| net::carries_secret(bytes, secret))
    };
    match value {
        Value::String(text) => sensitive(text.as_bytes()),
        Value::Array(values) => values.iter().any(|value| private_value(value, secret)),
        Value::Object(values) => values.iter().any(|(key, value)| {
            sensitive(key.as_bytes()) || private_value(value, secret)
        }),
        _ => secret.is_some_and(|secret| {
            net::json_scalar_matches(value, |bytes| net::carries_secret(bytes, secret))
        }),
    }
}

fn safe_mime(content_type: Option<&str>) -> Option<&'static str> {
    let essence = content_type?.split(';').next()?.trim();
    ["application/json", "text/plain", "text/html", "application/xhtml+xml", "application/octet-stream"]
        .into_iter().find(|candidate| essence.eq_ignore_ascii_case(candidate))
}

fn fallback(body: &[u8], content_type: Option<&str>, reason: &'static str, withheld: Option<&str>) -> Value {
    // Unparsed escape sequences could conceal a credential. Raw evidence is
    // allowed only after the same conservative screen as the checkin reader.
    let withheld = withheld.or_else(|| {
        (marked(body) || body.contains(&b'\\') || body.windows(2).any(|part| part == b"&#")
            || url::form_urlencoded::parse(body).any(|(key, value)| marked(key.as_bytes()) || marked(value.as_bytes())))
            .then_some("sensitive_response_material")
    });
    json!({"result":"fallback","fallback_reason":reason,"raw_html":withheld.is_none().then(|| STANDARD.encode(body)),
        "content_type":safe_mime(content_type),"byte_length":body.len(),"raw_withheld":withheld.is_some(),
        "raw_withheld_reason":withheld,"write_performed":false})
}

fn data_contract(operation: Operation, data: &Value) -> bool {
    let identifier = |value: &Value| value.is_u64() || value.as_str().is_some_and(|text| !text.is_empty());
    let rows = || data.get("content").and_then(Value::as_array);
    let slot_status = |slot: &Value| {
        slot.get("reservationStatus").is_some_and(|status| status.is_string() || status.is_i64())
    };
    match operation {
        Operation::Venues => rows().is_some_and(|rows| rows.iter().all(|row| {
            identifier(&row["id"]) && identifier(&row["campusId"])
                && row["venueName"].is_string() && row["campusName"].is_string()
                && row["siteList"].as_array().is_some_and(|sites| sites.iter().all(|site| {
                    identifier(&site["id"]) && site["siteName"].is_string()
                }))
        })),
        Operation::Orders => rows().is_some_and(|rows| rows.iter().all(Value::is_object))
            && data.get("totalElements").is_some_and(Value::is_u64),
        Operation::Codes => rows().is_some_and(|rows| rows.iter().all(Value::is_object)),
        Operation::Day => data.get("spaceTimeInfo").and_then(Value::as_array).is_some_and(|slots| {
            slots.iter().all(|slot| identifier(&slot["id"]) && slot["beginTime"].is_string() && slot["endTime"].is_string())
        }) && data.get("reservationDateSpaceInfo").and_then(Value::as_object).is_some_and(|dates| {
            dates.values().all(|spaces| match spaces {
                Value::Array(rooms) => rooms.iter().all(|room| {
                    room["spaceName"].is_string() && room.as_object().is_some_and(|fields| {
                        fields.iter().filter(|(key, _)| {
                            !key.is_empty() && key.bytes().all(|byte| byte.is_ascii_digit())
                        }).all(|(_, slot)| slot_status(slot))
                    })
                }),
                Value::Object(rooms) => rooms.values().all(|slots| {
                    slots.as_object().is_some_and(|slots| slots.values().all(slot_status))
                }),
                _ => false,
            })
        }),
    }
}

fn parse_response(operation: Operation, status: u16, body: &[u8], content_type: Option<&str>, secret: &str,
    assessment: crate::html::ChallengeAssessment) -> Value {
    let mut document = serde_json::from_slice::<PrivateValue>(body).ok();
    let issued_token = if matches!(operation, Operation::Day) {
        document.as_mut()
            .and_then(|document| document.0.get_mut("data"))
            .and_then(Value::as_object_mut)
            .and_then(|data| data.remove("token"))
            .map(PrivateValue)
    } else {
        None
    };
    let value = document.as_ref().map(|document| &document.0);
    let code = value.and_then(|value| value.get("code")).and_then(Value::as_i64);
    let message = value.and_then(|value| value.get("message").or_else(|| value.get("msg"))).and_then(Value::as_str);
    const DENIAL: &str = "没有权限访问此接口";
    if status == 401 || code == Some(401)
        || value.is_some_and(|value| ["message", "msg"].into_iter().any(|key| {
            value[key].as_str().is_some_and(|message| message.contains(DENIAL))
        }))
        || std::str::from_utf8(body).is_ok_and(|text| text.trim() == DENIAL)
    {
        return json!({"result":"session_expired","write_performed":false});
    }
    let issued_material = issued_token.as_ref().is_some_and(|token| match &token.0 {
        Value::Null => false,
        Value::String(token) => !token.is_empty() && value.is_some_and(|value| private_value(value, Some(token))),
        _ => true,
    });
    let sensitive = issued_material || net::carries_secret(body, secret)
        || value.is_some_and(|value| private_value(value, Some(secret)));
    if assessment == crate::html::ChallengeAssessment::Clear && (status != 200 || code.is_some_and(|code| code != 200)) {
        let code = code.filter(|code| *code != 200).unwrap_or(i64::from(status));
        let message = if sensitive { "upstream error message withheld" } else { message.unwrap_or("upstream HTTP failure") };
        let mut error = json!({"result":"upstream_error","message":message.chars().take(200).collect::<String>(),"write_performed":false});
        if !net::json_scalar_matches(&Value::from(code), |bytes| {
            net::carries_secret(bytes, secret)
                || issued_token.as_ref().and_then(|token| token.0.as_str())
                    .filter(|token| !token.is_empty())
                    .is_some_and(|token| net::carries_secret(bytes, token))
        }) {
            error["code"] = Value::from(code);
        }
        return error;
    }
    let withheld = if sensitive {
        Some("sensitive_response_material")
    } else {
        match assessment {
            crate::html::ChallengeAssessment::Clear => None,
            crate::html::ChallengeAssessment::Detected => Some("challenge_detected"),
            crate::html::ChallengeAssessment::Unreviewed => Some("response_safety_unreviewed"),
        }
    };
    if withheld.is_some() {
        return fallback(body, content_type, "response_withheld", withheld);
    }
    if code != Some(200) || !value.and_then(|value| value.get("data")).is_some_and(|data| data_contract(operation, data)) {
        return fallback(body, content_type, "unrecognized_json_contract",
            issued_token.is_some().then_some("sensitive_response_material"));
    }
    let data = document.as_mut().unwrap().0.as_object_mut().unwrap().remove("data").unwrap();
    json!({"result":"success","operation":operation.name(),"response":data,"write_performed":false})
}

fn admitted(url: &Url, body: Option<&[u8]>) -> bool {
    body.is_none() && url.scheme() == "https" && url.host_str() == Some("cgyy.buaa.edu.cn")
        && url.port_or_known_default() == Some(443) && url.username().is_empty()
        && url.password().is_none() && url.fragment().is_none()
        && [Operation::Venues, Operation::Orders, Operation::Day, Operation::Codes]
            .iter().any(|operation| url.path().strip_prefix(SERVER) == Some(operation.path()))
}

struct VenueClient {
    http: Client,
    governor: Governor,
}
impl VenueClient {
    fn open() -> Result<Self, Error> {
        Ok(Self {
            http: Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never()).timeout(Duration::from_secs(30)).build()
                .map_err(|_| Error::new("transport", "cannot initialize HTTPS client"))?,
            governor: Governor::open().map_err(|_| Error::new("governor_denied", "cannot open shared governor"))?,
        })
    }

    fn request_inner(&self, operation: Operation, url: Url, session: &Session,
        parameters: &BTreeMap<String, Value>, body: Option<&[u8]>) -> Result<Value, Error> {
        if !admitted(&url, body) {
            return Err(Error::new("unsupported", "venue transport permits only the four fixed HTTPS GET endpoints"));
        }
        let mut token = HeaderValue::from_str(&session.access_token).map_err(|_| invalid())?;
        token.set_sensitive(true);
        let mut lease = net::acquire(&self.governor)?;
        let mut response = match lease.start_request(|| {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
                .map_err(|_| Error::new("clock", "invalid clock"))?.as_millis().to_string();
            Ok(self.http.get(url).header("app-key", APP_KEY).header("timestamp", &timestamp)
                .header("sign", sign(operation.path(), parameters, &timestamp))
                .header("Referer", REFERER).header("cgAuthorization", token).send())
        }) {
            Ok(Ok(Ok(response))) => response,
            Ok(Err(failure)) => {
                lease.finish_without_request().map_err(|_| Error::new("governor_denied", "cannot settle local request refusal"))?;
                return Err(failure);
            }
            Ok(Ok(Err(_))) => {
                lease.finish(Outcome::NetworkFailure).map_err(|_| Error::new("governor_denied", "cannot settle request"))?;
                return Err(Error::new("network_error", "HTTPS request failed; no retry performed"));
            }
            Err(_) => return Err(Error::new("governor_denied", "request-start admission unavailable")),
        };
        let status = response.status().as_u16();
        let header_challenge = response.headers().iter().any(|(key, value)| net::challenge_header(key.as_str(), value.as_bytes()));
        lease.observe_http_many(status, response.headers().get_all("retry-after").iter().map(|value| value.to_str().ok()), header_challenge)
            .map_err(|_| Error::new("governor_denied", "cannot persist response headers"))?;
        let retry = response.headers().get("retry-after").and_then(|value| value.to_str().ok()).map(str::to_owned);
        let content_type = Zeroizing::new((response.headers().get_all("content-type").iter().count() == 1)
            .then(|| response.headers().get("content-type").and_then(|value| value.to_str().ok()).map(str::to_owned)).flatten());
        let cookies: Vec<Zeroizing<String>> = response.headers().get_all("set-cookie").iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned)).map(Zeroizing::new).collect();
        let mut bytes = Zeroizing::new(Vec::new());
        let read = response.by_ref().take(BODY_LIMIT + 1).read_to_end(&mut bytes);
        let network_failure = read.is_err() || bytes.len() as u64 > BODY_LIMIT;
        let assessment = crate::html::assess_challenge_body(&bytes, content_type.as_deref(), !network_failure);
        let challenge = header_challenge || assessment == crate::html::ChallengeAssessment::Detected;
        let result = if status == 401 {
            Ok(json!({"result":"session_expired","write_performed":false}))
        } else if network_failure {
            Err(Error::new("body_error", "response incomplete or over limit"))
        } else if status == 429 {
            Err(Error::new("rate_limited", "request denied; no retry performed"))
        } else if header_challenge {
            Err(Error::new("challenge_requires_human", "upstream request requires human verification"))
        } else {
            let mut value = parse_response(operation, status, &bytes, content_type.as_deref(), &session.access_token, assessment);
            // Issued cookies are never adopted. Check every declaration and
            // credential-length value, including escaped JSON projections.
            for cookie in &cookies {
                if value["result"] == "session_expired" {
                    break;
                }
                let pair_value = cookie.split(';').next().and_then(|pair| pair.split_once('='))
                    .map(|(_, value)| value.trim()).filter(|value| value.len() >= 8);
                for secret in std::iter::once(cookie.as_str()).chain(pair_value) {
                    if net::carries_secret(&bytes, secret) || private_value(&value, Some(secret)) {
                        value = fallback(&bytes, content_type.as_deref(), "response_withheld", Some("sensitive_response_material"));
                    }
                }
            }
            if !cookies.is_empty() && value["result"] == "fallback" {
                value["raw_html"] = Value::Null;
                value["raw_withheld"] = Value::Bool(true);
                value["raw_withheld_reason"] = json!("session_cookie_issued");
            }
            Ok(value)
        };
        drop(response);
        let business_denial = result.as_ref().is_ok_and(|value| value["result"] == "session_expired");
        lease.finish(Outcome::Http { status, retry_after: retry.as_deref(), challenge: challenge || business_denial, network_failure })
            .map_err(|_| Error::new("governor_denied", "cannot settle request"))?;
        result
    }

    fn read(&self, operation: Operation, session: &Session, parameters: &BTreeMap<String, Value>) -> Result<Value, Error> {
        let mut url = Url::parse(ORIGIN).map_err(|_| invalid())?;
        url.set_path(&format!("{SERVER}{}", operation.path()));
        if !parameters.is_empty() {
            let mut query = url.query_pairs_mut();
            for (key, value) in parameters {
                query.append_pair(key, value.as_str().ok_or_else(invalid)?);
            }
        }
        self.request_inner(operation, url, session, parameters, None)
    }
}

pub fn run(input: &str, online: bool) -> Result<Value, Error> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let input: RunInput = object(&mut deserializer).map_err(|_| invalid())?;
    deserializer.end().map_err(|_| invalid())?;
    input.payload.validate()?;
    if !online {
        return Ok(json!({"result":"unsupported","reason":"offline","operation":input.operation.name(),
            "network_performed":false,"write_performed":false}));
    }
    let session = input.payload.session.as_ref().ok_or_else(invalid)?;
    let parameters = input.payload.parameters(input.operation)?;
    VenueClient::open()?.read(input.operation, session, &parameters)
}

pub fn schema() -> Value {
    json!({"module":"venue","state":"partial-live-verified",
        "input":{"type":"object","additionalProperties":false,"required":["operation"],"properties":{
            "operation":{"enum":["venues","orders","day","codes"]},
            "payload":{"type":"object","additionalProperties":false,"properties":{
                "session":{"type":["object","null"],"additionalProperties":false,"required":["access_token"],"properties":{
                    "access_token":{"type":"string","minLength":1,"maxLength":8192,"pattern":"^[!-~]+$","writeOnly":true}}},
                "page":{"type":["integer","null"],"minimum":0,"maximum":u32::MAX,"default":1},
                "size":{"type":["integer","null"],"minimum":1,"maximum":1000,"default":10},
                "venue_site_id":{"type":["integer","null"],"minimum":1,"maximum":u64::MAX},
                "date":{"type":["string","null"],"format":"date","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
                "code_key":{"type":["string","null"],"minLength":1,"maxLength":200,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]+$"}
            }}}},
        "online_requires":{"all":["payload.session.access_token"],"day":["payload.venue_site_id","payload.date"],"codes":["payload.code_key"]},
        "authentication":"Existing access_token from protected stdin only; cgAuthorization header, no login, persistence, refresh or retry.",
        "network_policy":{"default":"offline","opt_in":"--online","host":"cgyy.buaa.edu.cn:443","methods":["GET"],"redirects":false,"timeout_seconds":30,"governor":"shared"},
        "output":{"type":"object","required":["result","write_performed"],"properties":{
            "result":{"enum":["success","session_expired","upstream_error","fallback","unsupported"]},
            "response":{"type":"object"},"reason":{"type":"string"},"code":{"type":"integer"},
            "message":{"type":"string","maxLength":200},"fallback_reason":{"type":"string"},
            "raw_html":{"type":["string","null"],"contentEncoding":"base64"},"write_performed":{"const":false}}}})
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "synthetic.private.session";

    fn parse(operation: Operation, status: u16, body: &[u8]) -> Value {
        let mime = Some("application/json");
        parse_response(operation, status, body, mime, TOKEN, crate::html::assess_challenge_body(body, mime, true))
    }

    #[test]
    fn venue_signature_uses_browser_constants_and_empty_query() {
        let probe_key = concat!("8fceb735082b5a52", "9312040b58ea780b");
        assert!(APP_KEY == probe_key);
        assert_eq!(sign(Operation::Venues.path(), &BTreeMap::new(), "1700000000123"), "ca025887dcd32679975387bf5e0656df");
    }

    #[test]
    fn venue_signature_sorts_query_and_drops_metadata() {
        let mut params = BTreeMap::from([("size".into(), json!(10)), ("page".into(), json!(1))]);
        for key in ["gmtCreate", "gmtModified", "creator", "modifier", "id", "_index", "_rowKey"] {
            params.insert(key.into(), json!("ignored"));
        }
        assert_eq!(sign("api/orders/mine", &params, "1700000000123"), "50215f436dbc52e75d406f956bdbec47");
    }

    #[test]
    fn venue_signature_uses_raw_query_values_and_api_path() {
        let params = RunPayload { date: Some("2026-11-20".into()), venue_site_id: Some(1), ..Default::default() };
        assert_eq!(sign(Operation::Day.path(), &params.parameters(Operation::Day).unwrap(), "1700000000123"), "3cfdade37e5ffe9f7faf9c703236aa12");
        let params = RunPayload { code_key: Some("用途 类型".into()), ..Default::default() };
        assert_eq!(sign(Operation::Codes.path(), &params.parameters(Operation::Codes).unwrap(), "1700000000123"), "ada463e551544e3bd335dd33936d4e2f");
    }

    #[test]
    fn venue_parses_campuses_and_sites() {
        let body = r#"{"code":200,"data":{"content":[{"id":1,"campusId":2,"venueName":"研讨室","campusName":"学院路","siteList":[{"id":3,"siteName":"示例场地"}]}]}}"#;
        let value = parse(Operation::Venues, 200, body.as_bytes());
        assert_eq!(value["result"], "success");
        assert_eq!(value["response"]["content"][0]["siteList"][0]["id"], 3);
    }

    #[test]
    fn venue_parses_order_rows_and_totals() {
        let value = parse(Operation::Orders, 200, br#"{"code":200,"data":{"content":[{"id":42,"status":1}],"totalElements":23}}"#);
        assert_eq!(value["result"], "success");
        assert_eq!(value["response"]["content"][0]["id"], 42);
        assert_eq!(value["response"]["totalElements"], 23);
    }

    #[test]
    fn venue_parses_empty_orders_as_a_successful_page() {
        let value = parse(Operation::Orders, 200, br#"{"code":200,"data":{"content":[],"totalElements":0}}"#);
        assert_eq!(value["result"], "success");
        assert_eq!(value["response"]["content"], json!([]));
    }

    #[test]
    fn venue_parses_day_slot_and_availability_maps() {
        let body = r#"{"code":200,"data":{"spaceTimeInfo":[{"id":4,"beginTime":"09:00","endTime":"10:00"}],"reservationDateSpaceInfo":{"2026-11-20":{"示例场地":{"4":{"reservationStatus":0,"orderId":null}}}}}}"#;
        let value = parse(Operation::Day, 200, body.as_bytes());
        assert_eq!(value["result"], "success");
        assert_eq!(value["response"]["spaceTimeInfo"][0]["beginTime"], "09:00");
        assert_eq!(value["response"]["reservationDateSpaceInfo"]["2026-11-20"]["示例场地"]["4"]["reservationStatus"], 0);
    }

    #[test]
    fn venue_parses_day_room_rows_with_numeric_slot_keys() {
        let body = r#"{"code":200,"data":{"spaceTimeInfo":[{"id":4,"beginTime":"09:00","endTime":"10:00"}],"reservationDateSpaceInfo":{"2026-11-20":[{"id":12,"spaceName":"示例场地","4":{"reservationStatus":1,"orderId":null}},{"id":13,"spaceName":"另一间","4":{"reservationStatus":4,"orderId":null}}]}}}"#;
        let value = parse(Operation::Day, 200, body.as_bytes());
        assert_eq!(value["result"], "success");
        let rooms = &value["response"]["reservationDateSpaceInfo"]["2026-11-20"];
        assert_eq!(rooms[0]["4"]["reservationStatus"], 1);
        assert_eq!(rooms[1]["4"]["reservationStatus"], 4);
        let malformed = body.replace("\"reservationStatus\":4", "\"reservationStatus\":null");
        assert_eq!(parse(Operation::Day, 200, malformed.as_bytes())["fallback_reason"], "unrecognized_json_contract");
    }

    #[test]
    fn venue_discards_day_token_and_withholds_echoes_and_raw_fallback() {
        let body = r#"{"code":200,"data":{"token":"fixture-private-value","spaceTimeInfo":[],"reservationDateSpaceInfo":{}}}"#;
        let clean = parse(Operation::Day, 200, body.as_bytes());
        assert_eq!(clean["result"], "success");
        assert!(clean["response"].get("token").is_none());
        let echo = body.replace("\"spaceTimeInfo\":[]", "\"note\":\"fixture-private-value\",\"spaceTimeInfo\":[]");
        let malformed = body.replace("\"spaceTimeInfo\":[]", "\"spaceTimeInfo\":null");
        for rejected in [echo, malformed] {
            let result = parse(Operation::Day, 200, rejected.as_bytes());
            assert_eq!(result["result"], "fallback");
            assert_eq!(result["raw_withheld"], true);
            assert!(result["raw_html"].is_null());
        }
    }

    #[test]
    fn venue_parses_code_table() {
        let value = parse(Operation::Codes, 200, br#"{"code":200,"data":{"content":[{"codeKey":"purpose_type","codeValue":"discussion"}]}}"#);
        assert_eq!(value["result"], "success");
        assert_eq!(value["response"]["content"][0]["codeValue"], "discussion");
    }

    #[test]
    fn venue_classifies_http_401_even_without_a_json_body() {
        assert_eq!(parse(Operation::Orders, 401, b"")["result"], "session_expired");
    }

    #[test]
    fn venue_classifies_business_401_and_permission_text() {
        for body in [r#"{"code":401}"#, r#"{"code":403,"msg":"没有权限访问此接口"}"#, "没有权限访问此接口"] {
            assert_eq!(parse(Operation::Orders, 200, body.as_bytes())["result"], "session_expired");
        }
    }

    #[test]
    fn venue_truncates_business_error_message_at_character_boundary() {
        let body = json!({"code": 500, "message": "错".repeat(201)}).to_string();
        let value = parse(Operation::Orders, 200, body.as_bytes());
        assert_eq!(value["result"], "upstream_error");
        assert_eq!(value["code"], 500);
        assert_eq!(value["message"], "错".repeat(200));
    }

    #[test]
    fn venue_withholds_numeric_credential_echo_in_error_code() {
        let value = parse_response(Operation::Orders, 200, br#"{"code":1234}"#,
            Some("application/json"), "1234", crate::html::ChallengeAssessment::Clear);
        assert_eq!(value["result"], "upstream_error");
        assert!(value.get("code").is_none());
    }

    #[test]
    fn venue_retains_safe_fallback_bytes() {
        let body = br#"{"code":200,"data":{"content":null}}"#;
        let value = parse(Operation::Venues, 200, body);
        assert_eq!(value["fallback_reason"], "unrecognized_json_contract");
        assert_eq!(STANDARD.decode(value["raw_html"].as_str().unwrap()).unwrap(), body);
    }

    #[test]
    fn venue_withholds_credentials_in_errors_data_and_raw_fallback() {
        let error = json!({"code": 500, "msg": TOKEN}).to_string();
        let value = parse(Operation::Orders, 200, error.as_bytes());
        assert_eq!(value["result"], "upstream_error");
        assert_eq!(value["message"], "upstream error message withheld");
        for body in [
            r#"{"code":200,"data":{"content":[{"name":"synthetic.private.\u0073ession"}],"totalElements":1}}"#,
            r#"{"code":200,"data":{"content":[{"access_token":"other-secret"}],"totalElements":1}}"#,
            r#"{"code":200,"data":{"content":null,"format":"synthetic.private.session"}}"#,
            r#"{"code":200,"code":401,"message":"synthetic.private.\u0073ession"}"#,
        ] {
            let value = parse(Operation::Orders, 200, body.as_bytes());
            assert_eq!(value["result"], "fallback");
            assert!(value["raw_html"].is_null());
            assert_eq!(value["raw_withheld"], true);
            assert!(!value.to_string().contains(TOKEN));
        }
    }

    #[test]
    fn venue_requires_strict_object_inputs() {
        for input in [
            r#"{"operation":"venues","unknown":true}"#,
            r#"{"operation":"venues","payload":{"unknown":true}}"#,
            r#"{"operation":"venues","payload":{"session":{"access_token":"demo","unknown":true}}}"#,
            r#"{"operation":"venues","payload":{"session":{"access_token":"a","access_token":"b"}}}"#,
            r#"["venues",{}]"#,
            r#"{"operation":"venues","payload":[]}"#,
            r#"{"operation":"venues","payload":{"session":["demo"]}}"#,
            r#"{"operation":"login"}"#,
        ] {
            assert_eq!(run(input, false).unwrap_err().code, "invalid_input");
        }
    }

    #[test]
    fn venue_offline_every_operation_works_without_a_session() {
        for operation in ["venues", "orders", "day", "codes"] {
            let input = json!({"operation":operation,"payload":{}}).to_string();
            let value = run(&input, false).unwrap();
            assert_eq!(value["result"], "unsupported");
            assert_eq!(value["reason"], "offline");
            assert_eq!(value["network_performed"], false);
        }
    }

    #[test]
    fn venue_online_validation_rejects_missing_session_or_query_before_transport() {
        for input in [
            r#"{"operation":"venues"}"#,
            r#"{"operation":"day","payload":{"session":{"access_token":"demo"},"date":"2026-11-20"}}"#,
            r#"{"operation":"day","payload":{"session":{"access_token":"demo"},"venue_site_id":1}}"#,
            r#"{"operation":"codes","payload":{"session":{"access_token":"demo"}}}"#,
        ] {
            assert_eq!(run(input, true).unwrap_err().code, "invalid_input");
        }
    }

    #[test]
    fn venue_validates_page_size_site_date_key_and_header_input() {
        for payload in [json!({"page":-1}), json!({"size":0}), json!({"size":1001}),
            json!({"venue_site_id":0}), json!({"date":"2026-02-29"}), json!({"date":"2026-1-01"}),
            json!({"code_key":""}), json!({"session":{"access_token":"\r\n"}})] {
            let input = json!({"operation":"orders","payload":payload}).to_string();
            assert_eq!(run(&input, false).unwrap_err().code, "invalid_input");
        }
        assert!(run(r#"{"operation":"day","payload":{"date":"2028-02-29","venue_site_id":1}}"#, false).is_ok());
        let defaults = RunPayload::default().parameters(Operation::Orders).unwrap();
        assert_eq!(defaults["page"], "1");
        assert_eq!(defaults["size"], "10");
    }

    #[test]
    fn venue_transport_admits_only_reviewed_https_get_routes() {
        for operation in [Operation::Venues, Operation::Orders, Operation::Day, Operation::Codes] {
            let url = Url::parse(&format!("{ORIGIN}{SERVER}{}", operation.path())).unwrap();
            assert!(admitted(&url, None));
            assert!(!admitted(&url, Some(b"")));
        }
        for url in [
            "http://cgyy.buaa.edu.cn/venue-zhjs-server/api/codes",
            "https://cgyy.buaa.edu.cn:8443/venue-zhjs-server/api/codes",
            "https://cgyy.buaa.edu.cn.example.org/venue-zhjs-server/api/codes",
            "https://user@cgyy.buaa.edu.cn/venue-zhjs-server/api/codes",
            "https://cgyy.buaa.edu.cn/venue-zhjs-server/api/login",
            "https://cgyy.buaa.edu.cn/venue-zhjs-server/api/orders/lock/code",
        ] {
            assert!(!admitted(&Url::parse(url).unwrap(), None));
        }
    }
}
