//! HTTPS-only shuttle observations and fail-closed purchase planning.
//! The published HTTP CAS service is not an authorization to downgrade transport.
//! No ticket is submitted until HTTPS authentication and order verification have
//! a documented contract. Payment, retries and captcha recognition are absent.

use crate::governor::{FollowupError, Governor, Outcome, RequestKind};
use crate::html::{ChallengeAssessment, assess_challenge_body};
use crate::net::Error;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;

const ORIGIN: &str = "https://zhihuixiaoche.buaa.edu.cn";
const LIMIT: usize = 4 * 1024 * 1024;
const AUTH_REASON: &str = "The upstream CAS service is http://zhihuixiaoche.buaa.edu.cn/wechat/CASLogin. HTTPS-equivalent CAS acceptance and an authenticated session are unverified; HTTP downgrade is prohibited.";

fn invalid() -> Error {
    Error::new("invalid_input", "invalid shuttle input; consult shuttle schema")
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn blocked(operation: &str, reason: &str) -> Value {
    json!({"operation":operation,"status":"blocked","reason":reason})
}

fn sensitive_echo(bytes: &[u8]) -> bool {
    if let Ok(value)=serde_json::from_slice::<JsonPrivacy>(bytes) {
        return value.0;
    }
    sensitive_text(bytes)
}

struct JsonPrivacy(bool);
impl<'de> serde::Deserialize<'de> for JsonPrivacy {
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value=JsonPrivacy;
            fn expecting(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("a JSON value")}
            fn visit_map<M:serde::de::MapAccess<'de>>(self,mut map:M)->Result<Self::Value,M::Error>{
                let mut sensitive=false;
                while let Some(key)=map.next_key::<String>()? {
                    sensitive|=sensitive_text(key.as_bytes());
                    sensitive|=map.next_value::<JsonPrivacy>()?.0;
                }
                Ok(JsonPrivacy(sensitive))
            }
            fn visit_seq<S:serde::de::SeqAccess<'de>>(self,mut seq:S)->Result<Self::Value,S::Error>{
                let mut sensitive=false;
                while let Some(value)=seq.next_element::<JsonPrivacy>()?{sensitive|=value.0;}
                Ok(JsonPrivacy(sensitive))
            }
            fn visit_str<E:serde::de::Error>(self,value:&str)->Result<Self::Value,E>{Ok(JsonPrivacy(sensitive_text(value.as_bytes())))}
            fn visit_bool<E:serde::de::Error>(self,_:bool)->Result<Self::Value,E>{Ok(JsonPrivacy(false))}
            fn visit_i64<E:serde::de::Error>(self,_:i64)->Result<Self::Value,E>{Ok(JsonPrivacy(false))}
            fn visit_u64<E:serde::de::Error>(self,_:u64)->Result<Self::Value,E>{Ok(JsonPrivacy(false))}
            fn visit_f64<E:serde::de::Error>(self,_:f64)->Result<Self::Value,E>{Ok(JsonPrivacy(false))}
            fn visit_unit<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok(JsonPrivacy(false))}
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn sensitive_value(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key,value)| sensitive_text(key.as_bytes()) || sensitive_value(value)),
        Value::Array(values) => values.iter().any(sensitive_value),
        Value::String(text) => sensitive_text(text.as_bytes()),
        _ => false,
    }
}

fn safe_content_type(content_type: Option<&str>) -> Option<&'static str> {
    match content_type?.split(';').next()?.trim() {
        value if value.eq_ignore_ascii_case("application/json") => Some("application/json"),
        value if value.eq_ignore_ascii_case("text/html") => Some("text/html"),
        value if value.eq_ignore_ascii_case("text/plain") => Some("text/plain"),
        value if value.eq_ignore_ascii_case("application/octet-stream") => Some("application/octet-stream"),
        _ => None,
    }
}

fn sensitive_text(bytes: &[u8]) -> bool {
    const MARKERS: &[&[u8]] = &[b"session", b"cookie", b"token", b"ticket",
        b"authorization", b"credential", b"password", b"passwd", b"secret",
        b"csrf", b"execution", b"<input", b"<form", b"bearer", b"jwt",
        b"nonce", b"loginname", b"login_name", b"\\u", b"\\x", b"&#"];
    MARKERS.iter().any(|marker| bytes.windows(marker.len())
        .any(|window| window.eq_ignore_ascii_case(marker)))
}

fn evidence(bytes: &[u8], content_type: Option<&str>, reason: &str,
    assessment: &ChallengeAssessment) -> Value {
    let retain = matches!(assessment, ChallengeAssessment::Clear) && !sensitive_echo(bytes);
    json!({"body_base64":retain.then(||STANDARD.encode(bytes)),"content_type":safe_content_type(content_type),
        "byte_count":bytes.len(),"sha256":digest(bytes),"fallback_reason":reason,
        "raw_withheld":!retain,"raw_provenance":if retain {"original_response"} else {"withheld_unsafe_or_unreviewed_response"}})
}

fn response_assessment(_status: u16, header_challenge: bool, bytes: &[u8],
    content_type: Option<&str>, complete: bool) -> ChallengeAssessment {
    if header_challenge {
        ChallengeAssessment::Detected
    } else {
        assess_challenge_body(bytes, content_type, complete)
    }
}
fn response_content_type(headers:&reqwest::header::HeaderMap)->Result<Option<&str>,()> {
    let mut values=headers.get_all(reqwest::header::CONTENT_TYPE).iter();
    let first=values.next();
    if values.next().is_some(){return Err(());}
    first.map(|value|value.to_str().map_err(|_|())).transpose()
}

fn review_rejection(operation: &str, bytes: &[u8], content_type: Option<&str>,
    assessment: &ChallengeAssessment) -> Option<Value> {
    let reason = match assessment {
        ChallengeAssessment::Clear => return None,
        ChallengeAssessment::Detected =>
            "confirmed authentication challenge requires human review; no automatic retry attempted",
        ChallengeAssessment::Unreviewed =>
            "response body could not be safely reviewed; admission refused and no automatic retry attempted",
    };
    Some(json!({"operation":operation,"status":"blocked","reason":reason,
        "human_action_required":true,
        "evidence":evidence(bytes,content_type,"response withheld from raw fallback",assessment)}))
}
fn observed_response_rejection(operation:&str,status:u16,retry:bool,challenge:bool,complete:bool)->Option<Value> {
    if matches!(status,401|403) {
        Some(json!({"operation":operation,"status":"blocked","http_status":status,"reason":"HTTP authentication refused; shared safety latched; no automatic retry attempted","body_complete":complete}))
    } else if challenge {
        Some(json!({"operation":operation,"status":"blocked","http_status":status,"reason":"confirmed challenge requires human review; shared safety latched; no automatic retry attempted","body_complete":complete}))
    } else if status==429 || retry {
        Some(json!({"operation":operation,"status":"blocked","http_status":status,"reason":"HTTP cooldown requires operator review; no automatic retry attempted","retry_after_present":retry,"body_complete":complete,"https_cas_acceptance":"unknown","service_contract_reason":if operation=="service" {Some(AUTH_REASON)} else {None}}))
    } else {None}
}

/// Complete admitted/refused observation for one live response, computed
/// before the original shared lease settles. Issued session cookies withhold
/// projected and raw body bytes; denial, challenge, cooldown and body-failure
/// facts are preserved as independent refusals.
struct LiveResponse<'a> {
    status:u16, retry:bool, challenge:bool, complete:bool, issued:bool,
    assessment:&'a ChallengeAssessment, bytes:&'a [u8], content_type:Option<&'a str>,
}
fn live_admission(operation: &str, response: LiveResponse<'_>) -> Value {
    let LiveResponse {status,retry,challenge,complete,issued,assessment,bytes,content_type}=response;
    if let Some(rejection)=observed_response_rejection(operation,status,retry,challenge,complete) { return rejection; }
    if !complete { return blocked(operation,"response incomplete or exceeds byte limit; no subsequent request permitted"); }
    if issued { return json!({"operation":operation,"status":"blocked","http_status":status,"body_complete":complete,
        "reason":"response issued session cookie; body admission refused"}); }
    if let Some(rejection)=review_rejection(operation,bytes,content_type,assessment) { return rejection; }
    if operation=="service" { return json!({"operation":operation,"status":"unsupported","reason":AUTH_REASON,"https_probe_status":status,"https_cas_acceptance":"unknown","evidence":evidence(bytes,content_type,"HTTPS callback reachability does not prove CAS service acceptance",assessment)}); }
    if status!=200 { return json!({"operation":operation,"status":"blocked","reason":"HTTP response requires operator review; redirects are not followed","http_status":status,"evidence":evidence(bytes,content_type,"non-success response",assessment)}); }
    parse_page_assessed(bytes,content_type,operation,assessment)
}
// Accept only one unambiguous, literal assignment. Never execute page scripts.
fn csrf(text: &str) -> Option<&str> {
    let mut found = None;
    for tail in text.split("var csrf_token").skip(1) {
        let tail = tail.trim_start().strip_prefix('=')?.trim_start();
        let quote = tail.chars().next()?;
        if quote != '\'' && quote != '"' { return None; }
        let rest = &tail[1..];
        let end = rest.find(quote)?;
        let token = &rest[..end];
        if token.is_empty() || token.len() > 4096
            || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-./+=".contains(&b))
            || !rest[end + 1..].trim_start().starts_with(';') || found.is_some()
        { return None; }
        found = Some(token);
    }
    found
}

fn parse_page(bytes: &[u8], content_type: Option<&str>, operation: &str) -> Value {
    let assessment = assess_challenge_body(bytes, content_type, true);
    parse_page_assessed(bytes, content_type, operation, &assessment)
}

fn parse_page_assessed(bytes: &[u8], content_type: Option<&str>, operation: &str,
    assessment: &ChallengeAssessment) -> Value {
    if let Some(rejection) = review_rejection(operation, bytes, content_type, assessment) {
        return rejection;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return json!({"operation":operation,"status":"degraded","evidence":evidence(bytes,content_type,"response is not UTF-8",assessment)});
    };
    let Some(token) = csrf(text) else {
        return json!({"operation":operation,"status":"degraded","evidence":evidence(bytes,content_type,"missing or ambiguous literal csrf_token assignment",assessment)});
    };
    let document = Html::parse_document(text);
    let selector = Selector::parse("body").expect("constant selector");
    let visible: Vec<_> = document.select(&selector).flat_map(|body| body.descendants())
        .filter_map(|node| {
            if node.ancestors().filter_map(scraper::ElementRef::wrap).any(|el|
                matches!(el.value().name(), "script" | "style" | "template" | "noscript")) {
                return None;
            }
            node.value().as_text().map(|s| {let text:&str=s; text})
        }).filter(|s| !s.is_empty()).collect();
    let original_visible=visible.concat();
    let compact_visible:String=original_visible.chars().filter(|c|!c.is_whitespace()).collect();
    if crate::net::carries_secret(original_visible.as_bytes(),token)
        || crate::net::carries_secret(compact_visible.as_bytes(),token) {
        return json!({"operation":operation,"status":"degraded","evidence":evidence(bytes,content_type,"sensitive visible response withheld",assessment)});
    }
    let visible=visible.iter().map(|s|s.split_whitespace().collect::<Vec<_>>().join(" ")).filter(|s|!s.is_empty()).collect::<Vec<_>>().join(" ");
    if crate::net::carries_secret(visible.as_bytes(),token) || sensitive_text(visible.as_bytes()) {
        return json!({"operation":operation,"status":"degraded","evidence":evidence(bytes,content_type,"sensitive visible response withheld",assessment)});
    }
    json!({"operation":operation,"status":"ok","csrf_token_present":true,
        "visible_page_text":visible,"availability":null,
        "availability_reason":"该页面未提供可解析的余票结构；不推断余票数值",
        "evidence":evidence(bytes,content_type,"original page retained for offline re-reading when safe",assessment)})
}

fn purchase_response(bytes: &[u8], content_type: Option<&str>) -> Value {
    let assessment = assess_challenge_body(bytes, content_type, true);
    if let Some(rejection) = review_rejection("purchase", bytes, content_type, &assessment) {
        return rejection;
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(value) if !sensitive_value(&value) && value.is_object() && value.get("message").and_then(Value::as_str).is_some() => {
            json!({"operation":"purchase","status":"observed",
                "order_success":value["message"].as_str()==Some("下单成功"),
                "message":value["message"],
                "payment_link_present":value.get("url").and_then(Value::as_str).is_some_and(|s| !s.is_empty()),
                "paid":null,"postcondition_verified":false,
                "evidence":evidence(bytes,content_type,"observed response only; not an independently verified order",&assessment)})
        }
        _ => json!({"operation":"purchase","status":"degraded","evidence":evidence(bytes,content_type,"purchase response lacks a string message",&assessment)}),
    }
}

fn validate(value: &Value) -> Result<&str, Error> {
    let object = value.as_object().ok_or_else(invalid)?;
    let operation = object.get("operation").and_then(Value::as_str).ok_or_else(invalid)?;
    let fields: &[&str] = match operation {
        "page" | "availability" => &["operation","date","shifts_number","source"],
        "purchase" => &["operation","date","shifts_number","captcha","intent","confirm","response"],
        "cancel" | "service" => &["operation"],
        _ => return Err(invalid()),
    };
    if object.keys().any(|key| !fields.contains(&key.as_str())) { return Err(invalid()); }
    if matches!(operation,"page" | "availability" | "purchase") {
        let date = value.get("date").and_then(Value::as_str).ok_or_else(invalid)?;
        if date.len()!=10 || chrono::NaiveDate::parse_from_str(date,"%Y-%m-%d").is_err()
            || date.as_bytes()[4]!=b'-' || date.as_bytes()[7]!=b'-'
            || !date.bytes().enumerate().all(|(i,b)| i==4 || i==7 || b.is_ascii_digit()) {
            return Err(invalid());
        }
        if !value.get("shifts_number").and_then(Value::as_u64).is_some_and(|n| n>=1 && n<=u32::MAX as u64) { return Err(invalid()); }
    }
    for field in ["captcha","intent","confirm"] {
        if let Some(v)=value.get(field) {
            if !v.as_str().is_some_and(|s| !s.is_empty() && s.chars().count()<=4096 && !s.chars().any(char::is_control)) { return Err(invalid()); }
        }
    }
    for field in ["source","response"] {
        if let Some(source)=value.get(field) {
            let source=source.as_object().ok_or_else(invalid)?;
            if source.len()!=2 || !source.contains_key("body_base64") || !source.contains_key("content_type")
                || !(source["content_type"].is_null() || source["content_type"].is_string()) {
                return Err(invalid());
            }
            let encoded=source["body_base64"].as_str().ok_or_else(invalid)?;
            if encoded.len()>LIMIT*2 || STANDARD.decode(encoded).map_err(|_|invalid())?.len()>LIMIT { return Err(invalid()); }
        }
    }
    Ok(operation)
}

/// Input is stdin JSON. Supplied source/response bytes are offline observations,
/// never authorization, a session, or evidence that this module sent an order.
pub fn run(input: &str, online: bool) -> Result<Value, Error> {
    if input.len()>LIMIT*2+16384 { return Err(invalid()); }
    let value: Value=serde_json::from_str(input).map_err(|_|invalid())?;
    let operation=validate(&value)?;
    if operation=="cancel" {
        return Ok(json!({"operation":operation,"status":"unsupported","reason":"Neither upstream branch implements cancellation; no cancellation endpoint is known."}));
    }
    if operation=="purchase" {
        if let Some(source)=value.get("response") {
            let bytes=STANDARD.decode(source["body_base64"].as_str().ok_or_else(invalid)?).map_err(|_|invalid())?;
            return Ok(purchase_response(&bytes,source["content_type"].as_str()));
        }
        let Some(captcha)=value.get("captcha").and_then(Value::as_str) else {
            return Ok(json!({"operation":operation,"status":"blocked","reason":"captcha must be provided by a human; no recognition or retrieval retries are performed",
                "human_action_required":true,"safety_latched":true,"latch_scope":"this purchase intent; no request can proceed without explicit human captcha input"}));
        };
        let preview=json!({"intent":"purchase_shuttle_ticket","date":value["date"],
            "shifts_number":value["shifts_number"],"captcha_sha256":digest(captcha.as_bytes()),
            "submission_count":0,"payment_automation":false});
        let hash=digest(&serde_json::to_vec(&preview).map_err(|_|invalid())?);
        if value.get("intent").and_then(Value::as_str)!=Some("purchase_shuttle_ticket")
            || value.get("confirm").and_then(Value::as_str)!=Some(hash.as_str()) {
            return Ok(json!({"operation":operation,"status":"preview","preview":preview,"preview_sha256":hash,"confirmation_required":true}));
        }
        return Ok(json!({"operation":operation,"status":"unsupported","reason":AUTH_REASON,
            "additional_blocker":"No independent order postcondition endpoint or authenticated session contract is documented. No submission is made, including repeated confirmations.",
            "preview":preview,"preview_sha256":hash,"submitted":false}));
    }
    if let Some(source)=value.get("source") {
        let bytes=STANDARD.decode(source["body_base64"].as_str().ok_or_else(invalid)?).map_err(|_|invalid())?;
        return Ok(parse_page(&bytes,source["content_type"].as_str(),operation));
    }
    if !online { return Ok(blocked(operation,"offline mode requires retained source bytes; no request was made")); }
    let path=if operation=="service" { "/wechat/CASLogin".to_owned() } else {
        format!("/wechat/ticketInfoPage?shifts_date={}&shifts_number={}",value["date"].as_str().ok_or_else(invalid)?,value["shifts_number"])
    };
    let client=Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(30)).build().map_err(|_|Error::new("network_error","cannot construct shuttle HTTPS client"))?;
    let governor=match Governor::open() { Ok(g)=>g,Err(_)=>return Ok(blocked(operation,"shared governor unavailable")) };
    let mut lease=match governor.try_acquire(RequestKind::Interactive) { Ok(l)=>l,Err(_)=>return Ok(blocked(operation,"shared governor refused this request; no retry attempted")) };
    let request=client.get(format!("{ORIGIN}{path}")).timeout(Duration::from_secs(30));
    let response=match lease.start_request(||request.send()) {
        Ok(result)=>result,
        Err(FollowupError::CachedChallenge)=>{
            lease.finish(Outcome::SafetyObserved).map_err(|_|Error::new("governor_error","cannot persist observed shared safety latch"))?;
            return Err(Error::new("auth_latched","shared safety latch observed before shuttle request; no request sent"));
        }
        Err(FollowupError::Governor(_))=>return Err(Error::new("governor_error","cannot admit shuttle request; pending outcome retained")),
    };
    let mut response=match response {
        Ok(r)=>r,
        Err(_)=>{ lease.finish(Outcome::NetworkFailure).map_err(|_|Error::new("governor_error","cannot persist shuttle request outcome"))?;return Ok(blocked(operation,"HTTPS request failed; no retry attempted")); }
    };
    let status=response.status().as_u16();
    let header_challenge=response.headers().iter().any(|(name,value)|
        crate::net::challenge_header(name.as_str(),value.as_bytes()));
    let content_type=response_content_type(response.headers());
    let mime_reviewed=content_type.is_ok();
    let content_type=content_type.unwrap_or(None).map(str::to_owned);
    let retry=response.headers().contains_key(reqwest::header::RETRY_AFTER);
    let retry_after=response.headers().get_all("retry-after").iter().find_map(|value|value.to_str().ok()).map(str::to_owned);
    if lease.observe_http_many(status,response.headers().get_all("retry-after").iter().map(|value|value.to_str().ok()),header_challenge).is_err() {
        drop(response);return Err(Error::new("governor_error","cannot persist shuttle HTTP headers"));
    }
    // Issuance alone is not a challenge or an authentication rejection.
    let issued=crate::net::issues_session_cookie(response.headers());
    let mut bytes=Vec::new();
    let read=response.by_ref().take((LIMIT+1) as u64).read_to_end(&mut bytes);
    let complete=read.is_ok() && bytes.len()<=LIMIT;
    let mut assessment=response_assessment(status,header_challenge,&bytes,content_type.as_deref(),complete);
    if !mime_reviewed && matches!(&assessment,ChallengeAssessment::Clear){assessment=ChallengeAssessment::Unreviewed;}
    // Cancel any unread body while the original shared lease is still held.
    drop(response);
    let challenge=matches!(&assessment,ChallengeAssessment::Detected);
    let result=live_admission(operation,LiveResponse {status,retry,challenge,complete,issued,assessment:&assessment,
        bytes:&bytes,content_type:content_type.as_deref()});
    lease.finish(Outcome::Http {status,retry_after:retry_after.as_deref(),challenge,network_failure:!complete})
        .map_err(|_|Error::new("governor_error","cannot persist shuttle request outcome"))?;
    Ok(result)
}

/// Exact input field/null contract; output is a tagged observation envelope.
pub fn schema() -> Value {
    let source=json!({"type":"object","additionalProperties":false,"required":["body_base64","content_type"],"properties":{"body_base64":{"type":"string","contentEncoding":"base64","description":"Decoded maximum 4194304 bytes"},"content_type":{"type":["string","null"]}}});
    let mut branches=Vec::new();
    for operation in ["page","availability","purchase","cancel","service"] {
        let mut properties=serde_json::Map::new();
        properties.insert("operation".into(),json!({"const":operation}));
        let mut required=vec!["operation"];
        if matches!(operation,"page"|"availability"|"purchase") {
            required.extend(["date","shifts_number"]);
            properties.insert("date".into(),json!({"type":"string","format":"date","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"}));
            properties.insert("shifts_number".into(),json!({"type":"integer","minimum":1,"maximum":u32::MAX}));
        }
        if operation=="purchase" {
            for field in ["captcha","intent","confirm"] { properties.insert(field.into(),json!({"type":"string","minLength":1,"maxLength":4096,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]+$"})); }
            properties.insert("response".into(),source.clone());
        } else if matches!(operation,"page"|"availability") { properties.insert("source".into(),source.clone()); }
        branches.push(json!({"type":"object","additionalProperties":false,"required":required,"properties":properties}));
    }
    json!({"input":{"oneOf":branches},"output":{"type":"object","required":["operation","status"],"properties":{"operation":{"enum":["page","availability","purchase","cancel","service"]},"status":{"enum":["ok","blocked","unsupported","preview","observed","degraded"]}},"additionalProperties":true},"limits":{"input_utf8_bytes":LIMIT*2+16384,"decoded_body_bytes":LIMIT},"online_verified":false})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_map_preserves_retry_values_and_refuses_ambiguous_mime() {
        use reqwest::header::{HeaderMap,HeaderValue,CONTENT_TYPE,RETRY_AFTER};
        let mut headers=HeaderMap::new();headers.append(CONTENT_TYPE,HeaderValue::from_static("application/json"));
        assert_eq!(response_content_type(&headers),Ok(Some("application/json")));
        headers.append(CONTENT_TYPE,HeaderValue::from_static("text/html"));assert!(response_content_type(&headers).is_err());
        headers.remove(CONTENT_TYPE);headers.append(CONTENT_TYPE,HeaderValue::from_bytes(&[0xff]).unwrap());assert!(response_content_type(&headers).is_err());
        headers.append(RETRY_AFTER,HeaderValue::from_static("0"));headers.append(RETRY_AFTER,HeaderValue::from_static("1800"));headers.append(RETRY_AFTER,HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(headers.get_all("retry-after").iter().map(|v|v.to_str().ok()).collect::<Vec<_>>(),vec![Some("0"),Some("1800"),None]);
        headers.append("x-challenge",HeaderValue::from_static("none"));headers.append("x-challenge",HeaderValue::from_static("required"));
        assert!(headers.iter().any(|(k,v)|crate::net::challenge_header(k.as_str(),v.as_bytes())));
    }

    fn assert_challenge_latches(header_challenge: bool, body: &[u8]) {
        use std::os::unix::fs::DirBuilderExt;
        let path=std::env::temp_dir().join(format!("buaa-shuttle-challenge-{}-{}",
            std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let governor=Governor::isolated_for_test(&path.join("governor")).unwrap();
        let lease=governor.try_acquire(RequestKind::Interactive).unwrap();
        let assessment=response_assessment(200,header_challenge,body,Some("text/html"),true);
        let challenge=matches!(assessment,ChallengeAssessment::Detected);
        assert!(challenge);
        lease.finish(Outcome::Http {status:200,retry_after:None,challenge,network_failure:false}).unwrap();
        assert!(governor.status().unwrap().safety_latched);
        assert!(governor.try_acquire(RequestKind::Interactive).is_err());
        drop(governor);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn http_200_header_only_challenge_latches_with_binary_body() {
        for (name,value) in [("cf-mitigated", b"challenge".as_slice()),
            ("x-captcha", b"required".as_slice()), ("x-challenge", b"required".as_slice()),
            ("cf-chl-test", b"present".as_slice())] {
            assert_challenge_latches(crate::net::challenge_header(name,value), &[0xff,0]);
        }
        assert!(matches!(response_assessment(200,crate::net::challenge_header("cf-mitigated",b"none"),b"ordinary page",Some("text/html"),true),ChallengeAssessment::Clear));
    }
    #[test]
    fn http_200_body_only_challenge_latches_without_headers() {
        assert_challenge_latches(false,b"<input name='captcha'>");
        assert!(matches!(response_assessment(200,false,b"<body>ordinary page</body>",Some("text/html"),true),ChallengeAssessment::Clear));
    }
    #[test]
    fn json_captcha_prose_is_not_a_challenge() {
        let body=br#"{"message":"CAPTCHA and getCaptchaImage are documentation terms"}"#;
        assert!(matches!(response_assessment(200,false,body,Some("application/json"),true),ChallengeAssessment::Clear));
    }
    #[test]
    fn authentication_status_latches_without_claiming_body_challenge() {
        use std::os::unix::fs::DirBuilderExt;
        for (status,complete,expected_latch) in [(401,true,true),(403,true,true),(200,false,false),(200,true,false)] {
            let path=std::env::temp_dir().join(format!("buaa-shuttle-status-{}-{}-{}",std::process::id(),status,std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
            std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            let governor=Governor::isolated_for_test(&path.join("governor")).unwrap();
            let lease=governor.try_acquire(RequestKind::Interactive).unwrap();
            let assessment=response_assessment(status,false,b"ordinary prose",Some("text/plain"),complete);
            assert!(!matches!(&assessment,ChallengeAssessment::Detected));
            if !complete {assert!(matches!(&assessment,ChallengeAssessment::Unreviewed));}
            lease.finish(Outcome::Http{status,retry_after:None,challenge:false,network_failure:!complete}).unwrap();
            assert_eq!(governor.status().unwrap().safety_latched,expected_latch);
            drop(governor);std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test]
    fn decoded_credentials_and_mime_parameters_are_withheld() {
        let body=br#"{"\u0074oken":"private_value"}"#;
        let result=purchase_response(body,Some("application/json; sessionid=private_value"));
        assert!(result["evidence"]["body_base64"].is_null());
        assert_eq!(result["evidence"]["content_type"],"application/json");
        assert!(!result.to_string().contains("private_value"));
    }
    #[test]
    fn incomplete_body_is_unreviewed_but_header_remains_detected() {
        assert!(matches!(response_assessment(200,false,b"<html><body>",Some("text/html"),false),ChallengeAssessment::Unreviewed));
        assert!(matches!(response_assessment(200,true,b"<html><body>",Some("text/html"),false),ChallengeAssessment::Detected));
    }
    #[test]
    fn unreviewed_and_challenge_rejections_withhold_raw_content() {
        let unreviewed=review_rejection("page",b"private body",Some("text/html"),&ChallengeAssessment::Unreviewed).unwrap();
        assert_eq!(unreviewed["status"],"blocked");
        assert!(unreviewed["evidence"]["body_base64"].is_null());
        assert!(!unreviewed["reason"].as_str().unwrap().to_ascii_lowercase().contains("captcha"));
        let detected=parse_page(b"<input name='captcha'>",Some("text/html"),"page");
        assert_eq!(detected["status"],"blocked");
        assert!(detected["evidence"]["body_base64"].is_null());
        assert!(!detected.to_string().contains("<input"));
    }
    #[test]
    fn token_echo_is_withheld_from_raw_fallback() {
        let result=parse_page(b"<script>var csrf_token='private_value';</script>",Some("text/html"),"page");
        assert!(result["evidence"]["body_base64"].is_null());
        assert_eq!(result["evidence"]["raw_withheld"],true);
        assert!(!result.to_string().contains("private_value"));
    }
    #[test]
    fn extracted_csrf_value_cannot_escape_through_visible_text() {
        let result=parse_page(b"<body>abc_123<script>var csrf_token='abc_123';</script></body>",Some("text/html"),"page");
        assert_eq!(result["status"],"degraded");assert!(result["visible_page_text"].is_null());
        assert!(!result.to_string().contains("abc_123"));
    }
    #[test]
    fn split_csrf_values_are_not_returned_to_source_consumers() {
        for text in ["<span>abc</span><span>123</span>","<span>ab c</span><span>1 23</span>"] {
            let body=format!("<body>{text}<script>var csrf_token='abc123';</script></body>");
            let input=json!({"operation":"page","date":"2026-10-27","shifts_number":1,"source":{"body_base64":STANDARD.encode(body),"content_type":"text/html"}});
            let result=run(&input.to_string(),false).unwrap();assert_eq!(result["status"],"degraded");
            assert!(result["visible_page_text"].is_null());assert!(result["evidence"]["body_base64"].is_null());
        }
    }
    #[test]
    fn encoded_csrf_value_is_not_returned_to_source_consumers() {
        let body=b"<body>YWJjMTIz<script>var csrf_token='abc123';</script></body>";
        let input=json!({"operation":"page","date":"2026-10-27","shifts_number":1,"source":{"body_base64":STANDARD.encode(body),"content_type":"text/html"}});
        let result=run(&input.to_string(),false).unwrap();assert_eq!(result["status"],"degraded");
        assert!(result["visible_page_text"].is_null());assert!(!result.to_string().contains("YWJjMTIz"));
    }
    #[test]
    fn observed_refusal_survives_incomplete_body_and_service_cooldown() {
        for status in [401,403] {let result=observed_response_rejection("service",status,false,false,false).unwrap();assert_eq!(result["http_status"],status);assert_eq!(result["body_complete"],false);assert!(!result["reason"].as_str().unwrap().contains("challenge"));}
        let result=observed_response_rejection("page",200,false,true,false).unwrap();assert_eq!(result["body_complete"],false);assert!(result["reason"].as_str().unwrap().contains("challenge"));
        for (status,retry) in [(429,false),(200,true)] {let result=observed_response_rejection("service",status,retry,false,true).unwrap();assert_eq!(result["http_status"],status);assert_eq!(result["retry_after_present"],retry);assert_eq!(result["service_contract_reason"],AUTH_REASON);}
    }
    #[test]
    fn bearer_and_escaped_credential_responses_are_withheld() {
        for key in ["bearer","jwt","nonce","loginname","login_name"] {
            let result=purchase_response(json!({"message":"failed",(key):"synthetic_private"}).to_string().as_bytes(),Some("application/json"));
            assert_eq!(result["status"],"degraded");assert!(result["evidence"]["body_base64"].is_null());
        }
        for body in [br#"{"message":"failed","other":"\\x62earer synthetic_private"}"#.as_slice(),br#"{"message":"failed","other":"&#98;earer synthetic_private"}"#.as_slice()] {
            let result=purchase_response(body,Some("application/json"));assert!(result["evidence"]["body_base64"].is_null());
        }
    }
    #[test]
    fn duplicate_json_members_do_not_hide_early_secrets() {
        let body=br#"{"message":"failed","x":{"\u0074oken":"private_value"},"x":0}"#;
        let result=purchase_response(body,Some("application/json"));
        assert!(result["evidence"]["body_base64"].is_null());assert!(!result.to_string().contains("private_value"));
        let safe=br#"{"message":"failed","x":1,"x":0}"#;
        assert_eq!(STANDARD.decode(purchase_response(safe,Some("application/json"))["evidence"]["body_base64"].as_str().unwrap()).unwrap(),safe);
    }
    #[test]
    fn safe_unicode_json_preserves_original_but_escaped_token_is_withheld() {
        let safe=br#"{"title":"\u4e2d"}"#;
        let result=purchase_response(safe,Some("application/json"));
        assert_eq!(STANDARD.decode(result["evidence"]["body_base64"].as_str().unwrap()).unwrap(),safe);
        let result=purchase_response(br#"{"\u0074oken":"private_value"}"#,Some("application/json"));
        assert!(result["evidence"]["body_base64"].is_null());
        assert!(!result.to_string().contains("private_value"));
    }
    #[test]
    fn literal_csrf_and_visible_text() {
        let bytes=b"<body>Shuttle 08:00<script>var csrf_token='abc_123';</script></body>";
        let result=parse_page(bytes,Some("text/html"),"page");
        assert_eq!(result["csrf_token_present"],true);
        assert!(result["csrf_token"].is_null());
        assert_eq!(result["visible_page_text"],"Shuttle 08:00");
        assert!(result["availability"].is_null());
        assert!(csrf("var csrf_token='a';var csrf_token='b';").is_none());
    }
    #[test]
    fn purchase_message_is_authority() {
        assert_eq!(purchase_response("{\"message\":\"下单成功\",\"status\":0}".as_bytes(),Some("application/json"))["order_success"],true);
        assert_eq!(purchase_response(b"{\"message\":\"failed\",\"status\":1}",Some("application/json"))["order_success"],false);
        assert_eq!(purchase_response(b"{}",Some("application/json"))["status"],"degraded");
        let unreviewed=purchase_response(b"{\"message\":\"failed\"}",None);
        assert_eq!(unreviewed["status"],"blocked");
        assert!(unreviewed["evidence"]["body_base64"].is_null());
    }
    #[test]
    fn human_captcha_and_repeated_confirmation_fail_closed() {
        let mut input=json!({"operation":"purchase","date":"2026-10-27","shifts_number":1});
        assert_eq!(run(&input.to_string(),false).unwrap()["safety_latched"],true);
        input["captcha"]=json!("human");
        let preview=run(&input.to_string(),false).unwrap();
        input["intent"]=json!("purchase_shuttle_ticket");
        input["confirm"]=preview["preview_sha256"].clone();
        for _ in 0..2 { assert_eq!(run(&input.to_string(),true).unwrap()["submitted"],false); }
    }
    #[test]
    fn http_service_never_used() {
        assert_eq!(run(r#"{"operation":"service"}"#,false).unwrap()["status"],"blocked");
        assert!(AUTH_REASON.contains("HTTP downgrade is prohibited"));
    }
    #[test]
    fn raw_evidence_round_trips() {
        let body=b"ordinary response";
        let result=parse_page(body,Some("text/plain"),"page");
        assert_eq!(result["evidence"]["content_type"],"text/plain");
        assert_eq!(STANDARD.decode(result["evidence"]["body_base64"].as_str().unwrap()).unwrap(),body);
        let binary=[0xff,0,1];
        let result=parse_page(&binary,Some("application/octet-stream"),"page");
        assert_eq!(STANDARD.decode(result["evidence"]["body_base64"].as_str().unwrap()).unwrap(),binary);
    }
    fn admit_fixture(operation:&str,status:u16,headers:&reqwest::header::HeaderMap,bytes:&[u8],complete:bool)->Value {
        let header_challenge=headers.iter().any(|(name,value)|crate::net::challenge_header(name.as_str(),value.as_bytes()));
        let content_type=response_content_type(headers);
        let mime_reviewed=content_type.is_ok();
        let content_type=content_type.unwrap_or(None);
        let mut assessment=response_assessment(status,header_challenge,bytes,content_type,complete);
        if !mime_reviewed && matches!(&assessment,ChallengeAssessment::Clear){assessment=ChallengeAssessment::Unreviewed;}
        let challenge=matches!(&assessment,ChallengeAssessment::Detected);
        live_admission(operation,LiveResponse {status,retry:headers.contains_key(reqwest::header::RETRY_AFTER),challenge,complete,
            issued:crate::net::issues_session_cookie(headers),assessment:&assessment,bytes,content_type})
    }
    #[test]
    fn issued_session_cookie_withholds_service_raw_fallback_and_page_text() {
        use reqwest::header::{HeaderMap,HeaderValue,CONTENT_TYPE,LOCATION,SET_COOKIE};
        let mut headers=HeaderMap::new();
        headers.insert(CONTENT_TYPE,HeaderValue::from_static("text/plain"));
        let service_body=b"freshopaque123";
        let clean=admit_fixture("service",200,&headers,service_body,true);
        assert_eq!(STANDARD.decode(clean["evidence"]["body_base64"].as_str().unwrap()).unwrap(),service_body);
        for value in [HeaderValue::from_static("x=freshopaque123"),HeaderValue::from_static("x=q"),
            HeaderValue::from_static("malformed"),HeaderValue::from_static("x=; Max-Age=0"),
            HeaderValue::from_bytes(&[0xff]).unwrap()] {
            headers.insert(SET_COOKIE,value);
            let result=admit_fixture("service",200,&headers,service_body,true);
            assert_eq!(result["status"],"blocked");
            assert_eq!(result["reason"],"response issued session cookie; body admission refused");
            assert!(result.get("evidence").is_none());
            assert!(!result.to_string().contains("freshopaque123"));
        }
        let page_body=b"<body>Shuttle freshopaque123<script>var csrf_token='abc_123';</script></body>";
        headers.insert(CONTENT_TYPE,HeaderValue::from_static("text/html"));
        headers.remove(SET_COOKIE);
        let clean=admit_fixture("page",200,&headers,page_body,true);
        assert_eq!(clean["status"],"ok");
        assert_eq!(clean["visible_page_text"],"Shuttle freshopaque123");
        headers.insert(SET_COOKIE,HeaderValue::from_static("x=freshopaque123"));
        let result=admit_fixture("page",200,&headers,page_body,true);
        assert_eq!(result["status"],"blocked");
        assert!(result.get("visible_page_text").is_none());
        assert!(result.get("evidence").is_none());
        assert!(!result.to_string().contains("freshopaque123"));
        let redirect=admit_fixture("page",302,&headers,page_body,true);
        assert_eq!(redirect["http_status"],302);
        assert!(redirect.get("evidence").is_none());
        headers.insert(CONTENT_TYPE,HeaderValue::from_static("application/freshopaque123"));
        headers.insert(LOCATION,HeaderValue::from_static("https://example.invalid/freshopaque123"));
        let result=admit_fixture("service",200,&headers,service_body,true);
        assert_eq!(result["status"],"blocked");
        assert!(result.get("evidence").is_none());
        assert!(!result.to_string().contains("freshopaque123"));
    }
    #[test]
    fn denial_cooldown_and_body_failure_survive_cookie_withholding() {
        use reqwest::header::{HeaderMap,HeaderValue,CONTENT_TYPE,RETRY_AFTER,SET_COOKIE};
        let mut headers=HeaderMap::new();
        headers.insert(CONTENT_TYPE,HeaderValue::from_static("text/plain"));
        headers.insert(SET_COOKIE,HeaderValue::from_static("x=freshopaque123"));
        for status in [401u16,403] {
            let result=admit_fixture("service",status,&headers,b"freshopaque123",true);
            assert_eq!(result["http_status"],status);
            assert!(result["reason"].as_str().unwrap().contains("authentication refused"));
            assert!(!result.to_string().contains("freshopaque123"));
        }
        let cooldown=admit_fixture("service",429,&headers,b"freshopaque123",true);
        assert_eq!(cooldown["http_status"],429);
        assert_eq!(cooldown["retry_after_present"],false);
        headers.insert(RETRY_AFTER,HeaderValue::from_static("60"));
        let cooldown=admit_fixture("service",200,&headers,b"freshopaque123",true);
        assert_eq!(cooldown["reason"],"HTTP cooldown requires operator review; no automatic retry attempted");
        assert_eq!(cooldown["retry_after_present"],true);
        headers.remove(RETRY_AFTER);
        headers.insert("cf-mitigated",HeaderValue::from_static("challenge"));
        let challenge=admit_fixture("page",200,&headers,b"freshopaque123",true);
        assert!(challenge["reason"].as_str().unwrap().contains("challenge"));
        headers.remove("cf-mitigated");
        let incomplete=admit_fixture("page",200,&headers,b"freshopaque123",false);
        assert_eq!(incomplete["reason"],"response incomplete or exceeds byte limit; no subsequent request permitted");
    }
}
