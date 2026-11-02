//! Reviewed JumpServer reads and non-executing, explicitly authorized tunnel plans.
use crate::{governor::{FollowupError, Governor, Outcome}, net::{self, Error}};
use crate::html::{ChallengeAssessment, assess_challenge_body};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use zeroize::Zeroizing;

const HOST: &str = "buaaos.studio";
const LIMIT: u64 = 4 * 1024 * 1024;
fn invalid() -> Error { Error::new("invalid_input", "invalid reviewed OS lab request") }

/// This secret-bearing request must come directly from stdin, never argv or a receipt.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    host: String,
    #[serde(deserialize_with = "secret")]
    csrftoken: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    sessionid: Zeroizing<String>,
    asset_id: Option<String>,
}
fn secret<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}
fn token(s: &str) -> bool { !s.is_empty() && s.len() <= 4096 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) }
fn identifier(s: &str) -> bool { !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) }
fn parse(input: &str) -> Result<Request, Error> {
    require_object(input)?;
    let r: Request = serde_json::from_str(input).map_err(|_| invalid())?;
    if r.host != HOST || !token(&r.csrftoken) || !token(&r.sessionid) || r.asset_id.as_deref().is_some_and(|v| !identifier(v)) { return Err(invalid()); }
    Ok(r)
}
fn require_object(input:&str)->Result<(),Error> {
    if input.as_bytes().iter().copied().find(|&byte|!matches!(byte,b' '|b'\t'|b'\r'|b'\n'))!=Some(b'{') {
        return Err(invalid());
    }
    Ok(())
}
fn sensitive_echo(body: &[u8]) -> bool {
    if let Ok(v)=serde_json::from_slice::<JsonPrivacy>(body) {return v.0;}
    sensitive_text(body)
}
struct JsonPrivacy(bool);
impl<'de> serde::Deserialize<'de> for JsonPrivacy {
 fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error>{
  struct Visitor;
  impl<'de> serde::de::Visitor<'de> for Visitor {
   type Value=JsonPrivacy;
   fn expecting(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("a JSON value")}
   fn visit_map<M:serde::de::MapAccess<'de>>(self,mut m:M)->Result<Self::Value,M::Error>{
    let mut sensitive=false;
    while let Some(k)=m.next_key::<String>()?{sensitive|=sensitive_text(k.as_bytes());sensitive|=m.next_value::<JsonPrivacy>()?.0;}
    Ok(JsonPrivacy(sensitive))
   }
   fn visit_seq<S:serde::de::SeqAccess<'de>>(self,mut s:S)->Result<Self::Value,S::Error>{
    let mut sensitive=false;while let Some(v)=s.next_element::<JsonPrivacy>()?{sensitive|=v.0;}Ok(JsonPrivacy(sensitive))
   }
   fn visit_str<E:serde::de::Error>(self,v:&str)->Result<Self::Value,E>{Ok(JsonPrivacy(sensitive_text(v.as_bytes())))}
   fn visit_bool<E:serde::de::Error>(self,_:bool)->Result<Self::Value,E>{Ok(JsonPrivacy(false))}
   fn visit_i64<E:serde::de::Error>(self,_:i64)->Result<Self::Value,E>{Ok(JsonPrivacy(false))}
   fn visit_u64<E:serde::de::Error>(self,_:u64)->Result<Self::Value,E>{Ok(JsonPrivacy(false))}
   fn visit_f64<E:serde::de::Error>(self,_:f64)->Result<Self::Value,E>{Ok(JsonPrivacy(false))}
   fn visit_unit<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok(JsonPrivacy(false))}
  }
  d.deserialize_any(Visitor)
 }
}
fn sensitive_value(value: &Value) -> bool {
    match value {
        Value::Object(fields)=>fields.iter().any(|(key,value)|sensitive_text(key.as_bytes())||sensitive_value(value)),
        Value::Array(values)=>values.iter().any(sensitive_value),
        Value::String(text)=>sensitive_text(text.as_bytes()),
        _=>false,
    }
}
fn safe_content_type(ct: Option<&str>) -> Option<&'static str> {
    match ct?.split(';').next()?.trim() {
        v if v.eq_ignore_ascii_case("application/json")=>Some("application/json"),
        v if v.eq_ignore_ascii_case("text/html")=>Some("text/html"),
        v if v.eq_ignore_ascii_case("text/plain")=>Some("text/plain"),
        v if v.eq_ignore_ascii_case("application/octet-stream")=>Some("application/octet-stream"),
        _=>None,
    }
}
fn submitted_echo(value: &Value, secrets: &[&str]) -> bool {
    // A projected field may carry the credential literally, base64-encoded or
    // percent-encoded; every reversible form is refused.
    let contains=|text:&str|secrets.iter().any(|secret|!secret.is_empty()
        && crate::net::carries_secret(text.as_bytes(),secret));
    match value {
        Value::Object(fields)=>fields.iter().any(|(key,value)|contains(key)||submitted_echo(value,secrets)),
        Value::Array(values)=>values.iter().any(|value|submitted_echo(value,secrets)),
        Value::String(text)=>contains(text),
        Value::Number(_) | Value::Bool(_) | Value::Null=>contains(&value.to_string()),
    }
}
fn release_response(value: Value, secrets: &[&str]) -> Result<Value,Error> {
    if submitted_echo(&value,secrets) {
        Err(Error::new("unsafe_response","OS lab response withheld because it echoes submitted credentials"))
    } else {Ok(value)}
}
fn sensitive_text(body: &[u8]) -> bool {
    const MARKERS: &[&[u8]] = &[b"session",b"cookie",b"token",b"ticket",
        b"authorization",b"credential",b"password",b"passwd",b"secret",
        b"csrf",b"execution",b"<input",b"<form",b"bearer",b"jwt",
        b"nonce",b"loginname",b"login_name",b"\\u",b"\\x",b"&#"];
    MARKERS.iter().any(|marker|body.windows(marker.len())
        .any(|window|window.eq_ignore_ascii_case(marker)))
}
fn evidence(body: &[u8], ct: Option<&str>, reason: &str,
    assessment: &ChallengeAssessment, authenticated: bool) -> Value {
    // An authenticated unknown response may echo credentials in arbitrary
    // encodings or fields. Its original bytes are never a safe raw fallback.
    let retain = !authenticated && matches!(assessment,ChallengeAssessment::Clear)
        && !sensitive_echo(body);
    json!({"result":"fallback","raw_base64":retain.then(||STANDARD.encode(body)),"content_type":safe_content_type(ct),"byte_count":body.len(),"sha256":format!("{:x}",Sha256::digest(body)),"fallback_reason":reason,"raw_withheld":!retain,"raw_provenance":if retain {"original_response"} else {"withheld_unsafe_or_unreviewed_response"}})
}
fn response_assessment(header_challenge: bool, body: &[u8], ct: Option<&str>,
    complete: bool) -> ChallengeAssessment {
    if header_challenge {ChallengeAssessment::Detected} else {assess_challenge_body(body,ct,complete)}
}
fn response_content_type(headers:&reqwest::header::HeaderMap)->Result<Option<&str>,()> {
    let mut values=headers.get_all(reqwest::header::CONTENT_TYPE).iter();let first=values.next();
    if values.next().is_some(){return Err(());}
    first.map(|value|value.to_str().map_err(|_|())).transpose()
}
/// Parse retained bytes without network access. Authenticated reads project only
/// the fields needed for asset selection; offline reviewed originals remain intact.
pub fn parse_assets(body: &[u8], content_type: Option<&str>) -> Value {
    let assessment=assess_challenge_body(body,content_type,true);
    parse_assets_assessed(body,content_type,&assessment,false)
}
fn parse_assets_assessed(body: &[u8], content_type: Option<&str>,
    assessment: &ChallengeAssessment, authenticated: bool) -> Value {
    if !matches!(assessment,ChallengeAssessment::Clear) {
        return evidence(body,content_type,"response not admitted after challenge review",assessment,authenticated);
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(v) if !sensitive_value(&v) && v.get("results").and_then(Value::as_array).is_some_and(|a| a.iter().all(|x| x.get("id").and_then(Value::as_str).is_some_and(identifier) && x.get("name").is_some_and(Value::is_string) && x.get("hostname").is_some_and(Value::is_string))) => {
            let response=if authenticated {
                let results=v["results"].as_array().expect("validated results").iter().map(|item|json!({"id":item["id"],"name":item["name"],"hostname":item["hostname"]})).collect::<Vec<_>>();
                json!({"results":results})
            } else {v};
            json!({"result":"assets","response":response,"pagination":"only requested offset=0 limit=15; not a complete inventory"})
        },
        _ => evidence(body,content_type,"asset_shape_unknown",assessment,authenticated),
    }
}
/// One request, one lease; secrets are neither cached nor returned. The caller
/// must own stdin in a Zeroizing buffer. Reqwest's internal header copies cannot
/// be guaranteed to be zeroized by this module.
pub fn read_stdin(input: &str, online: bool) -> Result<Value, Error> {
    if !online { return Err(Error::new("offline", "OS lab network access requires explicit online authorization")); }
    let r = parse(input)?;
    let url = match &r.asset_id { Some(id) => format!("https://{HOST}/api/v1/perms/users/assets/{id}/system-users/?cache_policy=1"), None => format!("https://{HOST}/api/v1/perms/users/assets/?offset=0&limit=15&display=1&draw=1") };
    let client = reqwest::blocking::Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never()).timeout(std::time::Duration::from_secs(30)).build().map_err(|_| invalid())?;
    let g = Governor::open().map_err(|_| Error::new("governor_error","shared governor unavailable"))?;
    let cookie = Zeroizing::new(format!("csrftoken={}; sessionid={}",r.csrftoken.as_str(),r.sessionid.as_str()));
    let mut header = reqwest::header::HeaderValue::from_str(cookie.as_str()).map_err(|_| invalid())?;
    header.set_sensitive(true);
    drop(cookie);
    let mut lease = net::acquire(&g)?;
    let request=client.get(url).header(reqwest::header::COOKIE,header).timeout(std::time::Duration::from_secs(30));
    let response=match lease.start_request(||request.send()) {
        Ok(result)=>result,
        Err(FollowupError::Governor(_))=>return Err(Error::new("governor_error","cannot admit OS lab request; pending outcome retained")),
    };
    let mut response = match response {
        Ok(v) => v, Err(_) => { lease.finish(Outcome::NetworkFailure).map_err(|_|Error::new("governor_error","cannot persist OS lab request outcome"))?; return Err(Error::new("network_error","OS lab request failed")); }
    };
    let status = response.status().as_u16();
    let retry = response.headers().contains_key(reqwest::header::RETRY_AFTER);
    let retry_after=response.headers().get_all("retry-after").iter().find_map(|value|value.to_str().ok()).map(str::to_owned);
    let ct = response_content_type(response.headers());let mime_reviewed=ct.is_ok();let ct=ct.unwrap_or(None).map(str::to_owned);
    let header_challenge = response.headers().iter().any(|(k,v)|net::challenge_header(k.as_str(),v.as_bytes()));
    // A newly issued session cookie is a credential this client never
    // submitted and cannot revoke. Its value must never reach the caller.
    let issued_cookie = net::issues_session_cookie(response.headers());
    if lease.observe_http_many(status,response.headers().get_all("retry-after").iter().map(|value|value.to_str().ok()),header_challenge).is_err(){drop(response);return Err(Error::new("governor_error","cannot persist OS lab HTTP headers"));}
    let mut bytes = Vec::new();
    let read = response.by_ref().take(LIMIT+1).read_to_end(&mut bytes);
    let complete = read.is_ok() && bytes.len() as u64 <= LIMIT;
    let mut assessment = response_assessment(header_challenge,&bytes,ct.as_deref(),complete);
    if !mime_reviewed&&matches!(&assessment,ChallengeAssessment::Clear){assessment=ChallengeAssessment::Unreviewed;}
    // Cancel any unread body before making the shared lease available again.
    drop(response);
    let challenge = matches!(&assessment,ChallengeAssessment::Detected);
    // The complete admitted or refused result is computed while the original
    // lease is still held; the lease settles exactly once afterwards.
    let result = if matches!(status,401|403) || challenge {
        Err(response_refusal(status,retry,&assessment).expect("authentication refusal classified"))
    }
    else if read.is_err() { Err(Error::new("network_error","OS lab body read failed")) }
    else if bytes.len() as u64 > LIMIT { Err(Error::new("body_limit","OS lab body exceeds limit")) }
    else if let Some(error)=response_refusal(status,retry,&assessment) {Err(error)}
    // A response that issued a session cookie carries a credential this
    // client never submitted; its body is never projected.
    else { admit_body(&bytes,ct.as_deref(),&assessment,r.asset_id.is_none(),issued_cookie,&[r.csrftoken.as_str(),r.sessionid.as_str()]) };
    lease.finish(Outcome::Http {status,retry_after:retry_after.as_deref(),challenge,network_failure:!complete}).map_err(|_|Error::new("governor_error","cannot persist OS lab request outcome"))?;
    result
}

fn admit_body(bytes:&[u8],ct:Option<&str>,assessment:&ChallengeAssessment,assets:bool,issued_cookie:bool,secrets:&[&str])->Result<Value,Error>{
    if issued_cookie {return Err(Error::new("session_cookie_refused","OS lab response issued a session cookie; response withheld"));}
    let value=if assets {parse_assets_assessed(bytes,ct,assessment,true)} else {parse_system_users_assessed(bytes,ct,assessment)};
    release_response(value,secrets)
}
fn response_refusal(status:u16,retry:bool,assessment:&ChallengeAssessment)->Option<Error> {
    if status==401 {
        Some(Error::new("auth_latched","OS lab HTTP 401 authentication refusal; shared safety latched; no retry"))
    } else if status==403 {
        Some(Error::new("auth_latched","OS lab HTTP 403 authentication refusal; shared safety latched; no retry"))
    } else if matches!(assessment,ChallengeAssessment::Detected) {
        Some(Error::new("auth_latched","OS lab confirmed challenge; shared safety latched; no retry"))
    } else if status==429 {
        Some(Error::new("rate_limited","OS lab HTTP 429 rate limit; shared cooldown recorded; no retry"))
    } else if retry {
        Some(Error::new("rate_limited","OS lab Retry-After cooldown recorded; no retry"))
    } else if matches!(assessment,ChallengeAssessment::Unreviewed) {
        Some(Error::new("remote_refusal","OS lab response could not be safely reviewed; admission refused without retry"))
    } else if status!=200 {
        Some(Error::new("remote_refusal","OS lab HTTP refusal; no retry"))
    } else {None}
}

fn parse_system_users_assessed(bytes:&[u8],ct:Option<&str>,assessment:&ChallengeAssessment)->Value {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v) if matches!(assessment,ChallengeAssessment::Clear) && !sensitive_value(&v) && v.as_array().is_some_and(|a|a.iter().all(|x|x.get("id").and_then(Value::as_str).is_some_and(identifier)))=>{
            let users=v.as_array().expect("validated users").iter().map(|item|json!({"id":item["id"]})).collect::<Vec<_>>();
            json!({"result":"system_users","response":users})
        },
        _=>evidence(bytes,ct,"system_user_shape_unknown",assessment,true),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRequest {
    host:String, asset:String, system_user:String, local_port:u16,
    target_ipv4:std::net::Ipv4Addr, target_port:u16, repository:String, confirm:bool,
}
/// Local historical protocol description only; no helper, socket, SSH or Git is run.
pub fn connection_plan(input:&str)->Result<Value,Error> {
    require_object(input)?;
    let r:PlanRequest=serde_json::from_str(input).map_err(|_|invalid())?;
    if r.host!=HOST || !identifier(&r.asset) || !identifier(&r.system_user)
        || r.local_port==0 || r.target_port==0 || !identifier(&r.repository) || !r.confirm {return Err(invalid());}
    let mut connect=Vec::with_capacity(7);connect.push(0);connect.extend(r.target_ipv4.octets());connect.extend(r.target_port.to_le_bytes());
    Ok(json!({"result":"connection_plan","executed":false,"intent":"preview_os_lab_git_tunnel",
        "host":HOST,"asset_id":r.asset,"system_user_id":r.system_user,
        "listen":format!("127.0.0.1:{}",r.local_port),"target":format!("{}:{}",r.target_ipv4,r.target_port),
        "target_source":"caller_supplied_not_verified","target_exists":null,"authorization_verified":false,
        "deployment_verified":false,"native_jumpserver_smux":null,
        "historical_reference_uses_native_smux":false,
        "helper_installation_authorized":null,"helper_execution_authorized":null,"target_access_authorized":null,
        "confirmation_scope":"local preview only; confirm and caller-supplied target are not authorization evidence",
        "protocol_source":{"repository":"https://github.com/karin0/jumpserver-proxy","commit":"62c94e1187dbd4ded397f1e207bee3649bc98660","classification":"historical_remote_helper_protocol_not_current_deployment_contract"},
        "websocket":format!("wss://{HOST}/koko/ws/terminal/?target_id={}&type=asset&system_user_id={}",r.asset,r.system_user),
        "git_url":format!("ssh://git@127.0.0.1:{}/{}",r.local_port,r.repository),"tls_verification":true,
        "required_parameters":["separate current owner authorization for asset, system user, terminal and destination","separately authorized remote helper upload","separately authorized shell echo configuration, chmod and helper execution","helper startup synchronization: QAQ plus a 16-character synchronization token","historical helper-compatible hex transport and SMUX client; native Koko is not a SMUX server","reviewed bounded stream lifetime and shared governor policy","independent SSH host-key verification, SSH authentication, repository authorization and exact Git operation permission"],
        "envelope_fields":["data","id","type"],"terminal_types":["CONNECT","TERMINAL_INIT","TERMINAL_RESIZE","TERMINAL_DATA","PING"],
        "console_encoding":"historical helper channel: lowercase ASCII hex plus CR outbound; filter CR/LF and helper markers ! , ? before inbound hex decoding; synchronize before use",
        "smux_connect_bytes":connect,"smux_replies":{"connect_success":99,"connect_failure":1,"address_read_failure":2,"ping_command":1,"ping_reply":55,"exit_command":2,"exit_reply":66},
        "execution":"Not executed. Historical helper TCP success would not prove SSH authentication or Git access. Caller-supplied target, repository and IDs are syntax-checked only; current permissions, helper availability and deployment behavior remain unknown."}))
}
pub fn schema() -> Value {
    let identifier=json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"});
    let secret=json!({"type":"string","minLength":1,"maxLength":4096,"pattern":"^[A-Za-z0-9_-]+$","writeOnly":true});
    let read=json!({"type":"object","additionalProperties":false,"required":["host","csrftoken","sessionid"],"properties":{"host":{"const":HOST},"csrftoken":secret,"sessionid":secret,"asset_id":{"oneOf":[{"type":"null"},identifier]}}});
    let plan=json!({"type":"object","additionalProperties":false,"required":["host","asset","system_user","local_port","target_ipv4","target_port","repository","confirm"],"properties":{"host":{"const":HOST},"asset":identifier,"system_user":identifier,"local_port":{"type":"integer","minimum":1,"maximum":65535},"target_ipv4":{"type":"string","format":"ipv4","pattern":"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"},"target_port":{"type":"integer","minimum":1,"maximum":65535},"repository":identifier,"confirm":{"const":true}}});
    let read_output=json!({"oneOf":[{"type":"object","required":["result","response"],"properties":{"result":{"enum":["assets","system_users"]}}},{"type":"object","required":["result","raw_base64","content_type","byte_count","sha256","fallback_reason","raw_withheld","raw_provenance"],"properties":{"result":{"const":"fallback"},"raw_base64":{"type":["string","null"],"contentEncoding":"base64"},"content_type":{"enum":[null,"application/json","text/html","text/plain","application/octet-stream"]},"byte_count":{"type":"integer","minimum":0},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"raw_withheld":{"type":"boolean"}}}]});
    let plan_output=json!({"type":"object","required":["result","executed","intent","host","asset_id","system_user_id","listen","target","websocket","git_url","tls_verification","required_parameters","envelope_fields","terminal_types","console_encoding","smux_connect_bytes","smux_replies","execution"],"properties":{"result":{"const":"connection_plan"},"executed":{"const":false},"intent":{"const":"preview_os_lab_git_tunnel"},"host":{"const":HOST},"asset_id":identifier,"system_user_id":identifier,"tls_verification":{"const":true},"smux_connect_bytes":{"type":"array","minItems":7,"maxItems":7,"items":{"type":"integer","minimum":0,"maximum":255}}}});
    let mut plan_output=plan_output;
    for field in ["target_source","target_exists","authorization_verified","deployment_verified","native_jumpserver_smux","historical_reference_uses_native_smux","protocol_source","helper_installation_authorized","helper_execution_authorized","target_access_authorized","confirmation_scope"] {
        plan_output["required"].as_array_mut().expect("schema required array").push(json!(field));
    }
    plan_output["properties"]["target_source"]=json!({"const":"caller_supplied_not_verified"});
    plan_output["properties"]["target_exists"]=json!({"const":null});
    for field in ["helper_installation_authorized","helper_execution_authorized","target_access_authorized"] {plan_output["properties"][field]=json!({"const":null});}
    plan_output["properties"]["confirmation_scope"]=json!({"const":"local preview only; confirm and caller-supplied target are not authorization evidence"});
    plan_output["properties"]["native_jumpserver_smux"]=json!({"const":null});
    for field in ["authorization_verified","deployment_verified","historical_reference_uses_native_smux"] {plan_output["properties"][field]=json!({"const":false});}
    json!({"input":{"oneOf":[read,plan]},"output":{"oneOf":[read_output,plan_output]},"operations":{"read":{"input":read,"output":read_output,"online_required":true},"plan":{"input":plan,"output":plan_output,"requests_performed":0,"executed":false}}})
}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn header_map_preserves_retry_values_and_refuses_ambiguous_mime(){
  use reqwest::header::{HeaderMap,HeaderValue,CONTENT_TYPE,RETRY_AFTER};
  let mut headers=HeaderMap::new();headers.append(CONTENT_TYPE,HeaderValue::from_static("application/json"));
  assert_eq!(response_content_type(&headers),Ok(Some("application/json")));
  headers.append(CONTENT_TYPE,HeaderValue::from_static("text/html"));assert!(response_content_type(&headers).is_err());
  headers.remove(CONTENT_TYPE);headers.append(CONTENT_TYPE,HeaderValue::from_bytes(&[0xff]).unwrap());assert!(response_content_type(&headers).is_err());
  headers.append(RETRY_AFTER,HeaderValue::from_static("0"));headers.append(RETRY_AFTER,HeaderValue::from_static("1800"));headers.append(RETRY_AFTER,HeaderValue::from_bytes(&[0xff]).unwrap());
  assert_eq!(headers.get_all("retry-after").iter().map(|v|v.to_str().ok()).collect::<Vec<_>>(),vec![Some("0"),Some("1800"),None]);
 }

 #[test] fn assets_fixture(){assert_eq!(parse_assets(br#"{"results":[{"id":"a","name":"n","hostname":"h"}]}"#,Some("application/json"))["result"],"assets");assert!(parse_assets(b"html",None)["content_type"].is_null());}
 #[test] fn rejects_secrets_and_hosts(){assert!(parse(r#"{"host":"evil","csrftoken":"x","sessionid":"y"}"#).is_err());assert!(parse(r#"{"host":"buaaos.studio","csrftoken":"x"}"#).is_err());}
 #[test] fn positional_secret_arrays_are_rejected_without_echo(){
  let input=r#" ["buaaos.studio","synthetic_private_csrf","synthetic_private_session",null]"#;
  let error=match parse(input){Ok(_)=>panic!("positional read input admitted"),Err(error)=>error};
  assert_eq!(error.code,"invalid_input");
  let rendered=format!("{error:?}");
  assert!(!rendered.contains("synthetic_private"));
  let error=read_stdin(input,true).unwrap_err();assert_eq!(error.code,"invalid_input");
  assert!(parse(" \t\r\n{\"host\":\"buaaos.studio\",\"csrftoken\":\"synthetic_csrf\",\"sessionid\":\"synthetic_session\"}").is_ok());
  let error=connection_plan(r#" ["buaaos.studio","a","u",2222,"192.0.2.7",22,"synthetic_private_repo",true]"#).unwrap_err();
  assert_eq!(error.code,"invalid_input");assert!(!format!("{error:?}").contains("synthetic_private"));
  assert!(connection_plan(&format!(" \t\r\n{}",plan_input())).is_ok());
 }
 #[test] fn offline_rejects_before_parsing(){assert_eq!(read_stdin("not json",false).unwrap_err().code,"offline");}
 #[test] fn json_challenge_prose_preserves_safe_raw_source(){
  let body=br#"{"message":"CAPTCHA documentation"}"#;
  assert!(matches!(response_assessment(false,body,Some("application/json"),true),ChallengeAssessment::Clear));
  let result=parse_assets(body,Some("application/json"));
  assert_eq!(STANDARD.decode(result["raw_base64"].as_str().unwrap()).unwrap(),body);
 }
 #[test] fn challenge_and_secret_fallbacks_withhold_raw(){
  for (body,ct) in [(b"<input name='captcha'>".as_slice(),"text/html"),(br#"{"sessionid":"private_value"}"#.as_slice(),"application/json")] {
   let result=parse_assets(body,Some(ct));
   assert_eq!(result["result"],"fallback");assert!(result["raw_base64"].is_null());
   assert!(!result.to_string().contains("private_value"));
  }
 }
 #[test] fn authenticated_unknown_response_never_returns_raw_echo(){
  let result=parse_assets_assessed(br#"{"unrelated":"private_value"}"#,Some("application/json"),&ChallengeAssessment::Clear,true);
  assert!(result["raw_base64"].is_null());assert_eq!(result["raw_withheld"],true);
  assert!(!result.to_string().contains("private_value"));assert!(result["sha256"].is_string());
 }
 #[test] fn incomplete_review_preserves_header_detection(){
  assert!(matches!(response_assessment(false,b"<html>",Some("text/html"),false),ChallengeAssessment::Unreviewed));
  assert!(matches!(response_assessment(true,&[0xff],None,false),ChallengeAssessment::Detected));
 }
 #[test] fn decoded_credentials_are_withheld_in_both_success_shapes(){
  let assets=parse_assets(br#"{"results":[],"\u0073essionid":"private_value"}"#,Some("application/json; sessionid=private_value"));
  assert_eq!(assets["result"],"fallback");assert!(assets["raw_base64"].is_null());
  assert_eq!(assets["content_type"],"application/json");assert!(!assets.to_string().contains("private_value"));
  let users=parse_system_users_assessed(br#"[{"id":"u","\u0074oken":"private_value"}]"#,Some("application/json"),&ChallengeAssessment::Clear);
  assert_eq!(users["result"],"fallback");assert!(!users.to_string().contains("private_value"));
 }
 #[test] fn submitted_values_are_checked_after_json_decoding(){
  let decoded:Value=serde_json::from_slice(br#"{"result":"assets","response":{"results":[],"other":"\u0070rivate_value"}}"#).unwrap();
  assert!(release_response(decoded,&["private_value"]).is_err());
  for value in [json!({"result":"assets","response":{"results":[],"other":"private_value"}}),json!({"result":"system_users","response":[{"id":"u","name":"private_value"}]})] {
   assert!(release_response(value,&["private_value","other_credential"]).is_err());
  }
  assert!(release_response(json!({"content_type":"application/json"}),&["json"]).is_err());
  let safe=parse_assets(br#"{"results":[],"message":"ordinary data"}"#,Some("application/json"));
  assert_eq!(release_response(safe,&["private_value"]).unwrap()["result"],"assets");
 }
 #[test] fn duplicate_json_members_do_not_hide_early_secrets(){
  let result=parse_assets(br#"{"x":{"\u0074oken":"private_value"},"x":0}"#,Some("application/json"));
  assert!(result["raw_base64"].is_null());assert!(!result.to_string().contains("private_value"));
  let safe=br#"{"x":1,"x":0}"#;let result=parse_assets(safe,Some("application/json"));
  assert_eq!(STANDARD.decode(result["raw_base64"].as_str().unwrap()).unwrap(),safe);
 }
 #[test] fn bearer_and_escaped_credential_successes_are_withheld(){
  for key in ["bearer","jwt","nonce","loginname","login_name"] {
   let result=parse_assets(json!({"results":[],(key):"synthetic_private"}).to_string().as_bytes(),Some("application/json"));
   assert_eq!(result["result"],"fallback");assert!(result["raw_base64"].is_null());assert!(!result.to_string().contains("synthetic_private"));
   let result=parse_system_users_assessed(json!([{"id":"u",(key):"synthetic_private"}]).to_string().as_bytes(),Some("application/json"),&ChallengeAssessment::Clear);
   assert_eq!(result["result"],"fallback");assert!(result["raw_base64"].is_null());
  }
 }
 #[test] fn safe_unicode_json_preserves_original_but_escaped_token_is_withheld(){
  let safe=br#"{"title":"\u4e2d"}"#;let result=parse_assets(safe,Some("application/json"));
  assert_eq!(STANDARD.decode(result["raw_base64"].as_str().unwrap()).unwrap(),safe);
  let result=parse_assets(br#"{"\u0074oken":"private_value"}"#,Some("application/json"));
  assert!(result["raw_base64"].is_null());assert!(!result.to_string().contains("private_value"));
 }
 #[test] fn authentication_refusal_and_challenge_report_latched_not_unavailable(){
  for status in [401,403] {
   let error=response_refusal(status,false,&ChallengeAssessment::Clear).unwrap();assert_eq!(error.code,"auth_latched");
   let text=format!("{error:?}");assert!(text.contains(&status.to_string()));assert!(!text.contains("CAPTCHA"));assert!(!text.contains("confirmed challenge"));
  }
  assert_eq!(response_refusal(200,false,&ChallengeAssessment::Detected).unwrap().code,"auth_latched");
  assert_eq!(response_refusal(500,false,&ChallengeAssessment::Clear).unwrap().code,"remote_refusal");
  assert_eq!(response_refusal(200,true,&ChallengeAssessment::Clear).unwrap().code,"rate_limited");
  assert_eq!(response_refusal(429,false,&ChallengeAssessment::Unreviewed).unwrap().code,"rate_limited");
  assert_eq!(response_refusal(200,false,&ChallengeAssessment::Unreviewed).unwrap().code,"remote_refusal");
  assert!(response_refusal(200,false,&ChallengeAssessment::Clear).is_none());
 }
 #[test] fn authenticated_projection_drops_extra_fields_and_encoded_secrets(){
  let assets=parse_assets_assessed(br#"{"results":[{"id":"a","name":"safe","hostname":"host","extra":"YWJjMTIz"}],"extra":"YWJjMTIz"}"#,Some("application/json"),&ChallengeAssessment::Clear,true);
  assert_eq!(assets["result"],"assets");assert!(!assets.to_string().contains("YWJjMTIz"));
  let users=parse_system_users_assessed(br#"[{"id":"u","extra":"YWJjMTIz"}]"#,Some("application/json"),&ChallengeAssessment::Clear);
  assert_eq!(users["result"],"system_users");assert!(!users.to_string().contains("YWJjMTIz"));
  let encoded=parse_assets_assessed(br#"{"results":[{"id":"a","name":"YWJjMTIz","hostname":"host"}]}"#,Some("application/json"),&ChallengeAssessment::Clear,true);
  assert_eq!(release_response(encoded,&["abc123"]).unwrap_err().code,"unsafe_response");
  let safe=parse_assets_assessed(br#"{"results":[{"id":"a","name":"safe","hostname":"host"}]}"#,Some("application/json"),&ChallengeAssessment::Clear,true);
  assert_eq!(release_response(safe,&["abc123"]).unwrap()["result"],"assets");
 }
 #[test] fn reversible_credential_encodings_and_issued_cookie_are_detected(){
  for (assets,body) in [(true,br#"{"results":[{"id":"a","name":"freshopaque123","hostname":"h"}]}"#.as_slice()),(false,br#"[{"id":"u","name":"freshopaque123"}]"#.as_slice())] {
   let error=admit_body(body,Some("application/json"),&ChallengeAssessment::Clear,assets,true,&["abc_123"]).unwrap_err();
   assert_eq!(error.code,"session_cookie_refused");
   assert_eq!(error.message,"OS lab response issued a session cookie; response withheld");
   let safe=admit_body(body,Some("application/json"),&ChallengeAssessment::Clear,assets,false,&["abc_123"]).unwrap();
   assert_eq!(safe["result"],if assets {"assets"} else {"system_users"});
   if assets {assert_eq!(safe["response"]["results"][0]["name"],"freshopaque123");}
   else {assert_eq!(safe["response"],json!([{"id":"u"}]));}
  }
  for encoded in ["%61%62%63%5F%31%32%33","YWJjXzEyMw=="] {
   let body=json!({"results":[{"id":"a","name":encoded,"hostname":"h"}]});
   let error=admit_body(&serde_json::to_vec(&body).unwrap(),Some("application/json"),&ChallengeAssessment::Clear,true,false,&["abc_123"]).unwrap_err();
   assert_eq!(error.code,"unsafe_response");
   assert_eq!(error.message,"OS lab response withheld because it echoes submitted credentials");
   for assets in [true,false] {
    let body=if assets {json!({"results":[{"id":"a","name":"safe","hostname":"h","extra":encoded}],"extra":encoded})} else {json!([{"id":"u","name":"safe","extra":encoded}])};
    let safe=admit_body(&serde_json::to_vec(&body).unwrap(),Some("application/json"),&ChallengeAssessment::Clear,assets,false,&["abc_123"]).unwrap();
    assert_eq!(safe["result"],if assets {"assets"} else {"system_users"});
    assert!(!safe.to_string().contains(encoded));
   }
  }
  let error=admit_body(br#"[{"id":"YWJjXzEyMw"}]"#,Some("application/json"),&ChallengeAssessment::Clear,false,false,&["abc_123"]).unwrap_err();
  assert_eq!(error.code,"unsafe_response");
 }
 fn plan_input()->Value {json!({"host":HOST,"asset":"a","system_user":"u","local_port":2222,"target_ipv4":"192.0.2.7","target_port":22,"repository":"reviewed_repo","confirm":true})}
 #[test] fn port_bounds_and_caller_bound_target(){
  let mut input=plan_input();input["local_port"]=json!(0);assert!(connection_plan(&input.to_string()).is_err());
  input["local_port"]=json!(65535);input["target_port"]=json!(65535);
  let p=connection_plan(&input.to_string()).unwrap();assert_eq!(p["smux_connect_bytes"],json!([0,192,0,2,7,255,255]));
  assert_eq!(p["target"],"192.0.2.7:65535");assert_eq!(p["target_source"],"caller_supplied_not_verified");
  assert_eq!(p["authorization_verified"],false);assert!(p["native_jumpserver_smux"].is_null());
  assert_eq!(p["historical_reference_uses_native_smux"],false);
  assert_eq!(p["intent"],"preview_os_lab_git_tunnel");
  for field in ["helper_installation_authorized","helper_execution_authorized","target_access_authorized"] {assert!(p[field].is_null());}
  assert!(p["target_exists"].is_null());assert!(p["required_parameters"].to_string().contains("upload"));
  input["extra"]=json!(true);assert!(connection_plan(&input.to_string()).is_err());
  input.as_object_mut().unwrap().remove("extra");input.as_object_mut().unwrap().remove("target_ipv4");assert!(connection_plan(&input.to_string()).is_err());
 }
 #[test] fn schema_covers_read_and_credential_free_plan(){
  let schema=schema();let read=&schema["operations"]["read"];let plan=&schema["operations"]["plan"];
  assert_eq!(read["online_required"],true);assert_eq!(read["input"]["additionalProperties"],false);
  assert_eq!(plan["input"]["additionalProperties"],false);
  assert_eq!(plan["input"]["required"],json!(["host","asset","system_user","local_port","target_ipv4","target_port","repository","confirm"]));
  assert!(plan["input"]["properties"].get("sessionid").is_none());
  let output=connection_plan(&plan_input().to_string()).unwrap();
  for field in plan["output"]["required"].as_array().unwrap(){assert!(output.get(field.as_str().unwrap()).is_some());}
  assert_eq!(plan["output"]["properties"]["result"]["const"],output["result"]);
  assert_eq!(plan["output"]["properties"]["smux_connect_bytes"]["minItems"],output["smux_connect_bytes"].as_array().unwrap().len());
 }
}
