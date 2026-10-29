//! Coursegrading contract admission. HTTP-only upstream writes remain blocked.
//! A reachable HTTPS login page alone does not prove equivalent authentication,
//! submission, or result semantics; no password or submission is transmitted here.
use crate::{governor::{FollowupError, Governor, Outcome}, net::{self, Error}};
use crate::html::{ChallengeAssessment, assess_challenge_body};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet, io::Read, path::Path};
use std::os::unix::fs::MetadataExt;

const HTTPS: &str = "https://judge.buaa.edu.cn";
fn invalid() -> Error { Error::new("invalid_input","coursegrading requires explicit identifiers and a regular source file") }
fn id(s:&str)->bool { !s.is_empty() && s.len() <= 128 && s.bytes().all(|b|b.is_ascii_alphanumeric() || matches!(b,b'_'|b'-')) }
fn hash(b:&[u8])->String {format!("{:x}",Sha256::digest(b))}
fn sensitive_echo(b:&[u8])->bool {
 if let Ok(v)=serde_json::from_slice::<JsonPrivacy>(b){return v.0;}
 sensitive_text(b)
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
fn sensitive_value(v:&Value)->bool {
 match v {Value::Object(o)=>o.iter().any(|(k,v)|sensitive_text(k.as_bytes())||sensitive_value(v)),Value::Array(a)=>a.iter().any(sensitive_value),Value::String(s)=>sensitive_text(s.as_bytes()),_=>false}
}
fn safe_content_type(ct:Option<&str>)->Option<&'static str>{
 match ct?.split(';').next()?.trim(){
  v if v.eq_ignore_ascii_case("application/json")=>Some("application/json"),
  v if v.eq_ignore_ascii_case("text/html")=>Some("text/html"),
  v if v.eq_ignore_ascii_case("text/plain")=>Some("text/plain"),
  v if v.eq_ignore_ascii_case("application/octet-stream")=>Some("application/octet-stream"),_=>None}
}
fn sensitive_text(b:&[u8])->bool {
 const MARKERS:&[&[u8]]=&[b"session",b"cookie",b"token",b"ticket",b"authorization",b"credential",b"password",b"passwd",b"secret",b"csrf",b"execution",b"<input",b"<form",b"bearer",b"jwt",b"nonce",b"loginname",b"login_name",b"\\u",b"\\x",b"&#"];
 MARKERS.iter().any(|m|b.windows(m.len()).any(|w|w.eq_ignore_ascii_case(m)))
}
fn evidence(b:&[u8],ct:Option<&str>,reason:&str,assessment:&ChallengeAssessment,session_cookie:bool)->Value {
 // Without a cookie jar, a Set-Cookie response cannot be safely exported:
 // the original body may echo newly issued session material.
 let retain=matches!(assessment,ChallengeAssessment::Clear)&&!sensitive_echo(b)&&!session_cookie;
 let reason=if session_cookie {"session_cookie_issued"} else {reason};
 json!({"raw_base64":retain.then(||STANDARD.encode(b)),"content_type":safe_content_type(ct),"byte_count":b.len(),"sha256":hash(b),"fallback_reason":reason,"raw_withheld":!retain,"raw_provenance":if retain {"original_response"} else {"withheld_unsafe_or_unreviewed_response"}})
}
fn response_assessment(header_challenge:bool,b:&[u8],ct:Option<&str>,complete:bool)->ChallengeAssessment {
 if header_challenge {ChallengeAssessment::Detected} else {assess_challenge_body(b,ct,complete)}
}
fn response_content_type(headers:&reqwest::header::HeaderMap)->Result<Option<&str>,()> {
 let mut values=headers.get_all(reqwest::header::CONTENT_TYPE).iter();let first=values.next();
 if values.next().is_some(){return Err(());}
 first.map(|value|value.to_str().map_err(|_|())).transpose()
}
pub fn unsupported()->Value {json!({"result":"unsupported","reason":"Only HTTP upstream is source-established. HTTPS equivalence is not established; HTTP fallback and all authentication/submission are disabled.","https_candidate":HTTPS,"course_enumeration":"UNKNOWN","assignment_html_fields":"UNKNOWN","requests_performed":0})}

/// Explicit, single-shot HTTPS observation. Never redirects or falls back to HTTP.
pub fn probe_https(online:bool)->Result<Value,Error> {
 if !online{return Err(Error::new("offline","HTTPS probe requires explicit online authorization"));}
 let client=reqwest::blocking::Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never()).timeout(std::time::Duration::from_secs(30)).build().map_err(|_|invalid())?;
 let g=Governor::open().map_err(|_|Error::new("governor_error","shared governor unavailable"))?;
 let mut lease=net::acquire(&g)?;
 let request=client.get(format!("{HTTPS}/indexcs/simple.jsp?loginErr=0")).timeout(std::time::Duration::from_secs(30));
 let response=match lease.start_request(||request.send()){
  Ok(result)=>result,
  Err(FollowupError::CachedChallenge)=>{lease.finish(Outcome::SafetyObserved).map_err(|_|Error::new("governor_error","cannot persist observed shared safety latch"))?;return Err(Error::new("auth_latched","shared safety latch observed before coursegrading request; no request sent"));},
  Err(FollowupError::Governor(_))=>return Err(Error::new("governor_error","cannot admit coursegrading request; pending outcome retained")),
 };
 let mut response=match response{Ok(v)=>v,Err(_)=>{lease.finish(Outcome::NetworkFailure).map_err(|_|Error::new("governor_error","cannot persist coursegrading request outcome"))?;return Ok(json!({"result":"unsupported","reason":"HTTPS candidate unavailable or TLS validation failed; no HTTP fallback","requests_performed":1}));}};
 let status=response.status().as_u16();
 let ct=response_content_type(response.headers());let mime_reviewed=ct.is_ok();let ct=ct.unwrap_or(None).map(str::to_owned);
 let header_challenge=response.headers().iter().any(|(k,v)|net::challenge_header(k.as_str(),v.as_bytes()));
 let retry_after=response.headers().get_all("retry-after").iter().find_map(|value|value.to_str().ok()).map(str::to_owned);
 // This probe does not maintain a cookie jar; no Set-Cookie body is exported.
 let session_cookie=net::issues_session_cookie(response.headers());
 if lease.observe_http_many(status,response.headers().get_all("retry-after").iter().map(|value|value.to_str().ok()),header_challenge).is_err(){drop(response);return Err(Error::new("governor_error","cannot persist coursegrading HTTP headers"));}
 let mut b=Vec::new();let read=response.by_ref().take(4*1024*1024+1).read_to_end(&mut b);
 let complete=read.is_ok()&&b.len()<=4*1024*1024;
 let mut assessment=response_assessment(header_challenge,&b,ct.as_deref(),complete);
 if !mime_reviewed&&matches!(&assessment,ChallengeAssessment::Clear){assessment=ChallengeAssessment::Unreviewed;}
 // Cancel any unread body before releasing the original shared lease.
 drop(response);
 let challenge=matches!(&assessment,ChallengeAssessment::Detected);
 // The complete admitted or refused result is computed while the original
 // lease is still held; the lease settles exactly once, whatever the result.
 let result=(||{
  if let Some(rejection)=observed_safety_rejection(status,challenge,complete){return Ok(rejection);}
  if read.is_err(){return Err(Error::new("network_error","HTTPS response body failed"));}
  if b.len()>4*1024*1024{return Err(Error::new("body_limit","HTTPS response exceeds limit"));}
  let reason=match &assessment {
   ChallengeAssessment::Clear=>"HTTPS application equivalence remains unverified; no authentication or submission enabled",
   ChallengeAssessment::Detected=>"Confirmed authentication challenge requires human review; no authentication, submission, or automatic retry enabled",
   ChallengeAssessment::Unreviewed=>"Response body could not be safely reviewed; admission refused and no automatic retry enabled",
  };
  Ok(json!({"result":"blocked","https_status":status,"https_page_reachable":status==200 && matches!(&assessment,ChallengeAssessment::Clear),"reason":reason,"evidence":evidence(&b,ct.as_deref(),"login_page_fields_unknown",&assessment,session_cookie)}))
 })();
 lease.finish(Outcome::Http{status,retry_after:retry_after.as_deref(),challenge,network_failure:!complete}).map_err(|_|Error::new("governor_error","cannot persist coursegrading request outcome"))?;
 result
}
fn observed_safety_rejection(status:u16,challenge:bool,complete:bool)->Option<Value>{
 if matches!(status,401|403){Some(json!({"result":"blocked","https_status":status,"https_page_reachable":false,"reason":"HTTP authentication refused; shared safety latched; no automatic retry","body_complete":complete}))}
 else if challenge {Some(json!({"result":"blocked","https_status":status,"https_page_reachable":false,"reason":"confirmed challenge requires human review; shared safety latched; no automatic retry","body_complete":complete}))}
 else {None}
}

#[derive(Clone,Debug,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct SubmissionPreview { pub intent:String,pub course_id:String,pub assignment_id:String,pub problem_id:String,pub local_file:String,pub byte_count:u64,pub sha256:String }
fn validate_preview(p:&SubmissionPreview)->Result<(),Error>{
 if p.intent!="submit_coursegrading_file"||!id(&p.course_id)||!id(&p.assignment_id)||!id(&p.problem_id)||p.byte_count>16*1024*1024||p.sha256.len()!=64||!p.sha256.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err(invalid());}
 Ok(())
}
// Match replay's local-file policy: descriptor-relative traversal without
// symlinks, caller-owned final parent and file, neither group/world writable.
// This does not prevent an authorized writer modifying an inode in place.
fn open_source(path:&Path)->Result<std::fs::File,Error>{
 let name=path.file_name().and_then(|s|s.to_str()).filter(|s|!s.is_empty()&&*s!="."&&*s!="..").ok_or_else(invalid)?;
 let parent=path.parent().filter(|p|!p.as_os_str().is_empty()).ok_or_else(invalid)?;
 let directory=crate::governor::open_directory(parent,false,false).map_err(|_|invalid())?;
 let dm=directory.metadata().map_err(|_|invalid())?;
 // SAFETY: geteuid has no preconditions.
 let uid=unsafe{libc::geteuid()};
 if !dm.is_dir()||dm.uid()!=uid||dm.mode()&0o022!=0{return Err(Error::new("permission","unsafe submission file parent"));}
 let f=crate::governor::open_child(&directory,name,libc::O_RDONLY).map_err(|_|invalid())?;
 let m=f.metadata().map_err(|_|invalid())?;
 if !m.is_file()||m.uid()!=uid||m.mode()&0o022!=0{return Err(Error::new("permission","unsafe submission file"));}
 if m.len()>16*1024*1024{return Err(invalid());}
 Ok(f)
}
/// Pure local immutable preview. Neither the contents nor password enter receipts.
pub fn preview(course:&str,assignment:&str,problem:&str,file:&Path)->Result<SubmissionPreview,Error>{
 if !id(course)||!id(assignment)||!id(problem){return Err(invalid());}
 let mut f=open_source(file)?;
 let mut bytes=Vec::new();f.by_ref().take(16*1024*1024+1).read_to_end(&mut bytes).map_err(|_|invalid())?;
 if bytes.len()>16*1024*1024{return Err(invalid());}
 Ok(SubmissionPreview{intent:"submit_coursegrading_file".into(),course_id:course.into(),assignment_id:assignment.into(),problem_id:problem.into(),local_file:file.to_str().ok_or_else(invalid)?.into(),byte_count:bytes.len() as u64,sha256:hash(&bytes)})
}
/// Build a candidate multipart part only after exact preview/content confirmation.
/// This is not a submission and performs no remote request.
pub fn multipart_part(p:&SubmissionPreview,bytes:Vec<u8>,confirmed_sha256:&str)->Result<(String,Vec<u8>),Error>{
 validate_preview(p)?;
 if p.sha256!=confirmed_sha256||bytes.len() as u64!=p.byte_count||hash(&bytes)!=p.sha256{return Err(invalid());}
 let boundary=format!("buaa-{}",p.sha256);
 if bytes.windows(boundary.len()).any(|w|w==boundary.as_bytes()){return Err(Error::new("multipart_boundary_collision","source collides with multipart boundary"));}
 let mut body=format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"submission\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
 body.extend_from_slice(&bytes);body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
 Ok((format!("multipart/form-data; boundary={boundary}"),body))
}
/// Local duplicate admission for a caller-owned durable ledger. The caller must
/// persist the returned key atomically BEFORE any future enabled POST, including
/// uncertain outcomes. No network write is currently enabled by this module.
pub fn admit_submission(p:&SubmissionPreview,previous:&BTreeSet<String>,reconfirm:bool)->Result<String,Error>{
 validate_preview(p)?;
 let key=hash(&serde_json::to_vec(&(&p.course_id,&p.assignment_id,&p.problem_id,&p.sha256)).map_err(|_|invalid())?);
 if previous.contains(&key)&&!reconfirm{return Err(Error::new("duplicate_submission","explicit reconfirmation required for duplicate submission"));}Ok(key)
}
/// Offline parsing only. HTTP 200 is never considered submission success.
pub fn parse_status(bytes:&[u8],ct:Option<&str>)->Value {
 let assessment=assess_challenge_body(bytes,ct,true);
 if !matches!(&assessment,ChallengeAssessment::Clear) {
  return json!({"result":"fallback","evidence":evidence(bytes,ct,"response not admitted after challenge review",&assessment,false)});
 }
 match serde_json::from_slice::<Value>(bytes){
 Ok(v) if !sensitive_value(&v) && v.as_array().is_some_and(|a|a.len()>=2 && a[0].get("ret").is_some_and(Value::is_string) && a[1].get("content").is_some_and(Value::is_string))=>json!({"result":"judging_status","finished":v[0]["ret"]=="1","result_html":v[1]["content"],"html_trust":"untrusted_data","submission_success":null}),
 _=>json!({"result":"fallback","evidence":evidence(bytes,ct,"judging_status_shape_unknown",&assessment,false)}) }
}
pub fn schema()->Value {
 let preview=json!({"type":"object","additionalProperties":false,"required":["intent","course_id","assignment_id","problem_id","local_file","byte_count","sha256"],"properties":{"intent":{"const":"submit_coursegrading_file"},"course_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"assignment_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"problem_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"local_file":{"type":"string"},"byte_count":{"type":"integer","minimum":0,"maximum":16777216},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"}}});
 json!({"preview":preview,"output":{"oneOf":[preview,{"type":"object","required":["result","reason"],"properties":{"result":{"enum":["unsupported","blocked"]}}},{"type":"object","required":["result","finished","result_html","submission_success"],"properties":{"result":{"const":"judging_status"}}},{"type":"object","required":["result","evidence"],"properties":{"result":{"const":"fallback"}}}]},"unknown":["HTTPS application equivalence","course enumeration","assignment HTML fields"],"writes_enabled":false})
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

 fn p()->SubmissionPreview{SubmissionPreview{intent:"submit_coursegrading_file".into(),course_id:"c".into(),assignment_id:"a".into(),problem_id:"p".into(),local_file:"source.c".into(),byte_count:3,sha256:hash(b"abc")}}
 #[test] fn preview_receipt_is_a_schema_output_alternative(){
  let schema=schema();assert_eq!(schema["output"]["oneOf"][0],schema["preview"]);
  let preview=serde_json::to_value(p()).unwrap();for field in schema["preview"]["required"].as_array().unwrap(){assert!(preview.get(field.as_str().unwrap()).is_some());}
 }
 #[test] fn observed_authentication_refusal_survives_incomplete_body(){
  for status in [401,403]{let result=observed_safety_rejection(status,false,false).unwrap();assert_eq!(result["https_status"],status);assert_eq!(result["body_complete"],false);assert!(!result["reason"].as_str().unwrap().contains("challenge"));}
  let result=observed_safety_rejection(200,true,false).unwrap();assert_eq!(result["body_complete"],false);assert!(result["reason"].as_str().unwrap().contains("challenge"));
 }
 #[test] fn multipart_and_digest(){let p=p();let (ct,body)=multipart_part(&p,b"abc".to_vec(),&p.sha256).unwrap();assert!(ct.starts_with("multipart/form-data; boundary="));assert!(String::from_utf8(body).unwrap().contains("name=\"file\""));assert!(multipart_part(&p,b"bad".to_vec(),&p.sha256).is_err());}
 #[test] fn duplicate_rejected(){let p=p();let mut ledger=BTreeSet::new();ledger.insert(admit_submission(&p,&ledger,false).unwrap());assert!(admit_submission(&p,&ledger,false).is_err());assert!(admit_submission(&p,&ledger,true).is_ok());}
 #[test] fn status_and_http_block(){assert_eq!(parse_status(br#"[{"ret":"1"},{"content":"accepted"}]"#,Some("application/json"))["finished"],true);assert_eq!(unsupported()["result"],"unsupported");assert!(parse_status(b"broken",None)["evidence"]["content_type"].is_null());}
 #[test] fn offline_probe(){assert_eq!(probe_https(false).unwrap_err().code,"offline");}
 #[test] fn json_challenge_prose_preserves_safe_raw_source(){
  let body=br#"{"message":"CAPTCHA documentation"}"#;
  assert!(matches!(response_assessment(false,body,Some("application/json"),true),ChallengeAssessment::Clear));
  let result=parse_status(body,Some("application/json"));
  assert_eq!(STANDARD.decode(result["evidence"]["raw_base64"].as_str().unwrap()).unwrap(),body);
 }
 #[test] fn challenge_and_secret_fallbacks_withhold_raw(){
  for (body,ct) in [(b"<input name='captcha'>".as_slice(),"text/html"),(br#"{"sessionid":"private_value"}"#.as_slice(),"application/json")] {
   let result=parse_status(body,Some(ct));
   assert_eq!(result["result"],"fallback");assert!(result["evidence"]["raw_base64"].is_null());
   assert!(!result.to_string().contains("private_value"));
  }
 }
 #[test] fn issued_session_cookie_withholds_original_evidence(){
  let body=b"freshopaque123";let mime=Some("text/plain");
  let assessment=assess_challenge_body(body,mime,true);
  let withheld=evidence(body,mime,"login_page_fields_unknown",&assessment,true);
  assert!(withheld["raw_base64"].is_null());assert_eq!(withheld["raw_withheld"],true);
  assert_eq!(withheld["fallback_reason"],"session_cookie_issued");
  assert_eq!(withheld["byte_count"],body.len());assert_eq!(withheld["sha256"],hash(body));
  let retained=evidence(body,mime,"login_page_fields_unknown",&assessment,false);
  assert_eq!(retained["raw_base64"],"ZnJlc2hvcGFxdWUxMjM=");assert_eq!(retained["raw_withheld"],false);
 }
 #[test] fn incomplete_review_preserves_header_detection(){
  assert!(matches!(response_assessment(false,b"<html>",Some("text/html"),false),ChallengeAssessment::Unreviewed));
  assert!(matches!(response_assessment(true,&[0xff],None,false),ChallengeAssessment::Detected));
  let result=evidence(b"private body",None,"incomplete",&ChallengeAssessment::Unreviewed,false);
  assert!(result["raw_base64"].is_null());assert_eq!(result["byte_count"],12);
 }
 #[test] fn decoded_credentials_and_mime_parameters_are_withheld(){
  let result=parse_status(br#"{"\u0074oken":"private_value"}"#,Some("application/json; sessionid=private_value"));
  assert!(result["evidence"]["raw_base64"].is_null());assert_eq!(result["evidence"]["content_type"],"application/json");
  assert!(!result.to_string().contains("private_value"));
  let result=parse_status(br#"[{"ret":"1"},{"content":"accepted","\u0074oken":"private_value"}]"#,Some("application/json"));
  assert_eq!(result["result"],"fallback");assert!(!result.to_string().contains("private_value"));
 }
 #[test] fn duplicate_json_members_do_not_hide_early_secrets(){
  let result=parse_status(br#"{"x":{"\u0074oken":"private_value"},"x":0}"#,Some("application/json"));
  assert!(result["evidence"]["raw_base64"].is_null());assert!(!result.to_string().contains("private_value"));
  let safe=br#"{"x":1,"x":0}"#;let result=parse_status(safe,Some("application/json"));
  assert_eq!(STANDARD.decode(result["evidence"]["raw_base64"].as_str().unwrap()).unwrap(),safe);
 }
 #[test] fn bearer_and_escaped_credential_responses_are_withheld(){
  for key in ["bearer","jwt","nonce","loginname","login_name"] {
   let result=parse_status(json!({(key):"synthetic_private"}).to_string().as_bytes(),Some("application/json"));
   assert!(result["evidence"]["raw_base64"].is_null());assert!(!result.to_string().contains("synthetic_private"));
  }
  for body in [br#"{"other":"\\x62earer synthetic_private"}"#.as_slice(),br#"{"other":"&#98;earer synthetic_private"}"#.as_slice()] {
   assert!(parse_status(body,Some("application/json"))["evidence"]["raw_base64"].is_null());
  }
 }
 #[test] fn safe_unicode_json_preserves_original_but_escaped_token_is_withheld(){
  let safe=br#"{"title":"\u4e2d"}"#;let result=parse_status(safe,Some("application/json"));
  assert_eq!(STANDARD.decode(result["evidence"]["raw_base64"].as_str().unwrap()).unwrap(),safe);
  let result=parse_status(br#"{"\u0074oken":"private_value"}"#,Some("application/json"));
  assert!(result["evidence"]["raw_base64"].is_null());assert!(!result.to_string().contains("private_value"));
 }
 #[test] fn forged_previews_rejected(){let base=p();for bad in [SubmissionPreview{sha256:base.sha256.to_uppercase(),..base.clone()},SubmissionPreview{byte_count:16*1024*1024+1,..base.clone()},SubmissionPreview{course_id:String::new(),..base.clone()},SubmissionPreview{intent:"other".into(),..base.clone()}]{assert!(admit_submission(&bad,&BTreeSet::new(),true).is_err());assert!(multipart_part(&bad,b"abc".to_vec(),&bad.sha256).is_err());}}
 #[test] fn unsafe_file_types_and_permissions(){
  use std::os::unix::fs::{PermissionsExt,symlink};
  let dir=std::env::temp_dir().join(format!("buaa-grading-input-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
  std::fs::create_dir(&dir).unwrap();std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700)).unwrap();
  let file=dir.join("source");std::fs::write(&file,b"abc").unwrap();std::fs::set_permissions(&file,std::fs::Permissions::from_mode(0o600)).unwrap();
  assert_eq!(preview("c","a","p",&file).unwrap().sha256,hash(b"abc"));
  let link=dir.join("link");symlink(&file,&link).unwrap();assert!(preview("c","a","p",&link).is_err());
  let child=dir.join("child");std::fs::create_dir(&child).unwrap();std::fs::set_permissions(&child,std::fs::Permissions::from_mode(0o700)).unwrap();
  let child_file=child.join("source");std::fs::write(&child_file,b"abc").unwrap();std::fs::set_permissions(&child_file,std::fs::Permissions::from_mode(0o600)).unwrap();
  let alias=dir.join("alias");symlink(&child,&alias).unwrap();assert!(preview("c","a","p",&alias.join("source")).is_err());
  let large=dir.join("large");let big=std::fs::File::create(&large).unwrap();big.set_len(16*1024*1024+1).unwrap();std::fs::set_permissions(&large,std::fs::Permissions::from_mode(0o600)).unwrap();assert!(preview("c","a","p",&large).is_err());
  let fifo=dir.join("fifo");let name=std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
  // SAFETY: name is a live NUL-terminated path for this test-owned FIFO.
  assert_eq!(unsafe{libc::mkfifo(name.as_ptr(),0o600)},0);assert!(preview("c","a","p",&fifo).is_err());
  std::fs::set_permissions(&file,std::fs::Permissions::from_mode(0o666)).unwrap();assert!(preview("c","a","p",&file).is_err());
  std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o777)).unwrap();assert!(preview("c","a","p",&file).is_err());
  std::fs::remove_dir_all(dir).unwrap();
 }
}
