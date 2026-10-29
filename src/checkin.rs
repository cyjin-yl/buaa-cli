//! Pending iClass contract. No HTTP fallback, QR generation, polling or retries.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crate::{governor::{Governor, Outcome}, net::{self, Error}};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Read, time::{SystemTime, UNIX_EPOCH}};
use url::Url;
use zeroize::Zeroizing;
use zeroize::Zeroize;

#[derive(Serialize)]
#[serde(transparent)]
struct PrivateValue(Value);
impl<'de> Deserialize<'de> for PrivateValue{
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor{
            type Value=PrivateValue;
            fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("JSON value")}
            fn visit_unit<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok(PrivateValue(Value::Null))}
            fn visit_bool<E:serde::de::Error>(self,value:bool)->Result<Self::Value,E>{Ok(PrivateValue(Value::Bool(value)))}
            fn visit_i64<E:serde::de::Error>(self,value:i64)->Result<Self::Value,E>{Ok(PrivateValue(Value::from(value)))}
            fn visit_u64<E:serde::de::Error>(self,value:u64)->Result<Self::Value,E>{Ok(PrivateValue(Value::from(value)))}
            fn visit_f64<E:serde::de::Error>(self,value:f64)->Result<Self::Value,E>{Ok(PrivateValue(Value::from(value)))}
            fn visit_str<E:serde::de::Error>(self,value:&str)->Result<Self::Value,E>{Ok(PrivateValue(Value::String(value.to_owned())))}
            fn visit_string<E:serde::de::Error>(self,value:String)->Result<Self::Value,E>{Ok(PrivateValue(Value::String(value)))}
            fn visit_seq<A:serde::de::SeqAccess<'de>>(self,mut access:A)->Result<Self::Value,A::Error>{
                let mut result=PrivateValue(Value::Array(Vec::new()));while let Some(mut value)=access.next_element::<PrivateValue>()?{result.0.as_array_mut().unwrap().push(std::mem::take(&mut value.0));}Ok(result)
            }
            fn visit_map<A:serde::de::MapAccess<'de>>(self,mut access:A)->Result<Self::Value,A::Error>{
                let mut result=PrivateValue(Value::Object(serde_json::Map::new()));
                while let Some(key)=access.next_key::<String>()?{let mut key=Zeroizing::new(key);let values=result.0.as_object_mut().unwrap();if values.contains_key(key.as_str()){return Err(serde::de::Error::custom("duplicate JSON key"));}let mut value=access.next_value::<PrivateValue>()?;values.insert(std::mem::take(&mut *key),std::mem::take(&mut value.0));}Ok(result)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
impl std::ops::Deref for PrivateValue{type Target=Value;fn deref(&self)->&Value{&self.0}}
impl Drop for PrivateValue{fn drop(&mut self){wipe_value(&mut self.0);}}
fn wipe_value(value:&mut Value){match value{
    Value::String(text)=>text.zeroize(),Value::Array(values)=>values.iter_mut().for_each(wipe_value),
    Value::Object(values)=>for(mut key,mut value)in std::mem::take(values){key.zeroize();wipe_value(&mut value);},_=>{}
}}
fn private_value(value:&Value,secret:Option<&str>)->bool{
    let sensitive=|text:&str|match secret{Some(secret)=>crate::net::carries_secret(text.as_bytes(),secret),None=>sensitive_raw(text.as_bytes())};
    match value{Value::String(text)=>sensitive(text),Value::Array(values)=>values.iter().any(|value|private_value(value,secret)),Value::Object(values)=>values.iter().any(|(key,value)|sensitive(key)||private_value(value,secret)),
        Value::Number(_) | Value::Bool(_) | Value::Null=>secret.is_some_and(|secret|crate::net::json_scalar_matches(value,|bytes|crate::net::carries_secret(bytes,secret)))}
}

fn error(code: &'static str, message: &'static str) -> Error { Error::new(code, message) }
fn sensitive_raw(bytes:&[u8])->bool{
    if bytes.windows(2).any(|part|part==b"\\u"||part==b"\\x")||bytes.windows(2).any(|part|part==b"&#"){return true;}
    fn marked(bytes:&[u8])->bool{[b"token".as_slice(),b"cookie",b"password",b"ticket",b"authorization",b"session",b"csrf",b"secret",b"loginname",b"login_name",b"credential",b"bearer",b"execution",b"nonce",b"jwt"].iter().any(|marker|bytes.windows(marker.len()).any(|part|part.eq_ignore_ascii_case(marker)))}
    marked(bytes)||url::form_urlencoded::parse(bytes).any(|(key,value)|{let key=Zeroizing::new(key.into_owned());let value=Zeroizing::new(value.into_owned());marked(key.as_bytes())||marked(value.as_bytes())})
}
fn safe_mime(value:Option<&str>)->Option<&'static str>{let essence=value?.split(';').next()?.trim();["application/json","text/plain","text/html","application/xhtml+xml","application/octet-stream"].into_iter().find(|candidate|essence.eq_ignore_ascii_case(candidate))}
fn response_content_type(headers:&reqwest::header::HeaderMap)->Zeroizing<Option<String>>{Zeroizing::new(if headers.get_all("content-type").iter().count()==1{headers.get("content-type").and_then(|value|value.to_str().ok()).map(str::to_owned)}else{None})}
fn raw_evidence(bytes:&[u8],content_type:Option<&str>,complete:bool)->Value {
    let mime=safe_mime(content_type);
    let reason=match crate::html::assess_challenge_body(bytes,content_type,complete){
        crate::html::ChallengeAssessment::Clear=>None,
        crate::html::ChallengeAssessment::Detected=>Some("challenge_detected"),
        crate::html::ChallengeAssessment::Unreviewed=>Some("response_safety_unreviewed"),
    };
    let reason=if sensitive_raw(bytes)||serde_json::from_slice::<PrivateValue>(bytes).ok().is_some_and(|value|private_value(&value,None)){Some("sensitive_response_material")}else{reason};
    let content_type=mime;
    json!({"encoding":"base64","content_type":content_type,"byte_length":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes)),"data":reason.is_none().then(||STANDARD.encode(bytes)),"raw_withheld":reason.is_some(),"raw_withheld_reason":reason})
}
fn response_contains_secret(bytes:&[u8],content_type:Option<&str>,secret:&str)->bool {
    if secret.is_empty(){return false;}
    let contains=|candidate:&[u8]|crate::net::carries_secret(candidate,secret);
    contains(bytes)||content_type.is_some_and(|value|contains(value.as_bytes()))
        ||serde_json::from_slice::<PrivateValue>(bytes).ok().is_some_and(|value|private_value(&value,Some(secret)))
}
fn response_contains_cookie(bytes:&[u8],content_type:Option<&str>,cookie:&str)->bool {
    response_contains_secret(bytes,content_type,cookie)||cookie.split(';').filter_map(|part|part.trim().split_once('=')).any(|(_,value)|response_contains_secret(bytes,content_type,value.trim()))
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all="snake_case")]
pub enum SessionHeader { LoginName, SessionId }
#[derive(Clone, Copy)]
pub enum SignPathPrefix { Eschool, Root }
/// Secrets are deliberately not Debug/Serialize and must originate from stdin/session storage.
pub struct Session { pub user_id: String, pub login_name: Zeroizing<String>, pub session_id: Zeroizing<String>, pub header: SessionHeader }
fn object<'de,D:serde::Deserializer<'de>,T:Deserialize<'de>>(deserializer:D)->Result<T,D::Error>{
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de,T:Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T>{type Value=T;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("JSON object")}
        fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<T,A::Error>{T::deserialize(serde::de::value::MapAccessDeserializer::new(access))}}
    deserializer.deserialize_map(Visitor(std::marker::PhantomData))
}
fn optional_object<'de,D:serde::Deserializer<'de>,T:Deserialize<'de>>(deserializer:D)->Result<Option<T>,D::Error>{
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de,T:Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T>{type Value=Option<T>;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("object or null")}
        fn visit_none<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok(None)}fn visit_unit<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok(None)}
        fn visit_some<D:serde::Deserializer<'de>>(self,deserializer:D)->Result<Self::Value,D::Error>{object(deserializer).map(Some)}}
    deserializer.deserialize_option(Visitor(std::marker::PhantomData))
}
impl<'de> Deserialize<'de> for Session{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
    #[derive(Deserialize)] #[serde(deny_unknown_fields)]struct Fields{user_id:String,#[serde(deserialize_with="secret")]login_name:Zeroizing<String>,#[serde(deserialize_with="secret")]session_id:Zeroizing<String>,header:SessionHeader}
    let fields:Fields=object(deserializer)?;Ok(Self{user_id:fields.user_id,login_name:fields.login_name,session_id:fields.session_id,header:fields.header})
}}
fn secret<'de,D:serde::Deserializer<'de>>(deserializer:D)->Result<Zeroizing<String>,D::Error>{String::deserialize(deserializer).map(Zeroizing::new)}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentLesson {
    pub course_id: String, pub course_sched_id: String,
    /// Epoch milliseconds; caller must bind these to the freshly read schedule.
    pub begins_at_ms: u64, pub ends_at_ms: u64, pub sign_status: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignIntent { pub operation: SignOperation, pub course_sched_id: String, pub owner_present: bool }
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SignOperation { #[serde(rename="sign_current_lesson")] SignCurrentLesson }
/// An immutable, process-local preview. It cannot be deserialized or constructed by callers.
pub struct Preview { lesson: CurrentLesson, digest: String, time_format:TimeFormat }
/// These formats are caller assertions, not upstream-verified facts. Unknown
/// or nonmatching formats fail closed. UTC offset must be explicitly supplied.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimeFormat {pub datetime_formats:Vec<String>,pub utc_offset_seconds:i32}
impl TimeFormat {
    /// Unverified compatibility assumption: Chinese local date and HH:mm[:ss].
    pub fn assumed_china()->Self {Self{datetime_formats:["%Y-%m-%d %H:%M:%S","%Y-%m-%d %H:%M","%Y%m%d %H:%M:%S","%Y%m%d %H:%M"].iter().map(|v|(*v).to_owned()).collect(),utc_offset_seconds:8*60*60}}
}
impl Preview { pub fn value(&self) -> Value { json!({"operation":"sign_current_lesson","lesson":self.lesson,"time_format":self.time_format,"time_format_authority":"caller_assertion_not_upstream_verified","preview_digest":self.digest,"confirmation_available":false,"executable":false,"blocked_reason":"account_target_bound_preview_and_persistent_atomic_idempotency_not_implemented"}) } }
pub fn preview(intent: SignIntent, lesson: CurrentLesson, now_ms: u64) -> Result<Preview, Error> {
    preview_with_time_format(intent,lesson,now_ms,TimeFormat::assumed_china())
}
pub fn preview_with_time_format(intent: SignIntent, lesson: CurrentLesson, now_ms: u64,time_format:TimeFormat) -> Result<Preview, Error> {
    if time_format.datetime_formats.is_empty() || time_format.datetime_formats.len()>16 || !(-86399..=86399).contains(&time_format.utc_offset_seconds) {return Err(error("invalid_time_format","explicit formats and valid UTC offset required"));}
    if !intent.owner_present { return Err(error("owner_required", "owner must be present")); }
    if intent.course_sched_id != lesson.course_sched_id { return Err(error("lesson_mismatch", "intent differs from current lesson")); }
    eligible(&lesson, now_ms)?;
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&json!({"lesson":lesson,"time_format":time_format})).map_err(|_| error("invalid_lesson", "cannot encode lesson"))?));
    Ok(Preview { lesson, digest,time_format })
}
fn eligible(lesson: &CurrentLesson, now: u64) -> Result<(), Error> {
    if lesson.sign_status == "1" { return Err(error("already_signed", "duplicate sign-in refused")); }
    if lesson.sign_status != "0" { return Err(error("unknown_sign_status", "only known unsigned status 0 is admitted")); }
    if lesson.begins_at_ms >= lesson.ends_at_ms || now < lesson.begins_at_ms || now >= lesson.ends_at_ms {
        return Err(error("outside_lesson", "sign-in is only allowed during the current lesson"));
    }
    Ok(())
}
pub fn classify_message(message: &str) -> &'static str {
    if message.contains("已签到") { "already_signed" }
    else if message.contains("未开始") { "not_started" }
    else if message.contains("不是上课时间") { "outside_lesson" }
    else if message.contains("已结束") { "ended" }
    else if message.contains("范围") { "out_of_range" }
    else if message.contains("用户不存在") { "user_missing" }
    else if message.contains("课程不存在") { "course_missing" } else { "unclassified" }
}
fn session_denial(body:&[u8])->bool{
    struct Facts<'a>(&'a std::cell::Cell<bool>);
    impl<'de> serde::de::Visitor<'de> for Facts<'_>{type Value=();fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("response object")}
        fn visit_map<A:serde::de::MapAccess<'de>>(self,mut access:A)->Result<(),A::Error>{while let Some(key)=access.next_key::<String>()?{let key=Zeroizing::new(key);if key.as_str()=="STATUS"{let value=access.next_value::<PrivateValue>()?;if matches!(value.as_str(),Some("401"|"4001")){self.0.set(true);}}else{access.next_value::<serde::de::IgnoredAny>()?;}}Ok(())}}
    let denial=std::cell::Cell::new(false);let mut deserializer=serde_json::Deserializer::from_slice(body);let _=serde::Deserializer::deserialize_map(&mut deserializer,Facts(&denial));denial.get()
}
pub fn parse_response(body: &[u8], content_type: Option<&str>) -> Value {
    let assessment=crate::html::assess_challenge_body(body,content_type,true);
    let parsed=serde_json::from_slice::<PrivateValue>(body);
    if assessment!=crate::html::ChallengeAssessment::Clear||parsed.as_ref().ok().is_some_and(|value|private_value(value,None)){
        return json!({"result":"fallback","fallback_reason":"response_withheld","raw_evidence":{"content_type":safe_mime(content_type),"byte_length":body.len(),"sha256":format!("{:x}",Sha256::digest(body)),"data":null,"raw_withheld":true,"raw_withheld_reason":if assessment==crate::html::ChallengeAssessment::Detected{"challenge_detected"}else if assessment==crate::html::ChallengeAssessment::Unreviewed{"response_safety_unreviewed"}else{"sensitive_response_material"}}});
    }
    match parsed {
        Ok(v) if v.get("STATUS").and_then(Value::as_str).is_some_and(|s|s!="0" && s!="2") => {
            let status=v["STATUS"].as_str().unwrap_or_default();
            json!({"result":if matches!(status,"401"|"4001"){"session_expired"}else{"upstream_error"},"message_class":classify_message(v.get("MSG").or_else(||v.get("message")).and_then(Value::as_str).unwrap_or("")),"response":v})
        }
        Ok(v) if v.get("result").and_then(|v|v.get("stuSignStatus")).is_some() => json!({"result":"postcondition_unknown","response":v}),
        Ok(v) if v.get("STATUS").is_none()&&v.get("timestamp").is_some_and(|t|t.is_u64() || t.as_str().is_some_and(|s|!s.is_empty() && s.bytes().all(|b|b.is_ascii_digit()))) => json!({"result":"success","response":&v.0}),
        Ok(v) if matches!(v.get("STATUS").and_then(Value::as_str), Some("0"|"2"|"4001"|"401")) => {
            let status = v["STATUS"].as_str().unwrap_or_default();
            json!({"result":match status {"0"=>"success","2"=>"empty",_=>"session_expired"},"response":v})
        }
        Ok(v) if v.get("STATUS").and_then(Value::as_str).is_some() => json!({"result":"upstream_error","message_class":classify_message(v.get("MSG").or_else(||v.get("message")).and_then(Value::as_str).unwrap_or("")),"response":v}),
        _ => json!({"result":"fallback","fallback_reason":"unrecognized_json_contract","raw_evidence":raw_evidence(body,content_type,true)}),
    }
}
/// Percent-decoding is performed by the URL query parser, without following redirects.
pub fn login_name(location: &str) -> Result<Zeroizing<String>, Error> {
    let tail=location.strip_prefix("https://iclass.buaa.edu.cn:8346/").or_else(||location.strip_prefix('/')).ok_or_else(||error("invalid_location","invalid login redirect"))?;
    if tail.contains('#')||tail.chars().any(char::is_control){return Err(error("invalid_location","invalid login redirect"));}
    let query=tail.split_once('?').map(|(_,query)|query).ok_or_else(||error("invalid_location","loginName required"))?;
    let mut name=None;for(key,value)in url::form_urlencoded::parse(query.as_bytes()){
        let key=Zeroizing::new(key.into_owned());let value=Zeroizing::new(value.into_owned());
        if key.as_str()=="loginName"{if name.is_some(){return Err(error("invalid_location","ambiguous loginName"));}name=Some(value);}
    }
    name.filter(|name|!name.is_empty()).ok_or_else(||error("invalid_location","loginName required"))
}
pub enum ReadOperation<'a> { Today { date: &'a str }, Courses { semester: &'a str }, Semesters, Details { course_id: &'a str } }
pub struct CheckinClient { http: Client, governor: Governor }
struct ReadResponse<'a>{bytes:&'a [u8],content_type:Option<&'a str>,location:Option<&'a str>,status:u16,assessment:crate::html::ChallengeAssessment,challenge:bool,network_failure:bool,issues_cookie:bool}
impl CheckinClient {
    pub fn open() -> Result<Self, Error> {
        Ok(Self { http: Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never()).timeout(std::time::Duration::from_secs(30)).build().map_err(|_|error("transport", "cannot initialize HTTPS client"))?, governor: Governor::open().map_err(|_|error("governor_denied", "cannot open shared governor"))? })
    }
    fn request(&self, url: Url, session: Option<&Session>) -> Result<Value, Error> {
        self.request_inner(url,session,None)
    }
    fn request_inner(&self, url: Url, session: Option<&Session>, cookie:Option<&str>) -> Result<Value, Error> {
        if url.path().ends_with("login.action") || url.path().contains("stu_scan_sign") {return Err(error("unsupported","authentication and mutation transport are disabled pending safety implementation"));}
        if cookie.is_some_and(|value|reqwest::header::HeaderValue::from_str(value).is_err())
            ||session.is_some_and(|session|[session.login_name.as_str(),session.session_id.as_str()].iter().any(|value|reqwest::header::HeaderValue::from_str(value).is_err()))
        {return Err(error("invalid_input","credential headers cannot be constructed"));}
        let mut req = self.http.get(url);
        if let Some(cookie)=cookie {req=req.header("Cookie",cookie);}
        if let Some(s) = session { req = req.header("sessionId",match s.header { SessionHeader::LoginName=> s.login_name.as_str(), SessionHeader::SessionId=> s.session_id.as_str() }); }
        let req=req.timeout(std::time::Duration::from_secs(30));
        let mut lease = net::acquire(&self.governor)?;
        let mut response = match lease.start_request(||req.send()) {
            Ok(Ok(response))=>response,
            Ok(Err(_))=>{lease.finish(Outcome::NetworkFailure).map_err(|_|error("governor_denied","cannot settle request"))?;return Err(error("network_error","HTTPS request failed; no fallback or retry"));},
            Err(crate::governor::FollowupError::CachedChallenge)=>{lease.finish(Outcome::SafetyObserved).map_err(|_|error("governor_denied","cannot settle request"))?;return Err(error("safety_latched","shared safety observation prevents request"));},
            Err(crate::governor::FollowupError::Governor(_))=>return Err(error("governor_denied","request-start admission unavailable")),
        };
        let status = response.status().as_u16();
        let retry = response.headers().get("retry-after").and_then(|v|v.to_str().ok()).map(str::to_owned);
        let header_challenge = response.headers().iter().any(|(k,v)|net::challenge_header(k.as_str(),v.as_bytes()));
        let content_type = response_content_type(response.headers());
        let location = Zeroizing::new(response.headers().get("location").and_then(|v|v.to_str().ok()).map(str::to_owned));
        // A newly issued session cookie is a credential this client never
        // submitted and cannot revoke; its value must never reach the caller.
        let issues_cookie = net::issues_session_cookie(response.headers());
        lease.observe_http_many(status,response.headers().get_all("retry-after").iter().map(|value|value.to_str().ok()),header_challenge).map_err(|_|error("governor_denied","cannot persist response headers"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        let read = response.by_ref().take(8*1024*1024+1).read_to_end(&mut bytes);
        let network_failure = read.is_err()||bytes.len()>8*1024*1024;
        // Observe even partially read/oversized bodies before any parse error or
        // fallback. The lease must persist this fact before returning a refusal.
        let assessment=crate::html::assess_challenge_body(&bytes,content_type.as_deref(),!network_failure);
        let challenge=header_challenge||assessment==crate::html::ChallengeAssessment::Detected;
        drop(response);
        // The complete admitted or refused result is computed while the
        // original lease is still held, so no other request is admitted
        // between the response and its admission. The lease settles exactly
        // once, whatever the result.
        let (result,business_denial) = Self::admit_response(ReadResponse{bytes:&bytes,content_type:content_type.as_deref(),location:location.as_deref(),status,assessment,challenge,network_failure,issues_cookie},session,cookie);
        lease.finish(Outcome::Http{status,retry_after:retry.as_deref(),challenge:challenge||business_denial,network_failure}).map_err(|_|error("governor_denied","cannot settle request"))?;
        result
    }
    fn admit_response(response:ReadResponse<'_>,session:Option<&Session>,cookie:Option<&str>)->(Result<Value,Error>,bool){
            let ReadResponse{bytes,content_type,location,status,assessment,challenge,network_failure,issues_cookie}=response;
            let secret_echo=cookie.is_some_and(|secret|response_contains_cookie(bytes,content_type,secret)||location.is_some_and(|value|response_contains_cookie(value.as_bytes(),None,secret)))
                ||session.is_some_and(|session|[session.login_name.as_str(),session.session_id.as_str()].iter().any(|secret|response_contains_secret(bytes,content_type,secret)||location.is_some_and(|value|response_contains_secret(value.as_bytes(),None,secret))));
            let parsed = if assessment!=crate::html::ChallengeAssessment::Clear {Ok(PrivateValue(Value::Null))} else if (300..400).contains(&status) {Err(error("unsupported","redirect credential acquisition requires a private session sink"))} else {Ok(PrivateValue(parse_response(bytes,content_type)))};
            // A complete JSON denial remains a denial even when its MIME cannot
            // establish admission of the rest of the response.
            let business_denial=session_denial(bytes)||parsed.as_ref().ok().is_some_and(|value|value["result"]=="session_expired");
            let result=(||{
            if business_denial{return Err(error("safety_denied","application session denial latched shared governor"));}
            if challenge || matches!(status,401|403|429) { return Err(error("safety_denied","request denied; no subsequent request admitted")); }
            if network_failure { return Err(error("body_error","response incomplete or over limit")); }
            if !(200..400).contains(&status) { return Err(error("http_error","upstream HTTP failure")); }
            if assessment==crate::html::ChallengeAssessment::Unreviewed {return Err(error("response_safety_unreviewed","response body safety could not be established; admission refused without retry"));}
            if secret_echo {return Err(error("sensitive_response_withheld","response echoed submitted session material; no raw fallback exported"));}
            if issues_cookie {return Err(error("sensitive_response_withheld","response issued a session cookie; no raw fallback exported"));}
            parsed.map(|mut value|std::mem::take(&mut value.0))
            })();
            (result,business_denial)
    }
    pub fn acquire_login_name(&self) -> Result<Value, Error> { Err(error("unsupported","loginName acquisition blocked before transport: private zeroizing session sink unavailable")) }
    /// The session layer must supply only cookies valid for this exact HTTPS
    /// host. Redirects are disabled, so cookies cannot leak to CAS/other hosts.
    pub fn acquire_login_name_with_cookie(&self,_cookie:&str)->Result<Value,Error>{self.acquire_login_name()}
    pub fn application_login(&self, _name: &str) -> Result<Value, Error> {
        Err(error("unsupported","application authentication is disabled: one-shot Authentication admission and known business outcome settlement not implemented"))
    }
    pub fn read(&self, session: &Session, operation: ReadOperation<'_>) -> Result<Value, Error> {
        let (path, pairs) = match operation {
            ReadOperation::Today{date} => { if date.len()!=8 || !date.bytes().all(|b|b.is_ascii_digit()) {return Err(error("invalid_date","date must be yyyyMMdd"));} ("course/get_stu_course_sched.action",vec![("id",session.user_id.as_str()),("dateStr",date)]) },
            ReadOperation::Courses{semester} => ("choosecourse/get_myall_course.action",vec![("user_type","1"),("id",session.user_id.as_str()),("xq_code",semester)]),
            ReadOperation::Semesters => ("course/get_base_school_year.action",vec![("userId",session.user_id.as_str()),("type","2")]),
            ReadOperation::Details{course_id} => ("my/get_my_course_sign_detail.action",vec![("id",session.user_id.as_str()),("courseId",course_id),("sessionId",session.session_id.as_str())]),
        };
        let mut url=Url::parse(&format!("https://iclass.buaa.edu.cn:8347/app/{path}")).unwrap(); url.query_pairs_mut().extend_pairs(pairs); self.request(url,Some(session))
    }
    pub fn commit(&self, preview: Preview, confirmation: &str, owner_present: bool, _session: &Session) -> Result<Value, Error> {
        self.commit_with_prefix(preview,confirmation,owner_present,_session,SignPathPrefix::Eschool)
    }
    pub fn commit_with_prefix(&self, _preview: Preview, _confirmation: &str, _owner_present: bool, _session: &Session, _prefix:SignPathPrefix) -> Result<Value, Error> {
        Err(error("unsupported","sign-in disabled before any request: account/target-bound confirmation, persistent atomic account+lesson reservation and unknown-outcome recovery barrier not implemented"))
    }
}
#[cfg(test)]
fn verify_lesson(value:&Value,lesson:&CurrentLesson,signed:bool,time_format:&TimeFormat)->Result<(),Error>{
    if value["result"]!="success" {return Err(error("invalid_lesson","fresh lesson read failed"));}
    let rows=value["response"]["result"].as_array().ok_or_else(||error("invalid_lesson","detail list unavailable"))?;
    let matches:Vec<_>=rows.iter().filter(|v|v["courseSchedId"].as_str()==Some(lesson.course_sched_id.as_str())).collect();
    if matches.len()!=1{return Err(error("invalid_lesson","current lesson not uniquely found"));}
    let row=matches[0];
    if row["signStatus"].as_str()!=Some(if signed{"1"}else{"0"}){return Err(error("already_signed","fresh unsigned state not established"));}
    if !signed {
        let date=row["teachTime"].as_str().ok_or_else(||error("unsupported_time","teachTime format unknown"))?;
        let parse=|field:&str|->Option<u64>{
            let time=row[field].as_str()?;
            let joined=format!("{date} {time}");
            let dt=time_format.datetime_formats.iter().find_map(|fmt|chrono::NaiveDateTime::parse_from_str(&joined,fmt).ok())?;
            u64::try_from(dt.and_utc().timestamp_millis().checked_sub(i64::from(time_format.utc_offset_seconds)*1000)?).ok()
        };
        if parse("classBeginTime")!=Some(lesson.begins_at_ms)||parse("classEndTime")!=Some(lesson.ends_at_ms){return Err(error("unsupported_time","fresh schedule times differ or use unsupported format"));}
    }
    Ok(())
}
struct RunInput {operation:RunOperation,payload:Option<RunPayload>}
impl<'de> Deserialize<'de> for RunInput{
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
        #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Strict{operation:RunOperation,#[serde(default,deserialize_with="optional_object")]payload:Option<RunPayload>}
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor{type Value=Strict;
            fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("JSON object")}
            fn visit_seq<A:serde::de::SeqAccess<'de>>(self,_:A)->Result<Self::Value,A::Error>{Err(serde::de::Error::custom("positional input refused"))}
            fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<Self::Value,A::Error>{serde::de::Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(access))}
        }
        deserializer.deserialize_map(Visitor).map(|strict|Self{operation:strict.operation,payload:strict.payload})
    }
}
#[derive(Default,Deserialize)] #[serde(deny_unknown_fields)]
struct RunPayload {
    session:Option<Session>,
    #[serde(default,deserialize_with="optional_secret")]session_cookie:Option<Zeroizing<String>>,
    #[serde(default,rename="login_name",deserialize_with="optional_secret")]_login_name:Option<Zeroizing<String>>,
    kind:Option<String>,date:Option<String>,semester:Option<String>,course_id:Option<String>,course_sched_id:Option<String>,
    #[serde(default,deserialize_with="optional_object")]lesson:Option<CurrentLesson>,
    #[serde(default,deserialize_with="optional_object")]intent:Option<SignIntent>,
    #[serde(default,deserialize_with="optional_object")]time_format:Option<TimeFormat>,
    #[serde(rename="confirmation")]_confirmation:Option<String>,
    #[serde(rename="owner_present")]_owner_present:Option<bool>,
    #[serde(rename="sign_path_prefix")]_sign_path_prefix:Option<String>,
}
fn optional_secret<'de,D:serde::Deserializer<'de>>(deserializer:D)->Result<Option<Zeroizing<String>>,D::Error>{Option::<String>::deserialize(deserializer).map(|s|s.map(Zeroizing::new))}
#[derive(Clone,Copy,Deserialize)] #[serde(rename_all="snake_case")]
enum RunOperation {LoginName,Login,Courses,Lesson,Preview,Commit,Postcondition}
fn required(value:Option<&str>)->Result<&str,Error>{value.filter(|s|!s.is_empty()).ok_or_else(||error("invalid_input","nonempty required field missing"))}
pub fn run(input:&str,online:bool)->Result<Value,Error>{
    let result=(||->Result<Value,Error>{
        let input:RunInput=serde_json::from_str(input).map_err(|_|error("invalid_input","expected operation and optional JSON payload only"))?;
        if matches!(input.operation,RunOperation::LoginName){return Ok(json!({"result":"unsupported","reason":"login_name_private_zeroizing_session_sink_unavailable","network_performed":false}));}
        // Fail closed BEFORE constructing a client, acquiring a lease, or
        // examining a confirmation. Neither endpoint can currently be invoked.
        if matches!(input.operation,RunOperation::Commit|RunOperation::Login){return Ok(json!({"result":"unsupported","reason":if matches!(input.operation,RunOperation::Login){"authentication_one_shot_and_business_outcome_admission_not_implemented"}else{"account_target_bound_preview_persistent_atomic_reservation_and_unknown_outcome_recovery_not_implemented"},"write_performed":false}));}
        let p=input.payload.unwrap_or_default();
        if matches!(input.operation,RunOperation::Preview){
            let lesson=p.lesson.ok_or_else(||error("invalid_input","lesson required"))?;
            let intent=p.intent.ok_or_else(||error("invalid_input","typed intent required"))?;
            let format=p.time_format.ok_or_else(||error("invalid_input","explicit time_format required"))?;
            let now=u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|error("clock","invalid clock"))?.as_millis()).map_err(|_|error("clock","clock overflow"))?;
            let preview=preview_with_time_format(intent,lesson,now,format)?;
            return Ok(json!({"result":"preview","response":preview.value(),"write_performed":false}));
        }
        if !online{return Ok(json!({"result":"blocked","reason":"online permission required; no request made"}));}
        let client=CheckinClient::open()?;
        match input.operation {
            RunOperation::LoginName=>client.acquire_login_name_with_cookie(required(p.session_cookie.as_ref().map(|s|s.as_str()))?),
            RunOperation::Courses|RunOperation::Lesson|RunOperation::Postcondition=>{
                let session=p.session.as_ref().ok_or_else(||error("invalid_input","explicit session required"))?;
                if matches!(input.operation,RunOperation::Courses){return client.read(session,match required(p.kind.as_deref())?{"today"=>ReadOperation::Today{date:required(p.date.as_deref())?},"courses"=>ReadOperation::Courses{semester:required(p.semester.as_deref())?},"semesters"=>ReadOperation::Semesters,_=>return Err(error("invalid_input","unknown courses kind"))});}
                let expected_sched=if matches!(input.operation,RunOperation::Postcondition){
                    let id=required(p.course_sched_id.as_deref())?;
                    if id.is_empty(){return Err(error("invalid_input","nonempty course_sched_id required"));}
                    Some(id)
                }else{None};
                let value=client.read(session,ReadOperation::Details{course_id:required(p.course_id.as_deref())?})?;
                if matches!(input.operation,RunOperation::Postcondition){
                    if value["result"]!="success"{return Err(error("postcondition_unknown","detail response was not successful"));}
                    let rows=value["response"]["result"].as_array().ok_or_else(||error("postcondition_unknown","detail list unavailable"))?;
                    let matching:Vec<_>=rows.iter().filter(|r|r["courseSchedId"].as_str()==expected_sched).collect();
                    if matching.len()!=1||matching[0]["signStatus"]!="1" {return Err(error("postcondition_unknown","signed state not established"));}
                    return Ok(json!({"result":"success","response":value["response"],"postcondition":"signStatus_1"}));
                }
                Ok(value)
            },RunOperation::Preview|RunOperation::Commit|RunOperation::Login=>unreachable!(),
        }
    })();
    Ok(match result{Ok(v)=>v,Err(e)=>json!({"result":if e.code=="unsupported"{"unsupported"}else{"blocked"},"reason":e.code})})
}
pub fn schema() -> Value {
    let mut properties=serde_json::Map::new();
    for key in ["session_cookie","login_name","kind","date","semester","course_id","course_sched_id","confirmation","sign_path_prefix"] {properties.insert(key.into(),json!({"type":["string","null"]}));}
    properties.insert("owner_present".into(),json!({"type":["boolean","null"]}));
    properties.insert("session".into(),json!({"type":["object","null"],"additionalProperties":false,"required":["user_id","login_name","session_id","header"],"properties":{"user_id":{"type":"string"},"login_name":{"type":"string"},"session_id":{"type":"string"},"header":{"enum":["login_name","session_id"]}}}));
    let integer=json!({"type":"integer","minimum":0,"maximum":u64::MAX});
    properties.insert("lesson".into(),json!({"type":["object","null"],"additionalProperties":false,"required":["course_id","course_sched_id","begins_at_ms","ends_at_ms","sign_status"],"properties":{"course_id":{"type":"string"},"course_sched_id":{"type":"string"},"sign_status":{"type":"string"},"begins_at_ms":integer,"ends_at_ms":integer}}));
    properties.insert("intent".into(),json!({"type":["object","null"],"additionalProperties":false,"required":["operation","course_sched_id","owner_present"],"properties":{"operation":{"const":"sign_current_lesson"},"course_sched_id":{"type":"string"},"owner_present":{"type":"boolean"}}}));
    properties.insert("time_format".into(),json!({"type":["object","null"],"additionalProperties":false,"required":["datetime_formats","utc_offset_seconds"],"properties":{"datetime_formats":{"type":"array","items":{"type":"string"}},"utc_offset_seconds":{"type":"integer","minimum":i32::MIN,"maximum":i32::MAX}}}));
    json!({"module":"checkin","state":"pending","input":{"type":"object","additionalProperties":false,"required":["operation"],"properties":{"operation":{"enum":["login_name","login","courses","lesson","preview","commit","postcondition"]},"payload":{"type":["object","null"],"additionalProperties":false,"properties":properties}}},"authentication":"unsupported: one-shot authentication outcome admission not implemented","writes":"unsupported: persistent atomic reservation, unknown-outcome barrier and account/target-bound confirmation not implemented","time_format_authority":"caller assertion, not upstream verified","output":{"type":"object","required":["result"],"properties":{"result":{"enum":["success","empty","session_expired","upstream_error","redirect","fallback","preview","blocked","unsupported","postcondition_unknown"]}}}})
}
#[cfg(test)]
fn numeric_session_admit(body: &[u8], status: u16, challenge: bool) -> (Result<Value, Error>, bool) {
    let session = Session { user_id: "reader".into(), login_name: Zeroizing::new("1000.0".into()), session_id: Zeroizing::new("different-session".into()), header: SessionHeader::LoginName };
    CheckinClient::admit_response(ReadResponse {
        bytes: body, content_type: Some("application/json"), location: None, status,
        assessment: crate::html::assess_challenge_body(body, Some("application/json"), true),
        challenge, network_failure: false, issues_cookie: false,
    }, Some(&session), None)
}

#[cfg(test)]
fn numeric_session_structured() {
    let (result, denied) = numeric_session_admit(br#"{"STATUS":"0","data":1e3}"#, 200, false);
    assert_eq!(result.unwrap_err().code, "sensitive_response_withheld");
    assert!(!denied);
}

#[cfg(test)]
fn numeric_session_fallback() {
    let (result, denied) = numeric_session_admit(br#"{"data":1e3}"#, 200, false);
    assert_eq!(result.unwrap_err().code, "sensitive_response_withheld");
    assert!(!denied);
}

#[cfg(test)]
fn numeric_session_controls_and_denials() {
    let (result, denied) = numeric_session_admit(br#"{"STATUS":"0","data":42}"#, 200, false);
    assert_eq!(result.unwrap(), json!({"result":"success","response":{"STATUS":"0","data":42}}));
    assert!(!denied);
    let (result, denied) = numeric_session_admit(br#"{"data":42}"#, 200, false);
    assert_eq!(result.unwrap()["raw_evidence"]["data"], STANDARD.encode(br#"{"data":42}"#));
    assert!(!denied);
    let body = br#"{"STATUS":"401","data":1e3}"#;
    let (result, denied) = numeric_session_admit(body, 200, false);
    assert_eq!(result.unwrap_err().code, "safety_denied");
    assert!(denied);
    for (status, challenge) in [(401, false), (403, false), (429, false), (200, true)] {
        let (result, denied) = numeric_session_admit(br#"{"STATUS":"0","data":1e3}"#, status, challenge);
        assert_eq!(result.unwrap_err().code, "safety_denied");
        assert!(!denied);
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn numeric_session_scalar_is_withheld() { numeric_session_structured(); }
    #[test] fn numeric_session_fallback_is_withheld() { numeric_session_fallback(); }
    #[test] fn numeric_session_controls_and_denials_are_retained() { numeric_session_controls_and_denials(); }
    #[test] fn production_admission_withholds_cookies_and_encoded_credentials(){
        let admit=|body:&[u8],headers:&reqwest::header::HeaderMap|CheckinClient::admit_response(ReadResponse{bytes:body,content_type:Some("application/json"),location:None,status:200,assessment:crate::html::assess_challenge_body(body,Some("application/json"),true),challenge:false,network_failure:false,issues_cookie:net::issues_session_cookie(headers)},None,Some("sid=abc_123"));
        let mut headers=reqwest::header::HeaderMap::new();
        let safe=br#"{"STATUS":"0","data":"q"}"#;
        assert_eq!(admit(safe,&headers).0.unwrap()["response"]["data"],"q");
        headers.insert(reqwest::header::SET_COOKIE,reqwest::header::HeaderValue::from_static("x=q"));
        let (result,business_denial)=admit(safe,&headers);assert_eq!(result.unwrap_err().code,"sensitive_response_withheld");assert!(!business_denial);
        let opaque=br#"{"STATUS":"0","data":"freshopaque123"}"#;
        headers.insert(reqwest::header::SET_COOKIE,reqwest::header::HeaderValue::from_static("x=freshopaque123"));
        let (result,business_denial)=admit(opaque,&headers);assert_eq!(result.unwrap_err().code,"sensitive_response_withheld");assert!(!business_denial);
        headers.clear();
        for body in [br#"{"STATUS":"0","data":"YWJjXzEyMw=="}"#.as_slice(),br#"{"STATUS":"0","data":"%61%62%63%5F%31%32%33"}"#.as_slice(),br#"{"STATUS":"0","data":"\u0059WJjXzEyMw=="}"#.as_slice(),br#"{"STATUS":"0","data":"\u002561%62%63%5F%31%32%33"}"#.as_slice(),br#"{"STATUS":"0","\u0059WJjXzEyMw==":"ordinary"}"#.as_slice()] {assert_eq!(admit(body,&headers).0.unwrap_err().code,"sensitive_response_withheld");}
        let session=Session{user_id:"reader".into(),login_name:Zeroizing::new("abc_123".into()),session_id:Zeroizing::new("different-session".into()),header:SessionHeader::LoginName};
        let escaped=br#"{"STATUS":"0","data":"\u0059WJjXzEyMw=="}"#;
        let (result,business_denial)=CheckinClient::admit_response(ReadResponse{bytes:escaped,content_type:Some("application/json"),location:None,status:200,assessment:crate::html::assess_challenge_body(escaped,Some("application/json"),true),challenge:false,network_failure:false,issues_cookie:false},Some(&session),None);
        assert_eq!(result.unwrap_err().code,"sensitive_response_withheld");assert!(!business_denial);
        let session=Session{user_id:"reader".into(),login_name:Zeroizing::new("abc/def=".into()),session_id:Zeroizing::new("different-session".into()),header:SessionHeader::LoginName};
        let mixed=br#"{"STATUS":"0","data":"abc%2Fdef="}"#;
        let (result,business_denial)=CheckinClient::admit_response(ReadResponse{bytes:mixed,content_type:Some("application/json"),location:None,status:200,assessment:crate::html::assess_challenge_body(mixed,Some("application/json"),true),challenge:false,network_failure:false,issues_cookie:false},Some(&session),None);
        assert_eq!(result.unwrap_err().code,"sensitive_response_withheld");assert!(!business_denial);
        let fallback=br#"{"data":"ordinary"}"#;
        assert_eq!(admit(fallback,&headers).0.unwrap()["raw_evidence"]["data"],STANDARD.encode(fallback));
        headers.insert(reqwest::header::SET_COOKIE,reqwest::header::HeaderValue::from_static("x=q"));
        assert_eq!(admit(fallback,&headers).0.unwrap_err().code,"sensitive_response_withheld");
        let (result,business_denial)=admit(br#"{"STATUS":"401"}"#,&headers);
        assert_eq!(result.unwrap_err().code,"safety_denied");assert!(business_denial);
        for (status,challenge) in [(401,false),(403,false),(200,true)] {
            let (result,business_denial)=CheckinClient::admit_response(ReadResponse{bytes:safe,content_type:Some("application/json"),location:None,status,assessment:crate::html::assess_challenge_body(safe,Some("application/json"),true),challenge,network_failure:false,issues_cookie:net::issues_session_cookie(&headers)},None,Some("sid=abc_123"));
            assert_eq!(result.unwrap_err().code,"safety_denied");assert!(!business_denial);
        }
    }
    fn lesson()->CurrentLesson {CurrentLesson{course_id:"c".into(),course_sched_id:"s".into(),begins_at_ms:10,ends_at_ms:20,sign_status:"0".into()}}
    #[test] fn outside_and_duplicate_refused(){assert!(eligible(&lesson(),20).is_err());let mut l=lesson();l.sign_status="1".into();assert!(eligible(&l,15).is_err());}
    #[test] fn messages_and_status(){assert_eq!(classify_message("已签到"),"already_signed");assert_eq!(parse_response(br#"{"STATUS":"2"}"#,Some("application/json"))["result"],"empty");assert_eq!(parse_response(br#"{"STATUS":"401"}"#,Some("application/json"))["result"],"session_expired");let error=parse_response(r#"{"STATUS":"3","MSG":"已签到"}"#.as_bytes(),Some("application/json"));assert_eq!(error["result"],"upstream_error");assert_eq!(error["message_class"],"already_signed");}
    #[test] fn fallback_retains_bytes(){let v=parse_response(b"oops",Some("text/plain"));assert_eq!(v["raw_evidence"]["data"],"b29wcw==");assert_eq!(v["raw_evidence"]["content_type"],"text/plain");}
    #[test] fn preview_requires_owner(){assert!(preview(SignIntent{operation:SignOperation::SignCurrentLesson,course_sched_id:"s".into(),owner_present:false},lesson(),15).is_err());}
    #[test] fn preview_cannot_authorize_unbound_commit(){let p=preview(SignIntent{operation:SignOperation::SignCurrentLesson,course_sched_id:"s".into(),owner_present:true},lesson(),15).unwrap();assert_eq!(p.value()["confirmation_available"],false);assert_eq!(p.value()["executable"],false);assert!(p.value().get("confirmation").is_none());}
    #[test] fn redirect_decoding(){assert_eq!(login_name("/?loginName=a%2Bb").unwrap().as_str(),"a+b");assert!(login_name("/?loginName=a&loginName=b").is_err());}
    #[test] fn explicit_unknown_time_format_refused(){let value=json!({"result":"success","response":{"result":[{"courseSchedId":"s","signStatus":"0","teachTime":"unknown-date","classBeginTime":"unknown","classEndTime":"unknown"}]}});assert!(verify_lesson(&value,&lesson(),false,&TimeFormat{datetime_formats:vec!["%Y-%m-%d %H:%M".into()],utc_offset_seconds:0}).is_err());}
    #[test] fn offline_entry_never_requests(){assert_eq!(run(r#"{"operation":"courses"}"#,false).unwrap()["result"],"blocked");assert_eq!(run(r#"{"operation":"preview","payload":null}"#,false).unwrap()["result"],"blocked");assert_eq!(run(r#"["login_name",{"session_cookie":"sid=opaque123"}]"#,false).unwrap()["reason"],"invalid_input");assert_eq!(run(r#"[{"session_cookie":"sid=opaque123"}]"#,false).unwrap()["reason"],"invalid_input");assert!(!run(r#"["login_name",{"session_cookie":"sid=opaque123"}]"#,false).unwrap().to_string().contains("opaque123"));}
    #[test] fn auth_and_commit_closed_before_client_creation(){for operation in ["login","commit"] {let v=run(&json!({"operation":operation}).to_string(),true).unwrap();assert_eq!(v["result"],"unsupported");assert_eq!(v["write_performed"],false);}}
    #[test] fn rejection_precedes_timestamp(){assert_eq!(parse_response(br#"{"STATUS":"401","timestamp":123}"#,Some("application/json"))["result"],"session_expired");assert_eq!(parse_response(br#"{"STATUS":"4001","timestamp":123}"#,Some("application/json"))["result"],"session_expired");assert_eq!(parse_response(br#"{"STATUS":"2","timestamp":123}"#,Some("application/json"))["result"],"empty");}
    #[test] fn sign_ack_is_not_verified_success(){for status in ["0","1","unknown"] {let wire=json!({"STATUS":"0","result":{"stuSignStatus":status}}).to_string();assert_eq!(parse_response(wire.as_bytes(),Some("application/json"))["result"],"postcondition_unknown");}}
    #[test] fn session_secrets_are_typed_and_not_cloned_into_value(){let s:Session=serde_json::from_str(r#"{"user_id":"fixture","login_name":"ephemeral","session_id":"token","header":"session_id"}"#).unwrap();let _: &Zeroizing<String>=&s.session_id;assert_eq!(s.login_name.as_str(),"ephemeral");}
    #[test] fn unsafe_body_never_enters_raw_fallback(){
        let body=br#"<form><input name="captcha" value="unsafe"></form>"#;
        let out=parse_response(body,Some("text/html"));assert_eq!(out["raw_evidence"]["data"],Value::Null);assert_eq!(out["raw_evidence"]["raw_withheld_reason"],"challenge_detected");assert!(!out.to_string().contains("unsafe"));
        let out=raw_evidence(b"ordinary prefix",Some("text/plain"),false);assert_eq!(out["data"],Value::Null);assert_eq!(out["raw_withheld_reason"],"response_safety_unreviewed");
    }
    #[test] fn session_echo_checks_cover_escaped_body_and_metadata(){
        assert!(response_contains_secret(br#"{"error":"echo private\"session"}"#,None,"private\"session"));
        assert!(response_contains_secret(b"safe",Some("text/plain; private-session"),"private-session"));
        assert!(!response_contains_secret(b"ordinary",Some("text/plain"),"private-session"));
        assert!(response_contains_cookie(b"echo cookie-value",None,"first=other; session=cookie-value"));
        let out=parse_response(b"new access_token=private-material",Some("text/plain"));assert_eq!(out["raw_evidence"]["data"],Value::Null);assert!(!out.to_string().contains("private-material"));
    }
    #[test] fn decoded_secrets_and_nonclear_mime_never_become_receipts(){
        assert!(response_contains_secret(br#"{"STATUS":"0","echo":"\u006fpaque123"}"#,Some("application/json"),"opaque123"));
        assert!(response_contains_secret(br#"{"\u006fpaque123":"value"}"#,Some("application/json"),"opaque123"));
        for body in [br#"{"STATUS":"0","access_token":"fresh-material"}"#.as_slice(),br#"{"STATUS":"0","\u0061ccess_token":"fresh-material"}"#.as_slice()]{let out=parse_response(body,Some("application/json"));assert_ne!(out["result"],"success");assert!(!out.to_string().contains("fresh-material"));}
        for mime in [None,Some("application/xhtml+xml")]{assert_ne!(parse_response(br#"{"STATUS":"0"}"#,mime)["result"],"success");}
        for online in [false,true]{let out=run(r#"{"operation":"login_name","payload":{"session_cookie":"sid=private-material"}}"#,online).unwrap();assert_eq!(out["result"],"unsupported");assert_eq!(out["network_performed"],false);assert!(!out.to_string().contains("private-material"));}
        assert!(serde_json::from_slice::<PrivateValue>(br#"{"first":"private","first":"duplicate"}"#).is_err());
    }
    #[test] fn sensitive_denial_still_latches_business_rejection(){
        let parsed=parse_response(br#"{"STATUS":"401","sessionId":"fresh-material"}"#,Some("application/json"));assert_ne!(parsed["result"],"success");
        use std::os::unix::fs::DirBuilderExt;let path=std::env::temp_dir().join(format!("checkin-sensitive-denial-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let governor=Governor::isolated_for_test(&path).unwrap();let lease=governor.try_acquire(crate::governor::RequestKind::Interactive).unwrap();let denial=session_denial(br#"{"STATUS":"401","sessionId":"fresh-material"}"#);assert!(denial);
        lease.finish(Outcome::Http{status:200,retry_after:Some("1800"),challenge:denial,network_failure:false}).unwrap();let state=governor.status().unwrap();assert!(state.safety_latched);assert!(state.cooldown_wait>std::time::Duration::from_secs(1700));drop(governor);std::fs::remove_dir_all(path).unwrap();
    }
    #[test] fn nested_shape_and_encoded_echo_contracts(){
        assert!(response_contains_secret(b"echo=abc%2B123",Some("text/plain"),"abc+123"));
        let out=parse_response(br#"{"STATUS":"0","sessionId":"freshopaque123"}"#,Some("application/json; proof=freshopaque123"));assert_eq!(out["raw_evidence"]["content_type"],"application/json");assert!(!out.to_string().contains("freshopaque123"));
        assert!(serde_json::from_str::<Session>(r#"["user","opaque123","opaque456","session_id"]"#).is_err());
        for input in [r#"{"operation":"courses","payload":{"session":["user","opaque123","opaque456","session_id"],"kind":"semesters"}}"#,r#"{"operation":"courses","payload":[["user","opaque123","opaque456","session_id"]]}"#]{let out=run(input,true).unwrap();assert_eq!(out["reason"],"invalid_input");assert!(!out.to_string().contains("opaque"));}
        assert_eq!(run(" \n {\"operation\":\"login_name\"} \t",true).unwrap()["network_performed"],false);
    }
    #[test] fn composed_encoding_and_independent_denials(){
        assert_eq!(raw_evidence(b"%61%63%63%65%73%73%5F%74%6F%6B%65%6E=opaqueABC123",Some("application/x-www-form-urlencoded"),true)["data"],Value::Null);
        assert!(response_contains_secret(br#"{"STATUS":"0","echo":"abc%2B\u0031\u0032\u0033"}"#,Some("application/json"),"abc+123"));
        assert!(session_denial(br#"{"STATUS":"401","note":"a","note":"b"}"#));assert!(session_denial(br#"{"note":"a","note":"b","STATUS":"4001"}"#));
        let mut headers=reqwest::header::HeaderMap::new();headers.append("content-type",reqwest::header::HeaderValue::from_static("text/plain"));headers.append("content-type",reqwest::header::HeaderValue::from_static("text/html"));let mime=response_content_type(&headers);assert!(mime.is_none());assert_ne!(crate::html::assess_challenge_body(b"<input name=captcha>",mime.as_deref(),true),crate::html::ChallengeAssessment::Clear);
    }
    #[test] fn cached_observation_fences_checkin_send(){
        use std::os::unix::fs::DirBuilderExt;let path=std::env::temp_dir().join(format!("checkin-fence-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let governor=Governor::isolated_for_test(&path).unwrap();let mut lease=governor.try_acquire(crate::governor::RequestKind::Interactive).unwrap();crate::governor::publish_cached_challenge_for_test(&path).unwrap();let mut sent=false;
        assert!(matches!(lease.start_request(||{sent=true;}),Err(crate::governor::FollowupError::CachedChallenge)));assert!(!sent);lease.finish(Outcome::SafetyObserved).unwrap();let state=governor.status().unwrap();assert!(state.safety_latched);assert_eq!(state.consecutive_network_failures,0);drop(governor);std::fs::remove_dir_all(path).unwrap();
    }
}
