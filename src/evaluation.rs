//! SPOC evaluation primitives. Answers and all scoring metadata are supplied by
//! the owner; this module never generates an answer or a score. Each operation
//! is one request (no retries, pagination loops, or automatic CAS redirects).
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crate::governor::{FollowupError, Governor, Outcome, RequestKind};
use crate::html::{ChallengeAssessment, assess_challenge_body};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

pub const BASE: &str = "https://spoc.buaa.edu.cn/pjxt/";
const MAX_BODY: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Task { pub rwid: String, pub rwmc: String }
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Questionnaire { pub wjid: String, pub wjmc: String, pub rwmc: String, pub msid: Option<String> }
impl<'de> Deserialize<'de> for Questionnaire {
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
        #[derive(Deserialize)] struct Fields { wjid:String,wjmc:String,rwmc:String,msid:Option<String> }
        let v:Fields=deserialize_map(deserializer)?;
        Ok(Self{wjid:v.wjid,wjmc:v.wjmc,rwmc:v.rwmc,msid:v.msid})
    }
}
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Answer { pub topic: String, pub options: Vec<String> }
impl<'de> Deserialize<'de> for Answer {
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
        #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Fields { topic:String,options:Vec<String> }
        let v:Fields=deserialize_map(deserializer)?; Ok(Self{topic:v.topic,options:v.options})
    }
}
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub rwid: String,
    pub wjid: String,
    /// Exact course row returned by getRequiredReviewsData.
    pub course: Value,
    /// Exact pjjg entry metadata supplied by the owner, excluding pjxxlist.
    /// In particular pjdf is explicit, never inferred from option scores.
    pub metadata: Value,
    pub answers: Vec<Answer>,
}
impl<'de> Deserialize<'de> for Intent {
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
        #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Fields { rwid:String,wjid:String,course:Value,metadata:Value,answers:Vec<Answer> }
        let v:Fields=deserialize_map(deserializer)?;
        Ok(Self{rwid:v.rwid,wjid:v.wjid,course:v.course,metadata:v.metadata,answers:v.answers})
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub raw_base64: Option<String>, pub content_type: Option<String>,
    pub bytes: usize, pub sha256: String, pub fallback_reason: String,
    pub raw_provenance: &'static str,
}
#[derive(Debug)]
pub enum Error { Invalid(&'static str), Local(String), Remote(Evidence), Unsupported(&'static str) }
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn deserialize_map<'de,T,D>(deserializer:D)->Result<T,D::Error>
where T:Deserialize<'de>, D:serde::Deserializer<'de> {
    struct MapOnly<T>(std::marker::PhantomData<T>);
    impl<'de,T:Deserialize<'de>> serde::de::Visitor<'de> for MapOnly<T> {
        type Value=T;
        fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("a JSON object")}
        fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<T,A::Error>{T::deserialize(serde::de::value::MapAccessDeserializer::new(access))}
        fn visit_seq<A>(self,_:A)->Result<T,A::Error> where A:serde::de::SeqAccess<'de> { Err(serde::de::Error::invalid_type(serde::de::Unexpected::Seq,&self)) }
    }
    deserializer.deserialize_map(MapOnly(std::marker::PhantomData))
}
fn sensitive_material(bytes: &[u8]) -> bool {
    [b"password".as_slice(), b"passwd", b"credential", b"cookie", b"authorization", b"token", b"ticket", b"secret", b"session", b"csrf", b"xsrf", b"private_key"]
        .iter().any(|marker| bytes.windows(marker.len()).any(|part| part.eq_ignore_ascii_case(marker)))
}
fn cookie_material(bytes: &[u8], cookie: &str) -> bool {
    cookie.split(';').map(str::trim).filter(|part| !part.is_empty()).any(|part| {
        crate::net::carries_secret(bytes,part)
            || part.split_once('=').is_some_and(|(_, value)| {
                let value=value.trim();
                crate::net::carries_secret(bytes,value)
                    || value.strip_prefix('"').and_then(|inner|inner.strip_suffix('"'))
                        .is_some_and(|unquoted|crate::net::carries_secret(bytes,unquoted))
            })
    })
}
fn sensitive_json(value: &Value, cookie: &str) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key,value)| sensitive_material(key.as_bytes()) || cookie_material(key.as_bytes(),cookie) || sensitive_json(value,cookie)),
        Value::Array(values) => values.iter().any(|value| sensitive_json(value,cookie)),
        Value::String(value) => sensitive_material(value.as_bytes()) || cookie_material(value.as_bytes(),cookie),
        Value::Number(_) => crate::net::json_scalar_matches(value,|bytes|cookie_material(bytes,cookie)),
        _ => false,
    }
}
/// Response wrapper retains legal JSON arrays while rejecting duplicate
/// object keys and recursively wiping key/value strings when dropped.
struct PrivateValue(Value);
impl<'de> Deserialize<'de> for PrivateValue {
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D) -> Result<Self,D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
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
                let mut result=PrivateValue(Value::Array(Vec::new()));
                while let Some(mut value)=access.next_element::<PrivateValue>()? { result.0.as_array_mut().unwrap().push(std::mem::take(&mut value.0)); }
                Ok(result)
            }
            fn visit_map<A:serde::de::MapAccess<'de>>(self,mut access:A)->Result<Self::Value,A::Error>{
                let mut result=PrivateValue(Value::Object(serde_json::Map::new()));
                while let Some(key)=access.next_key::<String>()? {
                    let mut key=Zeroizing::new(key);
                    let values=result.0.as_object_mut().unwrap();
                    if values.contains_key(key.as_str()) { return Err(serde::de::Error::custom("duplicate JSON key")); }
                    let mut value=access.next_value::<PrivateValue>()?;
                    values.insert(std::mem::take(&mut *key),std::mem::take(&mut value.0));
                }
                Ok(result)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
impl Drop for PrivateValue {
    fn drop(&mut self) {
        fn wipe(value:&mut Value) {
            match value {
                Value::String(text)=>text.zeroize(),
                Value::Array(values)=>values.iter_mut().for_each(wipe),
                Value::Object(values)=>for(mut key,mut value) in std::mem::take(values) { key.zeroize(); wipe(&mut value); },
                _=>{},
            }
        }
        wipe(&mut self.0);
    }
}
impl std::ops::Deref for PrivateValue {
    type Target=Value;
    fn deref(&self)->&Value { &self.0 }
}
fn safe_response(endpoint: &str, value: &Value, cookie: &str) -> Result<Value, String> {
    if session_denied(value) { return Err("application rejected the session; admission refused".into()); }
    if sensitive_json(value,cookie) { return Err("structured response contains sensitive material; admission refused".into()); }
    let value=match endpoint {
        "personnelEvaluation/listObtainPersonnelEvaluationTasks" => {
            let (tasks,total)=parse_tasks(value).map_err(|_| "response task contract unreviewed; admission refused".to_string())?;
            json!({"result":{"list":tasks,"total":total}})
        }
        "component/queryDaiBan" => Value::Array(value.as_array().ok_or("response pending contract unreviewed; admission refused")?.iter().map(|_|json!({})).collect()),
        "evaluationMethodSix/getQuestionnaireListToTask" => json!({"result":parse_questionnaires(value).map_err(|_| "response questionnaire contract unreviewed; admission refused")?}),
        "evaluationMethodSix/getRequiredReviewsData" => {
            let rows=value.get("result").and_then(Value::as_array).ok_or("response course contract unreviewed; admission refused")?;
            let rows=rows.iter().map(|row| {
                for key in ["rwid","wjid","kcdm","bpdm"] { text(row,key).map_err(|_|"response course identity unreviewed; admission refused")?; }
                for key in ["ypjcs","xypjcs"] { if !row.get(key).is_some_and(|v|v.is_number()||v.as_str().is_some_and(|v|v.parse::<u64>().is_ok())) { return Err("response course counts unreviewed; admission refused"); } }
                let mut fields=serde_json::Map::new();
                for key in ["id","rwid","wjid","zdmc","ypjcs","xypjcs","sxz","pjrdm","pjrmc","bpdm","bpmc","kcdm","kcmc","rwh","xn","xq","xnxq","pjlxid","sfksqbpj","yxsfktjst"] {
                    if let Some(value)=row.get(key) { if !value.is_string()&&!value.is_number() { return Err("response course scalar unreviewed; admission refused"); } fields.insert(key.into(),value.clone()); }
                }
                Ok(Value::Object(fields))
            }).collect::<Result<Vec<_>,_>>()?;
            json!({"result":rows})
        }
        "evaluationMethodSix/getQuestionnaireTopic" => {
            let rows=value.get("result").and_then(Value::as_array).ok_or("response topic contract unreviewed; admission refused")?;
            let rows=rows.iter().map(|row| {
                let groups=row.pointer("/pjxtWjWjbReturnEntity/wjzblist").and_then(Value::as_array).ok_or("response topic contract unreviewed; admission refused")?;
                let groups=groups.iter().map(|group| {
                    let topics=group.get("tklist").and_then(Value::as_array).ok_or("response topic list unreviewed; admission refused")?;
                    let topics=topics.iter().map(|topic| {
                        let id=text(topic,"tmid").map_err(|_|"response topic identity unreviewed; admission refused")?;
                        let kind=topic.get("tmlx").filter(|v|v.is_string()||v.is_number()).ok_or("response topic kind unreviewed; admission refused")?;
                        let options=topic.get("tmxxlist").and_then(Value::as_array).ok_or("response topic options unreviewed; admission refused")?;
                        let options=options.iter().map(|option|text(option,"tmxxid").map(|id|json!({"tmxxid":id})).map_err(|_|"response option identity unreviewed; admission refused")).collect::<Result<Vec<_>,_>>()?;
                        Ok(json!({"tmid":id,"tmlx":kind,"tmxxlist":options}))
                    }).collect::<Result<Vec<_>,&str>>()?;
                    Ok(json!({"tklist":topics}))
                }).collect::<Result<Vec<_>,&str>>()?;
                let map=row.get("pjmap").filter(|v|v.is_string()||v.is_number()).ok_or("response topic map unreviewed; admission refused")?;
                Ok(json!({"pjmap":map,"pjxtWjWjbReturnEntity":{"wjzblist":groups}}))
            }).collect::<Result<Vec<_>,&str>>()?;
            json!({"result":rows})
        }
        _=>return Err("response endpoint contract unreviewed; admission refused".into()),
    };
    if sensitive_json(&value,cookie) { return Err("projected response contains sensitive material; admission refused".into()); }
    Ok(value)
}
fn session_denied(value:&Value)->bool {
    ["msg","message"].iter().filter_map(|key|value.get(*key).and_then(Value::as_str)).any(|message|matches!(message.trim(),"请重新登录"|"请先登录"|"未登录"|"登录已失效"|"登录已过期"|"会话已过期"|"会话失效"|"not logged in"|"session expired"|"unauthorized"))
}
fn evidence(bytes: &[u8], content_type: Option<String>, reason: &str, assessment: ChallengeAssessment, challenge: bool, complete: bool, cookie: &str, authenticated: bool) -> Evidence {
    let raw_provenance = if challenge { "withheld_confirmed_challenge" }
        else if !complete { "withheld_incomplete_body" }
        else if assessment == ChallengeAssessment::Unreviewed { "withheld_unreviewed_body" }
        // Clear is challenge admission, not a proof that an authenticated
        // response contains no unlabeled credentials or opaque session tokens.
        else if authenticated { "withheld_authenticated_response" }
        else if sensitive_material(bytes) || cookie_material(bytes,cookie) || serde_json::from_slice::<PrivateValue>(bytes).is_ok_and(|value| sensitive_json(&value,cookie)) { "withheld_sensitive_material" }
        else { "complete_response_body" };
    Evidence { raw_base64: (raw_provenance == "complete_response_body").then(|| STANDARD.encode(bytes)),
        content_type: content_type.and_then(|value| match value.split(';').next().unwrap_or("").trim().to_ascii_lowercase().as_str() { "application/json"=>Some("application/json".into()),"text/html"=>Some("text/html".into()),"text/plain"=>Some("text/plain".into()),"application/xhtml+xml"=>Some("application/xhtml+xml".into()),_=>None }),
        bytes: bytes.len(), sha256: digest(bytes), fallback_reason: reason.into(), raw_provenance }
}
/// Complete admitted/refused result for one response, computed before the
/// original lease settles. A Set-Cookie response returns only fixed
/// diagnostics; response MIME, body-derived evidence and cookie values stay private.
struct ResponseAdmission<'a> {
    bytes: &'a [u8],
    content_type: Option<String>,
    status: u16,
    assessment: ChallengeAssessment,
    challenge: bool,
    complete: bool,
    read_failed: bool,
    issued: bool,
    denied: bool,
    retry_present: bool,
    cookie: &'a str,
    endpoint: &'a str,
    session: bool,
    parsed: Option<PrivateValue>,
}
fn admission(response: ResponseAdmission<'_>) -> Result<Value, Error> {
    let ResponseAdmission { bytes,content_type,status,assessment,challenge,complete,
        read_failed,issued,denied,retry_present,cookie,endpoint,session,parsed }=response;
    let refusal = if read_failed { Some("response body read failed; admission refused") }
        else if !complete { Some("response exceeds body limit; admission refused") }
        else if challenge { Some("confirmed response challenge; admission refused") }
        else if assessment == ChallengeAssessment::Unreviewed { Some("response body assessment unreviewed; admission refused without a confirmed challenge") }
        else if denied { Some("application rejected the session; admission refused") }
        else if retry_present { Some("response requested cooldown; no automatic retry") }
        else if !(200..300).contains(&status) { Some("HTTP response refused; redirects and automatic retries disabled") }
        else { None };
    if issued {
        return Err(Error::Invalid(refusal.unwrap_or("response issued session cookie; body admission refused")));
    }
    if let Some(reason) = refusal {
        return Err(Error::Remote(evidence(bytes,content_type,reason,assessment,challenge,complete,cookie,challenge||assessment==ChallengeAssessment::Unreviewed||!cookie.is_empty())));
    }
    if session { return Ok(json!({"initialized":false,"session_acceptance":"unknown","reason":"HTTP success alone does not prove authenticated CAS session acceptance"})); }
    match parsed {
        None => Err(Error::Remote(evidence(bytes,content_type,"response is not structured JSON",assessment,challenge,complete,cookie,true))),
        Some(value) => safe_response(endpoint,&value,cookie)
            .map_err(|reason|Error::Remote(evidence(bytes,content_type,&reason,assessment,false,true,cookie,true)))
            .map(|admitted|{ drop(value); admitted }),
    }
}
fn response_challenge(headers: &reqwest::header::HeaderMap) -> bool {
    headers.iter().any(|(name,value)|crate::net::challenge_header(name.as_str(),value.as_bytes()))
}
fn response_content_type(headers:&reqwest::header::HeaderMap)->Option<&str> {
    let mut values=headers.get_all(reqwest::header::CONTENT_TYPE).iter();
    let first=values.next()?.to_str().ok()?;
    // Multiple declarations have no source-established combined MIME meaning.
    if values.next().is_some() { return None; }
    Some(first)
}
const MUTATION_BLOCKED: &str = "evaluation mutation blocked before network: trusted read-only endpoint evidence is absent, and the mutation workflow lacks account/target-bound immutable plan/commit authorization, source-authorized durable atomic idempotency, and an authorized postcondition; a caller-injected SubmissionLedger is not source authorization";
pub fn legacy() -> Error { Error::Unsupported("legacy JWXT evaluation requires plaintext HTTP; HTTPS downgrade forbidden") }
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or(Error::Invalid("missing string identifier"))
}
pub fn parse_tasks(value: &Value) -> Result<(Vec<Task>, u64), Error> {
    let result = value.get("result").ok_or(Error::Invalid("missing result"))?;
    let rows = result.get("list").and_then(Value::as_array).ok_or(Error::Invalid("missing task list"))?;
    let tasks = rows.iter().map(|v| Ok(Task { rwid: text(v,"rwid")?.into(), rwmc: text(v,"rwmc")?.into() })).collect::<Result<_,Error>>()?;
    Ok((tasks, result.get("total").and_then(Value::as_u64).ok_or(Error::Invalid("missing total"))?))
}
pub fn parse_questionnaires(value: &Value) -> Result<Vec<Questionnaire>, Error> {
    Vec::<Questionnaire>::deserialize(value.get("result").ok_or(Error::Invalid("missing result"))?).map_err(|_| Error::Invalid("invalid questionnaires"))
}
pub fn parse_courses(value: &Value) -> Result<Vec<Value>, Error> {
    let rows = value.get("result").and_then(Value::as_array).ok_or(Error::Invalid("invalid courses"))?;
    for row in rows { for key in ["rwid","wjid","kcdm","bpdm"] { text(row,key)?; } if row.get("ypjcs").is_none() || row.get("xypjcs").is_none() { return Err(Error::Invalid("missing evaluation counts")); } }
    Ok(rows.clone())
}
pub fn has_pending(value: &Value) -> Result<bool, Error> { value.as_array().map(|v| !v.is_empty()).ok_or(Error::Invalid("invalid pending array")) }
pub fn success(value: &Value) -> bool { value.get("msg").and_then(Value::as_str) == Some("成功") }

/// Pattern identity for offline preview binding, not authenticated mutation proof.
pub struct Pattern { rwid: String, wjid: String }
/// Immutable, digest-bound preview. No mutating access to its submission body.
pub struct Preview { body: Value, digest: String, idempotency_key: String, intent: Intent }
impl Preview {
    pub fn body(&self) -> &Value { &self.body }
    pub fn digest(&self) -> &str { &self.digest }
    pub fn idempotency_key(&self) -> &str { &self.idempotency_key }
    pub fn intent(&self) -> &Intent { &self.intent }
}
/// Caller bookkeeping alone cannot establish source authorization. Submission
/// remains blocked even when an implementation claims durable atomic storage.
pub trait SubmissionLedger {
    fn claim(&mut self, key: &str, explicit_reconfirmation: bool) -> Result<(), String>;
}

pub fn prepare(intent: Intent, topics: &Value, pattern: &Pattern) -> Result<Preview, Error> {
    if intent.rwid != pattern.rwid || intent.wjid != pattern.wjid || text(&intent.course,"rwid")? != intent.rwid || text(&intent.course,"wjid")? != intent.wjid { return Err(Error::Invalid("pattern/course identity mismatch")); }
    let result = topics.get("result").and_then(Value::as_array).filter(|r| r.len()==1).ok_or(Error::Invalid("ambiguous topic result"))?;
    let groups = result[0].pointer("/pjxtWjWjbReturnEntity/wjzblist").and_then(Value::as_array).ok_or(Error::Invalid("missing topic groups"))?;
    let mut seen = BTreeSet::new(); let mut responses = Vec::new();
    for group in groups {
        for topic in group.get("tklist").and_then(Value::as_array).ok_or(Error::Invalid("missing topics"))? {
            let id = text(topic,"tmid")?;
            if !seen.insert(id.to_owned()) { return Err(Error::Invalid("duplicate topic")); }
            let answers: Vec<_> = intent.answers.iter().filter(|a| a.topic == id).collect();
            if answers.len()!=1 { return Err(Error::Invalid("exactly one explicit answer required per topic")); }
            let answer = answers[0];
            let options = topic.get("tmxxlist").and_then(Value::as_array).ok_or(Error::Invalid("missing options"))?;
            let choice = topic.get("tmlx").is_some_and(|v| v=="1" || v==1);
            let (kind, context) = if choice {
                let mut unique = BTreeSet::new();
                if answer.options.is_empty() || answer.options.iter().any(|a| !unique.insert(a) || !options.iter().any(|o| o.get("tmxxid").and_then(Value::as_str)==Some(a))) { return Err(Error::Invalid("invalid explicit option")); }
                ("1", "")
            } else {
                if answer.options != [String::new()] { return Err(Error::Invalid("unsupported free-text answer contract")); }
                ("6", text(options.first().ok_or(Error::Invalid("missing free-text context"))?,"tmxxid")?)
            };
            responses.push(json!({"sjly":"1","stlx":kind,"wjid":intent.wjid,"wjstctid":context,"wjstid":id,"xxdalist":answer.options}));
        }
    }
    if seen.is_empty() || seen.len()!=intent.answers.len() { return Err(Error::Invalid("extra or missing answers")); }
    let mut metadata = intent.metadata.as_object().cloned().ok_or(Error::Invalid("metadata must be object"))?;
    const FIELDS: &[&str] = &["bprdm","bprmc","kcdm","kcmc","pjdf","pjfs","pjid","pjlx","pjmap","pjrdm","pjrjsdm","pjrxm","pjsx","rwh","stzjid","wjid","wjssrwid","wtjjy","xhgs","xnxq","sfxxpj","sqzt","yxfz","zsxz","sfnm"];
    if metadata.len()!=FIELDS.len() || FIELDS.iter().any(|k| !metadata.contains_key(*k)) { return Err(Error::Invalid("explicit complete submission metadata required")); }
    for (field, expected) in [("wjid",intent.wjid.as_str()),("wjssrwid",intent.rwid.as_str()),("kcdm",text(&intent.course,"kcdm")?),("bprdm",text(&intent.course,"bpdm")?)] {
        if metadata.get(field).and_then(Value::as_str)!=Some(expected) { return Err(Error::Invalid("submission metadata identity mismatch")); }
    }
    if metadata.get("pjmap") != result[0].get("pjmap") { return Err(Error::Invalid("pjmap mismatch")); }
    metadata.insert("pjxxlist".into(), Value::Array(responses));
    let body = json!({"pjidlist":[],"pjjglist":[metadata],"pjzt":"1"});
    let mut canonical_answers = intent.answers.clone();
    canonical_answers.sort_by(|a,b|a.topic.cmp(&b.topic));
    for answer in &mut canonical_answers { answer.options.sort(); }
    let idempotency_key = digest(&serde_json::to_vec(&json!([intent.rwid,intent.wjid,canonical_answers])).map_err(|_| Error::Invalid("serialization"))?);
    let digest = digest(&serde_json::to_vec(&body).map_err(|_| Error::Invalid("serialization"))?);
    Ok(Preview { body, digest, idempotency_key, intent })
}

pub struct Client { http: reqwest::blocking::Client, cookie: Zeroizing<String>, governor: Governor }
impl Client {
    /// Cookie must be obtained from stdin/keyring, not command-line arguments.
    pub fn new(cookie: String) -> Result<Self, Error> {
        Self::with_secret(Zeroizing::new(cookie))
    }
    fn with_secret(cookie: Zeroizing<String>) -> Result<Self, Error> {
        if cookie.is_empty() || cookie.contains(['\r','\n']) { return Err(Error::Invalid("invalid session cookie")); }
        let http = reqwest::blocking::Client::builder().redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never()).timeout(std::time::Duration::from_secs(30)).build().map_err(|_| Error::Invalid("client initialization"))?;
        Ok(Self { http, cookie, governor: Governor::open().map_err(Error::Local)? })
    }
    fn request(&self, endpoint: &str, query: &[(&str,String)], body: Option<&Value>, session: bool) -> Result<Value, Error> {
        let url = Url::parse(BASE).and_then(|u| u.join(endpoint)).map_err(|_| Error::Invalid("invalid endpoint"))?;
        if url.scheme()!="https" || url.host_str()!=Some("spoc.buaa.edu.cn") || !url.path().starts_with("/pjxt/") { return Err(legacy()); }
        if matches!(endpoint,"evaluationMethodSix/confirmQuestionnairePattern"|"evaluationMethodSix/reviseQuestionnairePattern"|"evaluationMethodSix/submitSaveEvaluation") { return Err(Error::Invalid(MUTATION_BLOCKED)); }
        let mut cookie = reqwest::header::HeaderValue::from_str(self.cookie.as_str()).map_err(|_| Error::Invalid("invalid session cookie"))?;
        cookie.set_sensitive(true);
        let mut lease = self.governor.try_acquire(RequestKind::Interactive).map_err(Error::Local)?;
        let builder = if let Some(body)=body { self.http.post(url).json(body).timeout(std::time::Duration::from_secs(30)) } else { self.http.get(url).timeout(std::time::Duration::from_secs(30)) };
        let request=builder.query(query).header(reqwest::header::COOKIE,cookie);
        let response = match lease.start_request(||request.send()) {
            Ok(Ok(response))=>response,
            Ok(Err(_))=>{ lease.finish(Outcome::NetworkFailure).map_err(Error::Local)?; return Err(Error::Invalid("network failure")); }
            Err(FollowupError::Governor(_))=>return Err(Error::Invalid("governor request-start admission failed; request not sent; pending reservation retained")),
        };
        let status = response.status().as_u16();
        let retry = response.headers().get(reqwest::header::RETRY_AFTER).and_then(|value|value.to_str().ok()).map(str::to_owned);
        let retry_present = response.headers().contains_key(reqwest::header::RETRY_AFTER);
        let content_type = response_content_type(response.headers()).map(str::to_owned);
        // Observe all raw headers before consuming the response; do not filter
        // challenge headers into an allowlisted receipt before classification.
        let header_challenge = response_challenge(response.headers());
        // Issuance alone is not a challenge or an authentication rejection.
        let issued = crate::net::issues_session_cookie(response.headers());
        lease.observe_http_many(status,response.headers().get_all(reqwest::header::RETRY_AFTER).iter().map(|value|value.to_str().ok()),header_challenge).map_err(Error::Local)?;
        let declared_oversize = response.content_length().is_some_and(|length| length > MAX_BODY);
        let mut bytes = Zeroizing::new(Vec::new());
        let read = response.take(MAX_BODY+1).read_to_end(&mut bytes);
        let oversize = declared_oversize || bytes.len() as u64 > MAX_BODY;
        let complete = read.is_ok() && !oversize;
        let assessment = assess_challenge_body(&bytes, content_type.as_deref(), complete);
        let challenge = header_challenge || assessment == ChallengeAssessment::Detected;
        let parsed=if complete { serde_json::from_slice::<PrivateValue>(&bytes).ok() } else { None };
        let denied=parsed.as_ref().is_some_and(|value|session_denied(value));
        // Compute the complete admitted/refused result before settlement.
        let admission=admission(ResponseAdmission {bytes:&bytes,content_type,status,assessment,challenge,complete,
            read_failed:read.is_err(),issued,denied,retry_present,cookie:self.cookie.as_str(),endpoint,session,parsed});
        // Settle the original lease once with every independent observed fact.
        if denied {
            lease.observe_http(status,retry.as_deref(),challenge).map_err(Error::Local)?;
            lease.finish(Outcome::CredentialRejected).map_err(Error::Local)?;
        // The complete header set is already durable. Final HTTP settlement
        // cannot shorten its maximum cooldown, including on body failure.
        } else { lease.finish(Outcome::Http { status, retry_after:retry.as_deref(), challenge, network_failure:!complete }).map_err(Error::Local)?; }
        admission
    }
    pub fn initialize(&self) -> Result<Value,Error> { self.request("cas",&[],None,true) }
    pub fn tasks(&self, student: &str, page: u32) -> Result<Value,Error> { self.request("personnelEvaluation/listObtainPersonnelEvaluationTasks",&[("yhdm",student.into()),("pageNum",page.to_string()),("pageSize","10".into())],None,false) }
    pub fn pending(&self) -> Result<Value,Error> { self.request("component/queryDaiBan",&[],Some(&json!({})),false) }
    pub fn questionnaires(&self,rwid:&str) -> Result<Value,Error> { self.request("evaluationMethodSix/getQuestionnaireListToTask",&[("rwid",rwid.into()),("pageNum","1".into()),("pageSize","999".into())],None,false) }
    /// Pattern endpoints are not source-proven read-only or mutation-authorized.
    pub fn confirm_pattern(&self,_rwid:&str,_wjid:&str) -> Result<Value,Error> { Err(Error::Invalid(MUTATION_BLOCKED)) }
    pub fn revise_pattern(&self,_rwid:&str,_questionnaire:&Questionnaire) -> Result<Pattern,Error> {
        Err(Error::Invalid(MUTATION_BLOCKED))
    }
    pub fn courses(&self,wjid:&str) -> Result<Value,Error> { self.request("evaluationMethodSix/getRequiredReviewsData",&[("wjid",wjid.into()),("sfyp","0".into()),("xnxq","".into()),("pageNum","1".into()),("pageSize","999".into())],None,false) }
    pub fn topics(&self,pattern:&Pattern,course:&Value,yxdm:&str) -> Result<Value,Error> {
        if text(course,"rwid")?!=pattern.rwid || text(course,"wjid")?!=pattern.wjid { return Err(Error::Invalid("pattern identity mismatch")); }
        let mut query=Vec::new();
        for key in ["id","rwid","wjid","zdmc","ypjcs","xypjcs","sxz","pjrdm","pjrmc","bpdm","bpmc","kcdm","kcmc","rwh","xn","xq","xnxq","pjlxid","sfksqbpj","yxsfktjst"] {
            let value=course.get(key).ok_or(Error::Invalid("incomplete course query"))?;
            let string=match value { Value::String(s)=>s.clone(),Value::Number(n)=>n.to_string(),_=>return Err(Error::Invalid("invalid course query scalar")) };
            query.push((key,string));
        }
        query.push(("yxdm",yxdm.into())); self.request("evaluationMethodSix/getQuestionnaireTopic",&query,None,false)
    }
    /// A caller-provided ledger does not establish source authorization.
    pub fn submit(&self,_preview:&Preview,_confirmation:&str,_reconfirmation:bool,_ledger:&mut impl SubmissionLedger) -> Result<Value,Error> {
        Err(Error::Invalid(MUTATION_BLOCKED))
    }
    pub fn verify_postcondition(&self,preview:&Preview) -> Result<bool,Error> {
        let rows=parse_courses(&self.courses(&preview.intent.wjid)?)?;
        postcondition(&preview.intent.course,&rows)
    }
}
pub fn postcondition(course:&Value,rows:&[Value]) -> Result<bool,Error> {
    let matches:Vec<_>=rows.iter().filter(|r| ["rwid","wjid","kcdm","bpdm","rwh"].iter().all(|k|r.get(*k)==course.get(*k))).collect();
    if matches.len()!=1 { return Ok(false); }
    let row=matches[0];
    let count=|k| row.get(k).and_then(|v|v.as_u64().or_else(||v.as_str().and_then(|s|s.parse::<u64>().ok())));
    Ok(matches!((count("ypjcs"),count("xypjcs")),(Some(a),Some(b)) if b>0 && a==b))
}
#[derive(Deserialize)]
#[serde(tag="operation", rename_all="snake_case", deny_unknown_fields)]
enum Command {
    Tasks { student: String, page: u32, #[serde(default, deserialize_with="optional_cookie")] session_cookie: Option<Zeroizing<String>>, source: Option<Value> },
    Questionnaires { rwid: String, #[serde(default, deserialize_with="optional_cookie")] session_cookie: Option<Zeroizing<String>>, source: Option<Value> },
    Courses { wjid: String, #[serde(default, deserialize_with="optional_cookie")] session_cookie: Option<Zeroizing<String>>, source: Option<Value> },
    Topics { rwid: String, questionnaire: Questionnaire, course: Value, yxdm: String, #[serde(default, deserialize_with="optional_cookie")] session_cookie: Option<Zeroizing<String>>, source: Option<Value> },
    Prepare { intent: Intent, topics: Value },
    Submit { intent: Intent, topics: Value, confirmation: String, reconfirmation: bool, #[serde(default, deserialize_with="optional_cookie")] session_cookie: Option<Zeroizing<String>> },
    Verify { course: Value, #[serde(default, deserialize_with="optional_cookie")] session_cookie: Option<Zeroizing<String>>, source: Option<Value> },
    Legacy,
}
fn optional_cookie<'de,D:serde::Deserializer<'de>>(deserializer:D) -> Result<Option<Zeroizing<String>>,D::Error> {
    Option::<String>::deserialize(deserializer).map(|cookie| cookie.map(Zeroizing::new))
}
fn parse_command(input:&str)->Result<Command,Error> {
    let mut value=serde_json::from_str::<PrivateValue>(input).map_err(|_|Error::Invalid("invalid evaluation command"))?;
    let cookie=match value.0.get_mut("session_cookie") {
        Some(slot)=>match slot {
            Value::String(text)=>Some(Zeroizing::new(std::mem::take(text))),
            Value::Null=>None,
            _=>return Err(Error::Invalid("invalid evaluation command")),
        },
        None=>None,
    };
    // The internally tagged enum never buffers the decoded cookie. The
    // protected original owns every other temporary until parsing completes.
    if let Some(slot)=value.0.get_mut("session_cookie") { *slot=Value::Null; }
    let mut command=Command::deserialize(&value.0).map_err(|_|Error::Invalid("invalid evaluation command"))?;
    match &mut command {
        Command::Tasks{session_cookie,..}|Command::Questionnaires{session_cookie,..}|Command::Courses{session_cookie,..}|Command::Topics{session_cookie,..}|Command::Submit{session_cookie,..}|Command::Verify{session_cookie,..}=>*session_cookie=cookie,
        _=>{},
    }
    Ok(command)
}
fn blocked(reason: &str) -> Value { json!({"status":"blocked","reason":reason}) }
fn report(error: Error) -> Value {
    match error {
        Error::Remote(e)=>json!({"status":"blocked","reason":"remote response refused","evidence":e}),
        Error::Unsupported(reason)=>json!({"status":"unsupported","reason":reason}),
        Error::Invalid(reason)=>blocked(reason), Error::Local(reason)=>blocked(&reason),
    }
}
fn source_or_fetch(source: Option<Value>, online: bool, cookie: Option<Zeroizing<String>>, fetch: impl FnOnce(&Client)->Result<Value,Error>) -> Result<Value,Error> {
    if let Some(source)=source { return Ok(source); }
    if !online { return Err(Error::Invalid("offline operation requires source response")); }
    let client=Client::with_secret(cookie.ok_or(Error::Invalid("session_cookie required for online request"))?)?;
    fetch(&client)
}
fn topic_structure(value:&Value) -> Result<(),Error> {
    let rows=value.get("result").and_then(Value::as_array).ok_or(Error::Invalid("missing topic result"))?;
    if rows.is_empty() || rows.iter().any(|row| !row.pointer("/pjxtWjWjbReturnEntity/wjzblist").is_some_and(Value::is_array)) { return Err(Error::Invalid("invalid topic response")); }
    Ok(())
}
/// JSON stdin dispatcher. Submission is blocked before client construction:
/// neither this dispatcher nor a caller-supplied ledger proves source authority.
pub fn run(input:&str, online:bool) -> Result<Value,Error> {
    let result=(|| {
        if input.len()>MAX_BODY as usize { return Err(Error::Invalid("input exceeds limit")); }
        let command=parse_command(input)?;
        match command {
            Command::Tasks {student,page,session_cookie,source}=>{
                let source=source_or_fetch(source,online,session_cookie,|c|c.tasks(&student,page))?;
                let (tasks,total)=parse_tasks(&source)?; Ok(json!({"status":"ok","tasks":tasks,"total":total}))
            }
            Command::Questionnaires {rwid,session_cookie,source}=>{
                let source=source_or_fetch(source,online,session_cookie,|c|c.questionnaires(&rwid))?;
                Ok(json!({"status":"ok","questionnaires":parse_questionnaires(&source)?}))
            }
            Command::Courses {wjid,session_cookie,source}=>{
                let source=source_or_fetch(source,online,session_cookie,|c|c.courses(&wjid))?;
                Ok(json!({"status":"ok","courses":parse_courses(&source)?}))
            }
            Command::Topics {rwid,questionnaire,course,yxdm,session_cookie,source}=>{
                if text(&course,"rwid")?!=rwid || text(&course,"wjid")?!=questionnaire.wjid || yxdm.is_empty() { return Err(Error::Invalid("topic identity mismatch")); }
                // A serialized boolean cannot attest a remote pattern mutation.
                // No live pattern mutation is currently source-authorized.
                let _=session_cookie;
                let source=source.ok_or(Error::Invalid("topics requires source; live pattern mutation is not source-authorized"))?;
                topic_structure(&source)?;
                Ok(json!({"status":"ok","topics":source,"source":"provided","live_pattern_verified":false}))
            }
            Command::Prepare {intent,topics}=>{
                let pattern=Pattern {rwid:intent.rwid.clone(),wjid:intent.wjid.clone()};
                let preview=prepare(intent,&topics,&pattern)?;
                Ok(json!({"status":"ok","submission_body":preview.body(),"preview_digest":preview.digest(),"idempotency_key":preview.idempotency_key(),"live_pattern_verified":false,"submission_authorized":false}))
            }
            Command::Submit {intent,topics,confirmation,reconfirmation,session_cookie}=>{
                let pattern=Pattern {rwid:intent.rwid.clone(),wjid:intent.wjid.clone()};
                let preview=prepare(intent,&topics,&pattern)?;
                if confirmation!=preview.digest() { return Err(Error::Invalid("explicit preview digest confirmation required")); }
                let _=(reconfirmation,session_cookie);
                Ok(blocked(MUTATION_BLOCKED))
            }
            Command::Verify {course,session_cookie,source}=>{
                let wjid=text(&course,"wjid")?;
                let operator_supplied=source.is_some();
                let source=source_or_fetch(source,online,session_cookie,|c|c.courses(wjid))?;
                let matched=postcondition(&course,&parse_courses(&source)?)?;
                // This dispatcher has no authenticated account/preview binding
                // or durable submission receipt. Even a live observation is not
                // final proof of this invocation's confirmed submission.
                Ok(json!({"status":"ok","completed":false,"verification":false,"postcondition_matches":matched,"source":if operator_supplied {"operator_supplied"} else {"online_unbound"},"reason":"final completion requires authorized online readback bound to the account and immutable submission preview"}))
            }
            Command::Legacy=>Ok(report(legacy())),
        }
    })();
    Ok(match result { Ok(value)=>value,Err(error)=>report(error) })
}
pub fn schema() -> Value {
    let mut variants=Vec::new();
    let fields = [
        ("tasks",vec![("student",json!({"type":"string"})),("page",json!({"type":"integer","minimum":0,"maximum":u32::MAX}))]),
        ("questionnaires",vec![("rwid",json!({"type":"string"}))]),
        ("courses",vec![("wjid",json!({"type":"string"}))]),
        ("topics",vec![("rwid",json!({"type":"string"})),("questionnaire",json!({"$ref":"#/$defs/questionnaire"})),("course",json!({})),("yxdm",json!({"type":"string"}))]),
        ("prepare",vec![("intent",json!({"$ref":"#/$defs/intent"})),("topics",json!({}))]),
        ("submit",vec![("intent",json!({"$ref":"#/$defs/intent"})),("topics",json!({})),("confirmation",json!({"type":"string"})),("reconfirmation",json!({"type":"boolean"}))]),
        ("verify",vec![("course",json!({}))]),("legacy",vec![]),
    ];
    for (operation,fields) in fields {
        let mut properties=serde_json::Map::new(); properties.insert("operation".into(),json!({"const":operation}));
        let mut required=vec!["operation"];
        for (name,definition) in fields { required.push(name); properties.insert(name.into(),definition); }
        if !matches!(operation,"prepare"|"legacy") { properties.insert("session_cookie".into(),json!({"type":["string","null"]})); }
        if matches!(operation,"tasks"|"questionnaires"|"courses"|"topics"|"verify") { properties.insert("source".into(),json!({})); }
        variants.push(json!({"type":"object","additionalProperties":false,"required":required,"properties":properties}));
    }
    let mut contract=typed_schema();
    contract["dispatcher_verify_output"]=json!({"type":"object","additionalProperties":false,"required":["status","completed","verification","postcondition_matches","source","reason"],"properties":{"status":{"const":"ok"},"completed":{"const":false},"verification":{"const":false},"postcondition_matches":{"type":"boolean"},"source":{"enum":["operator_supplied","online_unbound"]},"reason":{"type":"string"}}});
    json!({"input":{"oneOf":variants,"$defs":{"intent":contract["intent"],"questionnaire":{"type":"object","required":["wjid","wjmc","rwmc"],"properties":{"wjid":{"type":"string"},"wjmc":{"type":"string"},"rwmc":{"type":"string"},"msid":{"type":["string","null"]}}}}},"output":{"oneOf":[{"type":"object","required":["status","reason"],"properties":{"status":{"enum":["blocked","unsupported"]},"reason":{"type":"string"},"evidence":contract["evidence"]}},{"type":"object","required":["status"],"properties":{"status":{"const":"ok"}},"description":"operation-specific tasks/total, questionnaires, courses, topics, submission_body/preview_digest/idempotency_key, or completed"}]},"typed_api":contract})
}
fn typed_schema() -> Value {
    json!({
        "module":"evaluation","transport":BASE,
        "legacy":{"status":"unsupported","reason":"plaintext HTTP forbidden"},
        "intent":{"type":"object","additionalProperties":false,"required":["rwid","wjid","course","metadata","answers"],"properties":{"rwid":{"type":"string"},"wjid":{"type":"string"},"course":{},"metadata":{},"answers":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["topic","options"],"properties":{"topic":{"type":"string"},"options":{"type":"array","items":{"type":"string"}}}}}}},
        "intent_semantic_validation":"offline prepare binds course, topics, answer IDs and complete explicit metadata; it does not authorize submission or attest an authenticated account",
        "workflow":["read_sources","offline_prepare","inspect_preview"],
        "initialization":{"authenticated_session_acceptance":"unknown","http_success_is_authentication_proof":false},
        "clean_authenticated_response_projection":"recognized endpoints expose only parser-supported result/task/course/acknowledgement fields; sensitive or otherwise unreviewed responses are withheld without a CAPTCHA claim",
        "submission":{"status":"blocked","reason":MUTATION_BLOCKED,"owner_answers_only":true,"score_source":"explicit owner metadata","confirmation":"exact immutable preview digest is necessary but insufficient"},
        "submit_output":{"type":"object","required":["status","reason"],"properties":{"status":{"const":"blocked"},"reason":{"const":MUTATION_BLOCKED}}},
        "postcondition_output":{"type":"boolean","description":"unbound observation only, not authorized mutation completion"},
        "errors":["invalid","local","remote_evidence","unsupported"],
        "unknown":["live CAS session acceptance","read-only semantics of pattern endpoints","source-authorized account/target-bound plan/commit and durable atomic idempotency","authorized submission postcondition","server metadata semantics"],
        "evidence":{"type":"object","required":["raw_base64","content_type","bytes","sha256","fallback_reason","raw_provenance"],"additionalProperties":false,"properties":{"raw_base64":{"type":["string","null"]},"content_type":{"type":["string","null"]},"bytes":{"type":"integer","minimum":0},"sha256":{"type":"string"},"fallback_reason":{"type":"string"},"raw_provenance":{"enum":["complete_response_body","withheld_confirmed_challenge","withheld_incomplete_body","withheld_unreviewed_body","withheld_sensitive_material","withheld_authenticated_response"]}}}
    })
}

#[cfg(test)]
mod numeric_cookie_regression {
    use super::*;

    fn admit(body: &[u8], cookie: &str, endpoint: &str) -> Result<Value, Error> {
        let content_type=Some("application/json".to_owned());
        let assessment=assess_challenge_body(body,content_type.as_deref(),true);
        let parsed=serde_json::from_slice::<PrivateValue>(body).ok();
        let denied=parsed.as_ref().is_some_and(|value|session_denied(value));
        admission(ResponseAdmission {bytes:body,content_type,status:200,assessment,challenge:false,
            complete:true,read_failed:false,issued:false,denied,retry_present:false,
            cookie,endpoint,session:false,parsed})
    }

    #[test]
    pub(super) fn numeric_cookie_echo_is_not_projected() {
        let endpoint="personnelEvaluation/listObtainPersonnelEvaluationTasks";
        let safe=admit(br#"{"result":{"list":[],"total":42}}"#,"sid=987654321",endpoint).unwrap();
        assert_eq!(safe["result"]["total"],42);
        let secret=admit(br#"{"result":{"list":[],"total":987654321}}"#,"sid=987654321",endpoint);
        assert!(secret.is_err(),"a numeric cookie echo must not reach the task total");
        let output=report(secret.unwrap_err());
        assert!(output["evidence"]["raw_base64"].is_null());
        assert!(!output.to_string().contains("987654321"));

        let body=br#"{"result":[{"rwid":"r","wjid":"w","kcdm":"c","bpdm":"b","ypjcs":1e9,"xypjcs":1}]}"#;
        let source: Value=serde_json::from_slice(body).unwrap();
        let projected_number=source["result"][0]["ypjcs"].to_string();
        assert_ne!(projected_number,"1e9");
        let cookie=format!("sid={projected_number}");
        let result=admit(body,&cookie,"evaluationMethodSix/getRequiredReviewsData");
        assert!(result.is_err(),"a normalized numeric cookie echo must not reach the course projection");
    }

    #[test]
    pub(super) fn mixed_encoded_cookie_echo_is_not_projected() {
        for (cookie,echo) in [
            ("sid=abc/def=", "abc%2Fdef="),
            ("sid=A+B=C&D", "A+B=%43&D"),
            ("sid=\"A B+C=D&E\"", "A+B%2BC=%44&E"),
            ("sid=abc/def=", "%ffabc%2Fdef="),
            ("sid=abc/def=", "%zzabc%2Fdef="),
            ("sid=~~~???x", "%66n5+Pz8/eA=="),
        ] {
            let body=json!({"result":{"list":[{"rwid":"r","rwmc":echo}],"total":1}}).to_string();
            let result=admit(body.as_bytes(),cookie,"personnelEvaluation/listObtainPersonnelEvaluationTasks");
            assert!(result.is_err(),"a partially encoded cookie must not reach the task projection");
            let output=report(result.unwrap_err());
            assert!(output["evidence"]["raw_base64"].is_null());
            assert!(!output.to_string().contains(echo));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn header_only_http200_challenge_is_observed_before_settlement() {
        for (name,value) in [("cf-mitigated","challenge"),("x-captcha","required"),("x-challenge","required"),("cf-chl-test","1")] {
            let mut headers=reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),reqwest::header::HeaderValue::from_str(value).unwrap());
            // A success-looking body must not hide the header-only challenge.
            assert!(response_challenge(&headers));
        }
        let mut headers=reqwest::header::HeaderMap::new();
        headers.insert("cf-mitigated",reqwest::header::HeaderValue::from_static("none"));
        assert!(!response_challenge(&headers));
        assert_eq!(assess_challenge_body(b"CAPTCHA documentation",Some("text/plain"),true),ChallengeAssessment::Clear);
    }
    #[test] fn complete_header_sets_preserve_cooldowns_and_refuse_ambiguous_mime() {
        let mut headers=reqwest::header::HeaderMap::new();
        headers.append("retry-after",reqwest::header::HeaderValue::from_static("1"));
        headers.append("retry-after",reqwest::header::HeaderValue::from_static("60"));
        headers.append("retry-after",reqwest::header::HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(headers.get_all("retry-after").iter().map(|value|value.to_str().ok()).collect::<Vec<_>>(),vec![Some("1"),Some("60"),None]);
        headers.insert("content-type",reqwest::header::HeaderValue::from_static("application/json"));
        assert_eq!(response_content_type(&headers),Some("application/json"));
        assert_eq!(assess_challenge_body(b"{}",response_content_type(&headers),true),ChallengeAssessment::Clear);
        headers.append("content-type",reqwest::header::HeaderValue::from_static("text/html"));
        assert_eq!(response_content_type(&headers),None);
        assert_eq!(assess_challenge_body(b"{}",response_content_type(&headers),true),ChallengeAssessment::Unreviewed);
        headers.remove("content-type");
        headers.insert("content-type",reqwest::header::HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(response_content_type(&headers),None);
        assert_eq!(assess_challenge_body(b"{}",response_content_type(&headers),true),ChallengeAssessment::Unreviewed);
    }
    #[test] fn body_challenge_and_unreviewed_are_distinct() {
        let active=br#"<form><input name="captcha" value="private_fixture"></form>"#;
        assert_eq!(assess_challenge_body(active,Some("text/html"),true),ChallengeAssessment::Detected);
        assert_eq!(assess_challenge_body(b"ordinary",Some("text/plain"),false),ChallengeAssessment::Unreviewed);
        assert_eq!(assess_challenge_body(&[0xff],Some("text/html"),true),ChallengeAssessment::Unreviewed);
        let e=evidence(active,Some("text/html".into()),"confirmed response challenge",ChallengeAssessment::Detected,true,true,"",false);
        assert!(e.raw_base64.is_none());
        assert_eq!(e.raw_provenance,"withheld_confirmed_challenge");
        let e=evidence(&[0xff],Some("text/html".into()),"response body assessment unreviewed",ChallengeAssessment::Unreviewed,false,true,"",false);
        assert!(e.raw_base64.is_none());
        assert!(!e.fallback_reason.to_ascii_lowercase().contains("captcha"));
        assert_eq!(e.sha256,digest(&[0xff]));
    }
    #[test] fn unsafe_raw_is_withheld_but_safe_original_is_preserved() {
        for body in [br#"{"token":"A9q7P3"}"#.as_slice(),br#"{"\u0074oken":"A9q7P3"}"#,b"echoed private_cookie_fixture"] {
            let e=evidence(body,Some("application/json".into()),"fixture",ChallengeAssessment::Clear,false,true,"sid=private_cookie_fixture",false);
            assert!(e.raw_base64.is_none());
        }
        let body=b"safe unknown response";
        let e=evidence(body,Some("text/plain".into()),"fixture",ChallengeAssessment::Clear,false,true,"",false);
        assert_eq!(STANDARD.decode(e.raw_base64.unwrap()).unwrap(),body);
        assert_eq!(e.raw_provenance,"complete_response_body");
        let e=evidence(body,Some("text/plain".into()),"body read failed",ChallengeAssessment::Unreviewed,false,false,"",false);
        assert!(e.raw_base64.is_none());
        assert_eq!(e.raw_provenance,"withheld_incomplete_body");
        let e=evidence(body,Some("text/plain".into()),"header challenge",ChallengeAssessment::Clear,true,true,"",false);
        assert!(e.raw_base64.is_none());
        let e=evidence(br#"{"value":"opaque-unlabeled-value"}"#,Some("application/json".into()),"unknown authenticated structure",ChallengeAssessment::Clear,false,true,"sid=unrelated",true);
        assert!(e.raw_base64.is_none());
        assert_eq!(e.raw_provenance,"withheld_authenticated_response");
    }
    #[test] fn decoded_structured_response_material_is_screened() {
        for value in [
            json!({"result":{"list":[{"rwid":"r","rwmc":"n"}],"total":1},"token":"fresh-secret"}),
            serde_json::from_slice::<Value>(br#"{"\u0074oken":"A9q7P3"}"#).unwrap(),
            json!({"result":"sid=private_cookie_fixture"}),
        ] {
            assert!(sensitive_json(&value,"unrelated_cookie"));
        }
        let clean=json!({"result":{"list":[{"rwid":"r","rwmc":"n"}],"total":1}});
        assert!(!sensitive_json(&clean,"unrelated_cookie"));
        assert!(!sensitive_material(serde_json::to_vec(&clean).unwrap().as_slice()));
        let e=evidence(br#"{"result":{"list":[{"rwid":"r","rwmc":"n"}],"total":1},"token":"fresh-secret"}"#,Some("application/json".into()),"structured response contains sensitive material",ChallengeAssessment::Clear,false,true,"unrelated_cookie",true);
        assert!(e.raw_base64.is_none());
        assert_eq!(e.raw_provenance,"withheld_authenticated_response");
        assert!(!e.fallback_reason.to_ascii_lowercase().contains("captcha"));
        assert_eq!(e.sha256,digest(br#"{"result":{"list":[{"rwid":"r","rwmc":"n"}],"total":1},"token":"fresh-secret"}"#));
    }
    #[test] fn supplied_completed_fixture_is_never_online_verification() {
        let course=json!({"rwid":"r","wjid":"w","kcdm":"k","bpdm":"b","rwh":"h"});
        let mut row=course.clone(); row["ypjcs"]=json!(1); row["xypjcs"]=json!(1);
        let command=json!({"operation":"verify","course":course,"source":{"result":[row]}}).to_string();
        for online in [false,true] {
            let result=run(&command,online).unwrap();
            assert_eq!(result["status"],"ok");
            assert_eq!(result["source"],"operator_supplied");
            assert_eq!(result["postcondition_matches"],true);
            assert_eq!(result["verification"],false);
            assert_eq!(result["completed"],false);
        }
    }
    #[test] fn dispatcher_offline_and_blocked_contract() {
        let value=run(r#"{"operation":"tasks","student":"owner","page":1,"source":{"result":{"list":[{"rwid":"r","rwmc":"task"}],"total":1}}}"#,false).unwrap();
        assert_eq!(value["status"],"ok"); assert_eq!(value["total"],1);
        assert_eq!(run(r#"{"operation":"courses","wjid":"w"}"#,false).unwrap()["status"],"blocked");
        assert_eq!(run(r#"{"operation":"legacy"}"#,false).unwrap()["status"],"unsupported");
        assert_eq!(run(r#"{"operation":"legacy","unexpected":true}"#,false).unwrap()["status"],"blocked");
        let (intent,topics,pattern)=fixture(); let preview=prepare(intent.clone(),&topics,&pattern).unwrap();
        let command=json!({"operation":"submit","intent":intent,"topics":topics,"confirmation":preview.digest(),"reconfirmation":false});
        let output=run(&command.to_string(),true).unwrap();
        assert_eq!(output["status"],"blocked"); assert!(output["reason"].as_str().unwrap().contains("SubmissionLedger"));
    }
    #[test] fn fixture_lists() {
        assert_eq!(parse_tasks(&json!({"result":{"list":[{"rwid":"r","rwmc":"task"}],"total":1}})).unwrap().0.len(),1);
        assert_eq!(parse_questionnaires(&json!({"result":[{"wjid":"w","wjmc":"q","rwmc":"task","msid":null}]})).unwrap()[0].msid,None);
        assert!(has_pending(&json!([{}])).unwrap());
        assert!(parse_courses(&json!({"result":[{"rwid":"r","wjid":"w","kcdm":"k","bpdm":"b","ypjcs":0,"xypjcs":1}]})).is_ok());
    }
    fn fixture() -> (Intent,Value,Pattern) {
        let mut metadata=serde_json::Map::new();
        for key in ["bprdm","bprmc","kcdm","kcmc","pjdf","pjfs","pjid","pjlx","pjmap","pjrdm","pjrjsdm","pjrxm","pjsx","rwh","stzjid","wjid","wjssrwid","wtjjy","xhgs","xnxq","sfxxpj","sqzt","yxfz","zsxz","sfnm"] { metadata.insert(key.into(),json!("owner")); }
        for (k,v) in [("bprdm","b"),("kcdm","k"),("wjid","w"),("wjssrwid","r"),("pjdf","owner-score"),("pjmap","map")] { metadata.insert(k.into(),json!(v)); }
        (Intent {rwid:"r".into(),wjid:"w".into(),course:json!({"rwid":"r","wjid":"w","kcdm":"k","bpdm":"b"}),metadata:Value::Object(metadata),answers:vec![Answer {topic:"t".into(),options:vec!["low".into()]}]},json!({"result":[{"pjmap":"map","pjxtWjWjbReturnEntity":{"wjzblist":[{"tklist":[{"tmid":"t","tmlx":"1","tmxxlist":[{"tmxxid":"low","xxfz":1},{"tmxxid":"high","xxfz":100}]}]}]}}]}),Pattern {rwid:"r".into(),wjid:"w".into()})
    }
    #[test] fn input_structs_reject_positional_arrays_through_run() {
        let (intent,topics,pattern)=fixture(); let preview=prepare(intent.clone(),&topics,&pattern).unwrap();
        let positional_intent=json!({"operation":"prepare","intent":["r","w",{},"",[]],"topics":topics});
        let positional_answers=json!({"operation":"prepare","intent":{"rwid":"r","wjid":"w","course":{"rwid":"r","wjid":"w"},"metadata":{},"answers":[["t",["low"]]]},"topics":topics});
        for command in [positional_intent,positional_answers] {
            let result=run(&command.to_string(),false).unwrap();
            assert_eq!(result["status"],"blocked");
            assert_eq!(result["reason"],"invalid evaluation command");
            assert!(!result.to_string().contains("private"));
        }
        let clean=json!({"operation":"submit","intent":{"rwid":"r","wjid":"w","course":{"rwid":"r","wjid":"w"},"metadata":{},"answers":[{"topic":"t","options":["low"]}]},"topics":topics,"confirmation":preview.digest(),"reconfirmation":false});
        assert_eq!(run(&clean.to_string(),true).unwrap()["status"],"blocked");
    }
    #[test] fn owner_answers_and_pattern() {
        let (intent,topics,pattern)=fixture(); let preview=prepare(intent.clone(),&topics,&pattern).unwrap();
        assert_eq!(preview.body().pointer("/pjjglist/0/pjxxlist/0/xxdalist"),Some(&json!(["low"])));
        assert_eq!(preview.body().pointer("/pjjglist/0/pjdf"),Some(&json!("owner-score")));
        assert!(prepare(intent,&topics,&Pattern {rwid:"other".into(),wjid:"w".into()}).is_err());
    }
    #[test] fn explicit_success_only() { assert!(success(&json!({"msg":"成功"}))); for v in [json!({"msg":"操作成功"}),json!({"code":200}),json!({"msg":"失败"})] { assert!(!success(&v)); } }
    #[test] fn recognized_clean_responses_are_projected_not_withheld() {
        assert_eq!(safe_response("personnelEvaluation/listObtainPersonnelEvaluationTasks",&json!({"result":{"list":[{"rwid":"r","rwmc":"n"}],"total":1},"token":"fresh-secret"}),"unrelated").unwrap_err(),"structured response contains sensitive material; admission refused");
        let tasks=safe_response("personnelEvaluation/listObtainPersonnelEvaluationTasks",&json!({"result":{"list":[{"rwid":"r","rwmc":"n"}],"total":1},"extra":"ignored"}),"unrelated").unwrap();
        assert_eq!(tasks.pointer("/result/list/0/rwid"),Some(&json!("r")));
        assert!(tasks.get("token").is_none());
        assert_eq!(tasks.pointer("/result/total"),Some(&json!(1)));
        assert!(has_pending(&safe_response("component/queryDaiBan",&json!([{}]),"unrelated").unwrap()).unwrap());
        assert!(!has_pending(&safe_response("component/queryDaiBan",&json!([]),"unrelated").unwrap()).unwrap());
        let courses=safe_response("evaluationMethodSix/getRequiredReviewsData",&json!({"result":[{"rwid":"r","wjid":"w","kcdm":"k","bpdm":"b","ypjcs":0,"xypjcs":1,"opaque":"A9q7P3"}]}),"unrelated").unwrap();
        assert_eq!(parse_courses(&courses).unwrap().len(),1);
        assert!(courses.pointer("/result/0/opaque").is_none());
        let questionnaires=safe_response("evaluationMethodSix/getQuestionnaireListToTask",&json!({"result":[{"wjid":"w","wjmc":"q","rwmc":"r"}]}),"unrelated").unwrap();
        assert_eq!(parse_questionnaires(&questionnaires).unwrap().len(),1);
        let (_,original,_)=fixture();
        let topics=safe_response("evaluationMethodSix/getQuestionnaireTopic",&original,"unrelated").unwrap();
        assert_eq!(topics.pointer("/result/0/pjxtWjWjbReturnEntity/wjzblist/0/tklist/0/tmid"),Some(&json!("t")));
        assert!(!topics.to_string().contains("ignored"));
        assert_eq!(safe_response("component/queryDaiBan",&json!({"unrecognized":1}),"unrelated").unwrap_err(),"response pending contract unreviewed; admission refused");
        assert!(!safe_response("component/queryDaiBan",&json!({"unrecognized":1}),"unrelated").unwrap_err().to_ascii_lowercase().contains("captcha"));
        assert_eq!(safe_response("cas",&json!({"msg":"成功","token":"secret"}),"unrelated").unwrap_err(),"structured response contains sensitive material; admission refused");
        assert!(safe_response("cas",&json!({"msg":"成功"}),"unrelated").is_err());
    }
    #[test] fn parsed_private_values_reject_positional_object_forms_and_wipe() {
        let value=serde_json::from_slice::<PrivateValue>(br#"{"result":{"list":[{"rwid":"r","rwmc":"n"}],"total":1}}"#).unwrap();
        assert_eq!(value.pointer("/result/total"),Some(&json!(1)));
        drop(value);
        let pending=serde_json::from_slice::<PrivateValue>(br#"[{},{}]"#).unwrap();
        assert!(pending.as_array().is_some_and(|rows|rows.len()==2));
        drop(pending);
        assert!(serde_json::from_slice::<PrivateValue>(br#"{"session_cookie":{"session":"secret"},"dup":1,"dup":2}"#).is_err());
        let cookie=serde_json::from_slice::<PrivateValue>(br#"{"session_cookie":{"name":"private_cookie_fixture"}}"#).unwrap();
        assert_eq!(sensitive_json(&cookie,"private_cookie_fixture"),true);
        drop(cookie);
    }
    #[test] fn denial_metadata_and_cookie_errors_do_not_disclose_material() {
        let denial=json!({"msg":"请重新登录","result":{"list":[],"total":0}});
        assert!(session_denied(&denial));
        let reason=safe_response("personnelEvaluation/listObtainPersonnelEvaluationTasks",&denial,"sid=unrelated").unwrap_err();
        assert!(!reason.to_ascii_lowercase().contains("captcha"));
        let receipt=evidence(b"unknown",Some("application/json; opaque=A9q7P3".into()),"unreviewed",ChallengeAssessment::Clear,false,true,"sid=unrelated",true);
        assert_eq!(receipt.content_type.as_deref(),Some("application/json"));
        assert!(receipt.raw_base64.is_none());
        let output=run(r#"{"operation":"tasks","student":0,"page":1,"session_cookie":"sid=fixture\u0073ecret"}"#,false).unwrap();
        assert_eq!(output["status"],"blocked");
        assert!(!output.to_string().contains("fixture"));
        let command=parse_command(r#"{"operation":"tasks","student":"owner","page":1,"session_cookie":"sid=fixture\u0073ecret"}"#).unwrap();
        match command { Command::Tasks{session_cookie:Some(cookie),..}=>assert_eq!(cookie.as_str(),"sid=fixturesecret"),_=>panic!("unexpected command") }
        let output=run(r#"{"operation":"topics","rwid":"r","questionnaire":["w","q","r",null],"course":{},"yxdm":"x","source":{}}"#,false).unwrap();
        assert_eq!(output["reason"],"invalid evaluation command");
        assert!(serde_json::from_str::<Answer>(r#"{"topic":"t","options":["x"]}"#).is_ok());
        let (intent,topics,_)=fixture();
        let output=run(&json!({"operation":"prepare","intent":intent,"topics":topics}).to_string(),false).unwrap();
        assert_eq!(output["status"],"ok");
    }
    fn admit_fixture(body:&[u8],headers:&reqwest::header::HeaderMap,status:u16,complete:bool,read_failed:bool,session:bool)->(Result<Value,Error>,bool) {
        let content_type=response_content_type(headers).map(str::to_owned);
        let assessment=assess_challenge_body(body,content_type.as_deref(),complete);
        let challenge=response_challenge(headers)||assessment==ChallengeAssessment::Detected;
        let parsed=if complete { serde_json::from_slice::<PrivateValue>(body).ok() } else { None };
        let denied=parsed.as_ref().is_some_and(|value|session_denied(value));
        let result=admission(ResponseAdmission {bytes:body,content_type,status,assessment,challenge,complete,read_failed,
            issued:crate::net::issues_session_cookie(headers),denied,retry_present:headers.contains_key(reqwest::header::RETRY_AFTER),
            cookie:"sid=priorvalue",endpoint:"personnelEvaluation/listObtainPersonnelEvaluationTasks",session,parsed});
        (result,denied)
    }
    #[test] fn cookie_issuing_task_response_withholds_projection_and_metadata() {
        use reqwest::header::{HeaderMap,HeaderValue,CONTENT_TYPE,LOCATION,SET_COOKIE};
        let body=br#"{"result":{"list":[{"rwid":"r","rwmc":"freshopaque123"}],"total":1}}"#;
        let mut headers=HeaderMap::new();
        headers.insert(CONTENT_TYPE,HeaderValue::from_static("application/json"));
        let clean=admit_fixture(body,&headers,200,true,false,false).0.unwrap();
        assert_eq!(clean["result"]["list"][0]["rwmc"],"freshopaque123");
        for value in [HeaderValue::from_static("x=freshopaque123"),HeaderValue::from_static("x=q"),
            HeaderValue::from_static("malformed"),HeaderValue::from_static("x=; Max-Age=0"),
            HeaderValue::from_bytes(&[0xff]).unwrap()] {
            headers.insert(SET_COOKIE,value);
            let output=report(admit_fixture(body,&headers,200,true,false,false).0.unwrap_err());
            assert_eq!(output["status"],"blocked");
            assert_eq!(output["reason"],"response issued session cookie; body admission refused");
            assert!(output.get("evidence").is_none());
            assert!(!output.to_string().contains("freshopaque123"));
        }
        headers.insert(SET_COOKIE,HeaderValue::from_static("x=q"));
        let short=br#"{"result":{"list":[{"rwid":"r","rwmc":"q"}],"total":1}}"#;
        let output=report(admit_fixture(short,&headers,200,true,false,false).0.unwrap_err());
        assert_eq!(output["reason"],"response issued session cookie; body admission refused");
        assert!(output.get("evidence").is_none());
        headers.insert(CONTENT_TYPE,HeaderValue::from_static("application/freshopaque123"));
        headers.insert(LOCATION,HeaderValue::from_static("https://example.invalid/freshopaque123"));
        let output=report(admit_fixture(body,&headers,200,true,false,false).0.unwrap_err());
        assert_eq!(output["status"],"blocked");
        assert!(output.get("evidence").is_none());
        assert!(!output.to_string().contains("freshopaque123"));
    }
    #[test] fn encoded_submitted_cookie_in_task_name_is_not_projected() {
        let mut headers=reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE,reqwest::header::HeaderValue::from_static("application/json"));
        let admit=|body:&[u8],cookie:&str| {
            let content_type=response_content_type(&headers).map(str::to_owned);
            let assessment=assess_challenge_body(body,content_type.as_deref(),true);
            let parsed=serde_json::from_slice::<PrivateValue>(body).unwrap();
            admission(ResponseAdmission {bytes:body,content_type,status:200,assessment,challenge:false,complete:true,read_failed:false,
                issued:crate::net::issues_session_cookie(&headers),denied:session_denied(&parsed),retry_present:false,
                cookie,endpoint:"personnelEvaluation/listObtainPersonnelEvaluationTasks",session:false,parsed:Some(parsed)})
        };
        for (cookie,echo) in [
            ("sid=priorvalue",STANDARD.encode("priorvalue")),
            ("sid=priorvalue","%70%72%69%6F%72%76%61%6C%75%65".to_owned()),
            ("sid=\"priorvalue\"",STANDARD.encode("priorvalue")),
            ("sid=\"prior+value\"","prior%2Bvalue".to_owned()),
            ("first=other; sid=priorvalue",STANDARD.encode("sid=priorvalue")),
            ("sid=priorvalue","%73%69%64%3D%70%72%69%6F%72%76%61%6C%75%65".to_owned()),
        ] {
            let body=json!({"result":{"list":[{"rwid":"r","rwmc":echo}],"total":1}}).to_string();
            let output=report(admit(body.as_bytes(),cookie).unwrap_err());
            assert_eq!(output["evidence"]["fallback_reason"],"structured response contains sensitive material; admission refused");
            assert!(output["evidence"]["raw_base64"].is_null());
            assert!(!output.to_string().contains("priorvalue"));
        }
        let escaped=br#"{"result":{"list":[{"rwid":"r","rwmc":"\u0063HJpb3J2YWx1ZQ=="}],"total":1}}"#;
        let output=report(admit(escaped,"sid=priorvalue").unwrap_err());
        assert_eq!(output["evidence"]["fallback_reason"],"structured response contains sensitive material; admission refused");
        assert!(output["evidence"]["raw_base64"].is_null());
        assert!(!output.to_string().contains("cHJpb3J2YWx1ZQ"));
    }
    #[test] fn cookie_withholding_preserves_denial_cooldown_and_body_failure_facts() {
        use reqwest::header::{HeaderMap,HeaderValue,CONTENT_TYPE,RETRY_AFTER,SET_COOKIE};
        let mut headers=HeaderMap::new();
        headers.insert(CONTENT_TYPE,HeaderValue::from_static("application/json"));
        headers.insert(SET_COOKIE,HeaderValue::from_static("x=freshopaque123"));
        let denied_body=br#"{"msg":"unauthorized","echo":"freshopaque123"}"#;
        let (result,denied)=admit_fixture(denied_body,&headers,200,true,false,false);
        assert!(denied);
        let output=report(result.unwrap_err());
        assert_eq!(output["reason"],"application rejected the session; admission refused");
        assert!(!output.to_string().contains("freshopaque123"));
        let body=br#"{"result":{"list":[],"total":0}}"#;
        for status in [401,403,429] {
            let output=report(admit_fixture(body,&headers,status,true,false,false).0.unwrap_err());
            assert_eq!(output["reason"],"HTTP response refused; redirects and automatic retries disabled");
        }
        headers.insert(RETRY_AFTER,HeaderValue::from_static("60"));
        let output=report(admit_fixture(body,&headers,200,true,false,false).0.unwrap_err());
        assert_eq!(output["reason"],"response requested cooldown; no automatic retry");
        headers.remove(RETRY_AFTER);
        headers.insert("cf-mitigated",HeaderValue::from_static("challenge"));
        let output=report(admit_fixture(body,&headers,200,true,false,false).0.unwrap_err());
        assert_eq!(output["reason"],"confirmed response challenge; admission refused");
        headers.remove("cf-mitigated");
        let output=report(admit_fixture(body,&headers,200,false,true,false).0.unwrap_err());
        assert_eq!(output["reason"],"response body read failed; admission refused");
        let output=report(admit_fixture(body,&headers,200,true,false,true).0.unwrap_err());
        assert_eq!(output["reason"],"response issued session cookie; body admission refused");
        headers.remove(SET_COOKIE);
        let initialized=admit_fixture(body,&headers,200,true,false,true).0.unwrap();
        assert_eq!(initialized["session_acceptance"],"unknown");
    }
    #[test] fn immutable_idempotency_key() {
        struct Ledger(BTreeSet<String>); impl SubmissionLedger for Ledger { fn claim(&mut self,key:&str,reconfirm:bool)->Result<(),String> { if !self.0.insert(key.into()) && !reconfirm { return Err("duplicate".into()); } Ok(()) } }
        let (i,t,p)=fixture(); let preview=prepare(i,&t,&p).unwrap(); let mut l=Ledger(BTreeSet::new());
        assert!(l.claim(preview.digest(),false).is_ok()); assert!(l.claim(preview.digest(),false).is_err()); assert!(l.claim(preview.digest(),true).is_ok());
    }
    #[test] fn legacy_and_fallback() { assert!(matches!(legacy(),Error::Unsupported(_))); let e=evidence(b"not json",Some("text/plain".into()),"fixture",ChallengeAssessment::Clear,false,true,"",false); assert_eq!(e.content_type.as_deref(),Some("text/plain")); assert_eq!(STANDARD.decode(e.raw_base64.unwrap()).unwrap(),b"not json"); }
    #[test] fn positive_postcondition_only() { let c=json!({"rwid":"r","wjid":"w","kcdm":"k","bpdm":"b","rwh":"h"}); let mut row=c.clone(); row["ypjcs"]=json!(1); row["xypjcs"]=json!(1); assert!(postcondition(&c,&[row]).unwrap()); assert!(!postcondition(&c,&[]).unwrap()); }
}
