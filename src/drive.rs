//! AnyShare efast contracts. No implicit login, refresh, retry or mutation.
//! OAuth password encryption is deliberately unavailable without an admitted
//! platform public key and padding contract; a client identifier is not a key.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use url::Url;
use crate::net::Error;
use crate::governor::{Governor, Outcome};
use zeroize::{Zeroize,Zeroizing};
#[derive(Serialize)] #[serde(transparent)]
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
fn wipe_value(value:&mut Value){match value{Value::String(text)=>text.zeroize(),Value::Array(values)=>values.iter_mut().for_each(wipe_value),Value::Object(values)=>for(mut key,mut value)in std::mem::take(values){key.zeroize();wipe_value(&mut value);},_=>{}}}
fn private_value(value:&Value,secret:Option<&str>)->bool{
    let sensitive=|text:&str|match secret{Some(secret)=>crate::net::carries_secret(text.as_bytes(),secret),None=>sensitive_raw(text.as_bytes())};
    match value{Value::String(text)=>sensitive(text),Value::Array(values)=>values.iter().any(|value|private_value(value,secret)),Value::Object(values)=>values.iter().any(|(key,value)|sensitive(key)||private_value(value,secret)),
        Value::Number(_) | Value::Bool(_) | Value::Null=>secret.is_some_and(|secret|crate::net::json_scalar_matches(value,|bytes|crate::net::carries_secret(bytes,secret)))}
}
struct Secret(Zeroizing<String>);
impl<'de> Deserialize<'de> for Secret{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{String::deserialize(deserializer).map(|value|Self(Zeroizing::new(value)))}}
fn object<'de,D:serde::Deserializer<'de>,T:Deserialize<'de>>(deserializer:D)->Result<T,D::Error>{
    struct Visitor<T>(std::marker::PhantomData<T>);impl<'de,T:Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T>{type Value=T;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("JSON object")}
        fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<T,A::Error>{T::deserialize(serde::de::value::MapAccessDeserializer::new(access))}}
    deserializer.deserialize_map(Visitor(std::marker::PhantomData))
}

const AUTHORITY_HOST: &str = "bhpan.buaa.edu.cn";
const MAX_BODY: u64 = 32 * 1024 * 1024;
fn err(code: &'static str) -> Error { Error::new(code, "drive contract refused; no automatic retry") }
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn rejection_code(body:&[u8])->Option<i64>{
    struct Facts<'a>(&'a std::cell::Cell<Option<i64>>);
    impl<'de> serde::de::Visitor<'de> for Facts<'_>{type Value=();fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("response object")}
        fn visit_map<A:serde::de::MapAccess<'de>>(self,mut access:A)->Result<(),A::Error>{while let Some(key)=access.next_key::<String>()?{let key=Zeroizing::new(key);if key.as_str()=="code"{let value=access.next_value::<PrivateValue>()?;let code=value.as_i64().or_else(||value.as_str()?.parse().ok());if matches!(code,Some(401001001|401001003))&&(self.0.get()!=Some(401001003)){self.0.set(code);}}else{access.next_value::<serde::de::IgnoredAny>()?;}}Ok(())}}
    let code=std::cell::Cell::new(None);let mut deserializer=serde_json::Deserializer::from_slice(body);let _=serde::Deserializer::deserialize_map(&mut deserializer,Facts(&code));code.get()
}
fn sensitive_raw(bytes:&[u8])->bool{
    if bytes.windows(2).any(|part|part==b"\\u"||part==b"\\x")||bytes.windows(2).any(|part|part==b"&#"){return true;}
    fn marked(bytes:&[u8])->bool{[b"token".as_slice(),b"cookie",b"password",b"ticket",b"authorization",b"session",b"csrf",b"secret",b"loginname",b"login_name",b"credential",b"bearer",b"execution",b"nonce",b"jwt"].iter().any(|marker|bytes.windows(marker.len()).any(|part|part.eq_ignore_ascii_case(marker)))}
    marked(bytes)||url::form_urlencoded::parse(bytes).any(|(key,value)|{let key=Zeroizing::new(key.into_owned());let value=Zeroizing::new(value.into_owned());marked(key.as_bytes())||marked(value.as_bytes())})
}
fn safe_mime(value:Option<&str>)->Option<&'static str>{let essence=value?.split(';').next()?.trim();["application/json","text/plain","text/html","application/xhtml+xml","application/octet-stream"].into_iter().find(|candidate|essence.eq_ignore_ascii_case(candidate))}
fn response_content_type(headers:&reqwest::header::HeaderMap)->Zeroizing<Option<String>>{Zeroizing::new(if headers.get_all("content-type").iter().count()==1{headers.get("content-type").and_then(|value|value.to_str().ok()).map(str::to_owned)}else{None})}
fn response_contains_secret(bytes:&[u8],content_type:Option<&str>,secret:&str)->bool {
    if secret.is_empty(){return false;}
    let contains=|candidate:&[u8]|crate::net::carries_secret(candidate,secret);
    contains(bytes)||content_type.is_some_and(|value|contains(value.as_bytes()))||serde_json::from_slice::<PrivateValue>(bytes).ok().is_some_and(|value|private_value(&value,Some(secret)))
}

/// Authorization-URL production is blocked: the historical fixed state is not
/// a private single-consumption binding, and token exchange has no sink.
pub fn auth_url(_host: &str) -> Result<Url, Error> { Err(err("oauth_authorization_state_unsafe")) }
fn base(host: &str) -> Result<Url, Error> {
    if host != AUTHORITY_HOST { return Err(err("authority_host_unsupported")); }
    let url = Url::parse(&format!("https://{host}:443/")).map_err(|_| err("invalid_host"))?;
    if url.host_str() != Some(host) || !url.username().is_empty() || url.password().is_some()
        || url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(err("invalid_host"));
    }
    Ok(url)
}

/// Secret-bearing values deliberately have no Debug or Serialize implementation.
pub struct LoginChallenge { csrf: Zeroizing<String>, challenge: Zeroizing<String> }
impl LoginChallenge {
    pub fn parse(html: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(html).map_err(|_| err("login_html_invalid"))?;
        fn field(text: &str, key: &str) -> Result<Zeroizing<String>, Error> {
            let needle = format!("\"{key}\"");
            let mut matches = text.match_indices(&needle);
            let (at, _) = matches.next().ok_or_else(|| err("login_field_missing"))?;
            if matches.next().is_some() { return Err(err("login_field_ambiguous")); }
            let tail = text[at + needle.len()..].trim_start().strip_prefix(':')
                .ok_or_else(|| err("login_field_invalid"))?.trim_start();
            let mut stream = serde_json::Deserializer::from_str(tail).into_iter::<String>();
            let result = Zeroizing::new(stream.next().ok_or_else(|| err("login_field_invalid"))?
                .map_err(|_| err("login_field_invalid"))?);
            if result.is_empty() { return Err(err("login_field_invalid")); } Ok(result)
        }
        Ok(Self { csrf: field(text, "csrftoken")?, challenge: field(text, "challenge")? })
    }
    /// Expose neither nonce in receipts; only readiness is public.
    pub fn ready(&self) -> bool { !self.csrf.is_empty() && !self.challenge.is_empty() }
}

/// No callback code can be admitted without a private, session-bound state
/// and a proven private exchange sink. This avoids a misleading public helper.
pub fn authorization_code(_location: &str) -> Result<Zeroizing<String>, Error> { Err(err("oauth_callback_state_unsafe")) }

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub docid: String, pub name: String, pub rev: String, pub size: i64,
    #[serde(default)] pub modified: Value,
}
impl<'de> Deserialize<'de> for Entry{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
    #[derive(Deserialize)] #[serde(deny_unknown_fields)]struct Fields{docid:String,name:String,rev:String,size:i64,#[serde(default)]modified:Value}
    let fields:Fields=object(deserializer)?;Ok(Self{docid:fields.docid,name:fields.name,rev:fields.rev,size:fields.size,modified:fields.modified})
}}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub raw_base64: String, pub content_type: Option<String>, pub byte_length: usize,
    pub sha256: String, pub fallback_reason: String,
    #[serde(default)] pub raw_withheld: bool,
    #[serde(default,skip_serializing_if="Option::is_none")] pub raw_withheld_reason: Option<String>,
}
impl Evidence {
    pub fn new(bytes: &[u8], content_type: Option<&str>, reason: &str) -> Self {
        let withheld=match crate::html::assess_challenge_body(bytes,content_type,true){
            crate::html::ChallengeAssessment::Clear=>None,
            crate::html::ChallengeAssessment::Detected=>Some("challenge_detected"),
            crate::html::ChallengeAssessment::Unreviewed=>Some("response_safety_unreviewed"),
        };
        let withheld=if sensitive_raw(bytes)||serde_json::from_slice::<PrivateValue>(bytes).ok().is_some_and(|value|private_value(&value,None)){Some("sensitive_response_material")}else{withheld};
        Self { raw_base64: if withheld.is_none(){STANDARD.encode(bytes)}else{String::new()}, content_type: safe_mime(content_type).map(str::to_owned),
            byte_length: bytes.len(), sha256: digest(bytes), fallback_reason: reason.into(),raw_withheld:withheld.is_some(),raw_withheld_reason:withheld.map(str::to_owned) }
    }
}
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Listing { Structured { entries: Vec<Entry> }, Degraded { evidence: Evidence } }
pub fn parse_listing(bytes: &[u8], content_type: Option<&str>) -> Listing {
    if crate::html::assess_challenge_body(bytes,content_type,true)!=crate::html::ChallengeAssessment::Clear||serde_json::from_slice::<PrivateValue>(bytes).ok().is_some_and(|value|private_value(&value,None)){
        return Listing::Degraded{evidence:Evidence::new(bytes,content_type,"response_not_admitted")};
    }
    fn parse(bytes: &[u8]) -> Option<Vec<Entry>> {
        let value: PrivateValue = serde_json::from_slice(bytes).ok()?;
        let mut result = Vec::new(); let mut ids = BTreeSet::new();
        for (key, directory) in [("dirs", true), ("files", false)] {
            for item in value.get(key)?.as_array()? {
                let entry = Entry { docid: item.get("docid")?.as_str()?.into(),
                    name: item.get("name")?.as_str()?.into(), rev: item.get("rev")?.as_str()?.into(),
                    size: item.get("size")?.as_i64()?, modified: item.get("modified").cloned().unwrap_or(Value::Null) };
                if entry.docid.is_empty() || entry.name.is_empty() || (directory != (entry.size == -1))
                    || entry.size < -1 || !ids.insert(entry.docid.clone()) { return None; }
                result.push(entry);
            }
        } Some(result)
    }
    match parse(bytes) { Some(entries) => Listing::Structured { entries }, None => Listing::Degraded {
        evidence: Evidence::new(bytes, content_type, "unrecognized_dir_list") } }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor { version: u8, binding: String, offset: usize }
#[derive(Debug, Serialize)]
pub struct Page { pub entries: Vec<Entry>, pub next_cursor: Option<String> }
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Tree {
    Structured { entries: Vec<Entry> },
    Degraded { completed_entries: Vec<Entry>, response: Value },
}
/// `entries` is the complete flattened snapshot (including a recursively collected
/// tree when requested). Root, traversal mode, ordering and every entry are bound.
pub fn page(root: &str, by: &str, sort: &str, recursive: bool, entries: &[Entry],
    limit: usize, cursor: Option<&str>) -> Result<Page, Error> {
    if root.is_empty() || !(1..=1000).contains(&limit) || !matches!(sort, "asc" | "desc") {
        return Err(err("invalid_page"));
    }
    let binding = digest(&serde_json::to_vec(&(root, by, sort, recursive, entries))
        .map_err(|_| err("snapshot_invalid"))?);
    let offset = if let Some(cursor) = cursor {
        if cursor.len() > 2048 { return Err(err("invalid_cursor")); }
        let decoded = STANDARD.decode(cursor).map_err(|_| err("invalid_cursor"))?;
        let c: Cursor = serde_json::from_slice(&decoded).map_err(|_| err("invalid_cursor"))?;
        if c.version != 1 || c.binding != binding || c.offset == 0 || c.offset >= entries.len() {
            return Err(err("cursor_snapshot_mismatch"));
        } c.offset
    } else { 0 };
    let end = offset.saturating_add(limit).min(entries.len());
    let next_cursor = if end < entries.len() { Some(STANDARD.encode(serde_json::to_vec(
        &Cursor { version: 1, binding, offset: end }).map_err(|_| err("invalid_cursor"))?)) } else { None };
    Ok(Page { entries: entries[offset..end].to_vec(), next_cursor })
}

#[derive(Default, Serialize)]
pub struct IntegrityManifest { records: BTreeMap<String, String> }
impl<'de> Deserialize<'de> for IntegrityManifest{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
    #[derive(Deserialize)] #[serde(deny_unknown_fields)]struct Fields{records:BTreeMap<String,String>}
    let fields:Fields=object(deserializer)?;Ok(Self{records:fields.records})
}}
impl IntegrityManifest {
    fn key(docid: &str, rev: &str, length: u64) -> String { json!([docid, rev, length]).to_string() }
    pub fn record(&mut self, docid: &str, rev: &str, length: u64, bytes: &[u8]) -> Result<String, Error> {
        if docid.is_empty() || rev.is_empty() || bytes.len() as u64 != length { return Err(err("length_mismatch")); }
        let hash = digest(bytes); let key = Self::key(docid, rev, length);
        if self.records.get(&key).is_some_and(|old| old != &hash) { return Err(err("integrity_mismatch")); }
        self.records.insert(key, hash.clone()); Ok(hash)
    }
    pub fn verify(&self, docid: &str, rev: &str, length: u64, bytes: &[u8]) -> bool {
        bytes.len() as u64 == length && self.records.get(&Self::key(docid, rev, length)) == Some(&digest(bytes))
    }
}

/// In-memory bearer client. Redirects are never automatically followed, so the
/// bearer cannot migrate to an object-storage URL or another origin.
pub struct Client { http: reqwest::blocking::Client, governor: Governor, base: Url, token: zeroize::Zeroizing<String>, expires: std::time::Instant }
enum TokenSend<T>{Expired,Sent(T)}
fn send_before_expiry<T>(expires:std::time::Instant,send:impl FnOnce()->T)->TokenSend<T>{
    if std::time::Instant::now()>=expires{TokenSend::Expired}else{TokenSend::Sent(send())}
}
impl Client {
    /// Collect a bounded, cycle-checked tree before issuing a snapshot cursor.
    /// Every directory request independently acquires and settles the shared lease.
    pub fn tree(&self, root: &str, by: &str, sort: &str, max_directories: usize) -> Result<Tree, Error> {
        if root.is_empty() || !matches!(sort, "asc" | "desc") || !(1..=1000).contains(&max_directories) {
            return Err(err("invalid_tree_bound"));
        }
        let mut pending = vec![root.to_owned()];
        let mut visited = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut entries = Vec::new();
        while let Some(docid) = pending.pop() {
            if !visited.insert(docid.clone()) { return Err(err("directory_cycle")); }
            if visited.len() > max_directories { return Err(err("tree_bound_exceeded")); }
            let value = self.read(ReadEndpoint::List { docid, by: by.into(), sort: sort.into() })?;
            if value.get("status").and_then(Value::as_str) != Some("structured")
                || value.get("http_status").and_then(Value::as_u64) != Some(200) {
                return Ok(Tree::Degraded { completed_entries: entries, response: value });
            }
            let bytes = serde_json::to_vec(&value["value"]).map_err(|_| err("invalid_tree_response"))?;
            let children = match parse_listing(&bytes, Some("application/json")) {
                Listing::Structured { entries } => entries,
                Listing::Degraded { .. } => return Ok(Tree::Degraded { completed_entries: entries,
                    response: json!({"status":"degraded","evidence":value["source"],"fallback_reason":"unrecognized_dir_list"}) }),
            };
            for entry in children {
                if entry.docid == root || !ids.insert(entry.docid.clone()) { return Err(err("directory_cycle_or_duplicate")); }
                if entry.size == -1 { pending.push(entry.docid.clone()); }
                entries.push(entry);
                if entries.len() > 100_000 { return Err(err("tree_entry_bound_exceeded")); }
            }
        }
        Ok(Tree::Structured { entries })
    }
    pub fn new(host: &str, token: Zeroizing<String>, remaining_seconds: u64) -> Result<Self, Error> {
        if host != AUTHORITY_HOST { return Err(err("authority_host_unsupported")); }
        if token.is_empty() || token.chars().any(char::is_control) || remaining_seconds == 0 || remaining_seconds > 3600 {
            return Err(err("invalid_token"));
        }
        Ok(Self { http: reqwest::blocking::Client::builder().redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(std::time::Duration::from_secs(60)).build().map_err(|_| err("transport_unavailable"))?,
            governor: Governor::open().map_err(|_| err("governor_unavailable"))?, base: base(host)?, token,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(remaining_seconds) })
    }
    /// Only read contracts are admitted. No guessed mutation or upload semantics.
    pub fn read(&self, endpoint: ReadEndpoint) -> Result<Value, Error> {
        if std::time::Instant::now() >= self.expires { return Err(err("token_expired")); }
        let (path, body) = endpoint.request()?;
        let url = self.base.join(&format!("/api/efast/v1{path}")).map_err(|_| err("invalid_endpoint"))?;
        let mut request = if body.is_some() { self.http.post(url) } else { self.http.get(url) };
        request = request.bearer_auth(self.token.as_str());
        if let Some(body) = body { request = request.header("Content-Type", "application/json").body(body.to_string()); }
        let mut lease = crate::net::acquire(&self.governor)?;
        if std::time::Instant::now()>=self.expires{lease.finish_without_request().map_err(|_|err("governor_settlement"))?;return Err(err("token_expired"));}
        let request=request.timeout(std::time::Duration::from_secs(60));
        let mut response = match lease.start_request(||send_before_expiry(self.expires,||request.send())) {
            Ok(TokenSend::Expired)=>{lease.finish_without_request().map_err(|_|err("governor_settlement"))?;return Err(err("token_expired"));},
            Ok(TokenSend::Sent(Ok(response)))=>response,
            Ok(TokenSend::Sent(Err(_)))=>{lease.finish(Outcome::NetworkFailure).map_err(|_| err("governor_settlement"))?;return Err(err("network_failure"));},
            Err(crate::governor::FollowupError::Governor(_))=>return Err(err("governor_settlement")),
        };
        let status = response.status().as_u16();
        let retry = response.headers().get("retry-after").and_then(|h| h.to_str().ok()).map(str::to_owned);
        let ct = response_content_type(response.headers());
        let header_challenge = response.headers().iter().any(|(k,v)| crate::net::challenge_header(k.as_str(), v.as_bytes()));
        // A newly issued session cookie is a credential this client never
        // submitted and cannot revoke; its value must never reach the caller.
        let issued_cookie = crate::net::issues_session_cookie(response.headers());
        lease.observe_http_many(status,response.headers().get_all("retry-after").iter().map(|value|value.to_str().ok()),header_challenge).map_err(|_| err("governor_settlement"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        let read = response.by_ref().take(MAX_BODY + 1).read_to_end(&mut bytes);
        let incomplete=read.is_err()||bytes.len() as u64>MAX_BODY;
        let assessment=crate::html::assess_challenge_body(&bytes,ct.as_deref(),!incomplete);
        let challenge=header_challenge||assessment==crate::html::ChallengeAssessment::Detected;
        let code=rejection_code(&bytes);
        drop(response);
        // The complete admitted or refused result is computed while the
        // original lease is still held, so no other request is admitted
        // between the response and its admission. The lease settles exactly
        // once, whatever the result.
        let result = (|| {
            if challenge || status == 401 || status == 403 || code == Some(401001001) || code == Some(401001003) {
                return Err(err("authentication_or_challenge_refused"));
            }
            if read.is_err() || bytes.len() as u64 > MAX_BODY { return Err(err("body_incomplete_or_oversized")); }
            if status == 429 || status >= 500 { return Err(err("remote_refused")); }
            if assessment==crate::html::ChallengeAssessment::Unreviewed {return Err(err("response_safety_unreviewed"));}
            admit_read_body(path,status,&bytes,ct.as_deref(),self.token.as_str(),issued_cookie)
        })();
        settle_response(lease, status, retry.as_deref(), challenge, incomplete, code)?;
        result
    }
}
fn admit_read_body(path:&str,status:u16,bytes:&[u8],content_type:Option<&str>,secret:&str,issued_cookie:bool)->Result<Value,Error>{
    if response_contains_secret(bytes,content_type,secret){return Err(err("credential_echo_withheld"));}
    if issued_cookie{return Err(err("session_cookie_refused"));}
    // No bearer/token endpoint response can enter raw evidence through this API.
    Ok(read_output(path,status,bytes,content_type))
}
fn settle_response(lease: crate::governor::RequestLease<'_>, status: u16, retry: Option<&str>,
    challenge: bool, body_failed: bool, code: Option<i64>) -> Result<(), Error> {
    // Independently preserve transport facts and application rejection, rather
    // than dropping cooldown/body failure when choosing a credential outcome.
    let outcome=Outcome::Http{status,retry_after:retry,challenge:challenge||matches!(code,Some(401001003|401001001)),network_failure:body_failed};
    lease.finish(outcome).map_err(|_| err("governor_settlement"))
}
fn read_output(path: &str, status: u16, bytes: &[u8], content_type: Option<&str>) -> Value {
    let parsed = serde_json::from_slice::<PrivateValue>(bytes).ok();
    if crate::html::assess_challenge_body(bytes,content_type,true)!=crate::html::ChallengeAssessment::Clear||parsed.as_ref().is_some_and(|value|private_value(value,None)){
        return json!({"status":"degraded","http_status":status,"network_performed":true,"evidence":Evidence::new(bytes,content_type,"response_not_admitted")});
    }
    let shape_ok = parsed.as_ref().is_some_and(|value| {
        if value.get("code").is_some() { return false; }
        match path {
            "/dir/list" => matches!(parse_listing(bytes, content_type), Listing::Structured { .. }),
            p if p.starts_with("/entry-doc-lib?") => value.as_array().is_some_and(|items|
                items.iter().all(|v| v.is_object() && v.get("docid").is_some_and(Value::is_string))),
            "/quota/user" => ["quota_used","quota_allocated","space_rate"].iter().all(|key| value.get(key).is_some_and(Value::is_number)),
            "/file/convertpath" => value.get("namepath").is_some_and(Value::is_string),
            "/file/getinfobypath" | "/file/metadata" => value.get("docid").is_some_and(Value::is_string) && value.get("name").is_some_and(Value::is_string),
            "/entrydoc2/get" | "/file/revisions" => value.is_array(),
            _ => false,
        }
    });
    if status == 200 && shape_ok {
        json!({"status":"structured","http_status":status,"value":parsed.unwrap(),"network_performed":true,
            "source":Evidence::new(bytes,content_type,"retained_original")})
    } else {
        json!({"status":"degraded","http_status":status,"network_performed":true,
            "evidence":Evidence::new(bytes,content_type,if status != 200 {"http_not_success"} else {"unexpected_application_shape"})})
    }
}
pub enum ReadEndpoint {
    Libraries, EntryDocuments, Quota, InfoByPath(String), ConvertPath(String), Metadata(String),
    List { docid: String, by: String, sort: String }, Revisions(String),
}
impl ReadEndpoint {
    fn request(self) -> Result<(&'static str, Option<Value>),Error> {
        Ok(match self {
            Self::Libraries => ("/entry-doc-lib?type=user_doc_lib&sort=doc_lib_name&direction=asc", None),
            Self::EntryDocuments => ("/entrydoc2/get", Some(json!({"doctype":1}))),
            Self::Quota => ("/quota/user", None),
            Self::InfoByPath(namepath) => ("/file/getinfobypath", Some(json!({"namepath":namepath}))),
            Self::ConvertPath(docid) => ("/file/convertpath", Some(json!({"docid":docid}))),
            Self::Metadata(docid) => ("/file/metadata", Some(json!({"docid":docid}))),
            Self::Revisions(docid) => ("/file/revisions", Some(json!({"docid":docid}))),
            // Neither conflicting candidate attr representation is bound to
            // this deployment. Other read endpoints remain independently usable.
            Self::List {..} => return Err(err("directory_listing_contract_unconfirmed")),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum Mutation { Upload, Move, Copy, DeleteFile, DeleteDirectory, Rename, CreateDirectory }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub operation: Mutation, pub source_docid: Option<String>, pub source_rev: Option<String>,
    pub target_path: String, pub parent_docid: String, pub expected_name: String,
    pub ondup: Option<u8>, pub overwrites: Option<bool>, pub byte_length: u64, pub local_sha256: Option<String>,
}
impl<'de> Deserialize<'de> for Intent{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
    #[derive(Deserialize)] #[serde(deny_unknown_fields)]struct Fields{operation:Mutation,source_docid:Option<String>,source_rev:Option<String>,target_path:String,parent_docid:String,expected_name:String,ondup:Option<u8>,overwrites:Option<bool>,byte_length:u64,local_sha256:Option<String>}
    let fields:Fields=object(deserializer)?;Ok(Self{operation:fields.operation,source_docid:fields.source_docid,source_rev:fields.source_rev,target_path:fields.target_path,parent_docid:fields.parent_docid,expected_name:fields.expected_name,ondup:fields.ondup,overwrites:fields.overwrites,byte_length:fields.byte_length,local_sha256:fields.local_sha256})
}}
/// Immutable by construction: callers can inspect a clone, not mutate the bound intent.
pub struct Preview { intent: Intent, confirmation: String }
impl Preview {
    pub fn new(intent: Intent) -> Result<Self, Error> {
        if intent.target_path.is_empty() || intent.parent_docid.is_empty() || intent.expected_name.is_empty()
            || intent.expected_name.contains('/') {
            // Server-selected rename is not an immutable expected-result contract.
            return Err(err("invalid_intent"));
        }
        if intent.ondup.is_none()||intent.overwrites.is_none(){
            // No unverified default can become an immutable result contract.
            return Err(err("ondup_semantics_unconfirmed"));
        }
        if !(1..=3).contains(intent.ondup.as_ref().unwrap())
            || (intent.overwrites != Some(intent.ondup == Some(3))) || intent.ondup == Some(2) {
            return Err(err("ambiguous_or_silent_ondup"));
        }
        if intent.operation == Mutation::Upload && !intent.local_sha256.as_ref().is_some_and(|s|
            s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())) {
            return Err(err("upload_digest_required"));
        }
        let confirmation = digest(&serde_json::to_vec(&intent).map_err(|_| err("invalid_intent"))?);
        Ok(Self { intent, confirmation })
    }
    pub fn inspect(&self) -> Value { json!({"intent":self.intent,"confirmation":self.confirmation,
        "commit_supported":false,"blocked_reason":"upstream_idempotency_and_postcondition_contract_not_admitted"}) }
    pub fn confirm(&self, confirmation: &str, explicit: bool) -> Result<(), Error> {
        if !explicit || confirmation != self.confirmation { return Err(err("explicit_confirmation_required")); }
        // Never label a preview or confirmation as a completed remote write.
        Err(err("mutation_blocked_missing_idempotency_contract"))
    }
}

enum Input {
    AuthUrl { host: String },
    LoginChallenge { raw_base64: Secret, content_type: Option<String> },
    Token { code: Option<Secret>, public_key_pem: Option<String>, public_key_source: Option<String>, padding: Option<String> },
    List { host: String, access_token: Option<Secret>, remaining_seconds: Option<u64>, docid: Option<String>, by: Option<String>, sort: Option<String>, raw_base64: Option<Secret>, content_type: Option<String> },
    Tree { host: String, access_token: Secret, remaining_seconds: u64, root: String, by: String, sort: String, max_directories: usize },
    Page { root: String, by: String, sort: String, recursive: bool, entries: Vec<Entry>, limit: usize, cursor: Option<String> },
    Integrity { action: IntegrityAction, manifest: IntegrityManifest, docid: String, rev: String, length: u64, raw_base64: Secret },
    Preview { intent: Intent },
}
impl Input{
    fn parse(input:&str)->Result<Self,serde_json::Error>{
        struct Operation{operation:String}
        impl<'de> Deserialize<'de> for Operation{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
            #[derive(Deserialize)] struct Probe{operation:String}
            struct Visitor;impl<'de> serde::de::Visitor<'de> for Visitor{type Value=Operation;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("JSON object")}
            fn visit_seq<A:serde::de::SeqAccess<'de>>(self,_:A)->Result<Self::Value,A::Error>{Err(serde::de::Error::custom("positional input refused"))}
            fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<Self::Value,A::Error>{Probe::deserialize(serde::de::value::MapAccessDeserializer::new(access)).map(|value|Operation{operation:value.operation})}}
            deserializer.deserialize_map(Visitor)}}
        let operation:Operation=serde_json::from_str(input)?;
        macro_rules! decode{($variant:ident{$($field:ident:$kind:ty),*$(,)?})=>{{
            struct Payload{$($field:$kind),*}
            impl<'de> Deserialize<'de> for Payload{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
                #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Strict{#[serde(rename="operation")]_operation:serde::de::IgnoredAny,$($field:$kind),*}
                struct Visitor;impl<'de> serde::de::Visitor<'de> for Visitor{type Value=Strict;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("JSON object")}
                fn visit_seq<A:serde::de::SeqAccess<'de>>(self,_:A)->Result<Self::Value,A::Error>{Err(serde::de::Error::custom("positional input refused"))}
                fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<Self::Value,A::Error>{serde::de::Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(access))}}
                deserializer.deserialize_map(Visitor).map(|value|Self{$($field:value.$field),*})}
            }
            serde_json::from_str::<Payload>(input).map(|value|Self::$variant{$($field:value.$field),*})
        }}}
        match operation.operation.as_str(){
            "auth_url"=>decode!(AuthUrl{host:String}),
            "login_challenge"=>decode!(LoginChallenge{raw_base64:Secret,content_type:Option<String>}),
            "token"=>decode!(Token{code:Option<Secret>,public_key_pem:Option<String>,public_key_source:Option<String>,padding:Option<String>}),
            "list"=>decode!(List{host:String,access_token:Option<Secret>,remaining_seconds:Option<u64>,docid:Option<String>,by:Option<String>,sort:Option<String>,raw_base64:Option<Secret>,content_type:Option<String>}),
            "tree"=>decode!(Tree{host:String,access_token:Secret,remaining_seconds:u64,root:String,by:String,sort:String,max_directories:usize}),
            "page"=>decode!(Page{root:String,by:String,sort:String,recursive:bool,entries:Vec<Entry>,limit:usize,cursor:Option<String>}),
            "integrity"=>decode!(Integrity{action:IntegrityAction,manifest:IntegrityManifest,docid:String,rev:String,length:u64,raw_base64:Secret}),
            "preview"=>decode!(Preview{intent:Intent}),
            _=>Err(<serde_json::Error as serde::de::Error>::custom("unknown operation")),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all="snake_case")]
enum IntegrityAction { Record, Verify }
fn blocked(reason: &str) -> Value { json!({"status":"blocked","reason":reason}) }

/// JSON is supplied through stdin by the CLI. Never log the input or Error's
/// source parser diagnostics, which can contain secret values.
pub fn run(input: &str, online: bool) -> Result<Value, Error> {
    if input.len() > 48 * 1024 * 1024 { return Ok(blocked("input_too_large")); }
    let request: Input = match Input::parse(input) {
        Ok(value) => value, Err(_) => return Ok(blocked("invalid_input_or_unknown_field")),
    };
    let execute = || -> Result<Value, Error> {
        Ok(match request {
            Input::AuthUrl { host } => {
                let _=host;blocked("oauth_authorization_state_unsafe")
            },
            Input::LoginChallenge { raw_base64, content_type } => {
                let bytes = Zeroizing::new(STANDARD.decode(raw_base64.0.as_bytes()).map_err(|_| err("invalid_base64"))?);
                match LoginChallenge::parse(&bytes) {
                    Ok(challenge) => json!({"status":"structured","challenge_present":challenge.ready(),
                        "csrf_present":true,"secret_values_omitted":true}),
                    // Login HTML contains CSRF/challenge material and must not be a receipt.
                    Err(_) => json!({"status":"blocked","reason":"login_challenge_parse_failed_secret_html_not_exported",
                        "content_type":safe_mime(content_type.as_deref()),"byte_length":bytes.len(),"sha256":digest(&bytes)}),
                }
            },
            Input::Token { code, public_key_pem, public_key_source, padding } => {
                let _secrets = (code, public_key_pem, public_key_source, padding);
                blocked("password_path_requires_trusted_platform_public_key_source_and_confirmed_padding; observed_signin_html_has_no_PEM_key; code_exchange_requires_private_session_sink_not_receipt_output_and_is_not_implemented")
            },
            Input::List { host, access_token, remaining_seconds, docid, by, sort, raw_base64, content_type } => {
                if let Some(raw) = raw_base64 {
                    let bytes = Zeroizing::new(STANDARD.decode(raw.0.as_bytes()).map_err(|_| err("invalid_base64"))?);
                    let mut value=if access_token.as_ref().is_some_and(|token|response_contains_secret(&bytes,content_type.as_deref(),token.0.as_str())){
                        json!({"status":"degraded","evidence":Evidence{raw_base64:String::new(),content_type:None,byte_length:bytes.len(),sha256:digest(&bytes),fallback_reason:"credential_echo".into(),raw_withheld:true,raw_withheld_reason:Some("credential_echo".into())}})
                    }else{serde_json::to_value(parse_listing(&bytes, content_type.as_deref())).map_err(|_| err("serialization"))?};
                    value["source"]=json!("operator_supplied");
                    value["network_performed"]=json!(false);
                    value
                } else if !online { blocked("online_permission_required") }
                else {
                    // Credential destination is an authentication authority,
                    // unlike offline parsing, which deliberately performs no
                    // request and admits operator evidence by role only.
                    let client=Client::new(&host, access_token.ok_or_else(|| err("token_required"))?.0,
                        remaining_seconds.ok_or_else(|| err("token_expiry_required"))?)?;
                    let endpoint=match docid { Some(docid)=>ReadEndpoint::List {docid,by:by.unwrap_or_else(||"name".into()),sort:sort.unwrap_or_else(||"asc".into())}, None=>ReadEndpoint::Libraries };
                    client.read(endpoint)?
                }
            },
            Input::Tree {host,access_token,remaining_seconds,root,by,sort,max_directories} => {
                if !online { blocked("online_permission_required") } else {
                    serde_json::to_value(Client::new(&host,access_token.0,remaining_seconds)?.tree(&root,&by,&sort,max_directories)?)
                        .map_err(|_| err("serialization"))?
                }
            },
            Input::Page {root,by,sort,recursive,entries,limit,cursor} => json!({"status":"structured",
                "page":page(&root,&by,&sort,recursive,&entries,limit,cursor.as_deref())?}),
            Input::Integrity {action,mut manifest,docid,rev,length,raw_base64} => {
                let bytes=Zeroizing::new(STANDARD.decode(raw_base64.0.as_bytes()).map_err(|_| err("invalid_base64"))?);
                match action {
                    IntegrityAction::Record => { let sha256=manifest.record(&docid,&rev,length,&bytes)?;
                        json!({"status":"structured","sha256":sha256,"manifest":manifest}) },
                    IntegrityAction::Verify => json!({"status":"structured","verified":manifest.verify(&docid,&rev,length,&bytes)}),
                }
            },
            Input::Preview {intent} => json!({"status":"structured","preview":Preview::new(intent)?.inspect()}),
        })
    };
    match execute() { Ok(value)=>Ok(value), Err(_)=>Ok(blocked("drive_contract_or_remote_request_refused_no_retry")) }
}

pub fn schema() -> Value {
    let string=json!({"type":"string"});
    let optional_string=json!({"type":["string","null"]});
    let integer=json!({"type":"integer","minimum":0,"maximum":u64::MAX});
    let optional_integer=json!({"type":["integer","null"],"minimum":0,"maximum":u64::MAX});
    let entry=json!({"type":"object","additionalProperties":false,"required":["docid","name","rev","size"],
        "properties":{"docid":string,"name":string,"rev":string,"size":{"type":"integer","minimum":i64::MIN,"maximum":i64::MAX},"modified":{}}});
    let intent=json!({"type":"object","additionalProperties":false,
        "required":["operation","target_path","parent_docid","expected_name","byte_length"],
        "properties":{"operation":{"enum":["upload","move","copy","delete_file","delete_directory","rename","create_directory"]},
            "source_docid":optional_string,"source_rev":optional_string,"target_path":string,"parent_docid":string,
            "expected_name":string,"ondup":{"type":["integer","null"]},"overwrites":{"type":["boolean","null"]},
            "byte_length":integer,"local_sha256":optional_string}});
    let mut branches=Vec::new();
    for (operation, required, mut properties) in [
        ("login_challenge",vec!["raw_base64"],json!({"raw_base64":string,"content_type":optional_string})),
        ("token",vec![],json!({"code":optional_string,"public_key_pem":optional_string,"public_key_source":optional_string,"padding":optional_string})),
        ("list",vec!["host"],json!({"host":string,"access_token":optional_string,"remaining_seconds":optional_integer,
            "docid":optional_string,"by":optional_string,"sort":optional_string,"raw_base64":optional_string,"content_type":optional_string})),
        ("tree",vec!["host","access_token","remaining_seconds","root","by","sort","max_directories"],json!({"host":string,"access_token":string,"remaining_seconds":integer,"root":string,"by":string,"sort":string,"max_directories":integer})),
        ("page",vec!["root","by","sort","recursive","entries","limit"],json!({"root":string,"by":string,"sort":string,"recursive":{"type":"boolean"},"entries":{"type":"array","items":entry},"limit":integer,"cursor":optional_string})),
        ("integrity",vec!["action","manifest","docid","rev","length","raw_base64"],json!({"action":{"enum":["record","verify"]},"manifest":{"type":"object","required":["records"],"properties":{"records":{"type":"object","additionalProperties":{"type":"string"}}}},"docid":string,"rev":string,"length":integer,"raw_base64":string})),
        ("preview",vec!["intent"],json!({"intent":intent})),
    ] {
        properties["operation"]=json!({"const":operation});
        let mut required=required; required.push("operation");
        branches.push(json!({"type":"object","additionalProperties":false,"required":required,"properties":properties}));
    }
    json!({"module":"drive","status":"pending","default_host":"bhpan.buaa.edu.cn",
        "input":{"oneOf":branches},
        "output":{"type":"object","required":["status"],"properties":{"status":{"enum":["structured","degraded","blocked"]}},
            "allOf":[{"if":{"required":["source"],"properties":{"source":{"const":"operator_supplied"}}},
                "then":{"required":["network_performed"],"properties":{"network_performed":{"const":false}}}}]},
        "offline_list_output":{"type":"object","required":["status","source","network_performed"],
            "properties":{"status":{"enum":["structured","degraded"]},"source":{"const":"operator_supplied"},"network_performed":{"const":false}}},
        "transport":"https_only","credential_authority_host":"bhpan.buaa.edu.cn","oauth_authorization":{"status":"blocked","reason":"private_random_single_consumption_state_and_exchange_sink_unavailable"},"directory_listing":{"status":"blocked","reason":"deployment_attr_contract_unconfirmed"},"authentication":{"status":"blocked",
            "reason":"platform_public_key_padding_and_key_provenance_not_supplied","credential_sources":["stdin","keyring"],
            "token_storage":"memory_only","automatic_refresh":false},
        "writes":{"status":"blocked","reason":"upstream_idempotency_and_postcondition_contract_not_admitted"},
        "pagination":{"origin":"client_snapshot","binds":["root","by","sort","recursive","complete_entry_snapshot"]},
        "integrity":{"algorithm":"sha256","key":["docid","rev","length"],"rev_is_digest":false},
        "read_output":{"oneOf":[
            {"type":"object","required":["status","http_status","value"],"properties":{"status":{"const":"structured"},"http_status":{"type":"integer"},"value":{}}},
            {"type":"object","required":["status","http_status","evidence"],"properties":{"status":{"const":"degraded"},"http_status":{"type":"integer"},"evidence":{"type":"object","required":["raw_base64","content_type","byte_length","sha256","fallback_reason","raw_withheld"],"properties":{"raw_base64":{"type":"string"},"content_type":{"type":["string","null"]},"byte_length":{"type":"integer","minimum":0},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"fallback_reason":{"type":"string"},"raw_withheld":{"type":"boolean"},"raw_withheld_reason":{"type":"string"}}}}}
        ]}})
}

// Fixed synthetic response scenarios exercise the same admission and projection
// used after a completed read, without constructing a client or a governor.
#[cfg(test)]
mod numeric_read_regression {
    use super::*;

    const BODY: &[u8] = br#"[{"docid":"d","n":1e3}]"#;
    const SAFE_BODY: &[u8] = br#"[{"docid":"d","n":42}]"#;
    const MIME: Option<&str> = Some("application/json");

    fn libraries_path() -> &'static str {
        let (path, request_body) = ReadEndpoint::Libraries.request().unwrap();
        assert!(request_body.is_none());
        path
    }

    #[test]
    pub(super) fn normalized_numeric_credential_is_withheld() {
        let error = admit_read_body(libraries_path(), 200, BODY, MIME, "1000.0", false)
            .err().expect("numeric credential must not be projected");
        assert_eq!(error.code, "credential_echo_withheld");
        assert_eq!(error.message, "drive contract refused; no automatic retry");
    }

    #[test]
    pub(super) fn issued_session_cookie_is_refused_before_projection() {
        // This reader keeps no cookie jar, so a Set-Cookie response carries a
        // credential the caller never submitted and cannot revoke.
        let error = admit_read_body(libraries_path(), 200, SAFE_BODY, MIME, "unrelated-secret", true)
            .err()
            .expect("a response that issued a session cookie must not be projected");
        assert_eq!(error.code, "session_cookie_refused");
        // The same body without cookie issuance is admitted, so the refusal is
        // caused by issuance alone.
        assert!(admit_read_body(libraries_path(), 200, SAFE_BODY, MIME, "unrelated-secret", false).is_ok());
    }

    fn assert_structured(body: &[u8], secret: &str, number: Value) {
        let result = admit_read_body(libraries_path(), 200, body, MIME, secret, false).unwrap();
        // read_output's network flag describes its production caller. This is
        // a synthetic direct call and does not claim an actual request.
        assert_eq!(result, json!({
            "status":"structured", "http_status":200, "network_performed":true,
            "value":[{"docid":"d","n":number}],
            "source":{
                "raw_base64":STANDARD.encode(body), "content_type":"application/json",
                "byte_length":body.len(), "sha256":digest(body),
                "fallback_reason":"retained_original", "raw_withheld":false
            }
        }));
    }

    #[test]
    pub(super) fn numeric_credential_controls() {
        assert_structured(BODY, "unrelated-secret", json!(1000.0));
        assert_structured(SAFE_BODY, "1000.0", json!(42));
    }

    #[test]
    pub(super) fn independent_denials_remain_recognized() {
        // Client::read classifies this response before admission and retains
        // the classification for lease settlement; no lease is opened here.
        assert_eq!(rejection_code(BODY), None);
        assert_eq!(rejection_code(br#"{"code":401001003,"n":1e3}"#), Some(401001003));
        let error = admit_read_body(libraries_path(), 200, BODY, MIME, "unrelated-secret", true)
            .unwrap_err();
        assert_eq!(error.code, "session_cookie_refused");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn fixture_source_never_claims_network() {
        for online in [false,true] {
            let output=run(&json!({"operation":"list","host":"bhpan.buaa.edu.cn", "raw_base64":STANDARD.encode(br#"{"dirs":[],"files":[]}"#),"content_type":"application/json"}).to_string(),online).unwrap();
            assert_eq!(output["status"],"structured");
            assert_eq!(output["source"],"operator_supplied");
            assert_eq!(output["network_performed"],false);
        }
    }
    #[test] fn error_json_is_not_success() {
        for status in [200,400,404] {
            let bytes=br#"{"code":404006,"message":"synthetic missing"}"#;
            let output=read_output("/dir/list",status,bytes,Some("application/json"));
            assert_eq!(output["status"],"degraded");
            assert_eq!(output["evidence"]["raw_base64"],STANDARD.encode(bytes));
        }
        assert_eq!(read_output("/dir/list",200,br#"{"dirs":[],"files":[]}"#,Some("application/json"))["status"],"structured");
        assert_eq!(read_output("/dir/list",404,br#"{"dirs":[],"files":[]}"#,None)["status"],"degraded");
    }
    #[test] fn credential_rejection_keeps_cooldown() {
        use std::os::unix::fs::DirBuilderExt;
        for body_failed in [false,true] {
            let path=std::env::temp_dir().join(format!("drive-settlement-{}-{}-{}",std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),body_failed));
            std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            let governor=Governor::isolated_for_test(&path).unwrap();
            let lease=governor.try_acquire(crate::governor::RequestKind::Interactive).unwrap();
            settle_response(lease,429,Some("1800"),false,body_failed,Some(401001003)).unwrap();
            let state=governor.status().unwrap();
            assert!(!state.safety_latched);
            assert!(state.cooldown_wait>std::time::Duration::from_secs(1700));
            assert!(governor.try_acquire(crate::governor::RequestKind::Interactive).is_err());
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test] fn unified_offline_dispatch() {
        let unsafe_url=run(r#"{"operation":"auth_url","host":"bhpan.buaa.edu.cn"}"#,false).unwrap();
        assert_eq!(unsafe_url["status"],"blocked");assert_eq!(unsafe_url["reason"],"oauth_authorization_state_unsafe");assert_eq!(unsafe_url["network_performed"],Value::Null);
        let challenge=STANDARD.encode(br#"{"challenge":"secret_fixture","csrftoken":"csrf_fixture"}"#);
        let output=run(&json!({"operation":"login_challenge","raw_base64":challenge}).to_string(),false).unwrap();
        assert_eq!(output["challenge_present"],true);
        assert!(!output.to_string().contains("secret_fixture"));
        assert_eq!(run(r#"{"operation":"list","host":"bhpan.buaa.edu.cn"}"#,false).unwrap()["status"],"blocked");
        assert_eq!(run(r#"{"operation":"token","code":"secret_fixture"}"#,true).unwrap()["status"],"blocked");
        assert_eq!(run(r#"{"operation":"auth_url","host":"bhpan.buaa.edu.cn","unexpected":true}"#,false).unwrap()["status"],"blocked");
        let record=run(&json!({"operation":"integrity","action":"record","manifest":{"records":{}},"docid":"id","rev":"r","length":3,"raw_base64":STANDARD.encode(b"abc")}).to_string(),false).unwrap();
        let verify=run(&json!({"operation":"integrity","action":"verify","manifest":record["manifest"],"docid":"id","rev":"r","length":3,"raw_base64":STANDARD.encode(b"abc")}).to_string(),false).unwrap();
        assert_eq!(verify["verified"],true);
        assert_eq!(schema()["input"]["oneOf"].as_array().unwrap().len(),7);
        assert_eq!(run(r#"["list",{"host":"bhpan.buaa.edu.cn","access_token":"opaque123"}]"#,false).unwrap()["reason"],"invalid_input_or_unknown_field");assert_eq!(run(r#"[{"host":"bhpan.buaa.edu.cn","access_token":"opaque123"}]"#,false).unwrap()["reason"],"invalid_input_or_unknown_field");assert!(!run(r#"["list",{"host":"bhpan.buaa.edu.cn","access_token":"opaque123"}]"#,false).unwrap().to_string().contains("opaque123"));
    }
    fn entry(id: &str) -> Entry { Entry {docid:id.into(),name:id.into(),rev:"v1".into(),size:1,modified:Value::Null} }
    #[test] fn login_contract() {
        assert!(auth_url(AUTHORITY_HOST).is_err());
        assert!(auth_url("evil.example").is_err());
        assert!(LoginChallenge::parse(br#"<script>{"challenge":"synthetic","csrftoken":"synthetic"}</script>"#).unwrap().ready());
        assert!(LoginChallenge::parse(br#"{"challenge":"a","challenge":"b","csrftoken":"c"}"#).is_err());
        assert!(authorization_code("anyshare://oauth2/login/callback?code=fixture&state=any").is_err());
        assert!(authorization_code("https://evil.invalid/?code=fixture&state=bad").is_err());
        assert_eq!(schema()["authentication"]["status"], "blocked");
        assert_eq!(run(r#"{"operation":"auth_url","host":"bhpan.buaa.edu.cn"}"#,false).unwrap()["reason"],"oauth_authorization_state_unsafe");
    }
    #[test] fn listing_and_fallback() {
        let bytes=br#"{"dirs":[],"files":[{"docid":"a","name":"a","rev":"v","size":1,"creator":"x"}]}"#;
        assert!(matches!(parse_listing(bytes,Some("application/json")), Listing::Structured{..}));
        let Listing::Degraded{evidence}=parse_listing(b"opaque",Some("text/plain")) else {panic!()};
        assert_eq!(STANDARD.decode(evidence.raw_base64).unwrap(),b"opaque");
        assert_eq!(evidence.content_type.as_deref(),Some("text/plain"));
        assert_eq!(evidence.sha256,digest(b"opaque"));
    }
    #[test] fn unsafe_fallback_withholds_raw_but_keeps_provenance(){
        for (bytes,ct,reason) in [
            (b"<input name=captcha value=unsafe>".as_slice(),Some("text/html"),"challenge_detected"),
            (b"opaque".as_slice(),None,"response_safety_unreviewed"),
        ]{
            let evidence=Evidence::new(bytes,ct,"unrecognized_dir_list");assert!(evidence.raw_withheld);assert!(evidence.raw_base64.is_empty());assert_eq!(evidence.raw_withheld_reason.as_deref(),Some(reason));assert_eq!(evidence.sha256,digest(bytes));assert_eq!(evidence.byte_length,bytes.len());
        }
        assert!(response_contains_secret(br#"{"message":"echo private\"token"}"#,None,"private\"token"));
        assert!(response_contains_secret(b"safe",Some("text/plain; private-token"),"private-token"));
        let evidence=Evidence::new(b"new access_token=private-material",Some("text/plain"),"unrecognized");assert!(evidence.raw_withheld);assert!(evidence.raw_base64.is_empty());
    }
    #[test] fn partial_challenge_and_header_facts_settle_on_original_lease(){
        use std::os::unix::fs::DirBuilderExt;
        for (index,(bytes,header,expected_latch)) in [
            (b"<input name=captcha>".as_slice(),false,true),
            (b"ordinary prefix".as_slice(),true,true),
            (b"ordinary prefix".as_slice(),false,false),
        ].into_iter().enumerate(){
            let path=std::env::temp_dir().join(format!("drive-tristate-{}-{}-{index}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
            std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            let governor=Governor::isolated_for_test(&path).unwrap();let lease=governor.try_acquire(crate::governor::RequestKind::Interactive).unwrap();
            let assessment=crate::html::assess_challenge_body(bytes,Some("text/html"),false);
            settle_response(lease,200,Some("1800"),header||assessment==crate::html::ChallengeAssessment::Detected,true,None).unwrap();
            let state=governor.status().unwrap();assert_eq!(state.safety_latched, false);assert!(state.cooldown_wait>std::time::Duration::from_secs(1700));
            if !header&&!expected_latch{assert_eq!(assessment,crate::html::ChallengeAssessment::Unreviewed);}
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test] fn decoded_credentials_and_offline_mime_are_gated(){
        assert!(response_contains_secret(br#"{"echo":"\u006fpaque123"}"#,Some("application/json"),"opaque123"));
        assert!(response_contains_secret(br#"{"\u006fpaque123":0}"#,Some("application/json"),"opaque123"));
        let body=br#"{"quota_used":0,"quota_allocated":1,"space_rate":0,"\u0061ccess_token":"fresh-material"}"#;
        let out=read_output("/quota/user",200,body,Some("application/json"));assert_eq!(out["status"],"degraded");assert!(!out.to_string().contains("fresh-material"));assert_eq!(out["evidence"]["raw_withheld"],true);
        for mime in [None,Some("application/xhtml+xml")]{assert!(matches!(parse_listing(br#"{"dirs":[],"files":[]}"#,mime),Listing::Degraded{..}));}
        let out=run(&json!({"operation":"list","host":"bhpan.buaa.edu.cn","access_token":"opaque123","raw_base64":STANDARD.encode(br#"{"dirs":[],"files":[]}"#),"content_type":"application/xhtml+xml"}).to_string(),true).unwrap();assert_eq!(out["status"],"degraded");assert_eq!(out["source"],"operator_supplied");assert_eq!(out["network_performed"],false);
        let output=run(&json!({"operation":"list","host":"evil.example","raw_base64":STANDARD.encode(br#"{"dirs":[],"files":[]}"#),"content_type":"application/json"}).to_string(),false).unwrap();assert_eq!(output["status"],"structured");assert_eq!(output["source"],"operator_supplied");assert_eq!(output["network_performed"],false);
        let offline=run(&json!({"operation":"list","host":"evil.example"}).to_string(),false).unwrap();assert_eq!(offline["status"],"blocked");assert_eq!(offline["network_performed"],Value::Null);
        for online in [false,true] {assert_eq!(run(&json!({"operation":"list","host":"evil.example","access_token":"opaque123","remaining_seconds":60}).to_string(),online).unwrap()["status"],"blocked");}
        let out=run(&json!({"operation":"list","host":"bhpan.buaa.edu.cn","access_token":"opaque123","raw_base64":STANDARD.encode(br#"{"echo":"\u006fpaque123"}"#),"content_type":"application/json"}).to_string(),false).unwrap();assert_eq!(out["evidence"]["raw_withheld"],true);assert_eq!(out["network_performed"],false);assert!(!out.to_string().contains("opaque123"));
        let input=Input::parse(r#"{"operation":"list","host":"bhpan.buaa.edu.cn","access_token":"opaque123"}"#).unwrap();if let Input::List{access_token:Some(token),..}=input{let _: &Zeroizing<String>=&token.0;}else{panic!("typed token absent");}
        assert!(serde_json::from_slice::<PrivateValue>(br#"{"first":"private","first":"duplicate"}"#).is_err());
    }
    #[test] fn metadata_echoes_are_sanitized(){
        let bytes=br#"{"access_token":"freshopaque123"}"#;let ct="application/json; proof=freshopaque123";
        let evidence=Evidence::new(bytes,Some(ct),"sensitive");assert_eq!(evidence.raw_withheld_reason.as_deref(),Some("sensitive_response_material"));assert_eq!(evidence.content_type.as_deref(),Some("application/json"));assert!(!serde_json::to_string(&evidence).unwrap().contains("freshopaque123"));
        let out=run(&json!({"operation":"login_challenge","raw_base64":"eA==","content_type":"text/html; access_token=fresh-material"}).to_string(),false).unwrap();assert_eq!(out["status"],"blocked");assert_eq!(out["content_type"],"text/html");assert!(!out.to_string().contains("fresh-material"));
        for online in [false,true] {assert_eq!(run(&json!({"operation":"list","host":"collector.example","access_token":"opaque123","remaining_seconds":60}).to_string(),online).unwrap()["status"],"blocked");}
    }
    #[test] fn nested_shape_and_encoded_echo_contracts(){
        assert!(response_contains_secret(b"echo=abc%2B123",Some("text/plain"),"abc+123"));
        for input in [r#"{"operation":"preview","intent":["rename",null,null,"private","parent","name",1,false,0,null]}"#,r#"{"operation":"page","root":"root","by":"name","sort":"asc","recursive":false,"entries":[["d","private","r",1,null]],"limit":10}"#,r#"{"operation":"integrity","action":"record","manifest":[{}],"docid":"d","rev":"r","length":0,"raw_base64":""}"#]{assert_eq!(run(input,false).unwrap()["reason"],"invalid_input_or_unknown_field");}
        assert_eq!(run(" \n {\"operation\":\"auth_url\",\"host\":\"bhpan.buaa.edu.cn\"} \t",false).unwrap()["reason"],"oauth_authorization_state_unsafe");
        assert!(ReadEndpoint::List{docid:"d".into(),by:"name".into(),sort:"asc".into()}.request().is_err());assert!(ReadEndpoint::Quota.request().is_ok());
    }
    #[test] fn composed_encoding_and_duplicate_facts(){
        let evidence=Evidence::new(b"%61%63%63%65%73%73%5F%74%6F%6B%65%6E=opaqueABC123",Some("application/x-www-form-urlencoded"),"shape");assert!(evidence.raw_withheld);assert!(evidence.raw_base64.is_empty());
        assert!(response_contains_secret(br#"{"echo":"abc%2B\u0031\u0032\u0033"}"#,Some("application/json"),"abc+123"));
        assert_eq!(rejection_code(br#"{"code":401001001,"note":0,"note":1}"#),Some(401001001));assert_eq!(rejection_code(br#"{"note":0,"note":1,"code":"401001003"}"#),Some(401001003));
        let mut headers=reqwest::header::HeaderMap::new();headers.append("content-type",reqwest::header::HeaderValue::from_static("text/plain"));headers.append("content-type",reqwest::header::HeaderValue::from_static("text/html"));let mime=response_content_type(&headers);assert!(mime.is_none());assert_ne!(crate::html::assess_challenge_body(b"<input name=captcha>",mime.as_deref(),true),crate::html::ChallengeAssessment::Clear);
    }
    #[test] fn repeated_retry_after_survives_body_failure(){
        use std::os::unix::fs::DirBuilderExt;let path=std::env::temp_dir().join(format!("drive-many-retry-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();let governor=Governor::isolated_for_test(&path).unwrap();
        let mut headers=reqwest::header::HeaderMap::new();headers.append("retry-after",reqwest::header::HeaderValue::from_static("0"));headers.append("retry-after",reqwest::header::HeaderValue::from_static("1800"));headers.append("retry-after",reqwest::header::HeaderValue::from_bytes(b"\xff").unwrap());
        let mut lease=governor.try_acquire(crate::governor::RequestKind::Interactive).unwrap();lease.observe_http_many(429,headers.get_all("retry-after").iter().map(|value|value.to_str().ok()),false).unwrap();settle_response(lease,429,Some("0"),false,true,None).unwrap();assert!(governor.status().unwrap().cooldown_wait>std::time::Duration::from_secs(1700));drop(governor);std::fs::remove_dir_all(path).unwrap();
    }
    
    #[test] fn cursor_binds_snapshot() {
        let entries=vec![entry("a"),entry("b")];
        let first=page("root","name","asc",false,&entries,1,None).unwrap();
        let c=first.next_cursor.as_deref();
        assert_eq!(page("root","name","asc",false,&entries,1,c).unwrap().entries[0].docid,"b");
        assert!(page("other","name","asc",false,&entries,1,c).is_err());
        assert!(page("root","name","asc",true,&entries,1,c).is_err());
        assert!(page("root","name","desc",false,&entries,1,c).is_err());
        assert!(page("root","name","asc",false,&[entry("a"),entry("c")],1,c).is_err());
    }
    #[test] fn local_integrity() {
        let mut manifest=IntegrityManifest::default();
        manifest.record("id","revision",3,b"abc").unwrap();
        assert!(manifest.verify("id","revision",3,b"abc"));
        assert!(!manifest.verify("id","revision",3,b"abd"));
        assert!(!manifest.verify("id","revision",2,b"ab"));
        assert!(manifest.record("id","revision",3,b"abd").is_err());
    }
    #[test] fn write_confirmation_is_not_commit() {
        let intent=Intent{operation:Mutation::Rename,source_docid:Some("id".into()),source_rev:Some("r".into()),target_path:"/new".into(),parent_docid:"parent".into(),expected_name:"new".into(),ondup:Some(1),overwrites:Some(false),byte_length:3,local_sha256:None};
        let preview=Preview::new(intent.clone()).unwrap();
        assert!(preview.confirm("wrong",true).is_err());
        assert!(preview.confirm(&preview.confirmation,false).is_err());
        assert!(preview.confirm(&preview.confirmation,true).is_err());
        let mut renamed=intent.clone(); renamed.ondup=Some(2); assert!(Preview::new(renamed).is_err());
        let mut overwrite=intent.clone(); overwrite.overwrites=Some(true); assert!(Preview::new(overwrite.clone()).is_err());
        overwrite.ondup=Some(3); assert!(Preview::new(overwrite).is_ok());
        let mut override_conflict=intent.clone();override_conflict.ondup=Some(3);override_conflict.overwrites=Some(false);assert!(Preview::new(override_conflict).is_err());
        let mut missing_semantics=intent.clone();missing_semantics.ondup=None;missing_semantics.overwrites=None;assert!(Preview::new(missing_semantics).is_err());
    }
    #[test] fn reversible_credential_encodings_and_issued_cookie_are_detected(){
        for body in [br#"{"docid":"YWJjXzEyMw==","name":"safe"}"#.as_slice(),br#"{"docid":"\u0059WJjXzEyMw==","name":"safe"}"#.as_slice(),br#"{"docid":"%61%62%63%5F%31%32%33","name":"safe"}"#.as_slice()] {
            let error=admit_read_body("/file/metadata",200,body,Some("application/json"),"abc_123",false).unwrap_err();
            assert_eq!(error.code,"credential_echo_withheld");
            assert_eq!(error.message,"drive contract refused; no automatic retry");
        }
        let body=br#"{"docid":"freshopaque123","name":"safe"}"#;
        let error=admit_read_body("/file/metadata",200,body,Some("application/json"),"abc_123",true).unwrap_err();
        assert_eq!(error.code,"session_cookie_refused");
        assert_eq!(error.message,"drive contract refused; no automatic retry");
        let safe=admit_read_body("/file/metadata",200,body,Some("application/json"),"abc_123",false).unwrap();
        assert_eq!(safe["status"],"structured");
        assert_eq!(safe["value"]["docid"],"freshopaque123");
    }
}
