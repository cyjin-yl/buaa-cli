//! Pending IEAS enrolment contract. No login, retry, polling, or HTTP fallback.
//! Calls are deliberately staged: a governor denial never sleeps or retries.
//! Mutation is blocked until authenticated account and postcondition contracts exist.
use crate::governor::{FollowupError, Governor, Outcome, RequestKind};
use crate::html::{ChallengeAssessment, assess_challenge_body};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rusqlite::Connection;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use url::Url;

const LIMIT: usize = 8 * 1024 * 1024;
const MISSING_BINDING: &str = "trusted binding of the exact HTTPS origin and port to the historical IEAS application is missing; welcome self-description is not independent evidence";
pub type Result<T, E = String> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action { Enrol, Withdraw }

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category { Professional, CoreGeneral, General, Sports }
impl Category {
    fn fields(self) -> (&'static str, &'static str) {
        match self {
            Self::Professional => ("ZYL", "xslbxk"),
            Self::CoreGeneral => ("TSL", "tsk"),
            Self::General => ("TSL", "qxrx"),
            Self::Sports => ("TSL", "ty"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Intent {
    /// Academic-year term, e.g. 2026-2027-1 (not the query code).
    pub term: String,
    /// IEAS query code, e.g. 20261.
    pub page_xnxq: String,
    pub course_id: String,
    pub serial: String,
    pub rwh: String,
    pub action: Action,
    pub category: Category,
}
impl<'de> Deserialize<'de> for Intent {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self,D::Error> {
        // Serde's derived struct contract does not reject a positional array.
        // Reject one before any credential reaches ordinary Value handling.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            term: String, page_xnxq: String, course_id: String, serial: String,
            rwh: String, action: Action, category: Category,
        }
        let raw:Raw=deserialize_object(deserializer)?;
        Ok(Self {term:raw.term,page_xnxq:raw.page_xnxq,course_id:raw.course_id,serial:raw.serial,rwh:raw.rwh,action:raw.action,category:raw.category})
    }
}
impl Intent {
    fn validate(&self) -> Result<()> {
        let pieces: Vec<_> = self.term.split('-').collect();
        if pieces.len() != 3 || pieces[0].len() != 4 || pieces[1].len() != 4
            || !pieces[0].bytes().chain(pieces[1].bytes()).all(|b| b.is_ascii_digit())
            || !matches!(pieces[2], "1" | "2" | "3")
            || pieces[0].parse::<u32>().ok().and_then(|v| v.checked_add(1)) != pieces[1].parse().ok()
            || self.page_xnxq != format!("{}{}", pieces[0], pieces[2])
            || self.course_id.is_empty() || !self.course_id.bytes().all(|b| b.is_ascii_alphanumeric())
            || self.serial.is_empty() || !self.serial.bytes().all(|b| b.is_ascii_digit())
            || self.rwh != format!("{}-{}-{}", self.term, self.course_id, self.serial)
        { return Err("invalid typed course intent".into()); }
        Ok(())
    }
}

/// The integration supplies an authenticated session transport. It MUST disable
/// redirects and automatic retries, and bound reads to `max_bytes`. Cookie values
/// remain inside that session; this module accepts only its explicit reference.
/// No implementation may issue additional requests inside `exchange`.
/// When `allow_credentials` is false, cookies, authorization headers and other
/// session credentials MUST NOT be attached, including client-default headers.
/// Implementations must enforce one overall request deadline covering headers
/// and the bounded body. Until a compliant deadline is supplied, every online
/// operation remains blocked; a client timeout alone does not satisfy this.
/// Each network response must report the privacy facts below, including on a
/// failed body read; absence of evidence is Unknown, never Absent. The Session
/// must not put cookie or credential values in these facts or diagnostics.
/// `exchange` currently returns only after body handling, so start_request
/// spans that entire synchronous call. A production transport must instead
/// expose header-returning send separately from body reads; none is bound by
/// the CLI today.
pub trait Session {
    fn reference(&self) -> &str;
    /// Integration-owned, independently reviewed binding to the historical
    /// IEAS application, including the exact HTTPS port and base path. Never
    /// derive this from candidate response prose or caller-supplied JSON.
    /// Absence is a real missing prerequisite, not a failed login verdict.
    fn trusted_ieas_base(&self) -> Option<&Url> { None }
    fn exchange(&mut self, request: &Request, max_bytes: usize) -> std::result::Result<Response, ExchangeError>;
}
/// A failure after headers retains every observed safety fact and the bounded
/// partial body. Error strings are deliberately excluded from this contract.
pub enum ExchangeError {
    BeforeResponse,
    AfterResponse(Response),
}
pub struct Request {
    pub url: Url,
    pub method: &'static str,
    pub fields: BTreeMap<String, String>,
    pub allow_credentials: bool,
}
/// An observation, not a boolean default: Unknown includes incomplete checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyFact { Present, Absent, Unknown }

/// Caller-supplied fixture bytes are not evidence about a network response.
/// Only a trusted Session may attest network privacy facts. Set-Cookie Absent
/// requires inspection of the complete header block. Credential echo Absent
/// requires an independently reviewed admission covering session credentials
/// and submitted sensitive fields, including their encoded representations.
/// Unsupported, ambiguous or incomplete encoding/inspection is Unknown; a
/// finite list of transformations cannot prove arbitrary encodings absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseSource {
    CallerSupplied,
    Network { set_cookie: PrivacyFact, credential_echo: PrivacyFact },
}
pub struct Response {
    pub status: u16,
    pub content_type: Option<String>,
    pub retry_after: Option<String>,
    pub bytes: Vec<u8>,
    /// Session-layer challenge detection, including redirects to authentication.
    pub challenge: bool,
    /// True only after a successful bounded read through response EOF.
    pub complete: bool,
    pub source: ResponseSource,
}

fn network_privacy_admitted(response: &Response) -> bool {
    matches!(response.source, ResponseSource::Network {
        set_cookie: PrivacyFact::Absent, credential_echo: PrivacyFact::Absent
    })
}

fn secure_endpoint(base: &Url) -> bool {
    base.scheme() == "https" && base.host_str() == Some("jwxt.buaa.edu.cn")
        && matches!(base.port_or_known_default(), Some(443 | 8080 | 8081 | 7001))
        && base.path() == "/ieas2.1/" && base.query().is_none() && base.fragment().is_none()
        && base.username().is_empty() && base.password().is_none()
}
fn required_token(token: Option<&str>) -> Result<&str> {
    token.filter(|s|!s.is_empty()).ok_or_else(|| "hidden token required".into())
}

fn evidence(response: &Response, reason: &str) -> Value {
    // Only anonymous or caller-provided content reaches this function. Even
    // there, attributes can carry secrets (including meta csrf tokens).
    if let Ok(source) = html(response) {
        let document = Html::parse_document(&source);
        let controls = Selector::parse("input,button,textarea,select,option,object,output,script,style,template,noscript,iframe").unwrap();
        let elements = Selector::parse("*").unwrap();
        if document.select(&controls).next().is_some()
            || document.tree.root().descendants().any(|node| matches!(node.value(), scraper::Node::Comment(_)))
            || document.select(&elements).any(|element| element.value().attrs().next().is_some()) {
            return withheld_evidence(response, reason);
        }
    } else { return withheld_evidence(response, reason); }
    json!({"kind":"fallback", "content_type":safe_content_type(response),
        "byte_count":response.bytes.len(), "sha256":format!("{:x}",Sha256::digest(&response.bytes)),
        "body_base64":STANDARD.encode(&response.bytes), "fallback_reason":reason})
}

fn response_assessment(response: &Response, complete: bool) -> ChallengeAssessment {
    if response.challenge { ChallengeAssessment::Detected }
    else {
        if response.content_type.is_none() {
            return assess_challenge_body(&response.bytes, None, complete && response.complete);
        }
        // UTF-8 prefix assessment must precede strict whole-document decoding:
        // a truncated trailing character cannot erase an observed challenge.
        if let Ok(encoding) = html_encoding(response) {
            if encoding.eq_ignore_ascii_case("utf-8") || encoding.eq_ignore_ascii_case("utf8") {
                // No transcoding occurred: preserve transport authority so an
                // absent charset cannot override an in-document declaration.
                return assess_challenge_body(&response.bytes, response.content_type.as_deref(), complete && response.complete);
            }
        }
        match html(response) {
            Ok(source) => assess_challenge_body(source.as_bytes(), Some("text/html; charset=utf-8"), complete && response.complete),
            Err(_) => ChallengeAssessment::Unreviewed,
        }
    }
}

fn safe_content_type(response: &Response) -> Option<&'static str> {
    let essence = response.content_type.as_deref()?.split(';').next()?.trim();
    if essence.eq_ignore_ascii_case("text/html") { Some("text/html") }
    else if essence.eq_ignore_ascii_case("application/xhtml+xml") { Some("application/xhtml+xml") }
    else if essence.eq_ignore_ascii_case("application/json") { Some("application/json") }
    else if essence.eq_ignore_ascii_case("text/plain") { Some("text/plain") }
    else { None }
}

fn withheld_evidence(response: &Response, reason: &str) -> Value {
    json!({"kind":"fallback", "content_type":safe_content_type(response),
        "byte_count":response.bytes.len(), "sha256":format!("{:x}",Sha256::digest(&response.bytes)),
        "http_status":response.status,"fallback_reason":reason,"body_withheld":true})
}

/// Decode declared UTF-8/GBK/GB2312/GB18030 without replacement characters.
/// iconv is already a platform libc dependency; unsupported encodings refuse.
fn html_encoding(response: &Response) -> Result<std::borrow::Cow<'_, str>> {
    let ct = response.content_type.as_deref().ok_or("missing content type")?;
    if !ct.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("text/html") {
        return Err("response is not HTML".into());
    }
    crate::html::declared_html_charset(ct)
        .map_err(|_| "malformed charset metadata".into())
        .map(|encoding| encoding.unwrap_or(std::borrow::Cow::Borrowed("utf-8")))
}

fn html(response: &Response) -> Result<String> {
    let encoding = html_encoding(response)?.to_ascii_lowercase();
    match encoding.as_str() {
        "utf-8" | "utf8" => String::from_utf8(response.bytes.clone()).map_err(|_| "invalid UTF-8; charset required".into()),
        "gbk" | "gb2312" | "gb18030" => {
            let from = std::ffi::CString::new(match encoding.as_str() { "gbk"=>"GBK","gb2312"=>"GB2312",_=>"GB18030" }).unwrap();
            let to = std::ffi::CString::new("UTF-8").unwrap();
            // SAFETY: valid C strings, bounded owned buffers, handle closed below.
            unsafe {
                let cd = libc::iconv_open(to.as_ptr(), from.as_ptr());
                if cd as usize == usize::MAX { return Err("charset decoder unavailable".into()); }
                let mut output = vec![0u8; response.bytes.len().saturating_mul(4).saturating_add(4)];
                let mut input = response.bytes.as_ptr() as *mut libc::c_char;
                let mut target = output.as_mut_ptr() as *mut libc::c_char;
                let mut remaining = response.bytes.len();
                let mut space = output.len();
                let result = libc::iconv(cd, &mut input, &mut remaining, &mut target, &mut space);
                libc::iconv_close(cd);
                if result == usize::MAX || remaining != 0 { return Err("invalid declared charset".into()); }
                output.truncate(output.len() - space);
                String::from_utf8(output).map_err(|_| "invalid decoded HTML".into())
            }
        }
        _ => Err("unsupported charset".into()),
    }
}

pub fn parse_list(response: &Response) -> Value {
    if !matches!(response.source, ResponseSource::CallerSupplied) && !network_privacy_admitted(response) {
        return withheld_evidence(response, "response privacy admission refused");
    }
    match response_assessment(response, response.bytes.len() <= LIMIT) {
        ChallengeAssessment::Detected => return withheld_evidence(response,"challenge detected; admission refused"),
        ChallengeAssessment::Unreviewed => return withheld_evidence(response,"challenge assessment unreviewed; admission refused"),
        ChallengeAssessment::Clear => {}
    }
    parse_list_admitted(response, matches!(response.source, ResponseSource::Network { .. }))
}

fn parse_list_admitted(response: &Response, authenticated: bool) -> Value {
    let fallback = |reason: &str| if authenticated { withheld_evidence(response, reason) } else { evidence(response, reason) };
    let source = match html(response) { Ok(s) => s, Err(e) => return fallback(&e) };
    let doc = Html::parse_document(&source);
    let token_selector = Selector::parse("input[name=token]").unwrap();
    let tokens: Vec<_> = doc.select(&token_selector).filter_map(|e| e.value().attr("value")).collect();
    if tokens.len() != 1 || tokens[0].is_empty() { return fallback("missing or ambiguous hidden token"); }
    let rows = Selector::parse("tr[id]").unwrap();
    let courses: Vec<_> = doc.select(&rows).map(|row| json!({"rwh":row.value().attr("id"),"text":row.text().collect::<Vec<_>>().join(" ")})).collect();
    if courses.is_empty() { return fallback("unrecognized or empty course table"); }
    json!({"kind":"course_list","token":tokens[0],"courses":courses})
}

/// Private fields make preview contents immutable to callers.
pub struct Preview {
    intent: Intent,
    fields: BTreeMap<String, String>,
    digest: String,
    session: String,
    base: Url,
}
impl Preview {
    pub fn value(&self) -> Value {
        json!({"intent":self.intent,"fields":self.fields,"confirmation":self.digest,
            "expected_selected":self.intent.action == Action::Enrol,"session_ref":self.session})
    }
}

pub struct Enrol<'a, S: Session> {
    session: &'a mut S,
    governor: &'a Governor,
    ledger: &'a Connection,
    base: Url,
    application_bound: bool,
}
impl<'a, S: Session> Enrol<'a, S> {
    /// Caller supplies a private durable ledger in autocommit mode. No mutation
    /// reservations are written while the postcondition contract is unavailable.
    pub fn new(session: &'a mut S, governor: &'a Governor, ledger: &'a Connection, base: &str) -> Result<Self> {
        let base = Url::parse(base).map_err(|_| "invalid endpoint")?;
        if !secure_endpoint(&base) || session.reference().is_empty()
        { return Err("unsupported endpoint: HTTPS required; 上游只提供明文 HTTP 时禁止降级".into()); }
        if !ledger.is_autocommit() { return Err("active caller transaction cannot provide durable enrol reservations".into()); }
        let application_bound = session.trusted_ieas_base().is_some_and(|trusted| trusted == &base);
        Ok(Self { session, governor, ledger, base, application_bound })
    }
    fn request(&mut self, path: &str, method: &'static str, fields: BTreeMap<String,String>) -> Result<Response> {
        let anonymous_probe = path == "welcome" && method == "GET" && fields.is_empty();
        if !anonymous_probe && !self.application_bound { return Err(MISSING_BINDING.into()); }
        let request = Request { url:self.base.join(path).map_err(|_| "invalid request path")?, method, fields, allow_credentials:!anonymous_probe };
        let mut lease = self.governor.try_acquire(RequestKind::Interactive)?;
        let (response, body_failed) = match lease.start_request(||self.session.exchange(&request, LIMIT)) {
            Ok(Ok(r)) => { let failed = !r.complete; (r, failed) },
            Ok(Err(ExchangeError::AfterResponse(mut r))) => { r.complete = false; (r, true) },
            Ok(Err(ExchangeError::BeforeResponse)) => { lease.finish(Outcome::NetworkFailure)?; return Err("session request failed before HTTP headers; no retry performed".into()); }
            Err(FollowupError::Governor(_)) => return Err("shared governor request admission failed; pending outcome retained".into()),
        };
        let oversized = response.bytes.len() > LIMIT;
        let assessment = response_assessment(&response, !oversized && !body_failed);
        lease.finish(Outcome::Http { status:response.status, retry_after:response.retry_after.as_deref(), challenge:matches!(assessment,ChallengeAssessment::Detected), network_failure:oversized || body_failed })?;
        if oversized { return Err("response exceeded bound".into()); }
        if body_failed { return Err(format!("response body did not complete (HTTP {}); no retry performed",response.status)); }
        match assessment {
            ChallengeAssessment::Detected => return Err(format!("challenge detected (HTTP {}); no subsequent request",response.status)),
            ChallengeAssessment::Unreviewed => return Err(format!("challenge assessment unreviewed (HTTP {}); admission refused without retry",response.status)),
            ChallengeAssessment::Clear => {}
        }
        if !(200..300).contains(&response.status) { return Err(format!("request blocked (HTTP {}); no subsequent request",response.status)); }
        if !network_privacy_admitted(&response) { return Err("response privacy admission refused; no subsequent request".into()); }
        Ok(response)
    }
    /// One credential-free HTTPS observation. A welcome page can establish a
    /// reachable candidate, never its equivalence to the historical application.
    pub fn probe(&mut self) -> Value {
        match self.request("welcome", "GET", BTreeMap::new()) {
            Ok(r) => match html(&r) {
                Ok(s) if s.contains("ieas") || s.contains("教务") => json!({"kind":"https_candidate","application_bound":self.application_bound,"reason":if self.application_bound { "independently bound by the trusted session integration" } else { MISSING_BINDING },"origin":self.base.origin().ascii_serialization()}),
                _ => evidence(&r,"HTTPS equivalent not established"),
            },
            Err(reason) => json!({"kind":"unsupported","reason":format!("HTTPS 等价端点尚未建立：{reason}；已知上游只提供明文 HTTP，禁止降级")}),
        }
    }
    pub fn list(&mut self, term: &str, category: Category, token: &str) -> Result<Value> {
        if !self.application_bound { return Err(MISSING_BINDING.into()); }
        if term.len()!=5 || !term.bytes().all(|b| b.is_ascii_digit()) || token.is_empty() { return Err("query term and hidden token required".into()); }
        let (module, class) = category.fields();
        let fields = BTreeMap::from([("pageXnxq".into(),term.into()),("pageXklb".into(),class.into()),("pageYcctkc".into(),"1".into()),("rwh".into(),String::new()),("pageKcmc".into(),String::new()),("pageKkxiaoqu".into(),String::new()),("pageKkyx".into(),String::new()),("pageKclb".into(),String::new()),("token".into(),token.into())]);
        self.request(&format!("xslbxk/queryXsxkList?pageXkmkdm={module}"),"POST",fields).map(|r|parse_list_admitted(&r, true))
    }
    pub fn preview(&self, intent: Intent, token: Option<&str>) -> Result<Preview> {
        make_preview(intent, token, self.session.reference(), &self.base)
    }
    /// Preview confirmation is not permission to write while authenticated
    /// account and authoritative postcondition contracts remain unavailable.
    pub fn submit(&mut self, preview: &Preview, confirmation: &str, explicit_reconfirmation: Option<&str>) -> Result<Value> {
        self.bound(preview)?;
        if confirmation != preview.digest { return Err("explicit immutable preview confirmation required".into()); }
        if !self.ledger.is_autocommit() { return Err("active caller transaction cannot provide durable enrol reservations".into()); }
        let _ = explicit_reconfirmation;
        Err("mutation blocked before request: authenticated-account, target-term, authoritative selected-course scope and completeness contracts are not established; no verifiable postcondition is available".into())
    }
    fn bound(&self, preview: &Preview) -> Result<()> {
        if !self.application_bound { return Err(MISSING_BINDING.into()); }
        if preview.base!=self.base || preview.session!=self.session.reference() { return Err("preview session or endpoint mismatch".into()); }
        Ok(())
    }
    /// Separate one-request readback; no automatic retries.
    pub fn verify(&mut self, preview: &Preview) -> Result<Value> {
        self.bound(preview)?;
        let fields = BTreeMap::from([("rwh".into(),String::new()),("pageXklb".into(),"xslbxk".into()),("pageXnxq".into(),preview.intent.page_xnxq.clone()),("pageKcmc".into(),String::new())]);
        let response = self.request("xslbxk/queryYxkc","POST",fields)?;
        Ok(postcondition(&response,preview))
    }
}

/// The retained endpoint contract specifies an ID test, but does not specify
/// an authenticated account marker, authoritative list container, response term
/// binding, or pagination/completeness marker. Neither arbitrary ID presence nor
/// absence can prove the requested account's final state. Do not invent those
/// markers from synthetic HTML or turn a login/error response into success.
fn postcondition(response: &Response, preview: &Preview) -> Value {
    let reason = match html(response) {
        Err(reason)=>reason,
        Ok(_)=>"selected-course response contract does not establish authenticated account, target term, authoritative list scope, and completeness".into(),
    };
    json!({"kind":"postcondition_unknown","selected":null,"verified":false,
        "confirmation":preview.digest,"reason":reason,
        "evidence":withheld_evidence(response,&reason)})
}

fn make_preview(intent: Intent, token: Option<&str>, session: &str, base: &Url) -> Result<Preview> {
        if session.is_empty() || !secure_endpoint(base) { return Err("explicit session reference and HTTPS endpoint required".into()); }
        intent.validate()?;
        let mut fields = BTreeMap::from([("rwh".into(),intent.rwh.clone()),("pageXnxq".into(),intent.page_xnxq.clone()),("pageXklb".into(),"xslbxk".into()),("pageKcmc".into(),String::new())]);
        match intent.action {
            Action::Enrol => {
                let token = required_token(token)?;
                fields.insert("token".into(),token.into());
                fields.insert("pageXklb".into(),intent.category.fields().1.into());
                fields.insert("pageYcctkc".into(),"1".into());
                for key in ["pageKkxiaoqu","pageKkyx","pageKclb"] { fields.insert(key.into(),String::new()); }
            }
            Action::Withdraw => for key in ["pageNj","pageYxdm","pageZydm","pageBs"] { fields.insert(key.into(),String::new()); },
        }
        let encoded = serde_json::to_vec(&json!({"intent":intent,"fields":fields,"session":session,"base":base.as_str()})).map_err(|_| "cannot encode preview")?;
        Ok(Preview { intent,fields,digest:format!("{:x}",Sha256::digest(encoded)),session:session.into(),base:base.clone() })
}

struct Command {
    operation: String,
    intent: Option<Intent>,
    base: Option<String>,
    session_ref: Option<String>,
    // Only the integrator's session constructor consumes this stdin material.
    session_cookie: Option<String>,
    token: Option<String>,
    confirmation: Option<String>,
    reconfirmation: Option<String>,
    page_xnxq: Option<String>,
    category: Option<Category>,
    html_base64: Option<String>,
    content_type: Option<String>,
}
impl<'de> Deserialize<'de> for Command {
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            operation:String, intent:Option<Intent>, base:Option<String>, session_ref:Option<String>,
            session_cookie:Option<String>, token:Option<String>, confirmation:Option<String>,
            reconfirmation:Option<String>, page_xnxq:Option<String>, category:Option<Category>,
            html_base64:Option<String>, content_type:Option<String>,
        }
        let raw:Raw=deserialize_object(deserializer)?;
        Ok(Self {operation:raw.operation,intent:raw.intent,base:raw.base,session_ref:raw.session_ref,
            session_cookie:raw.session_cookie,token:raw.token,confirmation:raw.confirmation,
            reconfirmation:raw.reconfirmation,page_xnxq:raw.page_xnxq,category:raw.category,
            html_base64:raw.html_base64,content_type:raw.content_type})
    }
}

/// Accept only a map before delegating field decoding to an independent helper.
/// No generic Value or credential-bearing diagnostic is constructed.
fn deserialize_object<'de,D,T>(deserializer:D)->Result<T,D::Error>
where D:serde::Deserializer<'de>, T:Deserialize<'de> {
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de,T:Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value=T;
        fn expecting(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("a JSON object")}
        fn visit_map<A:serde::de::MapAccess<'de>>(self,map:A)->Result<T,A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(std::marker::PhantomData))
}
fn blocked(reason: &str) -> Value { json!({"result":"blocked","reason":reason}) }
fn command(input: &str) -> Result<Command> {
    if input.len()>LIMIT { return Err("input exceeds bound".into()); }
    // Never include serde diagnostics: they can contain credential input.
    serde_json::from_str(input).map_err(|_| "invalid enrol command JSON".into())
}
fn command_preview(c: &Command) -> Result<Preview> {
    let intent = c.intent.clone().ok_or("typed intent required")?;
    let expected = match c.operation.as_str() { "drop_preview" | "drop" => Some(Action::Withdraw), "preview" | "submit" => Some(Action::Enrol), _ => None };
    if expected.is_some_and(|a|a!=intent.action) { return Err("operation and intent action differ".into()); }
    let base=Url::parse(c.base.as_deref().unwrap_or("https://jwxt.buaa.edu.cn:8080/ieas2.1/")).map_err(|_|"invalid endpoint")?;
    make_preview(intent,c.token.as_deref(),c.session_ref.as_deref().unwrap_or(""),&base)
}

/// CLI entry point. Network operations fail closed until the integration binds
/// its production Session through `run_with_enrol`. No fake session is created.
pub fn run(input: &str, online: bool) -> Result<Value, crate::net::Error> {
    let c=match command(input) { Ok(c)=>c,Err(e)=>return Ok(blocked(&e)) };
    let _ = &c.session_cookie; // never echo, persist, or use as a session identity
    let value=match c.operation.as_str() {
        "preview" | "drop_preview" => match command_preview(&c) {
            Ok(p)=>json!({"result":"preview","preview":p.value(),"online_verified":false}),
            Err(e)=>blocked(&e),
        },
        "list" if c.html_base64.is_some() => {
            match STANDARD.decode(c.html_base64.as_deref().unwrap_or("")) {
                Ok(bytes) if bytes.len()<=LIMIT => json!({"result":"parsed","data":parse_list(&Response {status:200,content_type:c.content_type,retry_after:None,bytes,challenge:false,complete:true,source:ResponseSource::CallerSupplied})}),
                _=>blocked("invalid or oversized base64 HTML fixture"),
            }
        }
        "export" => json!({"result":"unsupported","reason":"Export requires a production session and governed private attachment download; no unauthenticated download or raw attachment output", "path":"kbcx/ExportGrKbxx", "method":"GET", "query_parameter":"xnxq", "https_required":true,"automatic_download":false}),
        "list" | "submit" | "drop" | "verify" => blocked(if !online {"online access disabled; provide an offline list fixture or request a preview"} else {"production Session transport not bound; integration must call run_with_enrol with explicit stdin session material"}),
        _=>blocked("unsupported operation"),
    };
    Ok(value)
}

/// Integration entry: caller constructs a production Session from stdin only,
/// opens the shared governor/private persistent ledger, and passes its Enrol.
/// A probe does not establish trusted application binding. Until independent
/// binding evidence is admitted, credential-bearing operations remain blocked.
pub fn run_with_enrol<S: Session>(input: &str, online: bool, enrol: &mut Enrol<'_,S>) -> Result<Value,crate::net::Error> {
    let c=match command(input) { Ok(c)=>c,Err(e)=>return Ok(blocked(&e)) };
    if matches!(c.operation.as_str(),"preview"|"drop_preview"|"export") || c.html_base64.is_some() || !online { return run(input,online); }
    if c.session_ref.as_deref()!=Some(enrol.session.reference()) { return Ok(blocked("explicit session reference mismatch")); }
    let outcome: Result<Value> = (|| {
        match c.operation.as_str() {
            "list"=>enrol.list(c.page_xnxq.as_deref().ok_or("page_xnxq required")?,c.category.ok_or("category required")?,required_token(c.token.as_deref())?),
            "submit"|"drop" => {
                let p=command_preview(&c)?;
                enrol.submit(&p,c.confirmation.as_deref().ok_or("confirmation digest required")?,c.reconfirmation.as_deref())
            }
            "verify"=>enrol.verify(&command_preview(&c)?),
            _=>Err("unsupported operation".into()),
        }
    })();
    Ok(match outcome {Ok(data)=>json!({"result":"completed","data":data}),Err(e)=>blocked(&e)})
}

/// Nullable optional inputs correspond exactly to serde Option fields. Business
/// preconditions produce structured blocked results, not parser errors.
pub fn schema() -> Value {
    let intent=json!({"type":"object","additionalProperties":false,"required":["term","page_xnxq","course_id","serial","rwh","action","category"],"properties":{
        "term":{"type":"string"},"page_xnxq":{"type":"string"},"course_id":{"type":"string"},"serial":{"type":"string"},
        "rwh":{"type":"string"},"action":{"enum":["enrol","withdraw"]},"category":{"enum":["professional","core_general","general","sports"]}},
        "x-runtime-invariants":["adjacent academic years","page_xnxq equals term year and season","rwh equals term-course_id-serial"]});
    json!({"module":"enrol","status":"pending_online","transport":"explicit session reference; HTTPS only; production Session unbound; online response output requires trusted complete-header Set-Cookie absence and credential/sensitive-field echo absence; unknown refuses output",
        "operations":["list","preview","submit","verify","drop_preview","drop","export"],
        "input":{"type":"object","additionalProperties":false,"required":["operation"],"properties":{
            "operation":{"type":"string"},"intent":{"anyOf":[intent.clone(),{"type":"null"}]},
            "base":{"type":["string","null"]},"session_ref":{"type":["string","null"]},"session_cookie":{"type":["string","null"],"writeOnly":true},
            "token":{"type":["string","null"]},"confirmation":{"type":["string","null"]},"reconfirmation":{"type":["string","null"]},
            "page_xnxq":{"type":["string","null"]},"category":{"enum":["professional","core_general","general","sports",null]},
            "html_base64":{"type":["string","null"]},"content_type":{"type":["string","null"]}}},
        "intent":intent,
        "output":{"oneOf":[
            {"type":"object","required":["kind","reason"],"properties":{"kind":{"const":"unsupported"},"reason":{"type":"string"}}},
            {"type":"object","required":["kind","content_type","byte_count","sha256","fallback_reason"],"properties":{"kind":{"const":"fallback"},"content_type":{"type":["string","null"]},"byte_count":{"type":"integer"},"sha256":{"type":"string"},"body_base64":{"type":"string"},"body_withheld":{"type":"boolean"},"http_status":{"type":"integer"},"fallback_reason":{"type":"string"}}},
            {"type":"object","required":["kind","application_bound","reason","origin"],"properties":{"kind":{"const":"https_candidate"},"application_bound":{"type":"boolean"},"reason":{"type":"string"},"origin":{"type":"string"}}},
            {"type":"object","required":["kind","token","courses"],"properties":{"kind":{"const":"course_list"},"token":{"type":"string"},"courses":{"type":"array","items":{"type":"object","required":["rwh","text"],"properties":{"rwh":{"type":"string"},"text":{"type":"string"}}}}}},
            {"type":"object","required":["kind","selected","verified","confirmation","reason","evidence"],"properties":{"kind":{"const":"postcondition_unknown"},"selected":{"type":"null"},"verified":{"const":false},"confirmation":{"type":"string"},"reason":{"type":"string"},"evidence":{"type":"object"}}}
        ]},"command_output":{"type":"object","required":["result"],"properties":{"result":{"enum":["blocked","unsupported","preview","parsed","completed"]},"reason":{"type":"string"},"data":{"type":"object"},"preview":{"type":"object"},"online_verified":{"type":"boolean"}}}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static FIXTURE: AtomicU64 = AtomicU64::new(0);
    struct ObservedSession { calls: usize, source: &'static str, mime: &'static str, challenge: bool }
    impl Session for ObservedSession {
        fn reference(&self) -> &str { "synthetic-session" }
        fn exchange(&mut self, request: &Request, _: usize) -> std::result::Result<Response,ExchangeError> {
            assert_eq!(request.method,"GET");
            assert!(request.fields.is_empty());
            assert!(!request.allow_credentials);
            self.calls += 1;
            Ok(Response {status:200,content_type:Some(self.mime.into()),retry_after:None,bytes:self.source.as_bytes().to_vec(),challenge:self.challenge,complete:true,source:ResponseSource::Network {set_cookie:PrivacyFact::Absent,credential_echo:PrivacyFact::Absent}})
        }
    }
    fn governor_fixture() -> (std::path::PathBuf, Governor) {
        let path=std::env::temp_dir().join(format!("buaa-enrol-safety-{}-{}",std::process::id(),FIXTURE.fetch_add(1,Ordering::Relaxed)));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let governor=Governor::isolated_for_test(&path).unwrap();
        (path,governor)
    }
    struct FailedBodySession { base: Url, observed: Option<Response>, calls: usize }
    impl Session for FailedBodySession {
        fn reference(&self) -> &str { "synthetic-session" }
        fn trusted_ieas_base(&self) -> Option<&Url> { Some(&self.base) }
        fn exchange(&mut self, _: &Request, _: usize) -> std::result::Result<Response,ExchangeError> {
            self.calls+=1;
            Err(ExchangeError::AfterResponse(self.observed.take().unwrap()))
        }
    }
    struct PrivacySession { base: Url, observed: Option<Response>, fail_body: bool, calls: usize }
    impl Session for PrivacySession {
        fn reference(&self) -> &str { "synthetic-session" }
        fn trusted_ieas_base(&self) -> Option<&Url> { Some(&self.base) }
        fn exchange(&mut self, _: &Request, _: usize) -> std::result::Result<Response,ExchangeError> {
            self.calls+=1;
            let response=self.observed.take().unwrap();
            if self.fail_body { Err(ExchangeError::AfterResponse(response)) } else { Ok(response) }
        }
    }
    #[test] fn network_privacy_facts_gate_anonymous_and_authenticated_outputs() {
        for (source,authenticated,allowed) in [
            (ResponseSource::Network {set_cookie:PrivacyFact::Present,credential_echo:PrivacyFact::Absent},false,false),
            (ResponseSource::Network {set_cookie:PrivacyFact::Unknown,credential_echo:PrivacyFact::Absent},false,false),
            (ResponseSource::Network {set_cookie:PrivacyFact::Absent,credential_echo:PrivacyFact::Present},true,false),
            (ResponseSource::Network {set_cookie:PrivacyFact::Absent,credential_echo:PrivacyFact::Unknown},true,false),
            (ResponseSource::CallerSupplied,false,false),
            (ResponseSource::CallerSupplied,true,false),
            (ResponseSource::Network {set_cookie:PrivacyFact::Absent,credential_echo:PrivacyFact::Absent},false,true),
            (ResponseSource::Network {set_cookie:PrivacyFact::Absent,credential_echo:PrivacyFact::Absent},true,true),
        ] {
            let (path,governor)=governor_fixture();
            let db=Connection::open_in_memory().unwrap();
            let base=Url::parse("https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap();
            let body=if authenticated { "<input name=token value=synthetic-secret><table><tr id=r><td>synthetic-secret</td></tr></table>" } else { "<p>ordinary server response</p>" };
            let mut observed=response(body); observed.source=source;
            let mut session=PrivacySession{base:base.clone(),observed:Some(observed),fail_body:false,calls:0};
            let mut enrol=Enrol::new(&mut session,&governor,&db,base.as_str()).unwrap();
            if authenticated {
                let result=enrol.list("20261",Category::Professional,"submitted-secret");
                if allowed { assert_eq!(result.unwrap()["kind"],"course_list"); }
                else { let error=result.unwrap_err(); assert!(error.contains("privacy admission refused")); assert!(!error.contains("synthetic-secret")); }
            } else {
                let result=enrol.probe();
                if allowed { assert_eq!(result["body_base64"],STANDARD.encode(body)); }
                else { assert_eq!(result["kind"],"unsupported"); assert!(result["reason"].as_str().unwrap().contains("privacy admission refused")); assert!(result.get("body_base64").is_none()); }
            }
            assert_eq!(enrol.session.calls,1);
            drop(enrol); drop(governor); std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test] fn verify_requires_admitted_privacy_and_never_claims_an_exact_target() {
        for source in [
            ResponseSource::Network {set_cookie:PrivacyFact::Absent,credential_echo:PrivacyFact::Absent},
            ResponseSource::Network {set_cookie:PrivacyFact::Present,credential_echo:PrivacyFact::Absent},
            ResponseSource::Network {set_cookie:PrivacyFact::Absent,credential_echo:PrivacyFact::Unknown},
            ResponseSource::CallerSupplied,
        ] {
            let (path,governor)=governor_fixture();
            let db=Connection::open_in_memory().unwrap();
            let base=Url::parse("https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap();
            let mut observed=response("<table><tr id='2026-2027-1-C-001'><td>synthetic</td></tr></table>");
            observed.source=source;
            let mut session=PrivacySession{base:base.clone(),observed:Some(observed),fail_body:false,calls:0};
            let mut enrol=Enrol::new(&mut session,&governor,&db,base.as_str()).unwrap();
            let intent=Intent{term:"2026-2027-1".into(),page_xnxq:"20261".into(),course_id:"C".into(),serial:"001".into(),rwh:"2026-2027-1-C-001".into(),action:Action::Enrol,category:Category::Professional};
            let preview=enrol.preview(intent,Some("synthetic-token")).unwrap();
            let result=enrol.verify(&preview);
            if matches!(source,ResponseSource::Network {set_cookie:PrivacyFact::Absent,credential_echo:PrivacyFact::Absent}) {
                let value=result.unwrap();
                assert_eq!(value["kind"],"postcondition_unknown");
                assert_eq!(value["verified"],false);
                assert!(value["selected"].is_null());
                assert_eq!(value["evidence"]["body_withheld"],true);
            } else {
                assert!(result.unwrap_err().contains("privacy admission refused"));
            }
            assert_eq!(enrol.session.calls,1);
            governor.status().unwrap();
            drop(enrol); drop(governor); std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test] fn privacy_refusal_never_erases_original_lease_safety_facts() {
        let (path,governor)=governor_fixture();
        let db=Connection::open_in_memory().unwrap();
        let base=Url::parse("https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap();
        let mut observed=response("<input name=captcha>");
        observed.status=429; observed.retry_after=Some("3600".into()); observed.complete=false;
        observed.source=ResponseSource::Network {set_cookie:PrivacyFact::Present,credential_echo:PrivacyFact::Unknown};
        let mut session=PrivacySession{base:base.clone(),observed:Some(observed),fail_body:true,calls:0};
        let mut enrol=Enrol::new(&mut session,&governor,&db,base.as_str()).unwrap();
        let result=enrol.probe();
        assert_eq!(result["kind"],"unsupported");
        assert!(result.get("body_base64").is_none());
        assert_eq!(enrol.session.calls,1);
        let state=governor.status().unwrap();
        assert!(!state.safety_latched);
        assert!(state.cooldown_wait.as_secs()>3500);
        assert_eq!(state.consecutive_network_failures,1);
        drop(enrol); drop(governor); std::fs::remove_dir_all(path).unwrap();
    }
    #[test] fn attested_encoded_echo_or_unknown_never_reaches_list_output() {
        // The Session supplies the observation; this module does not claim to
        // detect all encodings or turn these examples into an admission rule.
        for (body,fact) in [
            ("<input name=token value='secret&#45;value'><table><tr id=r><td>row</td></tr></table>",PrivacyFact::Present),
            ("<input name=token value='secret%2Dvalue'><table><tr id=r><td>row</td></tr></table>",PrivacyFact::Present),
            ("<input name=token value='c2VjcmV0LXZhbHVl'><table><tr id=r><td>row</td></tr></table>",PrivacyFact::Present),
            ("<input name=token value=unreviewable><table><tr id=r><td>row</td></tr></table>",PrivacyFact::Unknown),
        ] {
            let (path,governor)=governor_fixture();
            let db=Connection::open_in_memory().unwrap();
            let base=Url::parse("https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap();
            let mut observed=response(body);
            observed.source=ResponseSource::Network {set_cookie:PrivacyFact::Absent,credential_echo:fact};
            let mut session=PrivacySession{base:base.clone(),observed:Some(observed),fail_body:false,calls:0};
            let mut enrol=Enrol::new(&mut session,&governor,&db,base.as_str()).unwrap();
            let error=enrol.list("20261",Category::Professional,"secret-value").unwrap_err();
            assert_eq!(error,"response privacy admission refused; no subsequent request");
            assert_eq!(enrol.session.calls,1);
            drop(enrol); drop(governor); std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test] fn missing_mime_challenge_settles_original_failed_body_lease() {
        let (path,governor)=governor_fixture();
        let db=Connection::open_in_memory().unwrap();
        let base=Url::parse("https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap();
        let mut observed=response("<input name=captcha>");
        observed.content_type=None;
        observed.retry_after=Some("3600".into());
        observed.complete=false;
        assert_eq!(response_assessment(&observed,false),ChallengeAssessment::Detected);
        let mut session=FailedBodySession{base:base.clone(),observed:Some(observed),calls:0};
        let mut enrol=Enrol::new(&mut session,&governor,&db,base.as_str()).unwrap();
        assert_eq!(enrol.probe()["kind"],"unsupported");
        assert_eq!(enrol.session.calls,1);
        let state=governor.status().unwrap();
        assert!(!state.safety_latched);
        assert!(state.cooldown_wait.as_secs()>3500);
        assert_eq!(state.consecutive_network_failures,1);
        drop(enrol); drop(governor); std::fs::remove_dir_all(path).unwrap();
    }
    #[test] fn charset_parameters_do_not_forge_utf8_challenge() {
        for mime in [
            "text/html; note=\"x;charset=utf-8\"; charset=gbk",
            "text/html; charset=utf-8; charset=gbk",
            "text/html; charset=\"utf-8",
            "text/html; note=\"unterminated; charset=utf-8",
        ] {
            let mut r=response("");
            r.bytes=b"<input name=captcha>\xff".to_vec();
            r.content_type=Some(mime.into());
            assert_eq!(response_assessment(&r,true),ChallengeAssessment::Unreviewed, "{mime}");
        }
        let mut r=response("<input name=captcha>");
        r.content_type=Some("text/html; note=\"x;charset=gbk\"; charset=\"utf-8\"".into());
        assert_eq!(response_assessment(&r,true),ChallengeAssessment::Detected);
    }
    #[test] fn fallback_admits_only_safe_anonymous_or_caller_bytes() {
        let mut r=response("<meta name=csrf-token content=synthetic-secret><p>ordinary</p>");
        r.content_type=Some("text/html; private=synthetic-header-secret; charset=utf-8".into());
        let value=parse_list(&r);
        assert_eq!(value["content_type"],"text/html");
        assert_eq!(value["body_withheld"],true);
        assert!(!value.to_string().contains("synthetic-secret"));
        assert!(!value.to_string().contains("synthetic-header-secret"));
        let mut safe=response("<p>ordinary server response</p>");
        safe.content_type=Some("text/html; private=synthetic-header-secret; charset=utf-8".into());
        let value=parse_list(&safe);
        assert_eq!(value["content_type"],"text/html");
        assert_eq!(STANDARD.decode(value["body_base64"].as_str().unwrap()).unwrap(),safe.bytes);
        assert!(!value.to_string().contains("synthetic-header-secret"));
        let authenticated=parse_list_admitted(&safe,true);
        assert_eq!(authenticated["body_withheld"],true);
        assert!(authenticated.get("body_base64").is_none());
    }
    #[test] fn truncated_utf8_preserves_confirmed_prefix_challenge_without_admitting_body() {
        for (bytes,charset,detected) in [
            (b"<input name=captcha>\xe4".as_slice(),"utf-8",true),
            (b"<input name=captcha>\xe4".as_slice(),"UTF8",true),
            (b"<p>ordinary</p>\xe4".as_slice(),"utf-8",false),
            (b"<input name=captcha>\xff".as_slice(),"gbk",false),
            (b"<input name=captcha>\xe4".as_slice(),"unknown",false),
        ] {
            let (path,governor)=governor_fixture();
            let db=Connection::open_in_memory().unwrap();
            let base=Url::parse("https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap();
            let mut observed=response(""); observed.bytes=bytes.to_vec();
            observed.content_type=Some(format!("text/html; charset={charset}")); observed.complete=false;
            let assessment=response_assessment(&observed,false);
            assert_eq!(matches!(assessment,ChallengeAssessment::Detected),detected);
            if !detected { assert!(matches!(assessment,ChallengeAssessment::Unreviewed)); }
            let mut session=FailedBodySession{base:base.clone(),observed:Some(observed),calls:0};
            let mut enrol=Enrol::new(&mut session,&governor,&db,base.as_str()).unwrap();
            assert_eq!(enrol.probe()["kind"],"unsupported");
            assert_eq!(enrol.session.calls,1);
            assert_eq!(governor.status().unwrap().safety_latched, false);
            drop(enrol); drop(governor); std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test] fn fallback_withholds_all_value_bearing_controls_including_buttons() {
        for source in [
            "<form><button name=token value=synthetic-secret>Continue</button></form>",
            "<object name=token data=synthetic-secret></object>",
            "<output name=token>synthetic-secret</output>",
            "<option value=synthetic-secret>Continue</option>",
        ] {
            let value=parse_list(&response(source));
            assert_eq!(value["body_withheld"],true);
            assert!(value.get("body_base64").is_none());
            assert!(!value.to_string().contains("synthetic-secret"));
        }
        let source="<p>ordinary server response</p>";
        assert_eq!(parse_list(&response(source))["body_base64"],STANDARD.encode(source));
    }
    #[test] fn intent_schema_is_self_contained_standalone_and_under_command_root() {
        let module=schema();
        let input=module["input"].clone();
        let global=json!({"commands":{"enrol":module}});
        let embedded=&global["commands"]["enrol"]["input"];
        assert_eq!(&input,embedded);
        for root in [&input,embedded] {
            let intent=&root["properties"]["intent"]["anyOf"][0];
            assert!(intent.get("$ref").is_none());
            assert_eq!(intent["type"],"object");
            assert_eq!(intent["additionalProperties"],false);
            let command=json!({"operation":"drop_preview","session_ref":"session","intent":{
                "term":"2026-2027-1","page_xnxq":"20261","course_id":"C","serial":"001",
                "rwh":"2026-2027-1-C-001","action":"withdraw","category":"professional"}});
            for key in intent["required"].as_array().unwrap() {
                assert!(command["intent"].get(key.as_str().unwrap()).is_some());
            }
            assert_eq!(run(&command.to_string(),false).unwrap()["result"],"preview");
        }
    }
    #[test] fn failed_body_preserves_headers_challenge_and_failure_on_original_lease() {
        for (status,challenge) in [(429,false),(401,false),(403,false),(200,true)] {
            let (path,governor)=governor_fixture();
            let db=Connection::open_in_memory().unwrap();
            let base=Url::parse("https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap();
            let mut observed=response("<p>partial");
            observed.status=status; observed.challenge=challenge;
            observed.retry_after=Some("3600".into()); observed.complete=false;
            let mut session=FailedBodySession {base:base.clone(),observed:Some(observed),calls:0};
            let mut enrol=Enrol::new(&mut session,&governor,&db,base.as_str()).unwrap();
            assert_eq!(enrol.probe()["kind"],"unsupported");
            assert_eq!(enrol.session.calls,1);
            let state=governor.status().unwrap();
            assert!(state.cooldown_wait.as_secs()>3500);
            assert_eq!(state.safety_latched, false);
            assert_eq!(state.consecutive_network_failures,1);
            drop(enrol); drop(governor); std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test] fn trusted_origin_does_not_open_mutation_without_postcondition_or_durable_state() {
        let (path,governor)=governor_fixture();
        let db=Connection::open_in_memory().unwrap();
        let base=Url::parse("https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap();
        let mut session=FailedBodySession {base:base.clone(),observed:None,calls:0};
        let mut enrol=Enrol::new(&mut session,&governor,&db,base.as_str()).unwrap();
        for action in [Action::Enrol,Action::Withdraw] {
            let intent=Intent {term:"2026-2027-1".into(),page_xnxq:"20261".into(),course_id:"C".into(),serial:"001".into(),rwh:"2026-2027-1-C-001".into(),action,category:Category::Professional};
            let preview=enrol.preview(intent,Some("token")).unwrap();
            assert!(enrol.submit(&preview,&preview.digest,None).unwrap_err().contains("postcondition"));
            db.execute_batch("BEGIN").unwrap();
            assert!(enrol.submit(&preview,&preview.digest,Some("explicit-new-attempt")).unwrap_err().contains("transaction"));
            db.execute_batch("ROLLBACK").unwrap();
        }
        assert_eq!(enrol.session.calls,0);
        assert_eq!(db.total_changes(),0);
        drop(enrol); drop(governor); std::fs::remove_dir_all(path).unwrap();
    }
    #[test] fn declared_legacy_html_is_decoded_before_assessment_without_changing_source() {
        for charset in ["gbk","gb2312","gb18030"] {
            let mut r=response("");
            r.content_type=Some(format!("text/html; charset={charset}"));
            r.bytes=b"<input name=token value=t><table><tr id=r><td>\xbf\xce\xb3\xcc</td></tr></table>".to_vec();
            let original=r.bytes.clone();
            let parsed=parse_list(&r);
            assert_eq!(parsed["kind"],"course_list");
            assert!(parsed["courses"][0]["text"].as_str().unwrap().contains("课程"));
            assert_eq!(r.bytes,original);
        }
    }
    #[test] fn unsupported_and_malformed_charsets_withhold_credential_source() {
        for (charset,bytes) in [("windows-1252",b"<input type=password value=private>".as_slice()),("gbk",b"<input name=token value=private>\xff".as_slice())] {
            let mut r=response(""); r.content_type=Some(format!("text/html; charset={charset}")); r.bytes=bytes.to_vec();
            let value=parse_list(&r);
            assert_eq!(value["body_withheld"],true);
            assert!(value.get("body_base64").is_none());
            assert_eq!(value["sha256"],format!("{:x}",Sha256::digest(bytes)));
        }
    }
    #[test] fn welcome_self_description_does_not_authorize_credentials_or_mutation() {
        for port in [443,8080,8081,7001] {
            let (path,governor)=governor_fixture();
            let db=Connection::open_in_memory().unwrap();
            let mut session=ObservedSession {calls:0,source:"<h1>ieas 教务</h1>",mime:"text/html",challenge:false};
            let mut enrol=Enrol::new(&mut session,&governor,&db,&format!("https://jwxt.buaa.edu.cn:{port}/ieas2.1/")).unwrap();
            assert_eq!(enrol.probe()["kind"],"https_candidate");
            assert!(enrol.list("20261",Category::Professional,"private-token").unwrap_err().contains("trusted binding"));
            let intent=Intent {term:"2026-2027-1".into(),page_xnxq:"20261".into(),course_id:"C".into(),serial:"001".into(),rwh:"2026-2027-1-C-001".into(),action:Action::Enrol,category:Category::Professional};
            let preview=enrol.preview(intent,Some("private-token")).unwrap();
            assert!(enrol.submit(&preview,&preview.digest,None).unwrap_err().contains("trusted binding"));
            assert_eq!(enrol.session.calls,1);
            assert_eq!(db.total_changes(),0);
            drop(enrol); drop(governor);
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test] fn session_and_body_challenges_latch_but_unreviewed_does_not() {
        for (source,mime,session_challenge,_latched) in [
            ("<input name=captcha>","text/html",false,true),
            ("<meta charset=iso-2022-jp>\u{1b}$B<div/class=cf-turnstile>\u{1b}(B","text/html",false,false),
            ("<p>ordinary</p>","text/html",true,true),
            ("<html/>","application/xhtml+xml",false,false),
        ] {
            let (path,governor)=governor_fixture();
            let db=Connection::open_in_memory().unwrap();
            let mut session=ObservedSession {calls:0,source,mime,challenge:session_challenge};
            let mut enrol=Enrol::new(&mut session,&governor,&db,"https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap();
            let value=enrol.probe();
            assert_eq!(value["kind"],"unsupported");
            assert_eq!(governor.status().unwrap().safety_latched, false);
            assert_eq!(enrol.session.calls,1);
            drop(enrol); drop(governor);
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test] fn undeclared_charset_keeps_original_assessment_authority() {
        // Same unsupported encoding vector as the shared HTML assessor; not
        // evidence of an enrol service format or a live campus response.
        let mut r=response("<meta charset=iso-2022-jp>\u{1b}$B<div/class=cf-turnstile>\u{1b}(B");
        r.content_type=Some("text/html".into());
        assert_eq!(response_assessment(&r,true),ChallengeAssessment::Unreviewed);
        let parsed=parse_list(&r);
        assert_eq!(parsed["body_withheld"],true);
        assert!(parsed.get("body_base64").is_none());
    }
    #[test] fn unsafe_offline_fallback_withholds_body() {
        for mut r in [response("<input name=captcha value=private>"),response("<html/>")] {
            if r.bytes==b"<html/>" { r.content_type=Some("application/xhtml+xml".into()); }
            let value=parse_list(&r);
            assert_eq!(value["body_withheld"],true);
            assert!(value.get("body_base64").is_none());
            assert_eq!(value["sha256"],format!("{:x}",Sha256::digest(&r.bytes)));
        }
    }
    #[test] fn command_dispatch_never_fakes_session() {
        assert_eq!(run(r#"{"operation":"submit","session_cookie":"private"}"#,true).unwrap()["result"],"blocked");
        assert_eq!(run(r#"{"operation":"verify"}"#,false).unwrap()["result"],"blocked");
        assert_eq!(run(r#"{"operation":"export"}"#,true).unwrap()["result"],"unsupported");
        assert_eq!(run(r#"{"operation":"preview","unexpected":true}"#,false).unwrap()["result"],"blocked");
    }
    #[test] fn typed_struct_inputs_reject_positional_arrays() {
        let intent=r#"["2026-2027-1","20261","C","001","2026-2027-1-C-001","enrol","professional"]"#;
        let command=format!(r#"{{"operation":"preview","intent":{intent},"session_ref":"session","token":"token"}}"#);
        assert_eq!(run(&command,false).unwrap()["result"],"blocked");
        assert!(serde_json::from_str::<Command>(&command).is_err());
        assert!(serde_json::from_str::<Intent>(intent).is_err());
        let positional=r#"["preview",null,null,"session","synthetic-secret","token",null,null,null,null,null,null]"#;
        assert!(serde_json::from_str::<Command>(positional).is_err());
        let blocked=run(positional,false).unwrap();
        assert_eq!(blocked["result"],"blocked");
        assert!(!blocked.to_string().contains("synthetic-secret"));
        let valid=r#"{"operation":"drop_preview","session_ref":"session","intent":{"term":"2026-2027-1","page_xnxq":"20261","course_id":"C","serial":"001","rwh":"2026-2027-1-C-001","action":"withdraw","category":"professional"}}"#;
        assert_eq!(run(valid,false).unwrap()["result"],"preview");
        for invalid in [
            r#"{"operation":"drop_preview","intent":{"term":"2026-2027-1","unexpected":true}}"#,
            r#"{"operation":"drop_preview","intent":{"term":"2026-2027-1","term":"2027-2028"}}"#,
        ] { assert_eq!(run(invalid,false).unwrap()["result"],"blocked"); }
    }
    #[test] fn offline_command_preview() {
        let c=json!({"operation":"drop_preview","session_ref":"session-1","intent":{
            "term":"2026-2027-1","page_xnxq":"20261","course_id":"C1","serial":"001",
            "rwh":"2026-2027-1-C1-001","action":"withdraw","category":"professional"}});
        let value=run(&c.to_string(),false).unwrap();
        assert_eq!(value["result"],"preview");
        assert_eq!(value["preview"]["expected_selected"],false);
        assert!(value.to_string().find("session_cookie").is_none());
    }
    fn response(s: &str) -> Response { Response {status:200,content_type:Some("text/html; charset=utf-8".into()),retry_after:None,bytes:s.as_bytes().to_vec(),challenge:false,complete:true,source:ResponseSource::CallerSupplied} }
    #[test] fn list_and_missing_token() {
        assert_eq!(parse_list(&response("<input name=token value=t><table><tr id=r><td>课程</td></tr></table>"))["kind"],"course_list");
        assert_eq!(parse_list(&response("<table></table>"))["kind"],"fallback");
    }
    #[test] fn raw_evidence_preserves_missing_mime() {
        let mut r=response("bad"); r.content_type=None;
        let value=parse_list(&r);
        assert!(value["content_type"].is_null());
        assert!(value.get("body_base64").is_none());
        assert_eq!(value["body_withheld"],true);
    }
    #[test] fn reject_plaintext_and_missing_token() {
        assert!(!secure_endpoint(&Url::parse("http://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap()));
        assert!(secure_endpoint(&Url::parse("https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap()));
        assert!(!secure_endpoint(&Url::parse("https://jw.buaa.edu.cn/ieas2.1/").unwrap()));
        assert!(required_token(None).is_err());
        assert!(required_token(Some("")).is_err());
    }
    #[test] fn unadmitted_postcondition_scopes_remain_unknown() {
        let base=Url::parse("https://jwxt.buaa.edu.cn:8080/ieas2.1/").unwrap();
        for action in [Action::Enrol,Action::Withdraw] {
            let preview=make_preview(Intent {term:"2026-2027-1".into(),page_xnxq:"20261".into(),course_id:"C".into(),serial:"001".into(),rwh:"2026-2027-1-C-001".into(),action,category:Category::Professional},Some("token"),"session",&base).unwrap();
            let fixtures=[
                // Login page with an unrelated table.
                "<form action='/login'><input type=password></form><table></table>",
                // Error page.
                "<h1>系统错误</h1><table><tr><td>错误</td></tr></table>",
                // Unrelated table and an ID outside that table.
                "<div id='2026-2027-1-C-001'></div><table><tr><td>公告</td></tr></table>",
                // Partial selected-course-looking list cannot prove absence.
                "<h1>已选课程</h1><table><tr id='other'></tr></table><a>下一页</a>",
                // Even plausible account/term/complete attributes are not an
                // admitted upstream contract, including an exact target ID.
                "<table data-account='session' data-term='20261' data-complete='true'><tr id='2026-2027-1-C-001'></tr></table>",
                // A plausible complete empty scope also cannot prove withdrawal.
                "<table data-account='session' data-term='20261' data-complete='true'></table>",
            ];
            for source in fixtures {
                let response=response(source);
                let result=postcondition(&response,&preview);
                assert_eq!(result["kind"],"postcondition_unknown");
                assert_eq!(result["verified"],false);
                assert!(result["selected"].is_null());
                assert!(result["evidence"].get("body_base64").is_none());
                assert_eq!(result["evidence"]["body_withheld"],true);
            }
        }
    }
}
