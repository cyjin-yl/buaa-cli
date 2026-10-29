//! Pending Boya HTTPS client. No UI automation or speculative write endpoints.
use crate::{governor::{Governor,Outcome},net::{self,Error}};
use base64::{Engine as _,engine::general_purpose::STANDARD};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use openssl::{hash::{hash,MessageDigest},rand::rand_bytes,rsa::{Rsa,Padding},symm::{Cipher,encrypt,decrypt}};
use std::{io::Read,time::{SystemTime,UNIX_EPOCH}};
use zeroize::Zeroizing;
use zeroize::Zeroize;
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
fn sensitive_value(value:&Value)->bool{match value{Value::String(text)=>sensitive_raw(text.as_bytes()),Value::Array(values)=>values.iter().any(sensitive_value),Value::Object(values)=>values.iter().any(|(key,value)|{
    // A literal null contains no issued token. Do not exempt non-null values
    // or other credential-shaped keys from the existing privacy check.
    !(key.eq_ignore_ascii_case("token") && value.is_null())
        && (sensitive_raw(key.as_bytes()) || sensitive_value(value))
}),_=>false}}
struct Secret(Zeroizing<String>);
impl<'de> Deserialize<'de> for Secret{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{String::deserialize(deserializer).map(|value|Self(Zeroizing::new(value)))}}
fn optional_object<'de,D:serde::Deserializer<'de>,T:Deserialize<'de>>(deserializer:D)->Result<Option<T>,D::Error>{
    struct Map<T>(std::marker::PhantomData<T>);impl<'de,T:Deserialize<'de>> serde::de::Visitor<'de> for Map<T>{type Value=T;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("JSON object")}
        fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<T,A::Error>{T::deserialize(serde::de::value::MapAccessDeserializer::new(access))}}
    struct Optional<T>(std::marker::PhantomData<T>);impl<'de,T:Deserialize<'de>> serde::de::Visitor<'de> for Optional<T>{type Value=Option<T>;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("object or null")}
        fn visit_none<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok(None)}fn visit_unit<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok(None)}
        fn visit_some<D:serde::Deserializer<'de>>(self,deserializer:D)->Result<Self::Value,D::Error>{deserializer.deserialize_map(Map(std::marker::PhantomData)).map(Some)}}
    deserializer.deserialize_option(Optional(std::marker::PhantomData))
}
const KEY:&str="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlHMQ3B5GsWnCe7Nlo1YiG/YmHdlOiKOST5aRm4iaqYSvhvWmwcigoyWTM+8bv2+sf6nQBRDWTY4KmNV7DBk1eDnTIQo6ENA31k5/tYCLEXgjPbEjCK9spiyB62fCT6cqOhbamJB0lcDJRO6Vo1m3dy+fD0jbxfDVBBNtyltIsDQIDAQAB";
const ALPHABET:&[u8]=b"ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678";
fn err(code:&'static str,message:&'static str)->Error {Error::new(code,message)}
fn aes(input:&[u8],key:&[u8;16],encrypting:bool)->Result<Zeroizing<Vec<u8>>,Error>{
    if input.len()>8*1024*1024 {return Err(err("body_limit","encrypted body too large"));}
    let result=if encrypting {encrypt(Cipher::aes_128_ecb(),key,None,input)}else{decrypt(Cipher::aes_128_ecb(),key,None,input)};
    result.map(Zeroizing::new).map_err(|_|err("crypto","AES ciphertext or PKCS7 padding invalid"))
}
fn rsa(input:&[u8])->Result<String,Error>{
    // The supplied MIGf DER constant is SubjectPublicKeyInfo (PUBLIC KEY),
    // not the PKCS#1 RSAPublicKey (RSA PUBLIC KEY) encoding.
    let pem=format!("-----BEGIN PUBLIC KEY-----\n{KEY}\n-----END PUBLIC KEY-----\n");
    let key=Rsa::public_key_from_pem(pem.as_bytes()).map_err(|_|err("crypto","public key rejected"))?;
    let mut out=vec![0u8;key.size() as usize];
    let len=key.public_encrypt(input,&mut out,Padding::PKCS1).map_err(|_|err("crypto","RSA encryption failed"))?;
    out.truncate(len);Ok(STANDARD.encode(out))
}
fn random_key()->Result<Zeroizing<[u8;16]>,Error>{
    let mut key=Zeroizing::new([0u8;16]);
    for byte in key.iter_mut(){loop {let mut r=[0u8;1];rand_bytes(&mut r).map_err(|_|err("crypto","secure randomness unavailable"))?; let ceiling=256-(256%ALPHABET.len());if (r[0] as usize)<ceiling {*byte=ALPHABET[r[0] as usize%ALPHABET.len()];break;}}}
    Ok(key)
}
fn sensitive_raw(bytes:&[u8])->bool{
    if bytes.windows(2).any(|part|part==b"\\u"||part==b"\\x")||bytes.windows(2).any(|part|part==b"&#"){return true;}
    fn marked(bytes:&[u8])->bool{[b"token".as_slice(),b"cookie",b"password",b"ticket",b"authorization",b"session",b"csrf",b"secret",b"loginname",b"login_name",b"credential",b"bearer",b"execution",b"nonce",b"jwt"].iter().any(|marker|bytes.windows(marker.len()).any(|part|part.eq_ignore_ascii_case(marker)))}
    marked(bytes)||url::form_urlencoded::parse(bytes).any(|(key,value)|{let key=Zeroizing::new(key.into_owned());let value=Zeroizing::new(value.into_owned());marked(key.as_bytes())||marked(value.as_bytes())})
}
fn encoded_echo(text:&str,secret:&str)->bool{!secret.is_empty()&&crate::net::carries_secret(text.as_bytes(),secret)}
fn safe_mime(value:Option<&str>)->Option<&'static str>{let essence=value?.split(';').next()?.trim();["application/json","text/plain","text/html","application/xhtml+xml","application/octet-stream"].into_iter().find(|candidate|essence.eq_ignore_ascii_case(candidate))}
fn response_content_type(headers:&reqwest::header::HeaderMap)->Zeroizing<Option<String>>{Zeroizing::new(if headers.get_all("content-type").iter().count()==1{headers.get("content-type").and_then(|value|value.to_str().ok()).map(str::to_owned)}else{None})}
fn evidence(bytes:&[u8],content_type:Option<&str>,withheld_reason:Option<&str>)->Value{
    let content_type=safe_mime(content_type);
    json!({"encoding":"base64","content_type":content_type,"byte_length":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes)),"data":withheld_reason.is_none().then(||STANDARD.encode(bytes)),"raw_withheld":withheld_reason.is_some(),"raw_withheld_reason":withheld_reason})
}
fn raw_evidence(bytes:&[u8],content_type:Option<&str>,complete:bool)->Value{
    let withheld=match crate::html::assess_challenge_body(bytes,content_type,complete){
        crate::html::ChallengeAssessment::Clear=>None,
        crate::html::ChallengeAssessment::Detected=>Some("challenge_detected"),
        crate::html::ChallengeAssessment::Unreviewed=>Some("response_safety_unreviewed"),
    };
    evidence(bytes,content_type,if sensitive_raw(bytes)||serde_json::from_slice::<PrivateValue>(bytes).ok().is_some_and(|value|sensitive_value(&value)){Some("sensitive_response_material")}else{withheld})
}
fn fallback(bytes:&[u8],content_type:Option<&str>,reason:&str)->Value{
    json!({"result":"fallback","fallback_reason":reason,"raw_evidence":raw_evidence(bytes,content_type,true)})
}
fn withheld_fallback(bytes:&[u8],content_type:Option<&str>)->Value{
    json!({"result":"fallback","fallback_reason":"sensitive_response_withheld","raw_evidence":evidence(bytes,content_type,Some("credential_echo"))})
}
fn response_contains_secret(bytes:&[u8],content_type:Option<&str>,secret:&str)->bool{
    fn contains(candidate:&[u8],secret:&str)->bool{crate::net::carries_secret(candidate,secret)}
    contains(bytes,secret)||content_type.is_some_and(|value|contains(value.as_bytes(),secret))||serde_json::from_slice::<PrivateValue>(bytes).ok().is_some_and(|value|value_contains_secret(&value,secret))
}
fn value_contains_secret(value:&Value,secret:&str)->bool{
    if secret.is_empty(){return false;}
    match value{
        Value::String(text)=>encoded_echo(text,secret),
        Value::Array(values)=>values.iter().any(|value|value_contains_secret(value,secret)),
        Value::Object(values)=>values.iter().any(|(key,value)|encoded_echo(key,secret)||value_contains_secret(value,secret)),
        Value::Number(_) | Value::Bool(_) | Value::Null=>crate::net::json_scalar_matches(value,|bytes|crate::net::carries_secret(bytes,secret)),
    }
}
#[derive(Clone,Copy,Default)]
struct SourceFields { data:bool,status:bool,errmsg:bool }
fn projected_source_contains_secret(value:&Value,fields:SourceFields,secret:&str)->bool{
    match value.get("result").and_then(Value::as_str) {
        Some("success")=>fields.data&&value.get("data").is_some_and(|value|value_contains_secret(value,secret)),
        Some("upstream_error")=>[("status",fields.status),("data",fields.data),("errmsg",fields.errmsg)].iter().any(|(key,present)|
            *present&&value.get(*key).is_some_and(|value|value_contains_secret(value,secret))),
        // Fallback metadata is generated locally; the original wire bytes and
        // content type were independently checked before constructing it.
        _=>false,
    }
}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(tag="api",content="payload",deny_unknown_fields)]
pub enum ReadRequest {
    #[serde(rename="getUserProfile")] Profile,
    #[serde(rename="queryStudentSemesterCourseByPage")] Courses(PageRequest),
    #[serde(rename="queryCourseById")] Course(IdRequest),
    #[serde(rename="queryChosenCourse")] Chosen(DateRequest),
    #[serde(rename="querySelectableCourse")] Selectable,
    #[serde(rename="queryForeCourse")] Fore,
    #[serde(rename="getAllConfig")] Config,
    #[serde(rename="queryStatisticByUserId")] Statistics,
}
#[derive(Clone,Debug,Serialize)] #[serde(deny_unknown_fields,rename_all="camelCase")]
pub struct PageRequest {pub page_number:u32,pub page_size:u32}
impl<'de> Deserialize<'de> for PageRequest{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
    #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Strict{#[serde(rename="pageNumber")]page_number:u32,#[serde(rename="pageSize")]page_size:u32}
    struct Visitor;impl<'de> serde::de::Visitor<'de> for Visitor{type Value=PageRequest;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("query object")}
    fn visit_seq<A:serde::de::SeqAccess<'de>>(self,_:A)->Result<Self::Value,A::Error>{Err(serde::de::Error::custom("positional query refused"))}
    fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<Self::Value,A::Error>{Strict::deserialize(serde::de::value::MapAccessDeserializer::new(access)).map(|value|PageRequest{page_number:value.page_number,page_size:value.page_size})}}
    deserializer.deserialize_map(Visitor)}}
#[derive(Clone,Debug,Serialize)] #[serde(deny_unknown_fields)]
pub struct IdRequest {pub id:String}
impl<'de> Deserialize<'de> for IdRequest{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
    #[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Fields{id:String}
    struct Visitor;impl<'de> serde::de::Visitor<'de> for Visitor{type Value=IdRequest;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("query object")}
        fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<Self::Value,A::Error>{Fields::deserialize(serde::de::value::MapAccessDeserializer::new(access)).map(|fields|IdRequest{id:fields.id})}}
    deserializer.deserialize_map(Visitor)
}}
#[derive(Clone,Debug,Serialize)] #[serde(deny_unknown_fields,rename_all="camelCase")]
pub struct DateRequest {pub start_date:String,pub end_date:String}
impl<'de> Deserialize<'de> for DateRequest{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
    #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Strict{#[serde(rename="startDate")]start_date:String,#[serde(rename="endDate")]end_date:String}
    struct Visitor;impl<'de> serde::de::Visitor<'de> for Visitor{type Value=DateRequest;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("query object")}
    fn visit_seq<A:serde::de::SeqAccess<'de>>(self,_:A)->Result<Self::Value,A::Error>{Err(serde::de::Error::custom("positional query refused"))}
    fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<Self::Value,A::Error>{Strict::deserialize(serde::de::value::MapAccessDeserializer::new(access)).map(|value|DateRequest{start_date:value.start_date,end_date:value.end_date})}}
    deserializer.deserialize_map(Visitor)}}
fn payload(req:&ReadRequest)->Result<(&'static str,Value),Error>{Ok(match req {
    ReadRequest::Profile=>("getUserProfile",json!({})),ReadRequest::Courses(p)=>{if p.page_size==0||p.page_size>200{return Err(err("invalid_input","pageSize must be 1..200"));}("queryStudentSemesterCourseByPage",json!(p))},
    ReadRequest::Course(p)=>("queryCourseById",json!(p)),ReadRequest::Chosen(p)=>("queryChosenCourse",json!(p)),ReadRequest::Selectable=>("querySelectableCourse",json!({})),ReadRequest::Fore=>("queryForeCourse",json!({})),ReadRequest::Config=>("getAllConfig",json!({})),ReadRequest::Statistics=>("queryStatisticByUserId",json!({})),})}
fn decode_response_with_fields(bytes:&[u8],content_type:Option<&str>,key:&[u8;16])->(Value,SourceFields){
    if crate::html::assess_challenge_body(bytes,content_type,true)!=crate::html::ChallengeAssessment::Clear{return (fallback(bytes,content_type,"response_safety_not_clear"),SourceFields::default());}
    let decoded=STANDARD.decode(bytes).ok().map(Zeroizing::new).and_then(|b|aes(&b,key,false).ok()).and_then(|b|serde_json::from_slice::<PrivateValue>(&b).ok());
    if decoded.as_ref().is_some_and(|value|sensitive_value(value)){return (withheld_fallback(bytes,content_type),SourceFields::default());}
    match decoded {
        Some(v) if v.get("status").and_then(Value::as_str)==Some("0")=>{
            let fields=SourceFields{data:v.get("data").is_some(),..SourceFields::default()};
            (json!({"result":"success","data":v.get("data").cloned().unwrap_or(Value::Null)}),fields)
        },
        Some(v) if v.get("status").and_then(Value::as_str).is_some()=>{
            let fields=SourceFields{status:true,data:v.get("data").is_some(),errmsg:v.get("errmsg").is_some()};
            (json!({"result":"upstream_error","status":v["status"],"data":v.get("data"),"errmsg":v.get("errmsg")}),fields)
        },
        _=>(fallback(bytes,content_type,"base64_aes_json_contract_unrecognized"),SourceFields::default()),
    }
}
pub fn decode_response(bytes:&[u8],content_type:Option<&str>,key:&[u8;16])->Value{
    decode_response_with_fields(bytes,content_type,key).0
}
pub fn parse_page(data:&Value)->Result<Value,Error>{
    let content=data.get("content").and_then(Value::as_array).ok_or_else(||err("invalid_page","content is not a list"))?;
    let fields=["totalElements","totalPages","size","number"];
    if fields.iter().any(|k|data.get(k).and_then(Value::as_u64).is_none())||data["size"].as_u64()==Some(0)||content.len() as u64>data["size"].as_u64().unwrap_or(0){return Err(err("invalid_page","pagination metadata invalid"));}
    Ok(data.clone())
}
pub struct BoyaClient {http:reqwest::blocking::Client,governor:Governor}
struct ReadResponse<'a>{bytes:&'a [u8],ct:Option<&'a str>,status:u16,challenge:bool,body_failed:bool,assessment:crate::html::ChallengeAssessment,issues_cookie:bool}
/// Extract only from the canonical HTTPS application URL, never from a CAS
/// ticket or an untrusted redirect host. Returned token is secret.
pub fn auth_token(final_url:&str)->Result<Zeroizing<String>,Error>{
    let tail=final_url.strip_prefix("https://bykc.buaa.edu.cn/").ok_or_else(||err("login_contract","token URL must be canonical HTTPS Boya"))?;
    if tail.contains('#')||tail.chars().any(char::is_control){return Err(err("login_contract","invalid final URL"));}
    let query=tail.split_once('?').map(|(_,query)|query).ok_or_else(||err("login_required","authenticated final URL has no token"))?;
    let mut token=None;
    for(key,value)in url::form_urlencoded::parse(query.as_bytes()){
        let key=Zeroizing::new(key.into_owned());let value=Zeroizing::new(value.into_owned());
        if key.as_str()=="token"{if token.is_some(){return Err(err("login_contract","ambiguous auth token"));}token=Some(value);}
    }
    token.filter(|value|!value.is_empty()).ok_or_else(||err("login_required","authenticated final URL has no token"))
}
impl BoyaClient {
    pub fn open()->Result<Self,Error>{Ok(Self{http:reqwest::blocking::Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never()).timeout(std::time::Duration::from_secs(30)).build().map_err(|_|err("transport","HTTPS initialization failed"))?,governor:Governor::open().map_err(|_|err("governor_denied","shared governor unavailable"))?})}
    /// Token-issuing CAS authentication remains closed before transport. The
    /// current outcome contract cannot simultaneously represent indeterminate
    /// authentication on an HTTP success status and preserve body failures;
    /// sending would also require a one-shot Authentication lease.
    pub fn login(&self,_cookie:&str,_legacy_path:bool)->Result<Zeroizing<String>,Error>{
        Err(err("unsupported","Boya CAS token issuance is blocked: one-shot authentication outcome settlement cannot be proved"))
    }
    /// Token must come from a governed authenticated CAS session, never argv.
    pub fn read(&self,auth_token:&str,req:&ReadRequest)->Result<Value,Error>{
        if auth_token.is_empty()||reqwest::header::HeaderValue::from_str(auth_token).is_err(){return Err(err("invalid_input","credential header cannot be constructed"));}
        let (api,data)=payload(req)?;let key=random_key()?;
        let plain=Zeroizing::new(serde_json::to_vec(&data).map_err(|_|err("json","payload serialization failed"))?);
        let body=STANDARD.encode(aes(&plain,&key,true)?.as_slice());
        let digest=hash(MessageDigest::sha1(),plain.as_slice()).map_err(|_|err("crypto","SHA1 digest failed"))?;
        let digest_hex:String=digest.iter().map(|b|format!("{b:02x}")).collect();
        let ak=rsa(key.as_slice())?;let sk=rsa(digest_hex.as_bytes())?;
        let ts=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|err("clock","invalid clock"))?.as_millis().to_string();
        let request=self.http.post(format!("https://bykc.buaa.edu.cn/sscv/{api}")).header("auth_token",auth_token).header("authtoken",auth_token).header("Referer","https://bykc.buaa.edu.cn/system/course-select").header("Origin","https://bykc.buaa.edu.cn").header("Content-Type","application/json;charset=UTF-8").header("ak",ak).header("sk",sk).header("ts",ts).body(body).timeout(std::time::Duration::from_secs(30));
        let mut lease=net::acquire(&self.governor)?;
        let mut response=match lease.start_request(||request.send()){
            Ok(Ok(response))=>response,
            Ok(Err(_))=>{lease.finish(Outcome::NetworkFailure).map_err(|_|err("governor_denied","settlement failed"))?;return Err(err("network_error","HTTPS request failed; not retried"));},
            Err(crate::governor::FollowupError::CachedChallenge)=>{lease.finish(Outcome::SafetyObserved).map_err(|_|err("governor_denied","settlement failed"))?;return Err(err("safety_latched","shared safety observation prevents request"));},
            Err(crate::governor::FollowupError::Governor(_))=>return Err(err("governor_denied","request-start admission unavailable")),
        };
        let status=response.status().as_u16();let retry=response.headers().get("retry-after").and_then(|v|v.to_str().ok()).map(str::to_owned);
        let header_challenge=response.headers().iter().any(|(k,v)|net::challenge_header(k.as_str(),v.as_bytes()));
        let ct=response_content_type(response.headers());
        // A newly issued session cookie is a credential this client never
        // submitted and cannot revoke; its value must never reach the caller.
        let issues_cookie=net::issues_session_cookie(response.headers());
        lease.observe_http_many(status,response.headers().get_all("retry-after").iter().map(|value|value.to_str().ok()),header_challenge).map_err(|_|err("governor_denied","cannot persist response headers"))?;
        let mut bytes=Zeroizing::new(Vec::new());let failure=response.by_ref().take(8*1024*1024+1).read_to_end(&mut bytes).is_err();
        let body_failed=failure||bytes.len()>8*1024*1024;
        let assessment=crate::html::assess_challenge_body(&bytes,ct.as_deref(),!body_failed);
        let challenge=header_challenge||assessment==crate::html::ChallengeAssessment::Detected;
        drop(response);
        // Complete admission while the original lease is still held.
        let result=admit_response(ReadResponse{bytes:&bytes,ct:ct.as_deref(),status,challenge,body_failed,assessment,issues_cookie},auth_token,&key,req);
        lease.finish(Outcome::Http{status,retry_after:retry.as_deref(),challenge,network_failure:body_failed}).map_err(|_|err("governor_denied","settlement failed"))?;
        result
    }
}
fn admit_response(response:ReadResponse<'_>,auth_token:&str,key:&[u8;16],req:&ReadRequest)->Result<Value,Error>{
    let ReadResponse{bytes,ct,status,challenge,body_failed,assessment,issues_cookie}=response;
    let secret_echo=response_contains_secret(bytes,ct,auth_token);
    let safe_ct=ct.filter(|value|!response_contains_secret(b"",Some(value),auth_token));
    let (value,fields)=if assessment==crate::html::ChallengeAssessment::Clear{
        if secret_echo{(withheld_fallback(bytes,safe_ct),SourceFields::default())}else{decode_response_with_fields(bytes,ct,key)}
    }else{(Value::Null,SourceFields::default())};
    let mut decoded=PrivateValue(value);
    if !secret_echo&&projected_source_contains_secret(&decoded,fields,auth_token){decoded=PrivateValue(withheld_fallback(bytes,safe_ct));}
    if matches!(req,ReadRequest::Courses(_)) && decoded["result"]=="success" && parse_page(&decoded["data"]).is_err(){
        decoded=PrivateValue(fallback(bytes,ct,"invalid_pagination_contract"));
    }
    if challenge||matches!(status,401|403|429){return Err(err("safety_denied","access denied; no retry"));}
    if body_failed{return Err(err("body_limit","response incomplete or oversized"));}
    if status!=200{return Err(err("http_error","upstream HTTP failure"));}
    if assessment==crate::html::ChallengeAssessment::Unreviewed{return Err(err("response_safety_unreviewed","response body safety could not be established; admission refused without retry"));}
    // Cookie issuance alone is not a challenge; the issued value stays private
    // and the whole response is withheld without refresh or retry.
    if issues_cookie{return Err(err("session_cookie_refused","response issued a session cookie; response withheld"));}
    Ok(std::mem::take(&mut decoded.0))
}
#[derive(Deserialize,Serialize)] #[serde(rename_all="snake_case")]
pub enum WriteOperation {Select,Cancel}
#[derive(Deserialize,Serialize)] #[serde(deny_unknown_fields)]
pub struct WriteIntent {pub operation:WriteOperation,pub course_id:String,pub owner_present:bool}
pub fn preview_write(intent:&WriteIntent)->Value {json!({"result":"blocked","intent":intent,"reason":"缺少选/退课端点与载荷的上游证据","confirmation_available":false,"write_performed":false})}
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
#[derive(Default,Deserialize)]
struct RunPayload{auth_token:Option<Secret>,final_token_url:Option<Secret>,query:Option<RunQuery>}
#[derive(Deserialize)] #[serde(untagged)]
enum RunQuery{Page(PageRequest),Date(DateRequest)}
#[derive(Clone,Copy,Deserialize)] #[serde(rename_all="snake_case")]
enum RunOperation {Profile,SemesterCourses,Selectable,Chosen,Config,Statistics,PreviewWrite}
/// Envelope admission is strict; payload is arbitrary JSON so invalid/missing
/// operation-specific material is reported as structured blocked, not a panic.
pub fn run(input:&str,online:bool)->Result<Value,Error>{
    let result=(||->Result<Value,Error>{
        let input:RunInput=serde_json::from_str(input).map_err(|_|err("invalid_input","expected operation and optional JSON payload only"))?;
        if matches!(input.operation,RunOperation::PreviewWrite){return Ok(json!({"result":"blocked","reason":"缺少选/退课端点与载荷的上游证据","confirmation_available":false,"write_performed":false}));}
        if !online{return Ok(json!({"result":"blocked","reason":"online permission required; no request made"}));}
        let p=input.payload.unwrap_or_default();
        let token=if let Some(url)=p.final_token_url{auth_token(&url.0)?}else{p.auth_token.filter(|value|!value.0.is_empty()).ok_or_else(||err("login_required","auth_token or final_token_url required via stdin"))?.0};
        let req=match input.operation{
            RunOperation::Profile=>ReadRequest::Profile,RunOperation::Selectable=>ReadRequest::Selectable,RunOperation::Config=>ReadRequest::Config,RunOperation::Statistics=>ReadRequest::Statistics,
            RunOperation::SemesterCourses=>ReadRequest::Courses(match p.query{Some(RunQuery::Page(query))=>query,_=>return Err(err("invalid_input","query requires pageNumber and pageSize"))}),
            RunOperation::Chosen=>ReadRequest::Chosen(match p.query{Some(RunQuery::Date(query))=>query,_=>return Err(err("invalid_input","query requires startDate and endDate"))}),
            RunOperation::PreviewWrite=>unreachable!(),
        };
        BoyaClient::open()?.read(&token,&req)
    })();
    Ok(match result{Ok(v)=>v,Err(e)=>json!({"result":"blocked","reason":e.code})})
}
pub fn schema()->Value{json!({"module":"boya","state":"pending","input":{"type":"object","additionalProperties":false,"required":["operation"],"properties":{"operation":{"enum":["profile","semester_courses","selectable","chosen","config","statistics","preview_write"]},"payload":{}}},"payload_policy":"arbitrary JSON admitted; missing/invalid operation-specific fields produce structured blocked","output":{"type":"object","required":["result"],"properties":{"result":{"enum":["success","upstream_error","fallback","blocked"]}}},"writes":"blocked: missing authoritative endpoint and payload","login":"token issuance blocked before transport: one-shot Authentication outcome contract unproved; reads require an existing governed CAS session token"})}
#[cfg(test)]
mod numeric_admission_proof {
    use super::*;

    fn admit(plain: &[u8], secret: &str, status: u16, challenge: bool) -> Result<Value, Error> {
        let key = [0u8; 16];
        let wire = STANDARD.encode(aes(plain, &key, true).unwrap().as_slice());
        admit_response(ReadResponse {
            bytes: wire.as_bytes(), ct: Some("text/plain"), status, challenge,
            body_failed: false,
            assessment: crate::html::assess_challenge_body(wire.as_bytes(), Some("text/plain"), true),
            issues_cookie: false,
        }, secret, &key, &ReadRequest::Profile)
    }

    pub fn boolean_credential() {
        let value = admit(br#"{"status":"0","token":null,"data":false}"#, "false", 200, false).unwrap();
        assert_eq!(value["result"], "fallback");
        assert_eq!(value["fallback_reason"], "sensitive_response_withheld");
        assert_eq!(value["raw_evidence"]["data"], Value::Null);
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert!(value.get("data").is_none());
    }

    pub fn numeric_credential() {
        let value = admit(br#"{"status":"0","token":null,"data":1e3}"#, "1000.0", 200, false).unwrap();
        assert_eq!(value["result"], "fallback");
        assert_eq!(value["fallback_reason"], "sensitive_response_withheld");
        assert_eq!(value["raw_evidence"]["data"], Value::Null);
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert!(value.get("data").is_none());
    }

    pub fn controls_and_denials() {
        let body = br#"{"status":"0","token":null,"data":false}"#;
        assert_eq!(admit(body, "unrelated-secret", 200, false).unwrap(), json!({"result":"success","data":false}));
        let number = br#"{"status":"0","token":null,"data":42}"#;
        assert_eq!(admit(number, "unrelated-secret", 200, false).unwrap(), json!({"result":"success","data":42}));
        for (status, challenge) in [(401, false), (403, false), (429, false), (200, true)] {
            assert_eq!(admit(body, "false", status, challenge).unwrap_err().code, "safety_denied");
        }
    }

    pub fn generated_fallback_metadata_is_not_an_echo() {
        let wire = b"YWJj";
        let value = admit_response(ReadResponse {
            bytes: wire, ct: Some("text/plain"), status: 200, challenge: false,
            body_failed: false,
            assessment: crate::html::assess_challenge_body(wire, Some("text/plain"), true),
            issues_cookie: false,
        }, "false", &[0u8; 16], &ReadRequest::Profile).unwrap();
        assert_eq!(value["result"], "fallback");
        assert_eq!(value["fallback_reason"], "base64_aes_json_contract_unrecognized");
        assert_eq!(value["raw_evidence"]["data"], STANDARD.encode(wire));
        assert_eq!(value["raw_evidence"]["raw_withheld"], false);
    }

    pub fn upstream_error_scalar_is_still_screened() {
        let value = admit(br#"{"status":"9","data":false}"#, "false", 200, false).unwrap();
        assert_eq!(value["result"], "fallback");
        assert_eq!(value["fallback_reason"], "sensitive_response_withheld");
        assert!(value["raw_evidence"]["data"].is_null());
    }

    pub fn missing_fields_are_not_source_nulls() {
        let success = admit(br#"{"status":"0"}"#, "null", 200, false).unwrap();
        assert_eq!(success["result"], "success");
        assert!(success["data"].is_null());
        let error = admit(br#"{"status":"9","data":42}"#, "null", 200, false).unwrap();
        assert_eq!(error["result"], "upstream_error");
        assert_eq!(error["data"], 42);
        assert!(error["errmsg"].is_null());
    }

    pub fn explicit_source_null_is_screened() {
        let value = admit(br#"{"status":"0","data":null}"#, "null", 200, false).unwrap();
        assert_eq!(value["result"], "fallback");
        assert_eq!(value["fallback_reason"], "sensitive_response_withheld");
        assert!(value["raw_evidence"]["data"].is_null());
    }
}
#[cfg(test)] mod tests{
    use super::*;
    #[test] fn boolean_scalar_credential_is_withheld() { numeric_admission_proof::boolean_credential(); }
    #[test] fn numeric_scalar_credential_is_withheld() { numeric_admission_proof::numeric_credential(); }
    #[test] fn scalar_controls_and_safety_denials_are_retained() { numeric_admission_proof::controls_and_denials(); }
    #[test] fn generated_fallback_metadata_is_not_an_echo() { numeric_admission_proof::generated_fallback_metadata_is_not_an_echo(); }
    #[test] fn upstream_error_scalar_is_still_screened() { numeric_admission_proof::upstream_error_scalar_is_still_screened(); }
    #[test] fn missing_fields_are_not_source_nulls() { numeric_admission_proof::missing_fields_are_not_source_nulls(); }
    #[test] fn explicit_source_null_is_screened() { numeric_admission_proof::explicit_source_null_is_screened(); }
    #[test]fn production_admission_withholds_cookies_and_encoded_credentials(){
        let key=[0u8;16];
        let admit=|plain:&[u8],headers:&reqwest::header::HeaderMap|{
            let wire=STANDARD.encode(aes(plain,&key,true).unwrap().as_slice());
            let wire=Zeroizing::new(wire);
            let assessment=crate::html::assess_challenge_body(wire.as_bytes(),Some("text/plain"),true);
            admit_response(ReadResponse{bytes:wire.as_bytes(),ct:Some("text/plain"),status:200,challenge:false,body_failed:false,assessment,issues_cookie:net::issues_session_cookie(headers)},"abc_123",&key,&ReadRequest::Profile)
        };
        let mut headers=reqwest::header::HeaderMap::new();
        let safe=br#"{"status":"0","data":{"value":"q"}}"#;
        assert_eq!(admit(safe,&headers).unwrap()["data"]["value"],"q");
        headers.insert(reqwest::header::SET_COOKIE,reqwest::header::HeaderValue::from_static("x=q"));
        assert_eq!(admit(safe,&headers).unwrap_err().code,"session_cookie_refused");
        let opaque=br#"{"status":"0","data":"freshopaque123"}"#;
        headers.insert(reqwest::header::SET_COOKIE,reqwest::header::HeaderValue::from_static("x=freshopaque123"));
        assert_eq!(admit(opaque,&headers).unwrap_err().code,"session_cookie_refused");
        headers.clear();
        for plain in [br#"{"status":"0","data":"YWJjXzEyMw=="}"#.as_slice(),br#"{"status":"0","data":"%61%62%63%5F%31%32%33"}"#.as_slice(),br#"{"status":"0","data":"\u0059WJjXzEyMw=="}"#.as_slice(),br#"{"status":"0","data":"\u002561%62%63%5F%31%32%33"}"#.as_slice(),br#"{"status":"0","data":{"\u0059WJjXzEyMw==":"ordinary"}}"#.as_slice()] {
            let value=admit(plain,&headers).unwrap();assert_eq!(value["raw_evidence"]["data"],Value::Null);assert_ne!(value["result"],"success");
        }
        // A truncated ciphertext would otherwise be returned as raw fallback.
        let wire=Zeroizing::new(STANDARD.encode([0u8;15]));
        let admit_wire=|headers:&reqwest::header::HeaderMap|admit_response(ReadResponse{bytes:wire.as_bytes(),ct:Some("text/plain"),status:200,challenge:false,body_failed:false,assessment:crate::html::assess_challenge_body(wire.as_bytes(),Some("text/plain"),true),issues_cookie:net::issues_session_cookie(headers)},"abc_123",&key,&ReadRequest::Profile);
        assert_eq!(admit_wire(&headers).unwrap()["raw_evidence"]["data"],STANDARD.encode(wire.as_bytes()));
        headers.insert(reqwest::header::SET_COOKIE,reqwest::header::HeaderValue::from_static("x=q"));
        assert_eq!(admit_wire(&headers).unwrap_err().code,"session_cookie_refused");
        for (status,challenge) in [(401,false),(403,false),(200,true)] {
            let denied=admit_response(ReadResponse{bytes:wire.as_bytes(),ct:Some("text/plain"),status,challenge,body_failed:false,assessment:crate::html::assess_challenge_body(wire.as_bytes(),Some("text/plain"),true),issues_cookie:net::issues_session_cookie(&headers)},"abc_123",&key,&ReadRequest::Profile);
            assert_eq!(denied.unwrap_err().code,"safety_denied");
        }
    }
    #[test]fn aes_known_block_and_padding(){let key=[0u8;16];let encrypted=aes(&[0u8;16],&key,true).unwrap();assert_eq!(&encrypted[..16],&[0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e]);assert_eq!(&*aes(&encrypted,&key,false).unwrap(),&vec![0u8;16]);}
    #[test]fn status_error(){let key=[0u8;16];let wire=STANDARD.encode(aes(br#"{"status":"9","errmsg":"synthetic"}"#,&key,true).unwrap().as_slice());assert_eq!(decode_response(wire.as_bytes(),Some("text/plain"),&key)["result"],"upstream_error");}
    #[test]fn page_contract(){assert!(parse_page(&json!({"content":[],"totalElements":0,"totalPages":0,"size":20,"number":0})).is_ok());assert!(parse_page(&json!({"content":[]})).is_err());}
    #[test]fn unknown_writes_never_offer_confirmation(){assert_eq!(preview_write(&WriteIntent{operation:WriteOperation::Select,course_id:"fixture".into(),owner_present:true})["confirmation_available"],false);}
    #[test]fn rsa_contract_and_token_admission(){assert_eq!(STANDARD.decode(rsa(b"fixture").unwrap()).unwrap().len(),128);assert!(auth_token("http://bykc.buaa.edu.cn/?token=x").is_err());assert_eq!(auth_token("https://bykc.buaa.edu.cn/system/course-select?token=a%2Bb").unwrap().as_str(),"a+b");}
    #[test]fn offline_entry_and_write_blocked(){assert_eq!(run(r#"{"operation":"profile"}"#,false).unwrap()["result"],"blocked");assert_eq!(run(r#"{"operation":"preview_write"}"#,true).unwrap()["confirmation_available"],false);assert_eq!(run(r#"["profile",{"auth_token":"opaque123"}]"#,false).unwrap()["reason"],"invalid_input");assert_eq!(run(r#"[{"auth_token":"opaque123"}]"#,false).unwrap()["reason"],"invalid_input");}
    #[test]fn positional_queries_are_refused(){assert_eq!(run(r#"{"operation":"semester_courses","payload":{"query":[1,20]}}"#,false).unwrap()["reason"],"invalid_input");assert_eq!(run(r#"{"operation":"chosen","payload":{"query":["2026-01-01","2026-01-02"]}}"#,false).unwrap()["reason"],"invalid_input");assert!(serde_json::from_str::<PageRequest>(r#"[1,20]"#).is_err());assert!(serde_json::from_str::<DateRequest>(r#"["a","b"]"#).is_err());}
    #[test]fn unsafe_raw_evidence_is_withheld(){
        let challenge=decode_response(br#"<form><input name="captcha" value="unsafe"></form>"#,Some("text/html"),&[0u8;16]);
        assert_eq!(challenge["raw_evidence"]["data"],Value::Null);assert_eq!(challenge["raw_evidence"]["raw_withheld_reason"],"challenge_detected");assert!(!challenge.to_string().contains("unsafe"));
        let partial=raw_evidence(b"ordinary prefix",Some("text/plain"),false);assert_eq!(partial["data"],Value::Null);assert_eq!(partial["raw_withheld_reason"],"response_safety_unreviewed");
        let safe=raw_evidence(b"ordinary text",Some("text/plain"),true);assert_eq!(safe["data"],"b3JkaW5hcnkgdGV4dA==");
    }
    #[test]fn secret_echoes_never_leave_through_fallback(){
        let secret="private\"token";
        assert!(response_contains_secret(br#"{"echo":"private\"token"}"#,None,secret));
        assert!(response_contains_secret(b"safe",Some("text/plain; private\"token"),secret));
        assert!(value_contains_secret(&json!({"nested":[secret]}),secret));
        let out=withheld_fallback(secret.as_bytes(),Some("text/plain"));assert!(!out.to_string().contains("private"));assert_eq!(out["raw_evidence"]["data"],Value::Null);
        let out=fallback(b"new access_token=private-material",Some("text/plain"),"unrecognized");assert_eq!(out["raw_evidence"]["data"],Value::Null);assert!(!out.to_string().contains("private-material"));
    }
    #[test]fn cas_exchange_blocks_before_admission(){
        use std::os::unix::fs::DirBuilderExt;
        let path=std::env::temp_dir().join(format!("boya-auth-preflight-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let client=BoyaClient{http:reqwest::blocking::Client::builder().retry(reqwest::retry::never()).build().unwrap(),governor:Governor::isolated_for_test(&path).unwrap()};
        assert_eq!(client.login("private-cookie",false).unwrap_err().code,"unsupported");assert!(!client.governor.status().unwrap().safety_latched);
        drop(client);std::fs::remove_dir_all(path).unwrap();
    }
    #[test]fn decoded_response_and_original_input_are_protected(){
        let key=[0u8;16];let wire=STANDARD.encode(aes(br#"{"status":"0","data":{"\u0061ccess_token":"fresh-material"}}"#,&key,true).unwrap().as_slice());
        let out=decode_response(wire.as_bytes(),Some("text/plain"),&key);assert_ne!(out["result"],"success");assert!(!out.to_string().contains("fresh-material"));
        assert_ne!(decode_response(wire.as_bytes(),Some("application/xhtml+xml"),&key)["result"],"success");
        assert!(response_contains_secret(br#"{"echo":"\u006fpaque123"}"#,Some("application/json"),"opaque123"));
        let input:RunInput=serde_json::from_str(r#"{"operation":"profile","payload":{"auth_token":"opaque123"}}"#).unwrap();let token=input.payload.unwrap().auth_token.unwrap();let _: &Zeroizing<String>=&token.0;
        assert_eq!(run(r#"{"operation":"profile","payload":{"auth_token":"opaque123"}}"#,false).unwrap()["result"],"blocked");
        assert!(serde_json::from_slice::<PrivateValue>(br#"{"first":"private","first":"duplicate"}"#).is_err());
    }
    #[test]fn invalid_credential_never_consumes_a_request(){
        use std::os::unix::fs::DirBuilderExt;
        let path=std::env::temp_dir().join(format!("boya-header-preflight-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let client=BoyaClient{http:reqwest::blocking::Client::builder().build().unwrap(),governor:Governor::isolated_for_test(&path).unwrap()};
        assert_eq!(client.read("bad\nheader",&ReadRequest::Profile).unwrap_err().code,"invalid_input");assert!(!client.governor.status().unwrap().safety_latched);drop(client);std::fs::remove_dir_all(path).unwrap();
    }
    #[test]fn nested_shape_and_encoded_echo_contracts(){
        assert!(response_contains_secret(b"echo=abc%2B123",Some("text/plain"),"abc+123"));assert!(response_contains_secret(b"echo=abc%2b123",Some("text/plain"),"abc+123"));
        assert_eq!(evidence(b"safe",Some("application/json; proof=freshopaque123"),Some("withheld"))["content_type"],"application/json");
        assert_eq!(run(r#"{"operation":"profile","payload":["opaque123",null,null]}"#,true).unwrap()["reason"],"invalid_input");
        assert!(serde_json::from_str::<PageRequest>(" \n {\"pageNumber\":1,\"pageSize\":20} \t").is_ok());assert!(serde_json::from_str::<DateRequest>(r#"{"startDate":"a","endDate":"b"}"#).is_ok());
    }
    #[test]fn composed_encoding_and_ambiguous_headers_refuse(){
        let encoded=b"%61%63%63%65%73%73%5F%74%6F%6B%65%6E=opaqueABC123";assert_eq!(raw_evidence(encoded,Some("application/x-www-form-urlencoded"),true)["data"],Value::Null);
        let key=[0u8;16];let wire=STANDARD.encode(aes(br#"{"status":"0","data":{"echo":"abc%2B\u0031\u0032\u0033"}}"#,&key,true).unwrap().as_slice());let decoded=PrivateValue(decode_response(wire.as_bytes(),Some("text/plain"),&key));assert!(value_contains_secret(&decoded,"abc+123"));
        let mut headers=reqwest::header::HeaderMap::new();headers.append("content-type",reqwest::header::HeaderValue::from_static("text/plain"));headers.append("content-type",reqwest::header::HeaderValue::from_static("text/html"));let mime=response_content_type(&headers);assert!(mime.is_none());assert_ne!(crate::html::assess_challenge_body(b"<input name=captcha>",mime.as_deref(),true),crate::html::ChallengeAssessment::Clear);
    }
    #[test]fn cached_observation_fences_boya_send(){
        use std::os::unix::fs::DirBuilderExt;
        let path=std::env::temp_dir().join(format!("boya-fence-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let governor=Governor::isolated_for_test(&path).unwrap();let mut lease=governor.try_acquire(crate::governor::RequestKind::Interactive).unwrap();crate::governor::publish_cached_challenge_for_test(&path).unwrap();let mut sent=false;
        assert!(matches!(lease.start_request(||{sent=true;}),Err(crate::governor::FollowupError::CachedChallenge)));assert!(!sent);lease.finish(Outcome::SafetyObserved).unwrap();let state=governor.status().unwrap();assert!(state.safety_latched);assert_eq!(state.consecutive_network_failures,0);drop(governor);std::fs::remove_dir_all(path).unwrap();
    }
}
