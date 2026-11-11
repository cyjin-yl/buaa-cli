//! Coursegrading contract admission. HTTP-only upstream writes remain blocked.
//! A reachable HTTPS login page alone does not prove equivalent authentication,
//! submission, or result semantics; no password or submission is transmitted here.
//!
//! Every operation reports the basis it actually has. The pinned reference is a
//! historical plaintext-HTTP community client, so this module never establishes
//! the current HTTPS judge contract: `transport_equivalence` stays
//! `not_established`, `authentication` and `submission` stay `refused`, and
//! `accepted_postcondition_known` stays `false`. A judge/queue status code is
//! classified on its own axis and is never bound to a submission verdict.
use crate::html::{ChallengeAssessment, assess_challenge_body};
use crate::{
    governor::{FollowupError, Governor, Outcome},
    net::{self, Error},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::{collections::BTreeSet, io::Read, path::Path};

const HTTPS: &str = "https://judge.buaa.edu.cn";
const SOURCE_REFERENCE: &str = "dhy2000/CG-Submit@ef2869d756ce4f701dba0856a6ebf302570bdbd2 (2021-scoped plaintext-HTTP community client): protocol facts only, no implementation copied";
const UNSUPPORTED_OBSERVATION: &str =
    "local contract statement; no network request and no submission";
const PREVIEW_OBSERVATION: &str = "local immutable file read; no network request and no submission";
const STATUS_OBSERVATION: &str =
    "caller-supplied response bytes parsed offline; no network request and no submission";
const PROBE_OBSERVATION: &str = "one HTTPS GET to the judge login candidate; an unauthenticated response establishes no submission contract";
const PROBE_UNAVAILABLE_OBSERVATION: &str =
    "one HTTPS GET attempted; no response obtained (unavailable or TLS validation failed)";
const SUBMIT_OBSERVATION: &str = "the on-disk source was re-read and still matches the confirmed preview digest; the multipart payload is built and the idempotency key admitted through the caller-owned ledger, with no remote request and no submission verdict";
const JUDGE_CODE_REASON: &str = "judge status code table is not source-established; queued, running, judge-side error and rejection are indistinguishable here and none of them is a submission verdict";
const FALLBACK_CODE_REASON: &str = "response was not admitted as a judging-status body, so no judge or queue code was classified and none can read as a submission verdict";

/// Machine-readable account of what one invocation actually establishes.
/// `transport_equivalence`, `authentication`, `submission` and
/// `accepted_postcondition` are fixed refusals: the pinned reference is a
/// historical plaintext-HTTP client, so it establishes neither the current HTTPS
/// judge contract, nor any right to authenticate or submit, nor an
/// accepted-submission postcondition. This is not the raw response receipt; that
/// stays in `evidence`, which may be withheld.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBasis {
    pub observation: String,
    pub requests_performed: u64,
    pub source_reference: String,
    pub transport_equivalence: String,
    pub authentication: String,
    pub submission: String,
    pub accepted_postcondition: String,
}
impl EvidenceBasis {
    fn canonical(observation: &str, requests_performed: u64) -> Self {
        Self {
            observation: observation.into(),
            requests_performed,
            source_reference: SOURCE_REFERENCE.into(),
            transport_equivalence: "not_established".into(),
            authentication: "refused".into(),
            submission: "refused".into(),
            accepted_postcondition: "not_established".into(),
        }
    }
    fn to_json(&self) -> Value {
        json!({"observation":self.observation,"requests_performed":self.requests_performed,"source_reference":self.source_reference,"transport_equivalence":self.transport_equivalence,"authentication":self.authentication,"submission":self.submission,"accepted_postcondition":self.accepted_postcondition})
    }
    /// A deserialized basis is only admitted when it is byte-for-byte the
    /// canonical basis for that operation, never a caller-authored assertion.
    fn admits_only_canonical(&self, observation: &str, requests_performed: u64) -> bool {
        *self == Self::canonical(observation, requests_performed)
    }
}
fn invalid() -> Error {
    Error::new(
        "invalid_input",
        "coursegrading requires explicit identifiers and a regular source file",
    )
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn sensitive_echo(b: &[u8]) -> bool {
    if let Ok(v) = serde_json::from_slice::<JsonPrivacy>(b) {
        return v.0;
    }
    sensitive_text(b)
}
struct JsonPrivacy(bool);
impl<'de> serde::Deserialize<'de> for JsonPrivacy {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JsonPrivacy;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut m: M,
            ) -> Result<Self::Value, M::Error> {
                let mut sensitive = false;
                while let Some(k) = m.next_key::<String>()? {
                    sensitive |= sensitive_text(k.as_bytes());
                    sensitive |= m.next_value::<JsonPrivacy>()?.0;
                }
                Ok(JsonPrivacy(sensitive))
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(
                self,
                mut s: S,
            ) -> Result<Self::Value, S::Error> {
                let mut sensitive = false;
                while let Some(v) = s.next_element::<JsonPrivacy>()? {
                    sensitive |= v.0;
                }
                Ok(JsonPrivacy(sensitive))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(sensitive_text(v.as_bytes())))
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
        }
        d.deserialize_any(Visitor)
    }
}
fn sensitive_value(v: &Value) -> bool {
    match v {
        Value::Object(o) => o
            .iter()
            .any(|(k, v)| sensitive_text(k.as_bytes()) || sensitive_value(v)),
        Value::Array(a) => a.iter().any(sensitive_value),
        Value::String(s) => sensitive_text(s.as_bytes()),
        _ => false,
    }
}
fn safe_content_type(ct: Option<&str>) -> Option<&'static str> {
    match ct?.split(';').next()?.trim() {
        v if v.eq_ignore_ascii_case("application/json") => Some("application/json"),
        v if v.eq_ignore_ascii_case("text/html") => Some("text/html"),
        v if v.eq_ignore_ascii_case("text/plain") => Some("text/plain"),
        v if v.eq_ignore_ascii_case("application/octet-stream") => Some("application/octet-stream"),
        _ => None,
    }
}
fn sensitive_text(b: &[u8]) -> bool {
    const MARKERS: &[&[u8]] = &[
        b"session",
        b"cookie",
        b"token",
        b"ticket",
        b"authorization",
        b"credential",
        b"password",
        b"passwd",
        b"secret",
        b"csrf",
        b"execution",
        b"<input",
        b"<form",
        b"bearer",
        b"jwt",
        b"nonce",
        b"loginname",
        b"login_name",
        b"\\u",
        b"\\x",
        b"&#",
    ];
    MARKERS
        .iter()
        .any(|m| b.windows(m.len()).any(|w| w.eq_ignore_ascii_case(m)))
}
fn evidence(
    b: &[u8],
    ct: Option<&str>,
    reason: &str,
    assessment: &ChallengeAssessment,
    session_cookie: bool,
) -> Value {
    // Without a cookie jar, a Set-Cookie response cannot be safely exported:
    // the original body may echo newly issued session material.
    let retain =
        matches!(assessment, ChallengeAssessment::Clear) && !sensitive_echo(b) && !session_cookie;
    let reason = if session_cookie {
        "session_cookie_issued"
    } else {
        reason
    };
    json!({"raw_base64":retain.then(||STANDARD.encode(b)),"content_type":safe_content_type(ct),"byte_count":b.len(),"sha256":hash(b),"fallback_reason":reason,"raw_withheld":!retain,"raw_provenance":if retain {"original_response"} else {"withheld_unsafe_or_unreviewed_response"}})
}
fn response_assessment(
    header_challenge: bool,
    b: &[u8],
    ct: Option<&str>,
    complete: bool,
) -> ChallengeAssessment {
    if header_challenge {
        ChallengeAssessment::Detected
    } else {
        assess_challenge_body(b, ct, complete)
    }
}
fn response_content_type(headers: &reqwest::header::HeaderMap) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(reqwest::header::CONTENT_TYPE).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    first
        .map(|value| value.to_str().map_err(|_| ()))
        .transpose()
}
pub fn unsupported() -> Value {
    json!({"result":"unsupported","reason":"Only HTTP upstream is source-established. HTTPS equivalence is not established; HTTP fallback and all authentication/submission are disabled.","https_candidate":HTTPS,"course_enumeration":"UNKNOWN","assignment_html_fields":"UNKNOWN","requests_performed":0,"accepted_postcondition_known":false,"evidence_basis":EvidenceBasis::canonical(UNSUPPORTED_OBSERVATION,0).to_json()})
}

/// Explicit, single-shot HTTPS observation. Never redirects or falls back to HTTP.
pub fn probe_https(online: bool) -> Result<Value, Error> {
    if !online {
        return Err(Error::new(
            "offline",
            "HTTPS probe requires explicit online authorization",
        ));
    }
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|_| invalid())?;
    let g = Governor::open()
        .map_err(|_| Error::new("governor_error", "shared governor unavailable"))?;
    let mut lease = net::acquire(&g)?;
    let request = client
        .get(format!("{HTTPS}/indexcs/simple.jsp?loginErr=0"))
        .timeout(std::time::Duration::from_secs(30));
    let response = match lease.start_request(|| request.send()) {
        Ok(result) => result,
        Err(FollowupError::Governor(_)) => {
            return Err(Error::new(
                "governor_error",
                "cannot admit coursegrading request; pending outcome retained",
            ));
        }
    };
    let mut response = match response {
        Ok(v) => v,
        Err(_) => {
            lease.finish(Outcome::NetworkFailure).map_err(|_| {
                Error::new(
                    "governor_error",
                    "cannot persist coursegrading request outcome",
                )
            })?;
            return Ok(
                json!({"result":"unsupported","reason":"HTTPS candidate unavailable or TLS validation failed; no HTTP fallback","requests_performed":1,"accepted_postcondition_known":false,"evidence_basis":EvidenceBasis::canonical(PROBE_UNAVAILABLE_OBSERVATION,1).to_json()}),
            );
        }
    };
    let status = response.status().as_u16();
    let ct = response_content_type(response.headers());
    let mime_reviewed = ct.is_ok();
    let ct = ct.unwrap_or(None).map(str::to_owned);
    let header_challenge = response
        .headers()
        .iter()
        .any(|(k, v)| net::challenge_header(k.as_str(), v.as_bytes()));
    let retry_after = response
        .headers()
        .get_all("retry-after")
        .iter()
        .find_map(|value| value.to_str().ok())
        .map(str::to_owned);
    // This probe does not maintain a cookie jar; no Set-Cookie body is exported.
    let session_cookie = net::issues_session_cookie(response.headers());
    if lease
        .observe_http_many(
            status,
            response
                .headers()
                .get_all("retry-after")
                .iter()
                .map(|value| value.to_str().ok()),
            header_challenge,
        )
        .is_err()
    {
        drop(response);
        return Err(Error::new(
            "governor_error",
            "cannot persist coursegrading HTTP headers",
        ));
    }
    let mut b = Vec::new();
    let read = response
        .by_ref()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut b);
    let complete = read.is_ok() && b.len() <= 4 * 1024 * 1024;
    let mut assessment = response_assessment(header_challenge, &b, ct.as_deref(), complete);
    if !mime_reviewed && matches!(&assessment, ChallengeAssessment::Clear) {
        assessment = ChallengeAssessment::Unreviewed;
    }
    // Cancel any unread body before releasing the original shared lease.
    drop(response);
    let challenge = matches!(&assessment, ChallengeAssessment::Detected);
    // The complete admitted or refused result is computed while the original
    // lease is still held; the lease settles exactly once, whatever the result.
    let result = (|| {
        if let Some(rejection) = observed_safety_rejection(status, challenge, complete) {
            return Ok(rejection);
        }
        if read.is_err() {
            return Err(Error::new("network_error", "HTTPS response body failed"));
        }
        if b.len() > 4 * 1024 * 1024 {
            return Err(Error::new("body_limit", "HTTPS response exceeds limit"));
        }
        let reason = match &assessment {
            ChallengeAssessment::Clear => {
                "HTTPS application equivalence remains unverified; no authentication or submission enabled"
            }
            ChallengeAssessment::Detected => {
                "Confirmed authentication challenge requires human review; no authentication, submission, or automatic retry enabled"
            }
            ChallengeAssessment::Unreviewed => {
                "Response body could not be safely reviewed; admission refused and no automatic retry enabled"
            }
        };
        Ok(
            json!({"result":"blocked","https_status":status,"https_page_reachable":status==200 && matches!(&assessment,ChallengeAssessment::Clear),"reason":reason,"accepted_postcondition_known":false,"evidence_basis":EvidenceBasis::canonical(PROBE_OBSERVATION,1).to_json(),"evidence":evidence(&b,ct.as_deref(),"login_page_fields_unknown",&assessment,session_cookie)}),
        )
    })();
    lease
        .finish(Outcome::Http {
            status,
            retry_after: retry_after.as_deref(),
            challenge,
            network_failure: !complete,
        })
        .map_err(|_| {
            Error::new(
                "governor_error",
                "cannot persist coursegrading request outcome",
            )
        })?;
    result
}
fn observed_safety_rejection(status: u16, challenge: bool, complete: bool) -> Option<Value> {
    let basis = EvidenceBasis::canonical(PROBE_OBSERVATION, 1).to_json();
    if matches!(status, 401 | 403) {
        Some(
            json!({"result":"blocked","https_status":status,"https_page_reachable":false,"reason":"HTTP authentication refused; shared safety latched; no automatic retry","body_complete":complete,"accepted_postcondition_known":false,"evidence_basis":basis}),
        )
    } else if challenge {
        Some(
            json!({"result":"blocked","https_status":status,"https_page_reachable":false,"reason":"confirmed challenge requires human review; shared safety latched; no automatic retry","body_complete":complete,"accepted_postcondition_known":false,"evidence_basis":basis}),
        )
    } else {
        None
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubmissionPreview {
    pub intent: String,
    pub course_id: String,
    pub assignment_id: String,
    pub problem_id: String,
    pub local_file: String,
    pub byte_count: u64,
    pub sha256: String,
    // A local preview never establishes a submission verdict; the field exists so
    // the receipt states that explicitly and a forged value cannot pass admission.
    pub accepted_postcondition_known: bool,
    pub evidence_basis: EvidenceBasis,
}
fn validate_preview(p: &SubmissionPreview) -> Result<(), Error> {
    if p.intent != "submit_coursegrading_file"
        || !id(&p.course_id)
        || !id(&p.assignment_id)
        || !id(&p.problem_id)
        || p.byte_count > 16 * 1024 * 1024
        || p.sha256.len() != 64
        || !p
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || p.accepted_postcondition_known
        || !p
            .evidence_basis
            .admits_only_canonical(PREVIEW_OBSERVATION, 0)
    {
        return Err(invalid());
    }
    Ok(())
}
// Match replay's local-file policy: descriptor-relative traversal without
// symlinks, caller-owned final parent and file, neither group/world writable.
// This does not prevent an authorized writer modifying an inode in place.
fn open_source(path: &Path) -> Result<std::fs::File, Error> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .ok_or_else(invalid)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(invalid)?;
    let directory = crate::governor::open_directory(parent, false, false).map_err(|_| invalid())?;
    let dm = directory.metadata().map_err(|_| invalid())?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if !dm.is_dir() || dm.uid() != uid || dm.mode() & 0o022 != 0 {
        return Err(Error::new("permission", "unsafe submission file parent"));
    }
    let f = crate::governor::open_child(&directory, name, libc::O_RDONLY).map_err(|_| invalid())?;
    let m = f.metadata().map_err(|_| invalid())?;
    if !m.is_file() || m.uid() != uid || m.mode() & 0o022 != 0 {
        return Err(Error::new("permission", "unsafe submission file"));
    }
    if m.len() > 16 * 1024 * 1024 {
        return Err(invalid());
    }
    Ok(f)
}
/// Pure local immutable preview. Neither the contents nor password enter receipts.
pub fn preview(
    course: &str,
    assignment: &str,
    problem: &str,
    file: &Path,
) -> Result<SubmissionPreview, Error> {
    if !id(course) || !id(assignment) || !id(problem) {
        return Err(invalid());
    }
    let mut f = open_source(file)?;
    let mut bytes = Vec::new();
    f.by_ref()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(invalid());
    }
    Ok(SubmissionPreview {
        intent: "submit_coursegrading_file".into(),
        course_id: course.into(),
        assignment_id: assignment.into(),
        problem_id: problem.into(),
        local_file: file.to_str().ok_or_else(invalid)?.into(),
        byte_count: bytes.len() as u64,
        sha256: hash(&bytes),
        accepted_postcondition_known: false,
        evidence_basis: EvidenceBasis::canonical(PREVIEW_OBSERVATION, 0),
    })
}
/// Build a candidate multipart part only after exact preview/content confirmation.
/// This is not a submission and performs no remote request.
pub fn multipart_part(
    p: &SubmissionPreview,
    bytes: Vec<u8>,
    confirmed_sha256: &str,
) -> Result<(String, Vec<u8>), Error> {
    validate_preview(p)?;
    if p.sha256 != confirmed_sha256
        || bytes.len() as u64 != p.byte_count
        || hash(&bytes) != p.sha256
    {
        return Err(invalid());
    }
    let boundary = format!("buaa-{}", p.sha256);
    if bytes
        .windows(boundary.len())
        .any(|w| w == boundary.as_bytes())
    {
        return Err(Error::new(
            "multipart_boundary_collision",
            "source collides with multipart boundary",
        ));
    }
    let mut body=format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"submission\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    body.extend_from_slice(&bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok((format!("multipart/form-data; boundary={boundary}"), body))
}
/// Local duplicate admission for a caller-owned durable ledger. The caller must
/// persist the returned key atomically BEFORE any future enabled POST, including
/// uncertain outcomes. No network write is currently enabled by this module.
pub fn admit_submission(
    p: &SubmissionPreview,
    previous: &BTreeSet<String>,
    reconfirm: bool,
) -> Result<String, Error> {
    validate_preview(p)?;
    let key = hash(
        &serde_json::to_vec(&(&p.course_id, &p.assignment_id, &p.problem_id, &p.sha256))
            .map_err(|_| invalid())?,
    );
    if previous.contains(&key) && !reconfirm {
        return Err(Error::new(
            "duplicate_submission",
            "explicit reconfirmation required for duplicate submission",
        ));
    }
    Ok(key)
}

/// Caller-owned stdin for a confirmed submission. Every member is a plain
/// identifier, digest or ledger entry: no password, cookie or session
/// material enters this document. The ledger is the caller's own durable idempotency
/// record, keyed by the same id+digest derivation `admit_submission` uses.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitRequest {
    pub course_id: String,
    pub assignment_id: String,
    pub problem_id: String,
    pub local_file: String,
    pub confirmed_sha256: String,
    #[serde(default)]
    pub reconfirm: bool,
    #[serde(default)]
    pub previous_ledger: Vec<String>,
}

/// The confirmed, idempotent, offline submission contract. It re-reads the on-disk
/// source and confirms the immutable preview digest still holds, builds the
/// confirmed multipart payload from that same byte stream, and admits it through
/// the caller-owned idempotency ledger. No remote request is sent and no
/// submission verdict is produced: `submission_success` stays null and the
/// verdict stays unknown, so a local admission is never a remote acceptance. A
/// digest drift between the confirmed preview and the disk is refused before any
/// multipart part is built.
pub fn submit_confirmed(req: &SubmitRequest) -> Result<Value, Error> {
    let preview = preview(
        &req.course_id,
        &req.assignment_id,
        &req.problem_id,
        Path::new(&req.local_file),
    )?;
    if preview.sha256 != req.confirmed_sha256 {
        return Err(Error::new(
            "digest_mismatch",
            "the on-disk source no longer matches the confirmed preview digest",
        ));
    }
    let ledger: BTreeSet<String> = req.previous_ledger.iter().cloned().collect();
    let key = admit_submission(&preview, &ledger, req.reconfirm)?;
    // Re-read through open_source so the confirmed multipart part is built from a
    // freshly validated descriptor, not the preview's already-consumed read. A
    // second read catching an in-place mutation is the safety property the
    // single preview read alone cannot state.
    let mut file = open_source(Path::new(&req.local_file))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() as u64 != preview.byte_count || hash(&bytes) != preview.sha256 {
        return Err(Error::new(
            "digest_mismatch",
            "the on-disk source no longer matches the confirmed preview digest",
        ));
    }
    let (content_type, body) = multipart_part(&preview, bytes, &req.confirmed_sha256)?;
    Ok(json!({
        "result": "submission_admitted",
        "idempotency_key": key,
        "reconfirmed": req.reconfirm,
        "course_id": preview.course_id,
        "assignment_id": preview.assignment_id,
        "problem_id": preview.problem_id,
        "confirmed_sha256": preview.sha256,
        "byte_count": preview.byte_count,
        "multipart": {
            "content_type": content_type,
            "body_bytes": body.len(),
            "body_base64": STANDARD.encode(body)
        },
        "remote_request": false,
        "submission_success": null,
        "submission_verdict_known": false,
        "accepted_postcondition_known": false,
        "evidence_basis": EvidenceBasis::canonical(SUBMIT_OBSERVATION, 0).to_json()
    }))
}
/// Offline parsing only. HTTP 200 is never considered submission success.
/// The judge `ret` code is classified on its own axis: it is an upstream status
/// observation with unverified semantics, so queued, running, judge-side error
/// and rejection stay indistinguishable and no value maps to a submission
/// verdict. A judgement or queue error therefore never reads as a failed
/// submission, and a reported finish never reads as an accepted one.
pub fn parse_status(bytes: &[u8], ct: Option<&str>) -> Value {
    let basis = EvidenceBasis::canonical(STATUS_OBSERVATION, 0).to_json();
    let assessment = assess_challenge_body(bytes, ct, true);
    if !matches!(&assessment, ChallengeAssessment::Clear) {
        return json!({"result":"fallback","judgement_error_classification":{"classification":"not_established","scope":"judge_or_queue_only","submission_verdict_bound":false,"reason":FALLBACK_CODE_REASON},"submission_success":null,"submission_verdict_known":false,"accepted_postcondition_known":false,"evidence_basis":basis,"evidence":evidence(bytes,ct,"response not admitted after challenge review",&assessment,false)});
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v)
            if !sensitive_value(&v)
                && v.as_array().is_some_and(|a| {
                    a.len() >= 2
                        && a[0].get("ret").is_some_and(Value::is_string)
                        && a[1].get("content").is_some_and(Value::is_string)
                }) =>
        {
            // `finished` only mirrors `ret == "1"` under the unverified pinned shape.
            let reported_finished = v[0]["ret"] == "1";
            json!({"result":"judging_status","finished":reported_finished,"judgement_error_classification":{"classification":"not_established","scope":"judge_or_queue_only","submission_verdict_bound":false,"reason":JUDGE_CODE_REASON},"result_html":v[1]["content"],"html_trust":"untrusted_data","submission_success":null,"submission_verdict_known":false,"accepted_postcondition_known":false,"evidence_basis":basis})
        }
        _ => {
            json!({"result":"fallback","judgement_error_classification":{"classification":"not_established","scope":"judge_or_queue_only","submission_verdict_bound":false,"reason":FALLBACK_CODE_REASON},"submission_success":null,"submission_verdict_known":false,"accepted_postcondition_known":false,"evidence_basis":basis,"evidence":evidence(bytes,ct,"judging_status_shape_unknown",&assessment,false)})
        }
    }
}
pub fn schema() -> Value {
    // What each invocation establishes. The four refusal fields are constants so a
    // receipt cannot claim transport equivalence, authentication, submission or an
    // accepted postcondition that this module never obtains.
    let basis = json!({"type":"object","additionalProperties":false,"description":"Assertion of what this invocation establishes, distinct from `evidence` (a possibly withheld raw receipt).","required":["observation","requests_performed","source_reference","transport_equivalence","authentication","submission","accepted_postcondition"],"properties":{"observation":{"type":"string","minLength":1},"requests_performed":{"type":"integer","minimum":0,"maximum":1},"source_reference":{"const":SOURCE_REFERENCE},"transport_equivalence":{"const":"not_established"},"authentication":{"const":"refused"},"submission":{"const":"refused"},"accepted_postcondition":{"const":"not_established"}}});
    let judgement_error = json!({"type":"object","additionalProperties":false,"description":"Judge/queue classification on its own axis; never a submission verdict.","required":["classification","scope","submission_verdict_bound","reason"],"properties":{"classification":{"const":"not_established"},"scope":{"const":"judge_or_queue_only"},"submission_verdict_bound":{"const":false},"reason":{"const":JUDGE_CODE_REASON}}});
    let fallback_classification = json!({"type":"object","additionalProperties":false,"required":["classification","scope","submission_verdict_bound","reason"],"properties":{"classification":{"const":"not_established"},"scope":{"const":"judge_or_queue_only"},"submission_verdict_bound":{"const":false},"reason":{"const":FALLBACK_CODE_REASON}}});
    let preview = json!({"type":"object","additionalProperties":false,"required":["intent","course_id","assignment_id","problem_id","local_file","byte_count","sha256","accepted_postcondition_known","evidence_basis"],"properties":{"intent":{"const":"submit_coursegrading_file"},"course_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"assignment_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"problem_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"local_file":{"type":"string"},"byte_count":{"type":"integer","minimum":0,"maximum":16777216},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"accepted_postcondition_known":{"const":false},"evidence_basis":basis}});
    // `preview` is the derived receipt the CLI prints, never the stdin it reads.
    // The preview command reads four members individually and ignores everything
    // else, so its request document deliberately carries no
    // additionalProperties:false; `status` stdin is a strict typed object.
    let preview_request = json!({"type":"object","description":"Operation stdin actually read by the CLI: course_id, assignment_id, problem_id and local_file are read individually. A missing or non-string member becomes an empty string and then fails identity/path validation; unknown members are ignored; a repeated member keeps its last value; no explicit object-root check is made, so an array root simply yields no values and is refused. intent, byte_count and sha256 are produced by the receipt and are not read here.","required":["course_id","assignment_id","problem_id","local_file"],"properties":{"course_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"assignment_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"problem_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"local_file":{"type":"string","minLength":1,"description":"Caller-owned regular file, not a symlink, in a caller-owned non-group/world-writable directory."}}});
    let status_request = json!({"type":"object","additionalProperties":false,"description":"Operation stdin parsed as a strict typed object: a leading '{' is required, unknown or duplicate members and trailing documents are rejected with invalid_input (exit 2).","required":["body_base64"],"properties":{"body_base64":{"type":"string","description":"Standard base64 of the response body; decoded before offline parsing."},"content_type":{"type":["string","null"],"description":"Optional caller-declared media type used for body admission; echoed only when it normalizes to a known safe type."}}});
    let submit_request = json!({"type":"object","additionalProperties":false,"description":"Operation stdin parsed as a strict typed object: a leading '{' is required, unknown or duplicate members and trailing documents are rejected with invalid_input (exit 2). course_id, assignment_id, problem_id and local_file are the immutable preview identity; confirmed_sha256 must equal the preview digest of the on-disk source or the read is refused; previous_ledger is the caller's durable idempotency record and reconfirm admits a duplicate.","required":["course_id","assignment_id","problem_id","local_file","confirmed_sha256"],"properties":{"course_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"assignment_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"problem_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"local_file":{"type":"string"},"confirmed_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"reconfirm":{"type":"boolean"},"previous_ledger":{"type":"array","items":{"type":"string","pattern":"^[a-f0-9]{64}$"}}}});
    let operations = json!({
     "unsupported":{"stdin_request":"none","network_access":false,"outputs":["unsupported"]},
     "probe-https":{"stdin_request":"none","requires":["--online"],"network_access":"single HTTPS GET: https_only, redirects refused, retry disabled, no credentials and no cookie jar","outputs":["blocked","unsupported"]},
     "preview":{"stdin_request":"preview_request","network_access":false,"output_document":"preview","outputs":["preview"]},
     "status":{"stdin_request":"status_request","network_access":false,"outputs":["judging_status","fallback"]},
     "submit":{"stdin_request":"submit_request","network_access":false,"outputs":["submission_admitted"]}
    });
    json!({"operations":operations,"preview":preview,"preview_request":preview_request,"status_request":status_request,"submit_request":submit_request,"output":{"oneOf":[preview,{"type":"object","required":["result","reason","accepted_postcondition_known","evidence_basis"],"properties":{"result":{"enum":["unsupported","blocked"]},"accepted_postcondition_known":{"const":false},"evidence_basis":basis}},{"type":"object","required":["result","finished","judgement_error_classification","result_html","html_trust","submission_success","submission_verdict_known","accepted_postcondition_known","evidence_basis"],"properties":{"result":{"const":"judging_status"},"finished":{"type":"boolean","description":"Mirrors only ret == \"1\" under the unverified pinned shape; never an accepted-submission verdict."},"judgement_error_classification":judgement_error,"html_trust":{"const":"untrusted_data"},"submission_success":{"type":"null"},"submission_verdict_known":{"const":false},"accepted_postcondition_known":{"const":false},"evidence_basis":basis}},{"type":"object","required":["result","evidence","judgement_error_classification","submission_success","submission_verdict_known","accepted_postcondition_known","evidence_basis"],"properties":{"result":{"const":"fallback"},"judgement_error_classification":fallback_classification,"submission_success":{"type":"null"},"submission_verdict_known":{"const":false},"accepted_postcondition_known":{"const":false},"evidence_basis":basis}},{"type":"object","required":["result","idempotency_key","reconfirmed","course_id","assignment_id","problem_id","confirmed_sha256","byte_count","multipart","remote_request","submission_success","submission_verdict_known","accepted_postcondition_known","evidence_basis"],"properties":{"result":{"const":"submission_admitted"},"idempotency_key":{"type":"string","pattern":"^[a-f0-9]{64}$"},"reconfirmed":{"type":"boolean"},"course_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"assignment_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"problem_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"},"confirmed_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"byte_count":{"type":"integer","minimum":0,"maximum":16777216},"multipart":{"type":"object","required":["content_type","body_bytes","body_base64"],"properties":{"content_type":{"type":"string","pattern":"^multipart/form-data; boundary=buaa-[a-f0-9]{64}$"},"body_bytes":{"type":"integer","minimum":0},"body_base64":{"type":"string","contentEncoding":"base64"}}},"remote_request":{"const":false},"submission_success":{"type":"null"},"submission_verdict_known":{"const":false},"accepted_postcondition_known":{"const":false},"evidence_basis":basis}}]},"authentication":"refused","submission":"refused","accepted_postcondition_known":false,"unknown":["HTTPS application equivalence","course enumeration","assignment HTML fields","judge/queue status code table","accepted-submission postcondition","operation stdin read semantics outside the admission contract"],"writes_enabled":false})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_map_preserves_retry_values_and_refuses_ambiguous_mime() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, RETRY_AFTER};
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert_eq!(
            response_content_type(&headers),
            Ok(Some("application/json"))
        );
        headers.append(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        assert!(response_content_type(&headers).is_err());
        headers.remove(CONTENT_TYPE);
        headers.append(CONTENT_TYPE, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(response_content_type(&headers).is_err());
        headers.append(RETRY_AFTER, HeaderValue::from_static("0"));
        headers.append(RETRY_AFTER, HeaderValue::from_static("1800"));
        headers.append(RETRY_AFTER, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(
            headers
                .get_all("retry-after")
                .iter()
                .map(|v| v.to_str().ok())
                .collect::<Vec<_>>(),
            vec![Some("0"), Some("1800"), None]
        );
    }

    fn p() -> SubmissionPreview {
        SubmissionPreview {
            intent: "submit_coursegrading_file".into(),
            course_id: "c".into(),
            assignment_id: "a".into(),
            problem_id: "p".into(),
            local_file: "source.c".into(),
            byte_count: 3,
            sha256: hash(b"abc"),
            accepted_postcondition_known: false,
            evidence_basis: EvidenceBasis::canonical(PREVIEW_OBSERVATION, 0),
        }
    }
    #[test]
    fn preview_receipt_is_a_schema_output_alternative() {
        let schema = schema();
        assert_eq!(schema["output"]["oneOf"][0], schema["preview"]);
        let preview = serde_json::to_value(p()).unwrap();
        for field in schema["preview"]["required"].as_array().unwrap() {
            assert!(preview.get(field.as_str().unwrap()).is_some());
        }
        assert_eq!(
            schema["preview"]["properties"]["accepted_postcondition_known"],
            json!({"const":false})
        );
        assert_eq!(schema["accepted_postcondition_known"], false);
        assert_eq!(schema["authentication"], "refused");
        assert_eq!(schema["submission"], "refused");
        // Every output alternative must declare both the basis and the unknown postcondition.
        for alternative in schema["output"]["oneOf"].as_array().unwrap() {
            let required = alternative["required"].as_array().unwrap();
            for field in ["accepted_postcondition_known", "evidence_basis"] {
                assert!(
                    required.iter().any(|value| value.as_str() == Some(field)),
                    "missing {field}"
                );
            }
        }
        // `preview` is the receipt; the stdin actually read is preview_request.
        assert_eq!(
            schema["operations"]["preview"]["stdin_request"],
            "preview_request"
        );
        assert_eq!(
            schema["operations"]["preview"]["output_document"],
            "preview"
        );
        assert_eq!(
            schema["operations"]["status"]["stdin_request"],
            "status_request"
        );
        assert_eq!(schema["operations"]["unsupported"]["stdin_request"], "none");
        assert_eq!(schema["operations"]["probe-https"]["stdin_request"], "none");
        assert_eq!(
            schema["preview_request"]["required"],
            json!(["course_id", "assignment_id", "problem_id", "local_file"])
        );
        for unread in ["intent", "byte_count", "sha256"] {
            assert!(
                schema["preview_request"]["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|value| value.as_str() != Some(unread))
            );
            assert!(
                schema["preview_request"]["properties"]
                    .get(unread)
                    .is_none()
            );
        }
        // The preview reader ignores unknown members, so the document must not claim otherwise.
        assert!(
            schema["preview_request"]
                .get("additionalProperties")
                .is_none()
        );
        assert_eq!(schema["status_request"]["additionalProperties"], false);
        assert_eq!(schema["status_request"]["required"], json!(["body_base64"]));
    }
    #[test]
    fn preview_receipt_states_local_only_basis_and_refuses_forgery() {
        let p = p();
        let basis = p.evidence_basis.to_json();
        assert_eq!(p.accepted_postcondition_known, false);
        assert_eq!(basis["source_reference"], SOURCE_REFERENCE);
        assert_eq!(basis["requests_performed"], 0);
        assert_eq!(basis["transport_equivalence"], "not_established");
        assert_eq!(basis["authentication"], "refused");
        assert_eq!(basis["submission"], "refused");
        assert_eq!(basis["accepted_postcondition"], "not_established");
        for bad in [
            SubmissionPreview {
                accepted_postcondition_known: true,
                ..p.clone()
            },
            SubmissionPreview {
                evidence_basis: EvidenceBasis::canonical(PROBE_OBSERVATION, 1),
                ..p.clone()
            },
            SubmissionPreview {
                evidence_basis: EvidenceBasis {
                    authentication: "permitted".into(),
                    ..p.evidence_basis.clone()
                },
                ..p.clone()
            },
        ] {
            assert!(admit_submission(&bad, &BTreeSet::new(), true).is_err());
            assert!(multipart_part(&bad, b"abc".to_vec(), &bad.sha256).is_err());
        }
    }
    #[test]
    fn judgement_classification_is_independent_of_the_submission_verdict() {
        for (wire, finished) in [
            (br#"[{"ret":"1"},{"content":"accepted"}]"#.as_slice(), true),
            (br#"[{"ret":"0"},{"content":"queued"}]"#.as_slice(), false),
            (
                br#"[{"ret":"-1"},{"content":"judge error"}]"#.as_slice(),
                false,
            ),
        ] {
            let result = parse_status(wire, Some("application/json"));
            assert_eq!(result["result"], "judging_status");
            assert_eq!(result["finished"], finished);
            assert_eq!(result["submission_success"], Value::Null);
            assert_eq!(result["submission_verdict_known"], false);
            assert_eq!(result["accepted_postcondition_known"], false);
            assert_eq!(
                result["judgement_error_classification"]["classification"],
                "not_established"
            );
            assert_eq!(
                result["judgement_error_classification"]["scope"],
                "judge_or_queue_only"
            );
            assert_eq!(
                result["judgement_error_classification"]["submission_verdict_bound"],
                false
            );
            assert_eq!(result["evidence_basis"]["requests_performed"], 0);
            assert_eq!(result["evidence_basis"]["submission"], "refused");
            assert_eq!(
                result["evidence_basis"]["accepted_postcondition"],
                "not_established"
            );
        }
    }
    #[test]
    fn unsupported_and_fallbacks_state_their_basis() {
        let output = unsupported();
        assert_eq!(output["accepted_postcondition_known"], false);
        assert_eq!(output["evidence_basis"]["requests_performed"], 0);
        assert_eq!(
            output["evidence_basis"]["source_reference"],
            SOURCE_REFERENCE
        );
        assert_eq!(
            output["evidence_basis"]["transport_equivalence"],
            "not_established"
        );
        assert_eq!(output["evidence_basis"]["authentication"], "refused");
        assert_eq!(output["evidence_basis"]["submission"], "refused");
        assert_eq!(
            output["evidence_basis"]["accepted_postcondition"],
            "not_established"
        );
        for result in [
            parse_status(b"broken", None),
            parse_status(b"<input name='captcha'>", Some("text/html")),
        ] {
            assert_eq!(result["result"], "fallback");
            assert_eq!(result["submission_success"], Value::Null);
            assert_eq!(result["accepted_postcondition_known"], false);
            assert_eq!(result["submission_verdict_known"], false);
            assert_eq!(
                result["judgement_error_classification"]["classification"],
                "not_established"
            );
            assert_eq!(
                result["judgement_error_classification"]["scope"],
                "judge_or_queue_only"
            );
            assert_eq!(
                result["judgement_error_classification"]["submission_verdict_bound"],
                false
            );
            assert_eq!(result["evidence_basis"]["requests_performed"], 0);
            assert_eq!(result["evidence_basis"]["authentication"], "refused");
        }
        for status in [401, 403] {
            let result = observed_safety_rejection(status, false, true).unwrap();
            assert_eq!(result["accepted_postcondition_known"], false);
            assert_eq!(result["evidence_basis"]["requests_performed"], 1);
            assert_eq!(result["evidence_basis"]["submission"], "refused");
            assert_eq!(
                result["evidence_basis"]["accepted_postcondition"],
                "not_established"
            );
        }
    }
    #[test]
    fn observed_authentication_refusal_survives_incomplete_body() {
        for status in [401, 403] {
            let result = observed_safety_rejection(status, false, false).unwrap();
            assert_eq!(result["https_status"], status);
            assert_eq!(result["body_complete"], false);
            assert!(!result["reason"].as_str().unwrap().contains("challenge"));
        }
        let result = observed_safety_rejection(200, true, false).unwrap();
        assert_eq!(result["body_complete"], false);
        assert!(result["reason"].as_str().unwrap().contains("challenge"));
    }
    #[test]
    fn multipart_and_digest() {
        let p = p();
        let (ct, body) = multipart_part(&p, b"abc".to_vec(), &p.sha256).unwrap();
        assert!(ct.starts_with("multipart/form-data; boundary="));
        assert!(String::from_utf8(body).unwrap().contains("name=\"file\""));
        assert!(multipart_part(&p, b"bad".to_vec(), &p.sha256).is_err());
    }
    #[test]
    fn duplicate_rejected() {
        let p = p();
        let mut ledger = BTreeSet::new();
        ledger.insert(admit_submission(&p, &ledger, false).unwrap());
        assert!(admit_submission(&p, &ledger, false).is_err());
        assert!(admit_submission(&p, &ledger, true).is_ok());
    }
    #[test]
    fn status_and_http_block() {
        assert_eq!(
            parse_status(
                br#"[{"ret":"1"},{"content":"accepted"}]"#,
                Some("application/json")
            )["finished"],
            true
        );
        assert_eq!(unsupported()["result"], "unsupported");
        assert!(parse_status(b"broken", None)["evidence"]["content_type"].is_null());
    }
    #[test]
    fn offline_probe() {
        assert_eq!(probe_https(false).unwrap_err().code, "offline");
    }
    #[test]
    fn json_challenge_prose_preserves_safe_raw_source() {
        let body = br#"{"message":"CAPTCHA documentation"}"#;
        assert!(matches!(
            response_assessment(false, body, Some("application/json"), true),
            ChallengeAssessment::Clear
        ));
        let result = parse_status(body, Some("application/json"));
        assert_eq!(
            STANDARD
                .decode(result["evidence"]["raw_base64"].as_str().unwrap())
                .unwrap(),
            body
        );
    }
    #[test]
    fn challenge_and_secret_fallbacks_withhold_raw() {
        for (body, ct) in [
            (b"<input name='captcha'>".as_slice(), "text/html"),
            (
                br#"{"sessionid":"private_value"}"#.as_slice(),
                "application/json",
            ),
        ] {
            let result = parse_status(body, Some(ct));
            assert_eq!(result["result"], "fallback");
            assert!(result["evidence"]["raw_base64"].is_null());
            assert!(!result.to_string().contains("private_value"));
        }
    }
    #[test]
    fn issued_session_cookie_withholds_original_evidence() {
        let body = b"freshopaque123";
        let mime = Some("text/plain");
        let assessment = assess_challenge_body(body, mime, true);
        let withheld = evidence(body, mime, "login_page_fields_unknown", &assessment, true);
        assert!(withheld["raw_base64"].is_null());
        assert_eq!(withheld["raw_withheld"], true);
        assert_eq!(withheld["fallback_reason"], "session_cookie_issued");
        assert_eq!(withheld["byte_count"], body.len());
        assert_eq!(withheld["sha256"], hash(body));
        let retained = evidence(body, mime, "login_page_fields_unknown", &assessment, false);
        assert_eq!(retained["raw_base64"], "ZnJlc2hvcGFxdWUxMjM=");
        assert_eq!(retained["raw_withheld"], false);
    }
    #[test]
    fn incomplete_review_preserves_header_detection() {
        assert!(matches!(
            response_assessment(false, b"<html>", Some("text/html"), false),
            ChallengeAssessment::Unreviewed
        ));
        assert!(matches!(
            response_assessment(true, &[0xff], None, false),
            ChallengeAssessment::Detected
        ));
        let result = evidence(
            b"private body",
            None,
            "incomplete",
            &ChallengeAssessment::Unreviewed,
            false,
        );
        assert!(result["raw_base64"].is_null());
        assert_eq!(result["byte_count"], 12);
    }
    #[test]
    fn decoded_credentials_and_mime_parameters_are_withheld() {
        let result = parse_status(
            br#"{"\u0074oken":"private_value"}"#,
            Some("application/json; sessionid=private_value"),
        );
        assert!(result["evidence"]["raw_base64"].is_null());
        assert_eq!(result["evidence"]["content_type"], "application/json");
        assert!(!result.to_string().contains("private_value"));
        let result = parse_status(
            br#"[{"ret":"1"},{"content":"accepted","\u0074oken":"private_value"}]"#,
            Some("application/json"),
        );
        assert_eq!(result["result"], "fallback");
        assert!(!result.to_string().contains("private_value"));
    }
    #[test]
    fn duplicate_json_members_do_not_hide_early_secrets() {
        let result = parse_status(
            br#"{"x":{"\u0074oken":"private_value"},"x":0}"#,
            Some("application/json"),
        );
        assert!(result["evidence"]["raw_base64"].is_null());
        assert!(!result.to_string().contains("private_value"));
        let safe = br#"{"x":1,"x":0}"#;
        let result = parse_status(safe, Some("application/json"));
        assert_eq!(
            STANDARD
                .decode(result["evidence"]["raw_base64"].as_str().unwrap())
                .unwrap(),
            safe
        );
    }
    #[test]
    fn bearer_and_escaped_credential_responses_are_withheld() {
        for key in ["bearer", "jwt", "nonce", "loginname", "login_name"] {
            let result = parse_status(
                json!({(key):"synthetic_private"}).to_string().as_bytes(),
                Some("application/json"),
            );
            assert!(result["evidence"]["raw_base64"].is_null());
            assert!(!result.to_string().contains("synthetic_private"));
        }
        for body in [
            br#"{"other":"\\x62earer synthetic_private"}"#.as_slice(),
            br#"{"other":"&#98;earer synthetic_private"}"#.as_slice(),
        ] {
            assert!(
                parse_status(body, Some("application/json"))["evidence"]["raw_base64"].is_null()
            );
        }
    }
    #[test]
    fn safe_unicode_json_preserves_original_but_escaped_token_is_withheld() {
        let safe = br#"{"title":"\u4e2d"}"#;
        let result = parse_status(safe, Some("application/json"));
        assert_eq!(
            STANDARD
                .decode(result["evidence"]["raw_base64"].as_str().unwrap())
                .unwrap(),
            safe
        );
        let result = parse_status(
            br#"{"\u0074oken":"private_value"}"#,
            Some("application/json"),
        );
        assert!(result["evidence"]["raw_base64"].is_null());
        assert!(!result.to_string().contains("private_value"));
    }
    #[test]
    fn forged_previews_rejected() {
        let base = p();
        for bad in [
            SubmissionPreview {
                sha256: base.sha256.to_uppercase(),
                ..base.clone()
            },
            SubmissionPreview {
                byte_count: 16 * 1024 * 1024 + 1,
                ..base.clone()
            },
            SubmissionPreview {
                course_id: String::new(),
                ..base.clone()
            },
            SubmissionPreview {
                intent: "other".into(),
                ..base.clone()
            },
        ] {
            assert!(admit_submission(&bad, &BTreeSet::new(), true).is_err());
            assert!(multipart_part(&bad, b"abc".to_vec(), &bad.sha256).is_err());
        }
    }
    #[test]
    fn unsafe_file_types_and_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = std::env::temp_dir().join(format!(
            "buaa-grading-input-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.join("source");
        std::fs::write(&file, b"abc").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(preview("c", "a", "p", &file).unwrap().sha256, hash(b"abc"));
        let link = dir.join("link");
        symlink(&file, &link).unwrap();
        assert!(preview("c", "a", "p", &link).is_err());
        let child = dir.join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        let child_file = child.join("source");
        std::fs::write(&child_file, b"abc").unwrap();
        std::fs::set_permissions(&child_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = dir.join("alias");
        symlink(&child, &alias).unwrap();
        assert!(preview("c", "a", "p", &alias.join("source")).is_err());
        let large = dir.join("large");
        let big = std::fs::File::create(&large).unwrap();
        big.set_len(16 * 1024 * 1024 + 1).unwrap();
        std::fs::set_permissions(&large, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(preview("c", "a", "p", &large).is_err());
        let fifo = dir.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: name is a live NUL-terminated path for this test-owned FIFO.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(preview("c", "a", "p", &fifo).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(preview("c", "a", "p", &file).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(preview("c", "a", "p", &file).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    fn submit_source() -> (std::path::PathBuf, String) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "buaa-grading-submit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.join("source");
        std::fs::write(&file, b"abc").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        (file, hash(b"abc"))
    }
    #[test]
    fn confirmed_submission_admits_an_immutably_matching_preview() {
        let (file, digest) = submit_source();
        let req = SubmitRequest {
            course_id: "c".into(),
            assignment_id: "a".into(),
            problem_id: "p".into(),
            local_file: file.to_str().unwrap().into(),
            confirmed_sha256: digest.clone(),
            reconfirm: false,
            previous_ledger: vec![],
        };
        let result = submit_confirmed(&req).unwrap();
        assert_eq!(result["result"], "submission_admitted");
        assert_eq!(result["confirmed_sha256"], digest);
        assert_eq!(result["byte_count"], 3);
        assert_eq!(result["reconfirmed"], false);
        assert_eq!(result["remote_request"], false);
        // A local admission never becomes a remote verdict.
        assert_eq!(result["submission_success"], Value::Null);
        assert_eq!(result["submission_verdict_known"], false);
        assert_eq!(result["accepted_postcondition_known"], false);
        assert_eq!(result["evidence_basis"]["requests_performed"], 0);
        assert_eq!(result["evidence_basis"]["submission"], "refused");
        assert_eq!(result["evidence_basis"]["accepted_postcondition"], "not_established");
        // The multipart body is built from the confirmed bytes; the boundary is
        // the preview digest and the content type names it.
        assert_eq!(
            result["multipart"]["content_type"],
            format!("multipart/form-data; boundary=buaa-{digest}")
        );
        let body = STANDARD.decode(result["multipart"]["body_base64"].as_str().unwrap()).unwrap();
        let text = String::from_utf8(body.clone()).unwrap();
        assert!(text.contains("name=\"file\""));
        assert!(text.contains("abc"));
        assert_eq!(result["multipart"]["body_bytes"], body.len());
        // The idempotency key matches the ledger derivation.
        let key = hash(
            &serde_json::to_vec(&("c", "a", "p", digest)).unwrap(),
        );
        assert_eq!(result["idempotency_key"], key);
        let _ = std::fs::remove_dir_all(file.parent().unwrap());
    }
    #[test]
    fn confirmed_submission_refuses_a_digest_drift() {
        let (file, _digest) = submit_source();
        let req = SubmitRequest {
            course_id: "c".into(),
            assignment_id: "a".into(),
            problem_id: "p".into(),
            local_file: file.to_str().unwrap().into(),
            // The on-disk bytes hash to something else; the confirmed digest
            // must equal the preview digest or the read is refused.
            confirmed_sha256: format!("{:0>64}", 0),
            reconfirm: false,
            previous_ledger: vec![],
        };
        assert_eq!(submit_confirmed(&req).unwrap_err().code, "digest_mismatch");
        let _ = std::fs::remove_dir_all(file.parent().unwrap());
    }
    #[test]
    fn confirmed_submission_duplicate_requires_reconfirmation() {
        let (file, digest) = submit_source();
        let key = hash(&serde_json::to_vec(&("c", "a", "p", digest.clone())).unwrap());
        let req = SubmitRequest {
            course_id: "c".into(),
            assignment_id: "a".into(),
            problem_id: "p".into(),
            local_file: file.to_str().unwrap().into(),
            confirmed_sha256: digest,
            reconfirm: false,
            previous_ledger: vec![key.clone()],
        };
        assert_eq!(
            submit_confirmed(&req).unwrap_err().code,
            "duplicate_submission"
        );
        let req = SubmitRequest { reconfirm: true, ..req };
        assert_eq!(submit_confirmed(&req).unwrap()["reconfirmed"], true);
        let _ = std::fs::remove_dir_all(file.parent().unwrap());
    }
    #[test]
    fn schema_declares_the_submit_operation_and_output() {
        let schema = schema();
        assert_eq!(
            schema["operations"]["submit"]["stdin_request"],
            "submit_request"
        );
        assert_eq!(
            schema["operations"]["submit"]["network_access"],
            false
        );
        assert_eq!(
            schema["operations"]["submit"]["outputs"],
            json!(["submission_admitted"])
        );
        assert_eq!(schema["submit_request"]["additionalProperties"], false);
        assert_eq!(
            schema["submit_request"]["required"],
            json!(["course_id", "assignment_id", "problem_id", "local_file", "confirmed_sha256"])
        );
        // Every output alternative still declares the unknown postcondition and
        // the basis; the new submission_admitted branch keeps both const.
        for alternative in schema["output"]["oneOf"].as_array().unwrap() {
            let required = alternative["required"].as_array().unwrap();
            for field in ["accepted_postcondition_known", "evidence_basis"] {
                assert!(
                    required.iter().any(|value| value.as_str() == Some(field)),
                    "missing {field}"
                );
            }
        }
        let admitted = schema["output"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["properties"]["result"] == json!({"const":"submission_admitted"}))
            .expect("submission_admitted alternative present");
        assert_eq!(admitted["properties"]["remote_request"], json!({"const":false}));
        assert_eq!(admitted["properties"]["submission_success"], json!({"type":"null"}));
        assert_eq!(admitted["properties"]["submission_verdict_known"], json!({"const":false}));
        assert_eq!(admitted["properties"]["accepted_postcondition_known"], json!({"const":false}));
    }
}
