//! 航空航天概论 material inventory and local study practice.
//!
//! The source-reviewed upstream reference for this capability is the
//! community repository `Caniformia/HangGai` (GPL-3.0), a SwiftUI study
//! application for 北京航空航天大学 that ships a bundled question bank
//! (`HangGai/Assets/DB/questions.db`, table `science_questions`) together
//! with the question images it renders.
//!
//! That question bank stores the correct answer of every question. It is
//! answer-bearing material: it is listed in the inventory for transparency,
//! it is never retrievable, and it is never mirrored. The module implements
//! no bulk mirror operation at all, so a batch copy of homework or exam
//! answers is structurally impossible here.
//!
//! The upstream application is also not an authoritative course archive: it
//! publishes no lecture material, and its identity and rights as a mirror of
//! 北京航空航天大学 course content were not verified. The catalog entry that
//! records this repository marks it "reference-only-not-executed", and the
//! catalog also records a second 航空航天概论 entry with no reference at all,
//! described as a WeChat mini program whose identity and rights are
//! unverified. Neither the mini program nor any course material distribution
//! endpoint was reviewed, so this module never requests them.
//!
//! Local practice mirrors the upstream question model without its answers: an
//! operator-supplied question set keeps the upstream identifier, chapter and
//! single/multiple-choice type, but no answer field is ever accepted. The
//! practice result reflects only the operator's own local answers, and never
//! claims an official grade, a completion state or a submission.
//!
//! Every remote read takes one shared-governor lease, holds it until the
//! response body is processed, settles it against the observed HTTP status
//! and Retry-After, and never retries. A response that cannot be normalized
//! keeps its original bytes, the observed content type, the byte count, the
//! SHA-256 and the reason, and stays re-readable offline from the private
//! response cache.
//! Retrieval is bound to the admitted immutable tree entry's Git blob SHA:
//! the shared transport requests that blob, verifies its complete Git object
//! hash, and never follows the branch again for material bytes.

use crate::net::Error;
use crate::welearn::learning;
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// The source-reviewed 航空航天概论 reference. The branch was read from the
/// upstream repository; the license reference is an operator attestation and
/// is published only bound to the license object of the admitted tree.
const SOURCE: learning::SourceSpec = learning::SourceSpec {
    owner: "Caniformia",
    name: "HangGai",
    branch: "master",
};

const TYPE_LABEL: &str = "aerospace_material_inventory";
const SEARCH_TYPE_LABEL: &str = "aerospace_material_search";
const RAW_TYPE_LABEL: &str = "aerospace_material_bytes";
const PRACTICE_TYPE_LABEL: &str = "aerospace_practice_session";

/// The bundled question bank of the upstream application. Its `science_questions`
/// table holds the answer column, so the whole database is answer material.
const ANSWER_BANK_PATH: &str = "HangGai/Assets/DB/questions.db";

/// Keys that would carry an answer into a question set. A question set that
/// carries one is refused instead of being quietly stripped.
const FORBIDDEN_ANSWER_KEYS: &[&str] = &[
    "answer",
    "answers",
    "correct",
    "correctanswer",
    "correct_answer",
    "solution",
    "answer_key",
    "answerkey",
    "key",
    "rightanswer",
    "right_answer",
    "reference_answer",
    "standard_answer",
    "data-solution",
];

/// Classify one repository path. The classification is path based and is
/// applied identically to the inventory and to every retrieval, so the
/// reviewed inventory is the only gate that admits bytes.
fn classify(path: &str) -> learning::MaterialClass {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if lower == ANSWER_BANK_PATH
        || name.ends_with(".db")
        || name.ends_with(".sqlite")
        || name.ends_with(".sqlite3")
    {
        return learning::MaterialClass::AnswerMaterial;
    }
    if name.contains("answer")
        || name.contains("solution")
        || learning::answer_path_component(path)
    {
        return learning::MaterialClass::AnswerMaterial;
    }
    if lower.contains("questionimgs/") || lower.contains("questionimages/") {
        return learning::MaterialClass::AssessmentContent;
    }
    if name.starts_with("license") || name.starts_with("copying") {
        return learning::MaterialClass::License;
    }
    if name.ends_with(".md") || name.ends_with(".txt") || name.ends_with(".rst") {
        return learning::MaterialClass::Documentation;
    }
    if name.ends_with(".swift")
        || name.ends_with(".pbxproj")
        || name.ends_with(".plist")
        || name.ends_with(".xcworkspacedata")
    {
        return learning::MaterialClass::SourceCode;
    }
    if name.ends_with(".ttf")
        || name.ends_with(".otf")
        || name.ends_with(".png")
        || name.ends_with(".jpg")
        || name.ends_with(".jpeg")
    {
        return learning::MaterialClass::Asset;
    }
    if lower.contains("courseware") || lower.contains("material") {
        return learning::MaterialClass::CourseMaterial;
    }
    learning::MaterialClass::Other
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    query: String,
    rights_reviewed: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchInput {
    path: String,
    rights_reviewed: Option<bool>,
    tree_sha: Option<String>,
    blob_sha: Option<String>,
    mode: Option<String>,
    size: Option<u64>,
}

fn parse_search_input(input: &str) -> Result<SearchInput, Error> {
    if input.len() > learning::MAX_INPUT {
        return Err(learning::invalid_input("the search request is too large"));
    }
    let parsed: SearchInput = serde_json::from_str(input)
        .map_err(|_| learning::invalid_input("the search request is malformed"))?;
    if parsed.rights_reviewed != Some(true) {
        return Err(learning::authorization_required(
            "a material search requires an explicit rights-review attestation",
        ));
    }
    let query = parsed.query.trim();
    if query.is_empty() || query.len() > learning::MAX_QUERY_BYTES {
        return Err(learning::invalid_input("the search query is empty or too long"));
    }
    Ok(SearchInput {
        query: query.to_owned(),
        rights_reviewed: Some(true),
    })
}

fn parse_fetch_input(input: &str) -> Result<FetchInput, Error> {
    if input.len() > learning::MAX_INPUT {
        return Err(learning::invalid_input("the fetch request is too large"));
    }
    let parsed: FetchInput = serde_json::from_str(input)
        .map_err(|_| learning::invalid_input("the fetch request is malformed"))?;
    if parsed.rights_reviewed != Some(true) {
        return Err(learning::authorization_required(
            "a material download requires an explicit rights-review attestation",
        ));
    }
    if !learning::valid_path(&parsed.path) {
        return Err(learning::invalid_input(
            "the material path is not a normalized repository path",
        ));
    }
    let parsed = FetchInput {
        path: parsed.path,
        rights_reviewed: Some(true),
        tree_sha: parsed.tree_sha,
        blob_sha: parsed.blob_sha,
        mode: parsed.mode,
        size: parsed.size,
    };
    let provided = [
        parsed.tree_sha.is_some(),
        parsed.blob_sha.is_some(),
        parsed.mode.is_some(),
        parsed.size.is_some(),
    ];
    if provided.iter().any(|provided| *provided) && !provided.iter().all(|provided| *provided) {
        return Err(learning::invalid_input(
            "the rights-review attestation must carry the complete reviewed tree, blob, mode and size",
        ));
    }
    if parsed.tree_sha.is_none() {
        return Err(learning::authorization_required(
            "a material download requires the immutable tree, blob, mode and size the operator reviewed",
        ));
    }
    if let Some(tree_sha) = parsed.tree_sha.as_deref() {
        if !learning::valid_upstream_sha(tree_sha) {
            return Err(learning::invalid_input(
                "the reviewed tree identity is not a valid Git object SHA",
            ));
        }
    }
    if let Some(blob_sha) = parsed.blob_sha.as_deref() {
        if !learning::valid_upstream_sha(blob_sha) {
            return Err(learning::invalid_input(
                "the reviewed blob identity is not a valid Git object SHA",
            ));
        }
    }
    if let Some(mode) = parsed.mode.as_deref() {
        if !matches!(mode, "100644" | "100755") {
            return Err(learning::invalid_input(
                "only the reviewed mode of a regular file can be retrieved",
            ));
        }
    }
    Ok(parsed)
}

/// List the reviewed 航空航天概论 material inventory. Offline is the default;
/// `online` permits exactly one governed tree request on a cache miss.
pub fn materials(input: &str, online: bool) -> Result<Value, Error> {
    let trimmed = input.trim();
    let value: Value = if trimmed.is_empty() {
        json!({})
    } else {
        serde_json::from_str(trimmed)
            .map_err(|_| learning::invalid_input("the materials request is malformed"))?
    };
    let object = value
        .as_object()
        .ok_or_else(|| learning::invalid_input("the materials request must be an object"))?;
    learning::only_keys(object, &[])?;
    let url = SOURCE.tree_url()?;
    learning::with_tree_response(&SOURCE, online, |response, identity| {
        learning::inventory_output(&SOURCE, TYPE_LABEL, &url, response, identity, &classify)
    })
}

/// Search the reviewed inventory. The rights-review attestation is required
/// before any cache or network admission.
pub fn search(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_search_input(input)?;
    let url = SOURCE.tree_url()?;
    learning::with_tree_response(&SOURCE, online, |response, identity| {
        learning::search_output(
            &SOURCE,
            SEARCH_TYPE_LABEL,
            &url,
            response,
            identity,
            &request.query,
            &classify,
        )
    })
}

/// The outcome of resolving one requested path against the reviewed
/// inventory. A refusal travels as an inner result so that the complete
/// verified tree is retained before the error is reported.
enum Admission {
    Classified {
        class: learning::MaterialClass,
        tree_sha: String,
        blob_sha: String,
        size: u64,
        license: Value,
    },
    Degraded(Value),
    Refused(Error),
}

/// Fetch the bytes of one reviewed material entry. The material class is
/// resolved from the reviewed inventory first, so the bundled answer bank is
/// refused before any byte request is made.
pub fn fetch(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_fetch_input(input)?;
    let admission = learning::with_tree_response(&SOURCE, online, |response, identity| {
        match identity.tree() {
            Some(admitted) => {
                let tree_sha = admitted.tree_sha.as_str();
                let entries = admitted.entries.as_slice();
                let Some(entry) = entries.iter().find(|entry| entry.path == request.path) else {
                    return Ok(Admission::Refused(Error::new(
                        "path_not_in_inventory",
                        "the requested path is not present in the reviewed material inventory",
                    )));
                };
                let Some(size) = entry.size else {
                    return Ok(Admission::Refused(Error::new(
                        "path_not_in_inventory",
                        "the requested path is not present in the reviewed material inventory",
                    )));
                };
                let Some(mode) = entry.kind().filter(|kind| *kind == "file").map(|_| entry.mode.as_str()) else {
                    return Ok(Admission::Refused(learning::invalid_input(
                        "only regular inventory files can be retrieved",
                    )));
                };
                if request.tree_sha.as_deref() != Some(tree_sha)
                    || request.blob_sha.as_deref() != Some(entry.sha.as_str())
                    || request.mode.as_deref() != Some(mode)
                    || request.size != Some(size)
                {
                    return Ok(Admission::Refused(learning::authorization_required(
                        "the requested material does not match the reviewed immutable identity",
                    )));
                }
                let class = classify(&entry.path);
                if !class.retrieval_allowed()
                    || learning::blob_is_answer_material(entries, entry.sha.as_str(), &classify)
                {
                    return Ok(Admission::Refused(learning::answer_material_forbidden()));
                }
                Ok(Admission::Classified {
                    class,
                    tree_sha: tree_sha.to_owned(),
                    blob_sha: entry.sha.clone(),
                    size,
                    license: learning::verified_license(&SOURCE, entries),
                })
            }
            None => Ok(Admission::Degraded(
                learning::degraded_admission_output(
                    &SOURCE,
                    RAW_TYPE_LABEL,
                    &request.path,
                    response,
                    identity,
                    identity.tree_error().unwrap_or("upstream_parse"),
                    learning::Surface::Tree,
                )?,
            )),
        }
    })?;
    match admission {
        Admission::Degraded(output) => Ok(output),
        Admission::Refused(error) => Err(error),
        Admission::Classified { class, tree_sha, blob_sha, size, license } => {
            learning::with_raw_response(&SOURCE, &blob_sha, online, |response, identity| {
                learning::verified_blob_output(&SOURCE, RAW_TYPE_LABEL, &request.path, response, identity, class, &tree_sha, &blob_sha, &license, size)
            })
        }
    }
}

/// Local 航空航天概论 practice. The session never carries an official grade,
/// a completion claim or a submission.
pub fn practice(input: &str) -> Result<Value, Error> {
    if input.len() > learning::MAX_PRACTICE_INPUT {
        return Err(learning::invalid_input("the practice request is too large"));
    }
    let value: Value = serde_json::from_str(input)
        .map_err(|_| learning::invalid_input("the practice request is malformed"))?;
    let object = value
        .as_object()
        .ok_or_else(|| learning::invalid_input("the practice request must be an object"))?;
    let action = object
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| learning::invalid_input("the practice request requires an action"))?;
    match action {
        "generate" => generate_practice(object),
        "answer" => {
            learning::only_keys(object, &["action", "session", "answers"])?;
            let session = parse_session(object)?;
            let answers = object
                .get("answers")
                .ok_or_else(|| learning::invalid_input("the answer action requires answers"))?;
            let answers: Vec<learning::AnswerInput> = serde_json::from_value(answers.clone())
                .map_err(|_| learning::invalid_input("the answers are malformed"))?;
            let recorded = learning::record_answers(&session, PRACTICE_TYPE_LABEL, &answers)?;
            serde_json::to_value(recorded)
                .map_err(|_| learning::invalid_input("the practice session is not serializable"))
        }
        "check" => {
            learning::only_keys(object, &["action", "session"])?;
            let session = parse_session(object)?;
            let checked = learning::check_session(&session, PRACTICE_TYPE_LABEL)?;
            serde_json::to_value(checked)
                .map_err(|_| learning::invalid_input("the practice session is not serializable"))
        }
        _ => Err(learning::invalid_input("the practice action is unknown")),
    }
}

fn parse_session(object: &Map<String, Value>) -> Result<learning::PracticeSession, Error> {
    let session = object
        .get("session")
        .ok_or_else(|| learning::invalid_input("the practice action requires a session"))?;
    serde_json::from_value(session.clone())
        .map_err(|_| learning::invalid_input("the practice session is malformed"))
}

fn generate_practice(object: &Map<String, Value>) -> Result<Value, Error> {
    learning::only_keys(
        object,
        &[
            "action",
            "mode",
            "material_text",
            "count",
            "question_set",
            "local_answer_key",
            "rights_reviewed",
        ],
    )?;
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| learning::invalid_input("a practice generation mode is required"))?;
    let rights_reviewed = learning::optional_bool(object, "rights_reviewed")?;
    let (questions, practice_source): (Vec<learning::PracticeQuestion>, Value) = match mode {
        "cloze" => {
            learning::only_keys(
                object,
                &[
                    "action",
                    "mode",
                    "material_text",
                    "count",
                    "local_answer_key",
                    "rights_reviewed",
                ],
            )?;
            let material = object
                .get("material_text")
                .and_then(Value::as_str)
                .ok_or_else(|| learning::invalid_input("the cloze mode requires material_text"))?;
            if material.trim().is_empty() || material.len() > learning::MAX_MATERIAL_TEXT {
                return Err(learning::invalid_input("the material text is empty or too large"));
            }
            let count = object
                .get("count")
                .and_then(Value::as_u64)
                .ok_or_else(|| learning::invalid_input("the cloze mode requires a question count"))?;
            if count == 0 || count > learning::MAX_QUESTIONS as u64 {
                return Err(learning::invalid_input("the question count is out of range"));
            }
            let questions = learning::generate_cloze_questions(material, count as usize);
            let source = json!({
                "kind": "cloze",
                "origin": "operator_local_material",
                "rights_reviewed": rights_reviewed,
                "digest": learning::sha256_hex(material.as_bytes()),
                "scan": Value::Null
            });
            (questions, source)
        }
        "question_set" => {
            learning::only_keys(
                object,
                &[
                    "action",
                    "mode",
                    "question_set",
                    "local_answer_key",
                    "rights_reviewed",
                ],
            )?;
            let question_set = object
                .get("question_set")
                .ok_or_else(|| learning::invalid_input("the question set mode requires question_set"))?;
            let questions = questions_from_question_set(question_set)?;
            let digest = learning::sha256_hex(
                serde_json::to_string(question_set)
                    .map_err(|_| learning::invalid_input("the question set is not serializable"))?
                    .as_bytes(),
            );
            let source = json!({
                "kind": "question_set",
                "origin": "operator_local_question_set",
                "rights_reviewed": rights_reviewed,
                "digest": digest,
                "scan": Value::Null
            });
            (questions, source)
        }
        _ => return Err(learning::invalid_input("the practice generation mode is unknown")),
    };
    let mut questions = questions;
    learning::apply_operator_key(&mut questions, object.get("local_answer_key"))?;
    let session =
        learning::new_session(PRACTICE_TYPE_LABEL, practice_source, questions, rights_reviewed)?;
    serde_json::to_value(session)
        .map_err(|_| learning::invalid_input("the practice session is not serializable"))
}

/// One question of an operator-supplied question set, in the upstream model:
/// an identifier, an optional chapter, the stem, the options and the
/// single/multiple-choice type. No answer field exists.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionSetItem {
    id: i64,
    chapter: Option<i64>,
    question: String,
    options: Vec<String>,
    #[serde(rename = "type")]
    question_type: i64,
}

/// Import an operator-supplied question set. A set that carries any
/// answer-bearing key is refused rather than silently stripped.
fn questions_from_question_set(
    question_set: &Value,
) -> Result<Vec<learning::PracticeQuestion>, Error> {
    let object = question_set
        .as_object()
        .ok_or_else(|| learning::invalid_input("the question set must be an object"))?;
    learning::only_keys(object, &["questions"])?;
    let items = object
        .get("questions")
        .and_then(Value::as_array)
        .ok_or_else(|| learning::invalid_input("the question set must carry a questions array"))?;
    if items.is_empty() || items.len() > learning::MAX_QUESTIONS {
        return Err(learning::invalid_input(
            "a question set must hold between 1 and 200 questions",
        ));
    }
    let mut questions: Vec<learning::PracticeQuestion> = Vec::with_capacity(items.len());
    for item in items {
        let raw = item
            .as_object()
            .ok_or_else(|| learning::invalid_input("each question must be an object"))?;
        for key in raw.keys() {
            let lower = key.to_ascii_lowercase();
            if FORBIDDEN_ANSWER_KEYS.contains(&lower.as_str()) {
                return Err(learning::answer_material_forbidden());
            }
        }
        let parsed: QuestionSetItem = serde_json::from_value(item.clone())
            .map_err(|_| learning::invalid_input("a question does not match the question model"))?;
        if parsed.id <= 0 {
            return Err(learning::invalid_input("a question identifier must be positive"));
        }
        if let Some(chapter) = parsed.chapter {
            if chapter <= 0 {
                return Err(learning::invalid_input("a question chapter must be positive"));
            }
        }
        if parsed.question.trim().is_empty()
            || parsed.question.len() > learning::MAX_QUESTION_BYTES
        {
            return Err(learning::invalid_input("a question stem is empty or too long"));
        }
        if parsed.options.len() < 2 || parsed.options.len() > learning::MAX_OPTIONS {
            return Err(learning::invalid_input(
                "a question must carry between 2 and 8 options",
            ));
        }
        for option in &parsed.options {
            if option.trim().is_empty() || option.len() > learning::MAX_OPTION_BYTES {
                return Err(learning::invalid_input("a question option is empty or too long"));
            }
        }
        if !matches!(parsed.question_type, 1 | 2) {
            return Err(learning::invalid_input(
                "a question type must be 1 for single choice or 2 for multiple choice",
            ));
        }
        let question_id = format!("q{}", parsed.id);
        if questions
            .iter()
            .any(|question| question.question_id == question_id)
        {
            return Err(learning::invalid_input("a question identifier is repeated"));
        }
        questions.push(learning::PracticeQuestion {
            question_id,
            kind: "choice".to_owned(),
            prompt: learning::collapse_whitespace(&parsed.question),
            options: Some(
                parsed
                    .options
                    .iter()
                    .map(|option| learning::collapse_whitespace(option))
                    .collect(),
            ),
            blanks: None,
            chapter: parsed.chapter,
            question_type: Some(parsed.question_type),
            local_self_check_key: None,
            key_source: "none".to_owned(),
        });
    }
    Ok(questions)
}

/// Machine-readable stdin/output contracts for CLI integration.
pub fn schema() -> Value {
    json!({
        "materials": {
            "input":{
                "type":"object","additionalProperties":false,"properties":{},"required":[],
                "description":"The reviewed source, branch and license are pinned; this request accepts no parameter. An empty input is accepted as this empty object."
            },
            "options":{"--online":"Permit one governed GitHub tree request on a cache miss; no automatic retry, refresh or pagination."},
            "output":learning::inventory_schema(TYPE_LABEL)
        },
        "search": {
            "input":{
                "type":"object","additionalProperties":false,"required":["query","rights_reviewed"],
                "properties":{
                    "query":{"type":"string","minLength":1,"maxLength":learning::MAX_QUERY_BYTES,"description":"A case-insensitive substring matched against the path and the title of each reviewed entry."},
                    "rights_reviewed":{"const":true,"description":"Required operator attestation. False or omitted fails before cache or network admission."}
                }
            },
            "options":{"--online":"Permit one governed GitHub tree request on a cache miss; no automatic retry or refresh."},
            "output":learning::search_schema(SEARCH_TYPE_LABEL)
        },
        "fetch": {
            "input":{
                "type":"object","additionalProperties":false,"required":["path","rights_reviewed","tree_sha","blob_sha","mode","size"],
                "properties":{
                    "path":{"type":"string","minLength":1,"maxLength":learning::MAX_PATH,"description":"An explicit normalized repository-relative path that is present in the reviewed inventory."},
                    "rights_reviewed":{"const":true,"description":"Required operator attestation. False or omitted fails before cache or network admission."},
                    "tree_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"The immutable root tree object the operator reviewed. It is compared with the verified admitted tree before any byte request."},
                    "blob_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"The immutable blob object the operator reviewed. It is compared with the admitted inventory entry before any byte request."},
                    "mode":{"enum":["100644","100755"],"description":"The reviewed entry mode. Only a regular file can be retrieved."},
                    "size":{"type":"integer","minimum":0,"description":"The reviewed byte length. The retrieved blob must have exactly this length."}
                }
            },
            "options":{"--online":"Permit the governed inventory lookup and the governed byte request on a cache miss; no automatic retry or redirect."},
            "output":learning::raw_schema(RAW_TYPE_LABEL)
        },
        "practice": {
            "input":learning::practice_schema(PRACTICE_TYPE_LABEL, vec![
                json!({
                    "type":"object","additionalProperties":false,
                    "required":["action","mode","material_text","count"],
                    "properties":{
                        "action":{"const":"generate"},
                        "mode":{"const":"cloze"},
                        "material_text":{"type":"string","minLength":1,"maxLength":learning::MAX_MATERIAL_TEXT,"description":"Local material the operator supplies; the cloze key is derived from this text only."},
                        "count":{"type":"integer","minimum":1,"maximum":learning::MAX_QUESTIONS},
                        "local_answer_key":learning::operator_key_schema(),
                        "rights_reviewed":{"type":"boolean","description":"The operator's own attestation that the supplied material may be used."}
                    }
                }),
                json!({
                    "type":"object","additionalProperties":false,
                    "required":["action","mode","question_set"],
                    "properties":{
                        "action":{"const":"generate"},
                        "mode":{"const":"question_set"},
                        "question_set":question_set_schema(),
                        "local_answer_key":learning::operator_key_schema(),
                        "rights_reviewed":{"type":"boolean"}
                    }
                })
            ]),
            "options":{},
            "output":learning::session_schema(PRACTICE_TYPE_LABEL)
        }
    })
}

/// The accepted question-set shape. No answer field is part of it, and a
/// question set that carries one is refused at runtime.
fn question_set_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,"required":["questions"],
        "properties":{
            "questions":{"type":"array","minItems":1,"maxItems":learning::MAX_QUESTIONS,"items":{
                "type":"object","additionalProperties":false,
                "required":["id","question","options","type"],
                "properties":{
                    "id":{"type":"integer","minimum":1,"maximum":100000},
                    "chapter":{"type":["integer","null"],"minimum":1,"maximum":100000},
                    "question":{"type":"string","minLength":1,"maxLength":learning::MAX_QUESTION_BYTES},
                    "options":{"type":"array","minItems":2,"maxItems":learning::MAX_OPTIONS,"items":{"type":"string","minLength":1,"maxLength":learning::MAX_OPTION_BYTES}},
                    "type":{"enum":[1,2],"description":"1 for single choice, 2 for multiple choice, as in the upstream question model."}
                }
            }}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CacheStatus, Response};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::collections::BTreeMap;

    fn response(url: &url::Url, body: &[u8], content_type: &str) -> Response {
        Response {
            url: url.as_str().to_owned(),
            status: 200,
            headers: BTreeMap::from([("content-type".to_owned(), content_type.to_owned())]),
            body: body.to_vec(),
            sha256: learning::sha256_hex(body),
            fetched_at_unix_ms: 1_700_000_000_000,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    /// A tree whose root and every directory object hash really cover the
    /// listed entries, as a recursive GitHub tree response does.
    const TREE: &[u8] = br#"{
        "sha":"8af938222bb8f360509bd2d3983edb26b06db1ec",
        "url":"https://api.github.com/ignored",
        "truncated":false,
        "tree":[
            {"path":"LICENSE","mode":"100644","type":"blob","sha":"1123456789abcdef0123456789abcdef01234567","size":10795},
            {"path":"README.md","mode":"100644","type":"blob","sha":"2123456789abcdef0123456789abcdef01234567","size":228},
            {"path":"HangGai","mode":"040000","type":"tree","sha":"87360e2d0781993ca76f03909314b979e40f3b33"},
            {"path":"HangGai/Assets","mode":"040000","type":"tree","sha":"a7e40e1d953815aa1ae0a3c22df9d5b5afee68e2"},
            {"path":"HangGai/Assets/DB","mode":"040000","type":"tree","sha":"4e24d77a3d2437c4f525f932d78d51e1a6f3d163"},
            {"path":"HangGai/Assets/DB/questions.db","mode":"100644","type":"blob","sha":"3123456789abcdef0123456789abcdef01234567","size":352256},
            {"path":"HangGai/Assets/QuestionImgs","mode":"040000","type":"tree","sha":"385eb785a9f4c74582e8a4ed619d7dac04ca7d05"},
            {"path":"HangGai/Assets/QuestionImgs/1001h.png","mode":"100644","type":"blob","sha":"4123456789abcdef0123456789abcdef01234567","size":15285},
            {"path":"HangGai/Models","mode":"040000","type":"tree","sha":"5c7a8dd99f45d135aee0ee6d9485fe32f80d8908"},
            {"path":"HangGai/Models/QuestionModel.swift","mode":"100644","type":"blob","sha":"5123456789abcdef0123456789abcdef01234567","size":865}
        ]
    }"#;

    fn tree_identity(url: &url::Url, body: &[u8], content_type: &str) -> learning::ObservedIdentity {
        learning::observed_identity(learning::Surface::Tree, url, body, Some(content_type))
    }

    #[test]
    fn the_bundled_answer_bank_is_listed_but_never_retrievable() {
        let url = SOURCE.tree_url().unwrap();
        let identity = tree_identity(&url, TREE, "application/json");
        let output = learning::inventory_output(
            &SOURCE,
            TYPE_LABEL,
            &url,
            &response(&url, TREE, "application/json"),
            &identity,
            &classify,
        )
        .unwrap();
        assert_eq!(output["result"], "inventory_snapshot");
        assert_eq!(output["entry_count"], 10);
        assert_eq!(output["entries"][0]["material_class"], "license");
        assert_eq!(output["entries"][1]["material_class"], "documentation");
        let bank = output["entries"].as_array().unwrap().iter()
            .find(|entry| entry["path"] == ANSWER_BANK_PATH).unwrap();
        assert_eq!(bank["material_class"], "answer_material");
        assert_eq!(bank["retrieval_allowed"], false);
        assert_eq!(bank["mirror_allowed"], false);
        let images = output["entries"].as_array().unwrap().iter()
            .find(|entry| entry["path"] == "HangGai/Assets/QuestionImgs/1001h.png").unwrap();
        assert_eq!(images["material_class"], "assessment_content");
        assert_eq!(images["mirror_allowed"], false);
        let model = output["entries"].as_array().unwrap().iter()
            .find(|entry| entry["path"] == "HangGai/Models/QuestionModel.swift").unwrap();
        assert_eq!(model["material_class"], "source_code");
        // A directory is never advertised as retrievable.
        let directory = output["entries"].as_array().unwrap().iter()
            .find(|entry| entry["path"] == "HangGai").unwrap();
        assert_eq!(directory["kind"], "directory");
        assert_eq!(directory["retrieval_allowed"], false);
        assert_eq!(directory["url"], Value::Null);
        assert_eq!(
            output["entries"][1]["license"]["operator_reference"],
            Value::Null
        );
        assert_eq!(output["license"]["independently_verified"], false);
    }

    #[test]
    fn a_root_level_answer_directory_is_answer_material() {
        assert_eq!(classify("answers/key.txt"), learning::MaterialClass::AnswerMaterial);
        assert_eq!(classify("docs/answers/key.txt"), learning::MaterialClass::AnswerMaterial);
        assert!(learning::answer_path_component("answers/key.txt"));
    }

    #[test]
    fn a_malformed_tree_degrades_with_the_original_bytes() {
        let url = SOURCE.tree_url().unwrap();
        let body = br#"{"sha":"not-a-digest","tree":[],"truncated":false}"#;
        let identity = tree_identity(&url, body, "application/json");
        let output = learning::inventory_output(
            &SOURCE,
            TYPE_LABEL,
            &url,
            &response(&url, body, "application/json"),
            &identity,
            &classify,
        )
        .unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["fallback_reason"], "upstream_parse");
        assert_eq!(output["entries"], json!([]));
        assert_eq!(output["raw_evidence"]["content_type"], "application/json");
        assert_eq!(output["raw_evidence"]["byte_length"], body.len());
        assert_eq!(output["raw_evidence"]["sha256"], learning::sha256_hex(body));
        assert_eq!(output["raw_evidence"]["data"], STANDARD.encode(body));
        assert_eq!(output["raw_evidence"]["fallback_reason"], "upstream_parse");
    }

    #[test]
    fn the_rights_gate_precedes_any_admission() {
        let denied = parse_search_input(r#"{"query":"question","rights_reviewed":false}"#)
            .err()
            .unwrap();
        assert_eq!(denied.code, "authorization_required");
        let missing = parse_fetch_input(r#"{"path":"README.md"}"#).err().unwrap();
        assert_eq!(missing.code, "authorization_required");
        for path in ["", "/absolute", "../secret", "a/./b", "a//b", "a\\b"] {
            let request = json!({"path": path, "rights_reviewed": true}).to_string();
            assert_eq!(
                parse_fetch_input(&request).err().unwrap().code,
                "invalid_input",
                "path {path:?}"
            );
        }
        // A download must name the exact reviewed immutable object.
        let unattested = parse_fetch_input(r#"{"path":"README.md","rights_reviewed":true}"#)
            .err()
            .unwrap();
        assert_eq!(unattested.code, "authorization_required");
        let accepted = parse_fetch_input(
            r#"{"path":"README.md","rights_reviewed":true,"tree_sha":"3934f139b11918acc170f920c4e8290ef4b57376","blob_sha":"2123456789abcdef0123456789abcdef01234567","mode":"100644","size":228}"#,
        )
        .unwrap();
        assert_eq!(accepted.path, "README.md");
    }

    #[test]
    fn a_question_set_carrying_an_answer_is_refused() {
        let with_answer = json!({
            "questions": [{
                "id": 1,
                "chapter": 2,
                "question": "Which discipline studies aircraft motion?",
                "options": ["Aerodynamics", "Optics"],
                "type": 1,
                "answer": "A"
            }]
        });
        let refused = questions_from_question_set(&with_answer).err().unwrap();
        assert_eq!(refused.code, "answer_material_forbidden");

        let clean = json!({
            "questions": [{
                "id": 1,
                "chapter": 2,
                "question": "Which discipline studies aircraft motion?",
                "options": ["Aerodynamics", "Optics"],
                "type": 1
            }]
        });
        let questions = questions_from_question_set(&clean).unwrap();
        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].question_id, "q1");
        assert_eq!(questions[0].kind, "choice");
        assert_eq!(questions[0].chapter, Some(2));
        assert_eq!(questions[0].question_type, Some(1));
        assert_eq!(questions[0].options.as_ref().unwrap().len(), 2);
        assert_eq!(questions[0].local_self_check_key, None);
        assert_eq!(questions[0].key_source, "none");
    }

    #[test]
    fn the_practice_result_reflects_only_the_local_answers() {
        let generated = practice(
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"chapter":1,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]},"rights_reviewed":true}"#,
        )
        .unwrap();
        assert_eq!(generated["type"], PRACTICE_TYPE_LABEL);
        assert_eq!(generated["official_grade"], Value::Null);
        assert_eq!(generated["completion_reported"], false);
        assert_eq!(generated["submission_state"], "not_submitted");
        assert_eq!(generated["questions"][0]["question_id"], "q7");

        let answered = practice(
            &json!({
                "action": "answer",
                "session": generated,
                "answers": [{"question_id": "q7", "choices": ["A"]}]
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(answered["answers"][0]["choices"], json!(["A"]));

        let checked = practice(&json!({"action": "check", "session": answered}).to_string()).unwrap();
        assert_eq!(checked["results"]["authority"], "local_self_check");
        assert_eq!(checked["results"]["official_grade"], Value::Null);
        assert_eq!(checked["results"]["local_unverifiable_count"], 1);
        assert_eq!(checked["results"]["completion_reported"], false);

        let keyed = practice(
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]},"local_answer_key":[{"question_id":"q7","choices":["A"]}]}"#,
        )
        .unwrap();
        assert_eq!(keyed["questions"][0]["key_source"], "operator_supplied");
        assert_eq!(keyed["questions"][0]["local_self_check_key"], json!(["A"]));
    }

    #[test]
    fn the_schema_matches_the_accepted_sets() {
        let contract = schema();
        assert_eq!(
            contract["search"]["input"]["properties"]["rights_reviewed"]["const"],
            true
        );
        assert_eq!(
            contract["fetch"]["input"]["properties"]["rights_reviewed"]["const"],
            true
        );
        assert!(contract["fetch"]["output"]["oneOf"].is_array());
        assert_eq!(
            contract["practice"]["input"]["oneOf"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        let question_set = &contract["practice"]["input"]["oneOf"][1]["properties"]["question_set"];
        assert!(question_set["properties"]["questions"]["items"]["properties"]
            .get("answer")
            .is_none());
    }
}
