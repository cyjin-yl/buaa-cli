//! 航空航天概论 material inventory and local study practice.
//!
//! The source-reviewed upstream reference for this capability is the
//! community repository `Caniformia/HangGai` (GPL-3.0), a SwiftUI study
//! application for 北京航空航天大学 that ships a bundled question bank
//! (`HangGai/Assets/DB/questions.db`, table `science_questions`) together
//! with the question images it renders.
//!
//! The review is bound to one immutable upstream revision: commit
//! `6c28cbb7679865546eace87089807944a07f1714` and the tree it declares,
//! `4eb358ae271b5ceae2aa0003999172f806a128d7` (469 blobs and 177
//! directory objects). A branch head
//! can move, so the commit must name the reviewed commit and declare the
//! reviewed tree, and every advertised directory and the root object are
//! reconstructed and verified before an entry is published.
//!
//! Rights are decided per item, never per repository. Exactly two items
//! are admitted: the author's own `README.md` (228 bytes, GPL-3.0) and the
//! verbatim `LICENSE` notice object. Every other entry of the pinned tree
//! keeps its per-item exclusion reason: the answer-bearing question bank,
//! the 247 course question images, third-party font binaries, upstream
//! implementation sources, project metadata, asset-catalog indices and
//! artwork are listed with their reason and are never retrievable. A blob
//! that does not match the `README.md` or `LICENSE` reviewed object
//! identity is refused before any byte request, including when it is an
//! alias of an admitted or answer-bearing object under another path. The
//! license text is retrieved separately through `LICENSE`; metadata and
//! the notice-obligation flag do not attest redistribution compliance, and
//! no upstream prose or implementation is copied into this project.
//!
//! That per-item decision is published exhaustively and structurally: every
//! entry carries `admission: "admitted"` or `admission: "excluded"`, an
//! excluded entry always names its reason and carries neither a retrieval
//! URL nor license evidence, and an admitted entry carries the reviewed
//! license evidence that covers it. Naming a reviewed path is not enough to
//! be admitted: a directory, symlink or submodule at that path stays
//! excluded with its own reason.
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
//! claims an official grade, a completion state or a submission. The practice
//! request is decoded strictly, so a repeated object member at any depth or a
//! second JSON document is refused before use, and a submitted session is
//! admitted only when its rights attestation is present at both published
//! depths and both agree.
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
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
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

/// The reviewed upstream revision: one commit and the tree it declares.
const REVISION: learning::Revision = learning::Revision {
    commit: "6c28cbb7679865546eace87089807944a07f1714",
    tree: "4eb358ae271b5ceae2aa0003999172f806a128d7",
};

/// The reviewed license object: the verbatim GNU GPL version 3 text.
const REVIEWED_LICENSE_BLOB: &str = "f288702d2fa16d3cdf0035b15a9fcbc552cd88e7";
const REVIEWED_LICENSE_SIZE: u64 = 35149;
const REVIEWED_LICENSE_SPDX: &str = "GPL-3.0";
const REVIEWED_LICENSE_NAME: &str = "GNU General Public License v3.0";

/// The reviewed readme object: the author's own description of the app.
const REVIEWED_README_BLOB: &str = "0b4aaae22b098e2d00e603fb7ce39b95fd13905f";
const REVIEWED_README_SIZE: u64 = 228;

/// The reviewed answer-bank object: the bundled `science_questions`
/// database that holds every question's correct answer. It is answer
/// material under any path its object appears at.
const REVIEWED_ANSWER_BANK_BLOB: &str = "ef1a7ff882139fbbde6264916ca958f0717a1bd0";

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

/// The exact members of the practice-source attestation this module
/// publishes. A source object carrying any other member is not that
/// attestation.
const PRACTICE_SOURCE_KEYS: &[&str] = &["kind", "origin", "rights_reviewed", "digest", "scan"];

/// The reviewed material class of one item of the pinned tree.
/// `AnswerMaterial` is the strongest category: it is never retrievable and
/// never mirrorable, and the answer bank keeps it under any aliased path.
/// `AssessmentContent` carries course question renderings; it is never
/// mirrorable in bulk and this reviewed tree does not clear it for
/// retrieval either. `Excluded` is every other unreviewed item. A class is
/// only ever published together with the verdict that decides admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaterialClass {
    Documentation,
    License,
    AnswerMaterial,
    AssessmentContent,
    Excluded,
}

impl MaterialClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Documentation => "documentation",
            Self::License => "license",
            Self::AnswerMaterial => "answer_material",
            Self::AssessmentContent => "assessment_content",
            Self::Excluded => "excluded",
        }
    }
}

/// The reviewed license evidence of one admitted object. It binds the exact
/// admitted entry to the exact license object of the pinned tree; it is an
/// operator review of that object, not an independent rights proof, and it
/// does not attest redistribution compliance.
#[derive(Clone, Copy)]
struct LicenseEvidence {
    basis: &'static str,
    spdx_id: &'static str,
    name: &'static str,
    license_blob_sha: &'static str,
    license_size: u64,
}

impl LicenseEvidence {
    fn value(self) -> Value {
        json!({
            "basis": self.basis,
            "spdx_id": self.spdx_id,
            "name": self.name,
            "license_blob_sha": self.license_blob_sha,
            "license_size": self.license_size,
            "independently_verified": false,
        })
    }
}

/// The reviewed evidence of the author's own description: the description is
/// covered by the repository license, whose verbatim notice is a separate
/// admitted object of the same pinned tree.
const README_LICENSE_EVIDENCE: LicenseEvidence = LicenseEvidence {
    basis: "author_written_description_covered_by_the_repository_license",
    spdx_id: REVIEWED_LICENSE_SPDX,
    name: REVIEWED_LICENSE_NAME,
    license_blob_sha: REVIEWED_LICENSE_BLOB,
    license_size: REVIEWED_LICENSE_SIZE,
};

/// The reviewed evidence of the license object itself: the emitted bytes are
/// the verbatim notice the operator reviewed.
const LICENSE_EVIDENCE: LicenseEvidence = LicenseEvidence {
    basis: "verbatim_license_notice_of_the_reviewed_work",
    spdx_id: REVIEWED_LICENSE_SPDX,
    name: REVIEWED_LICENSE_NAME,
    license_blob_sha: REVIEWED_LICENSE_BLOB,
    license_size: REVIEWED_LICENSE_SIZE,
};

/// The exhaustive per-item rights verdict of one entry of the pinned tree.
/// Exactly one of the two outcomes applies to every entry, so an entry can
/// never be published without an explicit rights decision: either the
/// reviewed object is admitted under its exact identity together with the
/// license evidence that covers it, or the entry is excluded with its reason
/// and is never advertised as retrievable or mirrorable.
enum Verdict {
    Admitted {
        class: MaterialClass,
        evidence: LicenseEvidence,
    },
    Excluded {
        class: MaterialClass,
        reason: &'static str,
    },
}

impl Verdict {
    fn admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }
}

/// The reviewed per-item decision, keyed on the exact repository path, the
/// entry kind, the immutable blob identity and the declared size. Only a
/// regular file at the reviewed path with the reviewed object identity is
/// admitted; every other entry keeps its exclusion reason, including a
/// directory, symlink or submodule at a reviewed path and an alias of a
/// reviewed object under another path.
fn verdict_of(entry: &learning::TreeEntry) -> Verdict {
    if entry.kind() == Some("file") {
        match entry.path.as_str() {
            "README.md"
                if entry.sha == REVIEWED_README_BLOB
                    && entry.size == Some(REVIEWED_README_SIZE) =>
            {
                return Verdict::Admitted {
                    class: MaterialClass::Documentation,
                    evidence: README_LICENSE_EVIDENCE,
                };
            }
            "LICENSE"
                if entry.sha == REVIEWED_LICENSE_BLOB
                    && entry.size == Some(REVIEWED_LICENSE_SIZE) =>
            {
                return Verdict::Admitted {
                    class: MaterialClass::License,
                    evidence: LICENSE_EVIDENCE,
                };
            }
            _ => {}
        }
    }
    let (class, reason) = excluded_verdict(entry);
    Verdict::Excluded { class, reason }
}

/// The exclusion class and reason of an entry that is not admitted. The
/// bundled answer bank is recognized by exact object identity before its
/// path, so an alias or a non-file object of its bytes is answer material
/// under any name; a reviewed path carrying any other kind is excluded
/// because only a regular file can be retrieved.
fn excluded_verdict(entry: &learning::TreeEntry) -> (MaterialClass, &'static str) {
    if entry.path == ANSWER_BANK_PATH || entry.sha == REVIEWED_ANSWER_BANK_BLOB {
        return (
            MaterialClass::AnswerMaterial,
            "bundled_answer_bank_is_never_retrieved",
        );
    }
    if entry.kind() != Some("file") {
        return match entry.path.as_str() {
            "README.md" | "LICENSE" => (
                MaterialClass::Excluded,
                "the_reviewed_path_is_not_a_regular_file",
            ),
            _ => classify_excluded(&entry.path),
        };
    }
    match entry.path.as_str() {
        "README.md" => (
            MaterialClass::Excluded,
            "the_root_readme_is_not_the_reviewed_object",
        ),
        "LICENSE" => (
            MaterialClass::Excluded,
            "the_license_object_is_not_the_reviewed_license_identity",
        ),
        _ => classify_excluded(&entry.path),
    }
}

/// The path-based exclusion class and reason of a regular file that is not
/// one of the two reviewed objects. Answer material is detected here by
/// path, and by exact object identity in `excluded_verdict`, so an alias of
/// the bundled answer bank is answer material under any name.
fn classify_excluded(path: &str) -> (MaterialClass, &'static str) {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if name.ends_with(".db")
        || name.ends_with(".sqlite")
        || name.ends_with(".sqlite3")
        || name.contains("answer")
        || name.contains("solution")
        || learning::answer_path_component(path)
    {
        return (
            MaterialClass::AnswerMaterial,
            "answer_bearing_name_is_never_retrieved",
        );
    }
    if lower.contains("questionimgs/")
        || (lower.contains("questionimages/") && name.ends_with(".png"))
    {
        return (
            MaterialClass::AssessmentContent,
            "course_question_image_without_cleared_rights",
        );
    }
    if lower.contains("questionimages/") || lower.ends_with(".imageset") {
        return (
            MaterialClass::Excluded,
            "asset_catalog_entry_of_excluded_question_images",
        );
    }
    if name.ends_with(".ttf") || name.ends_with(".otf") {
        return (
            MaterialClass::Excluded,
            "third_party_font_binary_without_cleared_rights",
        );
    }
    if lower.contains(".appiconset") {
        return (
            MaterialClass::Excluded,
            "app_icon_artwork_without_a_study_purpose",
        );
    }
    if name.ends_with(".swift") {
        return (
            MaterialClass::Excluded,
            "upstream_implementation_source_is_not_reference_material",
        );
    }
    if name.ends_with(".plist")
        || name.ends_with(".pbxproj")
        || name.ends_with(".xcworkspacedata")
        || name.ends_with(".xcscheme")
        || name.ends_with(".xcuserstate")
        || name.ends_with(".xcbkptlist")
        || lower.starts_with("hanggai.xcodeproj/")
        || lower.starts_with("hanggai.xcworkspace/")
    {
        return (
            MaterialClass::Excluded,
            "upstream_project_or_developer_metadata",
        );
    }
    if lower.contains(".xcassets/") {
        return (MaterialClass::Excluded, "generated_asset_catalog_metadata");
    }
    if name.ends_with(".png") || name.ends_with(".jpg") || name.ends_with(".jpeg") {
        return (
            MaterialClass::Excluded,
            "artwork_or_screenshot_without_a_study_purpose",
        );
    }
    (
        MaterialClass::Excluded,
        "repository_metadata_or_unreviewed_item",
    )
}

/// The display title of one inventory entry, as the shared inventory used.
fn title_of(path: &str) -> String {
    let title = path.rsplit('/').next().unwrap_or(path);
    if title.chars().count() > learning::MAX_TITLE_BYTES {
        title.chars().take(learning::MAX_TITLE_BYTES).collect()
    } else {
        title.to_owned()
    }
}

/// The license provenance bound to the admitted tree. The SPDX reference is
/// the reviewed identifier of the exact license object the tree carries; it
/// is an operator review of that object, not an independent proof, and it
/// does not attest redistribution compliance.
fn license_value(entries: &[learning::TreeEntry]) -> Value {
    let bound = entries.iter().find(|entry| {
        entry.path == "LICENSE"
            && entry.sha == REVIEWED_LICENSE_BLOB
            && entry.size == Some(REVIEWED_LICENSE_SIZE)
    });
    json!({
        "operator_reference": bound.map(|_| json!({
            "spdx_id": REVIEWED_LICENSE_SPDX,
            "name": REVIEWED_LICENSE_NAME,
        })).unwrap_or(Value::Null),
        "bound_license_blob_sha": bound.map(|entry| entry.sha.as_str()),
        "bound_license_size": bound.and_then(|entry| entry.size),
        "bound_license_url": bound
            .and_then(|entry| SOURCE.blob_url(&entry.sha).ok())
            .map(|url| Value::String(url.as_str().to_owned()))
            .unwrap_or(Value::Null),
        "independently_verified": false,
    })
}

/// The reviewed revision published on every output.
fn revision_value() -> Value {
    json!({"commit": REVISION.commit, "tree": REVISION.tree})
}

/// One published inventory entry with its exhaustive per-item rights
/// verdict. An admitted entry advertises its immutable blob URL and the
/// reviewed license evidence that covers it; every excluded entry carries
/// `admission: "excluded"` with its reason, a null license evidence and no
/// retrieval URL.
fn inventory_entry(license: &Value, item: &learning::TreeEntry) -> Value {
    let verdict = verdict_of(item);
    let retrievable = verdict.admitted();
    let (admission, class, reason, evidence) = match &verdict {
        Verdict::Admitted { class, evidence } => {
            ("admitted", *class, evidence.basis, evidence.value())
        }
        Verdict::Excluded { class, reason } => ("excluded", *class, *reason, Value::Null),
    };
    let url = if retrievable {
        SOURCE
            .blob_url(&item.sha)
            .map(|url| Value::String(url.as_str().to_owned()))
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    json!({
        "title": title_of(&item.path),
        "source": SOURCE.full_name(),
        "source_url": SOURCE.repository_url(),
        "branch": SOURCE.branch,
        "path": item.path,
        "url": url,
        "size": item.size,
        "kind": item.kind().unwrap_or("other"),
        "mode": item.mode,
        "material_class": class.as_str(),
        "admission": admission,
        "admission_reason": reason,
        "license_evidence": evidence,
        "mirror_allowed": retrievable,
        "retrieval_allowed": retrievable,
        "rights_review_required": true,
        "rights_reviewed": false,
        "license": license,
        "attribution": SOURCE.full_name(),
        "upstream_sha": item.sha
    })
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
    // Decode through a map-only visitor, matching the reference-material
    // adapter: a positional sequence root is not a request object, and
    // decoding the map directly preserves duplicate fields so the derived
    // visitor rejects them instead of last-key-wins collapsing them.
    struct RequestObject;
    impl<'de> serde::de::Visitor<'de> for RequestObject {
        type Value = SearchInput;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a material search request object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            serde::Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(input);
    let parsed: SearchInput = serde::Deserializer::deserialize_map(&mut decoder, RequestObject)
        .map_err(|_| learning::invalid_input("the search request is malformed"))?;
    decoder
        .end()
        .map_err(|_| learning::invalid_input("the search request is malformed"))?;
    if parsed.rights_reviewed != Some(true) {
        return Err(learning::authorization_required(
            "a material search requires an explicit rights-review attestation",
        ));
    }
    let query = parsed.query.trim();
    if query.is_empty() || query.len() > learning::MAX_QUERY_BYTES {
        return Err(learning::invalid_input(
            "the search query is empty or too long",
        ));
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
    // The same map-only admission as the search request: only a JSON object
    // is a request, duplicate fields reach the derived visitor unchanged
    // and a trailing document is refused before any cache or network read.
    struct RequestObject;
    impl<'de> serde::de::Visitor<'de> for RequestObject {
        type Value = FetchInput;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a material download request object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            serde::Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(input);
    let parsed: FetchInput = serde::Deserializer::deserialize_map(&mut decoder, RequestObject)
        .map_err(|_| learning::invalid_input("the fetch request is malformed"))?;
    decoder
        .end()
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
        if tree_sha != REVISION.tree {
            return Err(learning::invalid_input(
                "tree_sha must be the reviewed tree object of the pinned revision",
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
/// `online` permits exactly the governed commit and immutable-tree requests
/// of the pinned revision on a cache miss.
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
    learning::with_pinned_tree_response(&SOURCE, &REVISION, online, |response, identity, url| {
        materials_output(url, response, identity)
    })
}

/// Search the reviewed inventory. The rights-review attestation is required
/// before any cache or network admission.
pub fn search(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_search_input(input)?;
    learning::with_pinned_tree_response(&SOURCE, &REVISION, online, |response, identity, url| {
        search_output(url, response, identity, &request.query)
    })
}

/// The inventory of the pinned revision, published only from a tree whose
/// every object was verified. Every entry carries its per-item verdict.
fn materials_output(
    expected: &url::Url,
    response: &crate::net::Response,
    identity: &learning::ObservedIdentity,
) -> Result<Value, Error> {
    if response.url != expected.as_str() || response.status != 200 {
        return Err(Error::new(
            "http_rejected",
            "the learning-material inventory provenance does not match the requested tree",
        ));
    }
    if response.body.len() > learning::MAX_TREE_BODY {
        return Err(learning::body_limit());
    }
    let mut output = json!({
        "schema_version": 1,
        "type": TYPE_LABEL,
        "result": Value::Null,
        "source": SOURCE.full_name(),
        "source_url": SOURCE.repository_url(),
        "branch": SOURCE.branch,
        "revision": revision_value(),
        "license": learning::unknown_license(),
        "attribution": SOURCE.full_name(),
        "rights_reviewed": false,
        "tree_sha": Value::Null,
        "truncated": Value::Null,
        "complete": false,
        "next_cursor": Value::Null,
        "entries": Value::Null,
        "entry_count": 0,
        "admitted_count": 0,
        "excluded_count": 0,
        "fallback_reason": Value::Null,
        "raw_evidence": Value::Null,
        "retrieval": learning::retrieval(response)
    });
    match identity.tree() {
        Some(admitted) => {
            let tree_sha = admitted.tree_sha.as_str();
            let entries = admitted.entries.as_slice();
            let license = license_value(entries);
            let values: Vec<Value> = entries
                .iter()
                .map(|entry| inventory_entry(&license, entry))
                .collect();
            let admitted_count = values
                .iter()
                .filter(|value| value["admission"].as_str() == Some("admitted"))
                .count();
            output["result"] = json!("inventory_snapshot");
            output["tree_sha"] = json!(tree_sha);
            output["truncated"] = json!(false);
            output["complete"] = json!(true);
            output["entries"] = json!(values);
            output["entry_count"] = json!(entries.len());
            output["admitted_count"] = json!(admitted_count);
            output["excluded_count"] = json!(entries.len() - admitted_count);
            output["license"] = license;
            Ok(output)
        }
        None => {
            let reason = identity.tree_error().unwrap_or("upstream_parse");
            output["result"] = json!("degraded");
            output["entries"] = json!([]);
            output["fallback_reason"] = json!(reason);
            output["raw_evidence"] = learning::degraded_evidence(response, identity, reason)?;
            Ok(output)
        }
    }
}

/// The entries matching one case-insensitive query of the pinned
/// inventory, each with its per-item verdict.
fn search_output(
    expected: &url::Url,
    response: &crate::net::Response,
    identity: &learning::ObservedIdentity,
    query: &str,
) -> Result<Value, Error> {
    if response.url != expected.as_str() || response.status != 200 {
        return Err(Error::new(
            "http_rejected",
            "the learning-material search provenance does not match the requested tree",
        ));
    }
    if response.body.len() > learning::MAX_TREE_BODY {
        return Err(learning::body_limit());
    }
    let needle = query.to_lowercase();
    let mut output = json!({
        "schema_version": 1,
        "type": SEARCH_TYPE_LABEL,
        "result": Value::Null,
        "query": query,
        "rights_reviewed": true,
        "source": SOURCE.full_name(),
        "source_url": SOURCE.repository_url(),
        "branch": SOURCE.branch,
        "revision": revision_value(),
        "license": learning::unknown_license(),
        "attribution": SOURCE.full_name(),
        "tree_sha": Value::Null,
        "truncated": Value::Null,
        "complete": false,
        "next_cursor": Value::Null,
        "matches": Value::Null,
        "match_count": 0,
        "fallback_reason": Value::Null,
        "raw_evidence": Value::Null,
        "retrieval": learning::retrieval(response)
    });
    match identity.tree() {
        Some(admitted) => {
            let tree_sha = admitted.tree_sha.as_str();
            let entries = admitted.entries.as_slice();
            let license = license_value(entries);
            let values: Vec<Value> = entries
                .iter()
                .filter(|entry| {
                    let title = title_of(&entry.path);
                    entry.path.to_lowercase().contains(&needle)
                        || title.to_lowercase().contains(&needle)
                })
                .map(|entry| inventory_entry(&license, entry))
                .collect();
            output["result"] = json!("search_snapshot");
            output["tree_sha"] = json!(tree_sha);
            output["truncated"] = json!(false);
            output["complete"] = json!(true);
            let match_count = values.len();
            output["matches"] = Value::Array(values);
            output["match_count"] = json!(match_count);
            output["license"] = license;
            Ok(output)
        }
        None => {
            let reason = identity.tree_error().unwrap_or("upstream_parse");
            output["result"] = json!("degraded");
            output["matches"] = json!([]);
            output["fallback_reason"] = json!(reason);
            output["raw_evidence"] = learning::degraded_evidence(response, identity, reason)?;
            Ok(output)
        }
    }
}

/// The outcome of resolving one requested path against the reviewed
/// inventory. A refusal travels as an inner result so that the complete
/// verified tree is retained before the error is reported.
enum Admission {
    Classified {
        class: MaterialClass,
        reason: &'static str,
        tree_sha: String,
        blob_sha: String,
        size: u64,
        license: Value,
    },
    Degraded(Value),
    Refused(Error),
}

/// The reviewed membership of the pinned tree for one requested item. The
/// complete reviewed attestation must match the entry's immutable identity;
/// the verdict is then resolved from the per-item review, so the bundled
/// answer bank, every excluded item and every nonadmitted alias is refused
/// before any byte request is made.
fn select_item(
    entries: &[learning::TreeEntry],
    request: &FetchInput,
) -> Result<(MaterialClass, &'static str, String, u64, Value), Error> {
    let entry = entries
        .iter()
        .find(|entry| entry.path == request.path)
        .ok_or_else(|| {
            Error::new(
                "path_not_in_inventory",
                "the requested path is not present in the reviewed material inventory",
            )
        })?;
    let Some(size) = entry.size else {
        return Err(Error::new(
            "path_not_in_inventory",
            "the requested path is not present in the reviewed material inventory",
        ));
    };
    let Some(mode) = entry
        .kind()
        .filter(|kind| *kind == "file")
        .map(|_| entry.mode.as_str())
    else {
        return Err(learning::invalid_input(
            "only regular inventory files can be retrieved",
        ));
    };
    if request.tree_sha.as_deref() != Some(REVISION.tree)
        || request.blob_sha.as_deref() != Some(entry.sha.as_str())
        || request.mode.as_deref() != Some(mode)
        || request.size != Some(size)
    {
        return Err(learning::authorization_required(
            "the requested material does not match the reviewed immutable identity",
        ));
    }
    match verdict_of(entry) {
        Verdict::Admitted { class, evidence } => Ok((
            class,
            evidence.basis,
            entry.sha.clone(),
            size,
            license_value(entries),
        )),
        Verdict::Excluded {
            class: MaterialClass::AnswerMaterial,
            ..
        } => Err(learning::answer_material_forbidden()),
        Verdict::Excluded { .. } => Err(learning::authorization_required(
            "the requested item has no documented per-item rights and is never retrievable",
        )),
    }
}

/// Fetch the bytes of one reviewed material entry. The material class is
/// resolved from the reviewed inventory first, so the bundled answer bank is
/// refused before any byte request is made.
pub fn fetch(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_fetch_input(input)?;
    let admission = learning::with_pinned_tree_response(
        &SOURCE,
        &REVISION,
        online,
        |response, identity, _| match identity.tree() {
            Some(admitted) => {
                let tree_sha = admitted.tree_sha.as_str();
                let entries = admitted.entries.as_slice();
                Ok(match select_item(entries, &request) {
                    Ok((class, reason, blob_sha, size, license)) => Admission::Classified {
                        class,
                        reason,
                        tree_sha: tree_sha.to_owned(),
                        blob_sha,
                        size,
                        license,
                    },
                    // Keep a refused selection inside the successful response
                    // consumer so the complete source tree is still cached.
                    Err(error) => Admission::Refused(error),
                })
            }
            None => {
                let reason = identity.tree_error().unwrap_or("upstream_parse");
                Ok(Admission::Degraded(degraded_bytes_output(
                    response, identity, &request, reason,
                )?))
            }
        },
    )?;
    match admission {
        Admission::Degraded(output) => Ok(output),
        Admission::Refused(error) => Err(error),
        Admission::Classified {
            class,
            reason,
            tree_sha,
            blob_sha,
            size,
            license,
        } => learning::with_raw_response(&SOURCE, &blob_sha, online, |response, identity| {
            raw_bytes_output(
                response,
                identity,
                &request,
                class,
                reason,
                &ReviewedObject {
                    tree_sha: &tree_sha,
                    blob_sha: &blob_sha,
                    size,
                },
                license,
            )
        }),
    }
}

/// The degraded output of a fetch whose tree could not be admitted. The
/// original inventory or commit response is preserved as degraded
/// evidence; no bytes were ever requested.
fn degraded_bytes_output(
    response: &crate::net::Response,
    identity: &learning::ObservedIdentity,
    request: &FetchInput,
    reason: &str,
) -> Result<Value, Error> {
    let evidence = learning::degraded_evidence(response, identity, reason)?;
    Ok(json!({
        "schema_version": 1,
        "type": RAW_TYPE_LABEL,
        "result": "degraded",
        "path": request.path,
        "source": SOURCE.full_name(),
        "source_url": SOURCE.repository_url(),
        "branch": SOURCE.branch,
        "revision": revision_value(),
        "tree_sha": Value::Null,
        "upstream_sha": Value::Null,
        "size": Value::Null,
        "license": learning::unknown_license(),
        "attribution": SOURCE.full_name(),
        "rights_reviewed": true,
        "material_class": Value::Null,
        "admission_reason": Value::Null,
        "license_notice_required": true,
        "bytes": Value::Null,
        "byte_encoding": "base64",
        "byte_length": Value::Null,
        "sha256": Value::Null,
        "content_type": Value::Null,
        "fallback_reason": reason,
        "raw_evidence": evidence,
        "retrieval": learning::retrieval(response)
    }))
}

/// The reviewed immutable object one retrieval must match.
struct ReviewedObject<'a> {
    tree_sha: &'a str,
    blob_sha: &'a str,
    size: u64,
}

/// The published output of one byte request. The bytes must be exactly the
/// reviewed object: bytes that are not that object never passed the
/// per-item rights admission, so only their length, digest and reason are
/// reported and the original bytes are never disclosed.
fn raw_bytes_output(
    response: &crate::net::Response,
    identity: &learning::ObservedIdentity,
    request: &FetchInput,
    class: MaterialClass,
    reason: &'static str,
    object: &ReviewedObject<'_>,
    license: Value,
) -> Result<Value, Error> {
    let ReviewedObject {
        tree_sha,
        blob_sha,
        size,
    } = object;
    let size = *size;
    let expected = SOURCE.blob_url(blob_sha)?;
    if response.url != expected.as_str()
        || response.status != 200
        || response.body.len() > learning::MAX_RAW_BODY
    {
        return Err(learning::upstream_parse());
    }
    let observed = learning::content_type(response);
    let mut output = json!({
        "schema_version": 1,
        "type": RAW_TYPE_LABEL,
        "result": Value::Null,
        "path": request.path,
        "source": SOURCE.full_name(),
        "source_url": SOURCE.repository_url(),
        "branch": SOURCE.branch,
        "revision": revision_value(),
        "tree_sha": tree_sha,
        "upstream_sha": blob_sha,
        "size": size,
        "license": license,
        "attribution": SOURCE.full_name(),
        "rights_reviewed": true,
        "material_class": class.as_str(),
        "admission_reason": reason,
        "license_notice_required": true,
        "bytes": Value::Null,
        "byte_encoding": "base64",
        "byte_length": Value::Null,
        "sha256": Value::Null,
        "content_type": Value::Null,
        "fallback_reason": Value::Null,
        "raw_evidence": Value::Null,
        "retrieval": learning::retrieval(response)
    });
    output["retrieval"]["admitted_tree_sha"] = json!(tree_sha);
    let mismatch = if identity.blob_sha() != Some(blob_sha) {
        Some("blob_identity_mismatch")
    } else if response.body.len() as u64 != size {
        Some("blob_size_mismatch")
    } else {
        None
    };
    if let Some(mismatch) = mismatch {
        output["result"] = json!("degraded");
        output["fallback_reason"] = json!(mismatch);
        output["raw_evidence"] = withheld_evidence(response, mismatch);
        return Ok(output);
    }
    // The body proved the immutable object identity; only now may the output
    // claim the Git blob SHA was verified.
    output["retrieval"]["verified_git_blob_sha"] = json!(blob_sha);
    match observed.as_deref() {
        Some(value) if learning::raw_content_type_allowed(value) => {
            output["result"] = json!("raw_snapshot");
            output["bytes"] = json!(STANDARD.encode(&response.body));
            output["byte_length"] = json!(response.body.len());
            output["sha256"] = json!(learning::sha256_hex(&response.body));
            output["content_type"] = json!(value);
            Ok(output)
        }
        _ => {
            let reason = if observed.is_some() {
                "unexpected_content"
            } else {
                "missing_content_type"
            };
            output["result"] = json!("degraded");
            output["fallback_reason"] = json!(reason);
            output["raw_evidence"] = learning::degraded_evidence(response, identity, reason)?;
            Ok(output)
        }
    }
}

/// The evidence of a response whose bytes are withheld. The original bytes
/// are not encoded here: they never matched an admitted object's pinned
/// identity, so they never passed the per-item rights admission and are
/// never disclosed.
fn withheld_evidence(response: &crate::net::Response, reason: &str) -> Value {
    json!({
        "kind": "withheld_response",
        "content_type": learning::content_type(response),
        "byte_length": response.body.len(),
        "sha256": learning::sha256_hex(&response.body),
        "encoding": "base64",
        "data": Value::Null,
        "fallback_reason": reason,
    })
}

/// One JSON value decoded with no repeated object member at any depth.
/// `serde_json::from_str::<Value>` collapses a repeated member last-key-wins,
/// which would let a contradicting `rights_reviewed`, question-set or session
/// field collapse into the attested value the last member wrote. This adapter
/// surfaces every duplicate — nested and escape-spelled ones alike, since
/// keys arrive already unescaped — as malformed input before the `Value` is
/// used.
struct StrictJson(Value);

impl<'de> serde::Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AnyVisitor;
        impl<'de> serde::de::Visitor<'de> for AnyVisitor {
            type Value = StrictJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON value without repeated object members")
            }

            fn visit_bool<E>(self, value: bool) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::from(value)))
            }

            fn visit_u64<E>(self, value: u64) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::from(value)))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<StrictJson, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| StrictJson(Value::Number(number)))
                    .ok_or_else(|| serde::de::Error::custom("a non-finite number is not JSON"))
            }

            fn visit_str<E>(self, value: &str) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::String(value.to_owned())))
            }

            fn visit_none<E>(self) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Null))
            }

            fn visit_some<D2: serde::Deserializer<'de>>(
                self,
                deserializer: D2,
            ) -> Result<StrictJson, D2::Error> {
                StrictJson::deserialize(deserializer)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<StrictJson, A::Error> {
                let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(item) = seq.next_element::<StrictJson>()? {
                    items.push(item.0);
                }
                Ok(StrictJson(Value::Array(items)))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<StrictJson, A::Error> {
                let mut object = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    match object.entry(key) {
                        serde_json::map::Entry::Vacant(entry) => {
                            entry.insert(map.next_value::<StrictJson>()?.0);
                        }
                        serde_json::map::Entry::Occupied(_) => {
                            return Err(serde::de::Error::custom(
                                "the request repeats an object member",
                            ));
                        }
                    }
                }
                Ok(StrictJson(Value::Object(object)))
            }
        }
        deserializer.deserialize_any(AnyVisitor)
    }
}

/// Local 航空航天概论 practice. The session never carries an official grade,
/// a completion claim or a submission.
pub fn practice(input: &str) -> Result<Value, Error> {
    if input.len() > learning::MAX_PRACTICE_INPUT {
        return Err(learning::invalid_input("the practice request is too large"));
    }
    // The strict decoder keeps repeated members visible instead of letting
    // them collapse into a last-key-wins `Value`; a trailing document is
    // refused before the object is used at all.
    let mut decoder = serde_json::Deserializer::from_str(input);
    let StrictJson(value) = StrictJson::deserialize(&mut decoder)
        .map_err(|_| learning::invalid_input("the practice request is malformed"))?;
    decoder
        .end()
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
    let session: learning::PracticeSession = serde_json::from_value(session.clone())
        .map_err(|_| learning::invalid_input("the practice session is malformed"))?;
    validate_practice_attestation(&session)?;
    Ok(session)
}

/// The session contract publishes the rights attestation twice: on the
/// session itself and inside the practice source. Both must be present
/// booleans at their own depth and must agree, so a short (missing)
/// attestation, a contradicting duplicate one or an unexpected nested member
/// is refused before the session is used. Once unescaped, a repeated object
/// member at any depth never reaches this check: the strict decoder already
/// refused the request.
fn validate_practice_attestation(session: &learning::PracticeSession) -> Result<(), Error> {
    let source = session.practice_source.as_object().ok_or_else(|| {
        learning::invalid_input("the practice source is not an attestation object")
    })?;
    if source.len() != PRACTICE_SOURCE_KEYS.len()
        || !PRACTICE_SOURCE_KEYS
            .iter()
            .all(|key| source.contains_key(*key))
    {
        return Err(learning::invalid_input(
            "the practice source is not a complete attestation object",
        ));
    }
    match source.get("rights_reviewed") {
        Some(Value::Bool(attested)) if *attested == session.rights_reviewed => {}
        _ => {
            return Err(learning::invalid_input(
                "the practice session does not carry one consistent rights attestation",
            ));
        }
    }
    for key in ["kind", "origin"] {
        match source.get(key).and_then(Value::as_str) {
            Some(value) if !value.is_empty() => {}
            _ => {
                return Err(learning::invalid_input(
                    "the practice source attestation is incomplete",
                ));
            }
        }
    }
    if !source
        .get("digest")
        .and_then(Value::as_str)
        .is_some_and(learning::valid_sha256)
        || !source.get("scan").is_some_and(Value::is_null)
    {
        return Err(learning::invalid_input(
            "the practice source attestation is incomplete",
        ));
    }
    Ok(())
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
                return Err(learning::invalid_input(
                    "the material text is empty or too large",
                ));
            }
            let count = object.get("count").and_then(Value::as_u64).ok_or_else(|| {
                learning::invalid_input("the cloze mode requires a question count")
            })?;
            if count == 0 || count > learning::MAX_QUESTIONS as u64 {
                return Err(learning::invalid_input(
                    "the question count is out of range",
                ));
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
            let question_set = object.get("question_set").ok_or_else(|| {
                learning::invalid_input("the question set mode requires question_set")
            })?;
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
        _ => {
            return Err(learning::invalid_input(
                "the practice generation mode is unknown",
            ));
        }
    };
    let mut questions = questions;
    learning::apply_operator_key(&mut questions, object.get("local_answer_key"))?;
    let session = learning::new_session(
        PRACTICE_TYPE_LABEL,
        practice_source,
        questions,
        rights_reviewed,
    )?;
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
            return Err(learning::invalid_input(
                "a question identifier must be positive",
            ));
        }
        if let Some(chapter) = parsed.chapter {
            if chapter <= 0 {
                return Err(learning::invalid_input(
                    "a question chapter must be positive",
                ));
            }
        }
        if parsed.question.trim().is_empty() || parsed.question.len() > learning::MAX_QUESTION_BYTES
        {
            return Err(learning::invalid_input(
                "a question stem is empty or too long",
            ));
        }
        if parsed.options.len() < 2 || parsed.options.len() > learning::MAX_OPTIONS {
            return Err(learning::invalid_input(
                "a question must carry between 2 and 8 options",
            ));
        }
        for option in &parsed.options {
            if option.trim().is_empty() || option.len() > learning::MAX_OPTION_BYTES {
                return Err(learning::invalid_input(
                    "a question option is empty or too long",
                ));
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

/// One published inventory entry with its per-item rights verdict.
fn entry_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["title","source","source_url","branch","path","url","size","kind","mode","material_class","admission","admission_reason","license_evidence","mirror_allowed","retrieval_allowed","rights_review_required","rights_reviewed","license","attribution","upstream_sha"],
        "properties":{
            "title":{"type":"string","minLength":1,"maxLength":learning::MAX_TITLE_BYTES},
            "source":{"type":"string","minLength":1},
            "source_url":{"type":"string","minLength":1},
            "branch":{"type":"string","minLength":1},
            "path":{"type":"string","minLength":1,"maxLength":learning::MAX_PATH},
            "url":{"type":["string","null"],"description":"The immutable blob object URL of an admitted entry; null for every entry this client cannot retrieve."},
            "size":{"type":["integer","null"],"minimum":0},
            "kind":{"enum":["file","directory","symlink","submodule","other"]},
            "mode":{"enum":["100644","100755","040000","120000","160000"],"description":"The exact source Git mode, required with the tree and blob identities when selecting a file for retrieval."},
            "material_class":{"enum":["documentation","license","answer_material","assessment_content","excluded"]},
            "admission":{"enum":["admitted","excluded"],"description":"The exhaustive per-item rights decision: every reviewed entry is either admitted or excluded, never unstated."},
            "admission_reason":{"type":"string","minLength":1,"description":"The reviewed retention basis of an admitted entry, or the exclusion reason of an excluded one."},
            "license_evidence": {"oneOf":[{"type":"null"},entry_license_evidence_schema()],"description":"The reviewed license evidence of an admitted entry; always null for an excluded entry."},
            "mirror_allowed":{"type":"boolean","description":"True only for the two reviewed admitted objects; this module implements no bulk mirror operation at all."},
            "retrieval_allowed":{"type":"boolean","description":"True only for the two reviewed admitted objects; every excluded or answer-bearing item is refused before any byte request."},
            "rights_review_required":{"const":true},
            "rights_reviewed":{"const":false},
            "license":learning::license_schema(),
            "attribution":{"type":"string","minLength":1},
            "upstream_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"}
        },
        "allOf":[
            {"if":{"properties":{"admission":{"const":"admitted"}},"required":["admission"]},
             "then":{"required":["admission","admission_reason","license_evidence"],
                     "properties":{
                         "kind":{"const":"file"},
                         "material_class":{"enum":["documentation","license"]},
                         "admission_reason":{"type":"string","minLength":1},
                         "license_evidence":{"type":"object"},
                         "url":{"type":"string","minLength":1},
                         "mirror_allowed":{"const":true},
                         "retrieval_allowed":{"const":true}
                     }}},
            {"if":{"properties":{"admission":{"const":"excluded"}},"required":["admission"]},
             "then":{"required":["admission","admission_reason","license_evidence"],
                     "properties":{
                         "material_class":{"enum":["answer_material","assessment_content","excluded"]},
                         "admission_reason":{"type":"string","minLength":1},
                         "license_evidence":{"type":"null"},
                         "url":{"type":"null"},
                         "mirror_allowed":{"const":false},
                         "retrieval_allowed":{"const":false}
                     }}}
        ]
    })
}

/// The reviewed license evidence of one admitted entry: the exact license
/// object of the pinned tree and the basis on which the admitted object is
/// covered by it. It is an operator review, not an independent rights proof.
fn entry_license_evidence_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["basis","spdx_id","name","license_blob_sha","license_size","independently_verified"],
        "properties":{
            "basis":{"type":"string","minLength":1,"description":"The reviewed basis on which this admitted object is covered by the license object."},
            "spdx_id":{"const":REVIEWED_LICENSE_SPDX},
            "name":{"const":REVIEWED_LICENSE_NAME},
            "license_blob_sha":{"const":REVIEWED_LICENSE_BLOB},
            "license_size":{"const":REVIEWED_LICENSE_SIZE},
            "independently_verified":{"const":false,"description":"Always false: the evidence is an operator review of the license object, not an independent rights or compliance proof."}
        }
    })
}

/// The revision object published on every output: the reviewed commit and
/// the reviewed root tree it declares.
fn revision_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,"required":["commit","tree"],
        "properties":{
            "commit":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
            "tree":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"}
        }
    })
}

/// The fallback reasons a degraded inventory, search or byte output can
/// carry.
fn fallback_reasons() -> Value {
    json!([
        "unexpected_content",
        "missing_content_type",
        "upstream_parse",
        "incomplete_tree",
        "commit_tree_unresolved",
        "tree_identity_mismatch",
        "blob_identity_mismatch",
        "blob_size_mismatch",
        null
    ])
}

/// The evidence of a response whose bytes are withheld: the length, the
/// digest and the reason, never the original bytes.
fn withheld_evidence_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["kind","content_type","byte_length","sha256","encoding","data","fallback_reason"],
        "properties":{
            "kind":{"const":"withheld_response"},
            "content_type":{"type":["string","null"]},
            "byte_length":{"type":"integer","minimum":0},
            "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "encoding":{"const":"base64"},
            "data":{"type":"null","description":"Always null: withheld bytes are never encoded into the output."},
            "fallback_reason":{"type":"string","minLength":1}
        }
    })
}

/// The output contract of the pinned-revision material inventory.
fn inventory_output_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["schema_version","type","result","source","source_url","branch","revision","license","attribution","rights_reviewed","tree_sha","truncated","complete","next_cursor","entries","entry_count","admitted_count","excluded_count","fallback_reason","raw_evidence","retrieval"],
        "properties":{
            "schema_version":{"const":1},
            "type":{"const":TYPE_LABEL},
            "result":{"enum":["inventory_snapshot","degraded"]},
            "source":{"type":"string","minLength":1},
            "source_url":{"type":"string","minLength":1},
            "branch":{"type":"string","minLength":1},
            "revision":revision_schema(),
            "license":learning::license_schema(),
            "attribution":{"type":"string","minLength":1},
            "rights_reviewed":{"const":false},
            "tree_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"The verified root tree object identity of the pinned revision; null only in the degraded variant."},
            "truncated":{"type":["boolean","null"]},
            "complete":{"type":"boolean"},
            "next_cursor":{"type":"null","description":"The recursive tree response supplies no continuation cursor; a truncated tree is refused rather than reported as a partial inventory."},
            "entries":{"type":"array","maxItems":learning::MAX_ENTRIES,"items":entry_schema()},
            "entry_count":{"type":"integer","minimum":0,"maximum":learning::MAX_ENTRIES},
            "admitted_count":{"type":"integer","minimum":0,"maximum":learning::MAX_ENTRIES},
            "excluded_count":{"type":"integer","minimum":0,"maximum":learning::MAX_ENTRIES},
            "fallback_reason":{"type":["string","null"],"enum":fallback_reasons()},
            "raw_evidence":{"oneOf":[{"type":"null"},learning::evidence_schema()]},
            "retrieval":learning::retrieval_schema()
        },
        "oneOf":[
            {"properties":{
                "result":{"const":"inventory_snapshot"},
                "fallback_reason":{"type":"null"},
                "raw_evidence":{"type":"null"},
                "tree_sha":{"type":"string"},
                "truncated":{"type":"boolean"},
                "entries":{"type":"array"}
            }},
            {"properties":{
                "result":{"const":"degraded"},
                "fallback_reason":{"type":"string"},
                "raw_evidence":{"type":"object"},
                "tree_sha":{"type":"null"},
                "truncated":{"type":"null"},
                "entries":{"type":"array","maxItems":0}
            }}
        ]
    })
}

/// The output contract of a query over the pinned-revision inventory.
fn search_output_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["schema_version","type","result","query","rights_reviewed","source","source_url","branch","revision","license","attribution","tree_sha","truncated","complete","next_cursor","matches","match_count","fallback_reason","raw_evidence","retrieval"],
        "properties":{
            "schema_version":{"const":1},
            "type":{"const":SEARCH_TYPE_LABEL},
            "result":{"enum":["search_snapshot","degraded"]},
            "query":{"type":"string","minLength":1,"maxLength":learning::MAX_QUERY_BYTES},
            "rights_reviewed":{"const":true},
            "source":{"type":"string","minLength":1},
            "source_url":{"type":"string","minLength":1},
            "branch":{"type":"string","minLength":1},
            "revision":revision_schema(),
            "license":learning::license_schema(),
            "attribution":{"type":"string","minLength":1},
            "tree_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
            "truncated":{"type":["boolean","null"]},
            "complete":{"type":"boolean"},
            "next_cursor":{"type":"null"},
            "matches":{"type":"array","maxItems":learning::MAX_ENTRIES,"items":entry_schema()},
            "match_count":{"type":"integer","minimum":0,"maximum":learning::MAX_ENTRIES},
            "fallback_reason":{"type":["string","null"],"enum":fallback_reasons()},
            "raw_evidence":{"oneOf":[{"type":"null"},learning::evidence_schema()]},
            "retrieval":learning::retrieval_schema()
        },
        "oneOf":[
            {"properties":{
                "result":{"const":"search_snapshot"},
                "fallback_reason":{"type":"null"},
                "raw_evidence":{"type":"null"},
                "tree_sha":{"type":"string"},
                "truncated":{"type":"boolean"},
                "matches":{"type":"array"}
            }},
            {"properties":{
                "result":{"const":"degraded"},
                "fallback_reason":{"type":"string"},
                "raw_evidence":{"type":"object"},
                "tree_sha":{"type":"null"},
                "truncated":{"type":"null"},
                "matches":{"type":"array","maxItems":0}
            }}
        ]
    })
}

/// The output contract of one admitted byte request. A response that is
/// not the reviewed object withholds its bytes as evidence.
fn bytes_output_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["schema_version","type","result","path","source","source_url","branch","revision","tree_sha","upstream_sha","size","license","attribution","rights_reviewed","material_class","admission_reason","license_notice_required","bytes","byte_encoding","byte_length","sha256","content_type","fallback_reason","raw_evidence","retrieval"],
        "properties":{
            "schema_version":{"const":1},
            "type":{"const":RAW_TYPE_LABEL},
            "result":{"enum":["raw_snapshot","degraded"]},
            "path":{"type":"string","minLength":1,"maxLength":learning::MAX_PATH},
            "source":{"type":"string","minLength":1},
            "source_url":{"type":"string","minLength":1},
            "branch":{"type":"string","minLength":1},
            "revision":revision_schema(),
            "tree_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
            "upstream_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
            "size":{"type":["integer","null"],"minimum":0},
            "license":learning::license_schema(),
            "attribution":{"type":"string","minLength":1},
            "rights_reviewed":{"const":true},
            "material_class":{"type":["string","null"],"enum":["documentation","license","answer_material","assessment_content","excluded",null]},
            "admission_reason":{"type":["string","null"],"minLength":1},
            "license_notice_required":{"const":true,"description":"Always true: the verbatim LICENSE notice is a separate retrieval and the metadata does not attest redistribution compliance."},
            "bytes":{"type":["string","null"],"contentEncoding":"base64"},
            "byte_encoding":{"const":"base64"},
            "byte_length":{"type":["integer","null"],"minimum":0},
            "sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"},
            "content_type":{"type":["string","null"],"description":"Null in the degraded variant; the observed value is inside raw_evidence.content_type."},
            "fallback_reason":{"type":["string","null"],"enum":fallback_reasons()},
            "raw_evidence":{"oneOf":[{"type":"null"},learning::evidence_schema(),withheld_evidence_schema()]},
            "retrieval":learning::retrieval_schema()
        },
        "oneOf":[
            {"properties":{
                "result":{"const":"raw_snapshot"},
                "material_class":{"type":"string"},
                "admission_reason":{"type":"string"},
                "bytes":{"type":"string"},
                "byte_length":{"type":"integer"},
                "sha256":{"type":"string"},
                "content_type":{"type":"string"},
                "fallback_reason":{"type":"null"},
                "raw_evidence":{"type":"null"}
            }},
            {"properties":{
                "result":{"const":"degraded"},
                "bytes":{"type":"null"},
                "byte_length":{"type":"null"},
                "sha256":{"type":"null"},
                "content_type":{"type":"null"},
                "fallback_reason":{"type":"string"},
                "raw_evidence":{"type":"object"}
            }}
        ],
        "allOf":[
            {"if":{"properties":{"result":{"const":"raw_snapshot"}},"required":["result"]},
             "then":{"properties":{"retrieval":{"type":"object","required":["verified_git_blob_sha"],
                 "properties":{"verified_git_blob_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"}}}}}},
            {"if":{"properties":{"raw_evidence":{"type":"object","required":["kind"],
                    "properties":{"kind":{"const":"withheld_response"}}}},
                  "required":["raw_evidence"]},
             "then":{"properties":{"retrieval":{"type":"object","not":{"required":["verified_git_blob_sha"]}}}}}
        ]
    })
}

/// Machine-readable stdin/output contracts for CLI integration.
pub fn schema() -> Value {
    let mut schema = json!({
        "materials": {
            "input":{
                "type":"object","additionalProperties":false,"properties":{},"required":[],
                "description":"The reviewed source, revision and license are pinned; this request accepts no parameter. An empty input is accepted as this empty object."
            },
            "options":{"--online":"Permit cache-first pinned-commit resolution and its immutable recursive-tree request; no automatic retry, refresh or pagination."},
            "output":inventory_output_schema()
        },
        "search": {
            "input":{
                "type":"object","additionalProperties":false,"required":["query","rights_reviewed"],
                "properties":{
                    "query":{"type":"string","minLength":1,"maxLength":learning::MAX_QUERY_BYTES,"description":"A case-insensitive substring matched against the path and the title of each reviewed entry."},
                    "rights_reviewed":{"const":true,"description":"Required operator attestation. False or omitted fails before cache or network admission."}
                }
            },
            "options":{"--online":"Permit cache-first pinned-commit resolution and its immutable recursive-tree request; no automatic retry or refresh."},
            "output":search_output_schema()
        },
        "fetch": {
            "input":{
                "type":"object","additionalProperties":false,"required":["path","rights_reviewed","tree_sha","blob_sha","mode","size"],
                "properties":{
                    "path":{"type":"string","minLength":1,"maxLength":learning::MAX_PATH,"description":"An explicit normalized repository-relative path that is present in the reviewed inventory."},
                    "rights_reviewed":{"const":true,"description":"Required operator attestation. False or omitted fails before cache or network admission."},
                    "tree_sha":{"const":REVISION.tree,"description":"The reviewed root tree object of the pinned revision. It is compared with the verified admitted tree before any byte request."},
                    "blob_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"The immutable blob object the operator reviewed. It is compared with the admitted inventory entry before any byte request."},
                    "mode":{"enum":["100644","100755"],"description":"The reviewed entry mode. Only a regular file can be retrieved."},
                    "size":{"type":"integer","minimum":0,"description":"The reviewed byte length. The retrieved blob must have exactly this length."}
                }
            },
            "options":{"--online":"Permit cache-first pinned commit/tree resolution and the reviewed immutable blob request; no automatic retry or redirect."},
            "output":bytes_output_schema()
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
    });
    schema["practice"]["input"]["description"] = json!(
        "A local-only practice request. The input is decoded strictly: a repeated object member at any depth or a second JSON document is refused before use. A submitted session is admitted only when its rights attestation is a boolean at both published depths — the session and its practice source — and both values agree; an omitted or contradicting attestation is refused rather than defaulted."
    );
    schema
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

    /// The root tree object of the fixture, produced by Git-object
    /// reconstruction over the listed entries.
    const FIXTURE_TREE: &str = "d279577368575a8a150c60c46907170251063005";

    /// A fixture in the reviewed tree's shape: the two admitted objects,
    /// the answer bank together with a fixture-only alias of its object
    /// (`backup.db`) and a fixture-only alias of the reviewed readme object
    /// (`DB/README.md`), a course question image plus its byte-identical
    /// asset-catalog copy, the four font binaries, an app icon, two
    /// screenshots, sources and project metadata. Every blob identity is
    /// the reviewed tree's real object; only `backup.db` and
    /// `DB/README.md` are invented paths. Every directory object and the
    /// root really cover their listed children, as a recursive GitHub tree
    /// response does.
    const TREE: &[u8] = br#"{"sha":"d279577368575a8a150c60c46907170251063005","url":"https://api.github.com/ignored","truncated":false,"tree":[
        {"path":"HangGai","mode":"040000","type":"tree","sha":"7e40c9096d845c677396f6f39632b1575964ff8f"},
        {"path":"HangGai/Assets","mode":"040000","type":"tree","sha":"57dbe9ad6ec422eb9d8f4c99c73081a685d41fe8"},
        {"path":"HangGai/Assets/DB","mode":"040000","type":"tree","sha":"482bf0ffcac40ecf251d1771fb71ab3a0d65297c"},
        {"path":"HangGai/Assets/DB/README.md","mode":"100644","type":"blob","sha":"0b4aaae22b098e2d00e603fb7ce39b95fd13905f","size":228},
        {"path":"HangGai/Assets/DB/backup.db","mode":"100644","type":"blob","sha":"ef1a7ff882139fbbde6264916ca958f0717a1bd0","size":352256},
        {"path":"HangGai/Assets/DB/questions.db","mode":"100644","type":"blob","sha":"ef1a7ff882139fbbde6264916ca958f0717a1bd0","size":352256},
        {"path":"HangGai/Assets/Fonts","mode":"040000","type":"tree","sha":"23d049f1a81e9ed493d67ed3c80c1455bdd62af8"},
        {"path":"HangGai/Assets/Fonts/FZSSJW.TTF","mode":"100644","type":"blob","sha":"982620401b87e2ab64fa1d60206ac770c4455d0d","size":3081292},
        {"path":"HangGai/Assets/Fonts/SmartFontUI.ttf","mode":"100644","type":"blob","sha":"8b07ac50948c5e474b3dd5b7fecc90a1bd406f75","size":5821864},
        {"path":"HangGai/Assets/Fonts/SourceHanSerifCN-Medium.ttf","mode":"100644","type":"blob","sha":"0215525ccb3a5afa549f7b9e07aafd9b2fffb3d9","size":14512860},
        {"path":"HangGai/Assets/Fonts/SourceHanSerifCN-Regular.ttf","mode":"100644","type":"blob","sha":"a03bed0c97e1817dedc976fb0b84fb257576ca07","size":14495132},
        {"path":"HangGai/Assets/QuestionImgs","mode":"040000","type":"tree","sha":"bf6396bed2c87304e9f57cb66794d707a741beab"},
        {"path":"HangGai/Assets/QuestionImgs/1001h.png","mode":"100644","type":"blob","sha":"ee42328c3df28b771bc5a8ad8796435427fe8a56","size":15285},
        {"path":"HangGai/Assets.xcassets","mode":"040000","type":"tree","sha":"63e9ba9408af792304f0c87bfd0bccbea46d3dbf"},
        {"path":"HangGai/Assets.xcassets/AppIcon.appiconset","mode":"040000","type":"tree","sha":"6fdff7c3211944ef8a5735e22d17f02a10d5b42c"},
        {"path":"HangGai/Assets.xcassets/AppIcon.appiconset/Contents.json","mode":"100644","type":"blob","sha":"28d9cc7aae2e009479bbbc8be5a4654384dba5fd","size":3148},
        {"path":"HangGai/Assets.xcassets/QuestionImages","mode":"040000","type":"tree","sha":"a62ab1920d05d474595a0056d655405b3616a18e"},
        {"path":"HangGai/Assets.xcassets/QuestionImages/1001h.imageset","mode":"040000","type":"tree","sha":"f6f0f0110e30e111259427f3148fea920e8f1c12"},
        {"path":"HangGai/Assets.xcassets/QuestionImages/1001h.imageset/1001h.png","mode":"100644","type":"blob","sha":"ee42328c3df28b771bc5a8ad8796435427fe8a56","size":15285},
        {"path":"HangGai/Assets.xcassets/QuestionImages/1001h.imageset/Contents.json","mode":"100644","type":"blob","sha":"b868580233423655ad6ebab2492389671a2a1713","size":303},
        {"path":"HangGai/Info.plist","mode":"100644","type":"blob","sha":"5c89eb5dac0d9c00034ba3c9a3e383edda4de2a2","size":1843},
        {"path":"HangGai/Models","mode":"040000","type":"tree","sha":"f1c66e078bf8435b46005524027d7c1ed10e1f79"},
        {"path":"HangGai/Models/QuestionModel.swift","mode":"100644","type":"blob","sha":"08096365b206d0c3666534b3553aa897cb3a708f","size":865},
        {"path":"HangGai/Utilities","mode":"040000","type":"tree","sha":"e7e516e19c14d705a98090862f577c30dde53643"},
        {"path":"HangGai/Utilities/QuestionLoader.swift","mode":"100644","type":"blob","sha":"a0b66183a52c22714709807424f91a900190b3ab","size":3660},
        {"path":"HangGai.xcodeproj","mode":"040000","type":"tree","sha":"8ff375aeade54d0c28412db963b2df9d35a459a1"},
        {"path":"HangGai.xcodeproj/project.pbxproj","mode":"100644","type":"blob","sha":"08cc394bb2bdbb3ac2c051b072530bf8ab428dfa","size":28876},
        {"path":"LICENSE","mode":"100644","type":"blob","sha":"f288702d2fa16d3cdf0035b15a9fcbc552cd88e7","size":35149},
        {"path":"README.md","mode":"100644","type":"blob","sha":"0b4aaae22b098e2d00e603fb7ce39b95fd13905f","size":228},
        {"path":"img","mode":"040000","type":"tree","sha":"39dd9cebb07767aeae5e65a550b8858528308c8d"},
        {"path":"img/dark.png","mode":"100644","type":"blob","sha":"1f60e318738aa678a2d8c5a9dca25cc243543aa4","size":96388},
        {"path":"img/light.png","mode":"100644","type":"blob","sha":"a29372c419c112f9fb184e48ca5746a42529f05a","size":68091}
    ]}"#;

    fn fixture_url() -> url::Url {
        url::Url::parse(&format!(
            "https://api.github.com/repos/Caniformia/HangGai/git/trees/{FIXTURE_TREE}?recursive=1"
        ))
        .unwrap()
    }

    /// The admitted fixture tree and the response it came from.
    fn admitted() -> (String, Vec<learning::TreeEntry>, Response) {
        let url = fixture_url();
        let response = response(&url, TREE, "application/json");
        let identity = learning::observed_identity(
            learning::Surface::Tree,
            &url,
            &response.body,
            Some("application/json"),
        );
        let tree = identity.tree().expect("the fixture tree verifies");
        (tree.tree_sha.clone(), tree.entries.clone(), response)
    }

    /// A retrieval request for one reviewed entry of the fixture.
    fn request(path: &str, blob_sha: &str, size: u64) -> FetchInput {
        FetchInput {
            path: path.to_owned(),
            rights_reviewed: Some(true),
            tree_sha: Some(REVISION.tree.to_owned()),
            blob_sha: Some(blob_sha.to_owned()),
            mode: Some("100644".to_owned()),
            size: Some(size),
        }
    }

    /// One regular-file entry with the given identity, or a directory entry
    /// when the object declares no size.
    fn tree_entry(path: &str, sha: &str, size: Option<u64>) -> learning::TreeEntry {
        let (mode, object_type) = if size.is_some() {
            ("100644", "blob")
        } else {
            ("040000", "tree")
        };
        learning::TreeEntry {
            path: path.to_owned(),
            mode: mode.to_owned(),
            object_type: object_type.to_owned(),
            sha: sha.to_owned(),
            size,
        }
    }

    /// One symbolic-link entry whose target bytes have the given identity.
    fn symlink_entry(path: &str, sha: &str, size: u64) -> learning::TreeEntry {
        learning::TreeEntry {
            mode: "120000".to_owned(),
            ..tree_entry(path, sha, Some(size))
        }
    }

    #[test]
    fn only_the_reviewed_readme_and_license_are_admitted() {
        let (tree_sha, entries, response) = admitted();
        let url = fixture_url();
        let output = materials_output(&url, &response, &identity_of(&response)).unwrap();
        assert_eq!(output["result"], json!("inventory_snapshot"));
        assert_eq!(output["tree_sha"], json!(tree_sha));
        assert_eq!(output["entry_count"], json!(entries.len()));
        assert_eq!(output["admitted_count"], json!(2));
        assert_eq!(output["excluded_count"], json!(entries.len() - 2));
        assert_eq!(output["revision"]["commit"], json!(REVISION.commit));
        assert_eq!(output["revision"]["tree"], json!(REVISION.tree));
        assert_eq!(
            output["license"]["operator_reference"]["spdx_id"],
            json!(REVIEWED_LICENSE_SPDX)
        );
        assert_eq!(
            output["license"]["bound_license_blob_sha"],
            json!(REVIEWED_LICENSE_BLOB)
        );
        assert_eq!(output["license"]["independently_verified"], false);
        let values = output["entries"].as_array().unwrap();
        let find = |path: &str| {
            values
                .iter()
                .find(|value| value["path"] == json!(path))
                .unwrap()
                .clone()
        };
        let readme = find("README.md");
        assert_eq!(readme["material_class"], json!("documentation"));
        assert_eq!(readme["admission"], json!("admitted"));
        assert_eq!(readme["retrieval_allowed"], json!(true));
        assert_eq!(readme["mirror_allowed"], json!(true));
        assert_eq!(
            readme["admission_reason"],
            json!("author_written_description_covered_by_the_repository_license")
        );
        assert_eq!(
            readme["license_evidence"],
            json!({
                "basis": "author_written_description_covered_by_the_repository_license",
                "spdx_id": REVIEWED_LICENSE_SPDX,
                "name": REVIEWED_LICENSE_NAME,
                "license_blob_sha": REVIEWED_LICENSE_BLOB,
                "license_size": REVIEWED_LICENSE_SIZE,
                "independently_verified": false
            })
        );
        assert!(readme["url"].is_string());
        let license = find("LICENSE");
        assert_eq!(license["material_class"], json!("license"));
        assert_eq!(license["admission"], json!("admitted"));
        assert_eq!(license["retrieval_allowed"], json!(true));
        assert_eq!(
            license["license_evidence"]["basis"],
            json!("verbatim_license_notice_of_the_reviewed_work")
        );
        assert_eq!(
            license["license_evidence"]["license_blob_sha"],
            json!(REVIEWED_LICENSE_BLOB)
        );
        assert_eq!(
            license["license_evidence"]["license_size"],
            json!(REVIEWED_LICENSE_SIZE)
        );
        // The answer bank and its alias are answer material.
        for path in [ANSWER_BANK_PATH, "HangGai/Assets/DB/backup.db"] {
            let entry = find(path);
            assert_eq!(entry["material_class"], json!("answer_material"), "{path}");
            assert_eq!(entry["admission"], json!("excluded"), "{path}");
            assert_eq!(entry["license_evidence"], Value::Null, "{path}");
            assert_eq!(entry["retrieval_allowed"], json!(false));
            assert_eq!(entry["mirror_allowed"], json!(false));
            assert_eq!(entry["url"], Value::Null);
        }
        // The same blob as the reviewed readme under another path stays
        // excluded: an alias of an admitted object is never admitted.
        let aliased_readme = find("HangGai/Assets/DB/README.md");
        assert_eq!(aliased_readme["material_class"], json!("excluded"));
        assert_eq!(aliased_readme["admission"], json!("excluded"));
        assert_eq!(aliased_readme["retrieval_allowed"], json!(false));
        // The course question images are assessment content.
        for path in [
            "HangGai/Assets/QuestionImgs/1001h.png",
            "HangGai/Assets.xcassets/QuestionImages/1001h.imageset/1001h.png",
        ] {
            let entry = find(path);
            assert_eq!(
                entry["material_class"],
                json!("assessment_content"),
                "{path}"
            );
            assert_eq!(entry["retrieval_allowed"], json!(false));
            assert_eq!(entry["mirror_allowed"], json!(false));
        }
        // Fonts, sources, metadata, catalog indices and artwork are excluded.
        for path in [
            "HangGai/Assets/Fonts/FZSSJW.TTF",
            "HangGai/Assets/Fonts/SmartFontUI.ttf",
            "HangGai/Assets/Fonts/SourceHanSerifCN-Medium.ttf",
            "HangGai/Assets/Fonts/SourceHanSerifCN-Regular.ttf",
            "HangGai/Models/QuestionModel.swift",
            "HangGai/Utilities/QuestionLoader.swift",
            "HangGai/Info.plist",
            "HangGai.xcodeproj/project.pbxproj",
            "HangGai/Assets.xcassets/AppIcon.appiconset/Contents.json",
            "HangGai/Assets.xcassets/QuestionImages/1001h.imageset/Contents.json",
            "img/dark.png",
            "img/light.png",
        ] {
            let entry = find(path);
            assert_eq!(entry["material_class"], json!("excluded"), "{path}");
            assert_eq!(entry["retrieval_allowed"], json!(false));
            assert_eq!(entry["mirror_allowed"], json!(false));
            assert_eq!(entry["url"], Value::Null);
        }
        // A directory is never advertised as retrievable.
        let directory = find("HangGai");
        assert_eq!(directory["kind"], json!("directory"));
        assert_eq!(directory["admission"], json!("excluded"));
        assert_eq!(
            directory["admission_reason"],
            json!("repository_metadata_or_unreviewed_item")
        );
        assert_eq!(directory["license_evidence"], Value::Null);
        assert_eq!(directory["retrieval_allowed"], json!(false));
        assert_eq!(directory["url"], Value::Null);

        // Every entry carries exactly one verdict, and the verdict decides
        // every derivative field: no entry is admitted silently and no
        // excluded entry keeps an admission artifact.
        let mut admitted_count = 0usize;
        for value in values {
            let admission = value["admission"]
                .as_str()
                .unwrap_or_else(|| panic!("every entry carries an admission verdict: {value}"));
            assert!(
                !value["admission_reason"]
                    .as_str()
                    .unwrap_or_default()
                    .is_empty(),
                "every verdict carries a reason: {value}"
            );
            match admission {
                "admitted" => {
                    admitted_count += 1;
                    assert_eq!(value["kind"], json!("file"), "{value}");
                    assert!(
                        matches!(
                            value["material_class"].as_str(),
                            Some("documentation" | "license")
                        ),
                        "{value}"
                    );
                    assert_eq!(value["retrieval_allowed"], json!(true), "{value}");
                    assert_eq!(value["mirror_allowed"], json!(true), "{value}");
                    assert!(value["url"].is_string(), "{value}");
                    assert_eq!(
                        value["license_evidence"]["basis"],
                        value["admission_reason"]
                    );
                    assert_eq!(
                        value["license_evidence"]["license_blob_sha"],
                        json!(REVIEWED_LICENSE_BLOB),
                        "{value}"
                    );
                    assert_eq!(
                        value["license_evidence"]["independently_verified"],
                        json!(false),
                        "{value}"
                    );
                }
                "excluded" => {
                    assert!(
                        !matches!(
                            value["material_class"].as_str(),
                            Some("documentation" | "license")
                        ),
                        "{value}"
                    );
                    assert_eq!(value["retrieval_allowed"], json!(false), "{value}");
                    assert_eq!(value["mirror_allowed"], json!(false), "{value}");
                    assert_eq!(value["url"], Value::Null, "{value}");
                    assert_eq!(value["license_evidence"], Value::Null, "{value}");
                }
                other => panic!("an unknown admission verdict {other}"),
            }
        }
        assert_eq!(admitted_count, 2);
        assert_eq!(output["admitted_count"], json!(admitted_count));
        assert_eq!(
            output["excluded_count"],
            json!(values.len() - admitted_count)
        );
    }

    fn identity_of(response: &Response) -> learning::ObservedIdentity {
        let url = url::Url::parse(&response.url).unwrap();
        learning::observed_identity(
            learning::Surface::Tree,
            &url,
            &response.body,
            Some("application/json"),
        )
    }

    #[test]
    fn a_tampered_reviewed_object_identity_is_not_admitted() {
        // The same paths with unreviewed object identities stay excluded.
        for (path, sha, size) in [
            (
                "README.md",
                "ad1fa0d43c170e76768c04152e1d6ddfe3879f7c",
                Some(228u64),
            ),
            (
                "README.md",
                REVIEWED_README_BLOB,
                Some(REVIEWED_README_SIZE - 1),
            ),
            (
                "LICENSE",
                "e6a86361c7f596424543a3d9a6c1362b8601204e",
                Some(REVIEWED_LICENSE_SIZE),
            ),
            (
                "LICENSE",
                REVIEWED_LICENSE_BLOB,
                Some(REVIEWED_LICENSE_SIZE + 1),
            ),
        ] {
            let verdict = verdict_of(&tree_entry(path, sha, size));
            let Verdict::Excluded { class, reason } = verdict else {
                panic!("{path} {sha} was admitted");
            };
            assert_eq!(class, MaterialClass::Excluded, "{path} {sha}");
            assert!(!reason.is_empty(), "{path} {sha}");
        }
        let verdict = verdict_of(&tree_entry(
            "LICENSE",
            REVIEWED_LICENSE_BLOB,
            Some(REVIEWED_LICENSE_SIZE),
        ));
        let Verdict::Admitted { class, evidence } = verdict else {
            panic!("the reviewed license object is admitted");
        };
        assert_eq!(class, MaterialClass::License);
        assert_eq!(
            evidence.basis,
            "verbatim_license_notice_of_the_reviewed_work"
        );
        assert_eq!(evidence.license_blob_sha, REVIEWED_LICENSE_BLOB);
        // An alias of the admitted readme object under a foreign path is
        // never admitted.
        let verdict = verdict_of(&tree_entry(
            "HangGai/Assets/DB/README.md",
            REVIEWED_README_BLOB,
            Some(REVIEWED_README_SIZE),
        ));
        let Verdict::Excluded { class, .. } = verdict else {
            panic!("an alias of an admitted object is never admitted");
        };
        assert_eq!(class, MaterialClass::Excluded);
        // An alias of the answer-bank object under a foreign path stays
        // answer material, the stronger category.
        let verdict = verdict_of(&tree_entry(
            "HangGai/Assets/DB/backup.db",
            REVIEWED_ANSWER_BANK_BLOB,
            Some(352256),
        ));
        let Verdict::Excluded { class, .. } = verdict else {
            panic!("an alias of the answer bank is never admitted");
        };
        assert_eq!(class, MaterialClass::AnswerMaterial);
        // A symlink or a directory at a reviewed path is excluded: naming the
        // reviewed path is not the reviewed object, and only a regular file
        // can ever be retrieved.
        for entry in [
            symlink_entry("README.md", REVIEWED_README_BLOB, REVIEWED_README_SIZE),
            tree_entry("README.md", REVIEWED_README_BLOB, None),
            symlink_entry("LICENSE", REVIEWED_LICENSE_BLOB, REVIEWED_LICENSE_SIZE),
            tree_entry("LICENSE", REVIEWED_LICENSE_BLOB, None),
        ] {
            let verdict = verdict_of(&entry);
            let Verdict::Excluded { class, reason } = verdict else {
                panic!("{} is not a regular file", entry.path);
            };
            assert_eq!(class, MaterialClass::Excluded, "{}", entry.path);
            assert_eq!(reason, "the_reviewed_path_is_not_a_regular_file");
        }
    }

    #[test]
    fn excluded_and_aliased_items_are_refused_before_bytes() {
        let (_, entries, _) = admitted();
        // The reviewed readme is admitted with its complete attestation.
        let readme_request = request("README.md", REVIEWED_README_BLOB, REVIEWED_README_SIZE);
        let (class, reason, blob_sha, size, license) =
            select_item(&entries, &readme_request).unwrap();
        assert_eq!(class, MaterialClass::Documentation);
        assert_eq!(
            reason,
            "author_written_description_covered_by_the_repository_license"
        );
        assert_eq!(blob_sha, REVIEWED_README_BLOB);
        assert_eq!(size, REVIEWED_README_SIZE);
        assert_eq!(
            license["bound_license_blob_sha"],
            json!(REVIEWED_LICENSE_BLOB)
        );
        // The answer bank keeps its stronger refusal, and so does an alias
        // of its object.
        for path in [ANSWER_BANK_PATH, "HangGai/Assets/DB/backup.db"] {
            let refused = select_item(&entries, &request(path, REVIEWED_ANSWER_BANK_BLOB, 352256))
                .unwrap_err();
            assert_eq!(refused.code, "answer_material_forbidden", "{path}");
        }
        // An alias of the admitted readme is refused as excluded.
        let refused = select_item(
            &entries,
            &request(
                "HangGai/Assets/DB/README.md",
                REVIEWED_README_BLOB,
                REVIEWED_README_SIZE,
            ),
        )
        .unwrap_err();
        assert_eq!(refused.code, "authorization_required");
        // Every excluded family refuses before any byte request.
        for (path, sha, size) in [
            (
                "HangGai/Assets/QuestionImgs/1001h.png",
                "ee42328c3df28b771bc5a8ad8796435427fe8a56",
                15285u64,
            ),
            (
                "HangGai/Assets.xcassets/QuestionImages/1001h.imageset/1001h.png",
                "ee42328c3df28b771bc5a8ad8796435427fe8a56",
                15285u64,
            ),
            (
                "HangGai/Assets/Fonts/FZSSJW.TTF",
                "982620401b87e2ab64fa1d60206ac770c4455d0d",
                3081292u64,
            ),
            (
                "HangGai/Models/QuestionModel.swift",
                "08096365b206d0c3666534b3553aa897cb3a708f",
                865u64,
            ),
            (
                "HangGai/Info.plist",
                "5c89eb5dac0d9c00034ba3c9a3e383edda4de2a2",
                1843u64,
            ),
            (
                "img/dark.png",
                "1f60e318738aa678a2d8c5a9dca25cc243543aa4",
                96388u64,
            ),
        ] {
            let refused = select_item(&entries, &request(path, sha, size)).unwrap_err();
            assert_eq!(refused.code, "authorization_required", "{path}");
        }
        // A tampered attestation never reaches the verdict.
        let mut tampered = request("README.md", REVIEWED_README_BLOB, REVIEWED_README_SIZE);
        tampered.blob_sha = Some(REVIEWED_LICENSE_BLOB.to_owned());
        assert_eq!(
            select_item(&entries, &tampered).unwrap_err().code,
            "authorization_required"
        );
        let mut tampered = request("README.md", REVIEWED_README_BLOB, REVIEWED_README_SIZE);
        tampered.size = Some(REVIEWED_README_SIZE - 1);
        assert_eq!(
            select_item(&entries, &tampered).unwrap_err().code,
            "authorization_required"
        );
        // A directory and an absent path are not retrievable items.
        let refused = select_item(
            &entries,
            &request("missing.md", REVIEWED_README_BLOB, REVIEWED_README_SIZE),
        )
        .unwrap_err();
        assert_eq!(refused.code, "path_not_in_inventory");
        let refused = select_item(
            &entries,
            &request("HangGai/Assets/DB", REVIEWED_ANSWER_BANK_BLOB, 352256),
        )
        .unwrap_err();
        assert_eq!(refused.code, "path_not_in_inventory");
        // A symlink at a reviewed path with the reviewed identity is still
        // not a regular file: the entry is excluded and never retrievable,
        // even when the whole attestation matches its bytes.
        let mut entries = entries;
        let readme = entries
            .iter_mut()
            .find(|entry| entry.path == "README.md")
            .expect("the fixture readme");
        readme.mode = "120000".to_owned();
        let refused = select_item(
            &entries,
            &request("README.md", REVIEWED_README_BLOB, REVIEWED_README_SIZE),
        )
        .unwrap_err();
        assert_eq!(refused.code, "invalid_input");
    }

    #[test]
    fn a_root_level_answer_directory_is_answer_material() {
        let other = "ad1fa0d43c170e76768c04152e1d6ddfe3879f7c";
        for path in ["answers/key.txt", "docs/answers/key.txt"] {
            let verdict = verdict_of(&tree_entry(path, other, Some(3)));
            let Verdict::Excluded { class, .. } = verdict else {
                panic!("{path} was admitted");
            };
            assert_eq!(class, MaterialClass::AnswerMaterial, "{path}");
        }
        // A directory named like answer material stays answer material, and
        // an alias of the answer-bank bytes is answer material even under a
        // reviewed path.
        for entry in [
            tree_entry("answers", other, None),
            symlink_entry("LICENSE", REVIEWED_ANSWER_BANK_BLOB, 352256),
        ] {
            let verdict = verdict_of(&entry);
            let Verdict::Excluded { class, .. } = verdict else {
                panic!("{} was admitted", entry.path);
            };
            assert_eq!(class, MaterialClass::AnswerMaterial, "{}", entry.path);
        }
        assert!(learning::answer_path_component("answers/key.txt"));
    }

    #[test]
    fn a_malformed_tree_degrades_with_the_original_bytes() {
        let url = fixture_url();
        let body = br#"{"sha":"not-a-digest","tree":[],"truncated":false}"#;
        let response = response(&url, body, "application/json");
        let identity = identity_of(&response);
        let output = materials_output(&url, &response, &identity).unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["fallback_reason"], "upstream_parse");
        assert_eq!(output["entries"], json!([]));
        assert_eq!(output["admitted_count"], 0);
        assert_eq!(output["raw_evidence"]["content_type"], "application/json");
        assert_eq!(output["raw_evidence"]["byte_length"], body.len());
        assert_eq!(output["raw_evidence"]["sha256"], learning::sha256_hex(body));
        assert_eq!(output["raw_evidence"]["data"], STANDARD.encode(body));
        assert_eq!(output["raw_evidence"]["fallback_reason"], "upstream_parse");
    }

    #[test]
    fn a_rejected_blob_response_never_discloses_its_bytes() {
        // A response that is not the reviewed object is withheld: the output
        // carries the length, the digest and the reason, never the bytes.
        let url = SOURCE.blob_url(REVIEWED_README_BLOB).unwrap();
        let body = b"bytes of an item that never passed the rights admission";
        let response = response(&url, body, "text/plain");
        let identity = learning::observed_identity(
            learning::Surface::Raw,
            &url,
            &response.body,
            Some("text/plain"),
        );
        let request = request("README.md", REVIEWED_README_BLOB, REVIEWED_README_SIZE);
        let output = raw_bytes_output(
            &response,
            &identity,
            &request,
            MaterialClass::Documentation,
            "author_written_description_covered_by_the_repository_license",
            &ReviewedObject {
                tree_sha: REVISION.tree,
                blob_sha: REVIEWED_README_BLOB,
                size: REVIEWED_README_SIZE,
            },
            learning::unknown_license(),
        )
        .unwrap();
        assert_eq!(output["result"], json!("degraded"));
        assert_eq!(output["fallback_reason"], json!("blob_identity_mismatch"));
        assert_eq!(output["bytes"], Value::Null);
        assert_eq!(output["byte_length"], Value::Null);
        assert_eq!(output["sha256"], Value::Null);
        assert_eq!(output["raw_evidence"]["kind"], json!("withheld_response"));
        assert_eq!(output["raw_evidence"]["data"], Value::Null);
        assert!(!output.to_string().contains("never passed the rights"));
        // The rejected body must not be labeled as the verified object: the
        // proof field is absent, while the admitted tree proof stays.
        assert_eq!(
            output["retrieval"]["verified_git_blob_sha"],
            Value::Null,
            "a rejected response must not claim a verified Git blob SHA"
        );
        assert_eq!(
            output["retrieval"]["admitted_tree_sha"],
            json!(REVISION.tree)
        );
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
        // The attestation must name the pinned revision's reviewed tree.
        let foreign_tree = parse_fetch_input(
            r#"{"path":"README.md","rights_reviewed":true,"tree_sha":"3934f139b11918acc170f920c4e8290ef4b57376","blob_sha":"0b4aaae22b098e2d00e603fb7ce39b95fd13905f","mode":"100644","size":228}"#,
        )
        .err()
        .unwrap();
        assert_eq!(foreign_tree.code, "invalid_input");
        let accepted = parse_fetch_input(
            r#"{"path":"README.md","rights_reviewed":true,"tree_sha":"4eb358ae271b5ceae2aa0003999172f806a128d7","blob_sha":"0b4aaae22b098e2d00e603fb7ce39b95fd13905f","mode":"100644","size":228}"#,
        )
        .unwrap();
        assert_eq!(accepted.path, "README.md");
    }

    #[test]
    fn a_non_object_duplicate_or_trailing_request_is_refused_before_admission() {
        // A positional sequence root is not a request object, even when its
        // elements would otherwise deserialize into an attested request.
        let array_search = parse_search_input(r#"["question",true]"#).err().unwrap();
        assert_eq!(array_search.code, "invalid_input");
        let array_fetch = parse_fetch_input(
            r#"["README.md",true,"4eb358ae271b5ceae2aa0003999172f806a128d7","0b4aaae22b098e2d00e603fb7ce39b95fd13905f","100644",228]"#,
        )
        .err()
        .unwrap();
        assert_eq!(array_fetch.code, "invalid_input");
        // A repeated attestation is a duplicate field, never last-key-wins:
        // a false value cannot collapse into an admitted true.
        let duplicate_search = parse_search_input(
            r#"{"query":"question","rights_reviewed":false,"rights_reviewed":true}"#,
        )
        .err()
        .unwrap();
        assert_eq!(duplicate_search.code, "invalid_input");
        let duplicate_fetch = parse_fetch_input(
            r#"{"path":"README.md","rights_reviewed":false,"rights_reviewed":true,"tree_sha":"4eb358ae271b5ceae2aa0003999172f806a128d7","blob_sha":"0b4aaae22b098e2d00e603fb7ce39b95fd13905f","mode":"100644","size":228}"#,
        )
        .err()
        .unwrap();
        assert_eq!(duplicate_fetch.code, "invalid_input");
        // A second document after a complete valid request is refused
        // rather than ignored.
        let trailing_search = parse_search_input(
            r#"{"query":"question","rights_reviewed":true} {"query":"other","rights_reviewed":true}"#,
        )
        .err()
        .unwrap();
        assert_eq!(trailing_search.code, "invalid_input");
        let trailing_fetch = parse_fetch_input(
            r#"{"path":"README.md","rights_reviewed":true,"tree_sha":"4eb358ae271b5ceae2aa0003999172f806a128d7","blob_sha":"0b4aaae22b098e2d00e603fb7ce39b95fd13905f","mode":"100644","size":228} {}"#,
        )
        .err()
        .unwrap();
        assert_eq!(trailing_fetch.code, "invalid_input");
        // The plain attested object request is still accepted.
        let accepted =
            parse_search_input(r#"{"query":"question","rights_reviewed":true}"#).unwrap();
        assert_eq!(accepted.query, "question");
        assert_eq!(accepted.rights_reviewed, Some(true));
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

        let checked =
            practice(&json!({"action": "check", "session": answered}).to_string()).unwrap();
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
    fn a_repeated_member_is_refused_before_the_practice_is_used() {
        // A contradicting attestation is refused; it is never collapsed into
        // the attested `true` the last member would otherwise publish.
        for input in [
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]},"rights_reviewed":false,"rights_reviewed":true}"#,
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]},"rights_reviewed":true,"rights_reviewed":false}"#,
        ] {
            let refused = practice(input).err().unwrap();
            assert_eq!(refused.code, "invalid_input", "{input}");
        }
        // An escape-spelled member name is the same member once unescaped:
        // the second spelling does not smuggle a contradicting value in.
        let base = r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]},"rights_reviewed":true,"rights_reviewed":false}"#;
        let backslash = 0x5c_u8 as char;
        let escaped = base.replacen(
            "rights_reviewed\":false",
            &format!("rights{backslash}u005freviewed\":false"),
            1,
        );
        let refused = practice(&escaped).err().unwrap();
        assert_eq!(refused.code, "invalid_input");
        // A repeated member nested inside the question set is malformed
        // input, never a last-key-wins identity or stem.
        for input in [
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"id":8,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]}}"#,
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"question":"Which discipline studies aircraft motion?","question":"What is Bernoulli's principle?","options":["Aerodynamics","Optics"],"type":1}]}}"#,
        ] {
            let refused = practice(input).err().unwrap();
            assert_eq!(refused.code, "invalid_input", "{input}");
        }
        // A repeated member inside a returned session is refused before the
        // session is used at all.
        let generated = practice(
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]}}"#,
        )
        .unwrap();
        let session = serde_json::to_string(&generated).unwrap();
        let tampered = session.replacen(
            "\"rights_reviewed\":false",
            "\"rights_reviewed\":false,\"rights_reviewed\":true",
            1,
        );
        let refused = practice(&format!("{{\"action\":\"check\",\"session\":{tampered}}}"))
            .err()
            .unwrap();
        assert_eq!(refused.code, "invalid_input");
        // A second document after a complete request is refused.
        let refused = practice(
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]}} {}"#,
        )
        .err()
        .unwrap();
        assert_eq!(refused.code, "invalid_input");
        // Ordinary inputs are unchanged: the attestation is published, a
        // non-member key still fails, and a non-object root is not a request.
        let attested = practice(
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]},"rights_reviewed":true}"#,
        )
        .unwrap();
        assert_eq!(attested["rights_reviewed"], true);
        assert_eq!(attested["practice_source"]["rights_reviewed"], true);
        let refused = practice(
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]},"unrelated":1}"#,
        )
        .err()
        .unwrap();
        assert_eq!(refused.code, "invalid_input");
        let refused = practice(r#"["generate"]"#).err().unwrap();
        assert_eq!(refused.code, "invalid_input");
    }

    #[test]
    fn one_consistent_practice_attestation_is_required_at_every_depth() {
        let generated = practice(
            r#"{"action":"generate","mode":"question_set","question_set":{"questions":[{"id":7,"question":"Which discipline studies aircraft motion?","options":["Aerodynamics","Optics"],"type":1}]},"rights_reviewed":true}"#,
        )
        .unwrap();
        assert_eq!(generated["rights_reviewed"], true);
        assert_eq!(generated["practice_source"]["rights_reviewed"], true);
        // The session contract publishes the attestation twice, and the two
        // published values agree, so the session is admitted.
        let checked =
            practice(&json!({"action": "check", "session": generated}).to_string()).unwrap();
        assert_eq!(checked["rights_reviewed"], true);
        assert_eq!(checked["practice_source"]["rights_reviewed"], true);

        // A short attestation: the source loses the member while the session
        // still claims it. It is refused instead of defaulting.
        let mut short = generated.clone();
        short["practice_source"]
            .as_object_mut()
            .unwrap()
            .remove("rights_reviewed");
        let refused = practice(&json!({"action": "check", "session": short}).to_string())
            .err()
            .unwrap();
        assert_eq!(refused.code, "invalid_input");
        // The same short attestation cannot pass as an answer action either.
        let mut short = generated.clone();
        short["practice_source"]
            .as_object_mut()
            .unwrap()
            .remove("rights_reviewed");
        let refused = practice(
            &json!({
                "action": "answer",
                "session": short,
                "answers": [{"question_id": "q7", "choices": ["A"]}]
            })
            .to_string(),
        )
        .err()
        .unwrap();
        assert_eq!(refused.code, "invalid_input");
        // A duplicate attestation at the nested depth that contradicts the
        // session attestation is refused, never last-key-wins.
        let mut contradicting = generated.clone();
        contradicting["practice_source"]["rights_reviewed"] = json!(false);
        let refused = practice(&json!({"action": "check", "session": contradicting}).to_string())
            .err()
            .unwrap();
        assert_eq!(refused.code, "invalid_input");
        // The session-root attestation is required as well: removing it is
        // malformed, not an implicit false.
        let mut root_short = generated.clone();
        root_short
            .as_object_mut()
            .unwrap()
            .remove("rights_reviewed");
        let refused = practice(&json!({"action": "check", "session": root_short}).to_string())
            .err()
            .unwrap();
        assert_eq!(refused.code, "invalid_input");
        // An unexpected member cannot smuggle a second attestation into the
        // source object, and the source must be complete.
        let mut unexpected = generated.clone();
        unexpected["practice_source"]["scan"] = json!({"rights_reviewed": true});
        let refused = practice(&json!({"action": "check", "session": unexpected}).to_string())
            .err()
            .unwrap();
        assert_eq!(refused.code, "invalid_input");
        let mut extra = generated.clone();
        extra["practice_source"]["nested"] = json!({"rights_reviewed": true});
        let refused = practice(&json!({"action": "check", "session": extra}).to_string())
            .err()
            .unwrap();
        assert_eq!(refused.code, "invalid_input");
        // A repeated member inside the source object is a duplicate at that
        // depth and never collapses into one attested value.
        let session = serde_json::to_string(&generated).unwrap();
        let duplicated = session.replacen(
            "\"origin\":\"operator_local_question_set\",\"rights_reviewed\":true",
            "\"origin\":\"operator_local_question_set\",\"rights_reviewed\":false,\"rights_reviewed\":true",
            1,
        );
        assert_ne!(session, duplicated);
        let refused = practice(&format!(
            "{{\"action\":\"check\",\"session\":{duplicated}}}"
        ))
        .err()
        .unwrap();
        assert_eq!(refused.code, "invalid_input");
    }

    #[test]
    fn the_published_schemas_require_the_exhaustive_verdict() {
        let schema = entry_schema();
        let required: Vec<String> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        for key in ["admission", "admission_reason", "license_evidence"] {
            assert!(required.contains(&key.to_owned()), "{key}");
        }
        let branches = schema["allOf"].as_array().unwrap();
        assert_eq!(branches.len(), 2);
        assert_eq!(
            branches[0]["if"]["properties"]["admission"]["const"],
            json!("admitted")
        );
        assert_eq!(
            branches[0]["then"]["properties"]["retrieval_allowed"]["const"],
            json!(true)
        );
        assert_eq!(
            branches[0]["then"]["properties"]["mirror_allowed"]["const"],
            json!(true)
        );
        assert_eq!(
            branches[1]["if"]["properties"]["admission"]["const"],
            json!("excluded")
        );
        assert_eq!(
            branches[1]["then"]["properties"]["retrieval_allowed"]["const"],
            json!(false)
        );
        assert_eq!(
            branches[1]["then"]["properties"]["license_evidence"]["type"],
            json!("null")
        );
        let evidence = entry_license_evidence_schema();
        assert_eq!(
            evidence["properties"]["license_blob_sha"]["const"],
            json!(REVIEWED_LICENSE_BLOB)
        );
        assert_eq!(
            evidence["properties"]["license_size"]["const"],
            json!(REVIEWED_LICENSE_SIZE)
        );
        assert_eq!(
            evidence["properties"]["independently_verified"]["const"],
            json!(false)
        );
        // A raw snapshot must publish the verified object identity, while a
        // withheld response must never publish it.
        let bytes = bytes_output_schema();
        let branches = bytes["allOf"].as_array().unwrap();
        assert_eq!(
            branches[0]["then"]["properties"]["retrieval"]["required"],
            json!(["verified_git_blob_sha"])
        );
        assert_eq!(
            branches[1]["then"]["properties"]["retrieval"]["not"]["required"],
            json!(["verified_git_blob_sha"])
        );
    }
}
