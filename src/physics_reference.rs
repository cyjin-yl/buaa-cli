//! Rights-reviewed physics reference material.
//!
//! One public upstream revision is bound here: the author's own experiment
//! data-processing guide in `wtdcode/BUAAPhyhelper`, at the reviewed commit
//! `dd2fda76dfa61d921e5efaf84f92a44e9243f3b2` and the tree that commit
//! declares, `82655593cd3486549b5e49eec55ca9add1d3ccd4`. A branch head can
//! move, so the review is bound to those immutable object identities: the
//! commit must name the reviewed commit and declare the reviewed tree, and
//! every advertised directory and the root object are reconstructed and
//! verified before an entry is published.
//!
//! Rights are decided per item, never per repository. The author's own
//! processing guide and the repository license notice are admitted. A
//! separately published third-party article, textbook-derived sample data, a
//! link-only stub, the upstream implementation sources and repository metadata
//! are listed with their exclusion reason and are never retrievable. Public
//! visibility is not permission, and no upstream implementation or upstream
//! prose is copied into this project: an admitted item is fetched at run time
//! and published with the license notice that must accompany any conveyed
//! copy.
//!
//! Retrieval returns the exact original bytes of one admitted item, bound to
//! the reviewed tree, blob identity and declared length. Every request is
//! cache-first and paced by the shared governor. Nothing here contacts a
//! campus service, authenticates, or mutates anything.

use crate::net::Error;
use crate::welearn::learning;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

/// The reviewed upstream repository.
const SOURCE: learning::SourceSpec = learning::SourceSpec {
    owner: "wtdcode",
    name: "BUAAPhyhelper",
    branch: "master",
};

/// The reviewed upstream revision: one commit and the tree it declares.
const REVISION: learning::Revision = learning::Revision {
    commit: "dd2fda76dfa61d921e5efaf84f92a44e9243f3b2",
    tree: "82655593cd3486549b5e49eec55ca9add1d3ccd4",
};

/// The reviewed license object: the verbatim GNU GPL version 3 text.
const REVIEWED_LICENSE_BLOB: &str = "474503f3470a8b7e0e859945b2b866aeb7a3f096";
const REVIEWED_LICENSE_SIZE: u64 = 35113;
const REVIEWED_LICENSE_SPDX: &str = "GPL-3.0";
const REVIEWED_LICENSE_NAME: &str = "GNU General Public License v3.0";

/// The reviewed guide object: the author's own calculation and processing
/// method write-up.
const REVIEWED_GUIDE_BLOB: &str = "02427435071267252f752280278fbb8af6b1919b";
const REVIEWED_GUIDE_SIZE: u64 = 6736;

const CATALOG_TYPE: &str = "physics_reference_catalog";
const BYTES_TYPE: &str = "physics_reference_bytes";

/// The reviewed material class of one item of the pinned tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaterialClass {
    Guide,
    License,
    Excluded,
}

impl MaterialClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Guide => "reference_guide",
            Self::License => "license_notice",
            Self::Excluded => "excluded",
        }
    }
}

/// The reviewed per-item decision. Only the two reviewed objects are
/// admitted; every other item of the pinned tree keeps its exclusion reason.
fn classify(path: &str, blob_sha: &str, size: Option<u64>) -> (MaterialClass, &'static str) {
    match path {
        "README.md" if blob_sha == REVIEWED_GUIDE_BLOB && size == Some(REVIEWED_GUIDE_SIZE) => (
            MaterialClass::Guide,
            "author_written_original_processing_guide",
        ),
        "README.md" => (
            MaterialClass::Excluded,
            "the_root_readme_is_not_the_reviewed_guide_object",
        ),
        "LICENSE" if blob_sha == REVIEWED_LICENSE_BLOB && size == Some(REVIEWED_LICENSE_SIZE) => (
            MaterialClass::License,
            "verbatim_license_notice_of_the_reviewed_work",
        ),
        "LICENSE" => (
            MaterialClass::Excluded,
            "the_license_object_is_not_the_reviewed_license_identity",
        ),
        _ if path.ends_with(".pdf") => (
            MaterialClass::Excluded,
            "third_party_published_document_not_cleared_by_the_repository_license",
        ),
        _ if path.ends_with("Test.txt") => (
            MaterialClass::Excluded,
            "textbook_derived_sample_data_without_documented_rights",
        ),
        _ if path.ends_with(".m") || path.ends_with(".py") => (
            MaterialClass::Excluded,
            "upstream_implementation_source_is_not_reference_material",
        ),
        _ if path.ends_with("README.md") => (
            MaterialClass::Excluded,
            "link_only_stub_without_original_content",
        ),
        _ => (
            MaterialClass::Excluded,
            "repository_metadata_or_unreviewed_item",
        ),
    }
}

/// Whether one item of the pinned tree may be retrieved at all.
fn retrievable(class: MaterialClass) -> bool {
    matches!(class, MaterialClass::Guide | MaterialClass::License)
}

/// One published item of the pinned tree.
struct Item {
    path: String,
    kind: &'static str,
    mode: String,
    size: Option<u64>,
    sha: String,
}

/// The items of an admitted tree.
fn items(entries: &[learning::TreeEntry]) -> Vec<Item> {
    entries
        .iter()
        .map(|entry| Item {
            path: entry.path.clone(),
            kind: entry.kind().unwrap_or("other"),
            mode: entry.mode.clone(),
            size: entry.size,
            sha: entry.sha.clone(),
        })
        .collect()
}

/// The license provenance bound to the admitted tree. The SPDX reference is
/// the reviewed identifier of the exact license object the tree carries; it is
/// an operator review of that object, not an independent proof.
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
        "bound_license_blob_sha": bound.map(|entry| Value::String(entry.sha.clone())).unwrap_or(Value::Null),
        "bound_license_size": bound.and_then(|entry| entry.size),
        "bound_license_url": bound
            .and_then(|entry| SOURCE.blob_url(&entry.sha).ok())
            .map(|url| Value::String(url.as_str().to_owned()))
            .unwrap_or(Value::Null),
        "independently_verified": false,
    })
}

/// One published catalog entry.
fn catalog_entry(item: &Item) -> Value {
    let (class, reason) = classify(&item.path, &item.sha, item.size);
    json!({
        "path": item.path,
        "kind": item.kind,
        "mode": item.mode,
        "size": item.size,
        "upstream_sha": item.sha,
        "material_class": class.as_str(),
        "admission_reason": reason,
        "retrievable": retrievable(class) && item.kind == "file",
    })
}

fn revision_value() -> Value {
    json!({"commit": REVISION.commit, "tree": REVISION.tree})
}

/// The catalog of the pinned revision, published only from a tree whose every
/// object was verified.
fn catalog_snapshot(tree_sha: &str, entries: &[learning::TreeEntry], retrieval: Value) -> Value {
    let items = items(entries);
    let values: Vec<Value> = items.iter().map(catalog_entry).collect();
    let admitted_count = values
        .iter()
        .filter(|value| value["retrievable"] == json!(true))
        .count();
    json!({
        "schema_version": 1,
        "type": CATALOG_TYPE,
        "result": "catalog_snapshot",
        "source": SOURCE.full_name(),
        "source_url": SOURCE.repository_url(),
        "branch": SOURCE.branch,
        "revision": revision_value(),
        "tree_sha": tree_sha,
        "license": license_value(entries),
        "attribution": SOURCE.full_name(),
        "rights_reviewed": false,
        "entries": values,
        "entry_count": items.len(),
        "admitted_count": admitted_count,
        "excluded_count": items.len() - admitted_count,
        "fallback_reason": Value::Null,
        "raw_evidence": Value::Null,
        "retrieval": retrieval,
    })
}

/// A catalog that could not be normalized from the pinned tree keeps the
/// original bytes as degraded evidence.
fn degraded_catalog(
    response: &crate::net::Response,
    identity: &learning::ObservedIdentity,
    reason: &str,
) -> Result<Value, Error> {
    let evidence = learning::degraded_evidence(response, identity, reason)?;
    Ok(json!({
        "schema_version": 1,
        "type": CATALOG_TYPE,
        "result": "degraded",
        "source": SOURCE.full_name(),
        "source_url": SOURCE.repository_url(),
        "branch": SOURCE.branch,
        "revision": revision_value(),
        "tree_sha": Value::Null,
        "license": learning::unknown_license(),
        "attribution": SOURCE.full_name(),
        "rights_reviewed": false,
        "entries": [],
        "entry_count": 0,
        "admitted_count": 0,
        "excluded_count": 0,
        "fallback_reason": reason,
        "raw_evidence": evidence,
        "retrieval": learning::retrieval(response),
    }))
}

/// The typed retrieval request. Unknown fields are refused, so a credential
/// field never reaches a diagnostic.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RetrieveInput {
    path: String,
    tree_sha: String,
    blob_sha: String,
    size: u64,
    rights_reviewed: Option<bool>,
}

fn parse_retrieve_input(input: &str) -> Result<RetrieveInput, Error> {
    if input.len() > learning::MAX_INPUT {
        return Err(learning::invalid_input(
            "the retrieval request is too large",
        ));
    }
    // A positional array is not a request object, so the object form is
    // required before the typed fields are read.
    let value: Value = serde_json::from_str(input)
        .map_err(|_| learning::invalid_input("invalid retrieval request"))?;
    if !value.is_object() {
        return Err(learning::invalid_input("invalid retrieval request"));
    }
    let request: RetrieveInput = serde_json::from_value(value)
        .map_err(|_| learning::invalid_input("invalid retrieval request"))?;
    if request.rights_reviewed != Some(true) {
        return Err(learning::authorization_required(
            "an explicit rights_reviewed attestation is required before reference material is retrieved",
        ));
    }
    if !learning::valid_path(&request.path) {
        return Err(learning::invalid_input(
            "path must be one explicit normalized repository file path",
        ));
    }
    if request.tree_sha != REVISION.tree {
        return Err(learning::invalid_input(
            "tree_sha must be the reviewed tree object of the pinned revision",
        ));
    }
    if !learning::valid_upstream_sha(&request.blob_sha) {
        return Err(learning::invalid_input(
            "blob_sha must be an exact Git object identifier",
        ));
    }
    if request.size == 0 {
        return Err(learning::invalid_input(
            "size must be the exact declared length of the reviewed object",
        ));
    }
    Ok(request)
}

/// The catalog of the rights-reviewed physics reference items.
pub fn catalog(input: &str, online: bool) -> Result<Value, Error> {
    if input.len() > learning::MAX_INPUT {
        return Err(learning::invalid_input("the catalog request is too large"));
    }
    let trimmed = input.trim();
    if !trimmed.is_empty() {
        let value: Value = serde_json::from_str(trimmed)
            .map_err(|_| learning::invalid_input("invalid catalog request"))?;
        let object = value
            .as_object()
            .ok_or_else(|| learning::invalid_input("the catalog request must be an object"))?;
        learning::only_keys(object, &[])?;
    }
    learning::with_pinned_tree_response(&SOURCE, &REVISION, online, |response, identity, _url| {
        match identity.tree() {
            Some(admitted) => Ok(catalog_snapshot(
                &admitted.tree_sha,
                &admitted.entries,
                learning::retrieval(response),
            )),
            None => {
                let reason = identity.tree_error().unwrap_or("upstream_parse");
                degraded_catalog(response, identity, reason)
            }
        }
    })
}

/// The membership of the pinned tree for one requested item.
enum Membership {
    Admitted { items: Vec<Item>, license: Value },
    Degraded(Value),
}

/// The original bytes of one rights-reviewed reference item.
pub fn retrieve(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_retrieve_input(input)?;
    // The reviewed tree is the only source of membership, so a path that the
    // pinned tree does not carry is refused before any byte request.
    let membership = learning::with_pinned_tree_response(
        &SOURCE,
        &REVISION,
        online,
        |response, identity, _url| match identity.tree() {
            Some(admitted) => Ok(Membership::Admitted {
                items: items(&admitted.entries),
                license: license_value(&admitted.entries),
            }),
            None => {
                let reason = identity.tree_error().unwrap_or("upstream_parse");
                let evidence = learning::degraded_evidence(response, identity, reason)?;
                Ok(Membership::Degraded(json!({
                    "schema_version": 1,
                    "type": BYTES_TYPE,
                    "result": "degraded",
                    "path": request.path,
                    "source": SOURCE.full_name(),
                    "source_url": SOURCE.repository_url(),
                    "branch": SOURCE.branch,
                    "revision": revision_value(),
                    "tree_sha": Value::Null,
                    "upstream_sha": Value::Null,
                    "size": Value::Null,
                    "material_class": Value::Null,
                    "admission_reason": Value::Null,
                    "license": learning::unknown_license(),
                    "attribution": SOURCE.full_name(),
                    "rights_reviewed": true,
                    "license_notice_required": true,
                    "bytes": Value::Null,
                    "byte_encoding": "base64",
                    "byte_length": Value::Null,
                    "sha256": Value::Null,
                    "content_type": Value::Null,
                    "fallback_reason": reason,
                    "raw_evidence": evidence,
                    "retrieval": learning::retrieval(response),
                })))
            }
        },
    )?;
    let (items, license) = match membership {
        Membership::Degraded(output) => return Ok(output),
        Membership::Admitted { items, license } => (items, license),
    };
    let Some(item) = items.into_iter().find(|item| item.path == request.path) else {
        return Err(learning::invalid_input(
            "the requested path is not present in the reviewed tree",
        ));
    };
    let (class, reason) = classify(&item.path, &item.sha, item.size);
    if !retrievable(class) {
        return Err(Error::new(
            "authorization_required",
            "the requested item has no documented per-item rights and is never retrievable",
        ));
    }
    if item.kind != "file" {
        return Err(learning::invalid_input(
            "only a regular file of the reviewed tree can be retrieved",
        ));
    }
    if item.sha != request.blob_sha || item.size != Some(request.size) {
        return Err(learning::invalid_input(
            "the requested item does not match the reviewed immutable identity",
        ));
    }
    learning::with_raw_response(&SOURCE, &request.blob_sha, online, |response, identity| {
        raw_bytes_output(response, identity, &request, class, reason, license.clone())
    })
}

/// The published output of one byte request. The bytes must be exactly the
/// reviewed object: bytes that are not that object never passed the
/// per-item rights admission, so only their length, digest and reason are
/// reported and the original bytes are never disclosed.
fn raw_bytes_output(
    response: &crate::net::Response,
    identity: &learning::ObservedIdentity,
    request: &RetrieveInput,
    class: MaterialClass,
    reason: &'static str,
    license: Value,
) -> Result<Value, Error> {
    let observed = learning::content_type(response);
    let mut output = json!({
        "schema_version": 1,
        "type": BYTES_TYPE,
        "result": Value::Null,
        "path": request.path,
        "source": SOURCE.full_name(),
        "source_url": SOURCE.repository_url(),
        "branch": SOURCE.branch,
        "revision": revision_value(),
        "tree_sha": request.tree_sha,
        "upstream_sha": request.blob_sha,
        "size": request.size,
        "material_class": class.as_str(),
        "admission_reason": reason,
        "license": license,
        "attribution": SOURCE.full_name(),
        "rights_reviewed": true,
        "license_notice_required": true,
        "bytes": Value::Null,
        "byte_encoding": "base64",
        "byte_length": Value::Null,
        "sha256": Value::Null,
        "content_type": Value::Null,
        "fallback_reason": Value::Null,
        "raw_evidence": Value::Null,
        "retrieval": learning::retrieval(response),
    });
    let mismatch = if identity.blob_sha() != Some(request.blob_sha.as_str()) {
        Some("blob_identity_mismatch")
    } else if response.body.len() as u64 != request.size {
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

fn entry_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["path","kind","mode","size","upstream_sha","material_class","admission_reason","retrievable"],
        "properties":{
            "path":{"type":"string","minLength":1,"maxLength":learning::MAX_PATH},
            "kind":{"enum":["file","directory","symlink","submodule","other"]},
            "mode":{"enum":["100644","100755","040000","120000","160000"]},
            "size":{"type":["integer","null"],"minimum":0},
            "upstream_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
            "material_class":{"enum":["reference_guide","license_notice","excluded"]},
            "admission_reason":{"type":"string","minLength":1},
            "retrievable":{"type":"boolean"}
        }
    })
}

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

fn catalog_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["schema_version","type","result","source","source_url","branch","revision","tree_sha","license","attribution","rights_reviewed","entries","entry_count","admitted_count","excluded_count","fallback_reason","raw_evidence","retrieval"],
        "properties":{
            "schema_version":{"const":1},
            "type":{"const":CATALOG_TYPE},
            "result":{"enum":["catalog_snapshot","degraded"]},
            "source":{"type":"string","minLength":1},
            "source_url":{"type":"string","minLength":1},
            "branch":{"type":"string","minLength":1},
            "revision":{"type":"object","additionalProperties":false,"required":["commit","tree"],"properties":{"commit":{"type":"string","pattern":"^[0-9a-f]{40}$"},"tree":{"type":"string","pattern":"^[0-9a-f]{40}$"}}},
            "tree_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
            "license":learning::license_schema(),
            "attribution":{"type":"string","minLength":1},
            "rights_reviewed":{"const":false},
            "entries":{"type":"array","items":entry_schema()},
            "entry_count":{"type":"integer","minimum":0,"maximum":learning::MAX_ENTRIES},
            "admitted_count":{"type":"integer","minimum":0,"maximum":learning::MAX_ENTRIES},
            "excluded_count":{"type":"integer","minimum":0,"maximum":learning::MAX_ENTRIES},
            "fallback_reason":{"type":["string","null"],"enum":fallback_reasons()},
            "raw_evidence":{"oneOf":[{"type":"null"},learning::evidence_schema()]},
            "retrieval":learning::retrieval_schema()
        },
        "oneOf":[
            {"properties":{"result":{"const":"catalog_snapshot"},"tree_sha":{"type":"string"},"fallback_reason":{"type":"null"},"raw_evidence":{"type":"null"}}},
            {"properties":{"result":{"const":"degraded"},"tree_sha":{"type":"null"},"fallback_reason":{"type":"string"},"raw_evidence":{"type":"object"},"entries":{"maxItems":0}}}
        ]
    })
}

fn bytes_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["schema_version","type","result","path","source","source_url","branch","revision","tree_sha","upstream_sha","size","material_class","admission_reason","license","attribution","rights_reviewed","license_notice_required","bytes","byte_encoding","byte_length","sha256","content_type","fallback_reason","raw_evidence","retrieval"],
        "properties":{
            "schema_version":{"const":1},
            "type":{"const":BYTES_TYPE},
            "result":{"enum":["raw_snapshot","degraded"]},
            "path":{"type":"string","minLength":1,"maxLength":learning::MAX_PATH},
            "source":{"type":"string","minLength":1},
            "source_url":{"type":"string","minLength":1},
            "branch":{"type":"string","minLength":1},
            "revision":{"type":"object","additionalProperties":false,"required":["commit","tree"],"properties":{"commit":{"type":"string","pattern":"^[0-9a-f]{40}$"},"tree":{"type":"string","pattern":"^[0-9a-f]{40}$"}}},
            "tree_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
            "upstream_sha":{"type":["string","null"],"pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$"},
            "size":{"type":["integer","null"],"minimum":1},
            "material_class":{"type":["string","null"],"enum":["reference_guide","license_notice",null]},
            "admission_reason":{"type":["string","null"]},
            "license":learning::license_schema(),
            "attribution":{"type":"string","minLength":1},
            "rights_reviewed":{"const":true},
            "license_notice_required":{"const":true},
            "bytes":{"type":["string","null"],"contentEncoding":"base64"},
            "byte_encoding":{"const":"base64"},
            "byte_length":{"type":["integer","null"],"minimum":0},
            "sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"},
            "content_type":{"type":["string","null"]},
            "fallback_reason":{"type":["string","null"],"enum":fallback_reasons()},
            "raw_evidence":{"oneOf":[{"type":"null"},learning::evidence_schema(),withheld_evidence_schema()]},
            "retrieval":learning::retrieval_schema()
        },
        "oneOf":[
            {"properties":{"result":{"const":"raw_snapshot"},"material_class":{"type":"string"},"admission_reason":{"type":"string"},"bytes":{"type":"string"},"byte_length":{"type":"integer"},"sha256":{"type":"string"},"content_type":{"type":"string"},"fallback_reason":{"type":"null"},"raw_evidence":{"type":"null"},"tree_sha":{"type":"string"},"upstream_sha":{"type":"string"},"size":{"type":"integer"}}},
            {"properties":{"result":{"const":"degraded"},"bytes":{"type":"null"},"byte_length":{"type":"null"},"sha256":{"type":"null"},"content_type":{"type":"null"},"fallback_reason":{"type":"string"},"raw_evidence":{"type":"object"}}}
        ]
    })
}

/// Machine-readable stdin/output contracts for CLI integration.
pub fn schema() -> Value {
    json!({
        "schema_version": 1,
        "description": "Rights-reviewed physics reference catalog and original-byte retrieval from one pinned public upstream revision. The catalog lists every item of the reviewed tree with its per-item rights verdict; an excluded item is never retrievable. Retrieval returns the exact original bytes of one admitted item after its Git object identity and declared length are verified, together with the license notice that must accompany any conveyed copy. Every request is cache-first and paced by the shared governor; no campus service, authentication or mutation exists here.",
        "catalog": {
            "input": {
                "type":"object","additionalProperties":false,"required":[],"properties":{},
                "description":"The catalog request takes no selector: the reviewed revision is pinned in the source. An empty input is accepted as this empty object."
            },
            "options":{"--online":"Permit cache-first commit resolution and its immutable recursive-tree request; no automatic retry, refresh or pagination."},
            "output":catalog_schema()
        },
        "retrieve": {
            "input": {
                "type":"object","additionalProperties":false,
                "required":["path","tree_sha","blob_sha","size","rights_reviewed"],
                "properties":{
                    "path":{"type":"string","minLength":1,"maxLength":learning::MAX_PATH,"description":"The exact repository-relative path of the reviewed item."},
                    "tree_sha":{"type":"string","pattern":"^[0-9a-f]{40}$","description":"The reviewed tree object of the pinned revision."},
                    "blob_sha":{"type":"string","pattern":"^([0-9a-f]{40}|[0-9a-f]{64})$","description":"The exact Git blob object of the reviewed item."},
                    "size":{"type":"integer","minimum":1,"description":"The exact declared length of the reviewed item."},
                    "rights_reviewed":{"const":true,"description":"The operator attests that its own use of the item is covered by the published rights verdict."}
                }
            },
            "options":{"--online":"Permit cache-first commit/tree resolution and the reviewed immutable blob request; no automatic retry or redirect."},
            "output":bytes_schema()
        },
        "errors": {"stream":"stderr","format":"JSON","fields":["schema_version","error","message"]}
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CacheStatus, Response};
    use std::collections::BTreeMap;

    /// A bounded JSON Schema checker for the constructs this module
    /// publishes. An unsupported type or pattern is a test failure rather
    /// than a silent pass; an unknown keyword would be ignored, so the
    /// published schemas use only the keywords handled here.
    fn schema_type(value: &Value, expected: &str) -> bool {
        match expected {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "null" => value.is_null(),
            "boolean" => value.is_boolean(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            other => panic!("unsupported schema type {other}"),
        }
    }

    /// Whether a number is below a published minimum. A negative integer is
    /// below every unsigned minimum, and an integer above the signed range
    /// is above every unsigned maximum.
    fn number_below(value: &Value, minimum: u64) -> bool {
        match (value.as_i64(), value.as_u64()) {
            (Some(number), _) => number < 0 || (number as u64) < minimum,
            (_, Some(number)) => number < minimum,
            _ => false,
        }
    }

    /// Whether a number is above a published maximum.
    fn number_above(value: &Value, maximum: u64) -> bool {
        match (value.as_i64(), value.as_u64()) {
            (Some(number), _) => number < 0 || (number as u64) > maximum,
            (_, Some(number)) => number > maximum,
            _ => false,
        }
    }

    fn validate(value: &Value, schema: &Value, path: &str) -> Result<(), String> {
        let fail = |message: &str| Err(format!("{path}: {message} for {value}"));
        if let Some(expected) = schema.get("const")
            && value != expected
        {
            return fail("const mismatch");
        }
        if let Some(expected) = schema.get("enum").and_then(Value::as_array)
            && !expected.contains(value)
        {
            return fail("enum mismatch");
        }
        if let Some(expected) = schema.get("type") {
            let matches = match expected {
                Value::String(kind) => schema_type(value, kind),
                Value::Array(kinds) => kinds
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|kind| schema_type(value, kind)),
                _ => false,
            };
            if !matches {
                return fail("type mismatch");
            }
        }
        if let Some(object) = value.as_object()
            && let Some(required) = schema.get("required").and_then(Value::as_array)
        {
            for key in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(key) {
                    return fail(&format!("missing required {key}"));
                }
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                for key in value.as_object().into_iter().flat_map(|map| map.keys()) {
                    if !properties.contains_key(key) {
                        return fail(&format!("additional property {key}"));
                    }
                }
            }
            for (key, subschema) in properties {
                if let Some(child) = value.get(key) {
                    validate(child, subschema, &format!("{path}.{key}"))?;
                }
            }
        }
        if let Some(items) = schema.get("items") {
            for (index, child) in value.as_array().into_iter().flatten().enumerate() {
                validate(child, items, &format!("{path}[{index}]"))?;
            }
        }
        if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64)
            && value.as_array().map_or(0, Vec::len) as u64 > maximum
        {
            return fail("too many items");
        }
        if let Some(minimum) = schema.get("minimum").and_then(Value::as_u64)
            && number_below(value, minimum)
        {
            return fail("below minimum");
        }
        if let Some(maximum) = schema.get("maximum").and_then(Value::as_u64)
            && number_above(value, maximum)
        {
            return fail("above maximum");
        }
        if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64)
            && value
                .as_str()
                .is_some_and(|text| (text.chars().count() as u64) < minimum)
        {
            return fail("too short");
        }
        if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64)
            && value
                .as_str()
                .is_some_and(|text| (text.chars().count() as u64) > maximum)
        {
            return fail("too long");
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str)
            && let Some(text) = value.as_str()
        {
            let matches = match pattern {
                "^[0-9a-f]{64}$" => learning::valid_sha256(text),
                "^([0-9a-f]{40}|[0-9a-f]{64})$" => learning::valid_upstream_sha(text),
                "^[0-9a-f]{40}$" => {
                    text.len() == 40
                        && text
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                }
                other => panic!("unsupported schema pattern {other}"),
            };
            if !matches {
                return fail("pattern mismatch");
            }
        }
        if let Some(alternatives) = schema.get("oneOf").and_then(Value::as_array) {
            let matched = alternatives
                .iter()
                .filter(|alternative| validate(value, alternative, path).is_ok())
                .count();
            if matched != 1 {
                return fail(&format!("oneOf matched {matched} alternatives"));
            }
        }
        Ok(())
    }

    /// The root tree object of the fixture, produced by native Git.
    const FIXTURE_TREE: &str = "e5a784b1ae0c9096068fa89d4de81e96279a32e0";

    /// A tree whose root and every directory object hash really cover the
    /// listed entries, as a recursive GitHub tree response does. The fixture
    /// was produced by native Git, so the shared object verifier accepts it.
    const TREE: &[u8] = br#"{"sha":"e5a784b1ae0c9096068fa89d4de81e96279a32e0","truncated":false,"tree":[
        {"path":".gitattributes","mode":"100644","type":"blob","sha":"7e37e196d32e23830e0148aed3ea247ca7cb55bf","size":19},
        {"path":"1021","mode":"040000","type":"tree","sha":"a48cbed7ce200822edb66838073176665ceeb130"},
        {"path":"1021/1","mode":"040000","type":"tree","sha":"75ab447e88b226f31cce6dcb96279f29074edc07"},
        {"path":"1021/1/main.m","mode":"100644","type":"blob","sha":"bcf10eff3fd4d0caab93a9ecc2ffcf13b813ad47","size":15},
        {"path":"1021/2","mode":"040000","type":"tree","sha":"da2cf0af95a9c10a3bc6b643ea19a41cfe987b9f"},
        {"path":"1021/2/paper.pdf","mode":"100644","type":"blob","sha":"ed99cee3dacec4fecf0e7b9704e95366686d1a1c","size":20},
        {"path":"1051","mode":"040000","type":"tree","sha":"37623ac41d00ec807a460c54db162d6d2f79ebbf"},
        {"path":"1051/Test.txt","mode":"100644","type":"blob","sha":"71da47a71055ab27ae256c112744db8fcf9b6af1","size":20},
        {"path":"LICENSE","mode":"100644","type":"blob","sha":"474503f3470a8b7e0e859945b2b866aeb7a3f096","size":35113},
        {"path":"README.md","mode":"100644","type":"blob","sha":"02427435071267252f752280278fbb8af6b1919b","size":6736}
    ]}"#;

    fn fixture_url() -> url::Url {
        url::Url::parse(&format!(
            "https://api.github.com/repos/wtdcode/BUAAPhyhelper/git/trees/{}",
            FIXTURE_TREE
        ))
        .unwrap()
    }

    fn response(url: &url::Url, body: &[u8]) -> Response {
        Response {
            url: url.as_str().to_owned(),
            status: 200,
            headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
            body: body.to_vec(),
            sha256: learning::sha256_hex(body),
            fetched_at_unix_ms: 1_700_000_000_000,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    /// The admitted fixture tree and the response it came from.
    fn admitted() -> (String, Vec<learning::TreeEntry>, Response) {
        let url = fixture_url();
        let response = response(&url, TREE);
        let identity = learning::observed_identity(
            learning::Surface::Tree,
            &url,
            &response.body,
            Some("application/json"),
        );
        let tree = identity.tree().expect("the fixture tree verifies");
        (tree.tree_sha.clone(), tree.entries.clone(), response)
    }

    #[test]
    fn only_the_reviewed_guide_and_license_are_admitted() {
        let (tree_sha, entries, response) = admitted();
        let snapshot = catalog_snapshot(&tree_sha, &entries, learning::retrieval(&response));
        let values = snapshot["entries"].as_array().unwrap();
        let find = |path: &str| {
            values
                .iter()
                .find(|value| value["path"] == json!(path))
                .unwrap()
                .clone()
        };
        assert_eq!(
            find("README.md")["material_class"],
            json!("reference_guide")
        );
        assert_eq!(find("README.md")["retrievable"], json!(true));
        assert_eq!(find("LICENSE")["material_class"], json!("license_notice"));
        assert_eq!(find("LICENSE")["retrievable"], json!(true));
        assert_eq!(
            find("1021/2/paper.pdf")["material_class"],
            json!("excluded")
        );
        assert_eq!(find("1021/2/paper.pdf")["retrievable"], json!(false));
        assert_eq!(find("1051/Test.txt")["material_class"], json!("excluded"));
        assert_eq!(find("1051/Test.txt")["retrievable"], json!(false));
        assert_eq!(find("1021/1/main.m")["material_class"], json!("excluded"));
        assert_eq!(find(".gitattributes")["material_class"], json!("excluded"));
        assert_eq!(snapshot["admitted_count"], json!(2));
        assert_eq!(snapshot["excluded_count"], json!(8));
        assert_eq!(snapshot["entry_count"], json!(10));
    }

    #[test]
    fn the_reviewed_license_is_bound_to_the_admitted_tree() {
        let (_, entries, _) = admitted();
        let license = license_value(&entries);
        assert_eq!(license["operator_reference"]["spdx_id"], json!("GPL-3.0"));
        assert_eq!(
            license["bound_license_blob_sha"],
            json!("474503f3470a8b7e0e859945b2b866aeb7a3f096")
        );
        assert_eq!(license["bound_license_size"], json!(35113));
        assert_eq!(license["independently_verified"], json!(false));
        assert_eq!(
            license["bound_license_url"],
            json!(
                "https://api.github.com/repos/wtdcode/BUAAPhyhelper/git/blobs/474503f3470a8b7e0e859945b2b866aeb7a3f096"
            )
        );
    }

    #[test]
    fn a_reviewed_object_identity_mismatch_is_not_admitted() {
        // The same paths with unreviewed object identities stay excluded.
        let (class, reason) = classify(
            "README.md",
            "ad1fa0d43c170e76768c04152e1d6ddfe3879f7c",
            Some(13),
        );
        assert_eq!(class, MaterialClass::Excluded);
        assert!(reason.contains("not_the_reviewed_guide"));
        assert!(!retrievable(class));
        let (class, reason) = classify(
            "LICENSE",
            "e6a86361c7f596424543a3d9a6c1362b8601204e",
            Some(15),
        );
        assert_eq!(class, MaterialClass::Excluded);
        assert!(reason.contains("not_the_reviewed_license"));
        let (class, reason) = classify(
            "LICENSE",
            "474503f3470a8b7e0e859945b2b866aeb7a3f096",
            Some(REVIEWED_LICENSE_SIZE),
        );
        assert_eq!(class, MaterialClass::License);
        assert!(retrievable(class));
        assert_eq!(reason, "verbatim_license_notice_of_the_reviewed_work");
    }

    #[test]
    fn a_retrieval_request_must_name_the_reviewed_identity() {
        let refused = parse_retrieve_input(
            r#"{"path":"README.md","tree_sha":"82655593cd3486549b5e49eec55ca9add1d3ccd4","blob_sha":"02427435071267252f752280278fbb8af6b1919b","size":6736}"#,
        )
        .unwrap_err();
        assert_eq!(refused.code, "authorization_required");
        let missing_attestation = parse_retrieve_input(
            r#"{"path":"README.md","tree_sha":"82655593cd3486549b5e49eec55ca9add1d3ccd4","blob_sha":"02427435071267252f752280278fbb8af6b1919b","size":6736,"rights_reviewed":false}"#,
        )
        .unwrap_err();
        assert_eq!(missing_attestation.code, "authorization_required");
        let wrong_tree = parse_retrieve_input(
            r#"{"path":"README.md","tree_sha":"1111111111111111111111111111111111111111","blob_sha":"02427435071267252f752280278fbb8af6b1919b","size":6736,"rights_reviewed":true}"#,
        )
        .unwrap_err();
        assert_eq!(wrong_tree.code, "invalid_input");
        let accepted = parse_retrieve_input(
            r#"{"path":"README.md","tree_sha":"82655593cd3486549b5e49eec55ca9add1d3ccd4","blob_sha":"02427435071267252f752280278fbb8af6b1919b","size":6736,"rights_reviewed":true}"#,
        )
        .unwrap();
        assert_eq!(accepted.path, "README.md");
        let credential = parse_retrieve_input(
            r#"{"path":"README.md","tree_sha":"82655593cd3486549b5e49eec55ca9add1d3ccd4","blob_sha":"02427435071267252f752280278fbb8af6b1919b","size":6736,"rights_reviewed":true,"password":"fixture-only"}"#,
        )
        .unwrap_err();
        assert_eq!(credential.code, "invalid_input");
        assert!(!credential.message.contains("fixture-only"));
    }

    #[test]
    fn the_catalog_rejects_an_unexpected_selector() {
        let refused = catalog(r#"{"path":"README.md"}"#, false).unwrap_err();
        assert_eq!(refused.code, "invalid_input");
        let refused = catalog("not json", false).unwrap_err();
        assert_eq!(refused.code, "invalid_input");
    }

    #[test]
    fn the_published_schema_matches_the_published_shapes() {
        let (tree_sha, entries, response) = admitted();
        let snapshot = catalog_snapshot(&tree_sha, &entries, learning::retrieval(&response));
        validate(&snapshot, &catalog_schema(), "$").unwrap();
    }

    #[test]
    fn a_positional_retrieval_request_is_not_a_request_object() {
        // The published input schema requires an object. A positional array
        // must never reach cache or network processing.
        let refused = parse_retrieve_input(
            r#"["README.md","82655593cd3486549b5e49eec55ca9add1d3ccd4","02427435071267252f752280278fbb8af6b1919b",6736,true]"#,
        )
        .unwrap_err();
        assert_eq!(refused.code, "invalid_input");
        let refused = parse_retrieve_input("[]").unwrap_err();
        assert_eq!(refused.code, "invalid_input");
    }

    #[test]
    fn withheld_bytes_are_never_encoded_into_the_output() {
        // A response that is not the reviewed object never passed the
        // per-item rights admission, so its bytes are withheld and only the
        // length, digest and reason are reported.
        let url = fixture_url();
        let body = b"bytes that never matched an admitted object";
        let response = response(&url, body);
        let evidence = withheld_evidence(&response, "blob_identity_mismatch");
        assert_eq!(evidence["kind"], json!("withheld_response"));
        assert_eq!(evidence["data"], Value::Null);
        assert_eq!(evidence["byte_length"], json!(body.len()));
        assert_eq!(evidence["sha256"], json!(learning::sha256_hex(body)));
        assert_eq!(evidence["fallback_reason"], json!("blob_identity_mismatch"));
        assert!(!evidence.to_string().contains("never matched an admitted"));
        validate(&evidence, &withheld_evidence_schema(), "$").unwrap();
    }

    #[test]
    fn a_rejected_blob_response_never_discloses_its_bytes() {
        // A response that is not the reviewed object is withheld: the output
        // carries the length, the digest and the reason, never the bytes.
        let request = RetrieveInput {
            path: "README.md".to_owned(),
            tree_sha: REVISION.tree.to_owned(),
            blob_sha: REVIEWED_GUIDE_BLOB.to_owned(),
            size: REVIEWED_GUIDE_SIZE,
            rights_reviewed: Some(true),
        };
        let url = url::Url::parse(&format!(
            "https://api.github.com/repos/wtdcode/BUAAPhyhelper/git/blobs/{REVIEWED_GUIDE_BLOB}"
        ))
        .unwrap();
        let body = b"bytes of an item that never passed the rights admission";
        let mut response = response(&url, body);
        response.headers = BTreeMap::from([("content-type".to_owned(), "text/plain".to_owned())]);
        // The response does not hash to the requested object, so the shared
        // identity check reports a different blob identity.
        let identity = learning::observed_identity(
            learning::Surface::Raw,
            &url,
            &response.body,
            Some("text/plain"),
        );
        let output = raw_bytes_output(
            &response,
            &identity,
            &request,
            MaterialClass::Guide,
            "author_written_original_processing_guide",
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
        validate(&output, &bytes_schema(), "$").unwrap();
    }

    #[test]
    fn an_admitted_blob_response_matches_the_published_bytes_schema() {
        let request = RetrieveInput {
            path: "README.md".to_owned(),
            tree_sha: REVISION.tree.to_owned(),
            blob_sha: REVIEWED_GUIDE_BLOB.to_owned(),
            size: REVIEWED_GUIDE_SIZE,
            rights_reviewed: Some(true),
        };
        let url = url::Url::parse(&format!(
            "https://api.github.com/repos/wtdcode/BUAAPhyhelper/git/blobs/{REVIEWED_GUIDE_BLOB}"
        ))
        .unwrap();
        // The exact bytes of the reviewed object.
        let body = b"the reviewed guide bytes";
        let mut response = response(&url, body);
        response.headers = BTreeMap::from([("content-type".to_owned(), "text/plain".to_owned())]);
        let identity = learning::observed_identity(
            learning::Surface::Raw,
            &url,
            &response.body,
            Some("text/plain"),
        );
        let blob_sha = identity.blob_sha().unwrap().to_owned();
        let mut request = request;
        request.blob_sha = blob_sha;
        request.size = body.len() as u64;
        let output = raw_bytes_output(
            &response,
            &identity,
            &request,
            MaterialClass::Guide,
            "author_written_original_processing_guide",
            learning::unknown_license(),
        )
        .unwrap();
        assert_eq!(output["result"], json!("raw_snapshot"));
        assert_eq!(output["byte_length"], json!(body.len()));
        assert_eq!(output["sha256"], json!(learning::sha256_hex(body)));
        validate(&output, &bytes_schema(), "$").unwrap();
    }

    #[test]
    fn the_degraded_catalog_matches_the_published_schema() {
        // A tree that cannot be admitted stays a degraded success: the
        // original bytes are the inspectable evidence and no entry is
        // published.
        let url = fixture_url();
        let response = response(&url, b"{\"truncated\":true,\"tree\":[]}");
        let identity = learning::observed_identity(
            learning::Surface::Tree,
            &url,
            &response.body,
            Some("application/json"),
        );
        assert!(identity.tree().is_none());
        let output = degraded_catalog(&response, &identity, "incomplete_tree").unwrap();
        assert_eq!(output["result"], json!("degraded"));
        assert!(output["tree_sha"].is_null());
        assert!(output["entries"].as_array().unwrap().is_empty());
        assert_eq!(output["fallback_reason"], json!("incomplete_tree"));
        validate(&output, &catalog_schema(), "$").unwrap();
    }

    #[test]
    fn a_content_type_degraded_retrieval_matches_the_published_schema() {
        // The bytes are the reviewed object, but the declared media type is
        // not one this client admits, so the result stays degraded and the
        // original bytes are the inspectable evidence.
        let request = RetrieveInput {
            path: "README.md".to_owned(),
            tree_sha: REVISION.tree.to_owned(),
            blob_sha: REVIEWED_GUIDE_BLOB.to_owned(),
            size: REVIEWED_GUIDE_SIZE,
            rights_reviewed: Some(true),
        };
        let url = url::Url::parse(&format!(
            "https://api.github.com/repos/wtdcode/BUAAPhyhelper/git/blobs/{REVIEWED_GUIDE_BLOB}"
        ))
        .unwrap();
        let body = b"the reviewed guide bytes";
        let mut response = response(&url, body);
        response.headers = BTreeMap::from([(
            "content-type".to_owned(),
            "application/x-unreviewed".to_owned(),
        )]);
        let identity = learning::observed_identity(
            learning::Surface::Raw,
            &url,
            &response.body,
            Some("application/x-unreviewed"),
        );
        let mut request = request;
        request.blob_sha = identity.blob_sha().unwrap().to_owned();
        request.size = body.len() as u64;
        let output = raw_bytes_output(
            &response,
            &identity,
            &request,
            MaterialClass::Guide,
            "author_written_original_processing_guide",
            learning::unknown_license(),
        )
        .unwrap();
        assert_eq!(output["result"], json!("degraded"));
        assert_eq!(output["fallback_reason"], json!("unexpected_content"));
        assert!(output["bytes"].is_null());
        validate(&output, &bytes_schema(), "$").unwrap();
    }

    #[test]
    fn the_schema_checker_catches_mutated_outputs() {
        // The checker is the regression oracle for the published schemas, so
        // it must reject the mutations it is meant to catch.
        let (tree_sha, entries, response) = admitted();
        let snapshot = catalog_snapshot(&tree_sha, &entries, learning::retrieval(&response));
        validate(&snapshot, &catalog_schema(), "$").unwrap();

        let mut negative = snapshot.clone();
        negative["entry_count"] = json!(-1);
        assert!(validate(&negative, &catalog_schema(), "$").is_err());

        let mut oversized = snapshot.clone();
        oversized["retrieval"]["response_body_byte_length"] = json!(16_777_217u64);
        assert!(validate(&oversized, &catalog_schema(), "$").is_err());

        // An integer above the signed range must not escape the maximum.
        let mut huge = snapshot.clone();
        huge["retrieval"]["response_body_byte_length"] = json!(u64::MAX);
        assert!(validate(&huge, &catalog_schema(), "$").is_err());

        let mut huge_count = snapshot.clone();
        huge_count["entry_count"] = json!(u64::MAX);
        assert!(validate(&huge_count, &catalog_schema(), "$").is_err());

        let mut extra = snapshot.clone();
        extra["unexpected"] = json!(true);
        assert!(validate(&extra, &catalog_schema(), "$").is_err());

        let mut missing = snapshot.clone();
        missing.as_object_mut().unwrap().remove("admitted_count");
        assert!(validate(&missing, &catalog_schema(), "$").is_err());

        let mut wrong_class = snapshot.clone();
        wrong_class["entries"][0]["material_class"] = json!("guide");
        assert!(validate(&wrong_class, &catalog_schema(), "$").is_err());

        let mut wrong_sha = snapshot.clone();
        wrong_sha["entries"][0]["upstream_sha"] = json!("NOTHEX");
        assert!(validate(&wrong_sha, &catalog_schema(), "$").is_err());
    }

    #[test]
    fn the_published_schema_wires_the_published_shapes() {
        let published = schema();
        let (tree_sha, entries, tree_response) = admitted();
        let snapshot = catalog_snapshot(&tree_sha, &entries, learning::retrieval(&tree_response));
        validate(&snapshot, &published["catalog"]["output"], "$").unwrap();
        // The published input schema is an object form, so the request the
        // module accepts is the object the schema describes.
        let request = json!({
            "path": "README.md",
            "tree_sha": REVISION.tree,
            "blob_sha": REVIEWED_GUIDE_BLOB,
            "size": REVIEWED_GUIDE_SIZE,
            "rights_reviewed": true,
        });
        validate(&request, &published["retrieve"]["input"], "$").unwrap();
        // The retrieval output the module publishes validates against the
        // published retrieval output contract as well.
        let url = url::Url::parse(&format!(
            "https://api.github.com/repos/wtdcode/BUAAPhyhelper/git/blobs/{REVIEWED_GUIDE_BLOB}"
        ))
        .unwrap();
        let body = b"the reviewed guide bytes";
        let mut response = response(&url, body);
        response.headers = BTreeMap::from([("content-type".to_owned(), "text/plain".to_owned())]);
        let identity = learning::observed_identity(
            learning::Surface::Raw,
            &url,
            &response.body,
            Some("text/plain"),
        );
        let request = RetrieveInput {
            path: "README.md".to_owned(),
            tree_sha: REVISION.tree.to_owned(),
            blob_sha: identity.blob_sha().unwrap().to_owned(),
            size: body.len() as u64,
            rights_reviewed: Some(true),
        };
        let output = raw_bytes_output(
            &response,
            &identity,
            &request,
            MaterialClass::Guide,
            "author_written_original_processing_guide",
            learning::unknown_license(),
        )
        .unwrap();
        validate(&output, &published["retrieve"]["output"], "$").unwrap();
    }
}
