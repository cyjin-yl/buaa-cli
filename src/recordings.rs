//! Read-only, operator-authorized lookup over a Life-compatible local catalog.
//! This module does not retrieve media objects or authenticate to any service.
mod catalog;
mod model;
mod provenance;
#[cfg(test)]
mod test_support;

use crate::net::Error;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

const MAX_INPUT: usize = 32 * 1024;
const MAX_CURSOR: usize = 2048;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    catalog: String,
    query: String,
    #[serde(default)]
    authorized: bool,
    asset_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    cursor: Option<String>,
}

fn default_limit() -> usize {
    20
}
fn invalid() -> Error {
    Error::new(
        "invalid_input",
        "Invalid recording catalog query or cursor.",
    )
}
fn unavailable() -> Error {
    Error::new(
        "unavailable",
        "Recording catalog result cannot be represented safely.",
    )
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    catalog_binding: String,
    query_binding: String,
    last_id: i64,
}

fn decode_cursor(value: &str) -> Result<Cursor, Error> {
    if value.len() > MAX_CURSOR {
        return Err(invalid());
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid())?;
    let cursor: Cursor = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if cursor.version != 1
        || [&cursor.catalog_binding, &cursor.query_binding]
            .iter()
            .any(|value| value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(invalid());
    }
    Ok(cursor)
}

/// Query local catalog records only. `authorized` is an operator attestation,
/// not proof of media rights or a grant of campus/remote-service permission.
pub fn search(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: SearchInput = serde_json::from_str(input).map_err(|_| invalid())?;
    if !request.authorized {
        return Err(Error::new(
            "permission",
            "Explicit operator authorization for this local catalog is required.",
        ));
    }
    let phrase = request.query.trim();
    if request.catalog.len() > 4096
        || !Path::new(&request.catalog).is_absolute()
        || request.catalog.contains('\0')
        || phrase.is_empty()
        || phrase.len() > 4096
        || phrase.contains('\0')
        || !(1..=100).contains(&request.limit)
        || request
            .asset_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
    {
        return Err(invalid());
    }
    let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
    let query_binding =
        digest(&serde_json::to_vec(&(phrase, &request.asset_id)).map_err(|_| invalid())?);
    let catalog = catalog::Catalog::open(Path::new(&request.catalog))?;
    let binding = catalog.fingerprint().to_owned();
    let after_id = match cursor {
        Some(cursor) => {
            if cursor.catalog_binding != binding || cursor.query_binding != query_binding {
                return Err(invalid());
            }
            Some(cursor.last_id)
        }
        None => None,
    };
    let mut segments = catalog.search_segments(
        phrase,
        request.asset_id.as_deref(),
        after_id,
        request.limit + 1,
    )?;
    let more = segments.len() > request.limit;
    segments.truncate(request.limit);
    let next_cursor = if more {
        let last_id = segments.last().ok_or_else(unavailable)?.id;
        Some(
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Cursor {
                    version: 1,
                    catalog_binding: binding.clone(),
                    query_binding: query_binding.clone(),
                    last_id,
                })
                .map_err(|_| unavailable())?,
            ),
        )
    } else {
        None
    };
    let mut asset_provenance = BTreeMap::new();
    let mut hits = Vec::with_capacity(segments.len());
    for segment in segments {
        if !asset_provenance.contains_key(&segment.asset_id) {
            let resolved = provenance::resolve(&catalog, &segment.asset_id)?;
            asset_provenance.insert(segment.asset_id.clone(), resolved);
        }
        let text_sha256 = digest(segment.text.as_bytes());
        hits.push(json!({"segment":segment,"text_sha256":text_sha256,"text_hash_scope":"retrieved_segment_utf8_only"}));
    }
    Ok(json!({
        "schema_version":1,
        "type":"recording_search",
        "result":if hits.is_empty() {"no_matching_segments"} else {"segments_found"},
        "catalog":{"contract":"life-compatible-catalog-fields-v1","identity_binding":binding,"binding_is_content_hash":false,"read_only":true,"snapshot_scope":"single_request"},
        "authorization":{"basis":"operator_attestation","media_rights_verified":false},
        "query":{"phrase_sha256":digest(phrase.as_bytes()),"match_mode":"literal_phrase_unicode61","asset_id":request.asset_id,"limit":request.limit},
        "hits":hits,
        "provenance":asset_provenance,
        "next_cursor":next_cursor,
        "completeness":{"scope":"provided_catalog","more_results":more,"frozen_snapshot_across_requests":false,"complete_history":false},
        "network_access":false,
        "source_objects_fetched":false
    }))
}

/// Standalone input/output JSON schemas for the local search operation.
pub fn schema() -> Value {
    let optional_text = json!({"type":["string","null"]});
    let hash = json!({"type":"string","pattern":"^[0-9a-f]{64}$"});
    let asset = json!({"type":"object","additionalProperties":false,
        "required":["id","kind","bucket","object_key","sha256","bytes","mime_type","captured_at","ingested_at","source","language","privacy"],
        "properties":{"id":{"type":"string"},"kind":{"enum":["audio","video","transcript","derived","manifest"]},
            "bucket":{"type":"string"},"object_key":{"type":"string"},"sha256":hash,"bytes":{"type":"integer","minimum":0},
            "mime_type":optional_text,"captured_at":{"type":["string","null"],"description":"Literal catalog value; never inferred from ingestion time."},
            "ingested_at":{"type":"string"},"source":optional_text,"language":optional_text,"privacy":{"enum":["private","shared","public"]}}});
    let segment = json!({"type":"object","additionalProperties":false,
        "required":["id","asset_id","segment_index","start_ms","end_ms","speaker","language","text"],
        "properties":{"id":{"type":"integer","minimum":i64::MIN,"maximum":i64::MAX},"asset_id":{"type":"string"},"segment_index":{"type":"integer","minimum":0},"start_ms":{"type":["integer","null"],"minimum":0},"end_ms":{"type":["integer","null"],"minimum":0},
            "speaker":optional_text,"language":optional_text,"text":{"type":"string"}}});
    let link = json!({"type":"object","additionalProperties":false,
        "required":["source_asset_id","target_asset_id","relation","created_at","source_sha256","target_sha256"],
        "properties":{"source_asset_id":{"type":"string"},"target_asset_id":{"type":"string"},"relation":{"enum":["transcript_of","derived_from"]},
            "created_at":{"type":"string"},"source_sha256":{"anyOf":[hash,{"type":"null"}]},"target_sha256":{"anyOf":[hash,{"type":"null"}]}}});
    let provenance = json!({"type":"object","additionalProperties":false,
        "required":["segment_asset","original_assets","links","issues","complete","hash_verification"],
        "properties":{"segment_asset":{"anyOf":[asset,{"type":"null"}]},"original_assets":{"type":"array","items":asset},
            "links":{"type":"array","items":link},"issues":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["kind","asset_id"],"properties":{"kind":{"enum":["missing_asset","cycle_detected","depth_limit","node_limit","edge_limit","no_original"]},"asset_id":{"type":"string"}}}},
            "complete":{"type":"boolean"},"hash_verification":{"const":"catalog_declared_not_blob_verified"}}});
    json!({"search":{
        "input":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["catalog","query"],
            "properties":{"catalog":{"type":"string","minLength":1,"maxLength":4096,"description":"Absolute local SQLite path; UTF-8 byte bound applies. Not a remote URI."},
                "query":{"type":"string","minLength":1,"maxLength":4096,"description":"Literal text phrase under the catalog's unicode61 FTS tokenizer; UTF-8 byte bound applies."},
                "authorized":{"type":"boolean","default":false,"description":"Must be true to attest operator permission; does not verify rights or grant remote access."},
                "asset_id":{"type":["string","null"],"minLength":1,"maxLength":256},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},
                "cursor":{"type":["string","null"],"maxLength":MAX_CURSOR}}},
        "output":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
            "required":["schema_version","type","result","catalog","authorization","query","hits","provenance","next_cursor","completeness","network_access","source_objects_fetched"],
            "properties":{"schema_version":{"const":1},"type":{"const":"recording_search"},"result":{"enum":["no_matching_segments","segments_found"]},
                "catalog":{"type":"object","additionalProperties":false,"required":["contract","identity_binding","binding_is_content_hash","read_only","snapshot_scope"],"properties":{"contract":{"const":"life-compatible-catalog-fields-v1"},"identity_binding":hash,"binding_is_content_hash":{"const":false},"read_only":{"const":true},"snapshot_scope":{"const":"single_request"}}},
                "authorization":{"type":"object","additionalProperties":false,"required":["basis","media_rights_verified"],"properties":{"basis":{"const":"operator_attestation"},"media_rights_verified":{"const":false}}},
                "query":{"type":"object","additionalProperties":false,"required":["phrase_sha256","match_mode","asset_id","limit"],"properties":{"phrase_sha256":hash,"match_mode":{"const":"literal_phrase_unicode61"},"asset_id":optional_text,"limit":{"type":"integer","minimum":1,"maximum":100}}},
                "hits":{"type":"array","maxItems":100,"items":{"type":"object","additionalProperties":false,"required":["segment","text_sha256","text_hash_scope"],"properties":{"segment":segment,"text_sha256":hash,"text_hash_scope":{"const":"retrieved_segment_utf8_only"}}}},
                "provenance":{"type":"object","additionalProperties":provenance},"next_cursor":{"type":["string","null"],"maxLength":MAX_CURSOR},
                "completeness":{"type":"object","additionalProperties":false,"required":["scope","more_results","frozen_snapshot_across_requests","complete_history"],"properties":{"scope":{"const":"provided_catalog"},"more_results":{"type":"boolean"},"frozen_snapshot_across_requests":{"const":false},"complete_history":{"const":false}}},
                "network_access":{"const":false},"source_objects_fetched":{"const":false}}}
    }})
}

#[cfg(test)]
mod tests {
    use super::test_support::Fixture;
    use super::*;

    fn request(fixture: &Fixture, phrase: &str) -> Value {
        json!({"catalog":fixture.path,"query":phrase,"authorized":true,"limit":1})
    }

    #[test]
    fn pagination_preserves_declared_source_hashes_and_unknown_times() {
        let fixture = Fixture::new();
        fixture.asset("original", "audio", &"0".repeat(64));
        fixture.asset("transcript", "transcript", &"1".repeat(64));
        fixture.relate("transcript", "original", "transcript_of");
        let first_id = fixture.segment("transcript", 0, "algebra introduction", None, None);
        let second_id =
            fixture.segment("transcript", 1, "algebra examples", Some(1000), Some(2000));
        fixture.segment(
            "transcript",
            2,
            "unrelated material",
            Some(2000),
            Some(3000),
        );
        let mut input = request(&fixture, "algebra");
        let first = search(&input.to_string()).unwrap();
        assert_eq!(first["hits"][0]["segment"]["id"], first_id);
        assert!(first["hits"][0]["segment"]["start_ms"].is_null());
        assert!(first["provenance"]["transcript"]["original_assets"][0]["captured_at"].is_null());
        assert_eq!(
            first["provenance"]["transcript"]["segment_asset"]["sha256"],
            "1".repeat(64)
        );
        assert_eq!(
            first["provenance"]["transcript"]["original_assets"][0]["sha256"],
            "0".repeat(64)
        );
        assert_eq!(
            first["provenance"]["transcript"]["hash_verification"],
            "catalog_declared_not_blob_verified"
        );
        input["cursor"] = first["next_cursor"].clone();
        let second = search(&input.to_string()).unwrap();
        assert_eq!(second["hits"][0]["segment"]["id"], second_id);
        assert_eq!(second["hits"].as_array().unwrap().len(), 1);
        assert!(second["next_cursor"].is_null());
    }

    #[test]
    fn cursor_cannot_cross_query_filter_or_catalog_identity() {
        let fixture = Fixture::new();
        fixture.asset("one", "audio", &"a".repeat(64));
        fixture.segment("one", 0, "needle first", None, None);
        fixture.segment("one", 1, "needle second", None, None);
        let mut input = request(&fixture, "needle");
        input["cursor"] = search(&input.to_string()).unwrap()["next_cursor"].clone();
        let original = input.clone();
        input["query"] = json!("different");
        assert_eq!(
            search(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
        input = original.clone();
        input["asset_id"] = json!("one");
        assert_eq!(
            search(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
        let other = Fixture::new();
        input = original;
        input["catalog"] = json!(other.path);
        assert_eq!(
            search(&input.to_string()).unwrap_err().code,
            "invalid_input"
        );
    }

    #[test]
    fn operator_authorization_is_required_before_catalog_access() {
        let fixture = Fixture::new();
        let missing = fixture.path.with_file_name("sensitive-sentinel.sqlite");
        let input = json!({"catalog":missing,"query":"private-sentinel","authorized":false});
        let error = search(&input.to_string()).unwrap_err();
        assert_eq!(error.code, "permission");
        assert!(!error.message.contains("sentinel"));
        assert!(!missing.exists());
        let invalid_json = "{private-sentinel";
        assert_eq!(search(invalid_json).unwrap_err().code, "invalid_input");
    }

    #[test]
    fn signed_sqlite_rowids_are_searchable_and_paginated() {
        let fixture = Fixture::new();
        fixture.asset("original", "audio", &"0".repeat(64));
        fixture.asset("transcript", "transcript", &"1".repeat(64));
        fixture.relate("transcript", "original", "transcript_of");
        let connection = fixture.db();
        for (id, segment_index) in [(-1_i64, 0_i64), (0, 1), (1, 2)] {
            connection
                .execute(
                    "INSERT INTO transcript_segment(id,asset_id,segment_index,text) VALUES(?1,?2,?3,?4)",
                    rusqlite::params![id, "transcript", segment_index, format!("needle id {id}")],
                )
                .unwrap();
        }
        drop(connection);

        let mut input = request(&fixture, "needle");
        let mut ids = Vec::new();
        for _ in 0..3 {
            let page = search(&input.to_string()).unwrap();
            let hits = page["hits"].as_array().unwrap();
            assert_eq!(hits.len(), 1);
            ids.push(hits[0]["segment"]["id"].as_i64().unwrap());
            input["cursor"] = page["next_cursor"].clone();
        }
        assert_eq!(ids, vec![-1, 0, 1]);
        assert!(input["cursor"].is_null());
        let segment_schema =
            schema()["search"]["output"]["properties"]["hits"]["items"]["properties"]["segment"]
                .clone();
        let id_schema = segment_schema["properties"]["id"].clone();
        assert_eq!(id_schema["minimum"].as_i64(), Some(i64::MIN));
        assert_eq!(id_schema["maximum"].as_i64(), Some(i64::MAX));

        assert_eq!(
            segment_schema["properties"]["start_ms"]["type"],
            serde_json::json!(["integer", "null"])
        );
        assert_eq!(
            segment_schema["properties"]["end_ms"]["type"],
            serde_json::json!(["integer", "null"])
        );
    }
}
