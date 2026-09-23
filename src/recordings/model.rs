//! Original interoperability types for reviewed, non-sensitive catalog fields.
//! No private implementation, record, credential, endpoint or default is copied.
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct Asset {
    pub id: String,
    pub kind: String,
    pub bucket: String,
    pub object_key: String,
    pub sha256: String,
    pub bytes: u64,
    pub mime_type: Option<String>,
    pub captured_at: Option<String>,
    pub ingested_at: String,
    pub source: Option<String>,
    pub language: Option<String>,
    pub privacy: String,
}

#[derive(Serialize)]
pub(crate) struct Segment {
    pub id: i64,
    pub asset_id: String,
    pub segment_index: i64,
    pub start_ms: Option<i64>,
    pub end_ms: Option<i64>,
    pub speaker: Option<String>,
    pub language: Option<String>,
    pub text: String,
}

pub(crate) struct Relation {
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub relation: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub(crate) struct ProvenanceLink {
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub relation: String,
    pub created_at: String,
    pub source_sha256: Option<String>,
    pub target_sha256: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ProvenanceIssue {
    pub kind: &'static str,
    pub asset_id: String,
}

#[derive(Serialize)]
pub(crate) struct Provenance {
    pub segment_asset: Option<Asset>,
    pub original_assets: Vec<Asset>,
    pub links: Vec<ProvenanceLink>,
    pub issues: Vec<ProvenanceIssue>,
    pub complete: bool,
    pub hash_verification: &'static str,
}
