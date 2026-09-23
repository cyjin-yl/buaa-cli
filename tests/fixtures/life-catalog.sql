-- Original synthetic fixture implementing only the reviewed field contract.
-- No private source SQL, records, credentials or operational values are copied.
CREATE TABLE asset (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    bucket TEXT NOT NULL,
    object_key TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    mime_type TEXT,
    captured_at TEXT,
    ingested_at TEXT NOT NULL,
    source TEXT,
    language TEXT,
    privacy TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE TABLE asset_relation (
    source_asset_id TEXT NOT NULL,
    target_asset_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (source_asset_id, target_asset_id, relation)
);
CREATE TABLE transcript_segment (
    id INTEGER PRIMARY KEY,
    asset_id TEXT NOT NULL,
    segment_index INTEGER NOT NULL,
    start_ms INTEGER,
    end_ms INTEGER,
    speaker TEXT,
    language TEXT,
    text TEXT NOT NULL
);
CREATE VIRTUAL TABLE transcript_fts USING fts5(
    text, speaker,
    content='transcript_segment', content_rowid='id', tokenize='unicode61'
);
CREATE TRIGGER fixture_segment_insert AFTER INSERT ON transcript_segment BEGIN
    INSERT INTO transcript_fts(rowid, text, speaker) VALUES (new.id, new.text, new.speaker);
END;
