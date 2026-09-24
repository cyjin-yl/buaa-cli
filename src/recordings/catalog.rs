//! Local, read-only catalog access. A transaction pins one query's snapshot.
//!
//! Normal SQLite WAL locking is retained: a WAL database needs readable sidecars
//! and SQLite may create/update its coordination sidecars when permitted. We do
//! not use `immutable`, alter journal mode, or write catalog/schema contents.
use super::model::{Asset, Relation, Segment};
use crate::net::Error;
use rusqlite::{
    Connection, OpenFlags, Row, config::DbConfig, limits::Limit, params, types::ValueRef,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::Path;
use std::time::Duration;

const MAX_FIELD: usize = 4096;
const MAX_TEXT: usize = 1024 * 1024;
const MAX_PAGE_TEXT: usize = 8 * 1024 * 1024;
const MAX_SCHEMA: usize = 16 * 1024;

pub(crate) struct Catalog {
    connection: Connection,
    fingerprint: String,
}

impl Catalog {
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        let raw = path.as_os_str().as_bytes();
        if raw.starts_with(b"file:") || raw.windows(3).any(|part| part == b"://") {
            return Err(invalid_input());
        }
        let canonical = fs::canonicalize(path).map_err(|_| unavailable())?;
        let metadata = fs::metadata(&canonical).map_err(|_| unavailable())?;
        if !metadata.is_file() {
            return Err(invalid_input());
        }
        // In particular, omit SQLITE_OPEN_URI and SQLITE_OPEN_CREATE.
        let connection = Connection::open_with_flags(
            &canonical,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| unavailable())?;
        connection
            .busy_timeout(Duration::from_millis(250))
            .map_err(|_| unavailable())?;
        for (category, bound) in [
            (Limit::SQLITE_LIMIT_LENGTH, 2 * MAX_TEXT as i32),
            (Limit::SQLITE_LIMIT_SQL_LENGTH, 64 * 1024),
            (Limit::SQLITE_LIMIT_COLUMN, 128),
            (Limit::SQLITE_LIMIT_EXPR_DEPTH, 32),
            (Limit::SQLITE_LIMIT_COMPOUND_SELECT, 8),
            (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 16),
            (Limit::SQLITE_LIMIT_ATTACHED, 0),
        ] {
            connection
                .set_limit(category, bound)
                .map_err(|_| unavailable())?;
        }
        connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| unavailable())?;
        // One cumulative budget for schema validation, search and provenance.
        let mut remaining = 20_000usize;
        connection.progress_handler(
            1000,
            Some(move || {
                if remaining == 0 {
                    return true;
                }
                remaining -= 1;
                false
            }),
        );
        connection
            .execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN DEFERRED;")
            .map_err(|_| unavailable())?;
        validate_schema(&connection)?;
        let current = fs::metadata(&canonical).map_err(|_| unavailable())?;
        if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
            return Err(unavailable());
        }
        let mut hash = Sha256::new();
        hash.update(b"buaa-cli:recording-catalog-identity:v1\0");
        let name = canonical.as_os_str().as_bytes();
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name);
        hash.update(metadata.dev().to_be_bytes());
        hash.update(metadata.ino().to_be_bytes());
        Ok(Self {
            connection,
            fingerprint: format!("{:x}", hash.finalize()),
        })
    }

    /// Identity, not a content hash or a cross-request snapshot guarantee.
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn search_segments(
        &self,
        phrase: &str,
        asset_id: Option<&str>,
        after_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<Segment>, Error> {
        if phrase.trim().is_empty()
            || phrase.len() > MAX_FIELD
            || !(1..=101).contains(&limit)
            || asset_id.is_some_and(|id| id.is_empty() || id.len() > MAX_FIELD)
        {
            return Err(invalid_input());
        }
        // FTS5 quoted phrases escape quotes by doubling them. Both the column
        // restriction and quoting are generated here, never supplied as syntax.
        let mut literal = String::with_capacity(phrase.len() * 2 + 9);
        literal.push_str("text : \"");
        for character in phrase.chars() {
            literal.push(character);
            if character == '"' {
                literal.push('"');
            }
        }
        literal.push('"');
        let mut statement = match after_id {
            None => self.connection.prepare(
                "SELECT s.id,s.asset_id,s.segment_index,s.start_ms,s.end_ms,s.speaker,s.language,s.text
                 FROM transcript_fts JOIN transcript_segment AS s ON transcript_fts.rowid=s.id
                 WHERE transcript_fts MATCH ?1 AND (?2 IS NULL OR s.asset_id COLLATE BINARY=?2)
                 ORDER BY s.id LIMIT ?3",
            ),
            Some(_) => self.connection.prepare(
                "SELECT s.id,s.asset_id,s.segment_index,s.start_ms,s.end_ms,s.speaker,s.language,s.text
                 FROM transcript_fts JOIN transcript_segment AS s ON transcript_fts.rowid=s.id
                 WHERE transcript_fts MATCH ?1 AND (?2 IS NULL OR s.asset_id COLLATE BINARY=?2) AND s.id>?3
                 ORDER BY s.id LIMIT ?4",
            ),
        }
        .map_err(|_| unavailable())?;
        let mut rows = match after_id {
            Some(after_id) => statement.query(params![literal, asset_id, after_id, limit as i64]),
            None => statement.query(params![literal, asset_id, limit as i64]),
        }
        .map_err(|_| unavailable())?;
        let mut result = Vec::new();
        let mut text_bytes = 0usize;
        while let Some(row) = rows.next().map_err(|_| unavailable())? {
            let segment_text = text(row, 7, MAX_TEXT)?;
            text_bytes += segment_text.len();
            if text_bytes > MAX_PAGE_TEXT {
                return Err(Error::new(
                    "unavailable",
                    "recording segment page exceeds the byte limit; reduce page size",
                ));
            }
            let start_ms = optional_integer(row, 3)?;
            let end_ms = optional_integer(row, 4)?;
            if matches!((start_ms, end_ms), (Some(start), Some(end)) if end < start) {
                return Err(invalid_data());
            }
            result.push(Segment {
                id: signed_integer(row, 0)?,
                asset_id: identifier(row, 1)?,
                segment_index: integer(row, 2)?,
                start_ms,
                end_ms,
                speaker: optional_text(row, 5)?,
                language: optional_text(row, 6)?,
                text: segment_text.to_owned(),
            });
        }
        Ok(result)
    }

    pub(crate) fn asset(&self, id: &str) -> Result<Option<Asset>, Error> {
        validate_id(id)?;
        let mut statement = self.connection.prepare(
            "SELECT id,kind,bucket,object_key,sha256,bytes,mime_type,captured_at,ingested_at,source,language,privacy
             FROM asset WHERE id COLLATE BINARY=?1",
        ).map_err(|_| unavailable())?;
        let mut rows = statement.query([id]).map_err(|_| unavailable())?;
        let Some(row) = rows.next().map_err(|_| unavailable())? else {
            return Ok(None);
        };
        let kind = text(row, 1, MAX_FIELD)?;
        let privacy = text(row, 11, MAX_FIELD)?;
        let sha256 = text(row, 4, 64)?;
        if !matches!(
            kind,
            "audio" | "video" | "transcript" | "derived" | "manifest"
        ) || !matches!(privacy, "private" | "shared" | "public")
            || sha256.len() != 64
            || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid_data());
        }
        Ok(Some(Asset {
            id: identifier(row, 0)?,
            kind: kind.to_owned(),
            bucket: text(row, 2, MAX_FIELD)?.to_owned(),
            object_key: text(row, 3, MAX_FIELD)?.to_owned(),
            sha256: sha256.to_ascii_lowercase(),
            bytes: integer(row, 5)? as u64,
            mime_type: optional_text(row, 6)?,
            captured_at: optional_text(row, 7)?,
            ingested_at: text(row, 8, MAX_FIELD)?.to_owned(),
            source: optional_text(row, 9)?,
            language: optional_text(row, 10)?,
            privacy: privacy.to_owned(),
        }))
    }

    pub(crate) fn parents(&self, id: &str, limit: usize) -> Result<Vec<Relation>, Error> {
        validate_id(id)?;
        if !(1..=129).contains(&limit) {
            return Err(invalid_input());
        }
        let mut statement = self.connection.prepare(
            "SELECT source_asset_id,target_asset_id,relation,created_at FROM asset_relation
             WHERE source_asset_id COLLATE BINARY=?1 AND relation COLLATE BINARY IN ('transcript_of','derived_from')
             ORDER BY target_asset_id COLLATE BINARY,relation COLLATE BINARY LIMIT ?2",
        ).map_err(|_| unavailable())?;
        let mut rows = statement
            .query(params![id, limit as i64])
            .map_err(|_| unavailable())?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|_| unavailable())? {
            result.push(Relation {
                source_asset_id: identifier(row, 0)?,
                target_asset_id: identifier(row, 1)?,
                relation: text(row, 2, MAX_FIELD)?.to_owned(),
                created_at: text(row, 3, MAX_FIELD)?.to_owned(),
            });
        }
        Ok(result)
    }
}

fn text<'a>(row: &'a Row<'_>, index: usize, limit: usize) -> Result<&'a str, Error> {
    match row.get_ref(index).map_err(|_| invalid_data())? {
        ValueRef::Text(bytes) if bytes.len() <= limit => {
            std::str::from_utf8(bytes).map_err(|_| invalid_data())
        }
        _ => Err(invalid_data()),
    }
}

fn optional_text(row: &Row<'_>, index: usize) -> Result<Option<String>, Error> {
    if matches!(
        row.get_ref(index).map_err(|_| invalid_data())?,
        ValueRef::Null
    ) {
        Ok(None)
    } else {
        Ok(Some(text(row, index, MAX_FIELD)?.to_owned()))
    }
}

fn identifier(row: &Row<'_>, index: usize) -> Result<String, Error> {
    let value = text(row, index, MAX_FIELD)?;
    if value.is_empty() {
        return Err(invalid_data());
    }
    Ok(value.to_owned())
}

fn signed_integer(row: &Row<'_>, index: usize) -> Result<i64, Error> {
    match row.get_ref(index).map_err(|_| invalid_data())? {
        ValueRef::Integer(value) => Ok(value),
        _ => Err(invalid_data()),
    }
}

fn integer(row: &Row<'_>, index: usize) -> Result<i64, Error> {
    let value = signed_integer(row, index)?;
    if value >= 0 {
        Ok(value)
    } else {
        Err(invalid_data())
    }
}

fn optional_integer(row: &Row<'_>, index: usize) -> Result<Option<i64>, Error> {
    if matches!(
        row.get_ref(index).map_err(|_| invalid_data())?,
        ValueRef::Null
    ) {
        Ok(None)
    } else {
        Ok(Some(integer(row, index)?))
    }
}

fn validate_id(id: &str) -> Result<(), Error> {
    if id.is_empty() || id.len() > MAX_FIELD {
        Err(invalid_input())
    } else {
        Ok(())
    }
}

fn validate_schema(connection: &Connection) -> Result<(), Error> {
    const ASSET: &[(&str, &str, i64)] = &[
        ("id", "TEXT", 1),
        ("kind", "TEXT", 0),
        ("bucket", "TEXT", 0),
        ("object_key", "TEXT", 0),
        ("sha256", "TEXT", 0),
        ("bytes", "INTEGER", 0),
        ("mime_type", "TEXT", 0),
        ("captured_at", "TEXT", 0),
        ("ingested_at", "TEXT", 0),
        ("source", "TEXT", 0),
        ("language", "TEXT", 0),
        ("privacy", "TEXT", 0),
    ];
    const SEGMENT: &[(&str, &str, i64)] = &[
        ("id", "INTEGER", 1),
        ("asset_id", "TEXT", 0),
        ("segment_index", "INTEGER", 0),
        ("start_ms", "INTEGER", 0),
        ("end_ms", "INTEGER", 0),
        ("speaker", "TEXT", 0),
        ("language", "TEXT", 0),
        ("text", "TEXT", 0),
    ];
    const RELATION: &[(&str, &str, i64)] = &[
        ("source_asset_id", "TEXT", 1),
        ("target_asset_id", "TEXT", 2),
        ("relation", "TEXT", 3),
        ("created_at", "TEXT", 0),
    ];
    for (name, required) in [
        ("asset", ASSET),
        ("transcript_segment", SEGMENT),
        ("asset_relation", RELATION),
    ] {
        let sql = schema_sql(connection, name)?;
        let tokens = sql_tokens(&sql)?;
        if tokens.first().map(String::as_str) != Some("create")
            || tokens.get(1).map(String::as_str) != Some("table")
        {
            return Err(unsupported());
        }
        let mut statement = connection
            .prepare("SELECT name,type,pk,hidden FROM pragma_table_xinfo(?1)")
            .map_err(|_| unsupported())?;
        let mut rows = statement.query([name]).map_err(|_| unsupported())?;
        let mut found = vec![false; required.len()];
        while let Some(row) = rows.next().map_err(|_| unsupported())? {
            let column = text(row, 0, MAX_FIELD).map_err(|_| unsupported())?;
            if let Some((index, (_, expected, pk))) = required
                .iter()
                .enumerate()
                .find(|(_, (field, _, _))| column.eq_ignore_ascii_case(field))
            {
                let declared = text(row, 1, MAX_FIELD).map_err(|_| unsupported())?;
                if !declared.eq_ignore_ascii_case(expected)
                    || row.get::<_, i64>(2).map_err(|_| unsupported())? != *pk
                    || row.get::<_, i64>(3).map_err(|_| unsupported())? != 0
                {
                    return Err(unsupported());
                }
                found[index] = true;
            }
        }
        if found.contains(&false) {
            return Err(unsupported());
        }
    }
    validate_fts(&schema_sql(connection, "transcript_fts")?)
}

fn schema_sql(connection: &Connection, name: &str) -> Result<String, Error> {
    let mut statement = connection
        .prepare("SELECT type,sql FROM sqlite_schema WHERE name=?1")
        .map_err(|_| unsupported())?;
    let mut rows = statement.query([name]).map_err(|_| unsupported())?;
    let row = rows
        .next()
        .map_err(|_| unsupported())?
        .ok_or_else(unsupported)?;
    if text(row, 0, 32).map_err(|_| unsupported())? != "table" {
        return Err(unsupported());
    }
    Ok(text(row, 1, MAX_SCHEMA)
        .map_err(|_| unsupported())?
        .to_owned())
}

// Parse tokens, not a substring test: e.g. a misleading SQL comment must not
// turn a contentless index or a different tokenizer into a supported mapping.
fn sql_tokens(sql: &str) -> Result<Vec<String>, Error> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if bytes[index..].starts_with(b"--") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            index += 2;
            while index + 1 < bytes.len() && &bytes[index..index + 2] != b"*/" {
                index += 1;
            }
            if index + 1 >= bytes.len() {
                return Err(unsupported());
            }
            index += 2;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`' | b'[') {
            let close = if byte == b'[' { b']' } else { byte };
            index += 1;
            let mut token = Vec::new();
            loop {
                let next = *bytes.get(index).ok_or_else(unsupported)?;
                index += 1;
                if next == close {
                    if byte != b'[' && bytes.get(index) == Some(&close) {
                        token.push(close);
                        index += 1;
                    } else {
                        break;
                    }
                } else {
                    token.push(next);
                }
            }
            tokens.push(
                String::from_utf8(token)
                    .map_err(|_| unsupported())?
                    .to_ascii_lowercase(),
            );
        } else if byte.is_ascii_alphanumeric() || byte == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            tokens.push(sql[start..index].to_ascii_lowercase());
        } else if byte.is_ascii() {
            tokens.push((byte as char).to_string());
            index += 1;
        } else {
            return Err(unsupported());
        }
    }
    Ok(tokens)
}

fn validate_fts(sql: &str) -> Result<(), Error> {
    let tokens = sql_tokens(sql)?;
    let mut parts: Vec<&str> = tokens.iter().map(String::as_str).collect();
    if parts.last() == Some(&";") {
        parts.pop();
    }
    if parts.get(3..6) == Some(&["if", "not", "exists"][..]) {
        parts.drain(3..6);
    }
    let prefix = [
        "create",
        "virtual",
        "table",
        "transcript_fts",
        "using",
        "fts5",
        "(",
        "text",
        ",",
        "speaker",
    ];
    if !parts.starts_with(&prefix) || parts.last() != Some(&")") {
        return Err(unsupported());
    }
    let options = &parts[prefix.len()..parts.len() - 1];
    if options.len() != 12 {
        return Err(unsupported());
    }
    let mut seen = [false; 3];
    for option in options.as_chunks::<4>().0 {
        if option[0] != "," || option[2] != "=" {
            return Err(unsupported());
        }
        let index = match (option[1], option[3]) {
            ("content", "transcript_segment") => 0,
            ("content_rowid", "id") => 1,
            ("tokenize", "unicode61") => 2,
            _ => return Err(unsupported()),
        };
        if seen[index] {
            return Err(unsupported());
        }
        seen[index] = true;
    }
    if seen.contains(&false) {
        return Err(unsupported());
    }
    Ok(())
}

fn invalid_input() -> Error {
    Error::new("invalid_input", "recording catalog input is invalid")
}
fn invalid_data() -> Error {
    Error::new(
        "invalid_input",
        "recording catalog selected fields are invalid",
    )
}
fn unsupported() -> Error {
    Error::new("unsupported", "recording catalog schema is unsupported")
}
fn unavailable() -> Error {
    Error::new(
        "unavailable",
        "recording catalog could not be read within local limits",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recordings::test_support::Fixture;

    const HASH: &str = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";

    #[test]
    fn existing_only_read_only_and_stable_snapshot() {
        let fixture = Fixture::new();
        let missing = fixture.path.with_file_name("never-created.sqlite");
        assert_eq!(Catalog::open(&missing).err().unwrap().code, "unavailable");
        assert!(!missing.exists());
        assert_eq!(
            Catalog::open(fixture.path.parent().unwrap())
                .err()
                .unwrap()
                .code,
            "invalid_input"
        );
        assert_eq!(
            Catalog::open(Path::new("file:secret?mode=memory"))
                .err()
                .unwrap()
                .code,
            "invalid_input"
        );
        fixture
            .db()
            .execute_batch("PRAGMA journal_mode=WAL;")
            .unwrap();
        fixture.asset("transcript", "transcript", HASH);
        fixture.segment("transcript", 0, "first snapshot", None, None);
        let before = fs::read(&fixture.path).unwrap();
        let catalog = Catalog::open(&fixture.path).unwrap();
        assert!(
            catalog
                .connection
                .execute("DELETE FROM transcript_segment", [])
                .is_err()
        );
        assert_eq!(fs::read(&fixture.path).unwrap(), before);
        fixture.segment("transcript", 1, "second snapshot", None, None);
        assert_eq!(
            catalog
                .search_segments("snapshot", None, None, 10)
                .unwrap()
                .len(),
            1
        );
        let later = Catalog::open(&fixture.path).unwrap();
        assert_eq!(
            later
                .search_segments("snapshot", None, None, 10)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(later.fingerprint(), catalog.fingerprint());
        assert_eq!(
            catalog.asset("transcript").unwrap().unwrap().sha256,
            HASH.to_ascii_lowercase()
        );
        assert!(catalog.asset("missing").unwrap().is_none());
    }

    #[test]
    fn literal_unicode_text_search_filter_and_keyset() {
        let fixture = Fixture::new();
        fixture.asset("a", "transcript", HASH);
        fixture.asset("b", "transcript", HASH);
        let first = fixture.segment("a", 0, "CAFÉ OR thé\nwith\ttabs", None, None);
        let second = fixture.segment("b", 0, "café OR thé", None, None);
        fixture.segment("a", 1, "café alone", None, None);
        let speaker_only = fixture.segment("a", 2, "unrelated", None, None);
        fixture
            .db()
            .execute(
                "UPDATE transcript_segment SET speaker='café OR thé' WHERE id=?1",
                [speaker_only],
            )
            .unwrap();
        fixture
            .db()
            .execute_batch("INSERT INTO transcript_fts(transcript_fts) VALUES('rebuild');")
            .unwrap();
        let catalog = Catalog::open(&fixture.path).unwrap();
        let rows = catalog
            .search_segments("café OR thé", None, None, 1)
            .unwrap();
        assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), [first]);
        assert_eq!(rows[0].text, "CAFÉ OR thé\nwith\ttabs");
        assert_eq!(
            catalog
                .search_segments("café OR thé", None, Some(first), 10)
                .unwrap()
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            [second]
        );
        assert!(
            catalog
                .search_segments("café OR thé", Some("a"), Some(first), 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            catalog
                .search_segments("café OR thé", Some("a' OR 1=1 --"), None, 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            catalog
                .search_segments("\" OR nonexistent --", None, None, 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            catalog
                .search_segments("cafe or the", None, None, 10)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn aggregate_text_limit_rejects_page_without_truncation() {
        let fixture = Fixture::new();
        fixture.asset("a", "transcript", HASH);
        let text = format!("needle{}", " ".repeat(MAX_TEXT - 6));
        for index in 0..9 {
            fixture.segment("a", index, &text, None, None);
        }
        let catalog = Catalog::open(&fixture.path).unwrap();
        assert_eq!(
            catalog
                .search_segments("needle", None, None, 8)
                .unwrap()
                .len(),
            8
        );
        let error = catalog
            .search_segments("needle", None, None, 9)
            .err()
            .unwrap();
        assert_eq!(error.code, "unavailable");
        assert!(!error.message.contains("needle"));
    }

    #[test]
    fn unknown_times_stay_unknown_but_invalid_times_fail() {
        let fixture = Fixture::new();
        fixture.asset("a", "transcript", HASH);
        let unknown = fixture.segment("a", 0, "needle", None, None);
        let partial = fixture.segment("a", 1, "needle", None, Some(10));
        fixture.segment("a", 2, "needle", Some(10), Some(10));
        let catalog = Catalog::open(&fixture.path).unwrap();
        let rows = catalog.search_segments("needle", None, None, 10).unwrap();
        assert_eq!(
            (rows[0].id, rows[0].start_ms, rows[0].end_ms),
            (unknown, None, None)
        );
        assert_eq!(
            (rows[1].id, rows[1].start_ms, rows[1].end_ms),
            (partial, None, Some(10))
        );
        drop(catalog);
        for (start, end) in [(-1, 10), (10, -1), (11, 10)] {
            fixture
                .db()
                .execute(
                    "UPDATE transcript_segment SET start_ms=?1,end_ms=?2 WHERE id=?3",
                    params![start, end, unknown],
                )
                .unwrap();
            assert_eq!(
                Catalog::open(&fixture.path)
                    .unwrap()
                    .search_segments("needle", None, None, 10)
                    .err()
                    .unwrap()
                    .code,
                "invalid_input"
            );
        }
    }

    #[test]
    fn rejects_broken_required_schema_and_wrong_fts_mapping() {
        for alteration in [
            "DROP TABLE asset_relation;",
            "ALTER TABLE asset RENAME COLUMN privacy TO secret_private_field;",
            "DROP TABLE transcript_fts; CREATE VIRTUAL TABLE transcript_fts USING fts5(text,speaker,content='transcript_segment',content_rowid='id',tokenize='porter');",
            "DROP TABLE transcript_fts; CREATE VIRTUAL TABLE transcript_fts USING fts5(text,speaker);",
            "DROP TABLE asset_relation; CREATE VIEW asset_relation AS SELECT 'x' AS source_asset_id,'y' AS target_asset_id,'derived_from' AS relation,'z' AS created_at;",
        ] {
            let fixture = Fixture::new();
            fixture.db().execute_batch(alteration).unwrap();
            assert_eq!(
                Catalog::open(&fixture.path).err().unwrap().code,
                "unsupported"
            );
        }
        let fixture = Fixture::new();
        fs::write(&fixture.path, b"not a database: synthetic-sensitive-value").unwrap();
        let error = Catalog::open(&fixture.path).err().unwrap();
        assert!(!format!("{error:?}").contains("synthetic-sensitive-value"));
        assert!(!format!("{error:?}").contains(fixture.path.to_str().unwrap()));
    }

    #[test]
    fn invalid_selected_fields_are_errors_not_skipped_or_leaked() {
        for (field, value) in [
            ("sha256", "synthetic-sensitive-hash"),
            ("privacy", "synthetic-sensitive-privacy"),
            ("kind", "unexpected-kind"),
            ("source", &"x".repeat(MAX_FIELD + 1)),
        ] {
            let fixture = Fixture::new();
            fixture.asset("a", "transcript", HASH);
            // Column names are test constants, never catalog/query input.
            fixture
                .db()
                .execute(&format!("UPDATE asset SET {field}=?1"), [value])
                .unwrap();
            let error = Catalog::open(&fixture.path)
                .unwrap()
                .asset("a")
                .err()
                .unwrap();
            assert_eq!(error.code, "invalid_input");
            let rendered = format!("{error:?}");
            assert!(!rendered.contains(value));
            assert!(!rendered.contains(fixture.path.to_str().unwrap()));
            assert!(!rendered.contains("UPDATE"));
        }
        let fixture = Fixture::new();
        fixture.asset("a", "transcript", HASH);
        fixture
            .db()
            .execute("UPDATE asset SET bytes=-1", [])
            .unwrap();
        assert_eq!(
            Catalog::open(&fixture.path)
                .unwrap()
                .asset("a")
                .err()
                .unwrap()
                .code,
            "invalid_input"
        );
        let id = fixture.segment("a", -1, "needle", None, None);
        assert_eq!(
            Catalog::open(&fixture.path)
                .unwrap()
                .search_segments("needle", None, None, 10)
                .err()
                .unwrap()
                .code,
            "invalid_input"
        );
        fixture.db().execute("UPDATE transcript_segment SET segment_index=0,speaker=CAST(x'80' AS TEXT) WHERE id=?1", [id]).unwrap();
        assert_eq!(
            Catalog::open(&fixture.path)
                .unwrap()
                .search_segments("needle", None, None, 10)
                .err()
                .unwrap()
                .code,
            "invalid_input"
        );
    }

    #[test]
    fn ancestry_is_outgoing_sorted_and_bounded() {
        let fixture = Fixture::new();
        fixture.relate("a", "z", "transcript_of");
        fixture.relate("a", "b", "transcript_of");
        fixture.relate("a", "b", "derived_from");
        fixture.relate("a", "ignored", "subtitle_of");
        fixture.relate("incoming", "a", "derived_from");
        let catalog = Catalog::open(&fixture.path).unwrap();
        let rows = catalog.parents("a", 2).unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| (row.target_asset_id.as_str(), row.relation.as_str()))
                .collect::<Vec<_>>(),
            [("b", "derived_from"), ("b", "transcript_of")]
        );
        assert!(catalog.parents("a' OR 1=1 --", 129).unwrap().is_empty());
    }
}
