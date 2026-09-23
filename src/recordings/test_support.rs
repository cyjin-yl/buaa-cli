use rusqlite::{Connection, params};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Fixture {
    root: PathBuf,
    pub path: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "buaa-recordings-{}-{nonce}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("synthetic.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(include_str!("../../tests/fixtures/life-catalog.sql"))
            .unwrap();
        Self { root, path }
    }

    pub fn db(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }

    pub fn asset(&self, id: &str, kind: &str, sha256: &str) {
        self.db().execute(
            "INSERT INTO asset(id,kind,bucket,object_key,sha256,bytes,mime_type,captured_at,ingested_at,source,language,privacy,metadata_json) VALUES(?1,?2,'synthetic-recordings',?3,?4,64,NULL,NULL,'2024-01-02T03:04:05Z','synthetic fixture',NULL,'private','{}')",
            params![id, kind, format!("fixtures/{id}"), sha256],
        ).unwrap();
    }

    pub fn segment(
        &self,
        asset_id: &str,
        index: i64,
        text: &str,
        start: Option<i64>,
        end: Option<i64>,
    ) -> i64 {
        let connection = self.db();
        connection.execute(
            "INSERT INTO transcript_segment(asset_id,segment_index,start_ms,end_ms,text) VALUES(?1,?2,?3,?4,?5)",
            params![asset_id,index,start,end,text],
        ).unwrap();
        connection.last_insert_rowid()
    }

    pub fn relate(&self, source: &str, target: &str, relation: &str) {
        self.db()
            .execute(
                "INSERT INTO asset_relation VALUES(?1,?2,?3,'2024-01-02T03:04:05Z')",
                params![source, target, relation],
            )
            .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
