use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct PrivateDir(PathBuf);
impl PrivateDir {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "buaa-subtitle-export-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create fixture: {error}"),
            }
        }
    }
}
impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn request(path: &Path, format: &str) -> Value {
    json!({"authorized":true,"format":format,"output":path.to_str().unwrap(),"segments":[
        {"source_order":1,"start_ms":1234,"end_ms":2500,"text":"private fixture first","translation":"ignored"},
        {"source_order":2,"start_ms":3600001,"end_ms":3601999,"text":"private fixture second","translation":""}
    ]})
}
fn invoke(input: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .args(["recordings", "subtitles", "export"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}
fn rejected(output: Output, code: i32) {
    assert_eq!(output.status.code(), Some(code));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private fixture"));
}

#[test]
fn exports_playable_srt_and_vtt_with_private_receipts() {
    let dir = PrivateDir::new();
    for (format, expected) in [
        (
            "srt",
            "1\r\n00:00:01,234 --> 00:00:02,500\r\nprivate fixture first\r\n\r\n2\r\n01:00:00,001 --> 01:00:01,999\r\nprivate fixture second\r\n\r\n",
        ),
        (
            "vtt",
            "WEBVTT\r\n\r\n00:00:01.234 --> 00:00:02.500\r\nprivate fixture first\r\n\r\n01:00:00.001 --> 01:00:01.999\r\nprivate fixture second\r\n\r\n",
        ),
    ] {
        let path = dir.0.join(format!("out.{format}"));
        let output = invoke(&request(&path, format));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(fs::read(&path).unwrap(), expected.as_bytes());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
        assert_eq!(receipt["format"], format);
        assert_eq!(receipt["bytes"], expected.len());
        assert_eq!(
            receipt["sha256"],
            format!("{:x}", Sha256::digest(expected.as_bytes()))
        );
        assert_eq!(
            receipt["derivation"],
            "derived-from-caller-supplied-segments"
        );
        assert_eq!(receipt["source_verified"], false);
        assert_eq!(receipt["rights_verified"], false);
        assert_eq!(receipt["native_track_association_verified"], false);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private fixture"));
    }
}

#[test]
fn refuses_existing_unauthorized_and_late_invalid_without_artifacts() {
    let dir = PrivateDir::new();
    let existing = dir.0.join("existing.srt");
    fs::write(&existing, b"original").unwrap();
    rejected(invoke(&request(&existing, "srt")), 9);
    assert_eq!(fs::read(&existing).unwrap(), b"original");
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    let unauthorized = dir.0.join("unauthorized.srt");
    let mut input = request(&unauthorized, "srt");
    input["authorized"] = json!(false);
    rejected(invoke(&input), 5);
    assert!(!unauthorized.exists());
    let invalid = dir.0.join("invalid.srt");
    let mut input = request(&invalid, "srt");
    input["segments"][1]["end_ms"] = json!(1);
    rejected(invoke(&input), 2);
    assert!(!invalid.exists());
}

#[test]
fn write_failure_never_publishes_a_partial_final_file() {
    let dir = PrivateDir::new();
    let destination = dir.0.join("incomplete.srt");
    let mut command = Command::new(env!("CARGO_BIN_EXE_buaa"));
    command
        .args(["recordings", "subtitles", "export"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: pre_exec calls only async-signal-safe libc operations and
    // restricts the child, not the test process. EFBIG then exercises cleanup.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let limit = libc::rlimit {
                rlim_cur: 16,
                rlim_max: 16,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request(&destination, "srt").to_string().as_bytes())
        .unwrap();
    rejected(child.wait_with_output().unwrap(), 7);
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[test]
fn refuses_symlink_and_nonprivate_parent_and_existing_hardlink() {
    let dir = PrivateDir::new();
    let real = dir.0.join("real");
    DirBuilder::new().mode(0o700).create(&real).unwrap();
    let alias = dir.0.join("alias");
    symlink(&real, &alias).unwrap();
    rejected(invoke(&request(&alias.join("out.srt"), "srt")), 5);
    assert!(!real.join("out.srt").exists());
    let public = dir.0.join("public");
    DirBuilder::new().mode(0o700).create(&public).unwrap();
    fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
    rejected(invoke(&request(&public.join("out.srt"), "srt")), 5);
    assert!(!public.join("out.srt").exists());
    let original = dir.0.join("original");
    let link = dir.0.join("link.srt");
    fs::write(&original, b"original").unwrap();
    fs::hard_link(&original, &link).unwrap();
    rejected(invoke(&request(&link, "srt")), 9);
    assert_eq!(fs::read(original).unwrap(), b"original");
}
