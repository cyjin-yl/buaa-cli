#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const URL: &str = "https://resource.msa.buaa.edu.cn/play/synthetic.mp4";
const BODY: &[u8] = b"synthetic media fixture";

struct Fixture {
    root: PathBuf,
    media: PathBuf,
    receipt: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "buaa-replay-binding-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let key = format!("{:x}", Sha256::digest(URL.as_bytes()));
        let media = root.join(format!("recording-{key}.mp4"));
        let receipt = root.join(format!("recording-{key}.receipt.json"));
        fs::write(&media, BODY).unwrap();
        fs::set_permissions(&media, fs::Permissions::from_mode(0o600)).unwrap();
        let fixture = Self {
            root,
            media,
            receipt,
        };
        fixture.write_receipt(&fixture.valid_receipt());
        fixture
    }

    fn valid_receipt(&self) -> Value {
        json!({"version":1,"url":URL,"http_status":200,"content_type":"video/mp4","container":"mp4","bytes":BODY.len(),"sha256":format!("{:x}", Sha256::digest(BODY)),"complete_body":true})
    }

    fn write_receipt(&self, value: &Value) {
        fs::write(&self.receipt, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(&self.receipt, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn reject(&self, media: &Path, receipt: &Path) {
        let input = json!({"authorized":true,"media":{"path":media,"receipt_path":receipt},"player":"mpv","headless":true,"max_seconds":2});
        // With no player on PATH, invalid_input rather than unavailable proves
        // rejection precedes attempting the executable.
        let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
            .args(["recordings", "replay"])
            .env("PATH", &self.root)
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
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        let parsed: Value = serde_json::from_str(&error).unwrap();
        assert_eq!(parsed["error"], "invalid_input");
        assert!(!error.contains(URL));
        assert!(!error.contains(self.root.to_str().unwrap()));
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn valid_local_inputs_reach_unavailable_player() {
    let f = Fixture::new();
    for with_receipt in [true, false] {
        let mut media = json!({"path": &f.media});
        if with_receipt {
            media["receipt_path"] = json!(&f.receipt);
        }
        let input =
            json!({"authorized":true,"media":media,"player":"mpv","headless":true,"max_seconds":2});
        let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
            .args(["recordings", "replay"])
            .env("PATH", &f.root)
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
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        let parsed: Value = serde_json::from_str(&error).unwrap();
        assert_eq!(parsed["error"], "unavailable");
        assert!(!error.contains(URL));
        assert!(!error.contains(f.root.to_str().unwrap()));
    }
}

#[test]
fn receipt_bound_hardlinked_media_is_rejected_without_removal() {
    let f = Fixture::new();
    let alias = f.root.join("media-hardlink");
    fs::hard_link(&f.media, &alias).unwrap();
    f.reject(&f.media, &f.receipt);
    assert_eq!(fs::read(&f.media).unwrap(), BODY);
    assert_eq!(fs::read(&alias).unwrap(), BODY);
}

// Linux inotify watches the inode, including reads through any hardlink.
struct AccessWatch(fs::File);

impl AccessWatch {
    fn new(path: &Path) -> Self {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: inotify_init1 returns a new owned descriptor on success.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        assert!(
            fd >= 0,
            "inotify_init1: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: fd is a newly created descriptor, owned by this File.
        let file = unsafe { fs::File::from_raw_fd(fd) };
        // SAFETY: name is NUL-terminated and file owns a valid inotify fd.
        let watch =
            unsafe { libc::inotify_add_watch(file.as_raw_fd(), name.as_ptr(), libc::IN_ACCESS) };
        assert!(
            watch >= 0,
            "inotify_add_watch: {}",
            std::io::Error::last_os_error()
        );
        Self(file)
    }

    fn saw_access(&mut self) -> bool {
        let mut buffer = [0_u8; 4096];
        let mut accessed = false;
        // The child has exited, so nonblocking reads drain already queued events.
        // Bound the drain even if an unexpected writer continuously adds events.
        for _ in 0..32 {
            let n = match self.0.read(&mut buffer) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return accessed,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("inotify read: {e}"),
            };
            assert!(n > 0, "unexpected inotify EOF");
            let mut offset = 0;
            while offset < n {
                let size = std::mem::size_of::<libc::inotify_event>();
                assert!(n - offset >= size, "truncated inotify event");
                // SAFETY: the buffer contains at least one complete event header;
                // read_unaligned handles the byte buffer's alignment.
                let event = unsafe {
                    std::ptr::read_unaligned(
                        buffer.as_ptr().add(offset).cast::<libc::inotify_event>(),
                    )
                };
                assert_eq!(
                    event.mask & (libc::IN_Q_OVERFLOW | libc::IN_IGNORED),
                    0,
                    "inotify watch lost"
                );
                accessed |= event.mask & libc::IN_ACCESS != 0;
                let event_size = size + event.len as usize;
                assert!(event_size <= n - offset, "truncated inotify name");
                offset += event_size;
            }
        }
        panic!("inotify event drain exceeded its bound");
    }
}

fn replay_without_receipt(f: &Fixture) {
    let input = json!({"authorized":true,"media":{"path":&f.media},"player":"mpv","headless":true,"max_seconds":2});
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .args(["recordings", "replay"])
        .env("PATH", &f.root)
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
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "unavailable");
}

#[test]
fn receipt_bound_hardlink_is_rejected_before_media_access() {
    let f = Fixture::new();
    let alias_dir = f.root.join("alias-directory");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&alias_dir)
        .unwrap();
    fs::set_permissions(&alias_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = alias_dir.join("media-hardlink");
    fs::hard_link(&f.media, &alias).unwrap();
    let media = fs::metadata(&f.media).unwrap();
    let linked = fs::metadata(&alias).unwrap();
    assert_eq!((media.dev(), media.ino()), (linked.dev(), linked.ino()));
    assert_eq!(media.nlink(), 2);
    assert_eq!(linked.nlink(), 2);

    // The legacy operator-asserted path still reads hardlinked media and
    // reaches the unavailable player; this also proves the watch works.
    let mut watch = AccessWatch::new(&f.media);
    replay_without_receipt(&f);
    assert!(watch.saw_access(), "no-receipt replay did not access media");
    drop(watch);

    let mut watch = AccessWatch::new(&f.media);
    f.reject(&f.media, &f.receipt);
    assert!(
        !watch.saw_access(),
        "receipt-bound hardlinked media was read before rejection"
    );
}

#[test]
fn single_link_receipt_reads_media_and_reaches_unavailable_player() {
    // Keep this control independent so it still runs when the regression is red.
    let f = Fixture::new();
    assert_eq!(fs::metadata(&f.media).unwrap().nlink(), 1);
    let mut watch = AccessWatch::new(&f.media);
    let input = json!({"authorized":true,"media":{"path":&f.media,"receipt_path":&f.receipt},"player":"mpv","headless":true,"max_seconds":2});
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .args(["recordings", "replay"])
        .env("PATH", &f.root)
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
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "unavailable");
    assert!(
        watch.saw_access(),
        "valid receipt replay did not access media"
    );
}

#[test]
fn invalid_receipts_reject_before_player_attempt() {
    let f = Fixture::new();
    for (field, value) in [
        ("sha256", json!("0".repeat(64))),
        ("bytes", json!(BODY.len() + 1)),
        ("version", json!(2)),
        ("http_status", json!(206)),
        ("complete_body", json!(false)),
        ("container", json!("webm")),
        ("content_type", json!("text/html")),
        (
            "url",
            json!("https://resource.msa.buaa.edu.cn/play/other.mp4"),
        ),
    ] {
        let mut receipt = f.valid_receipt();
        receipt[field] = value;
        f.write_receipt(&receipt);
        f.reject(&f.media, &f.receipt);
    }
    fs::write(&f.receipt, b"not json").unwrap();
    f.reject(&f.media, &f.receipt);
    fs::write(&f.receipt, vec![b'x'; 16 * 1024 + 1]).unwrap();
    f.reject(&f.media, &f.receipt);
    fs::remove_file(&f.receipt).unwrap();
    f.reject(&f.media, &f.receipt);
    f.write_receipt(&f.valid_receipt());
    fs::set_permissions(&f.receipt, fs::Permissions::from_mode(0o644)).unwrap();
    f.reject(&f.media, &f.receipt);
    fs::set_permissions(&f.receipt, fs::Permissions::from_mode(0o600)).unwrap();
    let hardlink = f.root.join("hardlink");
    fs::hard_link(&f.receipt, &hardlink).unwrap();
    f.reject(&f.media, &f.receipt);
    fs::remove_file(hardlink).unwrap();
    let wrong_media = f.root.join("other.mp4");
    fs::write(&wrong_media, BODY).unwrap();
    f.reject(&wrong_media, &f.receipt);
    let wrong_receipt = f.root.join("other.receipt.json");
    fs::copy(&f.receipt, &wrong_receipt).unwrap();
    fs::set_permissions(&wrong_receipt, fs::Permissions::from_mode(0o600)).unwrap();
    f.reject(&f.media, &wrong_receipt);
    f.reject(&f.root.join("missing.mp4"), &f.receipt);
    let other_dir = f.root.join("other");
    fs::create_dir(&other_dir).unwrap();
    let other_receipt = other_dir.join(f.receipt.file_name().unwrap());
    fs::copy(&f.receipt, &other_receipt).unwrap();
    f.reject(&f.media, &other_receipt);
    let link = f.root.join("parent-link");
    symlink(&f.root, &link).unwrap();
    f.reject(&f.media, &link.join(f.receipt.file_name().unwrap()));
    fs::remove_file(&f.receipt).unwrap();
    symlink(&wrong_receipt, &f.receipt).unwrap();
    f.reject(&f.media, &f.receipt);
}
