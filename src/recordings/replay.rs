//! Bounded local recording replay through an installed mpv or VLC binary.
//!
//! The command accepts only an operator-attested local media path.  Remote
// media is deliberately refused because the existing governed client has no
// generic media-origin profile.  Player diagnostics are discarded; normal
// audio/video output is used unless headless mode is explicitly requested.
// Stdout contains only structural, hashed facts and never contains a path,
// URL or subtitle text.

use crate::net::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

const MAX_INPUT: usize = 8 * 1024 * 1024;
const MAX_PATH: usize = 4096;
const MAX_URL: usize = 16 * 1024;
const MAX_SEGMENTS: usize = 20_000;
const MAX_SEGMENT_TEXT: usize = 8 * 1024;
const MAX_SUBTITLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MEDIA_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const IO_CHUNK: usize = 64 * 1024;
const TERM_GRACE: Duration = Duration::from_millis(250);
const KILL_WAIT: Duration = Duration::from_secs(5);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Player {
    Mpv,
    Vlc,
}

impl Player {
    fn as_str(self) -> &'static str {
        match self {
            Self::Mpv => "mpv",
            Self::Vlc => "vlc",
        }
    }

    fn executable(self) -> &'static str {
        self.as_str()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayInput {
    authorized: bool,
    media: MediaInput,
    player: Player,
    #[serde(default)]
    headless: bool,
    #[serde(default)]
    subtitles: Option<SubtitleInput>,
    #[serde(default)]
    seek_seconds: u64,
    #[serde(default = "default_max_seconds")]
    max_seconds: u64,
    #[serde(default)]
    private_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MediaInput {
    path: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubtitleInput {
    path: Option<String>,
    segments: Option<Vec<Value>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubtitleFormat {
    Srt,
    Vtt,
}

impl SubtitleFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Srt => "srt",
            Self::Vtt => "vtt",
        }
    }

    fn mpv_demuxer(self) -> &'static str {
        match self {
            Self::Srt => "srt",
            Self::Vtt => "webvtt",
        }
    }

    fn vlc_sub_type(self) -> &'static str {
        match self {
            Self::Srt => "subrip",
            // VLC versions differ in whether `webvtt` is accepted by the
            // subtitle module; content autodetection is the portable choice.
            Self::Vtt => "auto",
        }
    }
}

#[derive(Clone, Debug)]
struct FileIdentity {
    byte_length: u64,
    sha256: String,
}

#[derive(Debug)]
struct LocalFile {
    file: File,
    identity: FileIdentity,
}

struct TemporarySubtitle {
    directory: File,
    name: CString,
    file: File,
}

impl Drop for TemporarySubtitle {
    fn drop(&mut self) {
        // SAFETY: `directory` is a pinned directory descriptor and `name` is
        // the single component created in that directory.
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
        }
    }
}

struct PreparedSubtitle {
    format: SubtitleFormat,
    identity: FileIdentity,
    guard: SubtitleGuard,
}

enum SubtitleGuard {
    Existing { file: File },
    Generated { temporary: TemporarySubtitle },
}

impl SubtitleGuard {
    fn file(&self) -> &File {
        match self {
            Self::Existing { file } => file,
            Self::Generated { temporary } => &temporary.file,
        }
    }
}

impl PreparedSubtitle {
    fn file(&self) -> &File {
        self.guard.file()
    }
}

struct PlayerObservation {
    status: ExitStatus,
    stopped_by_bound: bool,
}

fn default_max_seconds() -> u64 {
    120
}

fn invalid() -> Error {
    Error::new("invalid_input", "recording replay input is invalid")
}

fn permission() -> Error {
    Error::new("permission", "recording replay path is not permitted")
}

fn unavailable() -> Error {
    Error::new("unavailable", "recording replay is unavailable")
}

fn unsupported() -> Error {
    Error::new("unsupported", "remote recording media is unsupported")
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_path_text(value: &str) -> Result<PathBuf, Error> {
    if value.is_empty()
        || value.len() > MAX_PATH
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(invalid());
    }
    Ok(path)
}

fn validate_url_text(value: &str) -> Result<Url, Error> {
    if value.is_empty()
        || value.len() > MAX_URL
        || value.contains('\0')
        || value.chars().any(char::is_control)
        || value.to_ascii_lowercase().contains("cookie")
    {
        return Err(invalid());
    }
    let url = Url::parse(value).map_err(|_| invalid())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(url)
}

fn validate_segment_array(segments: &[Value]) -> Result<(), Error> {
    if segments.is_empty() || segments.len() > MAX_SEGMENTS {
        return Err(invalid());
    }
    for segment in segments {
        let object = segment.as_object().ok_or_else(invalid)?;
        let start = object
            .get("start_ms")
            .and_then(Value::as_u64)
            .ok_or_else(invalid)?;
        let end = object
            .get("end_ms")
            .and_then(Value::as_u64)
            .ok_or_else(invalid)?;
        let text = object
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if start > end || text.len() > MAX_SEGMENT_TEXT || object.len() > 16 {
            return Err(invalid());
        }
    }
    Ok(())
}

fn parse_input(input: &str) -> Result<ReplayInput, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: ReplayInput = serde_json::from_str(input).map_err(|_| invalid())?;
    if !request.authorized {
        return Err(Error::new(
            "permission",
            "explicit operator authorization is required",
        ));
    }
    if request.max_seconds == 0 || request.max_seconds > 3600 {
        return Err(invalid());
    }
    if let Some(private_dir) = request.private_dir.as_deref() {
        validate_path_text(private_dir)?;
    }
    let media_count =
        usize::from(request.media.path.is_some()) + usize::from(request.media.url.is_some());
    if media_count != 1 {
        return Err(invalid());
    }
    if let Some(url) = request.media.url.as_deref() {
        let _ = validate_url_text(url)?;
    }
    if let Some(path) = request.media.path.as_deref() {
        let _ = validate_path_text(path)?;
    }
    if let Some(subtitles) = request.subtitles.as_ref() {
        let source_count =
            usize::from(subtitles.path.is_some()) + usize::from(subtitles.segments.is_some());
        if source_count != 1 {
            return Err(invalid());
        }
        if let Some(path) = subtitles.path.as_deref() {
            let _ = validate_path_text(path)?;
        }
        if let Some(segments) = subtitles.segments.as_deref() {
            validate_segment_array(segments)?;
            if request.private_dir.is_none() {
                return Err(invalid());
            }
        }
    }
    Ok(request)
}

fn parent_and_name(path: &Path) -> Result<(File, String), Error> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && *value != "." && *value != "..")
        .ok_or_else(invalid)?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or_else(invalid)?;
    let directory = crate::governor::open_directory(parent, false, false).map_err(|_| invalid())?;
    let metadata = directory.metadata().map_err(|_| unavailable())?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(permission());
    }
    Ok((directory, name.to_owned()))
}

fn open_local_file(path: PathBuf, max_bytes: u64) -> Result<LocalFile, Error> {
    let (directory, name) = parent_and_name(&path)?;
    let file =
        crate::governor::open_child(&directory, &name, libc::O_RDONLY).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| unavailable())?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(permission());
    }
    let mut file = file;
    let identity = digest_file(&mut file, max_bytes)?;
    drop(directory);
    Ok(LocalFile { file, identity })
}

fn digest_file(file: &mut File, max_bytes: u64) -> Result<FileIdentity, Error> {
    let expected = file.metadata().map_err(|_| unavailable())?.len();
    if expected > max_bytes {
        return Err(invalid());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| unavailable())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; IO_CHUNK];
    let mut total = 0_u64;
    loop {
        let read = match file.read(&mut buffer) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(unavailable()),
        };
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .filter(|value| *value <= max_bytes)
            .ok_or_else(invalid)?;
        hasher.update(&buffer[..read]);
    }
    if total != expected {
        return Err(unavailable());
    }
    // The child receives a proc-fd path which opens the admitted descriptor's
    // underlying file description.  Leave that description at the beginning;
    // otherwise the digest pass would hand the player an EOF position.
    file.seek(SeekFrom::Start(0)).map_err(|_| unavailable())?;
    Ok(FileIdentity {
        byte_length: total,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn subtitle_format(path: &Path) -> Result<SubtitleFormat, Error> {
    match path.extension().and_then(|value| value.to_str()) {
        Some(value) if value.eq_ignore_ascii_case("srt") => Ok(SubtitleFormat::Srt),
        Some(value) if value.eq_ignore_ascii_case("vtt") => Ok(SubtitleFormat::Vtt),
        _ => Err(invalid()),
    }
}

fn unlink_temp(directory: &File, name: &CString) {
    // SAFETY: the directory descriptor and one-component name are owned by
    // this operation; failure is intentionally ignored during cleanup.
    unsafe {
        libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0);
    }
}

fn create_temporary_subtitle(directory: File, body: &[u8]) -> Result<TemporarySubtitle, Error> {
    if body.is_empty() || body.len() as u64 > MAX_SUBTITLE_BYTES {
        return Err(invalid());
    }
    for _ in 0..16 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name_c = CString::new(format!(
            ".buaa-replay-{}-{}.srt",
            std::process::id(),
            sequence
        ))
        .map_err(|_| unavailable())?;
        let name = name_c.to_str().map_err(|_| unavailable())?;
        let file = match crate::governor::open_child(
            &directory,
            name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        ) {
            Ok(file) => file,
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(_) => return Err(unavailable()),
        };
        if crate::governor::validate_private_file(&file).is_err() {
            unlink_temp(&directory, &name_c);
            return Err(permission());
        }
        let mut file = file;
        let result = (|| {
            file.write_all(body).map_err(|_| unavailable())?;
            file.sync_all().map_err(|_| unavailable())?;
            let identity = digest_file(&mut file, MAX_SUBTITLE_BYTES)?;
            Ok::<_, Error>(identity)
        })();
        if let Err(error) = result {
            unlink_temp(&directory, &name_c);
            return Err(error);
        }
        return Ok(TemporarySubtitle {
            directory,
            name: name_c,
            file,
        });
    }
    Err(unavailable())
}

fn prepare_subtitle(request: &ReplayInput) -> Result<Option<PreparedSubtitle>, Error> {
    let Some(subtitles) = request.subtitles.as_ref() else {
        return Ok(None);
    };
    if let Some(path) = subtitles.path.as_deref() {
        let path = validate_path_text(path)?;
        let format = subtitle_format(&path)?;
        let local = open_local_file(path, MAX_SUBTITLE_BYTES)?;
        return Ok(Some(PreparedSubtitle {
            format,
            identity: local.identity.clone(),
            guard: SubtitleGuard::Existing { file: local.file },
        }));
    }
    let segments = subtitles.segments.as_ref().ok_or_else(invalid)?;
    validate_segment_array(segments)?;
    let private_dir = request.private_dir.as_deref().ok_or_else(invalid)?;
    let private_path = validate_path_text(private_dir)?;
    let directory =
        crate::governor::open_directory(&private_path, false, true).map_err(|_| permission())?;
    let body = crate::recordings::subtitle_export::srt(segments)?;
    let body = body.into_bytes();
    let temporary = create_temporary_subtitle(directory, &body)?;
    let identity = FileIdentity {
        byte_length: body.len() as u64,
        sha256: digest_bytes(&body),
    };
    Ok(Some(PreparedSubtitle {
        format: SubtitleFormat::Srt,
        identity,
        guard: SubtitleGuard::Generated { temporary },
    }))
}

fn prepare_media(request: &ReplayInput) -> Result<LocalFile, Error> {
    if let Some(url) = request.media.url.as_deref() {
        let _ = validate_url_text(url)?;
        return Err(unsupported());
    }
    let path = validate_path_text(request.media.path.as_deref().ok_or_else(invalid)?)?;
    open_local_file(path, MAX_MEDIA_BYTES)
}

fn build_argv(
    player: Player,
    media: &str,
    subtitle: Option<&str>,
    subtitle_format: Option<SubtitleFormat>,
    seek_seconds: u64,
    headless: bool,
) -> Vec<String> {
    let mut argv = match player {
        Player::Mpv => {
            let mut argv = vec![
                "--no-terminal".to_owned(),
                "--really-quiet".to_owned(),
                "--no-config".to_owned(),
                "--load-scripts=no".to_owned(),
                "--autoload-files=no".to_owned(),
                "--no-load-unsafe-playlists".to_owned(),
                "--access-references=no".to_owned(),
                "--ytdl=no".to_owned(),
                "--no-input-terminal".to_owned(),
                "--hwdec=no".to_owned(),
            ];
            if headless {
                argv.push("--vo=null".to_owned());
                argv.push("--ao=null".to_owned());
            }
            argv.push("--idle=no".to_owned());
            argv.push("--keep-open=no".to_owned());
            argv.push(format!("--start=+{seek_seconds}"));
            argv
        }
        Player::Vlc => {
            let mut argv = vec![
                // VLC 3.x documents --config as the alternate config-file
                // selector; /dev/null makes the choice explicit without
                // relying on an undocumented --no-config alias.
                "--config=/dev/null".to_owned(),
                "--no-daemon".to_owned(),
                "--no-one-instance".to_owned(),
                "--no-video-title-show".to_owned(),
                "--play-and-exit".to_owned(),
            ];
            if headless {
                // A headless host has no display or sound device.  These
                // sinks are opt-in so the default remains real playback.
                argv.extend([
                    "--intf".to_owned(),
                    "dummy".to_owned(),
                    "--vout=dummy".to_owned(),
                    "--aout=dummy".to_owned(),
                ]);
            }
            argv.push(format!("--start-time={seek_seconds}"));
            argv
        }
    };
    if let Some(subtitle) = subtitle {
        if let Some(format) = subtitle_format {
            match player {
                Player::Mpv => argv.push(format!("--sub-demuxer={}", format.mpv_demuxer())),
                Player::Vlc => argv.push(format!("--sub-type={}", format.vlc_sub_type())),
            }
        }
        argv.push(format!("--sub-file={subtitle}"));
    }
    argv.push(media.to_owned());
    argv
}

const CHILD_FD_MIN: i32 = 3;

fn duplicate_for_child(file: &File) -> Result<File, Error> {
    // Keep the admitted descriptor and duplicate it rather than changing its
    // close-on-exec flag in the parent.  Starting at fd 3 also avoids the
    // stdio descriptors that Command configures in the child before exec.
    let duplicate = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, CHILD_FD_MIN) };
    if duplicate < 0 {
        return Err(unavailable());
    }
    // SAFETY: a successful F_DUPFD_CLOEXEC returns one new owned descriptor.
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

fn descriptor_path(file: &File) -> String {
    format!("/proc/self/fd/{}", file.as_raw_fd())
}

fn clear_close_on_exec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl operates on the live descriptor supplied by this module.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::FD_CLOEXEC == 0 {
        return Ok(());
    }
    // SAFETY: the descriptor remains live in the pre-exec child; only its
    // close-on-exec bit is changed, and no parent descriptor is touched.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BPF_LD: u16 = 0x00;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BPF_W: u16 = 0x00;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BPF_ABS: u16 = 0x20;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BPF_JMP: u16 = 0x05;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BPF_JEQ: u16 = 0x10;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BPF_JSET: u16 = 0x40;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BPF_K: u16 = 0x00;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BPF_RET: u16 = 0x06;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SECCOMP_ARCH_OFFSET: u32 = 4;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SECCOMP_NR_OFFSET: u32 = 0;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SECCOMP_ARG0_OFFSET: u32 = 16;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// The filter is installed after fork and before exec, so it cannot affect
/// this process or any of its other children.  Unknown inherited descriptors
/// are closed separately below; that makes the domain check meaningful even
/// when the caller had an accidentally inherited network descriptor.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static NETWORK_SANDBOX: [libc::sock_filter; 23] = [
    // Check the native x86-64 syscall ABI before inspecting a syscall number.
    bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_ARCH_OFFSET),
    bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_NR_OFFSET),
    // x32 uses the x86-64 audit arch but a different syscall-number space.
    bpf_jump(BPF_JMP | BPF_JSET | BPF_K, X32_SYSCALL_BIT, 0, 1),
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    // socket(domain, ...) and socketpair(domain, ...) are the only creation
    // paths allowed to reach a socket.  AF_UNIX is required for X11 and local
    // audio IPC; every other domain receives EPERM in the child.
    bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_socket as u32, 0, 4),
    bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_ARG0_OFFSET),
    bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, libc::AF_UNIX as u32, 1, 0),
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_socketpair as u32, 0, 4),
    bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_ARG0_OFFSET),
    bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, libc::AF_UNIX as u32, 1, 0),
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    // Do not permit io_uring to create or use an unfiltered socket operation.
    bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_io_uring_setup as u32,
        0,
        1,
    ),
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
    bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_io_uring_enter as u32,
        0,
        1,
    ),
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
    bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_io_uring_register as u32,
        0,
        1,
    ),
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
];

fn inherited_parent_fds(media_fd: RawFd, subtitle_fd: Option<RawFd>) -> Result<Vec<RawFd>, Error> {
    // Enumerate before Command::spawn creates its private exec-error pipe.
    // The entry list is materialized first so the read_dir descriptor itself
    // is gone before any descriptor number is retained for the child.
    let entries = std::fs::read_dir("/proc/self/fd").map_err(|_| unavailable())?;
    let mut paths = Vec::new();
    for entry in entries {
        paths.push(entry.map_err(|_| unavailable())?.path());
    }
    let mut inherited = Vec::new();
    for path in paths {
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Ok(fd) = name.parse::<RawFd>() else {
            continue;
        };
        if fd < CHILD_FD_MIN || fd == media_fd || Some(fd) == subtitle_fd {
            continue;
        }
        // A read_dir entry for the iterator's own descriptor is stale after
        // the iterator drops.  Requiring the proc link to remain readable
        // avoids retaining that number for a later Command-owned descriptor.
        match std::fs::read_link(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(unavailable()),
        }
        inherited.push(fd);
    }
    Ok(inherited)
}

fn close_inherited_fds(fds: &[RawFd]) -> io::Result<()> {
    for &fd in fds {
        // SAFETY: these numbers were enumerated in the parent before spawn;
        // this operation runs only in the forked child.  Command's private
        // exec-error pipe is allocated after enumeration and is not included.
        if unsafe { libc::close(fd) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn install_network_sandbox() -> io::Result<()> {
    // SAFETY: no_new_privs is process-local to this child and is required for
    // an unprivileged seccomp filter install.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let program = libc::sock_fprog {
        len: NETWORK_SANDBOX.len() as libc::c_ushort,
        filter: NETWORK_SANDBOX.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: the static program remains valid until this syscall returns;
    // seccomp copies it into the kernel.  No TSYNC is needed in the fresh
    // single-threaded post-fork child.
    let result =
        unsafe { libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0_u32, &program) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn install_network_sandbox() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "recording replay requires Linux x86-64 seccomp",
    ))
}

fn send_signal(child: &Child, signal: i32) -> Result<(), Error> {
    let pid = i32::try_from(child.id()).map_err(|_| unavailable())?;
    // SAFETY: `pid` is the child process ID returned by `Command::spawn` and
    // the signal is one of SIGTERM/SIGKILL selected by this module.
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(unavailable())
    }
}

fn wait_for(child: &mut Child, duration: Duration) -> Result<Option<ExitStatus>, Error> {
    let deadline = Instant::now()
        .checked_add(duration)
        .ok_or_else(unavailable)?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(_) => return Err(unavailable()),
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn stop_after_bound(child: &mut Child) -> Result<ExitStatus, Error> {
    let _ = send_signal(child, libc::SIGTERM);
    if let Ok(Some(status)) = wait_for(child, TERM_GRACE) {
        return Ok(status);
    }
    // A failed TERM or an interrupted wait must not prevent the hard stop.
    // Cleanup is best effort here; callers retain their primary error when
    // they entered this path because observation already failed.
    let _ = send_signal(child, libc::SIGKILL);
    if let Ok(Some(status)) = wait_for(child, KILL_WAIT) {
        return Ok(status);
    }
    // Do not turn the bounded cleanup into an unbounded wait.  SIGKILL is
    // retried once in case the process crossed the first wait boundary.
    let _ = send_signal(child, libc::SIGKILL);
    match child.try_wait() {
        Ok(Some(status)) => Ok(status),
        Ok(None) | Err(_) => Err(unavailable()),
    }
}

fn run_player(
    player: Player,
    argv: &[String],
    max_seconds: u64,
    media_file: &File,
    subtitle_file: Option<&File>,
) -> Result<PlayerObservation, Error> {
    let media_fd = media_file.as_raw_fd();
    let subtitle_fd = subtitle_file.map(|file| file.as_raw_fd());
    let started = Instant::now();
    let mut command = Command::new(player.executable());
    command
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let parent_fds = inherited_parent_fds(media_fd, subtitle_fd)?;
    // SAFETY: the closure performs only async-signal-safe fcntl operations
    // on descriptors duplicated for this child plus the child-only seccomp
    // and descriptor-isolation syscalls.  It runs after stdio setup and
    // before exec, leaving the parent's descriptors and sandbox unchanged.
    unsafe {
        command.pre_exec(move || {
            close_inherited_fds(&parent_fds)?;
            clear_close_on_exec(media_fd)?;
            if let Some(fd) = subtitle_fd
                && fd != media_fd
            {
                clear_close_on_exec(fd)?;
            }
            install_network_sandbox()?;
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| unavailable())?;
    let bound = Duration::from_secs(max_seconds);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(PlayerObservation {
                    status,
                    stopped_by_bound: false,
                });
            }
            Ok(None) => {}
            Err(_) => {
                // Preserve the observation error; cleanup failure must not
                // replace the primary result or trigger an unbounded wait.
                let _ = stop_after_bound(&mut child);
                return Err(unavailable());
            }
        }
        if started.elapsed() >= bound {
            let status = stop_after_bound(&mut child)?;
            return Ok(PlayerObservation {
                status,
                stopped_by_bound: true,
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn exit_status_json(status: &ExitStatus) -> Value {
    json!({
        "code": status.code(),
        "signal": status.signal(),
        "success": status.success(),
    })
}

/// Launch a bounded local mpv/VLC replay and report only structural facts.
/// `authorized` is an operator attestation, not proof of media rights.
pub fn replay(input: &str) -> Result<Value, Error> {
    let request = parse_input(input)?;
    let media = prepare_media(&request)?;
    let subtitle = prepare_subtitle(&request)?;
    // The player receives proc-fd paths backed by descriptors admitted and
    // hashed above.  The duplicates remain alive through the whole child
    // lifetime, so a pathname replacement cannot change what is opened.
    let media_for_child = duplicate_for_child(&media.file)?;
    let subtitle_for_child = subtitle
        .as_ref()
        .map(|value| duplicate_for_child(value.file()))
        .transpose()?;
    let media_arg = descriptor_path(&media_for_child);
    let subtitle_arg = subtitle
        .as_ref()
        .zip(subtitle_for_child.as_ref())
        .map(|(_, file)| descriptor_path(file));
    let argv = build_argv(
        request.player,
        &media_arg,
        subtitle_arg.as_deref(),
        subtitle.as_ref().map(|value| value.format),
        request.seek_seconds,
        request.headless,
    );
    let observation = run_player(
        request.player,
        &argv,
        request.max_seconds,
        &media_for_child,
        subtitle_for_child.as_ref(),
    )?;
    let result = if observation.stopped_by_bound {
        "stopped_by_bound"
    } else if observation.status.success() {
        "completed"
    } else {
        "failed"
    };
    let subtitle_value = subtitle.as_ref().map(|value| {
        json!({
            "submitted": true,
            "format": value.format.as_str(),
            "byte_length": value.identity.byte_length,
            "sha256": value.identity.sha256,
        })
    });
    let subtitle_value = match subtitle_value {
        Some(value) => value,
        None => json!({
            "submitted": false,
            "format": Value::Null,
            "byte_length": Value::Null,
            "sha256": Value::Null,
        }),
    };
    Ok(json!({
        "schema_version": 1,
        "type": "recording_replay",
        "result": result,
        "player": request.player.as_str(),
        "headless": request.headless,
        "subtitle": subtitle_value,
        "media": {
            "kind": "local_file",
            "byte_length": media.identity.byte_length,
            "sha256": media.identity.sha256,
        },
        "submitted": {
            "media_descriptor": true,
            "subtitle_argv": subtitle.is_some(),
            "seek_seconds": request.seek_seconds,
            "max_seconds": request.max_seconds,
        },
        "observed_exit": {
            "process_launch": true,
            "status": exit_status_json(&observation.status),
            "stopped_by_bound": observation.stopped_by_bound,
        },
        "unverified": {
            "audio_output": true,
            "video_output": true,
            "subtitle_rendering": true,
            "subtitle_injection": true,
            "subtitle_synchronization": true,
            "live_playback": true,
            "media_rights": true,
        },
    }))
}

/// Return the standalone input/output schema for `recordings replay`.
pub fn schema() -> Value {
    let hash = json!({"type":"string","pattern":"^[0-9a-f]{64}$"});
    let segment = json!({
        "type":"object",
        "required":["start_ms","end_ms","text"],
        "properties":{
            "start_ms":{"type":"integer","minimum":0},
            "end_ms":{"type":"integer","minimum":0},
            "text":{"type":"string","maxLength":MAX_SEGMENT_TEXT},
        },
        "additionalProperties":true,
    });
    json!({
            "input": {
                "$schema":"https://json-schema.org/draft/2020-12/schema",
                "type":"object",
                "additionalProperties":false,
                "required":["authorized","media","player"],
                "properties":{
                    "authorized":{"const":true,"description":"Operator attestation only; media rights are not verified."},
                    "media":{
                        "type":"object",
                        "additionalProperties":false,
                        "oneOf":[
                            {"type":"object","required":["path"],"properties":{"path":{"type":"string","minLength":1,"maxLength":MAX_PATH},"url":{"type":"null"}}},
                            {"type":"object","required":["url"],"properties":{"url":{"type":"string","minLength":1,"maxLength":MAX_URL},"path":{"type":"null"}}}
                        ],
                        "properties":{"path":{"type":["string","null"]},"url":{"type":["string","null"]}}
                    },
                    "player":{"enum":["mpv","vlc"]},
                    "headless":{"type":"boolean","default":false,"description":"Use null/dummy audio/video sinks only when explicitly true."},
                    "subtitles":{
                        "type":["object","null"],
                        "additionalProperties":false,
                        "oneOf":[
                            {"type":"object","required":["path"],"properties":{"path":{"type":"string","minLength":1,"maxLength":MAX_PATH},"segments":{"type":"null"}}},
                            {"type":"object","required":["segments"],"properties":{"path":{"type":"null"},"segments":{"type":"array","minItems":1,"maxItems":MAX_SEGMENTS,"items":segment}}},
                            {"type":"null"}
                        ],
                        "properties":{"path":{"type":["string","null"]},"segments":{"type":["array","null"]}}
                    },
                    "seek_seconds":{"type":"integer","minimum":0,"default":0},
                    "max_seconds":{"type":"integer","minimum":1,"maximum":3600,"default":120},
                    "private_dir":{"type":["string","null"],"minLength":1,"maxLength":MAX_PATH,"description":"Required for generated SRT; existing owner-controlled 0700 absolute directory with no symlink components."},
                }
            },
            "output": {
                "$schema":"https://json-schema.org/draft/2020-12/schema",
                "type":"object",
                "additionalProperties":false,
                "required":["schema_version","type","result","player","headless","subtitle","media","submitted","observed_exit","unverified"],
                "properties":{
                    "schema_version":{"const":1},
                    "type":{"const":"recording_replay"},
                    "result":{"enum":["completed","stopped_by_bound","failed"]},
                    "player":{"enum":["mpv","vlc"]},
                    "headless":{"type":"boolean"},
                    "subtitle":{"type":"object","additionalProperties":false,"required":["submitted","format","byte_length","sha256"],"properties":{"submitted":{"type":"boolean"},"format":{"type":["string","null"],"enum":["srt","vtt",null]},"byte_length":{"type":["integer","null"],"minimum":0},"sha256":{"anyOf":[hash,{"type":"null"}]} }},
                    "media":{"type":"object","additionalProperties":false,"required":["kind","byte_length","sha256"],"properties":{"kind":{"const":"local_file"},"byte_length":{"type":"integer","minimum":0},"sha256":hash}},
                    "submitted":{"type":"object","additionalProperties":false,"required":["media_descriptor","subtitle_argv","seek_seconds","max_seconds"],"properties":{"media_descriptor":{"const":true},"subtitle_argv":{"type":"boolean"},"seek_seconds":{"type":"integer","minimum":0},"max_seconds":{"type":"integer","minimum":1,"maximum":3600}}},
                    "observed_exit":{"type":"object","additionalProperties":false,"required":["process_launch","status","stopped_by_bound"],"properties":{"process_launch":{"const":true},"status":{"type":"object","additionalProperties":false,"required":["code","signal","success"],"properties":{"code":{"type":["integer","null"]},"signal":{"type":["integer","null"]},"success":{"type":"boolean"}}},"stopped_by_bound":{"type":"boolean"}}},
                    "unverified":{"type":"object","additionalProperties":false,"required":["audio_output","video_output","subtitle_rendering","subtitle_injection","subtitle_synchronization","live_playback","media_rights"],"properties":{"audio_output":{"const":true},"video_output":{"const":true},"subtitle_rendering":{"const":true},"subtitle_injection":{"const":true},"subtitle_synchronization":{"const":true},"live_playback":{"const":true},"media_rights":{"const":true}}}
                }
            },
            "limits":{"max_input_bytes":MAX_INPUT,"max_subtitle_bytes":MAX_SUBTITLE_BYTES,"max_media_bytes":MAX_MEDIA_BYTES,"max_seconds":3600},
            "network_policy":{"remote_media":"refused; no generic governed media-origin profile exists","local_media":"no network"}
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "buaa-replay-test-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("test permissions");
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn input_validation_rejects_unauthorized_remote_and_duplicate_sources() {
        let unauthorized = r#"{"authorized":false,"media":{"path":"/tmp/media"},"player":"mpv"}"#;
        assert_eq!(parse_input(unauthorized).unwrap_err().code, "permission");
        let defaulted =
            parse_input(r#"{"authorized":true,"media":{"path":"/tmp/media"},"player":"mpv"}"#)
                .expect("default headless mode");
        assert!(!defaulted.headless);
        let duplicate = r#"{"authorized":true,"media":{"path":"/tmp/media","url":"https://example.test/media"},"player":"mpv"}"#;
        assert_eq!(parse_input(duplicate).unwrap_err().code, "invalid_input");
        let credential_url = r#"{"authorized":true,"media":{"url":"https://user:pass@example.test/media"},"player":"mpv"}"#;
        assert_eq!(
            parse_input(credential_url).unwrap_err().code,
            "invalid_input"
        );
    }

    #[test]
    fn path_safety_keeps_direct_argv_chars_and_rejects_controls() {
        use std::os::unix::fs::symlink;

        assert!(validate_path_text("relative/file.mp4").is_err());
        assert!(validate_path_text("/private/unsafe;file [1].mp4").is_ok());
        assert!(validate_path_text("/private/unsafe\nfile.mp4").is_err());
        assert!(validate_path_text("/private/unsafe\0file.mp4").is_err());
        let root = TempRoot::new();
        let writable = root.0.join("writable");
        fs::create_dir(&writable).expect("writable directory");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777))
            .expect("writable permissions");
        assert!(parent_and_name(&writable.join("media.mp4")).is_err());
        let target = root.0.join("target");
        fs::create_dir(&target).expect("target directory");
        let link = root.0.join("parent-link");
        symlink(&target, &link).expect("parent symlink");
        assert!(parent_and_name(&link.join("media.mp4")).is_err());
    }

    #[test]
    fn digest_helper_streams_a_file_with_identity() {
        let root = TempRoot::new();
        let path = root.0.join("media.mp4");
        let bytes = b"bounded media bytes";
        fs::write(&path, bytes).expect("media fixture");
        let file = open_local_file(path, MAX_MEDIA_BYTES).expect("safe media");
        assert_eq!(file.identity.byte_length, bytes.len() as u64);
        assert_eq!(file.identity.sha256, digest_bytes(bytes));
    }

    #[test]
    fn generated_subtitle_is_readable_and_removed_after_use() {
        let root = TempRoot::new();
        let directory = crate::governor::open_directory(&root.0, false, true)
            .expect("private subtitle directory");
        let bytes = b"1\r\n00:00:00,000 --> 00:00:01,000\r\nLocal cue\r\n\r\n";
        let mut temporary =
            create_temporary_subtitle(directory, bytes).expect("readable generated subtitle");
        let path = root.0.join(temporary.name.to_str().unwrap());
        let mut actual = Vec::new();
        temporary
            .file
            .read_to_end(&mut actual)
            .expect("read subtitle descriptor");
        assert_eq!(actual, bytes);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        drop(temporary);
        assert!(!path.exists());
    }

    #[test]
    fn schema_one_of_branches_are_type_disjoint() {
        let input = schema()["input"].clone();
        let media = &input["properties"]["media"]["oneOf"];
        assert_eq!(media[0]["type"], "object");
        assert_eq!(media[1]["type"], "object");
        let subtitles = &input["properties"]["subtitles"]["oneOf"];
        assert_eq!(subtitles[0]["type"], "object");
        assert_eq!(subtitles[1]["type"], "object");
        assert_eq!(subtitles[2]["type"], "null");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn child_sandbox_denies_non_unix_sockets_and_io_uring() {
        // A bare fork can retain another test thread's flock lease after that
        // thread drops it. Exec first, as the governor subprocess tests do, so
        // unrelated CLOEXEC descriptors cannot outlive their owners here.
        let module = module_path!().split_once("::").unwrap().1;
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("{module}::network_sandbox_worker"),
                "--ignored",
                "--nocapture",
            ])
            .env("BUAA_REPLAY_SANDBOX_WORKER", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        let result: [i32; 3] = serde_json::from_str(
            stderr
                .lines()
                .find_map(|line| line.strip_prefix("BUAA_SANDBOX_RESULT="))
                .expect("sandbox worker result"),
        )
        .unwrap();
        assert_eq!(result[0], libc::EPERM);
        assert_eq!(result[1], 1);
        assert_eq!(result[2], libc::EPERM);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    #[ignore = "subprocess entry point invoked by the offline sandbox regression"]
    fn network_sandbox_worker() {
        if std::env::var("BUAA_REPLAY_SANDBOX_WORKER").ok().as_deref() != Some("1") {
            return;
        }
        install_network_sandbox().unwrap();
        // SAFETY: these socket/syscall probes have scalar arguments, no borrowed
        // memory and close each descriptor that is unexpectedly admitted.
        let result = unsafe {
            let internet = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            let internet_errno = if internet < 0 {
                io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or_default()
            } else {
                libc::close(internet);
                0
            };
            let unix = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            let unix_allowed = unix >= 0;
            if unix_allowed {
                libc::close(unix);
            }
            let ring = libc::syscall(
                libc::SYS_io_uring_setup,
                1_u32,
                std::ptr::null_mut::<libc::c_void>(),
            );
            let ring_errno = if ring < 0 {
                io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or_default()
            } else {
                libc::close(ring as i32);
                0
            };
            [internet_errno, i32::from(unix_allowed), ring_errno]
        };
        eprintln!("BUAA_SANDBOX_RESULT={}", json!(result));
    }
}
