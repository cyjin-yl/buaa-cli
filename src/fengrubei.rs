//! Pinned, governed retrieval of one upstream Fengrubei template release.
//! The archive is never unpacked, executed, compiled, or relicensed here.
use crate::governor::{self, Governor, Outcome};
use crate::net::{self, Error};
use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;
use url::Url;

const MAX_INPUT: usize = 16 * 1024;
const MAX_ROBOTS: u64 = 1024 * 1024;
const MAX_REDIRECT_BODY: u64 = 4096;
const CACHE_DIR: &str = ".buaa-cli-fengrubei-cache";

struct ReleaseSpec {
    tag: &'static str,
    commit: &'static str,
    asset_name: &'static str,
    asset_url: &'static str,
    bytes: u64,
    sha256: &'static str,
}

const RELEASE: ReleaseSpec = ReleaseSpec {
    tag: "v1.0.3",
    commit: "20e27c67ebf09cc730d8988d7395d9a8d34acf47",
    asset_name: "v1.0.3.Fengrubei_LaTeX_Template.zip",
    asset_url: "https://github.com/GFCYqw/Fengrubei_LaTeX_Template/releases/download/v1.0.3/v1.0.3.Fengrubei_LaTeX_Template.zip",
    bytes: 52_816_733,
    sha256: "08b9ab2e06e440e462b6d8a65e77d579277613fe3cfb31b4bded7cd34e7177d1",
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchInput {
    output: String,
}

fn unavailable() -> Error {
    Error::new("unavailable", "pinned template artifact is unavailable")
}
fn conflict() -> Error {
    Error::new(
        "conflict",
        "template cache or output conflicts with the pinned artifact",
    )
}

pub fn info() -> Value {
    json!({
        "schema_version": 1,
        "type": "fengrubei_template",
        "result": "pinned_release",
        "upstream": {
            "repository": "https://github.com/GFCYqw/Fengrubei_LaTeX_Template",
            "tag": RELEASE.tag,
            "commit": RELEASE.commit,
            "asset_name": RELEASE.asset_name,
            "asset_url": RELEASE.asset_url,
            "bytes": RELEASE.bytes,
            "sha256": RELEASE.sha256,
            "license": "LPPL-1.3c-or-later",
            "license_url": "https://github.com/GFCYqw/Fengrubei_LaTeX_Template/blob/v1.0.3/LICENSE"
        },
        "behavior": {
            "cache_default": "offline",
            "unpacks": false,
            "executes_scripts": false,
            "compiles_template": false,
            "overwrites_output": false
        },
        "caveats": [
            "community_template_not_official_current_format_guarantee",
            "compare_with_current_competition_rules_before_use",
            "archive_contains_font_files_requiring_separate_license_and_runtime_review",
            "XeLaTeX_and_platform_fonts_may_be_required",
            "downloaded_bytes_remain_upstream_LPPL_material_not_project_MIT_source"
        ]
    })
}

fn open_cache_directory() -> Result<File, Error> {
    let home = governor::identity_home().map_err(|_| unavailable())?;
    let _home = governor::open_directory(&home, false, false).map_err(|_| unavailable())?;
    governor::open_directory(&home.join(CACHE_DIR), true, true).map_err(|_| unavailable())
}

fn verified_cache(directory: &File, spec: &ReleaseSpec) -> Result<Option<File>, Error> {
    let mut file = match governor::open_child(directory, spec.asset_name, libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    governor::validate_private_file(&file).map_err(|_| conflict())?;
    if file.metadata().map_err(|_| unavailable())?.len() != spec.bytes {
        return Err(conflict());
    }
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| unavailable())?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(unavailable)?;
        if total > spec.bytes {
            return Err(conflict());
        }
        hash.update(&buffer[..read]);
    }
    if total != spec.bytes || format!("{:x}", hash.finalize()) != spec.sha256 {
        return Err(conflict());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| unavailable())?;
    Ok(Some(file))
}

struct OutputTarget {
    directory: File,
    name: String,
}

fn prepare_output(output: &str) -> Result<OutputTarget, Error> {
    if output.len() > 4096 || output.contains('\0') || !Path::new(output).is_absolute() {
        return Err(Error::new(
            "invalid_input",
            "template output path must be an absolute new file in a safe directory",
        ));
    }
    let path = Path::new(output);
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or_else(|| Error::new("invalid_input", "template output path must name a new file"))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::new("invalid_input", "template output path must name a new file"))?
        .to_owned();
    if name.as_bytes().contains(&0) {
        return Err(Error::new(
            "invalid_input",
            "template output path is invalid",
        ));
    }
    let directory = governor::open_directory(parent, false, false).map_err(|_| {
        Error::new(
            "permission",
            "template output parent must be owner-controlled and free of symlinks",
        )
    })?;
    match governor::open_child(&directory, &name, libc::O_RDONLY) {
        Ok(_) => return Err(conflict()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(conflict()),
    }
    Ok(OutputTarget { directory, name })
}

fn copy_new(mut source: File, output: &OutputTarget, spec: &ReleaseSpec) -> Result<(), Error> {
    let name = CString::new(output.name.as_bytes()).map_err(|_| unavailable())?;
    let mut target = governor::open_child(
        &output.directory,
        &output.name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )
    .map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            conflict()
        } else {
            unavailable()
        }
    })?;
    let result = (|| {
        // openat creation mode is affected by umask; enforce the published mode.
        // SAFETY: target is our live, exclusively-created regular-file candidate.
        if unsafe { libc::fchmod(target.as_raw_fd(), 0o600) } != 0 {
            return Err(unavailable());
        }
        governor::validate_private_file(&target).map_err(|_| conflict())?;
        let opened = target.metadata().map_err(|_| unavailable())?;
        let copied = std::io::copy(&mut source, &mut target).map_err(|_| unavailable())?;
        if copied != spec.bytes {
            return Err(conflict());
        }
        target.sync_all().map_err(|_| unavailable())?;
        let current = governor::open_child(&output.directory, &output.name, libc::O_RDONLY)
            .map_err(|_| conflict())?;
        governor::validate_private_file(&current).map_err(|_| conflict())?;
        let current = current.metadata().map_err(|_| conflict())?;
        if current.dev() != opened.dev() || current.ino() != opened.ino() {
            return Err(conflict());
        }
        output.directory.sync_all().map_err(|_| unavailable())
    })();
    if result.is_err() {
        // SAFETY: the name is one validated component in the pinned safe parent.
        unsafe { libc::unlinkat(output.directory.as_raw_fd(), name.as_ptr(), 0) };
    }
    result
}

struct SmallResponse {
    status: u16,
    body: Vec<u8>,
    location: Option<String>,
}

struct Downloader<'a> {
    spec: &'a ReleaseSpec,
    directory: &'a File,
    governor: Governor,
    client: Client,
    #[cfg(test)]
    route: Option<std::net::SocketAddr>,
}

impl<'a> Downloader<'a> {
    fn open(spec: &'a ReleaseSpec, directory: &'a File) -> Result<Self, Error> {
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .http1_only()
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(90))
            .user_agent("buaa-cli/0.1 fengrubei-template")
            .build()
            .map_err(|_| unavailable())?;
        Ok(Self {
            spec,
            directory,
            governor: Governor::open().map_err(|_| unavailable())?,
            client,
            #[cfg(test)]
            route: None,
        })
    }

    fn request_url(&self, url: &Url) -> Url {
        #[cfg(test)]
        if let Some(address) = self.route {
            let mut routed = url.clone();
            routed.set_scheme("http").expect("test HTTP scheme");
            routed
                .set_host(Some(&address.ip().to_string()))
                .expect("test loopback host");
            routed
                .set_port(Some(address.port()))
                .expect("test loopback port");
            return routed;
        }
        url.clone()
    }

    fn classify(
        lease: crate::governor::RequestLease<'_>,
        response: Response,
        network_failure: bool,
    ) -> Result<(u16, Option<String>, bool), Error> {
        let status = response.status().as_u16();
        let retry = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let challenge = response
            .headers()
            .get_all("cf-mitigated")
            .iter()
            .any(|v| v.as_bytes().eq_ignore_ascii_case(b"challenge"));
        drop(response);
        lease
            .finish(Outcome::Http {
                status,
                retry_after: retry.as_deref(),
                challenge,
                network_failure,
            })
            .map_err(|_| unavailable())?;
        if challenge || matches!(status, 401 | 403) {
            return Err(Error::new(
                "auth_latched",
                "template source access was rejected",
            ));
        }
        if status == 429 {
            return Err(Error::new(
                "rate_limited",
                "template source requested a cooldown",
            ));
        }
        if network_failure {
            return Err(unavailable());
        }
        Ok((status, retry, challenge))
    }

    fn small_get(&self, original: &Url, max: u64) -> Result<SmallResponse, Error> {
        let lease = net::acquire(&self.governor)?;
        let mut response = match self
            .client
            .get(self.request_url(original))
            .header("Accept-Encoding", "identity")
            .send()
        {
            Ok(response) => response,
            Err(_) => {
                lease
                    .finish(Outcome::NetworkFailure)
                    .map_err(|_| unavailable())?;
                return Err(unavailable());
            }
        };
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let status = response.status().as_u16();
        let retry = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let challenge = response
            .headers()
            .get_all("cf-mitigated")
            .iter()
            .any(|v| v.as_bytes().eq_ignore_ascii_case(b"challenge"));
        let mut body = Vec::new();
        let read = response.by_ref().take(max + 1).read_to_end(&mut body);
        let failed = read.is_err() || body.len() as u64 > max;
        drop(response);
        lease
            .finish(Outcome::Http {
                status,
                retry_after: retry.as_deref(),
                challenge,
                network_failure: read.is_err(),
            })
            .map_err(|_| unavailable())?;
        if challenge || matches!(status, 401 | 403) {
            return Err(Error::new(
                "auth_latched",
                "template source access was rejected",
            ));
        }
        if status == 429 {
            return Err(Error::new(
                "rate_limited",
                "template source requested a cooldown",
            ));
        }
        if failed {
            return Err(unavailable());
        }
        Ok(SmallResponse {
            status,
            body,
            location,
        })
    }

    fn robots(&self, robots: &str, target: &str) -> Result<(), Error> {
        let robots = Url::parse(robots).map_err(|_| unavailable())?;
        let response = self.small_get(&robots, MAX_ROBOTS)?;
        if matches!(response.status, 404 | 410) {
            return Ok(());
        }
        if response.status != 200 {
            return Err(unavailable());
        }
        let body = std::str::from_utf8(&response.body).map_err(|_| unavailable())?;
        if robotstxt::DefaultMatcher::default()
            .one_agent_allowed_by_robots(body, "buaa-cli", target)
        {
            Ok(())
        } else {
            Err(Error::new(
                "permission",
                "template source robots policy disallows retrieval",
            ))
        }
    }

    fn download(&self) -> Result<(), Error> {
        let original = Url::parse(self.spec.asset_url).map_err(|_| unavailable())?;
        self.robots("https://github.com/robots.txt", self.spec.asset_url)?;
        let redirect = self.small_get(&original, MAX_REDIRECT_BODY)?;
        if redirect.status != 302 || !redirect.body.is_empty() {
            return Err(unavailable());
        }
        let location = redirect.location.ok_or_else(unavailable)?;
        let target = Url::parse(&location).map_err(|_| unavailable())?;
        if target.scheme() != "https"
            || target.host_str() != Some("release-assets.githubusercontent.com")
            || !target.username().is_empty()
            || target.password().is_some()
            || target.port().is_some()
            || target.fragment().is_some()
        {
            return Err(unavailable());
        }
        self.robots(
            "https://release-assets.githubusercontent.com/robots.txt",
            &location,
        )?;
        // Reserve private cache storage before the final network lease. A local
        // allocation failure must never abandon a durably pending request.
        let (temporary_name, temporary) =
            governor::create_temporary(self.directory).map_err(|_| unavailable())?;
        let result = self.download_asset(&target, &temporary_name, temporary);
        if result.is_err() {
            // SAFETY: temporary_name was exclusively created in this pinned directory.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
        }
        result
    }

    fn download_asset(
        &self,
        target: &Url,
        temporary_name: &CString,
        mut temporary: File,
    ) -> Result<(), Error> {
        let lease = net::acquire(&self.governor)?;
        let mut response = match self
            .client
            .get(self.request_url(target))
            .header("Accept-Encoding", "identity")
            .send()
        {
            Ok(response) => response,
            Err(_) => {
                lease
                    .finish(Outcome::NetworkFailure)
                    .map_err(|_| unavailable())?;
                return Err(unavailable());
            }
        };
        let status = response.status().as_u16();
        let retry = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let challenge = response
            .headers()
            .get_all("cf-mitigated")
            .iter()
            .any(|value| value.as_bytes().eq_ignore_ascii_case(b"challenge"));
        let encoding_ok = response
            .headers()
            .get_all("content-encoding")
            .iter()
            .all(|value| value.as_bytes().eq_ignore_ascii_case(b"identity"));
        if status != 200 || challenge || !encoding_ok {
            let _ = Self::classify(lease, response, false)?;
            return Err(unavailable());
        }
        if response
            .content_length()
            .is_some_and(|length| length != self.spec.bytes)
        {
            let _ = Self::classify(lease, response, false)?;
            return Err(conflict());
        }
        let mut hash = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        let mut body_read_failed = false;
        let result = (|| {
            loop {
                let read = match response.read(&mut buffer) {
                    Ok(read) => read,
                    Err(_) => {
                        body_read_failed = true;
                        return Err(unavailable());
                    }
                };
                if read == 0 {
                    break;
                }
                total = total.checked_add(read as u64).ok_or_else(unavailable)?;
                if total > self.spec.bytes {
                    return Err(conflict());
                }
                temporary
                    .write_all(&buffer[..read])
                    .map_err(|_| unavailable())?;
                hash.update(&buffer[..read]);
            }
            if total != self.spec.bytes || format!("{:x}", hash.finalize()) != self.spec.sha256 {
                return Err(conflict());
            }
            temporary.sync_all().map_err(|_| unavailable())?;
            let target_name = CString::new(self.spec.asset_name).map_err(|_| unavailable())?;
            // SAFETY: fixed single-component asset name and exclusively-created temporary.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    self.directory.as_raw_fd(),
                    target_name.as_ptr(),
                )
            } != 0
            {
                return Err(unavailable());
            }
            self.directory.sync_all().map_err(|_| unavailable())
        })();
        drop(response);
        let finished = lease.finish(Outcome::Http {
            status,
            retry_after: retry.as_deref(),
            challenge,
            network_failure: body_read_failed,
        });
        finished.map_err(|_| unavailable())?;
        result
    }
}

fn parse_fetch_input(input: &str) -> Result<OutputTarget, Error> {
    if input.len() > MAX_INPUT {
        return Err(Error::new(
            "invalid_input",
            "invalid template fetch request",
        ));
    }
    let request: FetchInput = serde_json::from_str(input)
        .map_err(|_| Error::new("invalid_input", "invalid template fetch request"))?;
    prepare_output(&request.output)
}

fn fetch_prepared(
    output: OutputTarget,
    online: bool,
    directory: &File,
    spec: &ReleaseSpec,
    download: impl FnOnce() -> Result<(), Error>,
) -> Result<Value, Error> {
    let cache_status = match verified_cache(directory, spec)? {
        Some(file) => {
            copy_new(file, &output, spec)?;
            "hit"
        }
        None if !online => {
            return Err(Error::new(
                "offline_miss",
                "pinned template artifact is not in the local cache",
            ));
        }
        None => {
            download()?;
            let file = verified_cache(directory, spec)?.ok_or_else(unavailable)?;
            copy_new(file, &output, spec)?;
            "miss"
        }
    };
    Ok(json!({
        "schema_version":1,"type":"fengrubei_template","result":"written_new_file",
        "tag":spec.tag,"commit":spec.commit,"asset_name":spec.asset_name,
        "bytes":spec.bytes,"sha256":spec.sha256,"cache_status":cache_status,
        "license":"LPPL-1.3c-or-later","output_overwritten":false,"archive_unpacked":false,"scripts_executed":false,
        "format_compliance_verified":false,"font_licenses_verified_by_buaa_cli":false
    }))
}

#[cfg(test)]
fn fetch_from(
    input: &str,
    online: bool,
    directory: &File,
    spec: &ReleaseSpec,
    download: impl FnOnce() -> Result<(), Error>,
) -> Result<Value, Error> {
    let output = parse_fetch_input(input)?;
    fetch_prepared(output, online, directory, spec, download)
}

pub fn fetch(input: &str, online: bool) -> Result<Value, Error> {
    let output = parse_fetch_input(input)?;
    let directory = open_cache_directory()?;
    fetch_prepared(output, online, &directory, &RELEASE, || {
        Downloader::open(&RELEASE, &directory)?.download()
    })
}

pub fn schema() -> Value {
    json!({
        "info":{"input":{"type":"null"},"output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","upstream","behavior","caveats"],"properties":{"schema_version":{"const":1},"type":{"const":"fengrubei_template"},"result":{"const":"pinned_release"},"upstream":{"type":"object","additionalProperties":false,"required":["repository","tag","commit","asset_name","asset_url","bytes","sha256","license","license_url"],"properties":{"repository":{"const":"https://github.com/GFCYqw/Fengrubei_LaTeX_Template"},"tag":{"const":"v1.0.3"},"commit":{"const":"20e27c67ebf09cc730d8988d7395d9a8d34acf47"},"asset_name":{"const":"v1.0.3.Fengrubei_LaTeX_Template.zip"},"asset_url":{"const":RELEASE.asset_url},"bytes":{"const":52816733},"sha256":{"const":RELEASE.sha256},"license":{"const":"LPPL-1.3c-or-later"},"license_url":{"type":"string"}}},"behavior":{"type":"object","additionalProperties":false,"required":["cache_default","unpacks","executes_scripts","compiles_template","overwrites_output"],"properties":{"cache_default":{"const":"offline"},"unpacks":{"const":false},"executes_scripts":{"const":false},"compiles_template":{"const":false},"overwrites_output":{"const":false}}},"caveats":{"type":"array","minItems":5,"maxItems":5,"items":{"type":"string"}}}}},
        "fetch":{"input":{"type":"object","additionalProperties":false,"required":["output"],"properties":{"output":{"type":"string","minLength":2,"maxLength":4096,"pattern":r"^/[^\u0000]+$","description":"Absolute path to a new file in an owner-controlled, symlink-free parent directory."}}},
            "options":{"--online":"explicitly permit governed retrieval on a cache miss"},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","tag","commit","asset_name","bytes","sha256","cache_status","license","output_overwritten","archive_unpacked","scripts_executed","format_compliance_verified","font_licenses_verified_by_buaa_cli"],"properties":{"schema_version":{"const":1},"type":{"const":"fengrubei_template"},"result":{"const":"written_new_file"},"tag":{"const":"v1.0.3"},"commit":{"const":"20e27c67ebf09cc730d8988d7395d9a8d34acf47"},"asset_name":{"const":"v1.0.3.Fengrubei_LaTeX_Template.zip"},"bytes":{"const":52816733},"sha256":{"const":"08b9ab2e06e440e462b6d8a65e77d579277613fe3cfb31b4bded7cd34e7177d1"},"cache_status":{"enum":["hit","miss"]},"license":{"const":"LPPL-1.3c-or-later"},"output_overwritten":{"const":false},"archive_unpacked":{"const":false},"scripts_executed":{"const":false},"format_compliance_verified":{"const":false},"font_licenses_verified_by_buaa_cli":{"const":false}}}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const TEST_RELEASE: ReleaseSpec = ReleaseSpec {
        tag: "test",
        commit: "0000000000000000000000000000000000000000",
        asset_name: "template.zip",
        asset_url: RELEASE.asset_url,
        bytes: 22,
        sha256: "6d6e4253d369a4c6c68d62c5fe388955917b1d8957985649e2da9f06b33c41e7",
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "buaa-fengrubei-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn cache(&self) -> File {
            governor::open_directory(&self.0.join("cache"), true, true).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Server {
        address: std::net::SocketAddr,
        requests: mpsc::Receiver<(Instant, String)>,
        count: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }
    impl Server {
        fn new(mut handler: impl FnMut(&mut TcpStream, &str, usize) + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let (sender, requests) = mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let count = Arc::new(AtomicUsize::new(0));
            let worker_stop = Arc::clone(&stop);
            let worker_count = Arc::clone(&count);
            let worker = thread::spawn(move || {
                while !worker_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            socket
                                .set_read_timeout(Some(Duration::from_secs(5)))
                                .unwrap();
                            let mut bytes = Vec::new();
                            let mut byte = [0u8];
                            while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 32 * 1024 {
                                match socket.read(&mut byte) {
                                    Ok(1) => bytes.push(byte[0]),
                                    _ => break,
                                }
                            }
                            let request = String::from_utf8(bytes).unwrap();
                            let index = worker_count.fetch_add(1, Ordering::SeqCst);
                            sender.send((Instant::now(), request.clone())).unwrap();
                            handler(&mut socket, &request, index);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("loopback listener failed: {error}"),
                    }
                }
            });
            Self {
                address,
                requests,
                count,
                stop,
                worker: Some(worker),
            }
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }
    fn reply(socket: &mut TcpStream, status: u16, headers: &str, body: &[u8]) {
        write!(
            socket,
            "HTTP/1.1 {status} Fixture\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
            body.len()
        )
        .unwrap();
        socket.write_all(body).unwrap();
    }
    fn test_downloader<'a>(
        fixture: &Fixture,
        directory: &'a File,
        server: &Server,
    ) -> Downloader<'a> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .http1_only()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        Downloader {
            spec: &TEST_RELEASE,
            directory,
            governor: Governor::isolated_for_test(&fixture.0.join("governor")).unwrap(),
            client,
            route: Some(server.address),
        }
    }

    #[test]
    fn pinned_info_discloses_license_integrity_and_caveats() {
        let value = info();
        assert_eq!(value["upstream"]["tag"], "v1.0.3");
        assert_eq!(value["upstream"]["sha256"], RELEASE.sha256);
        assert_eq!(value["upstream"]["license"], "LPPL-1.3c-or-later");
        assert_eq!(value["behavior"]["unpacks"], false);
        assert!(value["caveats"].as_array().unwrap().len() >= 4);
        assert_eq!(
            schema()["fetch"]["input"]["properties"]["output"]["pattern"],
            r"^/[^\u0000]+$"
        );
    }

    #[test]
    fn governed_redirect_download_is_verified_cached_and_never_overwritten() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, request, index| {
            assert!(!request.to_ascii_lowercase().contains("cookie:"));
            match index {
                0 | 2 => reply(socket, 404, "", b""),
                1 => reply(
                    socket,
                    302,
                    "Location: https://release-assets.githubusercontent.com/signed/template\r\n",
                    b"",
                ),
                3 => reply(
                    socket,
                    200,
                    "Content-Type: application/zip\r\n",
                    b"synthetic-template-zip",
                ),
                _ => panic!("unexpected extra request"),
            }
        });
        let cache = fixture.cache();
        let downloader = test_downloader(&fixture, &cache, &server);
        let first_path = fixture.0.join("first.zip");
        let first_input = json!({"output":first_path}).to_string();
        let first = fetch_from(&first_input, true, &cache, &TEST_RELEASE, || {
            downloader.download()
        })
        .unwrap();
        assert_eq!(first["cache_status"], "miss");
        assert_eq!(fs::read(&first_path).unwrap(), b"synthetic-template-zip");
        assert_eq!(
            fs::metadata(&first_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let observations: Vec<_> = server.requests.try_iter().collect();
        assert_eq!(observations.len(), 4);
        assert!(
            observations
                .windows(2)
                .all(|pair| pair[1].0.duration_since(pair[0].0) >= Duration::from_secs(5))
        );
        let second_path = fixture.0.join("second.zip");
        let second = fetch_from(
            &json!({"output":second_path}).to_string(),
            false,
            &cache,
            &TEST_RELEASE,
            || panic!("cache hit attempted network"),
        )
        .unwrap();
        assert_eq!(second["cache_status"], "hit");
        assert_eq!(server.count.load(Ordering::SeqCst), 4);
        assert_eq!(
            fetch_from(&first_input, false, &cache, &TEST_RELEASE, || panic!())
                .unwrap_err()
                .code,
            "conflict"
        );
        assert_eq!(fs::read(first_path).unwrap(), b"synthetic-template-zip");
    }

    #[test]
    fn offline_miss_tampered_cache_and_unsafe_outputs_fail_closed() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let output = fixture.0.join("output.zip");
        let input = json!({"output":output}).to_string();
        assert_eq!(
            fetch_from(&input, false, &cache, &TEST_RELEASE, || panic!())
                .unwrap_err()
                .code,
            "offline_miss"
        );
        assert!(!output.exists());
        let mut tampered = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(fixture.0.join("cache").join(TEST_RELEASE.asset_name))
            .unwrap();
        tampered.write_all(b"synthetic-template-bad").unwrap();
        tampered.sync_all().unwrap();
        assert_eq!(
            fetch_from(&input, false, &cache, &TEST_RELEASE, || panic!())
                .unwrap_err()
                .code,
            "conflict"
        );
        assert!(!output.exists());
        let invalid = json!({"output":"relative.zip"}).to_string();
        assert_eq!(
            fetch_from(&invalid, true, &cache, &TEST_RELEASE, || panic!(
                "invalid path attempted download"
            ))
            .unwrap_err()
            .code,
            "invalid_input"
        );
        let unsafe_parent = fixture.0.join("unsafe-parent");
        DirBuilder::new()
            .mode(0o777)
            .create(&unsafe_parent)
            .unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        let unsafe_input = json!({"output":unsafe_parent.join("template.zip")}).to_string();
        assert_eq!(
            fetch_from(&unsafe_input, true, &cache, &TEST_RELEASE, || panic!(
                "unsafe output attempted cache or network"
            ))
            .unwrap_err()
            .code,
            "permission"
        );
        assert!(!unsafe_parent.join("template.zip").exists());
    }

    #[test]
    fn cache_allocation_failure_occurs_before_final_request_lease() {
        let fixture = Fixture::new();
        let server = Server::new(|socket, _, index| match index {
            0 | 2 => reply(socket, 404, "", b""),
            1 => reply(
                socket,
                302,
                "Location: https://release-assets.githubusercontent.com/signed/template\r\n",
                b"",
            ),
            _ => panic!("asset request occurred after cache allocation failure"),
        });
        let cache = fixture.cache();
        fs::set_permissions(fixture.0.join("cache"), fs::Permissions::from_mode(0o500)).unwrap();
        let downloader = test_downloader(&fixture, &cache, &server);
        assert_eq!(downloader.download().unwrap_err().code, "unavailable");
        assert_eq!(server.count.load(Ordering::SeqCst), 3);
        assert!(downloader.governor.status().is_ok());
        fs::set_permissions(fixture.0.join("cache"), fs::Permissions::from_mode(0o700)).unwrap();
    }
}
