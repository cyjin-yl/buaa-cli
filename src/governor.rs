//! Cross-process, fail-closed request scheduling. This module never sends requests.
//!
//! Every client for the same operating-system identity must use the same directory
//! and retain a [`RequestLease`] throughout the actual I/O. The default directory
//! comes from the effective user's passwd home, independent of HOME, XDG, and
//! the current worktree. State replacement never replaces the permanent lock.
//! Scheduling uses Linux CLOCK_BOOTTIME, including time spent suspended, with a
//! persisted boot ID. UTC changes cannot shorten accepted reservations. A reboot
//! or boot-ID mismatch fails closed, including explicit resume; offline operator
//! review is required rather than silently resetting potentially live cooldowns.
//! Cooperating same-user clients are assumed; the account owner or root can remove
//! state or bypass this library. Filesystem locking and fsync must
//! have local-filesystem semantics. No credential or account identifier is stored.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MIN_INTERVAL_MS: u64 = 5_000;
const MIN_BACKGROUND_MS: u64 = 15 * 60 * 1_000;
const MISSING_RETRY_AFTER_MS: u64 = 30 * 60 * 1_000;
const MAX_STATE_BYTES: u64 = 16 * 1_024;
const LOCK_NAME: &str = "governor.lock";
const STATE_NAME: &str = "state.json";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Scheduling limits. Constructors reject values below the safety minimums.
/// A directory remembers the greatest limits ever requested; reopening it with
/// defaults cannot lower an existing policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    request_interval_ms: u64,
    background_interval_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_interval_ms: MIN_INTERVAL_MS,
            background_interval_ms: MIN_BACKGROUND_MS,
        }
    }
}

impl Limits {
    /// Raise the five-second request gap and fifteen-minute background gap.
    pub fn new(request_interval: Duration, background_interval: Duration) -> Result<Self, String> {
        if request_interval < Duration::from_millis(MIN_INTERVAL_MS)
            || background_interval < Duration::from_millis(MIN_BACKGROUND_MS)
        {
            return Err("governor limits cannot be lower than the safety minimums".into());
        }
        let request_interval_ms = duration_ms(request_interval)?;
        let background_interval_ms = duration_ms(background_interval)?;
        Ok(Self {
            request_interval_ms,
            background_interval_ms,
        })
    }
}

/// All kinds share one global in-flight lock and request gap.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    Interactive,
    BackgroundPoll,
    Authentication,
}

/// An observed result, supplied by the caller after its request completes.
/// HTTP Retry-After accepts nonnegative seconds or an IMF-fixdate HTTP date.
/// Header values are parsed in memory and are never saved or included in errors.
#[derive(Clone, Copy, Debug)]
pub enum Outcome<'a> {
    Success,
    Http {
        status: u16,
        retry_after: Option<&'a str>,
        /// An independently observed application-level challenge.
        challenge: bool,
        /// Response headers arrived but the network body did not complete.
        network_failure: bool,
    },
    NetworkFailure,
    CredentialRejected,
    CaptchaRequired,
    AccountLocked,
}

/// Explicit acknowledgement that a human deliberately authorized resuming.
/// Do not manufacture this in a timer, retry loop, or automatic login flow.
#[derive(Clone, Copy, Debug)]
pub enum ResumeAuthorization {
    ExplicitUserRequest,
}

/// Credential-free scheduling information. Deadlines are Linux CLOCK_BOOTTIME
/// milliseconds, valid only within this boot; wait durations are a snapshot.
#[derive(Clone, Debug)]
pub struct Status {
    pub next_request_boottime_ms: u64,
    pub next_background_boottime_ms: u64,
    pub cooldown_until_boottime_ms: u64,
    pub request_wait: Duration,
    pub background_wait: Duration,
    pub cooldown_wait: Duration,
    pub request_interval: Duration,
    pub background_interval: Duration,
    pub authentication_armed: bool,
    pub safety_latched: bool,
    pub consecutive_network_failures: u32,
}

/// A directory-pinned governor. Existing state fails rather than waiting when
/// another process holds a lease. Only a fresh lock's creator waits to complete
/// first initialization. No timers or automatic request retries are provided.
pub struct Governor {
    directory: File,
    boot_id: String,
}

/// Exclusive request permission. Keep this value alive across the complete I/O,
/// then call [`RequestLease::finish`]. Dropping or crashing before finish leaves
/// a durable unfinished request that requires offline operator review.
/// Authentication permission is consumed before this value is returned.
#[must_use = "retain the lease throughout request I/O and record its outcome"]
pub struct RequestLease<'a> {
    governor: &'a Governor,
    _lock: File,
    state: State,
    kind: RequestKind,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    boot_id: String,
    request_interval_ms: u64,
    background_interval_ms: u64,
    next_request_ms: u64,
    next_background_ms: u64,
    cooldown_until_ms: u64,
    last_observed_ms: u64,
    network_failures: u32,
    authentication_armed: bool,
    safety_latched: bool,
    pending: Option<RequestKind>,
}

impl State {
    fn initial(limits: Limits, now: u64, boot_id: String) -> Self {
        Self {
            version: 2,
            boot_id,
            request_interval_ms: limits.request_interval_ms,
            background_interval_ms: limits.background_interval_ms,
            next_request_ms: 0,
            next_background_ms: 0,
            cooldown_until_ms: 0,
            last_observed_ms: now,
            network_failures: 0,
            authentication_armed: false,
            safety_latched: false,
            pending: None,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != 2
            || !valid_boot_id(&self.boot_id)
            || self.request_interval_ms < MIN_INTERVAL_MS
            || self.background_interval_ms < MIN_BACKGROUND_MS
            || self.network_failures > 6
            || self.last_observed_ms == 0
            || (self.authentication_armed && self.safety_latched)
            || (self.pending == Some(RequestKind::Authentication)
                && (self.authentication_armed || !self.safety_latched))
        {
            return Err("governor state is invalid; refusing requests".into());
        }
        Ok(())
    }

    fn observe(&mut self, now: u64) -> Result<(), String> {
        if now < self.last_observed_ms {
            return Err("monotonic clock moved backwards; refusing requests".into());
        }
        self.last_observed_ms = now;
        Ok(())
    }

    fn failure_backoff(&mut self, now: u64) -> Result<(), String> {
        self.network_failures = self.network_failures.saturating_add(1).min(6);
        let base = (30_000_u64 << (self.network_failures - 1)).min(720_000);
        // Scheduling jitter, not a security primitive. The monotonic observation
        // time, process identity, and sequence vary a bounded 30-second..15-minute
        // backoff without introducing any dependency on the UTC clock.
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let seed = now.rotate_left(17) ^ u64::from(std::process::id()) ^ sequence;
        let jitter = seed.wrapping_mul(0x9e3779b97f4a7c15) % (base / 4 + 1);
        self.cooldown_until_ms = self.cooldown_until_ms.max(deadline(now, base + jitter)?);
        Ok(())
    }

    fn ensure_outcome_known(&self) -> Result<(), String> {
        if self.pending.is_some() {
            // The process may have received 429, CAPTCHA, or rejection before
            // dying or failing to save. Never invent a short timeout/backoff.
            return Err("request outcome is unknown; offline operator review is required".into());
        }
        Ok(())
    }

    fn status(&self, now: u64) -> Status {
        Status {
            next_request_boottime_ms: self.next_request_ms,
            next_background_boottime_ms: self.next_background_ms,
            cooldown_until_boottime_ms: self.cooldown_until_ms,
            request_wait: Duration::from_millis(self.next_request_ms.saturating_sub(now)),
            background_wait: Duration::from_millis(self.next_background_ms.saturating_sub(now)),
            cooldown_wait: Duration::from_millis(self.cooldown_until_ms.saturating_sub(now)),
            request_interval: Duration::from_millis(self.request_interval_ms),
            background_interval: Duration::from_millis(self.background_interval_ms),
            authentication_armed: self.authentication_armed,
            safety_latched: self.safety_latched,
            consecutive_network_failures: self.network_failures,
        }
    }
}

impl Governor {
    /// Open `.buaa-cli-governor` beneath the effective user's passwd home.
    /// HOME/XDG overrides are ignored. The home must be absolute, owned by this
    /// user, not writable by others, and free of symlink path components.
    pub fn open() -> Result<Self, String> {
        Self::with_limits(Limits::default())
    }

    /// Open the production directory, raising (never lowering) its limits.
    pub fn with_limits(limits: Limits) -> Result<Self, String> {
        let home = identity_home()?;
        let _verified_home = open_directory(&home, false, false)?;
        Self::open_at(home.join(".buaa-cli-governor"), limits)
    }

    // Private: arbitrary directories must never become a production namespace
    // override. Unit-process regressions use this with isolated private fixtures.
    fn open_at(path: impl AsRef<Path>, limits: Limits) -> Result<Self, String> {
        let governor = Self {
            directory: open_directory(path.as_ref(), true, true)?,
            boot_id: current_boot_id()?,
        };
        let (lock, created) = governor.open_lock(true)?;
        governor.initialize(limits, lock, created)?;
        Ok(governor)
    }

    #[cfg(test)]
    pub(crate) fn isolated_for_test(path: &Path) -> Result<Self, String> {
        Self::open_at(path, Limits::default())
    }

    // Separate descriptor acquisition from initialization so the first-open
    // interleaving can be exercised with a real contending process.
    fn initialize(&self, limits: Limits, lock: File, created: bool) -> Result<(), String> {
        if created {
            // A concurrent opener may win flock before the creator. It cannot
            // initialize state, so let it fail and release rather than abandon
            // our fresh lock with no state forever.
            FileExt::lock_exclusive(&lock).map_err(|_| "cannot initialize governor lock")?;
        } else {
            lock_exclusive(&lock)?;
        }
        let now = now_ms()?;
        if created {
            // A pre-existing state without its permanent lock is not a fresh
            // installation. Never silently reset its safety history.
            if child_exists(&self.directory, STATE_NAME)? {
                return Err("governor lock history is missing; refusing requests".into());
            }
            self.save(&State::initial(limits, now, self.boot_id.clone()), true)?;
        } else {
            let mut state = self.load()?;
            state.observe(now)?;
            state.ensure_outcome_known()?;
            let raised = state.request_interval_ms < limits.request_interval_ms
                || state.background_interval_ms < limits.background_interval_ms;
            if raised {
                state.request_interval_ms =
                    state.request_interval_ms.max(limits.request_interval_ms);
                state.background_interval_ms = state
                    .background_interval_ms
                    .max(limits.background_interval_ms);
                // Raising a policy cannot leave a shorter already-reserved gap.
                if state.next_request_ms != 0 {
                    state.next_request_ms = state
                        .next_request_ms
                        .max(deadline(now, state.request_interval_ms)?);
                }
                if state.next_background_ms != 0 {
                    state.next_background_ms = state
                        .next_background_ms
                        .max(deadline(now, state.background_interval_ms)?);
                }
            }
            if raised {
                self.save(&state, false)?;
            }
        }
        Ok(())
    }

    /// Obtain immediate permission, or return a sanitized denial. No sleeping or
    /// request retry occurs. A durable reservation and (for authentication)
    /// consumed one-shot authorization precede returning the lease.
    pub fn try_acquire(&self, kind: RequestKind) -> Result<RequestLease<'_>, String> {
        let (lock, _) = self.open_lock(false)?;
        lock_exclusive(&lock)?;
        let mut state = self.load()?;
        let now = now_ms()?;
        state.observe(now)?;
        state.ensure_outcome_known()?;
        if state.safety_latched {
            return Err("account safety is latched; explicit user resume is required".into());
        }
        if now < state.cooldown_until_ms {
            return Err("account cooldown has not elapsed".into());
        }
        if now < state.next_request_ms {
            return Err("minimum request interval has not elapsed".into());
        }
        if kind == RequestKind::BackgroundPoll && now < state.next_background_ms {
            return Err("minimum background polling interval has not elapsed".into());
        }
        if kind == RequestKind::Authentication && !state.authentication_armed {
            return Err("authentication requires an explicit one-shot user authorization".into());
        }
        state.next_request_ms = deadline(now, state.request_interval_ms)?;
        if kind == RequestKind::BackgroundPoll {
            state.next_background_ms = deadline(now, state.background_interval_ms)?;
        }
        if kind == RequestKind::Authentication {
            state.authentication_armed = false;
            state.safety_latched = true;
        }
        state.pending = Some(kind);
        self.save(&state, false)?;
        Ok(RequestLease {
            governor: self,
            _lock: lock,
            state,
            kind,
        })
    }

    /// Deliberately clear the safety latch and arm exactly one authentication
    /// attempt. This NEVER clears request reservations, failure backoff,
    /// Retry-After, background deadlines, or a raised scheduling policy.
    pub fn resume_authentication(&self, _authorization: ResumeAuthorization) -> Result<(), String> {
        let (lock, _) = self.open_lock(false)?;
        lock_exclusive(&lock)?;
        let mut state = self.load()?;
        let now = now_ms()?;
        state.observe(now)?;
        state.ensure_outcome_known()?;
        state.authentication_armed = true;
        state.safety_latched = false;
        self.save(&state, false)
    }

    /// Read scheduling state under the process lock. Unknown outcomes deny even
    /// ordinary auth resume: neither a lost Retry-After nor latch may be waived.
    pub fn status(&self) -> Result<Status, String> {
        let (lock, _) = self.open_lock(false)?;
        lock_exclusive(&lock)?;
        let mut state = self.load()?;
        let now = now_ms()?;
        state.observe(now)?;
        state.ensure_outcome_known()?;
        Ok(state.status(now))
    }

    fn open_lock(&self, allow_create: bool) -> Result<(File, bool), String> {
        validate_directory(&self.directory, true, true)?;
        let mut created = false;
        let file = if allow_create && !child_exists(&self.directory, STATE_NAME)? {
            match open_child(
                &self.directory,
                LOCK_NAME,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            ) {
                Ok(file) => {
                    created = true;
                    file
                }
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                    open_child(&self.directory, LOCK_NAME, libc::O_RDWR)
                        .map_err(|_| "cannot open governor lock".to_string())?
                }
                Err(_) => return Err("cannot create governor lock".into()),
            }
        } else {
            open_child(&self.directory, LOCK_NAME, libc::O_RDWR)
                .map_err(|_| "cannot open governor lock".to_string())?
        };
        validate_private_file(&file)?;
        if file
            .metadata()
            .map_err(|_| "cannot inspect governor lock")?
            .len()
            != 0
        {
            return Err("governor lock is invalid".into());
        }
        Ok((file, created))
    }

    fn load(&self) -> Result<State, String> {
        let file = open_child(&self.directory, STATE_NAME, libc::O_RDONLY)
            .map_err(|_| "cannot open governor state; refusing requests".to_string())?;
        validate_private_file(&file)?;
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read governor state".to_string())?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err("governor state is invalid; refusing requests".into());
        }
        let state: State = serde_json::from_slice(&bytes)
            .map_err(|_| "governor state is invalid; refusing requests".to_string())?;
        state.validate()?;
        if state.boot_id != self.boot_id {
            return Err("system boot changed; governor requires offline safety review".into());
        }
        Ok(state)
    }

    fn save(&self, state: &State, initial: bool) -> Result<(), String> {
        state.validate()?;
        validate_directory(&self.directory, true, true)?;
        if !initial {
            let existing = open_child(&self.directory, STATE_NAME, libc::O_RDONLY)
                .map_err(|_| "cannot inspect governor state before saving".to_string())?;
            validate_private_file(&existing)?;
        }
        let (name, mut temporary) = create_temporary(&self.directory)?;
        let result = (|| {
            validate_private_file(&temporary)?;
            serde_json::to_writer(&mut temporary, state)
                .map_err(|_| "cannot encode governor state".to_string())?;
            temporary
                .write_all(b"\n")
                .map_err(|_| "cannot write governor state".to_string())?;
            temporary
                .sync_all()
                .map_err(|_| "cannot synchronize governor state".to_string())?;
            let target = CString::new(STATE_NAME).map_err(|_| "invalid internal state name")?;
            // SAFETY: valid open directory descriptors and live NUL-terminated names.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    self.directory.as_raw_fd(),
                    target.as_ptr(),
                )
            } != 0
            {
                return Err("cannot replace governor state".into());
            }
            self.directory
                .sync_all()
                .map_err(|_| "cannot synchronize governor directory".to_string())
        })();
        if result.is_err() {
            // SAFETY: this name is an exclusively-created temporary in our pinned directory.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
        }
        result
    }
}

impl RequestLease<'_> {
    /// Record the actual outcome durably, then release exclusivity. Even success
    /// reserves a full request gap after completion. An I/O failure or invalid
    /// outcome returns an error, leaving the unfinished crash reservation.
    pub fn finish(mut self, outcome: Outcome<'_>) -> Result<(), String> {
        let now = now_ms()?;
        self.state.observe(now)?;
        self.state.next_request_ms = self
            .state
            .next_request_ms
            .max(deadline(now, self.state.request_interval_ms)?);
        if self.kind == RequestKind::BackgroundPoll {
            self.state.next_background_ms = self
                .state
                .next_background_ms
                .max(deadline(now, self.state.background_interval_ms)?);
        }
        let success = match outcome {
            Outcome::Success => true,
            Outcome::Http {
                status,
                retry_after,
                challenge,
                network_failure,
            } => {
                if !(100..=599).contains(&status) {
                    return Err("invalid HTTP outcome; unfinished reservation retained".into());
                }
                let retry_deadline = retry_after.and_then(|value| retry_after_deadline(value, now));
                if let Some(until) = retry_deadline {
                    self.state.cooldown_until_ms = self.state.cooldown_until_ms.max(until);
                } else if status == 429 {
                    self.state.cooldown_until_ms = self
                        .state
                        .cooldown_until_ms
                        .max(deadline(now, MISSING_RETRY_AFTER_MS)?);
                }
                if status == 401 || status == 403 || challenge {
                    self.state.safety_latched = true;
                    self.state.authentication_armed = false;
                }
                if network_failure {
                    self.state.failure_backoff(now)?;
                }
                (200..=299).contains(&status) && !challenge && !network_failure
            }
            Outcome::NetworkFailure => {
                self.state.failure_backoff(now)?;
                false
            }
            Outcome::CredentialRejected | Outcome::CaptchaRequired | Outcome::AccountLocked => {
                self.state.safety_latched = true;
                self.state.authentication_armed = false;
                false
            }
        };
        if success {
            self.state.network_failures = 0;
            if self.kind == RequestKind::Authentication {
                self.state.safety_latched = false;
            }
        }
        self.state.pending = None;
        self.governor.save(&self.state, false)
    }
}

fn duration_ms(value: Duration) -> Result<u64, String> {
    let millis = value.as_nanos().div_ceil(1_000_000);
    u64::try_from(millis).map_err(|_| "governor duration is too large".into())
}

fn now_ms() -> Result<u64, String> {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime writes one timespec to valid writable storage.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, timestamp.as_mut_ptr()) } != 0 {
        return Err("monotonic system clock is unavailable".into());
    }
    // SAFETY: a successful clock_gettime initialized the structure.
    let timestamp = unsafe { timestamp.assume_init() };
    let seconds = u64::try_from(timestamp.tv_sec).map_err(|_| "monotonic clock is invalid")?;
    let nanos = u64::try_from(timestamp.tv_nsec).map_err(|_| "monotonic clock is invalid")?;
    if nanos >= 1_000_000_000 {
        return Err("monotonic clock is invalid".into());
    }
    seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(nanos / 1_000_000))
        .ok_or_else(|| "monotonic clock is out of range".into())
}

fn current_boot_id() -> Result<String, String> {
    let mut bytes = String::new();
    File::open("/proc/sys/kernel/random/boot_id")
        .map_err(|_| "system boot identity is unavailable")?
        .take(64)
        .read_to_string(&mut bytes)
        .map_err(|_| "cannot read system boot identity")?;
    let value = bytes.trim_end_matches('\n');
    if !valid_boot_id(value) {
        return Err("system boot identity is invalid".into());
    }
    Ok(value.to_owned())
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn deadline(now: u64, delay: u64) -> Result<u64, String> {
    // One extra millisecond prevents truncation from admitting a request early.
    now.checked_add(delay)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| "governor deadline is out of range".into())
}

fn lock_exclusive(file: &File) -> Result<(), String> {
    FileExt::try_lock_exclusive(file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            "another process holds the account request lease".into()
        } else {
            "cannot acquire governor lock".into()
        }
    })
}

pub(crate) fn identity_home() -> Result<PathBuf, String> {
    // Resolve the effective identity, never a mutable HOME/XDG override. The
    // reentrant lookup keeps concurrent callers independent of libc globals.
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let mut buffer = vec![0_u8; 16 * 1_024];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: writable entry/buffer/result storage remains live throughout
        // the call; any returned strings are copied before buffer is released.
        let result = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if result == libc::ERANGE && buffer.len() < 1_024 * 1_024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if result != 0 || found.is_null() {
            return Err("cannot resolve the effective user's persistent home".into());
        }
        // SAFETY: successful getpwuid_r initialized entry and its buffer-backed strings.
        let entry = unsafe { entry.assume_init() };
        if entry.pw_uid != uid || entry.pw_dir.is_null() {
            return Err("effective user home is invalid".into());
        }
        // SAFETY: libc returned this NUL-terminated string within the live buffer.
        let home = unsafe { CStr::from_ptr(entry.pw_dir) };
        return Ok(PathBuf::from(OsStr::from_bytes(home.to_bytes())));
    }
}

pub(crate) fn open_directory(
    path: &Path,
    create_final: bool,
    private: bool,
) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("governor directory must be absolute".into());
    }
    let components: Vec<_> = path.components().collect();
    if components
        .iter()
        .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err("governor directory contains unsupported components".into());
    }
    let root = CString::new("/").map_err(|_| "invalid internal directory name")?;
    // SAFETY: root is a live NUL-terminated path; successful descriptors are owned below.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err("cannot open governor directory root".into());
    }
    // SAFETY: successful open returned a new, exclusively owned descriptor.
    let mut directory = unsafe { File::from_raw_fd(fd) };
    for (index, component) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = component else {
            return Err("invalid governor directory component".into());
        };
        validate_directory(&directory, false, false)?;
        let last = index + 1 == components.len();
        let name = c_name(name)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        // SAFETY: directory descriptor and component name remain live.
        let mut child = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if child < 0
            && last
            && create_final
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
        {
            // SAFETY: mkdirat operates on a single component in the pinned directory.
            let result = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
            if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err("cannot create private governor directory".into());
            }
            if result == 0 {
                directory
                    .sync_all()
                    .map_err(|_| "cannot synchronize governor parent directory")?;
            }
            // SAFETY: directory descriptor and component name remain live.
            child = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        }
        if child < 0 {
            return Err("cannot securely open governor directory".into());
        }
        // SAFETY: successful openat returned a new descriptor owned by this File.
        directory = unsafe { File::from_raw_fd(child) };
    }
    validate_directory(&directory, true, private)?;
    Ok(directory)
}

fn validate_directory(file: &File, final_directory: bool, private: bool) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect governor directory")?;
    // SAFETY: geteuid has no preconditions and does not allocate or retain pointers.
    let uid = unsafe { libc::geteuid() };
    let mode = metadata.mode() & 0o7777;
    let trusted_owner = metadata.uid() == uid || (!final_directory && metadata.uid() == 0);
    // A root-owned sticky ancestor (e.g. /tmp in isolated tests) cannot have an
    // existing user's child renamed by other users. Final state remains 0700.
    let sticky_root_ancestor = !final_directory && metadata.uid() == 0 && mode & 0o1000 != 0;
    if !metadata.is_dir()
        || !trusted_owner
        || (private && mode != 0o700)
        || (!private && mode & 0o022 != 0 && !sticky_root_ancestor)
    {
        return Err("governor directory ownership or permissions are unsafe".into());
    }
    Ok(())
}

pub(crate) fn validate_private_file(file: &File) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect governor file")?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("governor file ownership or permissions are unsafe".into());
    }
    Ok(())
}

fn c_name(name: &OsStr) -> Result<CString, String> {
    CString::new(name.as_bytes())
        .map_err(|_| "governor directory contains an invalid component".into())
}

pub(crate) fn open_child(directory: &File, name: &str, flags: i32) -> std::io::Result<File> {
    let name =
        CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // O_NONBLOCK prevents a substituted FIFO/device from hanging before its
    // type can be checked. O_NOFOLLOW rejects symlinks before any data is read.
    // SAFETY: live directory descriptor and single-component NUL-terminated name.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful openat returned an exclusively owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn child_exists(directory: &File, name: &str) -> Result<bool, String> {
    let name = CString::new(name).map_err(|_| "invalid internal state name")?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to writable storage; fstatat does not follow symlinks.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(true)
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err("cannot inspect governor state directory".into())
    }
}

pub(crate) fn create_temporary(directory: &File) -> Result<(CString, File), String> {
    for _ in 0..16 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".state-{}-{sequence}.tmp", std::process::id());
        match open_child(
            directory,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        ) {
            Ok(file) => {
                return Ok((
                    CString::new(name).map_err(|_| "invalid internal temporary name")?,
                    file,
                ));
            }
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(_) => return Err("cannot create temporary governor state".into()),
        }
    }
    Err("cannot reserve temporary governor state".into())
}

fn retry_after_deadline(header: &str, now: u64) -> Option<u64> {
    let value = header.trim_matches([' ', '\t']);
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        let seconds = value.parse::<u64>().unwrap_or(u64::MAX);
        return Some(
            now.saturating_add(seconds.saturating_mul(1_000))
                .saturating_add(1),
        );
    }
    let unix_deadline = http_date_ms(value)?;
    let wall = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => u64::try_from(value.as_millis()).unwrap_or(u64::MAX),
        Err(_) => return Some(u64::MAX),
    };
    let monotonic = match now_ms() {
        Ok(value) => value.max(now),
        Err(_) => return Some(u64::MAX),
    };
    Some(
        monotonic
            .saturating_add(unix_deadline.saturating_sub(wall))
            .saturating_add(1),
    )
}

// HTTP-date is accepted in all three formats per RFC 9110 §5.6.7:
//   IMF-fixdate            Sun, 06 Nov 1994 08:49:37 GMT
//   obsolete RFC 850       Sunday, 06-Nov-94 08:49:37 GMT
//   ANSI C asctime         Sun Nov  6 08:49:37 1994
// Anything else is treated as absent; a 4xx/5xx then receives the thirty-minute floor.
fn http_date_ms(value: &str) -> Option<u64> {
    if !value.is_ascii() {
        return None;
    }
    fn number(value: &str) -> Option<u64> {
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| value.parse().ok())
            .flatten()
    }
    fn month_index(name: &str) -> Option<u64> {
        Some(match name {
            "Jan" => 0,
            "Feb" => 1,
            "Mar" => 2,
            "Apr" => 3,
            "May" => 4,
            "Jun" => 5,
            "Jul" => 6,
            "Aug" => 7,
            "Sep" => 8,
            "Oct" => 9,
            "Nov" => 10,
            "Dec" => 11,
            _ => return None,
        })
    }
    fn weekday_name(name: &str) -> bool {
        matches!(
            name,
            "Mon"
                | "Mon."
                | "Monday"
                | "Tue"
                | "Tues"
                | "Tuesday"
                | "Wed"
                | "Wed."
                | "Wednesday"
                | "Thu"
                | "Thur"
                | "Thurs"
                | "Thursday"
                | "Fri"
                | "Fri."
                | "Friday"
                | "Sat"
                | "Sat."
                | "Saturday"
                | "Sun"
                | "Sun."
                | "Sunday"
        )
    }
    // Split into lexical tokens; weekdays with optional trailing space where
    // the empty token comes from a double space (e.g. asctime).
    let tokens: Vec<&str> = value.split_whitespace().collect();
    // Formats after whitespace-splitting:
    //   IMF: ["Sun,", "06", "Nov", "1994", "08:49:37", "GMT"]   (6)
    //   850: ["Sunday,", "06-Nov-94", "08:49:37", "GMT"]        (4)
    //   asc: ["Sun", "Nov", "6", "08:49:37", "1994"]            (5)
    let (year, month, day, hour, minute, second) = match tokens.len() {
        4 if tokens[1].contains('-') => {
            // RFC 850: Weekday, 06-Nov-94 08:49:37 GMT
            if !weekday_name(tokens[0].trim_end_matches(',')) {
                return None;
            }
            let date = tokens[1];
            if date.len() != 9 || date.get(2..3) != Some("-") || date.get(6..7) != Some("-") {
                return None;
            }
            let day = number(&date[..2])?;
            let month = month_index(&date[3..6])?;
            let mut year = number(&date[7..9])?;
            year += if year > 50 { 1900 } else { 2000 };
            let time = tokens[2];
            if time.len() != 8 || &time[2..3] != ":" || &time[5..6] != ":" || tokens[3] != "GMT" {
                return None;
            }
            let hour = number(&time[..2])?;
            let minute = number(&time[3..5])?;
            let second = number(&time[6..])?;
            (year, month, day, hour, minute, second)
        }
        6 if tokens[0].ends_with(',') => {
            // IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
            if !weekday_name(tokens[0].trim_end_matches(',')) || tokens[5] != "GMT" {
                return None;
            }
            if tokens[1].len() != 2 || tokens[3].len() != 4 {
                return None;
            }
            let day = number(tokens[1])?;
            let month = month_index(tokens[2])?;
            let year = number(tokens[3])?;
            let time = tokens[4];
            if time.len() != 8 || &time[2..3] != ":" || &time[5..6] != ":" {
                return None;
            }
            let hour = number(&time[..2])?;
            let minute = number(&time[3..5])?;
            let second = number(&time[6..])?;
            (year, month, day, hour, minute, second)
        }
        5 => {
            // asctime: Sun Nov  6 08:49:37 1994
            if !weekday_name(tokens[0]) {
                return None;
            }
            let month = month_index(tokens[1])?;
            if !(1..=2).contains(&tokens[2].len()) || tokens[4].len() != 4 {
                return None;
            }
            let day = number(tokens[2])?;
            let time = tokens[3];
            if time.len() != 8 || &time[2..3] != ":" || &time[5..6] != ":" {
                return None;
            }
            let hour = number(&time[..2])?;
            let minute = number(&time[3..5])?;
            let second = number(&time[6..])?;
            let year = number(tokens[4])?;
            (year, month, day, hour, minute, second)
        }
        _ => return None,
    };
    // GMT already validated per-format above; validate calendar bounds only.
    if year < 1601 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if month >= 12 || day == 0 || day > month_days[month as usize] {
        return None;
    }
    if year < 1970 {
        return Some(0);
    }
    let preceding = year.checked_sub(1)?;
    let days = 365_u64
        .checked_mul(preceding)?
        .checked_add(preceding / 4)?
        .checked_sub(preceding / 100)?
        .checked_add(preceding / 400)?
        .checked_sub(719_162)?
        .checked_add(month_days[..month as usize].iter().sum::<u64>())?
        .checked_add(day)?
        .checked_sub(1)?;
    let seconds = days
        .checked_mul(24)?
        .checked_add(hour)?
        .checked_mul(60)?
        .checked_add(minute)?
        .checked_mul(60)?
        .checked_add(second)?;
    seconds.checked_mul(1_000)
}

#[cfg(test)]
mod tests {
    include!("../tests/governor_process.rs");
    governor_process_regressions!();

    #[test]
    fn http_date_requires_protocol_year_width_and_checked_conversion() {
        for invalid in [
            "Sun, 06 Nov 999999999 08:49:37 GMT",
            "Sun, 06 Nov 99999 08:49:37 GMT",
            "Sun Nov  6 08:49:37 999999999",
            "Sun Nov  6 08:49:37 99999",
        ] {
            assert!(super::http_date_ms(invalid).is_none(), "{invalid}");
        }
        for valid in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 9999 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun Nov  6 08:49:37 9999",
            "Sunday, 06-Nov-94 08:49:37 GMT",
        ] {
            assert!(super::http_date_ms(valid).is_some(), "{valid}");
        }
    }
}
