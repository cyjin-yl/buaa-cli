// Expanded only inside governor's cfg(test) module, where the private directory
// constructor is available. As a standalone integration target this exports no
// runnable tests and cannot introduce a production state-directory override.
#[macro_export]
macro_rules! governor_process_regressions {
    () => {
        use super::{Governor, Limits, Outcome, RequestKind, ResumeAuthorization};
        use std::fs;
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
        use std::path::{Path, PathBuf};
        use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        static SEQUENCE: AtomicU64 = AtomicU64::new(0);

        struct Fixture(PathBuf);

        impl Fixture {
            fn new() -> Self {
                let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "buaa-governor-{}-{}-{sequence}",
                    std::process::id(),
                    timestamp_ms(),
                ));
                fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                Self(path)
            }

            fn state_dir(&self) -> PathBuf {
                self.0.join("shared")
            }

            fn open(&self) -> Governor {
                Governor::open_at(self.state_dir(), Limits::default()).unwrap()
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn timestamp_ms() -> u64 {
            super::now_ms().unwrap()
        }

        fn worker(path: &Path, action: &str) -> Command {
            let mut command = Command::new(std::env::current_exe().unwrap());
            let module = module_path!().split_once("::").unwrap().1;
            command.args([
                "--exact",
                &format!("{module}::subprocess_worker"),
                "--ignored",
                "--nocapture",
            ]);
            command.env("BUAA_GOVERNOR_TEST_DIRECTORY", path);
            command.env("BUAA_GOVERNOR_TEST_ACTION", action);
            let worktree = path.parent().unwrap().join(if action.starts_with("hold") {
                "worktree-a"
            } else {
                "worktree-b"
            });
            fs::create_dir_all(&worktree).unwrap();
            command.current_dir(worktree);
            command
        }

        fn attempt(path: &Path, kind: &str) -> bool {
            let output = worker(path, kind).output().unwrap();
            assert!(
                output.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let output = String::from_utf8(output.stdout).unwrap();
            assert!(output.contains("GOVERNOR_ALLOWED") || output.contains("GOVERNOR_DENIED"));
            output.contains("GOVERNOR_ALLOWED")
        }

        struct HeldProcess {
            child: Child,
            input: ChildStdin,
            output: BufReader<ChildStdout>,
        }

        impl HeldProcess {
            fn start(path: &Path, action: &str) -> Self {
                let mut child = worker(path, action)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap();
                let input = child.stdin.take().unwrap();
                let output = BufReader::new(child.stdout.take().unwrap());
                let mut process = Self {
                    child,
                    input,
                    output,
                };
                process.expect_marker("GOVERNOR_ACQUIRED");
                process
            }

            fn expect_marker(&mut self, marker: &str) {
                loop {
                    let mut line = String::new();
                    assert_ne!(
                        self.output.read_line(&mut line).unwrap(),
                        0,
                        "child ended before marker"
                    );
                    if line.contains(marker) {
                        return;
                    }
                }
            }

            fn finish(&mut self) {
                writeln!(self.input, "finish").unwrap();
                self.input.flush().unwrap();
                self.expect_marker("GOVERNOR_FINISHED");
                assert!(self.child.wait().unwrap().success());
            }

            fn crash(&mut self) {
                self.child.kill().unwrap();
                assert!(!self.child.wait().unwrap().success());
            }
        }

        impl Drop for HeldProcess {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }

        // A real child process, not a mocked lock or an accelerated policy.
        #[test]
        #[ignore = "subprocess entry point invoked by the offline governor regressions"]
        fn subprocess_worker() {
            let Ok(path) = std::env::var("BUAA_GOVERNOR_TEST_DIRECTORY") else {
                return;
            };
            let action = std::env::var("BUAA_GOVERNOR_TEST_ACTION").unwrap();
            if action == "identity" {
                let expected = std::env::var_os("BUAA_GOVERNOR_EXPECTED_IDENTITY").unwrap();
                assert_eq!(super::identity_home().unwrap(), PathBuf::from(expected));
                println!("GOVERNOR_IDENTITY_STABLE");
                return;
            }
            if action == "contended-initialization" {
                let governor = Governor {
                    directory: super::open_directory(Path::new(&path), true, true).unwrap(),
                    boot_id: super::current_boot_id().unwrap(),
                };
                let (lock, created) = governor.open_lock(true).unwrap();
                assert!(created);
                // The file exists, but its creator has not yet attempted flock.
                println!("GOVERNOR_ACQUIRED");
                std::io::stdout().flush().unwrap();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).unwrap();
                println!("GOVERNOR_INITIALIZING");
                std::io::stdout().flush().unwrap();
                governor
                    .initialize(Limits::default(), lock, created)
                    .unwrap();
                println!("GOVERNOR_FINISHED");
                return;
            }
            if action == "hold-auth" || action == "crash-auth" {
                let governor = Governor::open_at(&path, Limits::default()).unwrap();
                governor
                    .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                    .unwrap();
                let lease = governor.try_acquire(RequestKind::Authentication).unwrap();
                println!("GOVERNOR_ACQUIRED");
                std::io::stdout().flush().unwrap();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).unwrap();
                assert_eq!(
                    action, "hold-auth",
                    "crash worker must be killed while holding its lease"
                );
                lease.finish(Outcome::Success).unwrap();
                println!("GOVERNOR_FINISHED");
                std::io::stdout().flush().unwrap();
                return;
            }
            let kind = match action.as_str() {
                "try-auth" => RequestKind::Authentication,
                "try-interactive" => RequestKind::Interactive,
                _ => panic!("unknown subprocess action"),
            };
            let result = Governor::open_at(&path, Limits::default())
                .and_then(|governor| governor.try_acquire(kind)?.finish(Outcome::Success));
            println!(
                "{}",
                if result.is_ok() {
                    "GOVERNOR_ALLOWED"
                } else {
                    "GOVERNOR_DENIED"
                }
            );
        }

        #[test]
        fn first_lock_creator_waits_for_contender_and_does_not_strand_history() {
            let fixture = Fixture::new();
            let mut creator = HeldProcess::start(&fixture.state_dir(), "contended-initialization");
            let contender = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(fixture.state_dir().join("governor.lock"))
                .unwrap();
            fs2::FileExt::lock_exclusive(&contender).unwrap();
            writeln!(creator.input, "continue").unwrap();
            creator.input.flush().unwrap();
            creator.expect_marker("GOVERNOR_INITIALIZING");
            std::thread::sleep(Duration::from_millis(200));
            assert!(
                creator.child.try_wait().unwrap().is_none(),
                "creator abandoned fresh lock under contention"
            );
            drop(contender);
            creator.expect_marker("GOVERNOR_FINISHED");
            assert!(creator.child.wait().unwrap().success());
            fixture
                .open()
                .try_acquire(RequestKind::Interactive)
                .unwrap()
                .finish(Outcome::Success)
                .unwrap();
        }

        #[test]
        fn process_lock_real_five_second_gap_and_auth_consumption_survive_restart() {
            let fixture = Fixture::new();
            let mut held = HeldProcess::start(&fixture.state_dir(), "hold-auth");
            // Exceed the on-acquisition reservation while actual I/O remains
            // live. A deadline-only implementation would incorrectly admit this.
            std::thread::sleep(Duration::from_millis(5_100));
            // Opening existing state would recover an abandoned request if the
            // implementation released flock before the caller's I/O ended.
            assert!(Governor::open_at(fixture.state_dir(), Limits::default()).is_err());
            assert!(!attempt(&fixture.state_dir(), "try-interactive"));
            held.finish();
            let completed = Instant::now();
            // A new process after completion must still observe the shared gap.
            assert!(!attempt(&fixture.state_dir(), "try-interactive"));
            std::thread::sleep(Duration::from_millis(5_100));
            // The gap has expired but the consumed authentication token has not
            // reappeared after a successful login or a process restart.
            assert!(!attempt(&fixture.state_dir(), "try-auth"));
            assert!(attempt(&fixture.state_dir(), "try-interactive"));
            assert!(completed.elapsed() >= Duration::from_secs(5));
            assert!(!fixture.open().status().unwrap().authentication_armed);
        }

        #[test]
        fn killed_auth_process_requires_offline_review_not_auth_resume() {
            let fixture = Fixture::new();
            let governor = fixture.open();
            let mut held = HeldProcess::start(&fixture.state_dir(), "crash-auth");
            held.crash();
            assert!(governor.status().is_err());
            assert!(governor.try_acquire(RequestKind::Authentication).is_err());
            assert!(governor.try_acquire(RequestKind::Interactive).is_err());
            assert!(
                governor
                    .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                    .is_err()
            );
            assert!(Governor::open_at(fixture.state_dir(), Limits::default()).is_err());
            assert!(!attempt(&fixture.state_dir(), "try-auth"));
        }

        #[test]
        fn rejection_captcha_and_account_lock_require_deliberate_resume() {
            for outcome in [
                Outcome::CredentialRejected,
                Outcome::CaptchaRequired,
                Outcome::AccountLocked,
                Outcome::Http {
                    status: 401,
                    retry_after: None,
                    challenge: false,
                    network_failure: false,
                },
                Outcome::Http {
                    status: 403,
                    retry_after: None,
                    challenge: false,
                    network_failure: false,
                },
            ] {
                let fixture = Fixture::new();
                let governor = fixture.open();
                assert!(governor.try_acquire(RequestKind::Authentication).is_err());
                governor
                    .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                    .unwrap();
                governor
                    .try_acquire(RequestKind::Authentication)
                    .unwrap()
                    .finish(outcome)
                    .unwrap();
                let reopened = fixture.open();
                let denied = reopened.status().unwrap();
                assert!(denied.safety_latched);
                assert!(!denied.authentication_armed);
                assert!(reopened.try_acquire(RequestKind::Interactive).is_err());
                reopened
                    .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                    .unwrap();
                let resumed = reopened.status().unwrap();
                assert!(resumed.authentication_armed);
                assert!(!resumed.safety_latched);
                assert_eq!(
                    resumed.next_request_boottime_ms,
                    denied.next_request_boottime_ms
                );
            }
        }

        #[test]
        fn retry_after_seconds_dates_and_missing_429_cooldown_survive_resume() {
            for (status, header, minimum_delay) in [
                (429, None, 1_800_000),
                (429, Some("invalid HTTP date"), 1_800_000),
                (503, Some("120"), 120_000),
                (429, Some("Fri, 01 Jan 2100 00:00:00 GMT"), 0),
                (429, Some("9999999999999999999999999999999999"), 0),
            ] {
                let fixture = Fixture::new();
                let governor = fixture.open();
                let lease = governor.try_acquire(RequestKind::Interactive).unwrap();
                let before_finish = timestamp_ms();
                let wall_before = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                lease
                    .finish(Outcome::Http {
                        status,
                        retry_after: header,
                        challenge: false,
                        network_failure: false,
                    })
                    .unwrap();
                let before_resume = fixture.open().status().unwrap();
                if header == Some("Fri, 01 Jan 2100 00:00:00 GMT") {
                    let wall_after = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let remaining_low = 4_102_444_800_000_u64.saturating_sub(wall_after);
                    let remaining_high = 4_102_444_800_000_u64.saturating_sub(wall_before);
                    assert!(
                        before_resume.cooldown_until_boottime_ms >= before_finish + remaining_low
                    );
                    assert!(
                        before_resume.cooldown_until_boottime_ms
                            <= timestamp_ms() + remaining_high + 1
                    );
                } else if header == Some("9999999999999999999999999999999999") {
                    assert_eq!(before_resume.cooldown_until_boottime_ms, u64::MAX);
                } else {
                    assert!(
                        before_resume.cooldown_until_boottime_ms >= before_finish + minimum_delay
                    );
                }
                governor
                    .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                    .unwrap();
                assert_eq!(
                    governor.status().unwrap().cooldown_until_boottime_ms,
                    before_resume.cooldown_until_boottime_ms
                );
                assert!(governor.try_acquire(RequestKind::Authentication).is_err());
            }
        }

        #[test]
        fn network_failure_is_bounded_and_does_not_retry() {
            let fixture = Fixture::new();
            let governor = fixture.open();
            let lease = governor.try_acquire(RequestKind::Interactive).unwrap();
            let before_finish = timestamp_ms();
            lease.finish(Outcome::NetworkFailure).unwrap();
            let first = fixture.open().status().unwrap();
            assert_eq!(first.consecutive_network_failures, 1);
            assert!(first.cooldown_until_boottime_ms >= before_finish + 30_000);
            assert!(first.cooldown_until_boottime_ms <= timestamp_ms() + 37_501);
            assert!(!attempt(&fixture.state_dir(), "try-interactive"));
            let later = governor.status().unwrap();
            assert_eq!(later.consecutive_network_failures, 1);
            assert_eq!(
                later.cooldown_until_boottime_ms,
                first.cooldown_until_boottime_ms
            );
        }

        #[test]
        fn polling_and_raised_policy_cannot_be_lowered_on_reopen() {
            assert!(Limits::new(Duration::from_millis(4_999), Duration::from_secs(900)).is_err());
            assert!(Limits::new(Duration::from_secs(5), Duration::from_secs(899)).is_err());
            let fixture = Fixture::new();
            let limits = Limits::new(Duration::from_secs(10), Duration::from_secs(1_800)).unwrap();
            let governor = Governor::open_at(fixture.state_dir(), limits).unwrap();
            let before_request = timestamp_ms();
            governor
                .try_acquire(RequestKind::BackgroundPoll)
                .unwrap()
                .finish(Outcome::Success)
                .unwrap();
            let reopened = fixture.open();
            let status = reopened.status().unwrap();
            assert_eq!(status.request_interval, Duration::from_secs(10));
            assert_eq!(status.background_interval, Duration::from_secs(1_800));
            assert!(status.next_background_boottime_ms >= before_request + 1_800_000);
            assert!(status.next_request_boottime_ms >= before_request + 10_000);
            reopened
                .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                .unwrap();
            assert_eq!(
                reopened.status().unwrap().next_background_boottime_ms,
                status.next_background_boottime_ms
            );
            // The global gap has elapsed; only the background deadline can deny.
            std::thread::sleep(Duration::from_millis(10_100));
            assert!(reopened.try_acquire(RequestKind::BackgroundPoll).is_err());
            reopened
                .try_acquire(RequestKind::Interactive)
                .unwrap()
                .finish(Outcome::Success)
                .unwrap();
        }

        #[test]
        fn unsafe_permissions_symlinks_and_hardlinks_fail_closed() {
            let fixture = Fixture::new();
            let governor = fixture.open();
            let directory = fixture.state_dir();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(Governor::open_at(&directory, Limits::default()).is_err());
            assert!(governor.try_acquire(RequestKind::Interactive).is_err());
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            for name in ["governor.lock", "state.json"] {
                let path = directory.join(name);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                assert!(Governor::open_at(&directory, Limits::default()).is_err());
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                let target = fixture.0.join(format!("saved-{name}"));
                fs::rename(&path, &target).unwrap();
                symlink(&target, &path).unwrap();
                assert!(Governor::open_at(&directory, Limits::default()).is_err());
                fs::remove_file(&path).unwrap();
                fs::rename(&target, &path).unwrap();
                fs::hard_link(&path, &target).unwrap();
                assert!(Governor::open_at(&directory, Limits::default()).is_err());
                fs::remove_file(&target).unwrap();
            }
            let alias = fixture.0.join("alias");
            symlink(&directory, &alias).unwrap();
            assert!(Governor::open_at(&alias, Limits::default()).is_err());
            assert!(Governor::open_at(alias.join("child"), Limits::default()).is_err());
            assert!(Governor::open_at("relative-state", Limits::default()).is_err());
            assert!(!fixture.0.join("relative-state").exists());
        }

        #[test]
        fn malformed_or_missing_persistent_history_never_resets() {
            let fixture = Fixture::new();
            let governor = fixture.open();
            let state = fixture.state_dir().join("state.json");
            fs::write(&state, b"{broken state").unwrap();
            assert!(governor.try_acquire(RequestKind::Interactive).is_err());
            assert!(Governor::open_at(fixture.state_dir(), Limits::default()).is_err());
            assert_eq!(fs::read(&state).unwrap(), b"{broken state");
            fs::remove_file(&state).unwrap();
            for _ in 0..2 {
                assert!(Governor::open_at(fixture.state_dir(), Limits::default()).is_err());
                assert!(!state.exists());
            }
            let other = Fixture::new();
            let _ = other.open();
            let lock = other.state_dir().join("governor.lock");
            fs::remove_file(&lock).unwrap();
            for _ in 0..2 {
                assert!(Governor::open_at(other.state_dir(), Limits::default()).is_err());
                assert!(!lock.exists());
            }
        }

        #[test]
        fn state_failure_cannot_report_success_or_waive_unfinished_reservation() {
            let fixture = Fixture::new();
            let governor = fixture.open();
            let lease = governor.try_acquire(RequestKind::Interactive).unwrap();
            let state = fixture.state_dir().join("state.json");
            fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(lease.finish(Outcome::Success).is_err());
            assert!(governor.try_acquire(RequestKind::Interactive).is_err());
            fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(governor.status().is_err());
            assert!(
                governor
                    .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                    .is_err()
            );
            assert!(governor.try_acquire(RequestKind::Interactive).is_err());
        }

        #[test]
        fn unpersisted_safety_outcome_cannot_be_cleared_by_auth_resume() {
            for outcome in [
                Outcome::Http {
                    status: 429,
                    retry_after: Some("7200"),
                    challenge: false,
                    network_failure: false,
                },
                Outcome::CredentialRejected,
                Outcome::CaptchaRequired,
            ] {
                let fixture = Fixture::new();
                let governor = fixture.open();
                let lease = governor.try_acquire(RequestKind::Interactive).unwrap();
                let state = fixture.state_dir().join("state.json");
                fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
                assert!(lease.finish(outcome).is_err());
                fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
                assert!(
                    governor
                        .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                        .is_err()
                );
                assert!(governor.try_acquire(RequestKind::Interactive).is_err());
                assert!(Governor::open_at(fixture.state_dir(), Limits::default()).is_err());
            }
        }

        #[test]
        fn reboot_identity_mismatch_blocks_requests_and_explicit_resume() {
            let fixture = Fixture::new();
            let governor = fixture.open();
            let path = fixture.state_dir().join("state.json");
            let mut state: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let replacement = if state["boot_id"] == "00000000-0000-0000-0000-000000000000" {
                "11111111-1111-1111-1111-111111111111"
            } else {
                "00000000-0000-0000-0000-000000000000"
            };
            state["boot_id"] = replacement.into();
            fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
            assert!(Governor::open_at(fixture.state_dir(), Limits::default()).is_err());
            assert!(governor.try_acquire(RequestKind::Interactive).is_err());
            assert!(
                governor
                    .resume_authentication(ResumeAuthorization::ExplicitUserRequest)
                    .is_err()
            );
            let persisted: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(persisted["boot_id"], replacement);
        }

        #[test]
        fn production_identity_ignores_home_xdg_and_worktree_overrides() {
            let fixture = Fixture::new();
            let expected = super::identity_home().unwrap();
            let output = worker(&fixture.state_dir(), "identity")
                .env("BUAA_GOVERNOR_EXPECTED_IDENTITY", &expected)
                .env("HOME", fixture.0.join("different-home"))
                .env("XDG_STATE_HOME", fixture.0.join("different-state"))
                .env("XDG_CONFIG_HOME", fixture.0.join("different-config"))
                .output()
                .unwrap();
            assert!(output.status.success(), "identity worker failed");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("GOVERNOR_IDENTITY_STABLE")
            );
            assert!(!fixture.state_dir().exists());
        }
    };
}
