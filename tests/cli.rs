use serde_json::Value;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn invoke(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn invalid_late_input_emits_nothing_and_never_echoes_payload() {
    let output = invoke(
        &["timed-input", "--raw"],
        b"[0]first\n[sensitive-sentinel]private-sentinel",
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "invalid_input");
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("sentinel")
    );
}

#[test]
fn raw_replay_closes_with_exact_payload_and_no_json_wrapper() {
    let output = invoke(&["timed-input", "--raw"], "[0]  雪\t\r\n[0]\r\n".as_bytes());
    assert!(output.status.success());
    assert_eq!(output.stdout, "  雪\t\n\n".as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn non_utf8_and_oversized_inputs_fail_without_stdout() {
    for input in [vec![0xff], vec![b'x'; 8 * 1024 * 1024 + 1]] {
        let output = invoke(&["timed-input", "--dry-run"], &input);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"], "invalid_input");
    }
}

#[test]
fn unimplemented_command_cannot_report_success_or_echo_arguments() {
    let output = invoke(&["unsupported-sentinel"], b"");
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "unsupported");
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("sentinel")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn output_failure_is_unavailable_not_invalid_input() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .args(["timed-input", "--raw"])
        .stdin(Stdio::piped())
        .stdout(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"[0]local\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "unavailable");
}

#[cfg(unix)]
#[test]
fn non_unicode_arguments_fail_with_sanitized_json_instead_of_panic() {
    use std::os::unix::ffi::OsStringExt;
    let arg = std::ffi::OsString::from_vec(b"sensitive-sentinel\xff".to_vec());
    let output = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .arg(arg)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "invalid_input");
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("sentinel")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn operating_system_stdin_failure_is_unavailable() {
    let output = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .arg("timed-input")
        .stdin(std::fs::File::open(".").unwrap())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "unavailable");
}

#[test]
fn conflicting_archive_network_modes_reject_before_reading_stdin() {
    use std::time::{Duration, Instant};
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .args(["archive", "lookup", "--online", "--refresh"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep stdin open but empty: validation must not wait for input or attempt
    // network work. Even a regression cannot receive a URL in this test.
    let input = child.stdin.take().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("invalid network modes waited for stdin");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    drop(input);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "invalid_input");
}

#[test]
fn gateway_logout_recovery_is_offline_only_and_validates_typed_input() {
    use std::time::{Duration, Instant};

    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .args(["gateway", "logout-recovery-commit", "--online"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = child.stdin.take().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("online recovery mode waited for stdin");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "permission");

    let output = invoke(&["gateway", "logout-recovery-commit", "--offline"], b"{}");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "invalid_input");
}
