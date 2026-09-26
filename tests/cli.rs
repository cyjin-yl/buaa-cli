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

#[cfg(target_os = "linux")]
#[test]
fn baseline_save_stays_private_under_umask_0022() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::os::unix::process::CommandExt;

    let directory = std::env::temp_dir().join(format!("buaa-cli-baseline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let path = directory.join("baseline.json");
    let run = |score| {
        let input = format!(
            r#"{{"policy":{{"kind":"table","id":"synthetic","source":"https://example.invalid/policy","pass_min":60,"bands":[{{"min":85,"max":100,"point":4.0}},{{"min":75,"max":84,"point":3.0}},{{"min":60,"max":74,"point":2.0}}]}},"courses":[{{"name":"Synthetic Course","score":{score},"credit":4.0}}]}}"#
        );
        let mut command = Command::new(env!("CARGO_BIN_EXE_buaa"));
        command
            .args(["marks", "baseline", "save", path.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: this child hook only sets its process-local umask before exec.
        unsafe {
            command.pre_exec(|| {
                // SAFETY: umask is set only in this isolated child before exec.
                libc::umask(0o022);
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    for (score, expected) in [(92, "saved"), (92, "unchanged"), (88, "saved")] {
        let output = run(score);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["result"], expected);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn credits_cli_rejects_unknown_major_and_conflicting_course_identity() {
    let inputs = [
        serde_json::json!({
            "major":"NOT_A_REAL_MAJOR",
            "selected":[
                "运筹学（二）","管理信息系统","生产与运作管理","现代程序设计",
                "计量经济学","国际经济学","货币金融学","应用随机过程",
                "组织行为学","市场营销","财务报表分析"
            ]
        })
        .to_string(),
        r#"{"major":"经济统计","selected":["非参数统计"]}"#.to_owned(),
    ];
    for input in inputs {
        let output = invoke(&["credits", "calculate"], input.as_bytes());
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"], "invalid_input");
    }
}
