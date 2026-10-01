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
fn drift_check_reports_changes_and_rejects_invalid_input() {
    let output = invoke(
        &["drift", "check"],
        br#"{"baseline":{"v":"s","gone":2},"candidate":{"v":5,"new":9}}"#,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["type"], "contract_drift_report");
    assert_eq!(value["in_sync"], false);
    assert_eq!(value["change_count"], 3);
    let kinds: Vec<&str> = value["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"value_changed"));
    assert!(kinds.contains(&"removed"));
    assert!(kinds.contains(&"added"));
    // Raw values must not leak.
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("sensitive")
    );

    let bad = invoke(&["drift", "check"], b"not json");
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
    let error: Value = serde_json::from_slice(&bad.stderr).unwrap();
    assert_eq!(error["error"], "invalid_input");
}

#[test]
fn physics_commands_report_results_and_reject_invalid_input() {
    let pend = invoke(
        &["physics", "pendulum"],
        br#"{"length_m":0.980,"length_uncertainty_m":0.001,"cycles":50,"total_time_s":99.50,"total_time_uncertainty_s":0.05}"#,
    );
    assert!(
        pend.status.success(),
        "{}",
        String::from_utf8_lossy(&pend.stderr)
    );
    let value: Value = serde_json::from_slice(&pend.stdout).unwrap();
    assert_eq!(value["type"], "physics_pendulum");
    assert_eq!(value["units"]["g"], "m/s^2");
    assert!((value["g_m_s2"].as_f64().unwrap() - 9.769664718635964).abs() < 1e-9);

    let fit = invoke(
        &["physics", "fit"],
        br#"{"points":[[0,0.2],[1,0.9],[2,2.1],[3,3.0],[4,4.2],[5,4.9]]}"#,
    );
    let value: Value = serde_json::from_slice(&fit.stdout).unwrap();
    assert_eq!(value["type"], "physics_fit");
    assert_eq!(value["n"], 6);

    let type_a = invoke(
        &["physics", "type-a"],
        br#"{"samples":[0.980,0.978,0.981,0.979,0.980]}"#,
    );
    let value: Value = serde_json::from_slice(&type_a.stdout).unwrap();
    assert_eq!(value["type"], "physics_type_a");
    assert_eq!(value["n"], 5);

    let bad = invoke(&["physics", "pendulum"], b"not json");
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
    let error: Value = serde_json::from_slice(&bad.stderr).unwrap();
    assert_eq!(error["error"], "invalid_input");
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

#[test]
fn announcements_list_validates_filters_before_any_network_access() {
    for input in [
        br#"{"category":"nope"}"# as &[u8],
        br#"{"since":"2026/09/01"}"# as &[u8],
        br#"{"page":0}"# as &[u8],
        b"[1,2]" as &[u8],
    ]
    .iter()
    {
        let input = *input;
        let output = invoke(&["announcements", "list"], input);
        assert_eq!(output.status.code(), Some(2), "{input:?}");
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"], "invalid_input");
    }
}

/// The operator may already have a cached listing. Neither HOME nor unrelated
/// cache files establish that fact; assert the CLI's two valid offline outcomes.
/// The empty-cache branch itself is pinned hermetically by the lib test
/// `offline_lookup_with_empty_cache_reports_unavailable`.
#[test]
fn announcements_list_offline_serves_cache_or_reports_unavailable() {
    let output = invoke(&["announcements", "list"], b"");
    match output.status.code() {
        Some(0) => {
            assert!(output.stderr.is_empty());
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["type"], "announcements_list");
            assert_eq!(value["retrieval"]["cache_status"], "hit");
        }
        Some(7) => {
            assert!(output.stdout.is_empty());
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(error["error"], "unavailable");
        }
        status => panic!("unexpected offline status {status:?}: {:?}", output.stderr),
    }
}

#[test]
fn announcements_article_rejects_foreign_and_query_urls() {
    for input in [
        br#"{"url":"https://evil.example/info/1010/1.htm"}"# as &[u8],
        br#"{"url":"https://news.buaa.edu.cn/info/1010/1.htm?x=1"}"# as &[u8],
        br#"{"url":"https://news.buaa.edu.cn/info/abc/1.htm"}"# as &[u8],
        b"[]" as &[u8],
    ]
    .iter()
    {
        let input = *input;
        let output = invoke(&["announcements", "article"], input);
        assert_eq!(output.status.code(), Some(2), "{input:?}");
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"], "invalid_input");
    }
}

#[test]
fn announcements_history_replays_operator_asserted_snapshot_offline() {
    let html = "<!DOCTYPE html><html><head><title>通知公告-新闻网</title></head><body><div class=\"tlist\"><ul><li><a href=\"info/1010/69802.htm\"><div class=\"pub_date\"><div><b>15</b><span>2026.09</span></div></div><div class=\"pub_info\"><span>通知公告</span><h3>测试通知</h3><p>摘要</p></div></a></li></ul></div></body></html>";
    let encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, html.as_bytes());
    let payload = format!(
        "{{\"html\":\"{encoded}\",\"provenance\":{{\"source_url\":\"https://news.buaa.edu.cn/tzgg.htm\",\"asserted_by\":\"operator\"}}}}"
    );
    let output = invoke(&["announcements", "history"], payload.as_bytes());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["type"], "announcements_history");
    assert_eq!(value["entries"].as_array().unwrap().len(), 1);
    let entry = &value["entries"][0];
    assert_eq!(entry["title"], "测试通知");
    assert_eq!(entry["date"], "2026-09-15");
    assert_eq!(
        entry["resolved_http_url"],
        "https://news.buaa.edu.cn/info/1010/69802.htm"
    );
    assert_eq!(value["provenance"]["asserted_by"], "operator");
    assert_eq!(
        value["provenance"]["source_url"],
        "https://news.buaa.edu.cn/tzgg.htm"
    );
    assert!(value["retrieval"]["sha256"].as_str().is_some());
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

#[test]
fn schema_and_help_list_every_online_entry_point() {
    // STR-CLI-001: the machine-readable network_policy.opt_in must name every
    // command with an explicit online entry point.
    for command in ["help", "schema"] {
        let output = invoke(&[command], b"");
        assert!(output.status.success());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let opt_in = value["network_policy"]["opt_in"].as_str().unwrap_or("");
        for surface in [
            "archive",
            "organizations",
            "announcements",
            "fengrubei fetch --online",
            "gateway explicit online flags",
        ] {
            assert!(
                opt_in.contains(surface),
                "{command} opt_in missing {surface}: {opt_in}"
            );
        }
    }
}
