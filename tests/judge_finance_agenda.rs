use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

fn invoke(args: &[&str], input: &[u8]) -> std::process::Output {
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
fn finance_rejects_unknown_fields_without_echoing_them() {
    let refused = invoke(&["finance", "--online"], b"{}");
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());

    let input = serde_json::json!({
        "records": [{
            "serial": "PRIVATE-SERIAL-991",
            "project": "酬金",
            "summary": "甲",
            "gross_cents": 1,
            "tax_cents": 0,
            "net_cents": 1,
            "year": 2026,
            "month": 11,
            "recorded_on": "2026-11-15",
            "account": "SHOULD-NOT-PARSE"
        }]
    });
    let output = invoke(&["finance"], &serde_json::to_vec(&input).unwrap());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&stderr).unwrap()["error"], "invalid_input");
    assert!(!stderr.contains("PRIVATE-SERIAL-991"));
    assert!(!stderr.contains("SHOULD-NOT-PARSE"));
}

#[test]
fn judge_failure_and_agenda_sync_do_not_perform_network_work() {
    let judge = serde_json::json!({
        "now": "2026-11-22T09:00:00+08:00",
        "read_error": "upstream closed",
        "assignments": [{
            "course_id": "c",
            "course_name": "算法",
            "assignment_id": "hidden-assignment",
            "title": "机密作业标题",
            "problems": []
        }]
    });
    let output = invoke(&["judge"], &serde_json::to_vec(&judge).unwrap());
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["result"], "read_failed");
    assert_eq!(body["network_performed"], false);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("机密作业标题"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("hidden-assignment"));

    let agenda = serde_json::json!({
        "now": "2026-11-22T09:00:00+08:00",
        "operation": "sync",
        "school": [],
        "personal": []
    });
    let output = invoke(&["agenda"], &serde_json::to_vec(&agenda).unwrap());
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["result"], "blocked");
    assert_eq!(body["reason"], "cloud_sync_unverified");
    assert_eq!(body["network_performed"], false);
    assert_eq!(body["document_changed"], false);
}
