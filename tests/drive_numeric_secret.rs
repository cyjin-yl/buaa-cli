use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn listing(secret: &str) -> Value {
    let body = br#"{"dirs":[],"files":[{"docid":"d","name":"n","rev":"r","size":1,"modified":1e3}]}"#;
    let input = json!({"operation":"list", "host":"bhpan.buaa.edu.cn", "access_token":secret,
        "raw_base64":STANDARD.encode(body), "content_type":"application/json"});
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa")).arg("drive")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["source"], "operator_supplied");
    assert_eq!(value["network_performed"], false);
    value
}

#[test]
fn normalized_numeric_credential_is_not_returned() {
    let value = listing("1000.0");
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["evidence"]["raw_withheld"], true);
    assert_eq!(value["evidence"]["raw_base64"], "");
    assert!(!value.to_string().contains("1000.0"));
}

#[test]
fn unrelated_credential_keeps_numeric_metadata() {
    let value = listing("unrelated-secret");
    assert_eq!(value["status"], "structured");
    assert_eq!(value["entries"][0]["modified"], json!(1000.0));
}
