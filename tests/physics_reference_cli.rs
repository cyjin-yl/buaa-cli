//! CLI-level contract for the rights-reviewed physics reference command.
//!
//! These cases are offline: they prove the command routing, the stdin
//! contract and the refusal boundaries without any network request. No
//! upstream bytes are fetched, so nothing here discloses reference material.

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

const TREE: &str = "82655593cd3486549b5e49eec55ca9add1d3ccd4";
const GUIDE_BLOB: &str = "02427435071267252f752280278fbb8af6b1919b";

fn error_of(output: &Output) -> Value {
    serde_json::from_slice(&output.stderr).unwrap()
}

#[test]
fn the_reference_command_requires_a_known_subcommand() {
    for args in [
        vec!["physics-reference"],
        vec!["physics-reference", "bogus"],
    ] {
        let output = invoke(&args, b"");
        assert_eq!(output.status.code(), Some(3), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let error = error_of(&output);
        assert_eq!(error["error"], "unsupported", "{args:?}");
    }
}

#[test]
fn the_reference_command_refuses_an_unexpected_flag() {
    let output = invoke(&["physics-reference", "catalog", "--refresh"], b"");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = error_of(&output);
    assert_eq!(error["error"], "invalid_input");
}

#[test]
fn the_catalog_refuses_a_selector_before_any_request() {
    let output = invoke(
        &["physics-reference", "catalog"],
        br#"{"path":"README.md"}"#,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = error_of(&output);
    assert_eq!(error["error"], "invalid_input");
}

#[test]
fn the_retrieval_refuses_a_positional_request() {
    let input = format!(r#"["README.md","{TREE}","{GUIDE_BLOB}",6736,true]"#);
    let output = invoke(&["physics-reference", "retrieve"], input.as_bytes());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = error_of(&output);
    assert_eq!(error["error"], "invalid_input");
}

#[test]
fn the_retrieval_refuses_a_missing_rights_attestation() {
    let input = format!(
        r#"{{"path":"README.md","tree_sha":"{TREE}","blob_sha":"{GUIDE_BLOB}","size":6736}}"#
    );
    let output = invoke(&["physics-reference", "retrieve"], input.as_bytes());
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    let error = error_of(&output);
    assert_eq!(error["error"], "authorization_required");
}

#[test]
fn the_retrieval_refuses_a_foreign_tree_object() {
    let input = format!(
        r#"{{"path":"README.md","tree_sha":"1111111111111111111111111111111111111111","blob_sha":"{GUIDE_BLOB}","size":6736,"rights_reviewed":true}}"#
    );
    let output = invoke(&["physics-reference", "retrieve"], input.as_bytes());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = error_of(&output);
    assert_eq!(error["error"], "invalid_input");
}

#[test]
fn the_retrieval_refuses_a_credential_field_without_echoing_it() {
    let input = format!(
        r#"{{"path":"README.md","tree_sha":"{TREE}","blob_sha":"{GUIDE_BLOB}","size":6736,"rights_reviewed":true,"password":"fixture-only"}}"#
    );
    let output = invoke(&["physics-reference", "retrieve"], input.as_bytes());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("fixture-only"), "{stderr}");
    let error = error_of(&output);
    assert_eq!(error["error"], "invalid_input");
}

#[test]
fn the_offline_catalog_reports_a_cache_miss_instead_of_inventing_entries() {
    // Offline: the command either serves a verified cached catalog, serves a
    // cached degraded response, or reports the miss. It never publishes an
    // inventory it never verified.
    let output = invoke(&["physics-reference", "catalog"], b"");
    if output.status.success() {
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["type"], "physics_reference_catalog");
        assert!(value["entries"].is_array());
        match value["result"].as_str() {
            Some("catalog_snapshot") => {
                // A verified snapshot names the reviewed tree and admits
                // exactly the two reviewed items.
                assert_eq!(
                    value["tree_sha"],
                    "82655593cd3486549b5e49eec55ca9add1d3ccd4"
                );
                assert_eq!(value["admitted_count"], 2);
                assert_eq!(value["excluded_count"], 49);
            }
            Some("degraded") => {
                // A retained but unparseable cached response stays degraded
                // and names no tree.
                assert!(value["tree_sha"].is_null());
                assert!(value["fallback_reason"].is_string());
                assert!(value["entries"].as_array().unwrap().is_empty());
            }
            other => panic!("unexpected catalog result {other:?}"),
        }
    } else {
        assert_eq!(output.status.code(), Some(7));
        let error = error_of(&output);
        assert_eq!(error["error"], "unavailable");
    }
}

#[test]
fn the_reference_command_is_published_in_the_schema_and_help() {
    let output = invoke(&["schema"], b"");
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let published = &value["commands"]["physics-reference"];
    assert!(published["catalog"]["output"].is_object());
    assert!(published["retrieve"]["output"].is_object());
    assert!(published["retrieve"]["input"]["properties"]["rights_reviewed"].is_object());

    let output = invoke(&["help"], b"");
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let commands = value["commands"].as_array().unwrap();
    assert!(
        commands
            .iter()
            .any(|command| command == "physics-reference catalog|retrieve [--online]"),
        "{commands:?}"
    );
}
