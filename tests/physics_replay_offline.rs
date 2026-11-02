use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn replay(body: &str, mime: &str) -> Value {
    let input = json!({"operation":"physics-select", "action":"replay", "kind":"groups",
        "data":STANDARD.encode(body.as_bytes()), "content_type":mime});
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .arg("physics-experiment")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["source"], "operator_supplied_response_bytes");
    assert_eq!(value["online_acceptance"], false);
    assert_eq!(value["enrollment_verified"], false);
    value
}

#[test]
fn invalid_character_reference_keeps_safe_original_and_seat_count() {
    let body = "<p>分组代号：A 剩余空位：1</p><p>pass&amp;2;word</p>";
    let value = replay(body, "text/html; charset=utf-8");
    assert_eq!(value["result"], "parsed");
    assert_eq!(value["data"]["groups"][0]["remaining_seats"], 1);
    assert_eq!(value["raw_evidence"]["data"], STANDARD.encode(body));
}

#[test]
fn widget_text_cannot_hide_numeric_continuation() {
    let body = "<p>分组代号：A 剩余空位：1<progress max=1 value=0>loading</progress>2</p>";
    let value = replay(body, "text/html; charset=utf-8");
    assert_eq!(value["result"], "degraded");
    assert_eq!(value["fallback_reason"], "ambiguous_remaining_seats");
    assert!(value["data"].is_null());
}

#[test]
fn invalid_mime_does_not_release_original() {
    let value = replay("ordinary", "text/html; charset=utf-8;");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert_eq!(value["raw_evidence"]["raw_withheld_reason"], "response_safety_unreviewed");
    assert!(value["raw_evidence"]["data"].is_null());
}

#[test]
fn confirmed_sensitive_control_survives_unrelated_noscript() {
    let value = replay("<input type=password value=synthetic-private><noscript>fallback</noscript>", "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld_reason"], "sensitive_response_material");
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(!value.to_string().contains("synthetic-private"));
}

#[test]
fn long_numeric_character_reference_cannot_hide_private_marker() {
    let body = format!("<p>分组代号：A 剩余空位：1</p><p>pass&#{}8203;word:opaque-fixture-value</p>", "0".repeat(64));
    let value = replay(&body, "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert_eq!(value["raw_evidence"]["raw_withheld_reason"], "sensitive_response_material");
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn numeric_reference_without_semicolon_cannot_hide_private_marker() {
    let value = replay("<p>分组代号：A 剩余空位：1</p><p>pass&#8203word:opaque-fixture-value</p>", "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn legacy_named_reference_without_semicolon_cannot_hide_private_marker() {
    let value = replay("<p>分组代号：A 剩余空位：1</p><p>pass&shyword:opaque-fixture-value</p>", "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn printable_numeric_reference_without_semicolon_cannot_hide_private_marker() {
    let value = replay("<p>分组代号：A 剩余空位：1</p><p>pass&#97word:opaque-fixture-value</p>", "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn printable_named_reference_without_semicolon_cannot_hide_private_marker() {
    let value = replay("<p>分组代号：A 剩余空位：1</p><p>pass&ampword:opaque-fixture-value</p>", "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn unconsumed_reference_text_does_not_invent_a_private_marker() {
    for suffix in [
        "<p>pass&amp;shyword</p>",
        "<input name='pass&shyword' value='ordinary'>",
        "<script>pass&shyword</script>",
    ] {
        let body = format!("<p>分组代号：A 剩余空位：1</p>{suffix}");
        let value = replay(&body, "text/html; charset=utf-8");
        assert_eq!(value["result"], "parsed", "{suffix}");
        assert_eq!(value["raw_evidence"]["data"], STANDARD.encode(body));
    }
}

#[test]
fn quoted_pair_charset_decodes_as_utf8() {
    let body = "<p>分组代号：A 剩余空位：1</p>";
    let value = replay(body, r#"text/html; charset="ut\f-8""#);
    assert_eq!(value["result"], "parsed");
    assert_eq!(value["data"]["groups"][0]["remaining_seats"], 1);
    assert_eq!(value["raw_evidence"]["data"], STANDARD.encode(body));
}

#[test]
fn inert_template_srcdoc_never_releases_unreviewed_content() {
    let body = "<p>分组代号：A 剩余空位：1</p><template><iframe srcdoc=\"&lt;input type='pass&amp;#119;ord' value='opaque-fixture-value'&gt;\"></iframe></template>";
    let value = replay(body, "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn discarded_frameset_source_never_becomes_raw_evidence() {
    let body = "<!doctype html><!-- &amp; --><frameset><label>pass<b>word</b>:opaque-fixture-value</label></frameset>";
    let value = replay(body, "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn discarded_frameset_text_without_references_is_still_screened() {
    let body = "<!doctype html><frameset><label>pass<b>word</b>:opaque-fixture-value</label></frameset>";
    let value = replay(body, "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn duplicate_attribute_content_is_not_assumed_reviewed() {
    let body = "<p>分组代号：A 剩余空位：1</p><input title='ordinary' title='opaque-fixture-value'>";
    let value = replay(body, "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn chinese_private_label_in_comment_is_not_released() {
    let body = "<p>分组代号：A 剩余空位：1</p><!-- 密码：opaque-fixture-value -->";
    let value = replay(body, "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn whitespace_split_private_label_in_comment_is_withheld() {
    let value = replay("<p>分组代号：A 剩余空位：1</p><!-- pass word:opaque-fixture-value -->", "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

#[test]
fn whitespace_split_private_label_in_doctype_is_withheld() {
    let value = replay("<!DOCTYPE html PUBLIC \"pass word\" \"fixture\"><p>分组代号：A 剩余空位：1</p>", "text/html; charset=utf-8");
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
    assert!(value["data"].is_null());
}

fn bounded_replay(body: &str, seconds: u64) -> Value {
    use std::io::Read;
    use std::time::{Duration, Instant};

    let input = json!({"operation":"physics-select","action":"replay","kind":"groups",
        "data":STANDARD.encode(body.as_bytes()),"content_type":"text/html; charset=utf-8"});
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa")).arg("physics-experiment")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || { let mut bytes = Vec::new(); stdout.read_to_end(&mut bytes).unwrap(); bytes });
    let err = std::thread::spawn(move || { let mut bytes = Vec::new(); stderr.read_to_end(&mut bytes).unwrap(); bytes });
    child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() { break status; }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            out.join().unwrap();
            err.join().unwrap();
            panic!("HTML replay exceeded the bounded worker deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = out.join().unwrap();
    let stderr = err.join().unwrap();
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    serde_json::from_slice(&stdout).unwrap()
}

#[test]
fn oversized_tag_is_rejected_within_a_bounded_worker_deadline() {
    let mut body = String::from("<div");
    for i in 0..100_000 { body.push_str(&format!(" a{i:05}=x")); }
    body.push_str("></div>");
    let value = bounded_replay(&body, 10);
    assert_eq!(value["raw_evidence"]["raw_withheld"], true);
    assert!(value["raw_evidence"]["data"].is_null());
}

#[test]
fn many_short_attribute_sets_remain_readable_within_a_bounded_deadline() {
    let mut body = String::from("<p>分组代号：A 剩余空位：1</p><p>&amp;</p>");
    for _ in 0..64 {
        body.push_str("<div");
        for i in 0..512 { body.push_str(&format!(" a{i:04}=x")); }
        body.push_str("></div>");
    }
    let value = bounded_replay(&body, 20);
    assert_eq!(value["result"], "parsed");
    assert_eq!(value["data"]["groups"][0]["remaining_seats"], 1);
    assert_eq!(value["raw_evidence"]["data"], STANDARD.encode(body));
}
