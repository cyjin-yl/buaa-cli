//! `buaa ihome session` performs a one-shot CAS login plus exactly one
//! selected read. Every case below must settle without reaching the network
//! or the governor: only a disabled valid input exits successfully, every
//! enabled `--online` case is invalid at the local-input boundary so it must
//! be refused before the network factory runs, and no refusal may echo the
//! supplied credentials.
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Output, Stdio};

const USERNAME: &str = "synthetic-op-9z4qk7";
const PASSWORD: &str = "synthetic-pass-x8v2m5rd";

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

fn list_read(enabled: bool) -> Value {
    json!({"operation": "list", "enabled": enabled})
}

fn detail_read(enabled: bool) -> Value {
    json!({"operation": "detail", "enabled": enabled, "id": 42})
}

/// The session derives the bearer token from its own CAS login; the read
/// request shape itself carries no authentication material.
fn session(read: &Value) -> Value {
    json!({
        "operation": "session",
        "authorized": true,
        "username": USERNAME,
        "password": PASSWORD,
        "intent": format!("LOGIN {} ihome", USERNAME),
        "read": read,
    })
}

fn assert_not_echoed(output: &Output, secret: &str) {
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(secret),
            "sensitive value {secret:?} leaked into CLI output"
        );
    }
}

fn assert_no_credentials(output: &Output) {
    assert_not_echoed(output, PASSWORD);
    // The username is supplied both as a field and inside the typed intent;
    // it must not be reproduced on any refusal either.
    assert_not_echoed(output, USERNAME);
}

/// A refusal is a nonzero structured JSON error on stderr with no stdout. The
/// exact code is implementation-owned; only the failure shape is pinned here.
fn assert_refused(output: &Output) {
    assert!(
        !output.status.success(),
        "session input must be refused, not served"
    );
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(error["error"].is_string());
    assert_no_credentials(output);
}

/// Refusal for inputs that are malformed at the input-schema level.
fn assert_invalid(output: &Output) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "invalid_input");
    assert_no_credentials(output);
}

fn assert_disabled(output: &Output) {
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["type"], "ihome_session");
    assert_eq!(result["result"], "disabled");
    assert_eq!(result["network_performed"], false);
    assert_eq!(result["write_operations_performed"], false);
    assert!(output.stderr.is_empty());
    assert_no_credentials(output);
}

#[test]
fn disabled_session_reports_disabled_for_both_reads() {
    for read in [list_read(false), detail_read(false)] {
        for args in [
            &["ihome", "session"][..],
            &["ihome", "session", "--online"][..],
        ] {
            let output = invoke(args, serde_json::to_vec(&session(&read)).unwrap().as_slice());
            assert_disabled(&output);
        }
    }
    // The root `operation` member is optional; omitting it keeps the
    // session contract rather than falling back to another command shape.
    let mut implicit = session(&list_read(false));
    implicit.as_object_mut().unwrap().remove("operation");
    assert_disabled(&invoke(
        &["ihome", "session"],
        serde_json::to_vec(&implicit).unwrap().as_slice(),
    ));
}

/// A disabled read settles before credential or authorization validation, but
/// the shape of the request is still enforced.
#[test]
fn disabled_session_validates_shape_but_not_authorization() {
    let mut unauthorized = session(&list_read(false));
    unauthorized["authorized"] = json!(false);
    assert_disabled(&invoke(
        &["ihome", "session"],
        serde_json::to_vec(&unauthorized).unwrap().as_slice(),
    ));
    // `enabled` must remain a real boolean even on the disabled path.
    let bad_shape = session(&json!({"operation": "list", "enabled": "no"}));
    assert_invalid(&invoke(
        &["ihome", "session"],
        serde_json::to_vec(&bad_shape).unwrap().as_slice(),
    ));
}

#[test]
fn enabled_session_requires_explicit_online() {
    for read in [list_read(true), detail_read(true)] {
        let output = invoke(
            &["ihome", "session"],
            serde_json::to_vec(&session(&read)).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
}

#[test]
fn unauthorization_refuses_before_any_authentication_attempt() {
    for online in [false, true] {
        let mut payload = session(&list_read(true));
        payload["authorized"] = json!(false);
        let args = if online {
            &["ihome", "session", "--online"][..]
        } else {
            &["ihome", "session"][..]
        };
        assert_refused(&invoke(
            args,
            serde_json::to_vec(&payload).unwrap().as_slice(),
        ));
    }
}

#[test]
fn typed_intent_must_match_exactly() {
    for intent in [
        format!("LOGIN other-operator ihome"),
        format!("RESUME {USERNAME} ihome"),
        format!("LOGIN {USERNAME}"),
        format!("LOGIN {USERNAME} smart"),
        format!("LOGIN {USERNAME} ihome extra"),
        format!("login {USERNAME} ihome"),
        format!("LOGIN  {USERNAME} ihome"),
        // The final variant's last codepoint is a Cyrillic homoglyph: exact
        // matching must not fold it into the ASCII target.
        format!("LOGIN {USERNAME} IHOMЕ"),
    ] {
        let mut payload = session(&list_read(true));
        payload["intent"] = json!(intent);
        let output = invoke(
            &["ihome", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
    // A missing or mistyped intent is equally refused.
    let mut missing = session(&list_read(true));
    missing.as_object_mut().unwrap().remove("intent");
    assert_refused(&invoke(
        &["ihome", "session", "--online"],
        serde_json::to_vec(&missing).unwrap().as_slice(),
    ));
}

/// Root and read are map-only: unknown members, duplicates, and any
/// caller-supplied authentication material or pagination override are refused
/// at the input boundary.
#[test]
fn unknown_duplicate_and_injected_fields_refuse() {
    for extra in [
        ("token", json!("synthetic-caller-token-7q2w")),
        ("cookie", json!("synthetic-caller-cookie=9f4e")),
        ("url", json!("https://i.buaa.edu.cn/caller-chosen")),
        ("callback_url", json!("http://i.buaa.edu.cn/api/authLogin")),
        ("refresh", json!(true)),
        ("write", json!(true)),
        ("cas_ticket", json!("synthetic-st-ticket-4t8b")),
        ("credential", json!("synthetic-injected-private-value")),
    ] {
        let mut payload = session(&list_read(true));
        payload[extra.0] = extra.1.clone();
        let output = invoke(
            &["ihome", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_invalid(&output);
        if let Some(text) = extra.1.as_str() {
            assert_not_echoed(&output, text);
        }
    }
    // The read map carries no caller tokens, cookies, URLs, cursors or
    // write/pagination overrides either.
    for extra in [
        ("token", json!("synthetic-caller-token-7q2w")),
        ("cookie", json!("synthetic-caller-cookie=9f4e")),
        ("access_token", json!("synthetic-caller-token-7q2w")),
        ("url", json!("https://i.buaa.edu.cn/caller-chosen")),
        ("refresh", json!(true)),
        ("max_pages", json!(5)),
        ("since_id", json!(7)),
        ("write", json!(true)),
        ("cursor", json!("synthetic-cursor-3k9p")),
    ] {
        let mut read = list_read(true);
        read[extra.0] = extra.1.clone();
        let payload = session(&read);
        let output = invoke(
            &["ihome", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_invalid(&output);
        if let Some(text) = extra.1.as_str() {
            assert_not_echoed(&output, text);
        }
    }
    // Duplicate keys are not silently last-wins: both a duplicated root
    // member and a duplicated read member refuse instead of decoding.
    let dup_root = format!(
        concat!(
            "{{\"operation\":\"session\",\"operation\":\"session\",\"authorized\":true,",
            "\"username\":\"{u}\",\"password\":\"{p}\",\"intent\":\"LOGIN {u} ihome\",",
            "\"read\":{{\"operation\":\"list\",\"enabled\":false}}}}"
        ),
        u = USERNAME,
        p = PASSWORD,
    );
    assert_invalid(&invoke(&["ihome", "session"], dup_root.as_bytes()));
    let dup_read = format!(
        concat!(
            "{{\"authorized\":true,\"username\":\"{u}\",\"password\":\"{p}\",",
            "\"intent\":\"LOGIN {u} ihome\",",
            "\"read\":{{\"operation\":\"list\",\"operation\":\"list\",\"enabled\":false}}}}"
        ),
        u = USERNAME,
        p = PASSWORD,
    );
    assert_invalid(&invoke(&["ihome", "session"], dup_read.as_bytes()));
}

#[test]
fn list_window_bounds_enforced_before_network() {
    for read in [
        json!({"operation": "list", "enabled": true, "limit": 0}),
        json!({"operation": "list", "enabled": true, "limit": 101}),
        json!({"operation": "list", "enabled": true, "limit": "20"}),
        json!({"operation": "list", "enabled": true, "limit": -1}),
        json!({"operation": "list", "enabled": true, "page": 0}),
        json!({"operation": "list", "enabled": true, "page": 4294967295_u64}),
        json!({"operation": "list", "enabled": true, "page": "1"}),
        json!({"operation": "list", "enabled": true, "limit": 5, "page": 2, "max_pages": 4}),
    ] {
        let output = invoke(
            &["ihome", "session", "--online"],
            serde_json::to_vec(&session(&read)).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
}

#[test]
fn detail_read_requires_valid_id_and_enabled() {
    for read in [
        json!({"operation": "detail", "enabled": true}),
        json!({"operation": "detail", "enabled": true, "id": "42"}),
        json!({"operation": "detail", "enabled": true, "id": -1}),
        json!({"operation": "detail", "enabled": true, "id": null}),
        json!({"operation": "detail", "id": 42}),
    ] {
        let output = invoke(
            &["ihome", "session", "--online"],
            serde_json::to_vec(&session(&read)).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
}

/// The read operation discriminator only admits `list` or `detail`, and the
/// optional root `operation` only admits `session`: neither writes nor other
/// operations are reachable through this command.
#[test]
fn wrong_operations_refuse_before_network() {
    for operation in [
        json!("write"),
        json!("delete"),
        json!("export"),
        json!("login"),
        json!(42),
        json!(null),
    ] {
        let read = json!({"operation": operation, "enabled": true, "id": 42});
        let output = invoke(
            &["ihome", "session", "--online"],
            serde_json::to_vec(&session(&read)).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
    let mut missing_op = session(&list_read(true));
    missing_op["read"].as_object_mut().unwrap().remove("operation");
    assert_refused(&invoke(
        &["ihome", "session", "--online"],
        serde_json::to_vec(&missing_op).unwrap().as_slice(),
    ));
    for operation in [json!("list"), json!("detail"), json!("write"), json!(7)] {
        let mut payload = session(&list_read(true));
        payload["operation"] = operation;
        assert_refused(&invoke(
            &["ihome", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        ));
    }
}

#[test]
fn session_envelope_requires_object_shape() {
    let read_array = format!(
        concat!(
            "{{\"authorized\":true,\"username\":\"{u}\",\"password\":\"{p}\",",
            "\"intent\":\"LOGIN {u} ihome\",",
            "\"read\":[\"list\",false]}}"
        ),
        u = USERNAME,
        p = PASSWORD,
    );
    for input in [
        serde_json::to_vec(&json!("not-an-object")).unwrap(),
        serde_json::to_vec(&json!([true, USERNAME, PASSWORD, "LOGIN x ihome"])).unwrap(),
        read_array.into_bytes(),
        serde_json::to_vec(&json!({"authorized": true, "read": "list"})).unwrap(),
    ] {
        let output = invoke(&["ihome", "session", "--online"], input.as_slice());
        assert_invalid(&output);
    }
}

#[test]
fn missing_or_mistyped_envelope_fields_refuse() {
    let base = session(&list_read(true));
    let mut missing_authorized = base.clone();
    missing_authorized.as_object_mut().unwrap().remove("authorized");
    let mut missing_username = base.clone();
    missing_username.as_object_mut().unwrap().remove("username");
    let mut missing_password = base.clone();
    missing_password.as_object_mut().unwrap().remove("password");
    let mut missing_read = base.clone();
    missing_read.as_object_mut().unwrap().remove("read");
    let mut mistyped_authorized = base.clone();
    mistyped_authorized["authorized"] = json!("yes");
    let mut mistyped_username = base.clone();
    mistyped_username["username"] = json!(11223344);
    let mut mistyped_password = base.clone();
    mistyped_password["password"] = json!({"value": PASSWORD});
    let mut mistyped_intent = base.clone();
    mistyped_intent["intent"] = json!(true);
    let mut mistyped_read = base.clone();
    mistyped_read["read"] = json!("list");
    for payload in [
        missing_authorized,
        missing_username,
        missing_password,
        missing_read,
        mistyped_authorized,
        mistyped_username,
        mistyped_password,
        mistyped_intent,
        mistyped_read,
    ] {
        let output = invoke(
            &["ihome", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
}

#[test]
fn malformed_stdin_bytes_refuse_without_echo() {
    for input in [
        b"not json at all".as_slice(),
        b"{\"authorized\":true,".as_slice(),
        b"".as_slice(),
    ] {
        let output = invoke(&["ihome", "session", "--online"], input);
        assert_invalid(&output);
    }
}

/// Flag parsing happens before stdin is read; malformed flags are an
/// `invalid_input` regardless of the bytes that would follow.
#[test]
fn malformed_cli_flags_refuse() {
    let input = serde_json::to_vec(&session(&list_read(false))).unwrap();
    for args in [
        &["ihome", "session", "--refresh"][..],
        &["ihome", "session", "--offline"][..],
        &["ihome", "session", "--online", "--online"][..],
        &["ihome", "session", "--online", "extra"][..],
        &["ihome", "session", "extra"][..],
        &["ihome", "session", "list"][..],
    ] {
        let output = invoke(args, input.as_slice());
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"], "invalid_input");
    }
}

/// The pre-existing token-supplied `ihome list`/`detail` commands keep their
/// own dispatch and input contract after `session` is added.
#[test]
fn existing_list_detail_dispatch_remains_unchanged() {
    for args in [&["ihome"][..], &["ihome", "bogus"][..]] {
        let output = invoke(args, b"{}");
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
    }
    // `ihome list` still parses only the list operation; a detail request is
    // invalid there, and the session's enabled field is not a list field.
    for input in [
        br#"{"operation":"detail","token":"synthetic-token","id":42}"#.as_slice(),
        br#"{"operation":"list","token":"synthetic-token","enabled":false}"#.as_slice(),
        br#"{"operation":"list","token":"synthetic-token","session_cookie":"synthetic-injected-private-value"}"#
            .as_slice(),
    ] {
        let output = invoke(&["ihome", "list"], input);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_not_echoed(&output, "synthetic-injected-private-value");
    }
    let output = invoke(
        &["ihome", "detail"],
        br#"{"operation":"list","token":"synthetic-token"}"#,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}


