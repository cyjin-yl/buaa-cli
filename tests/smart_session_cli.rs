//! `buaa smart session` performs a one-shot CAS login plus exactly one read.
//! Every case below must settle without reaching the network or the governor:
//! only the disabled valid input exits successfully, and every refusal must
//! report a structured error while never echoing the supplied credentials.
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

fn classrooms_read() -> Value {
    json!({"service": "classrooms", "enabled": true, "campus_id": 3, "date": "2031-04-12"})
}

/// Read intent carries no authentication material: the session CLI derives the
/// campus cookie itself, so the request shape contains none.
fn library_read() -> Value {
    json!({"service": "library", "enabled": true,
           "query": {"operation": "premises", "day": "2031-04-12"}})
}

fn session(read: &Value) -> Value {
    json!({
        "authorized": true,
        "username": USERNAME,
        "password": PASSWORD,
        "intent": format!("LOGIN {} smart {}", USERNAME, read["service"].as_str().unwrap()),
        "read": read,
    })
}

fn assert_no_credentials(output: &Output) {
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        assert!(!text.contains(PASSWORD), "password leaked into CLI output");
        // The username is supplied both as a field and inside the typed
        // intent; it must not be reproduced on any refusal either.
        assert!(!text.contains(USERNAME), "username leaked into CLI output");
    }
}

/// A refusal is a nonzero structured JSON error on stderr with no stdout. The
/// exact code is implementation-owned; only the failure shape is pinned here.
fn assert_refused(output: &Output) {
    assert!(!output.status.success(), "session input must be refused, not served");
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

#[test]
fn disabled_session_reports_disabled_without_network_or_credentials() {
    let mut read = classrooms_read();
    read["enabled"] = json!(false);
    for args in [
        &["smart", "session"][..],
        &["smart", "session", "--online"][..],
    ] {
        let output = invoke(args, serde_json::to_vec(&session(&read)).unwrap().as_slice());
        assert!(output.status.success());
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["result"], "disabled");
        assert_eq!(result["network_performed"], false);
        assert!(output.stderr.is_empty());
        assert_no_credentials(&output);
    }
}

#[test]
fn enabled_session_requires_explicit_online() {
    for read in [classrooms_read(), library_read()] {
        let output = invoke(
            &["smart", "session"],
            serde_json::to_vec(&session(&read)).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
}

#[test]
fn unauthorization_refuses_before_any_authentication_attempt() {
    for online in [false, true] {
        let mut payload = session(&classrooms_read());
        payload["authorized"] = json!(false);
        let args = if online {
            &["smart", "session", "--online"][..]
        } else {
            &["smart", "session"][..]
        };
        assert_refused(&invoke(args, serde_json::to_vec(&payload).unwrap().as_slice()));
    }
}

#[test]
fn mismatched_typed_intent_refuses() {
    let mut library_intent_mismatch = session(&classrooms_read());
    library_intent_mismatch["intent"] = json!(format!("LOGIN {} smart library", USERNAME));
    let mut username_intent_mismatch = session(&library_read());
    username_intent_mismatch["intent"] =
        json!(format!("LOGIN other-operator smart library"));
    let mut wrong_verb = session(&classrooms_read());
    wrong_verb["intent"] = json!(format!("RESUME {} smart classrooms", USERNAME));
    let mut missing_service = session(&classrooms_read());
    missing_service["intent"] = json!(format!("LOGIN {} smart", USERNAME));
    for payload in [
        library_intent_mismatch,
        username_intent_mismatch,
        wrong_verb,
        missing_service,
    ] {
        let output = invoke(
            &["smart", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
}

#[test]
fn unknown_fields_and_authentication_material_in_read_refuse() {
    for extra in [
        ("caller_field", json!("surprise")),
        ("authorized_at", json!("2031-04-12T00:00:00Z")),
    ] {
        let mut payload = session(&classrooms_read());
        payload[extra.0] = extra.1;
        let output = invoke(
            &["smart", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_invalid(&output);
    }
    // The session derives credentials from the login itself; caller-supplied
    // tokens or cookies inside the read are never part of its contract.
    for key in ["token", "cookie", "access_token"] {
        let mut read = library_read();
        read[key] = json!("synthetic-caller-token-7q2w");
        let payload = session(&read);
        let output = invoke(
            &["smart", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_invalid(&output);
    }
    let mut read = classrooms_read();
    read["cookie"] = json!("synthetic-caller-cookie=9f4e");
    let payload = session(&read);
    assert_invalid(&invoke(
        &["smart", "session", "--online"],
        serde_json::to_vec(&payload).unwrap().as_slice(),
    ));
}

#[test]
fn legacy_reads_reject_internal_session_fields() {
    for field in ["authentication_password", "session_cookie", "authentication_cas", "authentication_session", "authentication_cookie"] {
        let mut input = json!({"service":"library","enabled":false,"token":"synthetic-token",
            "query":{"operation":"premises","day":"2031-04-12"}});
        input[field] = json!("synthetic-injected-private-value");
        let output = invoke(&["smart"], &serde_json::to_vec(&input).unwrap());
        assert_invalid(&output);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-injected-private-value"));
    }
    let input = json!({"service":"classrooms","enabled":false,"cookie":"synthetic=sid",
        "campus_id":3,"date":"2031-04-12","authentication_password":"synthetic-injected-private-value"});
    assert_invalid(&invoke(&["smart"], &serde_json::to_vec(&input).unwrap()));
}

#[test]
fn unsupported_read_service_refuses() {
    for service in ["exams", "cgyy", "running"] {
        let read = json!({"service": service, "enabled": true, "cookie": "synthetic-caller-cookie=9f4e"});
        let mut payload = session(&read);
        payload["intent"] = json!(format!("LOGIN {} smart {}", USERNAME, service));
        let output = invoke(
            &["smart", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
}

#[test]
fn library_login_and_mutation_queries_refuse_before_authentication() {
    for query in [
        json!({"operation": "login", "cas": "synthetic-cas-ticket-4t8b"}),
        json!({"operation": "reserve_seat", "id": "seat-9", "day": "2031-04-12"}),
        json!({"operation": "cancel_order", "id": 42}),
    ] {
        let read = json!({"service": "library", "enabled": true, "query": query});
        let payload = session(&read);
        let output = invoke(
            &["smart", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_refused(&output);
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("synthetic-cas-ticket-4t8b"),
            "supplied exchange credential leaked into CLI output"
        );
    }
}

#[test]
fn malformed_date_and_query_inputs_refuse() {
    for read in [
        json!({"service": "classrooms", "enabled": true, "campus_id": 3, "date": "2031-13-40"}),
        json!({"service": "classrooms", "enabled": true, "campus_id": 3, "date": "April 12, 2031"}),
        json!({"service": "classrooms", "enabled": true, "campus_id": "3", "date": "2031-04-12"}),
        json!({"service": "classrooms", "enabled": true, "campus_id": 3}),
        json!({"service": "library", "enabled": true, "query": {"operation": "premises", "day": "not-a-date"}}),
        json!({"service": "library", "enabled": true, "query": {"operation": "premises"}}),
        json!({"service": "library", "enabled": true, "query": "premises"}),
        json!({"service": "library", "enabled": true, "query": {"operation": "teleport", "day": "2031-04-12"}}),
    ] {
        let payload = session(&read);
        let output = invoke(
            &["smart", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
}

#[test]
fn missing_or_mistyped_envelope_fields_refuse() {
    let base = session(&classrooms_read());
    let mut missing_password = base.clone();
    missing_password.as_object_mut().unwrap().remove("password");
    let mut missing_intent = base.clone();
    missing_intent.as_object_mut().unwrap().remove("intent");
    let mut missing_read = base.clone();
    missing_read.as_object_mut().unwrap().remove("read");
    let mut non_string_username = base.clone();
    non_string_username["username"] = json!(11223344);
    for payload in [
        missing_password,
        missing_intent,
        missing_read,
        non_string_username,
        json!("not-an-object"),
    ] {
        let output = invoke(
            &["smart", "session", "--online"],
            serde_json::to_vec(&payload).unwrap().as_slice(),
        );
        assert_refused(&output);
    }
}

#[test]
fn positional_arrays_cannot_replace_session_objects() {
    let mut read = classrooms_read();
    read["enabled"] = json!(false);
    let envelope_array = json!([true,USERNAME,PASSWORD,format!("LOGIN {USERNAME} smart classrooms"),read]);
    let mut read_array = session(&classrooms_read());
    read_array["read"] = json!(["classrooms",false,3,"2031-04-12"]);
    let mut query_array = session(&library_read());
    query_array["read"]["enabled"] = json!(false);
    query_array["read"]["query"] = json!(["premises","2031-04-12"]);
    for input in [envelope_array,read_array,query_array] {
        assert_invalid(&invoke(&["smart","session","--online"], &serde_json::to_vec(&input).unwrap()));
    }
}

#[test]
fn malformed_stdin_bytes_refuse_without_echo() {
    for input in [
        b"not json at all".as_slice(),
        b"{\"authorized\":true,".as_slice(),
    ] {
        let output = invoke(&["smart", "session", "--online"], input);
        assert_invalid(&output);
    }
}

/// The pre-existing token/cookie `buaa smart` input is a different contract:
/// its disabled path must keep working unchanged after `session` is added.
#[test]
fn existing_smart_read_dispatch_remains_unchanged() {
    let output = invoke(
        &["smart"],
        br#"{"service":"classrooms","enabled":false,"cookie":"synthetic-caller-cookie=9f4e","campus_id":3,"date":"2031-04-12"}"#,
    );
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["result"], "disabled");
    assert_eq!(result["network_performed"], false);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-caller-cookie"));
}
