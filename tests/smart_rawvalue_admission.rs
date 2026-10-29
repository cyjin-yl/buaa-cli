use base64::{Engine as _, engine::general_purpose::STANDARD};
use buaa_cli::smart;
use serde_json::Value;

fn reread(body: &str) -> Value {
    smart::reread(
        "running",
        "count",
        200,
        Some("application/json"),
        &STANDARD.encode(body.as_bytes()),
    )
    .unwrap()
}

#[test]
fn reserved_raw_value_marker_cannot_export_embedded_credentials() {
    for body in [
        r#"{"code":1,"result":{"$serde_json::private::RawValue":"{\"token\":\"synthetic-secret\"}"}}"#,
        r#"{"code":1,"result":{"$serde_json::private::Raw\u0056alue":"{\"token\":\"synthetic-secret\"}"}}"#,
    ] {
        let output = reread(body);
        assert_ne!(output["result"], "ok");
        assert!(output.get("data").is_none());
        assert!(!output.to_string().contains("synthetic-secret"));
    }
}

#[test]
fn ordinary_count_data_remains_available_offline() {
    let output = reread(r#"{"code":1,"result":{"count":2}}"#);
    assert_eq!(output["result"], "ok");
    assert_eq!(output["data"]["count"], 2);
    assert_eq!(output["source"], "operator_supplied");
    assert_eq!(output["network_performed"], false);
}
