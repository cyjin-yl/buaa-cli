use buaa_cli::electricity::{parse_balance_fixture, parse_directory_fixture};

fn balance_html(usage: &str) -> String {
    format!(
        r#"<svg><tspan>1</tspan><tspan>2</tspan></svg><div style="float:left"><p class="shadow">R</p><p class="shadow">地址:A</p></div><table><tbody></tbody></table><script>x={{data:["d"],series:{{data:[{usage}]}}}};</script>"#
    )
}

#[test]
fn chart_object_must_not_be_reinterpreted_as_a_number() {
    let source = balance_html(r#"{"$serde_json::private::RawValue":"0"}"#);
    let output = parse_balance_fixture(source.as_bytes(), Some("text/html; charset=utf-8")).unwrap();
    assert_eq!(output["result"], "degraded");
    assert!(output["balance"].is_null());
}

#[test]
fn directory_object_id_must_not_be_reinterpreted_as_a_number() {
    let source = br#"[{"id":{"$serde_json::private::RawValue":"1"},"identityNo":"synthetic"}]"#;
    assert!(parse_directory_fixture(source, r#"{"identity_no":"synthetic"}"#).is_err());
}

#[test]
fn literal_numeric_chart_and_directory_ids_remain_usable() {
    let source = balance_html("0");
    let output = parse_balance_fixture(source.as_bytes(), Some("text/html; charset=utf-8")).unwrap();
    assert_eq!(output["result"], "parsed");
    assert_eq!(output["balance"]["history"]["usage_kwh"][0], 0);
    let row = parse_directory_fixture(
        br#"[{"id":1,"identityNo":"synthetic"}]"#,
        r#"{"identity_no":"synthetic"}"#,
    )
    .unwrap()
    .unwrap();
    assert_eq!(row["id"], "1");
}
