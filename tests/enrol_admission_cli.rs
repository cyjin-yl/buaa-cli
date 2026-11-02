use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn parse(source: &str, content_type: Option<&str>) -> Value {
    let input = json!({
        "operation": "list",
        "html_base64": STANDARD.encode(source.as_bytes()),
        "content_type": content_type,
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa"))
        .arg("enrol")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["result"], "parsed");
    value["data"].clone()
}

fn reason(value: &Value) -> &str {
    value["fallback_reason"].as_str().unwrap()
}

#[test]
fn missing_mime_does_not_erase_a_confirmed_challenge() {
    let value = parse("<input name=captcha>", None);
    assert!(reason(&value).contains("challenge detected"));
    assert_eq!(value["body_withheld"], true);
    assert!(value.get("body_base64").is_none());
}

#[test]
fn malformed_charset_cannot_invent_a_confirmed_challenge() {
    let value = parse("<input name=captcha>", Some("text/html; charset=\"gbk"));
    assert!(reason(&value).contains("unreviewed"));
    assert_eq!(value["body_withheld"], true);
}

#[test]
fn credential_metadata_and_mime_parameters_do_not_escape() {
    let private = parse(
        "<meta name=csrf-token content=synthetic-private-value>",
        Some("text/html; charset=utf-8"),
    );
    assert_eq!(private["body_withheld"], true);
    assert!(private.get("body_base64").is_none());
    assert!(!private.to_string().contains("synthetic-private-value"));

    let challenge = parse(
        "<input name=captcha>",
        Some("text/html; charset=utf-8; session=synthetic-private-value"),
    );
    assert_eq!(challenge["body_withheld"], true);
    assert!(!challenge.to_string().contains("synthetic-private-value"));
    assert_eq!(challenge["content_type"], "text/html");
}

#[test]
fn late_stylesheets_keep_truncated_source_challenges_unreviewed() {
    let prefix = format!("<input name=captcha>{}", "<a></a>".repeat(1025));
    for suffix in [
        "<link rel=stylesheet rel=x href=/site.css>",
        "<!-- a=\"--><style>input{display:none}</style>",
    ] {
        let value = parse(&(prefix.clone() + suffix), Some("text/html; charset=utf-8"));
        assert!(reason(&value).contains("unreviewed"), "{value}");
        assert_eq!(value["body_withheld"], true);
    }
}

#[test]
fn hidden_popover_and_button_challenge_cues_are_not_clear() {
    for source in [
        "<div popover><input name=captcha></div>",
        "<button type=button>Solve CAPTCHA</button>",
        "<input type=button value=\"Get verification code\">",
    ] {
        let value = parse(source, Some("text/html; charset=utf-8"));
        assert!(reason(&value).contains("unreviewed"), "{value}");
        assert_eq!(value["body_withheld"], true);
    }
}

#[test]
fn visible_challenge_and_safe_quoted_parameter_keep_their_distinctions() {
    let challenge = parse("<input name=captcha>", Some("text/html; charset=utf-8"));
    assert!(reason(&challenge).contains("challenge detected"));
    let safe = "<p>ordinary server response</p>";
    let value = parse(safe, Some("text/html; note=\"a;charset=gbk\"; charset=utf-8"));
    assert_eq!(value["body_base64"], STANDARD.encode(safe));
}

#[test]
fn invalid_tag_open_cannot_hide_a_late_stylesheet() {
    let source = format!(
        "<input name=captcha>{}<<style>input{{display:none}}</style>",
        "<a></a>".repeat(1025),
    );
    let value = parse(&source, Some("text/html; charset=utf-8"));
    assert!(reason(&value).contains("unreviewed"));
    assert_eq!(value["body_withheld"], true);
}

#[test]
fn split_button_text_remains_an_unreviewed_challenge_cue() {
    for source in [
        "<button>CAP<span>TCHA</span></button>",
        "<button>验<span>证</span>码</button>",
    ] {
        let value = parse(source, Some("text/html; charset=utf-8"));
        assert!(reason(&value).contains("unreviewed"), "{value}");
        assert_eq!(value["body_withheld"], true);
    }
}

#[test]
fn other_invalid_tag_openers_cannot_hide_late_stylesheets() {
    let prefix = format!("<input name=captcha>{}", "<a></a>".repeat(1025));
    for suffix in [
        "< <style>input{display:none}</style>",
        "<0<style>input{display:none}</style>",
    ] {
        let value = parse(&(prefix.clone() + suffix), Some("text/html; charset=utf-8"));
        assert!(reason(&value).contains("unreviewed"), "{value}");
        assert_eq!(value["body_withheld"], true);
    }
}

#[test]
fn button_cues_normalize_actual_whitespace() {
    for source in [
        "<button>Verification\n  code</button>",
        "<button>Verification\tcode</button>",
    ] {
        let value = parse(source, Some("text/html; charset=utf-8"));
        assert!(reason(&value).contains("unreviewed"), "{value}");
        assert_eq!(value["body_withheld"], true);
    }
}

#[test]
fn bogus_comment_cannot_hide_a_late_stylesheet() {
    let prefix = format!("<input name=captcha>{}", "<a></a>".repeat(1025));
    for suffix in [
        "<!bogus a=\"><style>input{display:none}</style>\">",
        "<?bogus a=\"><style>input{display:none}</style>\">",
    ] {
        let value = parse(&(prefix.clone() + suffix), Some("text/html; charset=utf-8"));
        assert!(reason(&value).contains("unreviewed"), "{value}");
        assert_eq!(value["body_withheld"], true);
    }
    let control = format!("<!doctype html>{prefix}");
    assert!(reason(&parse(&control, Some("text/html; charset=utf-8"))).contains("challenge detected"));
}

#[test]
fn invalid_end_tag_cannot_hide_a_late_stylesheet() {
    let source = format!(
        "<input name=captcha>{}</0 a=\"><style>input{{display:none}}</style>\">",
        "<a></a>".repeat(1025),
    );
    let value = parse(&source, Some("text/html; charset=utf-8"));
    assert!(reason(&value).contains("unreviewed"), "{value}");
    assert_eq!(value["body_withheld"], true);
}

#[test]
fn foreign_cdata_cannot_hide_a_late_stylesheet() {
    let source = format!(
        "<input name=captcha>{}<svg><![CDATA[><fake a=\"]]></svg><style>input{{display:none}}</style>\">",
        "<a></a>".repeat(1025),
    );
    let value = parse(&source, Some("text/html; charset=utf-8"));
    assert!(reason(&value).contains("unreviewed"), "{value}");
    assert_eq!(value["body_withheld"], true);
}
