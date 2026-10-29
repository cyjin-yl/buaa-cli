use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn page(body: &str) -> Value {
    let input = json!({"operation":"page", "date":"2026-10-29", "shifts_number":1,
        "source":{"body_base64":STANDARD.encode(body), "content_type":"text/html; charset=utf-8"}});
    let mut child = Command::new(env!("CARGO_BIN_EXE_buaa")).arg("shuttle")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn percent_encoded_csrf_never_reaches_visible_page_text() {
    for body in [
        "<body>%61%62%63%31%32%33<script>var csrf_token='abc123';</script></body>",
        "<body><span>%61%62%63</span><span>%31%32%33</span><script>var csrf_token='abc123';</script></body>",
        "<body>YWJjMTIz<script>var csrf_token='abc123';</script></body>",
    ] {
        let value = page(body);
        assert_ne!(value["status"], "ok");
        assert!(value.get("visible_page_text").is_none());
        assert!(!value.to_string().contains("%61%62%63%31%32%33"));
        assert!(!value.to_string().contains("abc123"));
    }
}

#[test]
fn ordinary_page_text_is_still_available_without_token_echo() {
    let value = page("<body>Shuttle service<script>var csrf_token='abc123';</script></body>");
    assert_eq!(value["status"], "ok");
    assert_eq!(value["visible_page_text"], "Shuttle service");
    assert!(!value.to_string().contains("abc123"));
}

#[test]
fn partially_encoded_csrf_with_literal_equals_is_withheld() {
    for (body,echo) in [
        ("<body>abc%2Fdef=<script>var csrf_token='abc/def=';</script></body>","abc%2Fdef="),
        ("<body>abc%2Bdef+ghi=<script>var csrf_token='abc+def+ghi=';</script></body>","abc%2Bdef+ghi="),
    ] {
        let value = page(body);
        assert_ne!(value["status"], "ok");
        assert!(value.get("visible_page_text").is_none());
        assert!(!value.to_string().contains(echo));
    }
}
