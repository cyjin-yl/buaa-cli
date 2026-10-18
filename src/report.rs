//! Agent/user self-reporting: create a GitHub Issue via the local `gh` CLI.
//! Never fabricates an Issue URL; fails closed when `gh` is unavailable.

use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

const REPO: &str = "cyjin-yl/buaa-cli";

fn unavailable() -> crate::net::Error {
    crate::net::Error::new(
        "unavailable",
        "report requires the local gh CLI to be installed and authenticated",
    )
}

fn invalid_input() -> crate::net::Error {
    crate::net::Error::new("invalid_input", "report input must be a JSON object")
}

fn gh_auth_status() -> Result<(), String> {
    let output = Command::new("gh")
        .args(["auth", "status", "-h", "github.com"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("gh CLI not found or not executable: {}", e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn gh_create_issue(title: &str, body: &str, labels: &[String]) -> Result<String, String> {
    let mut args: Vec<String> = vec![
        "issue".into(),
        "create".into(),
        "--repo".into(),
        REPO.into(),
        "--title".into(),
        title.into(),
        "--body".into(),
        body.into(),
    ];
    for l in labels {
        args.push("--label".into());
        args.push(l.clone());
    }
    let mut child = Command::new("gh")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn gh: {}", e))?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to wait for gh: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "gh issue create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(url)
}

pub fn report(input: &str) -> Result<Value, crate::net::Error> {
    let parsed: Value = serde_json::from_str(input).map_err(|_| invalid_input())?;
    if !parsed.is_object() {
        return Err(invalid_input());
    }

    // Check gh availability first
    if let Err(msg) = gh_auth_status() {
        let mut out = json!({
            "schema_version": 1,
            "type": "report",
            "result": "blocked",
            "reason": msg,
            "next_steps": [
                "Install GitHub CLI: https://cli.github.com/",
                "Run: gh auth login",
                "Then retry: buaa-cli report"
            ]
        });
        if let Some(obj) = out.as_object_mut() {
            for (k, v) in parsed.as_object().unwrap() {
                obj.insert(k.clone(), v.clone());
            }
        }
        return Ok(out);
    }

    let title = parsed
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("buaa-cli agent report")
        .to_string();
    let body = parsed
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let labels: Vec<String> = parsed
        .get("labels")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let url = gh_create_issue(&title, &body, &labels).map_err(|e| unavailable())?;

    Ok(json!({
        "schema_version": 1,
        "type": "report",
        "result": "created",
        "url": url,
        "repo": REPO,
        "title": title,
        "labels": labels
    }))
}
