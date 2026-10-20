//! Agent/user self-reporting: create a GitHub Issue via the local `gh` CLI.
//! Never fabricates an Issue URL; fails closed when `gh` is unavailable or its
//! writer outcome cannot be reconciled.

use serde::Deserialize;
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::io::Write;
use std::process::{Command, Stdio};

const REPO: &str = "cyjin-yl/buaa-cli";
const GH_REPO: &str = "github.com/cyjin-yl/buaa-cli";
const ISSUE_URL_PREFIX: &str = "https://github.com/cyjin-yl/buaa-cli/issues/";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportRequest {
    title: String,
    body: String,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GhAuthFailure {
    Missing,
    NotAuthenticated,
    Unavailable,
}

enum GhIssueOutcome {
    Created(String),
    Unknown,
}

fn invalid_input() -> crate::net::Error {
    crate::net::Error::new(
        "invalid_input",
        "report input must contain only title/body strings and optional string labels",
    )
}

fn gh_auth_status(command: &OsStr) -> Result<(), GhAuthFailure> {
    let output = Command::new(command)
        .args(["auth", "status", "-h", "github.com"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                GhAuthFailure::Missing
            } else {
                GhAuthFailure::Unavailable
            }
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(GhAuthFailure::NotAuthenticated)
    }
}

fn canonical_issue_url(value: &str) -> bool {
    let Some(id) = value.strip_prefix(ISSUE_URL_PREFIX) else {
        return false;
    };
    let Some(first) = id.as_bytes().first() else {
        return false;
    };
    *first != b'0' && id.bytes().all(|byte| byte.is_ascii_digit())
}

fn gh_create_issue(command: &OsStr, request: &ReportRequest) -> GhIssueOutcome {
    let mut invocation = Command::new(command);
    invocation.args([
        "issue", "create", "--repo", GH_REPO, "--title", request.title.as_str(),
        "--body-file", "-",
    ]);
    for label in &request.labels {
        invocation.args(["--label", label.as_str()]);
    }

    let mut child = match invocation
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return GhIssueOutcome::Unknown,
    };

    let body_delivered = child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(request.body.as_bytes()).is_ok())
        .unwrap_or(false);
    if !body_delivered {
        let _ = child.kill();
        let _ = child.wait();
        return GhIssueOutcome::Unknown;
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(_) => return GhIssueOutcome::Unknown,
    };
    if !output.status.success() {
        return GhIssueOutcome::Unknown;
    }

    let Ok(raw_url) = std::str::from_utf8(&output.stdout) else {
        return GhIssueOutcome::Unknown;
    };
    let url = raw_url.trim();
    if canonical_issue_url(url) {
        GhIssueOutcome::Created(url.to_owned())
    } else {
        GhIssueOutcome::Unknown
    }
}

fn blocked(failure: GhAuthFailure) -> Value {
    let (reason, next_steps) = match failure {
        GhAuthFailure::Missing => (
            "the local gh CLI is not installed or executable",
            vec![
                "Install GitHub CLI: https://cli.github.com/",
                "Run: gh auth login",
                "Then retry: buaa report",
            ],
        ),
        GhAuthFailure::NotAuthenticated => (
            "authentication for github.com could not be confirmed",
            vec![
                "Run: gh auth status -h github.com",
                "If not logged in, run: gh auth login",
                "Then retry: buaa report",
            ],
        ),
        GhAuthFailure::Unavailable => (
            "the local gh CLI could not be started",
            vec![
                "Install GitHub CLI: https://cli.github.com/",
                "Run: gh auth login",
                "Then retry: buaa report",
            ],
        ),
    };
    json!({
        "schema_version": 1,
        "type": "report",
        "result": "blocked",
        "reason": reason,
        "next_steps": next_steps
    })
}

fn unknown_outcome(request: &ReportRequest) -> Value {
    json!({
        "schema_version": 1,
        "type": "report",
        "result": "unknown_outcome",
        "url": null,
        "repo": REPO,
        "title": &request.title,
        "labels": &request.labels,
        "reconciliation": "required",
        "automatic_retry": false,
        "reason": "gh issue writer did not return a canonical Issue URL; reconcile the repository before retrying"
    })
}

fn report_with_command(input: &str, command: &OsStr) -> Result<Value, crate::net::Error> {
    let request: ReportRequest = serde_json::from_str(input).map_err(|_| invalid_input())?;

    if let Err(failure) = gh_auth_status(command) {
        return Ok(blocked(failure));
    }

    let outcome = gh_create_issue(command, &request);
    match outcome {
        GhIssueOutcome::Created(url) => Ok(json!({
            "schema_version": 1,
            "type": "report",
            "result": "created",
            "url": url,
            "repo": REPO,
            "title": request.title,
            "labels": request.labels
        })),
        GhIssueOutcome::Unknown => Ok(unknown_outcome(&request)),
    }
}

pub fn report(input: &str) -> Result<Value, crate::net::Error> {
    report_with_command(input, OsStr::new("gh"))
}

pub fn schema() -> Value {
    json!({
        "input": {
            "type":"object", "additionalProperties":false, "required":["title","body"],
            "properties": {
                "title":{"type":"string"}, "body":{"type":"string"},
                "labels":{"type":"array","items":{"type":"string"}}
            }
        },
        "output": {
            "type":"object", "required":["schema_version","type","result"],
            "properties": {
                "schema_version":{"const":1}, "type":{"const":"report"},
                "result":{"enum":["created","blocked","unknown_outcome"]},
                "url":{"type":["string","null"],"pattern":"^https://github[.]com/cyjin-yl/buaa-cli/issues/[1-9][0-9]*$"},
                "reason":{"type":"string"},
                "next_steps":{"type":"array","items":{"type":"string"}}
            },
            "allOf":[
                {"if":{"properties":{"result":{"const":"created"}}},"then":{"required":["url"],"properties":{"url":{"type":"string"}}}},
                {"if":{"properties":{"result":{"const":"blocked"}}},"then":{"required":["reason","next_steps"]}},
                {"if":{"properties":{"result":{"const":"unknown_outcome"}}},"then":{"required":["url","reconciliation","automatic_retry"],"properties":{"url":{"const":null},"reconciliation":{"const":"required"},"automatic_retry":{"const":false}}}}
            ]
        },
        "description":"Explicit sanitized GitHub Issue write through gh. Blocked or uncertain results are not created Issues; reconcile unknown outcomes before retrying. Body is delivered via stdin, never argv."
    })
}

#[cfg(test)]
mod tests {
    use super::{canonical_issue_url, report_with_command};
    use serde_json::Value;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "buaa-report-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            Self { root }
        }

        fn command(&self, script: &str) -> PathBuf {
            let path = self.root.join("gh");
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn valid_input() -> &'static str {
        r#"{"title":"synthetic report","body":"synthetic body","labels":["fallback"]}"#
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn malformed_or_spoofed_input_is_rejected_before_any_gh_call() {
        let fixture = Fixture::new();
        let marker = fixture.path("called");
        let command = fixture.command(&format!(
            "#!/bin/sh\nprintf called > '{}'\n",
            marker.display()
        ));
        let error = report_with_command(
            r#"{"title":"ok","body":"body","result":"created","url":"https://github.com/cyjin-yl/buaa-cli/issues/7"}"#,
            command.as_os_str(),
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_input");
        assert!(!marker.exists());

        let error = report_with_command(
            r#"{"title":"ok","body":"body","labels":[7]}"#,
            command.as_os_str(),
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_input");
        assert!(!marker.exists());
    }

    #[test]
    fn missing_gh_and_logged_out_gh_keep_distinct_sanitized_guidance() {
        let fixture = Fixture::new();
        let missing = fixture.path("not-installed");
        let blocked = report_with_command(valid_input(), missing.as_os_str()).unwrap();
        assert_eq!(blocked["result"], "blocked");
        assert!(blocked["next_steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step == "Install GitHub CLI: https://cli.github.com/"));

        let logged_out = fixture.command(
            "#!/bin/sh\nprintf '%s' 'synthetic-auth-secret' >&2\nexit 1\n",
        );
        let blocked = report_with_command(valid_input(), logged_out.as_os_str()).unwrap();
        assert_eq!(blocked["result"], "blocked");
        assert!(!blocked.to_string().contains("synthetic-auth-secret"));
        assert!(blocked["next_steps"].as_array().unwrap().iter().any(|step| {
            step.as_str().is_some_and(|value| value.contains("gh auth login"))
        }));
    }

    #[test]
    fn issue_body_is_delivered_on_stdin_and_not_in_writer_arguments() {
        let fixture = Fixture::new();
        let args = fixture.path("args");
        let body = fixture.path("body");
        let command = fixture.command(&format!(
            "#!/bin/sh\nif [ \"$1\" = auth ]; then exit 0; fi\nprintf '%s\\n' \"$@\" > '{}'\ncat > '{}'\nprintf '%s\\n' 'https://github.com/cyjin-yl/buaa-cli/issues/42'\n",
            args.display(),
            body.display()
        ));
        let output = report_with_command(
            r#"{"title":"synthetic title","body":"body-via-stdin\nsecond line","labels":["fallback","agent-report"]}"#,
            command.as_os_str(),
        )
        .unwrap();
        assert_eq!(output["result"], "created");
        assert_eq!(output["url"], "https://github.com/cyjin-yl/buaa-cli/issues/42");
        let args = read(&args);
        assert!(args.contains("--body-file\n-\n"));
        assert!(!args.contains("body-via-stdin"));
        assert_eq!(read(&body), "body-via-stdin\nsecond line");
    }

    #[test]
    fn invalid_or_uncertain_writer_outcome_requires_reconciliation_without_retry() {
        let fixture = Fixture::new();
        let command = fixture.command(
            "#!/bin/sh\nif [ \"$1\" = auth ]; then exit 0; fi\nprintf '%s' 'https://example.invalid/not-an-issue'\n",
        );
        let output = report_with_command(valid_input(), command.as_os_str()).unwrap();
        assert_eq!(output["result"], "unknown_outcome");
        assert_eq!(output["url"], Value::Null);
        assert_eq!(output["reconciliation"], "required");
        assert_eq!(output["automatic_retry"], false);

        let command = fixture.command(
            "#!/bin/sh\nif [ \"$1\" = auth ]; then exit 0; fi\nprintf '%s' 'synthetic-writer-secret' >&2\nexit 1\n",
        );
        let output = report_with_command(valid_input(), command.as_os_str()).unwrap();
        assert_eq!(output["result"], "unknown_outcome");
        assert_eq!(output["automatic_retry"], false);
        assert!(!output.to_string().contains("synthetic-writer-secret"));
    }

    #[test]
    fn canonical_issue_url_requires_a_positive_numeric_id() {
        assert!(canonical_issue_url(
            "https://github.com/cyjin-yl/buaa-cli/issues/1"
        ));
        assert!(!canonical_issue_url(
            "https://github.com/cyjin-yl/buaa-cli/issues/0"
        ));
        assert!(!canonical_issue_url(
            "https://github.com/cyjin-yl/buaa-cli/issues/01"
        ));
        assert!(!canonical_issue_url(
            "https://github.com/cyjin-yl/buaa-cli/issues/1?spoof=1"
        ));
        assert!(!canonical_issue_url(
            "https://github.com/other/repo/issues/1"
        ));
    }
}
