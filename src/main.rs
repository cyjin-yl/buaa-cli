use serde_json::{Value, json};
use std::io::{self, Read, Write};
use zeroize::Zeroize;

const MAX_INPUT: u64 = 8 * 1024 * 1024;
const MATRIX: &str = include_str!("../acceptance.json");

type CliError = (&'static str, u8, String);
type CliResult = Result<(), CliError>;

fn emit(value: &Value) -> CliResult {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value)
        .and_then(|_| out.write_all(b"\n").map_err(serde_json::Error::io))
        .map_err(|_| ("unavailable", 7, "output unavailable".into()))
}

fn read_input() -> Result<String, CliError> {
    let mut input = String::new();
    io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_string(&mut input)
        .map_err(|error| match error.kind() {
            io::ErrorKind::InvalidData => ("invalid_input", 2, "stdin must be UTF-8".into()),
            _ => ("unavailable", 7, "stdin is unavailable".into()),
        })?;
    if input.len() as u64 > MAX_INPUT {
        return Err(("invalid_input", 2, "input exceeds 8 MiB limit".into()));
    }
    Ok(input)
}

fn service_error(error: buaa_cli::net::Error) -> CliError {
    let (code, exit) = match error.code {
        "invalid_input" => ("invalid_input", 2),
        "unsupported" | "redirect_refused" | "unsupported_encoding" => ("unsupported", 3),
        "auth_latched" | "safety_latched" => ("auth_latched", 4),
        "permission" | "robots_denied" | "egress_denied" => ("permission", 5),
        "rate_limited" | "cooldown" | "request_gap" => ("rate_limited", 8),
        "conflict" | "immutable_conflict" => ("conflict", 9),
        _ => ("unavailable", 7),
    };
    (code, exit, error.message.into())
}

fn run_archive(args: &[String]) -> CliResult {
    use buaa_cli::net::{ArchiveClient, CacheMode};
    let operation = match args.first().map(String::as_str) {
        Some("lookup") => buaa_cli::archive::lookup,
        Some("capture") => buaa_cli::archive::capture,
        _ => {
            return Err((
                "unsupported",
                3,
                "expected archive lookup or capture".into(),
            ));
        }
    };
    let mode = match args.get(1).map(String::as_str) {
        None => CacheMode::Offline,
        Some("--online") if args.len() == 2 => CacheMode::PreferCache,
        Some("--refresh") if args.len() == 2 => CacheMode::Revalidate,
        _ => {
            return Err((
                "invalid_input",
                2,
                "expected at most one of --online or --refresh".into(),
            ));
        }
    };
    let input = read_input()?;
    let client = ArchiveClient::open(mode).map_err(service_error)?;
    let output = operation(&input, &client).map_err(service_error)?;
    emit(&output)
}

fn run_gateway(args: &[String]) -> CliResult {
    use buaa_cli::net::CacheMode;
    match args.first().map(String::as_str) {
        Some("usage") => {
            let mode = match args.get(1).map(String::as_str) {
                None => CacheMode::Offline,
                Some("--online") if args.len() == 2 => CacheMode::PreferCache,
                Some("--refresh") if args.len() == 2 => CacheMode::Revalidate,
                _ => {
                    return Err((
                        "invalid_input",
                        2,
                        "expected at most one of --online or --refresh".into(),
                    ));
                }
            };
            emit(&buaa_cli::gateway::usage(mode).map_err(service_error)?)
        }
        Some("resume-auth") if args.len() == 1 => {
            let input = read_input()?;
            emit(&buaa_cli::gateway::resume_auth(&input).map_err(service_error)?)
        }
        Some("login") if args.len() == 2 && args[1] == "--online" => {
            let mut input = read_input()?;
            let output = buaa_cli::gateway::login(&input).map_err(service_error);
            input.zeroize();
            emit(&output?)
        }
        Some("logout") if args.len() == 2 && args[1] == "--online" => {
            let input = read_input()?;
            emit(&buaa_cli::gateway::logout(&input).map_err(service_error)?)
        }
        Some("login" | "logout") => Err((
            "permission",
            5,
            "gateway mutation requires explicit --online and typed stdin intent".into(),
        )),
        _ => Err((
            "unsupported",
            3,
            "expected gateway usage, resume-auth, login, or logout".into(),
        )),
    }
}
fn run() -> CliResult {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| ("invalid_input", 2, "arguments must be UTF-8".into()))
        })
        .collect::<Result<_, _>>()?;
    let command = args.first().map(String::as_str).unwrap_or("help");
    match command {
        "help" | "--help" if args.len() <= 1 => emit(&json!({
            "schema_version": 1,
            "commands": ["capabilities", "schema", "timed-input [--raw] [--dry-run]", "archive lookup|capture [--online|--refresh]", "gateway usage [--online|--refresh]", "gateway resume-auth", "gateway login|logout --online"],
            "network_policy": {"default":"offline", "opt_in":"archive/gateway explicit online flags", "campus_enabled":true, "automatic_authentication_retry":false},
            "help": "timed-input reads [seconds]text lines from stdin; default output NDJSON; --raw explicitly opts into pipe-compatible text; --dry-run validates without waiting"
        })),
        "capabilities" if args.len() == 1 => {
            let matrix: Value = serde_json::from_str(MATRIX)
                .map_err(|_| ("unavailable", 7, "capability manifest invalid".into()))?;
            emit(&matrix)
        }
        "schema" if args.len() == 1 => emit(&json!({
            "schema_version": 1,
            "commands": {
                "archive": buaa_cli::archive::schema(),
                "gateway": buaa_cli::gateway::schema(),
                "timed-input": {
                    "stdin": {"format":"[seconds]text lines", "max_bytes":MAX_INPUT,
                        "seconds":"nonnegative fixed decimal; at most 9 fractional digits",
                        "order":"nondecreasing; stable for equal timestamps", "max_rows":100000, "max_seconds":86400},
                    "options":{"--raw":"explicit raw text lines, not JSON", "--dry-run":"NDJSON validated schedule without waiting; incompatible with --raw"},
                    "stdout_schema": {"$schema":"https://json-schema.org/draft/2020-12/schema",
                        "type":"object", "required":["type","sequence","at_ns","text"],
                        "properties":{"type":{"const":"timed_input"},"sequence":{"type":"integer","minimum":1},"at_ns":{"type":"integer","minimum":0,"maximum":86400000000000_u64},"text":{"type":"string"}},"additionalProperties":false}
                },
                "capabilities":{"stdout":"single JSON acceptance manifest; pending/deferred entries are not available commands"}
            },
            "errors":{"stream":"stderr","format":"JSON","fields":["schema_version","error","message"],
                "exit_codes":{"invalid_input":2,"unsupported":3,"auth_latched":4,"permission":5,"unavailable":7,"rate_limited":8,"conflict":9}},
            "network_policy":{"default":"offline","opt_in":"archive/gateway explicit online flags","campus_enabled":true,"automatic_authentication_retry":false}
        })),
        "timed-input" => {
            let mut raw = false;
            let mut dry_run = false;
            for arg in &args[1..] {
                match arg.as_str() {
                    "--raw" if !raw => raw = true,
                    "--dry-run" if !dry_run => dry_run = true,
                    _ => {
                        return Err((
                            "invalid_input",
                            2,
                            "unknown or repeated timed-input option".into(),
                        ));
                    }
                }
            }
            if raw && dry_run {
                return Err((
                    "invalid_input",
                    2,
                    "--raw and --dry-run are mutually exclusive".into(),
                ));
            }
            let input = read_input()?;
            buaa_cli::timed_input::run(&input, raw, dry_run).map_err(|error| match error {
                buaa_cli::timed_input::Error::InvalidInput(message) => {
                    ("invalid_input", 2, message)
                }
                buaa_cli::timed_input::Error::Unavailable(message) => {
                    ("unavailable", 7, message.into())
                }
            })
        }
        "archive" => run_archive(&args[1..]),
        "gateway" => run_gateway(&args[1..]),
        _ => Err((
            "unsupported",
            3,
            "command unavailable; use capabilities for tracked scope".into(),
        )),
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err((code, exit, message)) => {
            let _ = writeln!(
                io::stderr().lock(),
                "{}",
                json!({
                    "schema_version":1, "error":code, "message":message
                })
            );
            std::process::ExitCode::from(exit)
        }
    }
}
