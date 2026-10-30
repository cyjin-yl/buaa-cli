use serde_json::{Value, json};
use std::io::{self, Read, Write};
use zeroize::{Zeroize, Zeroizing};

const MAX_INPUT: u64 = 8 * 1024 * 1024;
const MATRIX: &str = include_str!("../acceptance.json");
const NETWORK_OPT_IN: &str = "Network-capable reads and authentication require --online or --refresh where supported; contribution scan requires online:true on stdin. Report may invoke an authenticated GitHub Issue writer. See each command schema for operation-specific gates.";

type CliError = (&'static str, u8, String);
type CliResult = Result<(), CliError>;

/// The recordings capability schema plus the live-stream sub-capability.
fn recordings_schema() -> Value {
    let mut schema = buaa_cli::recordings::schema();
    schema["live"] = buaa_cli::recordings::live::schema();
    schema
}

fn emit(value: &Value) -> CliResult {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value)
        .and_then(|_| out.write_all(b"\n").map_err(serde_json::Error::io))
        .map_err(|_| ("unavailable", 7, "output unavailable".into()))
}

fn read_input() -> Result<String, CliError> {
    let mut input = Zeroizing::new(Vec::new());
    io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut input)
        .map_err(|error| match error.kind() {
            io::ErrorKind::InvalidData => ("invalid_input", 2, "stdin must be UTF-8".into()),
            _ => ("unavailable", 7, "stdin is unavailable".into()),
        })?;
    if input.len() as u64 > MAX_INPUT {
        return Err(("invalid_input", 2, "input exceeds 8 MiB limit".into()));
    }
    match String::from_utf8(std::mem::take(&mut *input)) {
        Ok(text) => Ok(text),
        Err(error) => {
            let _invalid_bytes = Zeroizing::new(error.into_bytes());
            Err(("invalid_input", 2, "stdin must be UTF-8".into()))
        }
    }
}

/// Read stdin only when data is actually piped; interactive terminals fall
/// back to module defaults so `announcements list` never blocks a TTY.
fn read_input_optional() -> Result<Option<String>, CliError> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return Ok(None);
    }
    Ok(Some(read_input()?))
}

fn service_error(error: buaa_cli::net::Error) -> CliError {
    let (code, exit) = match error.code {
        "invalid_input" => ("invalid_input", 2),
        "unsupported" | "redirect_refused" | "unsupported_encoding" => ("unsupported", 3),
        "auth_latched" | "safety_latched" => ("auth_latched", 4),
        "scoped_cookie_unusable" => ("scoped_cookie_unusable", 7),
        "authorization_required" => ("authorization_required", 4),
        "permission" | "robots_denied" | "egress_denied" => ("permission", 5),
        "rate_limited" | "cooldown" | "request_gap" => ("rate_limited", 8),
        "unknown_outcome" => ("unknown_outcome", 9),
        "conflict" | "immutable_conflict" => ("conflict", 9),
        _ => ("unavailable", 7),
    };
    let message = match error.source {
        Some(source) => format!(
            "{} [src_file={} src_line={} invariant={}]",
            error.message, source.file, source.line, source.invariant,
        ),
        None => error.message.into(),
    };
    (code, exit, message)
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

fn marks_value(value: &Value) -> (&'static str, u8) {
    match value.get("error").and_then(serde_json::Value::as_str) {
        Some("invalid_input") => ("invalid_input", 2),
        Some("permission") => ("permission", 5),
        Some("unavailable") => ("unavailable", 7),
        _ => ("unavailable", 7),
    }
}

fn run_marks(args: &[String]) -> CliResult {
    let operation = args.first().map(String::as_str);
    let subcommand = args.get(1).map(String::as_str);
    let path = args.get(2).map(String::as_str);
    let value = match (operation, subcommand) {
        (Some("gpa"), None) if args.len() == 1 => {
            let input = read_input()?;
            buaa_cli::marks::gpa(&input)
        }
        (Some("baseline"), Some("save")) if args.len() == 3 => {
            let input = read_input()?;
            buaa_cli::marks::baseline_save(&input, path.unwrap())
        }
        (Some("baseline"), Some("show")) if args.len() == 3 => {
            buaa_cli::marks::baseline_show(path.unwrap())
        }
        _ => {
            return Err((
                "unsupported",
                3,
                "expected marks gpa or marks baseline save|show <absolute-path>".into(),
            ));
        }
    };
    if value.get("error").is_some() {
        let (code, exit) = marks_value(&value);
        let message = value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("marks failed")
            .to_string();
        return Err((code, exit, message));
    }
    emit(&value)
}

fn run_fengrubei(args: &[String]) -> CliResult {
    match args.first().map(String::as_str) {
        Some("info") if args.len() == 1 => emit(&buaa_cli::fengrubei::info()),
        Some("fetch") => {
            let online = match args.get(1).map(String::as_str) {
                None => false,
                Some("--online") if args.len() == 2 => true,
                _ => return Err(("invalid_input", 2, "expected at most --online".into())),
            };
            let input = read_input()?;
            let output = buaa_cli::fengrubei::fetch(&input, online).map_err(service_error)?;
            emit(&output)
        }
        _ => Err(("unsupported", 3, "expected fengrubei info or fetch".into())),
    }
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
        Some("logout-plan") if args.len() == 1 => {
            let input = read_input()?;
            emit(&buaa_cli::gateway::plan_logout(&input).map_err(service_error)?)
        }
        Some("logout-recovery-plan") if args.len() == 1 => {
            let input = read_input()?;
            emit(&buaa_cli::gateway::plan_logout_recovery(&input).map_err(service_error)?)
        }
        Some("logout-commit") if args.len() == 2 && args[1] == "--online" => {
            let input = read_input()?;
            emit(&buaa_cli::gateway::commit_logout(&input).map_err(service_error)?)
        }
        Some("logout-recovery-commit") if args.len() == 2 && args[1] == "--offline" => {
            let input = read_input()?;
            emit(&buaa_cli::gateway::resolve_logout_recovery(&input).map_err(service_error)?)
        }
        Some("login" | "logout-commit") => Err((
            "permission",
            5,
            "gateway mutation requires its prerequisite, explicit --online, and typed stdin intent"
                .into(),
        )),
        Some("logout-recovery-commit") => Err((
            "permission",
            5,
            "logout recovery is local-only and requires --offline with typed stdin intent".into(),
        )),
        _ => Err((
            "unsupported",
            3,
            "expected gateway usage, resume-auth, login, logout-plan, logout-commit, logout-recovery-plan, or logout-recovery-commit --offline".into(),
        )),
    }
}

fn run_governor(args: &[String]) -> CliResult {
    match args.first().map(String::as_str) {
        Some("boot-review-plan") if args.len() == 1 => {
            emit(&buaa_cli::governor::boot_review_plan().map_err(service_error)?)
        }
        Some("boot-review-commit") if args.len() == 2 && args[1] == "--offline" => {
            let input = read_input()?;
            emit(&buaa_cli::governor::boot_review_commit(&input).map_err(service_error)?)
        }
        Some("boot-review-commit") => Err((
            "permission",
            5,
            "boot review commit requires --offline and exact typed stdin intent".into(),
        )),
        _ => Err((
            "unsupported",
            3,
            "expected governor boot-review-plan or boot-review-commit --offline".into(),
        )),
    }
}

fn run_organizations(args: &[String]) -> CliResult {
    use buaa_cli::net::CacheMode;
    if args.first().map(String::as_str) != Some("list") {
        return Err(("unsupported", 3, "expected organizations list".into()));
    }
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
    let output = buaa_cli::organizations::list(mode).map_err(service_error)?;
    emit(&output)
}

fn run_spoc(args: &[String]) -> CliResult {
    use buaa_cli::net::CacheMode;
    let operation = match args.first().map(String::as_str) {
        Some("surface") => "surface",
        Some("script") => "script",
        _ => return Err(("unsupported", 3, "expected spoc surface or script".into())),
    };
    let (page, flags) = match (operation, args.get(1).map(String::as_str)) {
        ("surface", Some(page @ ("root" | "entry"))) => (Some(page), &args[1..]),
        _ => (None, args),
    };
    let mode = match flags.get(1).map(String::as_str) {
        None => CacheMode::Offline,
        Some("--online") if flags.len() == 2 => CacheMode::PreferCache,
        Some("--refresh") if flags.len() == 2 => CacheMode::Revalidate,
        _ => {
            return Err((
                "invalid_input",
                2,
                "expected at most one of --online or --refresh".into(),
            ));
        }
    };
    let output = if operation == "surface" {
        buaa_cli::spoc::surface(mode, page)
    } else {
        buaa_cli::spoc::script(mode, &read_input()?)
    }
    .map_err(service_error)?;
    emit(&output)
}

fn run_departments(args: &[String]) -> CliResult {
    let operation = match args.first().map(String::as_str) {
        Some("inventory") => "inventory",
        Some("retrieve") => "retrieve",
        _ => {
            return Err((
                "unsupported",
                3,
                "expected departments inventory or retrieve".into(),
            ));
        }
    };
    let online = match args.get(1).map(String::as_str) {
        None => false,
        Some("--online") if args.len() == 2 => true,
        _ => {
            return Err((
                "invalid_input",
                2,
                "expected at most one of --online".into(),
            ));
        }
    };
    let input = Zeroizing::new(read_input()?);
    let output = if operation == "inventory" {
        buaa_cli::departments::inventory(&input, online)
    } else {
        buaa_cli::departments::retrieve(&input, online)
    }
    .map_err(service_error)?;
    emit(&output)
}

/// Shared dispatcher for the JSON-input capability modules: the module reads
/// one JSON object from standard input and returns its structured output.
fn run_json_module(
    args: &[String],
    entry: fn(&str, bool) -> Result<serde_json::Value, buaa_cli::net::Error>,
) -> CliResult {
    let online = match args.first().map(String::as_str) {
        None => false,
        Some("--online") if args.len() == 1 => true,
        _ => {
            return Err((
                "invalid_input",
                2,
                "expected at most one of --online".into(),
            ));
        }
    };
    let input = Zeroizing::new(read_input()?);
    let output = entry(input.as_str(), online).map_err(service_error)?;
    emit(&output)
}

fn run_announcements(args: &[String]) -> CliResult {
    use buaa_cli::net::CacheMode;
    let mode = |args: &[String]| -> Result<CacheMode, CliError> {
        match args.get(1).map(String::as_str) {
            None => Ok(CacheMode::Offline),
            Some("--online") if args.len() == 2 => Ok(CacheMode::PreferCache),
            Some("--refresh") if args.len() == 2 => Ok(CacheMode::Revalidate),
            _ => Err((
                "invalid_input",
                2,
                "expected at most one of --online or --refresh".into(),
            )),
        }
    };
    match args.first().map(String::as_str) {
        Some("list") => {
            let mode = mode(args)?;
            let input = read_input_optional()?;
            let output = buaa_cli::announcements::list(mode, input.as_deref())
                .map_err(service_error)?;
            emit(&output)
        }
        Some("article") => {
            let mode = mode(args)?;
            let input = read_input()?;
            let output =
                buaa_cli::announcements::article(mode, &input).map_err(service_error)?;
            emit(&output)
        }
        Some("document") => {
            let mode = mode(args)?;
            let input = read_input()?;
            let output = buaa_cli::announcements::document(mode, &input).map_err(service_error)?;
            emit(&output)
        }
        Some("college-source") if matches!(args.get(1).map(String::as_str), Some("scse" | "ic" | "aviation" | "beijing" | "shenyuan" | "h3i" | "iai" | "hss" | "bme" | "ygy" | "cst" | "dept3" | "ee" | "zfai" | "iiif" | "mse" | "rse" | "sepe" | "math" | "soft" | "transportation" | "physics" | "sce" | "sse" | "sem" | "fld" | "me" | "wrj" | "yqgdxy" | "ase" | "sa")) => {
            let (page, flags) = match args.get(2).map(String::as_str) {
                Some("root" | "notices" | "public-notices") => (args[2].as_str(), &args[2..]),
                _ => ("root", &args[1..]),
            };
            let mode = mode(flags).map_err(|(code, exit, _)| {
                (code, exit, "expected college-source category root|notices|public-notices (default root), optionally followed by one of --online or --refresh".into())
            })?;
            let output = buaa_cli::announcements::college_surface(mode, &args[1], page)
                .map_err(service_error)?;
            emit(&output)
        }
        Some("history") if args.len() == 1 => {
            let input = read_input()?;
            let output = buaa_cli::announcements::history(&input).map_err(service_error)?;
            emit(&output)
        }
        _ => Err((
            "unsupported",
            3,
            "expected announcements list|article|document [--online|--refresh], announcements college-source <college> (including fld) [root|notices|public-notices] [--online|--refresh], or announcements history".into(),
        )),
    }
}
fn run_credits(args: &[String]) -> CliResult {
    if args.len() != 1
        || !matches!(
            args.first().map(String::as_str),
            Some("calculate" | "school6")
        )
    {
        return Err((
            "unsupported",
            3,
            "expected credits calculate or credits school6".into(),
        ));
    }
    let input = read_input()?;
    let output = if args[0] == "school6" {
        buaa_cli::credits::school6::calculate(&input)
    } else {
        buaa_cli::credits::calculate(&input)
    };
    if let Some(raw) = output.get("error").and_then(|v| v.as_str()) {
        let code = match raw {
            "invalid_input" => "invalid_input",
            _ => "unavailable",
        };
        let exit = match code {
            "invalid_input" => 2,
            _ => 7,
        };
        let message = output
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("credits failed")
            .to_string();
        return Err((code, exit, message));
    }
    emit(&output)
}

/// Parse the optional `--online` flag that follows a sub-action.
fn online_flag(args: &[String]) -> Result<bool, CliError> {
    match args.first().map(String::as_str) {
        None => Ok(false),
        Some("--online") if args.len() == 1 => Ok(true),
        _ => Err(("invalid_input", 2, "expected at most one of --online".into())),
    }
}

fn run_ihome(args: &[String]) -> CliResult {
    let operation = match args.first().map(String::as_str) {
        Some(operation @ ("list" | "detail")) => operation,
        _ => return Err(("unsupported", 3, "expected ihome list or detail".into())),
    };
    let online = online_flag(&args[1..])?;
    let input = Zeroizing::new(read_input()?);
    let output = if operation == "list" {
        buaa_cli::ihome::list(&input, online)
    } else {
        buaa_cli::ihome::detail(&input, online)
    }
    .map_err(service_error)?;
    emit(&output)
}

fn run_welearn(args: &[String]) -> CliResult {
    let operation = match args.first().map(String::as_str) {
        Some(operation @ ("materials" | "search" | "fetch" | "practice")) => operation,
        _ => {
            return Err((
                "unsupported",
                3,
                "expected welearn materials, search, fetch or practice".into(),
            ));
        }
    };
    let online = online_flag(&args[1..])?;
    let input = read_input()?;
    let output = match operation {
        "materials" => buaa_cli::welearn::materials(&input, online),
        "search" => buaa_cli::welearn::search(&input, online),
        "fetch" => buaa_cli::welearn::fetch(&input, online),
        _ => buaa_cli::welearn::practice(&input),
    }
    .map_err(service_error)?;
    emit(&output)
}

fn run_aerospace(args: &[String]) -> CliResult {
    let operation = match args.first().map(String::as_str) {
        Some(operation @ ("materials" | "search" | "fetch" | "practice")) => operation,
        _ => {
            return Err((
                "unsupported",
                3,
                "expected aerospace materials, search, fetch or practice".into(),
            ));
        }
    };
    let online = online_flag(&args[1..])?;
    let input = read_input()?;
    let output = match operation {
        "materials" => buaa_cli::aerospace::materials(&input, online),
        "search" => buaa_cli::aerospace::search(&input, online),
        "fetch" => buaa_cli::aerospace::fetch(&input, online),
        _ => buaa_cli::aerospace::practice(&input),
    }
    .map_err(service_error)?;
    emit(&output)
}

fn json_input(input: &str) -> Result<Value, CliError> {
    serde_json::from_str(input).map_err(|_| ("invalid_input", 2, "expected JSON input".to_string()))
}

fn json_text(value: &Value, key: &str) -> String {
            value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn run_os_lab(args: &[String]) -> CliResult {
    let operation = match args.first().map(String::as_str) {
        Some(operation @ ("read" | "plan")) => operation,
        _ => return Err(("unsupported", 3, "expected os-lab read or plan".into())),
    };
    let online = online_flag(&args[1..])?;
    if operation == "read" && !online {
        return Err(("invalid_input", 2, "os-lab read requires --online".into()));
    }
    let input = Zeroizing::new(read_input()?);
    let output = if operation == "read" {
        buaa_cli::os_lab::read_stdin(&input, online)
    } else {
        buaa_cli::os_lab::connection_plan(input.as_str())
    }
    .map_err(service_error)?;
    emit(&output)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CoursegradingStatusInput {
    #[serde(deserialize_with = "zeroizing_string")]
    body_base64: Zeroizing<String>,
    #[serde(default, deserialize_with = "optional_zeroizing_string")]
    content_type: Option<Zeroizing<String>>,
}

fn zeroizing_string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Zeroizing<String>, D::Error> {
    <String as serde::Deserialize>::deserialize(deserializer).map(Zeroizing::new)
}

fn optional_zeroizing_string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Zeroizing<String>>, D::Error> {
    <Option<String> as serde::Deserialize>::deserialize(deserializer).map(|value|value.map(Zeroizing::new))
}

fn run_coursegrading(args: &[String]) -> CliResult {
    let operation = match args.first().map(String::as_str) {
        Some(operation @ ("unsupported" | "probe-https" | "preview" | "status")) => operation,
        _ => {
            return Err((
                "unsupported",
                3,
                "expected coursegrading unsupported, probe-https, preview or status".into(),
            ));
        }
    };
    let online = online_flag(&args[1..])?;
    let output = match operation {
        "unsupported" => buaa_cli::coursegrading::unsupported(),
        "probe-https" => {
            if !online {
                return Err((
                    "invalid_input",
                    2,
                    "the HTTPS probe requires --online".into(),
                ));
            }
            buaa_cli::coursegrading::probe_https(online).map_err(service_error)?
        }
        "preview" => {
            let input = read_input()?;
            let value = json_input(&input)?;
            let path = std::path::PathBuf::from(json_text(&value, "local_file"));
            let preview = buaa_cli::coursegrading::preview(
                &json_text(&value, "course_id"),
                &json_text(&value, "assignment_id"),
                &json_text(&value, "problem_id"),
                &path,
            )
            .map_err(service_error)?;
            serde_json::to_value(preview)
                .map_err(|_| ("unavailable", 7, "preview serialization failed".into()))?
        }
        _ => {
            let input = Zeroizing::new(read_input()?);
            if !input.trim_start_matches([' ', '\t', '\r', '\n']).starts_with('{') {
                return Err(("invalid_input", 2, "coursegrading status requires a JSON object".into()));
            }
            let value: CoursegradingStatusInput = serde_json::from_str(input.as_str())
                .map_err(|_| ("invalid_input", 2, "invalid coursegrading status input".into()))?;
            let bytes = Zeroizing::new(base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                value.body_base64.as_str(),
            )
            .map_err(|_| ("invalid_input", 2, "body_base64 must be base64".to_string()))?);
            buaa_cli::coursegrading::parse_status(
                &bytes,
                value.content_type.as_ref().map(|value|value.as_str()),
            )
        }
    };
    emit(&output)
}

// Build the growing command map outside json! to avoid recursive macro depth.
fn command_schemas() -> Value {
    let commands: serde_json::Map<String, Value> = [
        ("archive", buaa_cli::archive::schema()),
        ("marks", buaa_cli::marks::schema()),
        ("fengrubei", buaa_cli::fengrubei::schema()),
        ("gateway", buaa_cli::gateway::schema()),
        ("governor", buaa_cli::governor::boot_review_schema()),
        ("recordings", recordings_schema()),
        ("report", buaa_cli::report::schema()),
        ("organizations", buaa_cli::organizations::schema()),
        ("spoc", buaa_cli::spoc::schema()),
        ("announcements", buaa_cli::announcements::schema()),
        ("credits", buaa_cli::credits::schema()),
        ("drift", buaa_cli::drift::schema()),
        ("timetable", buaa_cli::timetable::schema()),
        ("timetable-pg", buaa_cli::timetable_pg::schema()),
        ("departments", buaa_cli::departments::schema()),
        ("contribution", buaa_cli::contribution::schema()),
        ("smart", buaa_cli::smart::schema()),
        ("ihome", buaa_cli::ihome::schema()),
        ("welearn", buaa_cli::welearn::schema()),
        ("aerospace", buaa_cli::aerospace::schema()),
        ("electricity", buaa_cli::electricity::schema()),
        ("enrol", buaa_cli::enrol::schema()),
        ("evaluation", buaa_cli::evaluation::schema()),
        ("checkin", buaa_cli::checkin::schema()),
        ("boya", buaa_cli::boya::schema()),
        ("drive", buaa_cli::drive::schema()),
        ("shuttle", buaa_cli::shuttle::schema()),
        ("os-lab", buaa_cli::os_lab::schema()),
        ("coursegrading", buaa_cli::coursegrading::schema()),
        ("physics", buaa_cli::physics::schema()),
        ("physics-experiment", buaa_cli::physics_experiment::schema()),
        ("timed-input", json!({
                    "stdin": {"format":"[seconds]text lines", "max_bytes":MAX_INPUT,
                        "seconds":"nonnegative fixed decimal; at most 9 fractional digits",
                        "order":"nondecreasing; stable for equal timestamps", "max_rows":100000, "max_seconds":86400},
                    "options":{"--raw":"explicit raw text lines, not JSON", "--dry-run":"NDJSON validated schedule without waiting; incompatible with --raw"},
                    "stdout_schema": {"$schema":"https://json-schema.org/draft/2020-12/schema",
                        "type":"object", "required":["type","sequence","at_ns","text"],
                        "properties":{"type":{"const":"timed_input"},"sequence":{"type":"integer","minimum":1},"at_ns":{"type":"integer","minimum":0,"maximum":86400000000000_u64},"text":{"type":"string"}},"additionalProperties":false}
                })),
        ("capabilities", json!({"stdout":"single JSON acceptance manifest; pending/deferred entries are incomplete capabilities and may expose partial or blocked commands"})),
    ]
    .into_iter()
    .map(|(name, schema)| (name.to_owned(), schema))
    .collect();
    Value::Object(commands)
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
            "commands": ["capabilities", "schema", "timed-input [--raw] [--dry-run]", "archive lookup|capture [--online|--refresh]", "organizations list [--online|--refresh]", "departments inventory|retrieve [--online]", "contribution scan", "timetable-pg parse", "smart [--online]", "ihome list|detail [--online]", "welearn materials|search|fetch|practice [--online]", "aerospace materials|search|fetch|practice [--online]", "enrol [--online]", "evaluation [--online]", "checkin [--online]", "boya [--online]", "drive [--online]", "shuttle [--online]", "electricity [--online]", "os-lab read|plan [--online]", "coursegrading unsupported|probe-https|preview|status [--online]", "physics-experiment [--online]", "announcements list [--online|--refresh]", "announcements article [--online|--refresh]", "announcements history", "announcements document [--online|--refresh]", "announcements college-source scse|ic|beijing|shenyuan|h3i|iai|hss|bme|ygy|cst|dept3|ee|zfai|iiif|mse|sepe|math|soft|transportation|physics|sce|sse|sem|fld|me|wrj|yqgdxy|ase [root|notices] [--online|--refresh]", "announcements college-source aviation [root|notices|public-notices] [--online|--refresh]", "announcements college-source rse|sa [root] [--online|--refresh]", "marks gpa", "marks baseline save|show <absolute-path>", "fengrubei info|fetch [--online]", "gateway usage [--online|--refresh]", "gateway resume-auth", "gateway login --online", "gateway logout-plan", "gateway logout-commit --online", "gateway logout-recovery-plan", "gateway logout-recovery-commit --offline", "recordings search", "recordings replay", "recordings session --offline|--online", "recordings session inspect --online", "recordings session diagnose --online", "recordings media --online", "recordings subtitles [--online|--refresh]", "recordings subtitles export", "report", "credits calculate|school6", "spoc surface [root|entry] [--online|--refresh]", "spoc script [--online|--refresh]", "drift check", "timetable ics", "physics pendulum|fit|type-a"],
            "network_policy": {"default":"offline", "opt_in":NETWORK_OPT_IN, "campus_account_enabled":true, "automatic_authentication_retry":false,"public_official_directory_enabled":true},
            "help": "recordings subtitles export reads authorized caller-supplied normalized segments, srt/vtt format and absolute new output path from JSON stdin; it is offline and does not verify source, rights or native track association. timed-input reads [seconds]text lines from stdin; default output NDJSON; --raw explicitly opts into pipe-compatible text; --dry-run validates without waiting. 'recordings session --offline' with intent 'RESUME CLASSROOM AUTH' validates durable governor state without sending a request; 'recordings session diagnose --online' submits no credential. Authentication attempts are always admitted — no latch requires clearing; challenges and HTTP 401/403 are reported per request."
        })),
        "capabilities" if args.len() == 1 => {
            let matrix: Value = serde_json::from_str(MATRIX)
                .map_err(|_| ("unavailable", 7, "capability manifest invalid".into()))?;
            emit(&matrix)
        }
        "schema" if args.len() == 1 => emit(&json!({
            "schema_version": 1,
            "commands": command_schemas(),
            "errors":{"stream":"stderr","format":"JSON","fields":["schema_version","error","message"],
            "exit_codes":{"invalid_input":2,"unsupported":3,"auth_latched":4,"authorization_required":4,"permission":5,"unavailable":7,"scoped_cookie_unusable":7,"rate_limited":8,"conflict":9,"unknown_outcome":9}},
            "network_policy":{"default":"offline","opt_in":NETWORK_OPT_IN,"campus_account_enabled":true,"automatic_authentication_retry":false,"public_official_directory_enabled":true}
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
        "credits" => run_credits(&args[1..]),
        "marks" => run_marks(&args[1..]),
        "fengrubei" => run_fengrubei(&args[1..]),
        "gateway" => run_gateway(&args[1..]),
        "governor" => run_governor(&args[1..]),
        "report" if args.len() == 1 => {
            let input = read_input()?;
            let output = buaa_cli::report::report(&input).map_err(service_error)?;
            emit(&output)
        }
        "recordings" if args.len() == 2 && args[1] == "search" => {
            let input = read_input()?;
            let output = buaa_cli::recordings::search(&input).map_err(service_error)?;
            emit(&output)
        }
        "recordings" if args.len() == 2 && args[1] == "replay" => {
            let mut input = read_input()?;
            let output = buaa_cli::recordings::replay::replay(&input);
            input.zeroize();
            emit(&output.map_err(service_error)?)
        }
        "recordings"
            if args.len() == 4
                && args[1] == "session"
                && args[2] == "inspect"
                && args[3] == "--online" =>
        {
            let mut input = read_input()?;
            let output = buaa_cli::recordings::session::inspect(&input);
            input.zeroize();
            emit(&output.map_err(service_error)?)
        }
        "recordings"
            if args.len() == 4
                && args[1] == "session"
                && args[2] == "diagnose"
                && args[3] == "--online" =>
        {
            let mut input = read_input()?;
            let output = buaa_cli::recordings::session::diagnose(&input);
            input.zeroize();
            emit(&output.map_err(service_error)?)
        }
        "recordings"
            if args.len() == 3
                && args[1] == "session"
                && matches!(args[2].as_str(), "--offline" | "--online") =>
        {
            let mut input = read_input()?;
            let output = match args[2].as_str() {
                "--online" => buaa_cli::recordings::session::login(&input),
                _ => buaa_cli::recordings::session::resume(&input),
            };
            input.zeroize();
            emit(&output.map_err(service_error)?)
        }
        "recordings" if args.len() == 2 && args[1] == "session" => Err((
            "invalid_input",
            2,
            "recordings session requires --offline to validate governor state or --online to run it".into(),
        )),
        "recordings" if args.len() == 3 && args[1] == "media" && args[2] == "--online" => {
            let mut input = read_input()?;
            let output = buaa_cli::recordings::media::online(&input);
            input.zeroize();
            emit(&output.map_err(service_error)?)
        }
        "recordings" if args.len() == 2 && args[1] == "media" => Err((
            "invalid_input",
            2,
            "recordings media requires --online with authorized JSON on stdin".into(),
        )),
        "recordings" if args.len() == 3 && args[1] == "subtitles" && args[2] == "export" => {
            let mut input = read_input()?;
            let output = buaa_cli::recordings::subtitles::export(&input);
            input.zeroize();
            emit(&output.map_err(service_error)?)
        }
        "recordings"
            if args.get(1).map(String::as_str) == Some("subtitles")
                && (args.len() == 2
                    || (args.len() == 3
                        && matches!(args[2].as_str(), "--online" | "--refresh"))) =>
        {
            let mut input = read_input()?;
            let output = match args.get(2).map(String::as_str) {
                Some("--online") => buaa_cli::recordings::subtitles::online(
                    buaa_cli::net::CacheMode::PreferCache,
                    &input,
                ),
                Some("--refresh") => buaa_cli::recordings::subtitles::online(
                    buaa_cli::net::CacheMode::Revalidate,
                    &input,
                ),
                _ => buaa_cli::recordings::subtitles::import(&input),
            };
            input.zeroize();
            emit(&output.map_err(service_error)?)
        }
        "organizations" => run_organizations(&args[1..]),
        "departments" => run_departments(&args[1..]),
        "smart" => run_json_module(&args[1..], buaa_cli::smart::read),
        "ihome" => run_ihome(&args[1..]),
        "welearn" => run_welearn(&args[1..]),
        "aerospace" => run_aerospace(&args[1..]),
        "os-lab" => run_os_lab(&args[1..]),
        "coursegrading" => run_coursegrading(&args[1..]),
        "enrol" => run_json_module(&args[1..], buaa_cli::enrol::run),
        "evaluation" => {
            let online = online_flag(&args[1..])?;
            let input = Zeroizing::new(read_input()?);
            let output = buaa_cli::evaluation::run(&input, online).map_err(|error| {
                let message = match &error {
                    buaa_cli::evaluation::Error::Invalid(reason) => reason.to_string(),
                    buaa_cli::evaluation::Error::Unsupported(reason) => reason.to_string(),
                    buaa_cli::evaluation::Error::Local(reason) => reason.clone(),
                    buaa_cli::evaluation::Error::Remote(evidence) => {
                        format!("remote response not admitted: {}", evidence.fallback_reason)
                    }
                };
                match &error {
                    buaa_cli::evaluation::Error::Invalid(_) => ("invalid_input", 2, message),
                    buaa_cli::evaluation::Error::Unsupported(_) => ("unsupported", 3, message),
                    _ => ("unavailable", 7, message),
                }
            })?;
            emit(&output)
        }
        "checkin" => run_json_module(&args[1..], buaa_cli::checkin::run),
        "boya" => run_json_module(&args[1..], buaa_cli::boya::run),
        "drive" => run_json_module(&args[1..], buaa_cli::drive::run),
        "shuttle" => run_json_module(&args[1..], buaa_cli::shuttle::run),
        "electricity" => run_json_module(&args[1..], buaa_cli::electricity::run),
        "physics-experiment" => run_json_module(&args[1..], buaa_cli::physics_experiment::run),
        "contribution" if args.len() == 2 && args[1] == "scan" => {
            let input = Zeroizing::new(read_input()?);
            let output = buaa_cli::contribution::scan(input.as_str()).map_err(service_error)?;
            emit(&output)
        }
        "timetable-pg" if args.len() == 2 && args[1] == "parse" => {
            let input = read_input()?;
            let output = buaa_cli::timetable_pg::check(&input);
            if output.get("error").is_some() {
                return Err((
                    "invalid_input",
                    2,
                    output
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("timetable-pg parse failed")
                        .to_string(),
                ));
            }
            emit(&output)
        }
        "spoc" => run_spoc(&args[1..]),
        "announcements" => run_announcements(&args[1..]),
        "drift" if args.len() == 2 && args[1] == "check" => {
            let input = read_input()?;
            let output = buaa_cli::drift::check(&input);
            if output.get("error").is_some() {
                return Err((
                    "invalid_input",
                    2,
                    output
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("drift check failed")
                        .to_string(),
                ));
            }
            emit(&output)
        }
        "timetable" if args.len() == 2 && args[1] == "ics" => {
            let input = read_input()?;
            let output = buaa_cli::timetable::check(&input);
            if output.get("error").is_some() {
                return Err((
                    "invalid_input",
                    2,
                    output
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("timetable ics failed")
                        .to_string(),
                ));
            }
            emit(&output)
        }
        "physics"
            if args.len() == 2
                && (args[1] == "pendulum" || args[1] == "fit" || args[1] == "type-a") =>
        {
            let input = read_input()?;
            let output = buaa_cli::physics::check(&input, args[1].as_str());
            if output.get("error").is_some() {
                return Err((
                    "invalid_input",
                    2,
                    output
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("physics command failed")
                        .to_string(),
                ));
            }
            emit(&output)
        }
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
