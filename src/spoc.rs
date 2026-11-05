//! Read-only SPOC public surface observation.
//!
//! This is contract-evidence tooling for the SPOC acceptance item, not an
//! authenticated adapter. It fetches fixed public pages and source-declared
//! public scripts through the shared process governor (robots policy first).
//! A script observation is bound to the declaration found in the entry bytes
//! observed for that same request: the declared bundle changes over time, so a
//! retired reference is refused instead of being replayed as if it were
//! current.
//! Only sanitized structural and retrieval facts leave the private cache;
//! bodies, input names and values are never output, logged or published.
//! Scripts are not executed. No authentication is attempted.
use crate::html::{ScriptKind, script_kind};
use crate::net::{
    ArchiveClient, CacheMode, Error, Response, SPOC_ENTRY_URL, SPOC_ROOT_URL,
    spoc_script_url_allowed,
};
use scraper::{ElementRef, Html, Selector};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

const MAX_HTML: usize = 2 * 1024 * 1024;
const MAX_TITLE: usize = 512;
const MAX_FORMS: usize = 16;
const MAX_ACTION: usize = 4096;
const MAX_SCRIPTS: usize = 32;
const MAX_DEPTH: usize = 128;
const MAX_SCRIPT: usize = 8 * 1024 * 1024;
const MAX_REFERENCE: usize = 512;
const HTML_MIMES: [&str; 1] = ["text/html"];
const SCRIPT_MIMES: [&str; 2] = ["text/javascript", "application/javascript"];
const REFERENCE_POLICY: &str = "declaration_is_rebound_to_the_entry_bytes_observed_for_this_request; --refresh revalidates that declaration before any retained immutable script bytes are replayed; offline_replay_reports_a_retained_snapshot_without_claiming_currency";

const SURFACE_PAGES: [(&str, &str); 2] = [(SPOC_ROOT_URL, "root"), (SPOC_ENTRY_URL, "entry")];

fn unavailable() -> Error {
    Error::new(
        "unavailable",
        "SPOC public surface could not be interpreted safely",
    )
}

fn normalized_text<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    parts
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

fn active_html(element: ElementRef<'_>) -> Result<bool, Error> {
    if !crate::html::is_html_element(element) {
        return Ok(false);
    }
    for (depth, node) in element.ancestors().enumerate() {
        if depth == MAX_DEPTH {
            return Err(unavailable());
        }
        if node
            .value()
            .as_element()
            .is_some_and(|value| matches!(value.name(), "template" | "noscript"))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn safe_reference(raw: &str) -> bool {
    raw.len() <= MAX_REFERENCE && !raw.chars().any(char::is_control) && !raw.contains(['%', '\\'])
}

fn script_hints(document: &Html, source: &Url) -> Result<Vec<Value>, Error> {
    let base_selector = Selector::parse("base[href]").map_err(|_| unavailable())?;
    let mut base = source.clone();
    for (index, element) in document.select(&base_selector).enumerate() {
        if index == MAX_SCRIPTS {
            return Err(unavailable());
        }
        if !active_html(element)? {
            continue;
        }
        let raw = element.value().attr("href").unwrap_or_default();
        if !safe_reference(raw) {
            return Err(unavailable());
        }
        base = source.join(raw).map_err(|_| unavailable())?;
        if base.scheme() != "https"
            || base.host_str() != Some("spoc.buaa.edu.cn")
            || !base.username().is_empty()
            || base.password().is_some()
            || base.port().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !matches!(base.path(), "/" | "/spocnew/" | "/spocnew/js/")
        {
            return Err(unavailable());
        }
        // HTML resolves URLs against the first active base[href], not the last.
        break;
    }
    let script_selector = Selector::parse("script[src]").map_err(|_| unavailable())?;
    let mut hints = Vec::new();
    for (index, element) in document.select(&script_selector).enumerate() {
        if index == MAX_SCRIPTS {
            return Err(unavailable());
        }
        if !active_html(element)? {
            continue;
        }
        let Some(kind) = script_kind(element) else {
            continue;
        };
        if kind == ScriptKind::Classic && element.value().attr("nomodule").is_some() {
            continue;
        }
        let raw = element.value().attr("src").unwrap_or_default();
        if !safe_reference(raw) || raw.is_empty() {
            continue;
        }
        let Ok(url) = base.join(raw) else {
            continue;
        };
        if !spoc_script_url_allowed(&url) {
            continue;
        }
        hints.push(json!({
            "listed_src":raw, "url":url.as_str(),
            "script_kind":match kind { ScriptKind::Classic => "classic", ScriptKind::Module => "module" }
        }));
    }
    Ok(hints)
}

fn response_facts(response: &Response) -> Value {
    json!({
        "url":response.url, "status":response.status,
        "content_type":response.headers.get("content-type"),
        "body_byte_length":response.body.len(), "body_sha256":response.sha256,
        "retrieval":retrieval_facts(response)
    })
}

fn retrieval_facts(response: &Response) -> Value {
    json!({
        "fetched_at_unix_ms":response.fetched_at_unix_ms,
        "cache_status":response.cache_status,
        "revalidated_at_unix_ms":response.revalidated_at_unix_ms,
        "revalidation_status":response.revalidation_status
    })
}

fn media_type(value: &str) -> &str {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim_matches([' ', '\t'])
}

/// Media-type admission for one observed response. A vanished header and a
/// changed media type are different degradations, so they never collapse into
/// one refusal.
#[derive(Clone, Copy, Eq, PartialEq)]
enum MimeClass {
    Supported,
    Missing,
    Unsupported,
}

fn mime_class(content_type: Option<&str>, allowed: &[&str]) -> MimeClass {
    let Some(value) = content_type else {
        return MimeClass::Missing;
    };
    let essence = media_type(value);
    if essence.is_empty() {
        return MimeClass::Missing;
    }
    if allowed
        .iter()
        .any(|allowed| essence.eq_ignore_ascii_case(allowed))
    {
        MimeClass::Supported
    } else {
        MimeClass::Unsupported
    }
}

fn entry_mime_fallback(content_type: Option<&str>) -> Option<&'static str> {
    match mime_class(content_type, &HTML_MIMES) {
        MimeClass::Supported => None,
        MimeClass::Missing => Some("entry_mime_missing"),
        MimeClass::Unsupported => Some("entry_mime_changed"),
    }
}

fn script_mime_fallback(content_type: Option<&str>) -> Option<&'static str> {
    match mime_class(content_type, &SCRIPT_MIMES) {
        MimeClass::Supported => None,
        MimeClass::Missing => Some("script_mime_missing"),
        MimeClass::Unsupported => Some("script_mime_changed"),
    }
}

/// An entry observed in this request is the declaration authority only when the
/// read reached the source (a miss or a revalidation). A plain cache hit is a
/// retained snapshot and is reported as such: it never claims currency.
fn declaration_source(response: &Response) -> &'static str {
    if response.cache_status == crate::net::CacheStatus::Hit {
        "retained_entry_snapshot"
    } else {
        "current_entry_bytes"
    }
}

fn envelope(result: &str, hash_scope: &str) -> Value {
    json!({
        "schema_version":1,"type":"spoc_public_script","result":result,
        "fallback_reason":Value::Null,
        "source_entry":Value::Null,"declaration":Value::Null,"binding":Value::Null,
        "script":Value::Null,"raw_evidence":Value::Null,
        "verification":{
            "hash_scope":hash_scope,"filename_fingerprint_is_checksum":false,
            "external_published_checksum_verified":false,"script_executed":false,
            "script_syntax_validated":false,"authentication_attempted":false
        },
        "reference_policy":REFERENCE_POLICY
    })
}

/// Exact observed facts for bytes that are never exported. Public-source entry
/// and script bodies stay in the private cache, so the digest and the original
/// retrieval timestamps are the evidence.
fn withheld_evidence(scope: &str, response: &Response) -> Value {
    json!({
        "scope":scope,
        "url":response.url,
        "content_type":response.headers.get("content-type"),
        "byte_length":response.body.len(),
        "sha256":response.sha256,
        "data":Value::Null,
        "raw_withheld":true,
        "raw_withheld_reason":"private_public_source_bytes",
        "retrieval":retrieval_facts(response)
    })
}

fn bound_binding(declaration: &Value, declaration_source: &str) -> Value {
    json!({
        "declared_url":declaration["url"],
        "declaration_source":declaration_source,
        "selected_script_declared":true
    })
}

fn unverified_binding(target: &Url) -> Value {
    json!({
        "declared_url":target.as_str(),
        "declaration_source":"unverified",
        "selected_script_declared":Value::Null
    })
}

/// Describe one fetched public page as sanitized structural facts. The body
/// itself is never included in the returned value.
pub fn describe_page(response: &Response, label: &str) -> Result<Value, Error> {
    if response.status != 200 {
        return Err(unavailable());
    }
    if response
        .headers
        .get("content-type")
        .is_some_and(|value| !media_type(value).eq_ignore_ascii_case("text/html"))
    {
        return Err(unavailable());
    }
    if response.body.len() > MAX_HTML {
        return Err(unavailable());
    }
    let input = std::str::from_utf8(&response.body).map_err(|_| unavailable())?;
    let document = Html::parse_document(input);
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let form_selector = Selector::parse("form").map_err(|_| unavailable())?;
    let field_selector = Selector::parse("input, select, textarea").map_err(|_| unavailable())?;
    let title = match document
        .select(&title_selector)
        .next()
        .map(|element| normalized_text(element.text()))
    {
        Some(value) if value.is_empty() => None,
        Some(value) if value.len() <= MAX_TITLE => Some(value),
        Some(_) => return Err(unavailable()),
        None => None,
    };
    let mut forms = Vec::new();
    for element in document.select(&form_selector) {
        if forms.len() == MAX_FORMS {
            return Err(unavailable());
        }
        let action = element
            .value()
            .attr("action")
            .map(str::trim)
            .unwrap_or_default();
        if action.len() > MAX_ACTION || action.chars().any(char::is_control) {
            return Err(unavailable());
        }
        forms.push(json!({
            "action": if action.is_empty() { None } else { Some(action) },
            "field_count": element.select(&field_selector).count(),
        }));
    }
    let source = Url::parse(&response.url).map_err(|_| unavailable())?;
    if !matches!(source.as_str(), SPOC_ROOT_URL | SPOC_ENTRY_URL) {
        return Err(unavailable());
    }
    let hints = script_hints(&document, &source)?;
    let mut page = response_facts(response);
    page["label"] = json!(label);
    page["title"] = title.map(Value::String).unwrap_or(Value::Null);
    page["forms"] = Value::Array(forms);
    page["script_hints"] = Value::Array(hints);
    Ok(page)
}

pub fn surface(mode: CacheMode, page: Option<&str>) -> Result<Value, Error> {
    let sources = match page {
        None => SURFACE_PAGES.as_slice(),
        Some("root") => &SURFACE_PAGES[..1],
        Some("entry") => &SURFACE_PAGES[1..],
        Some(_) => {
            return Err(Error::new(
                "invalid_input",
                "expected SPOC root or entry page",
            ));
        }
    };
    let client = ArchiveClient::open_spoc(mode)?;
    let mut pages = Vec::new();
    for &(url_str, label) in sources {
        let url = Url::parse(url_str).map_err(|_| unavailable())?;
        pages.push(client.get(&url, false, |response| describe_page(response, label))?);
    }
    Ok(json!({
        "schema_version": 1,
        "type": "spoc_public_surface",
        "result": "surface_snapshot",
        "authority": {
            "publisher": "北京航空航天大学",
            "source_urls": sources.iter().map(|(url, _)| *url).collect::<Vec<_>>(),
            "scope": "public surface only; no authentication, no private content, no mutation"
        },
        "pages": pages
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptInput {
    url: String,
}

fn invalid_script() -> Error {
    Error::new(
        "invalid_input",
        "expected a canonical source-declared HTTPS SPOC public script URL",
    )
}

fn script_url(input: &str) -> Result<Url, Error> {
    if input.len() > 4096 {
        return Err(invalid_script());
    }
    let query: ScriptInput = serde_json::from_str(input).map_err(|_| invalid_script())?;
    if !safe_reference(&query.url) {
        return Err(invalid_script());
    }
    let url = Url::parse(&query.url).map_err(|_| invalid_script())?;
    if query.url != url.as_str() || !spoc_script_url_allowed(&url) {
        return Err(invalid_script());
    }
    Ok(url)
}

pub(crate) fn validate_script(
    status: u16,
    content_type: Option<&str>,
    byte_length: usize,
) -> Result<(), Error> {
    // Transport admission stays strict: a fresh response whose bytes are not
    // provably JavaScript is never captured. Retained evidence that fails this
    // gate is reported as a degraded observation instead (see `script`).
    let mime_ok = mime_class(content_type, &SCRIPT_MIMES) == MimeClass::Supported;
    if status != 200 || !mime_ok || byte_length == 0 || byte_length > MAX_SCRIPT {
        return Err(Error::new(
            "unavailable",
            "source-declared script lacks supported HTTP status, JavaScript MIME or byte bounds",
        ));
    }
    Ok(())
}

/// Entry discovery outcome for one script observation.
enum EntryBinding {
    /// The selected URL is declared by the entry bytes observed here.
    Bound {
        source: Value,
        declaration: Value,
        declaration_source: &'static str,
    },
    /// The entry cannot authorize a script fetch; the exact observed facts are
    /// returned instead of a bare refusal.
    Degraded(Value),
}

/// Observe one source-declared public script without executing or disclosing it.
pub fn script(mode: CacheMode, input: &str) -> Result<Value, Error> {
    let target = script_url(input)?;
    let client = ArchiveClient::open_spoc(mode)?;
    script_with_client(client, mode, &target)
}

pub(crate) fn script_with_client(
    client: ArchiveClient,
    mode: CacheMode,
    target: &Url,
) -> Result<Value, Error> {
    // The binding must be re-derived from the entry bytes observed for this
    // request. A cache-first discovery downgrade is exactly the stale-reference
    // acceptance that lets a retired bundle keep binding, so the entry follows
    // the observation policy instead.
    let client = client.with_cache_mode(mode);
    let entry = Url::parse(SPOC_ENTRY_URL).map_err(|_| unavailable())?;
    let binding = client.get(&entry, false, |response| {
        // A missing or changed entry media type cannot authorize a script
        // fetch, but the fact itself is evidence: report the exact bytes,
        // digest and original retrieval timestamps instead of a bare refusal.
        let mime_fallback = if response.status == 200 {
            entry_mime_fallback(response.headers.get("content-type").map(String::as_str))
        } else {
            None
        };
        if let Some(reason) = mime_fallback {
            let mut snapshot = envelope("script_unverified", "retrieved_entry_bytes");
            snapshot["fallback_reason"] = json!(reason);
            snapshot["binding"] = unverified_binding(target);
            snapshot["raw_evidence"] = withheld_evidence("entry", response);
            return Ok(EntryBinding::Degraded(snapshot));
        }
        let source = describe_page(response, "entry")?;
        let declared = source["script_hints"]
            .as_array()
            .and_then(|hints| {
                hints
                    .iter()
                    .find(|hint| hint["url"].as_str() == Some(target.as_str()))
            })
            .cloned()
            .ok_or_else(|| {
                Error::new(
                    "unsupported",
                    "the entry bytes observed for this request do not declare the selected script; a changed bundle declaration retires the previous reference",
                )
            })?;
        Ok(EntryBinding::Bound {
            source,
            declaration: declared,
            declaration_source: declaration_source(response),
        })
    })?;
    let (source, declaration, declaration_source) = match binding {
        EntryBinding::Bound {
            source,
            declaration,
            declaration_source,
        } => (source, declaration, declaration_source),
        EntryBinding::Degraded(snapshot) => return Ok(snapshot),
    };
    // Script bytes are immutable at their URL, so a refresh revalidates the
    // only mutable fact first: the entry declaration above. The retained bytes
    // are then replayed and can never be re-bound to a retired reference; a
    // script that is not retained yet needs its own governed request.
    let script_mode = match mode {
        CacheMode::Revalidate => CacheMode::PreferCache,
        other => other,
    };
    client
        .with_cache_mode(script_mode)
        .get(target, true, move |response| {
            // A retained capture whose media type vanished or drifted is degraded
            // evidence, not a fabricated JavaScript snapshot. Fresh responses are
            // already refused by transport admission before they reach this point.
            let mime_fallback = if response.status == 200 {
                script_mime_fallback(response.headers.get("content-type").map(String::as_str))
            } else {
                None
            };
            if let Some(reason) = mime_fallback {
                let mut snapshot = envelope("script_unverified", "retrieved_script_bytes");
                snapshot["fallback_reason"] = json!(reason);
                snapshot["source_entry"] = source;
                snapshot["binding"] = bound_binding(&declaration, declaration_source);
                snapshot["declaration"] = declaration;
                snapshot["script"] = response_facts(response);
                snapshot["raw_evidence"] = withheld_evidence("script", response);
                return Ok(snapshot);
            }
            validate_script(
                response.status,
                response.headers.get("content-type").map(String::as_str),
                response.body.len(),
            )?;
            let mut snapshot = envelope("script_snapshot", "retrieved_script_bytes");
            snapshot["source_entry"] = source;
            snapshot["binding"] = bound_binding(&declaration, declaration_source);
            snapshot["declaration"] = declaration;
            snapshot["script"] = response_facts(response);
            Ok(snapshot)
        })
}

fn form_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["action","field_count"],
        "properties":{"action":{"type":["string","null"]},"field_count":{"type":"integer","minimum":0}}
    })
}

fn script_hint_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["listed_src","url","script_kind"],
        "properties":{"listed_src":{"type":"string","maxLength":MAX_REFERENCE},"url":{"type":"string"},"script_kind":{"enum":["classic","module"]}}
    })
}

fn retrieval_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["fetched_at_unix_ms","cache_status","revalidated_at_unix_ms","revalidation_status"],"properties":{"fetched_at_unix_ms":{"type":"integer","minimum":0},"cache_status":{"enum":["hit","miss","revalidated"]},"revalidated_at_unix_ms":{"type":["integer","null"],"minimum":0},"revalidation_status":{"type":["integer","null"]}}})
}

fn page_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["label","url","status","content_type","body_byte_length","body_sha256","title","forms","script_hints","retrieval"],
        "properties":{
            "label":{"enum":["root","entry"]},
            "url":{"type":"string"},
            "status":{"const":200},
            "content_type":{"type":["string","null"]},
            "body_byte_length":{"type":"integer","minimum":0},
            "body_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "title":{"type":["string","null"]},
            "forms":{"type":"array","maxItems":MAX_FORMS,"items":form_schema()},
            "script_hints":{"type":"array","maxItems":MAX_SCRIPTS,"items":script_hint_schema()},
            "retrieval":retrieval_schema()
        }
    })
}

fn script_facts_schema(strict: bool) -> Value {
    let content_type = if strict {
        json!({"type":"string"})
    } else {
        json!({"type":["string","null"]})
    };
    let minimum = if strict { 1 } else { 0 };
    json!({
        "type":"object","additionalProperties":false,
        "required":["url","status","content_type","body_byte_length","body_sha256","retrieval"],
        "properties":{
            "url":{"type":"string"},"status":{"const":200},
            "content_type":content_type,
            "body_byte_length":{"type":"integer","minimum":minimum,"maximum":MAX_SCRIPT},
            "body_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "retrieval":retrieval_schema()
        },
        "description":"Only retrieval metadata; raw bytes stay in the private immutable cache."
    })
}

fn evidence_schema(scope: &str) -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["scope","url","content_type","byte_length","sha256","data","raw_withheld","raw_withheld_reason","retrieval"],
        "properties":{
            "scope":{"const":scope},
            "url":{"type":"string"},
            "content_type":{"type":["string","null"]},
            "byte_length":{"type":"integer","minimum":0},
            "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "data":{"type":"null"},
            "raw_withheld":{"const":true},
            "raw_withheld_reason":{"const":"private_public_source_bytes"},
            "retrieval":retrieval_schema()
        }
    })
}

fn binding_schema(declaration_source: Value, selected_script_declared: Value) -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["declared_url","declaration_source","selected_script_declared"],
        "properties":{
            "declared_url":{"type":"string"},
            "declaration_source":declaration_source,
            "selected_script_declared":selected_script_declared
        }
    })
}

pub fn schema() -> Value {
    json!({
        "script": {
            "input":{"type":"object","additionalProperties":false,"required":["url"],"properties":{"url":{"type":"string","maxLength":MAX_REFERENCE,"pattern":"^https://spoc[.]buaa[.]edu[.]cn/spocnew/js/[A-Za-z0-9_-]{1,64}[.][0-9a-f]{8}[.]js$","description":"Canonical HTTPS spoc.buaa.edu.cn/spocnew/js/<name>.<8 lowercase hex>.js URL that the entry bytes observed for this same request still declare; no query/fragment/credentials/custom port. A retired reference fails binding."}}},
            "output":{
                "type":"object","additionalProperties":false,
                "required":["schema_version","type","result","fallback_reason","source_entry","declaration","binding","script","raw_evidence","verification","reference_policy"],
                "properties":{
                    "schema_version":{"const":1},"type":{"const":"spoc_public_script"},
                    "result":{"enum":["script_snapshot","script_unverified"]},
                    "fallback_reason":{"type":["string","null"],"enum":[null,"entry_mime_missing","entry_mime_changed","script_mime_missing","script_mime_changed"]},
                    "source_entry":{"type":["object","null"]},
                    "declaration":{"type":["object","null"]},
                    "binding":{"type":["object","null"]},
                    "script":{"type":["object","null"]},
                    "raw_evidence":{"type":["object","null"]},
                    "reference_policy":{"const":REFERENCE_POLICY},
                    "verification":{"type":"object","additionalProperties":false,"required":["hash_scope","filename_fingerprint_is_checksum","external_published_checksum_verified","script_executed","script_syntax_validated","authentication_attempted"],"properties":{"hash_scope":{"enum":["retrieved_script_bytes","retrieved_entry_bytes"]},"filename_fingerprint_is_checksum":{"const":false},"external_published_checksum_verified":{"const":false},"script_executed":{"const":false},"script_syntax_validated":{"const":false},"authentication_attempted":{"const":false}}}
                },
                "allOf":[
                    {
                        "if":{"required":["result"],"properties":{"result":{"const":"script_snapshot"}}},
                        "then":{"required":["source_entry","declaration","binding","script"],"properties":{
                            "fallback_reason":{"type":"null"},
                            "source_entry":page_schema(),
                            "declaration":script_hint_schema(),
                            "binding":binding_schema(json!({"enum":["current_entry_bytes","retained_entry_snapshot"]}),json!({"const":true})),
                            "script":script_facts_schema(true),
                            "raw_evidence":{"type":"null"}
                        }},
                        "else":{"required":["fallback_reason"],"properties":{
                            "result":{"const":"script_unverified"},
                            "fallback_reason":{"enum":["entry_mime_missing","entry_mime_changed","script_mime_missing","script_mime_changed"]}
                        }}
                    },
                    {
                        "if":{"required":["fallback_reason"],"properties":{"fallback_reason":{"enum":["entry_mime_missing","entry_mime_changed"]}}},
                        "then":{"required":["source_entry","declaration","binding","script","raw_evidence"],"properties":{
                            "result":{"const":"script_unverified"},
                            "source_entry":{"type":"null"},
                            "declaration":{"type":"null"},
                            "binding":binding_schema(json!({"const":"unverified"}),json!({"type":"null"})),
                            "script":{"type":"null"},
                            "raw_evidence":evidence_schema("entry")
                        }}
                    },
                    {
                        "if":{"required":["fallback_reason"],"properties":{"fallback_reason":{"enum":["script_mime_missing","script_mime_changed"]}}},
                        "then":{"required":["source_entry","declaration","binding","script","raw_evidence"],"properties":{
                            "result":{"const":"script_unverified"},
                            "source_entry":page_schema(),
                            "declaration":script_hint_schema(),
                            "binding":binding_schema(json!({"enum":["current_entry_bytes","retained_entry_snapshot"]}),json!({"const":true})),
                            "script":script_facts_schema(false),
                            "raw_evidence":evidence_schema("script")
                        }}
                    }
                ]
            },
            "network":"Offline by default. --online admits governed cache misses for the entry and the selected script. --refresh revalidates the entry declaration first, then replays the retained immutable script bytes; a script that is not retained needs a second governed request and may therefore exceed the bounded wait. A declaration that no longer lists the requested URL fails binding, and a changed or missing media type yields degraded evidence with the exact digest and retrieval timestamps. Raw scripts/configuration are never output."
        },
        "surface": {
            "input": {"type":"null","description":"No stdin. spoc surface [root|entry] [--online|--refresh]; omit the page to observe both fixed pages. Default is private cache only. Select entry explicitly to refresh declarations in one governed request."},
            "output": {
                "$schema":"https://json-schema.org/draft/2020-12/schema",
                "type":"object","additionalProperties":false,
                "required":["schema_version","type","result","authority","pages"],
                "properties":{
                    "schema_version":{"const":1},"type":{"const":"spoc_public_surface"},"result":{"const":"surface_snapshot"},
                    "authority":{"type":"object","additionalProperties":false,"required":["publisher","source_urls","scope"],"properties":{"publisher":{"const":"北京航空航天大学"},"source_urls":{"type":"array","minItems":1,"maxItems":2,"items":{"type":"string"}},"scope":{"const":"public surface only; no authentication, no private content, no mutation"}}},
                    "pages":{"type":"array","minItems":1,"maxItems":2,"items":page_schema()}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};

    fn response(status: u16, content_type: &str, body: &str) -> Response {
        let bytes = body.as_bytes().to_vec();
        let sha = format!("{:x}", Sha256::digest(&bytes));
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_owned(), content_type.to_owned());
        Response {
            url: SPOC_ROOT_URL.to_owned(),
            status,
            headers,
            body: bytes,
            sha256: sha,
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }
    const PAGE: &str = r#"<html><head><title>SPOC 门户</title></head><body>
        <form action="/login" method="post"><input name="a"/><input name="b"/></form>
        <form><select name="c"></select></form>
    </body></html>"#;

    #[test]
    fn describes_public_page_as_sanitized_facts() {
        let value =
            describe_page(&response(200, "text/html; charset=utf-8", PAGE), "root").unwrap();
        assert_eq!(value["label"], "root");
        assert_eq!(value["title"], "SPOC 门户");
        assert_eq!(value["forms"].as_array().unwrap().len(), 2);
        assert_eq!(value["forms"][0]["action"], "/login");
        assert_eq!(value["forms"][0]["field_count"], 2);
        assert_eq!(value["forms"][1]["action"], Value::Null);
        assert_eq!(value["forms"][1]["field_count"], 1);
        // The body and its field names must never appear in the output.
        let rendered = value.to_string();
        assert!(!rendered.contains("name=\"a\""));
        assert!(!rendered.contains("<body>"));
        assert!(value.get("body").is_none());
    }

    #[test]
    fn rejects_non_success_and_non_html() {
        assert!(describe_page(&response(404, "text/html", PAGE), "root").is_err());
        assert!(describe_page(&response(200, "application/json", "{}"), "root").is_err());
        assert!(describe_page(&response(200, "text/html-not-html", PAGE), "root").is_err());
    }

    #[test]
    fn rejects_oversized_and_unsafe_structure() {
        let page = format!(
            "<html><head><title>{}</title></head><body></body></html>",
            "x".repeat(MAX_TITLE + 1)
        );
        assert!(describe_page(&response(200, "text/html", &page), "root").is_err());
        let action = format!("a{}b", char::from_u32(1).unwrap());
        let page = format!(
            "<html><head><title>t</title></head><body><form action=\"{action}\"></form></body></html>"
        );
        assert!(describe_page(&response(200, "text/html", &page), "root").is_err());
        let mut forms = String::new();
        for _ in 0..=MAX_FORMS {
            forms.push_str("<form></form>");
        }
        let page = format!("<html><head><title>t</title></head><body>{forms}</body></html>");
        assert!(describe_page(&response(200, "text/html", &page), "root").is_err());
    }

    #[test]
    fn script_declarations_use_first_active_base_and_exclude_inert_sources() {
        let page = r#"<head><template><base href="https://foreign.example/"></template>
            <base href="/spocnew/js/"><base href="https://foreign.example/">
            </head><body>
            <script src="app.12345678.js"></script>
            <script type="module" nomodule src="module.abcdef12.js"></script>
            <script type="application/json" src="data.12345678.js"></script>
            <script language="vbscript" src="legacy.12345678.js"></script>
            <script nomodule src="fallback.12345678.js"></script>
            <template><script src="template.12345678.js"></script></template>
            <noscript><script src="noscript.12345678.js"></script></noscript>
            <svg><script src="svg.12345678.js"></script></svg>
            <script src="https://foreign.example/spocnew/js/foreign.12345678.js"></script>
            <script src="app.12345678.js?private-marker=value"></script>
            <script>const inlineMarker = "not a declaration";</script>
            </body>"#;
        let mut source = response(200, "text/html", page);
        source.url = SPOC_ENTRY_URL.into();
        let output = describe_page(&source, "entry").unwrap();
        assert_eq!(
            output["script_hints"],
            json!([
                {"listed_src":"app.12345678.js","url":"https://spoc.buaa.edu.cn/spocnew/js/app.12345678.js","script_kind":"classic"},
                {"listed_src":"module.abcdef12.js","url":"https://spoc.buaa.edu.cn/spocnew/js/module.abcdef12.js","script_kind":"module"}
            ])
        );
        assert!(!output.to_string().contains("private-marker"));
        assert!(!output.to_string().contains("inlineMarker"));
    }

    #[test]
    fn declaration_whitespace_does_not_activate_non_html_script_types_or_urls() {
        let page = concat!(
            "<script type=\"\u{a0}text/javascript\u{a0}\" src=\"/spocnew/js/inert.12345678.js\"></script>",
            "<script src=\"\u{a0}/spocnew/js/not-url.12345678.js\u{a0}\"></script>",
            "<script type=\"\ttext/javascript\n\" src=\"  /spocnew/js/active.12345678.js  \"></script>",
            "<script type=\"\" language=\"vbscript\" src=\"/spocnew/js/explicit.12345678.js\"></script>"
        );
        let output = describe_page(&response(200, "text/html", page), "root").unwrap();
        assert_eq!(
            output["script_hints"],
            json!([
                {"listed_src":"  /spocnew/js/active.12345678.js  ","url":"https://spoc.buaa.edu.cn/spocnew/js/active.12345678.js","script_kind":"classic"},
                {"listed_src":"/spocnew/js/explicit.12345678.js","url":"https://spoc.buaa.edu.cn/spocnew/js/explicit.12345678.js","script_kind":"classic"}
            ])
        );
    }

    #[test]
    fn unsupported_base_and_unbounded_declarations_fail_closed() {
        let script =
            r#"<script src="https://spoc.buaa.edu.cn/spocnew/js/app.12345678.js"></script>"#;
        for base in [
            "https://foreign.example/",
            "/unreviewed/",
            "/spocnew/?private-marker=x",
        ] {
            let page = format!("<base href=\"{base}\">{script}");
            assert_eq!(
                describe_page(&response(200, "text/html", &page), "root")
                    .unwrap_err()
                    .code,
                "unavailable"
            );
        }
        let too_many = script.repeat(MAX_SCRIPTS + 1);
        assert_eq!(
            describe_page(&response(200, "text/html", &too_many), "root")
                .unwrap_err()
                .code,
            "unavailable"
        );
        let too_deep = format!(
            "{}{script}{}",
            "<div>".repeat(MAX_DEPTH),
            "</div>".repeat(MAX_DEPTH)
        );
        assert_eq!(
            describe_page(&response(200, "text/html", &too_deep), "root")
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn script_input_rejects_unreviewed_and_normalized_urls() {
        for url in [
            "https://foreign.example/spocnew/js/app.12345678.js",
            "https://spoc.buaa.edu.cn/spocnew/js/app.12345678.js?private-marker=x",
            "https://spoc.buaa.edu.cn/spocnew/js/app.12345678.js.map",
            "https://spoc.buaa.edu.cn/spocnew/js/app.js",
            "https://spoc.buaa.edu.cn:443/spocnew/js/app.12345678.js",
            "https://spoc.buaa.edu.cn/unreviewed/../spocnew/js/app.12345678.js",
        ] {
            let error = script_url(&json!({"url":url}).to_string()).unwrap_err();
            assert_eq!(error.code, "invalid_input");
            assert!(!error.message.contains("private-marker"));
        }
    }

    #[test]
    fn script_mime_and_byte_bounds_reject_unsafe_responses() {
        let mut missing_mime = response(200, "application/javascript", "synthetic source");
        missing_mime.headers.clear();
        assert_eq!(
            validate_script(missing_mime.status, None, missing_mime.body.len())
                .unwrap_err()
                .code,
            "unavailable"
        );
        for source in [
            response(200, "text/html", "<html>not JavaScript</html>"),
            response(404, "application/javascript", "missing"),
            response(200, "application/javascript", ""),
            response(200, "application/javascript", &"x".repeat(MAX_SCRIPT + 1)),
        ] {
            assert_eq!(
                validate_script(
                    source.status,
                    source.headers.get("content-type").map(String::as_str),
                    source.body.len(),
                )
                .unwrap_err()
                .code,
                "unavailable"
            );
        }
    }

    #[test]
    fn degraded_mime_fallbacks_separate_missing_from_changed_media_types() {
        assert_eq!(entry_mime_fallback(Some("text/html; charset=utf-8")), None);
        assert_eq!(entry_mime_fallback(None), Some("entry_mime_missing"));
        assert_eq!(entry_mime_fallback(Some("")), Some("entry_mime_missing"));
        assert_eq!(
            entry_mime_fallback(Some("text/plain")),
            Some("entry_mime_changed")
        );
        assert_eq!(
            script_mime_fallback(Some("Application/JavaScript; charset=utf-8")),
            None
        );
        assert_eq!(script_mime_fallback(None), Some("script_mime_missing"));
        assert_eq!(
            script_mime_fallback(Some("text/html")),
            Some("script_mime_changed")
        );
        assert_eq!(
            script_mime_fallback(Some("application/json")),
            Some("script_mime_changed")
        );
    }

    #[test]
    fn degraded_evidence_keeps_exact_facts_without_exporting_bytes() {
        let mut source = response(200, "text/html", "<html>private synthetic entry</html>");
        source.url = SPOC_ENTRY_URL.into();
        source.cache_status = CacheStatus::Hit;
        source.revalidated_at_unix_ms = Some(7);
        source.revalidation_status = Some(304);
        let evidence = withheld_evidence("entry", &source);
        assert_eq!(evidence["scope"], "entry");
        assert_eq!(evidence["url"], SPOC_ENTRY_URL);
        assert_eq!(evidence["content_type"], "text/html");
        assert_eq!(evidence["byte_length"], json!(source.body.len()));
        assert_eq!(evidence["sha256"], source.sha256);
        assert_eq!(evidence["retrieval"]["fetched_at_unix_ms"], 1);
        assert_eq!(evidence["retrieval"]["cache_status"], "hit");
        assert_eq!(evidence["retrieval"]["revalidated_at_unix_ms"], 7);
        assert_eq!(evidence["retrieval"]["revalidation_status"], 304);
        assert_eq!(evidence["data"], Value::Null);
        assert_eq!(evidence["raw_withheld"], true);
        assert_eq!(
            evidence["raw_withheld_reason"],
            "private_public_source_bytes"
        );
        assert!(!evidence.to_string().contains("private synthetic entry"));
        // The evidence object the degraded path emits must satisfy its own
        // declared contract, including the facts it preserves byte for byte.
        let schema = schema();
        let declared =
            &schema["script"]["output"]["allOf"][1]["then"]["properties"]["raw_evidence"];
        let mut required = BTreeSet::new();
        for key in declared["required"].as_array().unwrap() {
            required.insert(key.as_str().unwrap());
        }
        let mut emitted = BTreeSet::new();
        for key in evidence.as_object().unwrap().keys() {
            emitted.insert(key.as_str());
        }
        assert_eq!(emitted, required);
        assert_eq!(declared["properties"]["scope"]["const"], "entry");
    }

    #[test]
    fn degraded_envelope_matches_schema_and_claims_nothing() {
        let snapshot = envelope("script_unverified", "retrieved_entry_bytes");
        assert_eq!(snapshot["result"], "script_unverified");
        assert_eq!(snapshot["fallback_reason"], Value::Null);
        assert_eq!(snapshot["source_entry"], Value::Null);
        assert_eq!(snapshot["declaration"], Value::Null);
        assert_eq!(snapshot["binding"], Value::Null);
        assert_eq!(snapshot["script"], Value::Null);
        assert_eq!(snapshot["raw_evidence"], Value::Null);
        assert_eq!(snapshot["reference_policy"], REFERENCE_POLICY);
        // The retained policy must name the rebinding and the offline
        // disclosure; the retired retained-snapshot wording may not return.
        assert!(REFERENCE_POLICY.contains("rebound_to_the_entry_bytes"));
        assert!(REFERENCE_POLICY.contains("offline_replay"));
        for flag in [
            "external_published_checksum_verified",
            "script_executed",
            "script_syntax_validated",
            "authentication_attempted",
        ] {
            assert_eq!(snapshot["verification"][flag], false);
        }
        // The emitted object and the declared contract must not drift apart.
        let schema = schema();
        let required = schema["script"]["output"]["required"].as_array().unwrap();
        let mut declared = BTreeSet::new();
        for key in required {
            declared.insert(key.as_str().unwrap());
        }
        let mut emitted = BTreeSet::new();
        for key in snapshot.as_object().unwrap().keys() {
            emitted.insert(key.as_str());
        }
        assert_eq!(emitted, declared);
        // A verified script snapshot and the degraded script branch must
        // declare the same script facts object, so a drifted MIME still carries
        // the exact original bytes/digest/retrieval facts.
        let verified = &schema["script"]["output"]["allOf"][0]["then"]["properties"]["script"];
        let degraded = &schema["script"]["output"]["allOf"][2]["then"]["properties"]["script"];
        assert_eq!(verified["required"], degraded["required"]);
        assert_eq!(
            verified["properties"]["body_sha256"],
            degraded["properties"]["body_sha256"]
        );
        assert_eq!(
            verified["properties"]["retrieval"],
            degraded["properties"]["retrieval"]
        );
        assert_ne!(
            verified["properties"]["content_type"],
            degraded["properties"]["content_type"]
        );
    }
}
