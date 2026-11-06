//! Live stream admission skeleton. Live streaming is not implemented.
//!
//! No live stream, playlist, encryption-key or fragment contract has been
//! reviewed for this CLI. Earlier hostname observations came from a temporary
//! client outside the production shared governor; they establish neither an
//! authorized source identity nor media rights and must not authorize
//! production requests. This module therefore admits only a strict, fully
//! source-bound request shape and then refuses execution: it forms no URL of
//! its own, invents no endpoint, playlist, key or segment, reads no
//! credential, opens no player and starts no stream.
//!
//! The optional bounded playlist+fragment plan is a finite acquisition plan
//! bound to caller-supplied exact URLs, inclusive byte ranges, expected
//! SHA-256 digests and expected byte lengths. Its structural admission is
//! reported, but no transport or host allowlist is admitted here, so the plan
//! is non-executable and disabled by default.
use crate::net::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::atomic::AtomicBool;
use url::Url;

const MAX_INPUT: usize = 64 * 1024;
const MAX_URL: usize = 8 * 1024;
const MAX_REFERENCE: usize = 512;
const MAX_TOKEN: usize = 512;
/// Bounded live playlist+fragment plan: objects, bytes per object and total.
const MAX_OBJECTS: usize = 64;
const MAX_OBJECT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PLAN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
/// The only protocol dialect this module can state or inspect: the finite HLS
/// manifest grammar handled by `inspect_manifest`. No live transport, key or
/// segment scheduling is implied by admitting this fact.
const PROTOCOL_HLS: &str = "hls";

/// Fact names reported in the receipt. They are names only: no supplied
/// value is ever echoed back.
const FACT_SOURCE_BINDING: &str = "source_binding";
const FACT_STREAM: &str = "stream";
const FACT_PLAYLIST: &str = "playlist";
const FACT_CREDENTIAL: &str = "credential";
const FACT_BOUNDED_FETCH: &str = "bounded_fetch_plan";

const REASON_SOURCE_MISSING: &str = "live_source_binding_not_supplied";
const REASON_SOURCE_UNREVIEWED: &str = "live_source_binding_not_reviewed";
const REASON_STREAM_MISSING: &str = "live_stream_contract_not_supplied";
const REASON_PLAYLIST_MISSING: &str = "live_playlist_contract_not_supplied";
const REASON_PLAYLIST_NOT_ONGOING: &str = "live_playlist_contract_not_ongoing";
const REASON_CREDENTIAL_MISSING: &str = "live_credential_contract_not_supplied";
const REASON_CREDENTIAL_UNBOUND: &str = "live_credential_contract_not_source_bound";
const REASON_CREDENTIAL_DELIVERY: &str = "live_credential_delivery_not_admitted";
const REASON_FETCH_TRANSPORT: &str = "bounded_playlist_fetch_requires_admitted_transport";
/// This module never admits a transport: no live host allowlist, request
/// cadence, cache namespace or credential delivery contract has been reviewed.
const REASON_TRANSPORT: &str = "live_transport_and_host_allowlist_not_reviewed";
/// No stream scheduler, segment collector, reconnect policy or player binding
/// exists, so playback cannot be claimed even when the facts are complete.
const REASON_NOT_IMPLEMENTED: &str = "live_streaming_not_implemented";

fn input_invalid() -> Error {
    Error::new(
        "invalid_input",
        "The live session request is malformed or unsupported.",
    )
}

fn denied() -> Error {
    Error::new(
        "permission",
        "Explicit operator authorization for a live session is required.",
    )
}

fn manifest_invalid() -> Error {
    Error::new(
        "invalid_input",
        "Unsupported or malformed offline HLS manifest.",
    )
}

/// Strict, object-root request for a live session. Every field is either an
/// explicit caller-supplied fact or absent; nothing is defaulted into an
/// admitted value and no credential value is accepted in any form.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveInput {
    authorized: bool,
    #[serde(default)]
    source: Option<SourceBinding>,
    #[serde(default)]
    stream: Option<StreamContract>,
    #[serde(default)]
    playlist: Option<PlaylistContract>,
    #[serde(default)]
    credential: Option<CredentialContract>,
    #[serde(default)]
    bounded_fetch: Option<BoundedFetch>,
}

/// The reviewed source snapshot the other facts were bound against.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBinding {
    reviewed: bool,
    /// Opaque label of the reviewed source snapshot, never a credential.
    reference: String,
    /// Exact digest of the reviewed source document.
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamContract {
    /// Opaque stream identity; no URL is admitted as an identity.
    id: String,
    /// Only the HLS manifest dialect this module can inspect offline can be
    /// stated as a live protocol fact; any other value is refused as input.
    protocol: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaylistContract {
    /// Exact caller-supplied absolute HTTPS playlist URL.
    url: String,
    /// Expected digest of the manifest bytes.
    sha256: String,
    /// The reviewed source declares an ongoing (no `EXT-X-ENDLIST`) playlist.
    live: bool,
}

/// How a live endpoint authenticates, as declared by the reviewed source.
/// The credential value itself is never part of this request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialContract {
    method: CredentialMethod,
    source_bound: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CredentialMethod {
    None,
    SessionCookie,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundedFetch {
    /// Disabled by default. Even an enabled, structurally admitted plan is not
    /// executed because no transport is admitted.
    enabled: bool,
    fragments: Vec<Fragment>,
    max_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fragment {
    /// Exact caller-supplied absolute HTTPS object URL.
    url: String,
    /// Expected digest of the fetched object (or of the requested range).
    sha256: String,
    /// Expected length of the object or of the requested range.
    bytes: u64,
    #[serde(default)]
    range: Option<ByteRange>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ByteRange {
    start: u64,
    /// Inclusive end offset; `end - start + 1` must equal `bytes`.
    end: u64,
}

struct BoundedPlan {
    requested: bool,
    admitted: bool,
    objects: usize,
    bytes: u64,
}

struct Assessment {
    supplied: Vec<&'static str>,
    missing: Vec<&'static str>,
    reasons: Vec<&'static str>,
    bounded: BoundedPlan,
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn contains_ascii_ignore_case(value: &str, needle: &[u8]) -> bool {
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn bounded_text(value: &str, max: usize) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > max
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(input_invalid());
    }
    Ok(())
}

/// A live URL is a source binding, not a credential carrier: the credential
/// contract is a separate fact. Accepting a token, cookie, session or
/// signature inside the URL would smuggle a secret through this request and
/// make `credentials_read:false` untrue, so such URLs are refused.
fn carries_credential_material(value: &str) -> bool {
    const MARKERS: &[&[u8]] = &[
        b"cookie",
        b"token",
        b"secret",
        b"passw",
        b"session",
        b"ticket",
        b"signature",
        b"apikey",
        b"api_key",
        b"access_key",
        b"auth=",
        b"key=",
        b"sig=",
    ];
    MARKERS
        .iter()
        .any(|marker| contains_ascii_ignore_case(value, *marker))
}

/// Admit exactly the URL the caller supplied. A parsed alias would bind a
/// different object than the declared source fact, so normalized forms are
/// refused rather than silently rewritten.
fn validate_exact_url(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > MAX_URL
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(input_invalid());
    }
    let url = Url::parse(value).map_err(|_| input_invalid())?;
    if url.as_str() != value
        || contains_ascii_ignore_case(value, b"%2e")
        || contains_ascii_ignore_case(value, b"%2f")
        || contains_ascii_ignore_case(value, b"%5c")
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || carries_credential_material(value)
    {
        return Err(input_invalid());
    }
    Ok(())
}

fn parse_input(input: &str) -> Result<LiveInput, Error> {
    if input.len() > MAX_INPUT {
        return Err(input_invalid());
    }
    // Decode through a map-only visitor: a positional sequence root is not a
    // request object, and decoding the map directly preserves duplicate fields
    // so the derived visitor rejects them instead of last-key-wins collapsing
    // them. `end()` refuses a trailing document before any fact is assessed.
    struct RequestObject;
    impl<'de> serde::de::Visitor<'de> for RequestObject {
        type Value = LiveInput;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a live session request object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            serde::Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(input);
    let parsed: LiveInput = serde::Deserializer::deserialize_map(&mut decoder, RequestObject)
        .map_err(|_| input_invalid())?;
    decoder.end().map_err(|_| input_invalid())?;
    Ok(parsed)
}

/// Validate the bounded plan's own structure. A malformed or unbounded plan is
/// invalid input; a well-formed plan is still non-executable here.
fn bounded_plan(
    plan: &BoundedFetch,
    playlist: Option<&PlaylistContract>,
) -> Result<(usize, u64), Error> {
    if plan.fragments.is_empty() || plan.fragments.len() > MAX_OBJECTS {
        return Err(input_invalid());
    }
    if plan.max_bytes == 0 || plan.max_bytes > MAX_PLAN_BYTES {
        return Err(input_invalid());
    }
    let mut seen: Vec<(&str, Option<(u64, u64)>)> = Vec::with_capacity(plan.fragments.len());
    let mut total = 0u64;
    for fragment in &plan.fragments {
        validate_exact_url(&fragment.url)?;
        if !lower_hex(&fragment.sha256, 64) {
            return Err(input_invalid());
        }
        if let Some(playlist) = playlist
            && playlist.url == fragment.url
        {
            return Err(input_invalid());
        }
        if fragment.bytes == 0 || fragment.bytes > MAX_OBJECT_BYTES {
            return Err(input_invalid());
        }
        let span = match fragment.range.as_ref() {
            None => None,
            Some(range) => {
                let length = range
                    .end
                    .checked_sub(range.start)
                    .and_then(|difference| difference.checked_add(1))
                    .ok_or_else(input_invalid)?;
                if length != fragment.bytes {
                    return Err(input_invalid());
                }
                Some((range.start, range.end))
            }
        };
        for (url, other) in &seen {
            if *url != fragment.url.as_str() {
                continue;
            }
            match (*other, span) {
                // The same whole object twice would double-fetch it.
                (None, None) => return Err(input_invalid()),
                (Some((first_start, first_end)), Some((start, end)))
                    if start <= first_end && first_start <= end =>
                {
                    return Err(input_invalid());
                }
                _ => {}
            }
        }
        seen.push((fragment.url.as_str(), span));
        total = total
            .checked_add(fragment.bytes)
            .ok_or_else(input_invalid)?;
        if total > plan.max_bytes {
            return Err(input_invalid());
        }
    }
    Ok((plan.fragments.len(), total))
}

/// Compare the supplied facts with the source-bound contract this module would
/// need, refusing any value the reviewed facts do not actually declare.
fn assess(request: &LiveInput) -> Result<Assessment, Error> {
    if !request.authorized {
        return Err(denied());
    }
    let mut supplied = Vec::new();
    let mut missing = Vec::new();
    let mut reasons = Vec::new();

    match request.source.as_ref() {
        None => {
            missing.push(FACT_SOURCE_BINDING);
            reasons.push(REASON_SOURCE_MISSING);
        }
        Some(source) => {
            bounded_text(&source.reference, MAX_REFERENCE)?;
            if !lower_hex(&source.sha256, 64) {
                return Err(input_invalid());
            }
            if source.reviewed {
                supplied.push(FACT_SOURCE_BINDING);
            } else {
                missing.push(FACT_SOURCE_BINDING);
                reasons.push(REASON_SOURCE_UNREVIEWED);
            }
        }
    }

    match request.stream.as_ref() {
        None => {
            missing.push(FACT_STREAM);
            reasons.push(REASON_STREAM_MISSING);
        }
        Some(stream) => {
            bounded_text(&stream.id, MAX_TOKEN)?;
            if stream.protocol == PROTOCOL_HLS {
                supplied.push(FACT_STREAM);
            } else {
                return Err(input_invalid());
            }
        }
    }

    match request.playlist.as_ref() {
        None => {
            missing.push(FACT_PLAYLIST);
            reasons.push(REASON_PLAYLIST_MISSING);
        }
        Some(playlist) => {
            validate_exact_url(&playlist.url)?;
            if !lower_hex(&playlist.sha256, 64) {
                return Err(input_invalid());
            }
            if playlist.live {
                supplied.push(FACT_PLAYLIST);
            } else {
                missing.push(FACT_PLAYLIST);
                reasons.push(REASON_PLAYLIST_NOT_ONGOING);
            }
        }
    }

    match request.credential.as_ref() {
        None => {
            missing.push(FACT_CREDENTIAL);
            reasons.push(REASON_CREDENTIAL_MISSING);
        }
        Some(credential) => {
            if credential.source_bound {
                supplied.push(FACT_CREDENTIAL);
                // A cookie-delivering live read needs a reviewed delivery
                // target and one-shot lease that this module does not admit.
                if matches!(credential.method, CredentialMethod::SessionCookie) {
                    reasons.push(REASON_CREDENTIAL_DELIVERY);
                }
            } else {
                missing.push(FACT_CREDENTIAL);
                reasons.push(REASON_CREDENTIAL_UNBOUND);
            }
        }
    }

    let bounded = match request.bounded_fetch.as_ref() {
        None => BoundedPlan {
            requested: false,
            admitted: false,
            objects: 0,
            bytes: 0,
        },
        Some(plan) => {
            let (objects, bytes) = bounded_plan(plan, request.playlist.as_ref())?;
            if plan.enabled {
                supplied.push(FACT_BOUNDED_FETCH);
                reasons.push(REASON_FETCH_TRANSPORT);
                BoundedPlan {
                    requested: true,
                    admitted: true,
                    objects,
                    bytes,
                }
            } else {
                BoundedPlan {
                    requested: false,
                    admitted: false,
                    objects: 0,
                    bytes: 0,
                }
            }
        }
    };

    reasons.push(REASON_TRANSPORT);
    reasons.push(REASON_NOT_IMPLEMENTED);
    Ok(Assessment {
        supplied,
        missing,
        reasons,
        bounded,
    })
}

/// Every admitted call returns this same envelope. Only the admitted/missing
/// fact names, the blocked reasons and the admitted plan counts vary; every
/// execution field is a constant refusal and no supplied value is echoed.
fn receipt(assessment: &Assessment) -> Value {
    json!({
        "schema_version":1,
        "type":"recording_live",
        "result":"blocked",
        "implemented":false,
        "implementation_complete":false,
        "reason":REASON_NOT_IMPLEMENTED,
        "blocked_reasons":assessment.reasons,
        "source_bound_facts_supplied":assessment.supplied,
        "missing_source_bound_facts":assessment.missing,
        "network_access":false,
        "source_objects_fetched":false,
        "credentials_read":false,
        "player_started":false,
        "automatic_reconnect":false,
        "still_following":false,
        "complete":false,
        "segment_count":0,
        "segment_bytes":0,
        "duration_seconds":0,
        "media_rights_verified":false,
        "decoder_verified":false,
        "host_allowlist_verified":false,
        "transport_admitted":false,
        "playback_admitted":false,
        "bounded_fetch":{
            "kind":"playlist_and_fragment_fetch_plan",
            "enabled_by_default":false,
            "requested":assessment.bounded.requested,
            "admitted":assessment.bounded.admitted,
            "executable":false,
            "executed":false,
            "objects":assessment.bounded.objects,
            "expected_bytes":assessment.bounded.bytes
        }
    })
}

/// Fail closed: parse the strict request shape, report which reviewed facts
/// are missing and return the blocked envelope. Nothing is fetched, no
/// credential is read, no player is started and no stream is created.
pub fn online(input: &str) -> Result<Value, Error> {
    let request = parse_input(input)?;
    let assessment = assess(&request)?;
    Ok(receipt(&assessment))
}

/// The stop-aware entry cannot create a stream or reconnect either. Because
/// no work is ever started, the signal cannot change the receipt; an admitted
/// transport would have to consult it before every request and every
/// reconnect decision.
pub fn online_with_stop(input: &str, _stop: &AtomicBool) -> Result<Value, Error> {
    online(input)
}

/// Inspect supplied bytes only. This does not resolve URIs, admit hosts,
/// establish stream identity, authorize media use or prove decoder support.
pub fn inspect_manifest(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(manifest_invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| manifest_invalid())?;
    let mut lines = text.lines();
    if lines.next() != Some("#EXTM3U") {
        return Err(manifest_invalid());
    }
    let mut duration = None;
    let mut variant = false;
    let mut variants = 0;
    let mut segments = 0;
    let mut seconds = 0.0;
    let mut keys = false;
    let mut end_list = false;
    let mut unsupported = false;
    for raw in lines {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("#EXTINF:") {
            if duration.is_some() || variant {
                return Err(manifest_invalid());
            }
            let value = value
                .split(',')
                .next()
                .unwrap_or("")
                .parse::<f64>()
                .map_err(|_| manifest_invalid())?;
            if !value.is_finite() || value <= 0.0 {
                return Err(manifest_invalid());
            }
            duration = Some(value);
        } else if line.starts_with("#EXT-X-STREAM-INF:") {
            if variant || duration.is_some() {
                return Err(manifest_invalid());
            }
            variant = true;
        } else if line.starts_with("#EXT-X-KEY:") {
            keys = true;
            unsupported = true;
        } else if line == "#EXT-X-ENDLIST" {
            end_list = true;
        } else if line.starts_with("#EXT-X-BYTERANGE:")
            || line.starts_with("#EXT-X-MAP:")
            || line.starts_with("#EXT-X-SKIP:")
            || line.starts_with("#EXT-X-PART:")
            || line == "#EXT-X-I-FRAMES-ONLY"
        {
            unsupported = true;
        } else if !line.starts_with('#') {
            if end_list {
                return Err(manifest_invalid());
            }
            if variant {
                variants += 1;
                variant = false;
            } else if let Some(value) = duration.take() {
                segments += 1;
                seconds += value;
            } else {
                return Err(manifest_invalid());
            }
        }
    }
    if variant
        || duration.is_some()
        || (variants > 0 && segments > 0)
        || variants + segments == 0
        || !seconds.is_finite()
    {
        return Err(manifest_invalid());
    }
    Ok(json!({
        "kind":if variants > 0 {"master"} else {"media"},
        "variants":variants,"segments":segments,"duration_seconds":seconds,
        "is_live_manifest":variants == 0 && !end_list,"end_list":end_list,
        "key_declared":keys,"unsupported_features":unsupported,
        "decoder_verified":false,"media_rights_verified":false
    }))
}

pub fn schema() -> Value {
    let baseline = LiveInput {
        authorized: true,
        source: None,
        stream: None,
        playlist: None,
        credential: None,
        bounded_fetch: None,
    };
    let blocked =
        receipt(&assess(&baseline).expect("an authorized empty request is always assessable"));
    let fields = blocked
        .as_object()
        .expect("the blocked receipt is an object");
    let required: Vec<String> = fields.keys().cloned().collect();
    let mut properties = serde_json::Map::new();
    for (key, value) in fields {
        let definition = match key.as_str() {
            "blocked_reasons" => json!({
                "type":"array","minItems":1,"items":{"type":"string"},
                "description":"Every reason the live session is refused; at least the unreviewed-transport and not-implemented reasons are always present."
            }),
            "source_bound_facts_supplied" => json!({
                "type":"array","items":{"enum":[FACT_SOURCE_BINDING,FACT_STREAM,FACT_PLAYLIST,FACT_CREDENTIAL,FACT_BOUNDED_FETCH]},
                "description":"Facts the caller supplied and this module admitted structurally. Names only; no supplied value is echoed."
            }),
            "missing_source_bound_facts" => json!({
                "type":"array","items":{"enum":[FACT_SOURCE_BINDING,FACT_STREAM,FACT_PLAYLIST,FACT_CREDENTIAL]},
                "description":"Facts that were absent or did not match the reviewed source declaration."
            }),
            "bounded_fetch" => json!({
                "type":"object","additionalProperties":false,
                "required":["kind","enabled_by_default","requested","admitted","executable","executed","objects","expected_bytes"],
                "properties":{
                    "kind":{"const":"playlist_and_fragment_fetch_plan"},
                    "enabled_by_default":{"const":false},
                    "requested":{"type":"boolean"},
                    "admitted":{"type":"boolean","description":"The supplied plan is complete, exact and bounded. It is still not executable."},
                    "executable":{"const":false},
                    "executed":{"const":false},
                    "objects":{"type":"integer","minimum":0,"maximum":MAX_OBJECTS},
                    "expected_bytes":{"type":"integer","minimum":0,"maximum":MAX_PLAN_BYTES}
                }
            }),
            _ => json!({"const":value}),
        };
        properties.insert(key.clone(), definition);
    }
    json!({
        "input":{
            "type":"object","additionalProperties":false,"required":["authorized"],
            "description":"Strict object-root live session request. A positional array root, duplicate fields and a trailing document are refused before any fact is assessed. No credential value, cookie, session reference or key material is accepted anywhere in this request.",
            "properties":{
                "authorized":{"const":true,"description":"Explicit operator authorization. Missing or false is a permission refusal."},
                "source":{"type":"object","additionalProperties":false,"required":["reviewed","reference","sha256"],"properties":{
                    "reviewed":{"const":true},
                    "reference":{"type":"string","minLength":1,"maxLength":MAX_REFERENCE,"description":"Opaque label of the reviewed source snapshot; never a credential."},
                    "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"Exact digest of the reviewed source document."}
                }},
                "stream":{"type":"object","additionalProperties":false,"required":["id","protocol"],"properties":{
                    "id":{"type":"string","minLength":1,"maxLength":MAX_TOKEN,"description":"Opaque stream identity; a URL is not an identity."},
                    "protocol":{"enum":[PROTOCOL_HLS],"description":"Only the HLS dialect inspectable offline can be stated as a live protocol fact."}
                }},
                "playlist":{"type":"object","additionalProperties":false,"required":["url","sha256","live"],"properties":{
                    "url":{"type":"string","minLength":1,"maxLength":MAX_URL,"description":"Exact absolute https playlist URL as declared by the reviewed source. No userinfo, fragment, normalization alias or credential marker."},
                    "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                    "live":{"const":true,"description":"The reviewed source declares an ongoing (no EXT-X-ENDLIST) playlist."}
                }},
                "credential":{"type":"object","additionalProperties":false,"required":["method","source_bound"],"properties":{
                    "method":{"enum":["none","session_cookie"],"description":"Declared authentication method. The credential value itself is never part of this request."},
                    "source_bound":{"const":true,"description":"The reviewed source declares this method for this stream."}
                }},
                "bounded_fetch":{"type":"object","additionalProperties":false,"required":["enabled","fragments","max_bytes"],"properties":{
                    "enabled":{"type":"boolean","description":"Disabled by default; an enabled, admitted plan is still non-executable because no transport is admitted."},
                    "max_bytes":{"type":"integer","minimum":1,"maximum":MAX_PLAN_BYTES},
                    "fragments":{"type":"array","minItems":1,"maxItems":MAX_OBJECTS,"items":{
                        "type":"object","additionalProperties":false,"required":["url","sha256","bytes"],"properties":{
                            "url":{"type":"string","minLength":1,"maxLength":MAX_URL,"description":"Exact absolute https fragment URL. The same URL may repeat only for disjoint ranges."},
                            "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"Expected digest of the object or requested range."},
                            "bytes":{"type":"integer","minimum":1,"maximum":MAX_OBJECT_BYTES},
                            "range":{"type":"object","additionalProperties":false,"required":["start","end"],"properties":{
                                "start":{"type":"integer","minimum":0},
                                "end":{"type":"integer","minimum":0,"description":"Inclusive end offset; end-start+1 must equal bytes."}
                            }}
                        }
                    }}
                }}
            }
        },
        "output":{
            "type":"object","additionalProperties":false,"required":required,"properties":properties,
            "description":"Every admitted call returns this blocked envelope. The receipt reports capability honestly: implemented, transport_admitted, playback_admitted, host_allowlist_verified, network_access, credentials_read, player_started, still_following and complete are always false, and no URL, stream identifier, source reference, digest or credential is ever echoed."
        },
        "capabilities":{
            "live_streaming":{"implemented":false,"reason":REASON_NOT_IMPLEMENTED},
            "live_transport":{"admitted":false,"reason":REASON_TRANSPORT},
            "bounded_playlist_fetch":{"implemented":false,"enabled_by_default":false,"reason":REASON_FETCH_TRANSPORT},
            "offline_manifest_inspection":{"implemented":true,"description":"inspect_manifest reads supplied bytes only and admits no host, stream identity or media right."}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const HASH_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    const PLAYLIST: &str = "https://media.example.test/live/index.m3u8";
    const FRAGMENT: &str = "https://media.example.test/live/a.ts";

    fn full_request() -> String {
        format!(
            r#"{{"authorized":true,
                "source":{{"reviewed":true,"reference":"reviewed-live-source-1","sha256":"{HASH_A}"}},
                "stream":{{"id":"opaque-stream","protocol":"hls"}},
                "playlist":{{"url":"{PLAYLIST}","sha256":"{HASH_B}","live":true}},
                "credential":{{"method":"session_cookie","source_bound":true}},
                "bounded_fetch":{{"enabled":true,"max_bytes":1048576,"fragments":[
                    {{"url":"{FRAGMENT}","sha256":"{HASH_C}","bytes":4,"range":{{"start":0,"end":3}}}},
                    {{"url":"{FRAGMENT}","sha256":"{HASH_D}","bytes":4,"range":{{"start":4,"end":7}}}}
                ]}}}}"#
        )
    }

    fn request(extra: &str) -> String {
        format!(r#"{{"authorized":true{extra}}}"#)
    }

    fn reasons<Strings: AsRef<[&'static str]>>(receipt: &Value, expected: Strings) {
        let blocked = receipt["blocked_reasons"].as_array().expect("reasons");
        for reason in expected.as_ref() {
            assert!(
                blocked.iter().any(|value| value == reason),
                "missing blocked reason {reason}: {blocked:?}"
            );
        }
    }

    #[test]
    fn input_is_a_strict_object_root() {
        for malformed in [
            "",
            "not json",
            "[]",
            "[{\"authorized\":true},{\"authorized\":true}]",
            "\"authorized\"",
            "{}",
            r#"{"authorized":"yes"}"#,
            r#"{"authorized":true,"authorized":true}"#,
            r#"{"authorized":true,"cookie":"synthetic"}"#,
            r#"{"authorized":true,"session_ref":"synthetic"}"#,
            r#"{"authorized":true} {"authorized":true}"#,
            r#"{"authorized":true,"stream":{"id":"a","id":"b","protocol":"hls"}}"#,
            r#"{"authorized":true,"stream":{"id":"a","protocol":"dash"}}"#,
            r#"{"authorized":true,"source":{"reviewed":true,"reference":"r","sha256":"zz"}}"#,
            r#"{"authorized":true,"playlist":{"url":"http://media.example.test/live.m3u8","sha256":"aa","live":true}}"#,
        ] {
            assert_eq!(
                online(malformed).unwrap_err().code,
                "invalid_input",
                "admitted malformed input: {malformed}"
            );
        }
        let oversized = format!(
            r#"{{"authorized":true,"source":{{"reviewed":true,"reference":"{}","sha256":"{HASH_A}"}}}}"#,
            "a".repeat(MAX_INPUT)
        );
        assert_eq!(online(&oversized).unwrap_err().code, "invalid_input");
        // The ongoing-live declaration is a required source-bound fact, not a
        // value this module may default on the caller's behalf.
        let undeclared_live = request(&format!(
            r#","playlist":{{"url":"{PLAYLIST}","sha256":"{HASH_B}"}}"#
        ));
        assert_eq!(online(&undeclared_live).unwrap_err().code, "invalid_input");
        assert_eq!(
            online(r#"{"authorized":false}"#).unwrap_err().code,
            "permission"
        );
        // A strictly valid minimal request is admitted as a blocked receipt,
        // never as an error and never as an executed live session.
        assert!(online(r#"{"authorized":true}"#).is_ok());
    }

    #[test]
    fn complete_source_bound_facts_still_block_execution() {
        let receipt = online(&full_request()).unwrap();
        assert_eq!(receipt["result"], "blocked");
        for key in [
            "implemented",
            "implementation_complete",
            "network_access",
            "source_objects_fetched",
            "credentials_read",
            "player_started",
            "automatic_reconnect",
            "still_following",
            "complete",
            "media_rights_verified",
            "decoder_verified",
            "host_allowlist_verified",
            "transport_admitted",
            "playback_admitted",
        ] {
            assert_eq!(receipt[key], false, "{key}");
        }
        assert_eq!(receipt["reason"], REASON_NOT_IMPLEMENTED);
        assert_eq!(receipt["segment_count"], 0);
        assert_eq!(receipt["segment_bytes"], 0);
        assert_eq!(receipt["duration_seconds"], 0);
        assert_eq!(
            receipt["source_bound_facts_supplied"],
            json!([
                FACT_SOURCE_BINDING,
                FACT_STREAM,
                FACT_PLAYLIST,
                FACT_CREDENTIAL,
                FACT_BOUNDED_FETCH
            ])
        );
        assert_eq!(receipt["missing_source_bound_facts"], json!([]));
        reasons(
            &receipt,
            [
                REASON_CREDENTIAL_DELIVERY,
                REASON_FETCH_TRANSPORT,
                REASON_TRANSPORT,
                REASON_NOT_IMPLEMENTED,
            ],
        );
        let plan = &receipt["bounded_fetch"];
        assert_eq!(plan["enabled_by_default"], false);
        assert_eq!(plan["requested"], true);
        assert_eq!(plan["admitted"], true);
        assert_eq!(plan["executable"], false);
        assert_eq!(plan["executed"], false);
        assert_eq!(plan["objects"], 2);
        assert_eq!(plan["expected_bytes"], 8);
    }

    #[test]
    fn missing_and_undeclared_facts_are_named() {
        let receipt = online(&request("")).unwrap();
        assert_eq!(
            receipt["missing_source_bound_facts"],
            json!([
                FACT_SOURCE_BINDING,
                FACT_STREAM,
                FACT_PLAYLIST,
                FACT_CREDENTIAL
            ])
        );
        assert_eq!(receipt["source_bound_facts_supplied"], json!([]));
        reasons(
            &receipt,
            [
                REASON_SOURCE_MISSING,
                REASON_STREAM_MISSING,
                REASON_PLAYLIST_MISSING,
                REASON_CREDENTIAL_MISSING,
                REASON_TRANSPORT,
                REASON_NOT_IMPLEMENTED,
            ],
        );
        assert_eq!(receipt["bounded_fetch"]["requested"], false);
        assert_eq!(receipt["bounded_fetch"]["admitted"], false);
        assert_eq!(receipt["bounded_fetch"]["objects"], 0);
        assert_eq!(receipt["bounded_fetch"]["expected_bytes"], 0);

        let unreviewed = online(&request(&format!(
            r#","source":{{"reviewed":false,"reference":"r","sha256":"{HASH_A}"}}"#
        )))
        .unwrap();
        assert_eq!(
            unreviewed["missing_source_bound_facts"],
            json!([
                FACT_SOURCE_BINDING,
                FACT_STREAM,
                FACT_PLAYLIST,
                FACT_CREDENTIAL
            ])
        );
        reasons(&unreviewed, [REASON_SOURCE_UNREVIEWED]);

        let not_ongoing = online(&request(&format!(
            r#","playlist":{{"url":"{PLAYLIST}","sha256":"{HASH_B}","live":false}}"#
        )))
        .unwrap();
        assert_eq!(
            not_ongoing["missing_source_bound_facts"],
            json!([
                FACT_SOURCE_BINDING,
                FACT_STREAM,
                FACT_PLAYLIST,
                FACT_CREDENTIAL
            ])
        );
        reasons(&not_ongoing, [REASON_PLAYLIST_NOT_ONGOING]);

        let unbound = online(&request(
            r#","credential":{"method":"session_cookie","source_bound":false}"#,
        ))
        .unwrap();
        reasons(&unbound, [REASON_CREDENTIAL_UNBOUND]);
        assert!(
            !unbound["blocked_reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reason| reason == REASON_CREDENTIAL_DELIVERY)
        );

        // A cookie-free declared method needs no delivery contract.
        let cookie_free = online(&request(
            r#","credential":{"method":"none","source_bound":true}"#,
        ))
        .unwrap();
        assert!(
            cookie_free["source_bound_facts_supplied"]
                .as_array()
                .unwrap()
                .iter()
                .any(|fact| fact == FACT_CREDENTIAL)
        );
        assert!(
            !cookie_free["blocked_reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reason| reason == REASON_CREDENTIAL_DELIVERY)
        );
    }

    #[test]
    fn bounded_plan_is_disabled_by_default() {
        let absent = online(&request("")).unwrap();
        assert_eq!(absent["bounded_fetch"]["requested"], false);
        assert_eq!(absent["bounded_fetch"]["admitted"], false);

        let disabled = online(&request(&format!(
            r#","bounded_fetch":{{"enabled":false,"max_bytes":16,"fragments":[{{"url":"{FRAGMENT}","sha256":"{HASH_C}","bytes":4}}]}}"#
        )))
        .unwrap();
        assert_eq!(disabled["bounded_fetch"]["requested"], false);
        assert_eq!(disabled["bounded_fetch"]["admitted"], false);
        assert_eq!(disabled["bounded_fetch"]["objects"], 0);
        assert!(
            !disabled["blocked_reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reason| reason == REASON_FETCH_TRANSPORT)
        );
        assert!(
            !disabled["source_bound_facts_supplied"]
                .as_array()
                .unwrap()
                .iter()
                .any(|fact| fact == FACT_BOUNDED_FETCH)
        );
    }

    #[test]
    fn bounded_plan_must_be_exact_and_bounded() {
        let plan = |fragments: &str, max: u64| {
            request(&format!(
                r#","playlist":{{"url":"{PLAYLIST}","sha256":"{HASH_B}","live":true}},"bounded_fetch":{{"enabled":true,"max_bytes":{max},"fragments":[{fragments}]}}"#
            ))
        };
        let one = format!(r#"{{"url":"{FRAGMENT}","sha256":"{HASH_C}","bytes":4}}"#);

        // A complete, exact plan is admitted structurally but not executable.
        let admitted = online(&plan(&one, 64)).unwrap();
        assert_eq!(admitted["bounded_fetch"]["admitted"], true);
        assert_eq!(admitted["bounded_fetch"]["executable"], false);

        let mut over_objects = Vec::new();
        for index in 0..=MAX_OBJECTS {
            over_objects.push(format!(
                r#"{{"url":"https://media.example.test/live/{index}.ts","sha256":"{HASH_C}","bytes":1}}"#
            ));
        }
        for malformed in [
            plan("", 64),
            plan(&one, 0),
            plan(&one, MAX_PLAN_BYTES + 1),
            // Total expected bytes exceed the declared plan budget.
            plan(&one, 3),
            // Range length must equal the expected byte count.
            plan(
                &format!(
                    r#"{{"url":"{FRAGMENT}","sha256":"{HASH_C}","bytes":5,"range":{{"start":0,"end":3}}}}"#
                ),
                64,
            ),
            // Inverted and non-positive ranges.
            plan(
                &format!(
                    r#"{{"url":"{FRAGMENT}","sha256":"{HASH_C}","bytes":1,"range":{{"start":4,"end":3}}}}"#
                ),
                64,
            ),
            // The same whole object twice, and overlapping ranges.
            plan(&format!("{one},{one}"), 64),
            plan(
                &format!(
                    r#"{{"url":"{FRAGMENT}","sha256":"{HASH_C}","bytes":4,"range":{{"start":0,"end":3}}}},{{"url":"{FRAGMENT}","sha256":"{HASH_D}","bytes":2,"range":{{"start":3,"end":4}}}}"#
                ),
                64,
            ),
            // Digest and byte length are mandatory facts.
            plan(&format!(r#"{{"url":"{FRAGMENT}","bytes":4}}"#), 64),
            plan(
                &format!(r#"{{"url":"{FRAGMENT}","sha256":"{HASH_C}"}}"#),
                64,
            ),
            plan(
                &format!(r#"{{"url":"{FRAGMENT}","sha256":"{HASH_C}","bytes":0}}"#),
                64,
            ),
            // The playlist cannot also be a fragment.
            plan(
                &format!(r#"{{"url":"{PLAYLIST}","sha256":"{HASH_C}","bytes":4}}"#),
                64,
            ),
            // Credential carriers, fragments, userinfo, plain HTTP and
            // normalized aliases are refused.
            plan(
                &format!(r#"{{"url":"{FRAGMENT}?token=abc","sha256":"{HASH_C}","bytes":4}}"#),
                64,
            ),
            plan(
                &format!(r#"{{"url":"{FRAGMENT}#frag","sha256":"{HASH_C}","bytes":4}}"#),
                64,
            ),
            plan(
                &format!(
                    r#"{{"url":"https://user:x@media.example.test/live/a.ts","sha256":"{HASH_C}","bytes":4}}"#
                ),
                64,
            ),
            plan(
                &format!(
                    r#"{{"url":"http://media.example.test/live/a.ts","sha256":"{HASH_C}","bytes":4}}"#
                ),
                64,
            ),
            plan(
                &format!(
                    r#"{{"url":"https://media.example.test/live/./a.ts","sha256":"{HASH_C}","bytes":4}}"#
                ),
                64,
            ),
            plan(
                &format!(r#"{{"url":"{FRAGMENT}","sha256":"{HASH_C}","bytes":4,"extra":1}}"#),
                64,
            ),
        ] {
            assert_eq!(
                online(&malformed).unwrap_err().code,
                "invalid_input",
                "admitted an incomplete or unbounded plan: {malformed}"
            );
        }
        let over = plan(&over_objects.join(","), MAX_PLAN_BYTES);
        assert_eq!(online(&over).unwrap_err().code, "invalid_input");
    }

    #[test]
    fn receipt_never_echoes_supplied_values() {
        let receipt = online(&full_request()).unwrap();
        let text = receipt.to_string();
        for secret in [
            PLAYLIST,
            FRAGMENT,
            "opaque-stream",
            "reviewed-live-source-1",
            HASH_A,
            HASH_B,
            HASH_C,
            HASH_D,
            "session_cookie",
        ] {
            assert!(!text.contains(secret), "receipt echoed {secret}");
        }
    }

    #[test]
    fn stop_aware_entry_matches_the_blocked_receipt() {
        let receipt = online(&full_request()).unwrap();
        assert_eq!(
            online_with_stop(&full_request(), &AtomicBool::new(true)).unwrap(),
            receipt
        );
        assert_eq!(
            online_with_stop(&full_request(), &AtomicBool::new(false)).unwrap(),
            receipt
        );
    }

    #[test]
    fn schema_matches_the_receipt_and_admits_no_capability() {
        let schema = schema();
        let receipt = online(&request("")).unwrap();
        let keys: Vec<&str> = receipt
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let required: Vec<&str> = schema["output"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(required, keys);
        assert_eq!(schema["output"]["additionalProperties"], false);
        assert_eq!(schema["output"]["properties"]["result"]["const"], "blocked");
        assert_eq!(
            schema["output"]["properties"]["implemented"]["const"],
            false
        );
        assert_eq!(
            schema["output"]["properties"]["transport_admitted"]["const"],
            false
        );
        assert_eq!(
            schema["output"]["properties"]["bounded_fetch"]["properties"]["executable"]["const"],
            false
        );
        assert_eq!(
            schema["output"]["properties"]["bounded_fetch"]["properties"]["enabled_by_default"]["const"],
            false
        );
        assert_eq!(
            schema["output"]["properties"]["blocked_reasons"]["items"]["type"],
            "string"
        );
        assert_eq!(schema["input"]["additionalProperties"], false);
        assert_eq!(schema["input"]["required"], json!(["authorized"]));
        assert_eq!(
            schema["capabilities"]["live_streaming"]["implemented"],
            false
        );
        assert_eq!(schema["capabilities"]["live_transport"]["admitted"], false);
        assert_eq!(
            schema["capabilities"]["bounded_playlist_fetch"]["enabled_by_default"],
            false
        );
        // No endpoint, playlist or host is invented by the schema either.
        let text = schema.to_string();
        assert!(!text.contains("://"), "schema contains a URL: {text}");
    }

    #[test]
    fn manifest_analysis_and_key_disclosure() {
        let master =
            inspect_manifest(b"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=100\nlow.m3u8\n").unwrap();
        assert_eq!(master["variants"], 1);
        let media = inspect_manifest(b"#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=\"key\"\n#EXTINF:2.5,\na.ts\n#EXTINF:3,\nb.ts\n").unwrap();
        assert_eq!(media["segments"], 2);
        assert_eq!(media["duration_seconds"], 5.5);
        assert_eq!(media["key_declared"], true);
        assert_eq!(media["unsupported_features"], true);
        assert_eq!(media["is_live_manifest"], true);
        assert_eq!(media["decoder_verified"], false);
        assert!(inspect_manifest(b"#EXTM3U\n#EXTINF:2,\n").is_err());
        let oversized = vec![b'a'; MAX_MANIFEST_BYTES + 1];
        assert!(inspect_manifest(&oversized).is_err());
    }
}
