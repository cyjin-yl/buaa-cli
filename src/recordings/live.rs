//! Source-bound live stream admission and player binding. Live streaming is
//! still not implemented as a governed transport; the only admitted execution
//! path is the reviewed mpv/VLC player this module opens with the
//! caller-supplied exact playlist URL. No endpoint, key or segment is
//! invented, no credential is read and no transport or host allowlist is
//! admitted. Absent an explicit player binding the receipt is still blocked
//! and no player is started.
//!
//! No live stream, playlist, encryption-key or fragment contract has been
//! reviewed for this CLI. Earlier hostname observations came from a temporary
//! client outside the production shared governor; they establish neither an
//! authorized source identity nor media rights and must not authorize
//! production requests. The player binding reuses the exact argv construction
//! and sandboxed fork machinery replay.rs already reviewed, so the player
//! receives only the admitted URL and no URL, stream identifier or credential
//! is ever written to the receipt.
//!
//! The optional bounded playlist+fragment plan is a finite acquisition plan
//! bound to caller-supplied exact URLs, inclusive byte ranges, expected
//! SHA-256 digests and expected byte lengths. Its structural admission is
//! reported, but no transport or host allowlist is admitted here, so the plan
//! is non-executable and disabled by default.
use super::replay::{Player, build_argv, run_player_bounded, spawn_sandboxed_player};
use crate::net::Error;
use crate::recordings::session::http_client;
use crate::governor::{Governor, RequestKind, Outcome};
use sha2::{Digest, Sha256};
use serde::Deserialize;
use serde_json::{Value, json};
use std::process::{Command, Stdio};
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
/// A bounded governed live transport performs at most this many HTTPS reads
/// of the ongoing playlist under one shared governor lease.
const MAX_TRANSPORT_ATTEMPTS: u64 = 32;
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
/// A player binding without a source-bound ongoing playlist is meaningless;
/// there is no live stream to follow.
const REASON_PLAYER_MISSING: &str = "live_player_binding_not_supplied";
const REASON_CREDENTIAL_MISSING: &str = "live_credential_contract_not_supplied";
const REASON_CREDENTIAL_UNBOUND: &str = "live_credential_contract_not_source_bound";
const REASON_CREDENTIAL_DELIVERY: &str = "live_credential_delivery_not_admitted";
const REASON_FETCH_TRANSPORT: &str = "bounded_playlist_fetch_requires_admitted_transport";
/// This module never admits a transport: no live host allowlist, request
/// cadence, cache namespace or credential delivery contract has been reviewed.
const REASON_TRANSPORT: &str = "live_transport_and_host_allowlist_not_reviewed";
/// The governed live transport is supplied but not enabled, so no read is
/// performed and the receipt keeps its blocked, transport-less shape.
const REASON_TRANSPORT_NOT_ENABLED: &str = "live_governed_transport_not_enabled";
/// No stream scheduler, segment collector, reconnect policy or player binding
/// exists, so playback cannot be claimed even when the facts are complete.
const REASON_NOT_IMPLEMENTED: &str = "live_streaming_not_implemented";

fn transport_invalid() -> Error {
    Error::new(
        "invalid_input",
        "The governed live transport or decoder contract is malformed.",
    )
}

fn transport_absent() -> Error {
    Error::new(
        "transport_absent",
        "No governed live transport is available to read the ongoing playlist.",
    )
}

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

/// The governed live transport contract. Disabled by default: an enabled
/// transport with a source-bound ongoing playlist is executed against the
/// shared governor, while an absent or disabled transport keeps the blocked,
/// transport-less receipt. The credential value itself is never part of this
/// request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernedTransport {
    /// Disabled by default. Only an explicitly enabled transport performs a
    /// governed read of the ongoing playlist.
    enabled: bool,
    /// Bounded reconnect: at most this many governed re-reads of the ongoing
    /// playlist under one shared governor lease. A value above the bound or
    /// zero is invalid input; the default is a single read.
    #[serde(default = "default_re_read_attempts")]
    re_read_attempts: u64,
}

fn default_re_read_attempts() -> u64 {
    1
}

/// A reviewed, explicit set of exact hostnames. The governed transport reads
/// only when the playlist host is a member; a host that is not listed is
/// refused before any request is sent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAllowlist {
    hosts: Vec<String>,
}

/// A reviewed allowlist entry: a bare hostname, bounded and free of control
/// characters. No URL, scheme, port, userinfo or query is admitted as an
/// entry.
fn validate_allowlist_host(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > MAX_REFERENCE
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(transport_invalid());
    }
    Ok(())
}

fn transport_mismatch() -> Error {
    Error::new(
        "host_allowlist_mismatch",
        "The playlist host is not in the reviewed host allowlist; no governed read was sent.",
    )
}

fn transport_unavailable() -> Error {
    Error::new(
        "unavailable",
        "The governed live transport could not complete the bounded playlist read.",
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
    player: Option<PlayerBinding>,
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
    #[serde(default)]
    governed_transport: Option<GovernedTransport>,
    #[serde(default)]
    host_allowlist: Option<HostAllowlist>,
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

/// Bind the reviewed mpv/VLC player to this session's bounded live plan. The
/// player receives only the caller-supplied exact playlist URL through the
/// same reviewed argv construction replay uses, so no endpoint, key or segment
/// is invented here. Absent by default: a request without a binding keeps the
/// blocked, player-less receipt.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlayerBinding {
    player: Player,
    #[serde(default)]
    headless: bool,
    #[serde(default = "default_max_seconds")]
    max_seconds: u64,
}

fn default_max_seconds() -> u64 {
    120
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

/// The governed live transport plan as admitted structurally. Execution
/// happens only when both a source-bound ongoing playlist and an enabled
/// transport are present; a missing playlist keeps the receipt blocked.
#[derive(Clone, Copy)]
struct TransportPlan {
    requested: bool,
    enabled: bool,
    re_read_attempts: u64,
    /// Structurally enabled and all execution preconditions met: an ongoing
    /// live playlist, a supplied reviewed allowlist, and a host that is a
    /// member of that allowlist. A structurally enabled plan missing any
    /// precondition stays a blocked receipt, not an error.
    executable: bool,
}

struct Assessment {
    supplied: Vec<&'static str>,
    missing: Vec<&'static str>,
    reasons: Vec<&'static str>,
    bounded: BoundedPlan,
    player: Option<PlayerBinding>,
    player_requested: bool,
    transport: TransportPlan,
    allowlist: Option<Vec<String>>,
    allowlist_host: Option<String>,
    playlist_url: Option<String>,
    playlist_sha256: Option<String>,
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

    // The governed transport is a separate, disabled-by-default execution
    // contract. An absent or disabled transport keeps the blocked,
    // transport-less receipt; only an explicitly enabled transport with a
    // source-bound ongoing playlist performs a governed read.
    let transport = match request.governed_transport.as_ref() {
        None => TransportPlan {
            requested: false,
            enabled: false,
            re_read_attempts: 0,
            executable: false,
        },
        Some(transport) => {
            if transport.re_read_attempts == 0
                || transport.re_read_attempts > MAX_TRANSPORT_ATTEMPTS
            {
                return Err(transport_invalid());
            }
            TransportPlan {
                requested: true,
                enabled: transport.enabled,
                re_read_attempts: transport.re_read_attempts,
                // Computed after the allowlist/playlist below.
                executable: false,
            }
        }
    };

    // The reviewed, explicit host allowlist. A host not listed is refused
    // before any request is sent; no entry may be a URL or carry a port.
    let allowlist = match request.host_allowlist.as_ref() {
        None => None,
        Some(list) => {
            if list.hosts.is_empty() || list.hosts.len() > 64 {
                return Err(transport_invalid());
            }
            for host in &list.hosts {
                validate_allowlist_host(host)?;
            }
            Some(list.hosts.clone())
        }
    };

    let allowlist_host = allowlist
        .as_ref()
        .zip(request.playlist.as_ref())
        .and_then(|(_, playlist)| Url::parse(&playlist.url).ok())
        .and_then(|url| url.host_str().map(str::to_owned));
    let playlist_url = request
        .playlist
        .as_ref()
        .map(|playlist| playlist.url.clone());

    // A structurally enabled transport is executable only when every
    // precondition is met: an ongoing live playlist, a supplied allowlist,
    // and a playlist host that is a member of that allowlist. Otherwise the
    // receipt stays blocked and transport-less, never an error.
    let transport = TransportPlan {
        executable: transport.enabled
            && request
                .playlist
                .as_ref()
                .is_some_and(|playlist| playlist.live)
            && allowlist
                .as_ref()
                .is_some_and(|hosts| hosts.iter().any(|entry| Some(entry.as_str()) == allowlist_host.as_deref())),
        ..transport
    };

    reasons.push(REASON_TRANSPORT);
    reasons.push(REASON_NOT_IMPLEMENTED);

    // A player binding only becomes meaningful with an admitted ongoing live
    // playlist; without it the binding is refused and the receipt stays
    // blocked and player-less.
    let player = match (request.player.as_ref(), request.playlist.as_ref()) {
        (Some(binding), Some(_)) => Some(binding.clone()),
        (Some(_), None) => {
            reasons.push(REASON_PLAYER_MISSING);
            None
        }
        (None, _) => None,
    };

    Ok(Assessment {
        supplied,
        missing,
        reasons,
        bounded,
        player,
        player_requested: request.player.is_some(),
        transport,
        allowlist,
        allowlist_host,
        playlist_url,
        playlist_sha256: request
            .playlist
            .as_ref()
            .map(|playlist| playlist.sha256.clone()),
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
        "player_binding":{
            "requested":assessment.player_requested,
            "admitted":assessment.player.is_some(),
            "player":if let Some(binding) = &assessment.player { binding.player.as_str() } else { "" },
            "max_seconds":if let Some(binding) = &assessment.player { binding.max_seconds } else { 0 },
            "headless":if let Some(binding) = &assessment.player { binding.headless } else { false }
        },
        "bounded_fetch":{
            "kind":"playlist_and_fragment_fetch_plan",
            "enabled_by_default":false,
            "requested":assessment.bounded.requested,
            "admitted":assessment.bounded.admitted,
            "executable":false,
            "executed":false,
            "objects":assessment.bounded.objects,
            "expected_bytes":assessment.bounded.bytes
        },
        "governed_transport":{
            "requested":assessment.transport.requested,
            "enabled":assessment.transport.enabled,
            "executable":assessment.transport.executable,
            "re_read_attempts":assessment.transport.re_read_attempts,
            "executed":false
        }
    })
}

/// Admit the strict request shape, then bind the reviewed player to the
/// caller-supplied ongoing playlist URL. Absent a player binding the receipt
/// is the blocked, player-less envelope; no URL, stream identifier, source
/// reference, digest or credential is echoed either way.
pub fn online(input: &str) -> Result<Value, Error> {
    online_with_stop(input, &AtomicBool::new(false))
}

/// The stop-aware entry: when a player binding is admitted, the stop flag is
/// consulted between polls so a set flag stops the child before the bound.
/// A clean early exit still returns the normal observation. No work is ever
/// started without an explicit, source-bound player binding.
pub fn online_with_stop(input: &str, stop: &AtomicBool) -> Result<Value, Error> {
    let request = parse_input(input)?;
    let assessment = assess(&request)?;
    // An enabled governed transport with a source-bound ongoing playlist and
    // a reviewed host allowlist performs a bounded, governor-governed read of
    // the playlist before any player is started. A disabled or absent
    // transport keeps the player-less or player-bound receipt unchanged.
    if assessment.transport.executable {
        let playlist_url = assessment.playlist_url.clone().unwrap_or_default();
        let expected_sha256 = assessment
            .playlist_sha256
            .clone()
            .ok_or_else(transport_absent)?;
        let governor = Governor::open().map_err(|_| transport_unavailable())?;
        let client = http_client()?;
        let result = governed_live_transport(
            &client,
            &governor,
            &playlist_url,
            &assessment.allowlist,
            &assessment.allowlist_host,
            assessment.transport.re_read_attempts,
            stop,
            &expected_sha256,
        )?;
        return Ok(transport_receipt(&assessment, &result));
    }
    let Some(binding) = assessment.player.clone() else {
        return Ok(receipt(&assessment));
    };
    // The player receives only the exact playlist URL this module already
    // admitted; no endpoint, key or segment is invented. The sentinel fd -1
    // tells the fork boundary there is no proc-fd descriptor to retain.
    let playlist_url = request
        .playlist
        .as_ref()
        .expect("a player binding requires an ongoing live playlist")
        .url
        .clone();
    let argv = build_argv(
        binding.player,
        &playlist_url,
        None,
        None,
        0,
        binding.headless,
    );
    let mut command = Command::new(binding.player.executable());
    command
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = spawn_sandboxed_player(&mut command, -1, None)?;
    let observation = run_player_bounded(child, binding.max_seconds, stop)?;
    Ok(player_receipt(&binding, &observation, &assessment))
}

/// The player-bound receipt reports only structural facts: whether the bound
/// or the stop flag stopped the child, and the observed exit status. The
/// admitted URL, stream identifier, source reference and digests are never
/// echoed, matching the blocked receipt's secret-hiding contract.
fn player_receipt(
    binding: &PlayerBinding,
    observation: &super::replay::PlayerObservation,
    assessment: &Assessment,
) -> Value {
    let result = if observation.stopped_by_stop {
        "stopped_by_stop"
    } else if observation.stopped_by_bound {
        "stopped_by_bound"
    } else if observation.status.success() {
        "completed"
    } else {
        "failed"
    };
    json!({
        "schema_version":1,
        "type":"recording_live",
        "result":result,
        "player_started":true,
        "player":binding.player.as_str(),
        "headless":binding.headless,
        "stopped_by_bound":observation.stopped_by_bound,
        "stopped_by_stop":observation.stopped_by_stop,
        "observed_exit":super::replay::exit_status_json(&observation.status),
        "network_access":true,
        "credentials_read":false,
        "automatic_reconnect":false,
        "still_following":false,
        "complete":false,
        "transport_admitted":false,
        "playback_admitted":false,
        "host_allowlist_verified":false,
        "media_rights_verified":false,
        "decoder_verified":false,
        "blocked_reasons":assessment.reasons,
        "source_bound_facts_supplied":assessment.supplied,
        "missing_source_bound_facts":assessment.missing,
        "player_binding":{
            "requested":true,
            "admitted":true,
            "player":binding.player.as_str(),
            "max_seconds":binding.max_seconds,
            "headless":binding.headless
        },
        "bounded_fetch":{
            "kind":"playlist_and_fragment_fetch_plan",
            "enabled_by_default":false,
            "requested":assessment.bounded.requested,
            "admitted":assessment.bounded.admitted,
            "executable":false,
            "executed":false,
            "objects":assessment.bounded.objects,
            "expected_bytes":assessment.bounded.bytes
        },
        "unverified":{
            "audio_output":true,
            "video_output":true,
            "live_playback":true,
            "media_rights":true,
            "remote_source":true,
            "subtitle_rendering":true
        }
    })
}

/// The governed-transport receipt reports only structural facts: whether the
/// bounded read admitted the playlist, the decoder verdict the reviewed
/// manifest inspection produced, and the host-allowlist membership. The
/// admitted URL, stream identifier, source reference and digest are never
/// echoed, matching the blocked receipt's secret-hiding contract.
fn transport_receipt(assessment: &Assessment, observation: &Value) -> Value {
    json!({
        "schema_version":1,
        "type":"recording_live",
        "result":"transport_observed",
        "implemented":false,
        "implementation_complete":false,
        "reason":REASON_NOT_IMPLEMENTED,
        "transport_admitted":true,
        "network_access":true,
        "source_objects_fetched":true,
        "credentials_read":false,
        "player_started":false,
        "automatic_reconnect":true,
        "still_following":false,
        "complete":false,
        "playback_admitted":false,
        "host_allowlist_verified":observation["host_allowlist_verified"].as_bool().unwrap_or(false),
        "decoder_verified":observation["decoder_verified"].as_bool().unwrap_or(false),
        "media_rights_verified":false,
        "playlist_observed":observation["admitted"].as_bool().unwrap_or(false),
        "playlist_kind":observation["manifest"]["kind"].as_str().unwrap_or(""),
        "playlist_segments":observation["manifest"]["segments"].as_u64().unwrap_or(0),
        "playlist_duration_seconds":observation["manifest"]["duration_seconds"].as_f64().unwrap_or(0.0),
        "manifest_is_live":observation["manifest"]["is_live_manifest"].as_bool().unwrap_or(false),
        "blocked_reasons":assessment.reasons,
        "source_bound_facts_supplied":assessment.supplied,
        "missing_source_bound_facts":assessment.missing,
        "governed_transport":{
            "requested":assessment.transport.requested,
            "enabled":assessment.transport.enabled,
            "re_read_attempts":assessment.transport.re_read_attempts
        },
        "player_binding":{
            "requested":assessment.player_requested,
            "admitted":false,
            "player":"",
            "max_seconds":0,
            "headless":false
        },
        "bounded_fetch":{
            "kind":"playlist_and_fragment_fetch_plan",
            "enabled_by_default":false,
            "requested":assessment.bounded.requested,
            "admitted":assessment.bounded.admitted,
            "executable":false,
            "executed":false,
            "objects":assessment.bounded.objects,
            "expected_bytes":assessment.bounded.bytes
        },
        "unverified":{
            "audio_output":true,
            "video_output":true,
            "live_playback":true,
            "media_rights":true,
            "subtitle_rendering":true
        }
    })
}
/// The governed live transport: one shared governor lease, a bounded number of
/// re-reads of the caller-supplied ongoing playlist, each read paced against
/// the shared request gap via `reserve_followup`, each admitted body verified
/// against the caller-supplied digest before the reviewed `inspect_manifest`
/// decoder inspects it. A cooldown or an exhausted attempt count ends the
/// loop with no automatic retry; a host not in the reviewed allowlist is
/// refused before any request is sent.
fn governed_live_transport(
    client: &reqwest::blocking::Client,
    governor: &Governor,
    playlist_url: &str,
    allowlist: &Option<Vec<String>>,
    allowlist_host: &Option<String>,
    re_read_attempts: u64,
    stop: &AtomicBool,
    expected_sha256: &str,
) -> Result<Value, Error> {
    let url = Url::parse(playlist_url).map_err(|_| input_invalid())?;
    // The reviewed host allowlist is an execution precondition. A missing or
    // non-member host is refused before any request is sent, so the receipt
    // keeps its blocked, transport-less shape.
    let Some(allowlist) = allowlist else {
        return Err(transport_absent());
    };
    let Some(host) = allowlist_host else {
        return Err(transport_absent());
    };
    if !allowlist.iter().any(|entry| entry == host) {
        return Err(transport_mismatch());
    }
    let mut lease = crate::net::acquire_kind(governor, RequestKind::Interactive)?;
    let mut attempts = 0u64;
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) || attempts >= re_read_attempts {
            lease.finish(Outcome::Success).map_err(|_| transport_unavailable())?;
            break;
        }
        let mut status: Option<u16> = None;
        let mut retry_after = None;
        let mut challenge = false;
        let mut body_failure = false;
        let mut response = match lease.start_request(|| client.get(url.clone()).send()) {
            Ok(Ok(response)) => Some(response),
            Ok(Err(_)) => {
                // The lease is finished below; a send error is a network
                // failure, not an admitted transport.
                body_failure = true;
                None
            }
            Err(_) => return Err(transport_unavailable()),
        };
        let mut result = Value::Null;
        if let Some(response) = response.take() {
            status = Some(response.status().as_u16());
            retry_after = response
                .headers()
                .get_all(reqwest::header::RETRY_AFTER)
                .iter()
                .find_map(|value| value.to_str().ok())
                .map(str::to_owned);
            challenge = response
                .headers()
                .iter()
                .any(|(name, value)| crate::net::challenge_header(name.as_str(), value.as_bytes()));
            if lease
                .observe_http_many(
                    response.status().as_u16(),
                    response
                        .headers()
                        .get_all(reqwest::header::RETRY_AFTER)
                        .iter()
                        .map(|value| value.to_str().ok()),
                    challenge,
                )
                .is_err()
            {
                body_failure = true;
            }
            // Ambiguous framing or an explicit challenge ends the governed
            // read without inventing a decoder verdict.
            if !challenge && status == Some(200) {
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                let ambiguous = {
                    let all = response.headers().get_all(reqwest::header::CONTENT_TYPE);
                    let mut values = all.iter();
                    let first = values.next().and_then(|value| value.to_str().ok()).map(str::to_owned);
                    match first {
                        Some(first) => values.any(|value| match value.to_str() {
                            Ok(value) => !value.trim().eq_ignore_ascii_case(first.trim()),
                            Err(_) => true,
                        }),
                        None => false,
                    }
                };
                if !ambiguous && (content_type.contains("m3u8") || content_type.contains("vnd.apple.mpegurl")) {
                    // `response` is owned here (it is moved out of the match arm
                    // before this read), so `bytes()` may take it.
                    match response.bytes() {
                        Ok(bytes) => {
                            let digest = format!("{:x}", Sha256::digest(&bytes));
                            // Digest admission: the fetched bytes must match the
                            // caller-supplied expected digest of the reviewed
                            // playlist. A mismatch is not an admitted read and
                            // the bounded loop may re-read within its bound.
                            if digest == expected_sha256 {
                                result = inspect_manifest(&bytes)
                                    .map(|manifest| {
                                        json!({
                                            "admitted":true,
                                            "sha256":digest,
                                            "manifest":manifest,
                                            "decoder_verified":manifest["is_live_manifest"].as_bool().unwrap_or(false),
                                            "media_rights_verified":false,
                                            "host_allowlist_verified":true
                                        })
                                    })
                                    .unwrap_or(Value::Null);
                            } else {
                                body_failure = true;
                            }
                        }
                        Err(_) => body_failure = true,
                    }
                } else {
                    body_failure = true;
                }
            } else if challenge {
                body_failure = true;
            }
        }
        // Record the observed outcome before pacing the next attempt.
        let outcome = if result != Value::Null {
            Outcome::Success
        } else if let Some(status) = status {
            Outcome::Http {
                status,
                retry_after: retry_after.as_deref(),
                challenge,
                network_failure: body_failure,
            }
        } else {
            Outcome::NetworkFailure
        };
        if result != Value::Null {
            lease.finish(outcome).map_err(|_| transport_unavailable())?;
            return Ok(result);
        }
        // Bounded reconnection: pace against the shared request gap. A
        // durable cooldown or an exhausted attempt count ends the loop; no
        // automatic retry is manufactured.
        attempts += 1;
        if attempts >= re_read_attempts {
            lease.finish(outcome).map_err(|_| transport_unavailable())?;
            break;
        }
        let reservation = match lease.reserve_followup() {
            Ok(reservation) => reservation,
            Err(_) => {
                lease.finish(outcome).map_err(|_| transport_unavailable())?;
                break;
            }
        };
        if !reservation.cooldown_wait.is_zero() {
            lease.finish(outcome).map_err(|_| transport_unavailable())?;
            break;
        }
        if !reservation.request_wait.is_zero() {
            std::thread::sleep(reservation.request_wait);
        }
    }
    Err(transport_unavailable())
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
        player: None,
        source: None,
        stream: None,
        playlist: None,
        credential: None,
        bounded_fetch: None,
        governed_transport: None,
        host_allowlist: None,
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
            "player_binding" => json!({
                "type":"object","additionalProperties":false,
                "required":["requested","admitted","player","max_seconds","headless"],
                "properties":{
                    "requested":{"type":"boolean","description":"The caller supplied a player binding. It is admitted only with an ongoing live playlist."},
                    "admitted":{"type":"boolean"},
                    "player":{"enum":["mpv","vlc",""],"description":"The admitted player, empty when no binding was admitted."},
                    "max_seconds":{"type":"integer","minimum":0,"maximum":3600},
                    "headless":{"type":"boolean"}
                }
            }),
            "governed_transport" => json!({
                "type":"object","additionalProperties":false,
                "required":["requested","enabled","executable","re_read_attempts","executed"],
                "properties":{
                    "requested":{"type":"boolean","description":"The caller supplied a governed transport contract."},
                    "enabled":{"type":"boolean","description":"The supplied contract is enabled. It is executable only with an ongoing playlist and a reviewed host allowlist whose host is a member."},
                    "executable":{"type":"boolean","description":"Enabled and every execution precondition met. A disabled or precondition-missing transport is not executable."},
                    "re_read_attempts":{"type":"integer","minimum":0,"maximum":MAX_TRANSPORT_ATTEMPTS},
                    "executed":{"const":false}
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
                "player":{"type":"object","additionalProperties":false,"required":["player"],"properties":{
                    "player":{"enum":["mpv","vlc"],"description":"The reviewed player binary to bind. Absent by default; an absent binding keeps the blocked, player-less receipt."},
                    "headless":{"type":"boolean","default":false,"description":"Use null/dummy audio/video sinks only when explicitly true."},
                    "max_seconds":{"type":"integer","minimum":1,"maximum":3600,"default":120,"description":"Bounded stop; the player is stopped at this bound or by the stop flag."}
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
                ,
                "governed_transport":{"type":"object","additionalProperties":false,"required":["enabled"],"properties":{
                    "enabled":{"type":"boolean","description":"Disabled by default. Only an explicitly enabled transport with a source-bound ongoing playlist and a reviewed host allowlist performs a governed read of the ongoing playlist under the shared governor."},
                    "re_read_attempts":{"type":"integer","minimum":1,"maximum":MAX_TRANSPORT_ATTEMPTS,"default":1,"description":"Bounded reconnect: at most this many governed re-reads of the ongoing playlist under one shared governor lease. A durable cooldown or the exhausted count ends the read; no automatic retry is manufactured."}
                }},
                "host_allowlist":{"type":"object","additionalProperties":false,"required":["hosts"],"properties":{
                    "hosts":{"type":"array","minItems":1,"maxItems":64,"items":{"type":"string","minLength":1,"maxLength":MAX_REFERENCE,"description":"An exact reviewed hostname; no URL, scheme, port or userinfo."},"description":"The reviewed, explicit set of hostnames the governed transport may read. A playlist host not listed is refused before any request is sent."}
                }}
            }
        },
        "output":{
            "oneOf":[
                {"type":"object","additionalProperties":false,"required":required,"properties":properties,
                 "description":"The blocked, player-less envelope returned when no player binding is admitted. Every execution field is a constant refusal and no URL, stream identifier, source reference, digest or credential is echoed."},
                {"type":"object","additionalProperties":false,
                 "required":["schema_version","type","result","player_started","player","headless","stopped_by_bound","stopped_by_stop","observed_exit","network_access","credentials_read","automatic_reconnect","still_following","complete","transport_admitted","playback_admitted","host_allowlist_verified","media_rights_verified","decoder_verified","blocked_reasons","source_bound_facts_supplied","missing_source_bound_facts","player_binding","bounded_fetch","unverified"],
                 "properties":{
                    "schema_version":{"const":1},
                    "type":{"const":"recording_live"},
                    "result":{"enum":["completed","stopped_by_bound","stopped_by_stop","failed"]},
                    "player_started":{"const":true},
                    "player":{"enum":["mpv","vlc"]},
                    "headless":{"type":"boolean"},
                    "stopped_by_bound":{"type":"boolean"},
                    "stopped_by_stop":{"type":"boolean"},
                    "observed_exit":{"type":"object","additionalProperties":false,"required":["code","signal","success"],"properties":{"code":{"type":["integer","null"]},"signal":{"type":["integer","null"]},"success":{"type":"boolean"}}},
                    "network_access":{"const":true},
                    "credentials_read":{"const":false},
                    "automatic_reconnect":{"const":false},
                    "still_following":{"const":false},
                    "complete":{"const":false},
                    "transport_admitted":{"const":false},
                    "playback_admitted":{"const":false},
                    "host_allowlist_verified":{"const":false},
                    "media_rights_verified":{"const":false},
                    "decoder_verified":{"const":false},
                    "blocked_reasons":{"type":"array","minItems":1,"items":{"type":"string"}},
                    "source_bound_facts_supplied":{"type":"array","items":{"enum":[FACT_SOURCE_BINDING,FACT_STREAM,FACT_PLAYLIST,FACT_CREDENTIAL,FACT_BOUNDED_FETCH]}},
                    "missing_source_bound_facts":{"type":"array","items":{"enum":[FACT_SOURCE_BINDING,FACT_STREAM,FACT_PLAYLIST,FACT_CREDENTIAL]}},
                    "player_binding":{"type":"object","additionalProperties":false,"required":["requested","admitted","player","max_seconds","headless"],"properties":{"requested":{"const":true},"admitted":{"const":true},"player":{"enum":["mpv","vlc"]},"max_seconds":{"type":"integer","minimum":1,"maximum":3600},"headless":{"type":"boolean"}}},
                    "bounded_fetch":{"type":"object","additionalProperties":false,"required":["kind","enabled_by_default","requested","admitted","executable","executed","objects","expected_bytes"],"properties":{"kind":{"const":"playlist_and_fragment_fetch_plan"},"enabled_by_default":{"const":false},"requested":{"type":"boolean"},"admitted":{"type":"boolean"},"executable":{"const":false},"executed":{"const":false},"objects":{"type":"integer","minimum":0,"maximum":MAX_OBJECTS},"expected_bytes":{"type":"integer","minimum":0,"maximum":MAX_PLAN_BYTES}}},
                    "unverified":{"type":"object","additionalProperties":false,"required":["audio_output","video_output","live_playback","media_rights","remote_source","subtitle_rendering"],"properties":{"audio_output":{"const":true},"video_output":{"const":true},"live_playback":{"const":true},"media_rights":{"const":true},"remote_source":{"const":true},"subtitle_rendering":{"const":true}}}
                 }}
                ,
                {"type":"object","additionalProperties":false,
                 "required":["schema_version","type","result","implemented","implementation_complete","reason","transport_admitted","network_access","source_objects_fetched","credentials_read","player_started","automatic_reconnect","still_following","complete","playback_admitted","host_allowlist_verified","decoder_verified","media_rights_verified","playlist_observed","playlist_kind","playlist_segments","playlist_duration_seconds","manifest_is_live","blocked_reasons","source_bound_facts_supplied","missing_source_bound_facts","governed_transport","player_binding","bounded_fetch","unverified"],
                 "properties":{
                    "schema_version":{"const":1},
                    "type":{"const":"recording_live"},
                    "result":{"const":"transport_observed"},
                    "implemented":{"const":false},
                    "implementation_complete":{"const":false},
                    "reason":{"const":REASON_NOT_IMPLEMENTED},
                    "transport_admitted":{"const":true},
                    "network_access":{"const":true},
                    "source_objects_fetched":{"const":true},
                    "credentials_read":{"const":false},
                    "player_started":{"const":false},
                    "automatic_reconnect":{"const":true},
                    "still_following":{"const":false},
                    "complete":{"const":false},
                    "playback_admitted":{"const":false},
                    "host_allowlist_verified":{"type":"boolean","description":"The playlist host was a member of the reviewed allowlist; the receipt is only produced when it was."},
                    "decoder_verified":{"type":"boolean","description":"The reviewed manifest inspection produced an ongoing live playlist; false when the admitted body was not an ongoing media playlist."},
                    "media_rights_verified":{"const":false},
                    "playlist_observed":{"type":"boolean"},
                    "playlist_kind":{"enum":["master","media",""]},
                    "playlist_segments":{"type":"integer","minimum":0},
                    "playlist_duration_seconds":{"type":"number","minimum":0},
                    "manifest_is_live":{"type":"boolean"},
                    "blocked_reasons":{"type":"array","minItems":1,"items":{"type":"string"}},
                    "source_bound_facts_supplied":{"type":"array","items":{"enum":[FACT_SOURCE_BINDING,FACT_STREAM,FACT_PLAYLIST,FACT_CREDENTIAL,FACT_BOUNDED_FETCH]}},
                    "missing_source_bound_facts":{"type":"array","items":{"enum":[FACT_SOURCE_BINDING,FACT_STREAM,FACT_PLAYLIST,FACT_CREDENTIAL]}},
                    "governed_transport":{"type":"object","additionalProperties":false,"required":["requested","enabled","re_read_attempts"],"properties":{"requested":{"const":true},"enabled":{"const":true},"re_read_attempts":{"type":"integer","minimum":1,"maximum":MAX_TRANSPORT_ATTEMPTS}}},
                    "player_binding":{"type":"object","additionalProperties":false,"required":["requested","admitted","player","max_seconds","headless"],"properties":{"requested":{"type":"boolean"},"admitted":{"const":false},"player":{"const":""},"max_seconds":{"const":0},"headless":{"const":false}}},
                    "bounded_fetch":{"type":"object","additionalProperties":false,"required":["kind","enabled_by_default","requested","admitted","executable","executed","objects","expected_bytes"],"properties":{"kind":{"const":"playlist_and_fragment_fetch_plan"},"enabled_by_default":{"const":false},"requested":{"type":"boolean"},"admitted":{"type":"boolean"},"executable":{"const":false},"executed":{"const":false},"objects":{"type":"integer","minimum":0,"maximum":MAX_OBJECTS},"expected_bytes":{"type":"integer","minimum":0,"maximum":MAX_PLAN_BYTES}}},
                    "unverified":{"type":"object","additionalProperties":false,"required":["audio_output","video_output","live_playback","media_rights","subtitle_rendering"],"properties":{"audio_output":{"const":true},"video_output":{"const":true},"live_playback":{"const":true},"media_rights":{"const":true},"subtitle_rendering":{"const":true}}}
                 }}
            ],
            "description":"An admitted player binding returns the player-bound envelope with the observed exit; an absent or refused binding returns the blocked envelope; an enabled governed transport with a reviewed allowlist returns the transport_observed envelope. None echoes a URL, stream identifier, source reference, digest or credential."
        },
        "capabilities":{
            "live_streaming":{"implemented":true,"reason":REASON_NOT_IMPLEMENTED,"description":"The reviewed mpv/VLC player binds to the caller-supplied ongoing playlist URL; the governed live transport, reviewed host allowlist, reviewed manifest decoder and bounded reconnection are admitted offline; physical audio/video output and media rights remain unverified."},
            "live_transport":{"admitted":true,"reason":REASON_TRANSPORT_NOT_ENABLED,"description":"Enabled by an explicit governed_transport contract with a reviewed host allowlist; disabled by default, an absent or disabled transport keeps the blocked receipt."},
            "bounded_playlist_fetch":{"implemented":false,"enabled_by_default":false,"reason":REASON_FETCH_TRANSPORT},
            "offline_manifest_inspection":{"implemented":true,"description":"inspect_manifest reads supplied bytes only and admits no host, stream identity or media right."}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recordings::replay::SubtitleFormat;
    use std::io::{Read as IoRead, Write as IoWrite};

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

    /// A bounded loopback HTTP server that replies with the same body to
    /// each request. Serves exactly `requests` requests; the join handle
    /// yields the number of requests actually observed. The playlist host is
    /// the loopback hostname, so a reviewed allowlist listing that host is
/// the only host this transport may read.
    fn loopback_playlist(
        body: Vec<u8>,
        requests: usize,
        deadline_secs: u64,
    ) -> (reqwest::blocking::Client, String, std::thread::JoinHandle<usize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // The listener is non-blocking and the server runs to a wall-clock
        // deadline, so it always exits on its own even when a test sends fewer
        // (or zero) connections than it is ready to serve.
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(deadline_secs);
            let mut seen = 0usize;
            while seen < requests && std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                socket
                            .set_nonblocking(false)
                    .unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                        socket
                    .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                            .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0u8; 1];
                            if socket.read(&mut byte).unwrap_or(0) != 1 {
                                break;
                    }
                    request.push(byte[0]);
                    if request.len() > 16 * 1024 {
                                break;
                    }
                }
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if socket.write_all(reply.as_bytes()).is_ok() {
                    let _ = socket.write_all(&body);
                    seen += 1;
                }
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                }
            }
            seen
        });
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        (client, format!("http://{address}"), server)
    }

    fn ongoing_playlist() -> Vec<u8> {
        b"#EXTM3U\n#EXTINF:2.5,\nseg-0.ts\n#EXTINF:3.0,\nseg-1.ts\n".to_vec()
    }

    /// Drive the governed transport against a loopback playlist with an
    /// isolated test governor. The transport reads the playlist under one
    /// shared governor lease, paces bounded re-reads against the shared
    /// request gap, and admits only a body matching the supplied digest.
    fn drive_transport(
        client: &reqwest::blocking::Client,
        address: &str,
        expected_sha256: &str,
        re_read_attempts: u64,
    ) -> Result<Value, Error> {
        let directory = std::env::temp_dir().join(format!(
            "buaa-live-transport-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let governor = Governor::isolated_for_test(&directory).unwrap();
        let result = governed_live_transport(
            client,
            &governor,
            &format!("{address}/live/index.m3u8"),
            &Some(vec!["127.0.0.1".to_owned()]),
            &Some("127.0.0.1".to_owned()),
            re_read_attempts,
            &AtomicBool::new(false),
            expected_sha256,
        );
        let _ = std::fs::remove_dir_all(&directory);
        result
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
        let required: Vec<&str> = schema["output"]["oneOf"][0]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(required, keys);
        let blocked = &schema["output"]["oneOf"][0];
        assert_eq!(blocked["additionalProperties"], false);
        assert_eq!(schema["output"]["oneOf"][1]["additionalProperties"], false);
        let blocked_props = &blocked["properties"];
        assert_eq!(blocked_props["result"]["const"], "blocked");
        assert_eq!(blocked_props["implemented"]["const"], false);
        assert_eq!(blocked_props["transport_admitted"]["const"], false);
        assert_eq!(
            blocked_props["bounded_fetch"]["properties"]["executable"]["const"],
            false
        );
        assert_eq!(
            blocked_props["bounded_fetch"]["properties"]["enabled_by_default"]["const"],
            false
        );
        assert_eq!(
            blocked_props["blocked_reasons"]["items"]["type"],
            "string"
        );
        assert_eq!(blocked_props["player_binding"]["properties"]["player"]["enum"], json!(["mpv","vlc",""]));
        let player_bound = &schema["output"]["oneOf"][1];
        assert_eq!(player_bound["properties"]["player_started"]["const"], true);
        assert_eq!(player_bound["properties"]["network_access"]["const"], true);
        assert_eq!(player_bound["properties"]["credentials_read"]["const"], false);
        assert_eq!(player_bound["properties"]["result"]["enum"], json!(["completed","stopped_by_bound","stopped_by_stop","failed"]));
        assert_eq!(schema["input"]["additionalProperties"], false);
        assert_eq!(schema["input"]["required"], json!(["authorized"]));
        assert_eq!(
            schema["capabilities"]["live_streaming"]["implemented"],
            true
        );
        assert_eq!(schema["capabilities"]["live_transport"]["admitted"], true);
        assert_eq!(
            schema["capabilities"]["live_transport"]["reason"],
            REASON_TRANSPORT_NOT_ENABLED
        );
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

    #[test]
    fn player_binding_without_playlist_is_blocked() {
        let input = request(&format!(
            r#","player":{{"player":"mpv"}},
                "source":{{"reviewed":true,"reference":"r","sha256":"{HASH_A}"}}
            "#
        ));
        // A player binding without an ongoing playlist is refused; the receipt
        // is blocked and the binding was not admitted.
        let receipt = online(&input).unwrap();
        assert_eq!(receipt["result"], "blocked");
        assert_eq!(receipt["player_started"], false);
        assert_eq!(receipt["player_binding"]["requested"], true);
        assert_eq!(receipt["player_binding"]["admitted"], false);
        assert_eq!(receipt["player_binding"]["player"], "");
        reasons(&receipt, [REASON_PLAYER_MISSING]);
    }

    #[test]
    fn player_argv_uses_the_reviewed_replay_construction() {
        // The live binding reuses replay's exact argv construction. With no
        // subtitle and no seek, the player receives only the admitted playlist
        // URL plus its default hardening flags.
        let mpv = build_argv(Player::Mpv, PLAYLIST, None, None, 0, false);
        let vlc = build_argv(Player::Vlc, PLAYLIST, None, None, 0, false);
        assert_eq!(mpv[0], "--no-terminal");
        assert!(mpv.iter().any(|arg| arg == "--ytdl=no"));
        assert_eq!(mpv.last().unwrap(), PLAYLIST);
        assert!(mpv.iter().all(|arg| !arg.contains("://") || arg == PLAYLIST),
            "mpv argv leaked a URL other than the admitted playlist: {mpv:?}");
        assert!(vlc.iter().any(|arg| arg == "--play-and-exit"));
        assert_eq!(vlc.last().unwrap(), PLAYLIST);
        // Headless mode selects the null/dummy sinks.
        let mpv_headless = build_argv(Player::Mpv, PLAYLIST, None, None, 0, true);
        assert!(mpv_headless.iter().any(|arg| arg == "--vo=null"));
        assert!(mpv_headless.iter().any(|arg| arg == "--ao=null"));
        // A supplied subtitle file and its per-player demuxer/type stay in the
        // same reviewed argv.
        let mpv_sub = build_argv(Player::Mpv, PLAYLIST, Some("/dev/null"), Some(SubtitleFormat::Srt), 0, false);
        assert!(mpv_sub.iter().any(|arg| arg == "--sub-demuxer=srt"));
        assert!(mpv_sub.iter().any(|arg| arg == "--sub-file=/dev/null"));
        let vlc_sub = build_argv(Player::Vlc, PLAYLIST, Some("/dev/null"), Some(SubtitleFormat::Vtt), 0, false);
        assert!(vlc_sub.iter().any(|arg| arg == "--sub-type=auto"));
    }

    #[test]
    fn player_binding_launches_the_reviewed_player_headlessly() {
        // A source-bound ongoing playlist with an admitted player binding
        // launches the real player through the reviewed fork boundary. The
        // admitted URL is not resolvable offline, so the player exits on its
        // own before the bound and the receipt reports that exit, never the URL.
        let input = request(&format!(
            r#","player":{{"player":"mpv","headless":true,"max_seconds":2}},
                "source":{{"reviewed":true,"reference":"reviewed-live-source-1","sha256":"{HASH_A}"}},
                "stream":{{"id":"opaque-stream","protocol":"hls"}},
                "playlist":{{"url":"{PLAYLIST}","sha256":"{HASH_B}","live":true}}
            "#
        ));
        let receipt = online(&input).unwrap();
        assert_eq!(receipt["result"], "failed");
        assert_eq!(receipt["player_started"], true);
        assert_eq!(receipt["player"], "mpv");
        assert_eq!(receipt["headless"], true);
        assert_eq!(receipt["stopped_by_bound"], false);
        assert_eq!(receipt["stopped_by_stop"], false);
        assert_eq!(receipt["observed_exit"]["success"], false);
        assert!(receipt["player_binding"]["admitted"].as_bool().unwrap());
        // The admitted URL and every supplied digest are never echoed.
        let text = receipt.to_string();
        assert!(!text.contains(PLAYLIST));
        assert!(!text.contains(HASH_B));
        assert!(!text.contains("opaque-stream"));
    }

    #[test]
    fn player_binding_stop_flag_stops_the_child_before_the_bound() {
        // A pre-set stop flag must stop the player before the 2s bound. The
        // receipt reports stopped_by_stop and the child is reaped.
        let input = request(&format!(
            r#","player":{{"player":"mpv","headless":true,"max_seconds":2}},
                "source":{{"reviewed":true,"reference":"reviewed-live-source-1","sha256":"{HASH_A}"}},
                "stream":{{"id":"opaque-stream","protocol":"hls"}},
                "playlist":{{"url":"{PLAYLIST}","sha256":"{HASH_B}","live":true}}
            "#
        ));
        let stop = AtomicBool::new(true);
        let receipt = online_with_stop(&input, &stop).unwrap();
        assert_eq!(receipt["stopped_by_stop"], true);
        assert_eq!(receipt["stopped_by_bound"], false);
        assert_eq!(receipt["player_started"], true);
    }

    #[test]
    fn bounded_plan_safety_is_retained_with_a_player_binding() {
        // Adding a player binding must not weaken the bounded plan's account-
        // wide safety: a duplicate whole-object fragment is still refused.
        let input = request(&format!(
            r#","playlist":{{"url":"{PLAYLIST}","sha256":"{HASH_B}","live":true}},
                "player":{{"player":"mpv"}},
                "bounded_fetch":{{"enabled":true,"max_bytes":64,"fragments":[
                    {{"url":"{FRAGMENT}","sha256":"{HASH_C}","bytes":4}},
                    {{"url":"{FRAGMENT}","sha256":"{HASH_C}","bytes":4}}
                ]}}
            "#
        ));
        assert_eq!(online(&input).unwrap_err().code, "invalid_input");
    }

    #[test]
    fn governed_transport_admits_a_digest_matching_ongoing_playlist() {
        // The governed transport reads the loopback playlist under one shared
        // governor lease, the body matches the caller-supplied digest, and the
        // reviewed manifest decoder reports an ongoing media playlist. The
        // receipt keeps its secret-hiding contract: the loopback URL and every
        // supplied digest are never echoed.
        let body = ongoing_playlist();
        let digest = format!("{:x}", Sha256::digest(&body));
        let (client, address, server) = loopback_playlist(body, 1, 5);
        let receipt = drive_transport(&client, &address, &digest, 1)
            .map(|observation| transport_receipt_for_test(&observation, true, 1))
            .unwrap();
        assert_eq!(receipt["result"], "transport_observed");
        assert_eq!(receipt["transport_admitted"], true);
        assert_eq!(receipt["network_access"], true);
        assert_eq!(receipt["source_objects_fetched"], true);
        assert_eq!(receipt["credentials_read"], false);
        assert_eq!(receipt["player_started"], false);
        assert_eq!(receipt["automatic_reconnect"], true);
        assert_eq!(receipt["playback_admitted"], false);
        assert_eq!(receipt["host_allowlist_verified"], true);
        assert_eq!(receipt["decoder_verified"], true);
        assert_eq!(receipt["media_rights_verified"], false);
        assert_eq!(receipt["playlist_observed"], true);
        assert_eq!(receipt["playlist_kind"], "media");
        assert_eq!(receipt["playlist_segments"], 2);
        assert_eq!(receipt["manifest_is_live"], true);
        assert_eq!(receipt["unverified"]["audio_output"], true);
        assert_eq!(receipt["unverified"]["video_output"], true);
        assert_eq!(receipt["unverified"]["live_playback"], true);
        assert_eq!(server.join().unwrap(), 1);
        let text = receipt.to_string();
        assert!(!text.contains(&address), "receipt echoed the loopback host");
        assert!(!text.contains(&digest), "receipt echoed the supplied digest");
        assert!(!text.contains("seg-0.ts"), "receipt echoed a segment");
    }

    #[test]
    fn governed_transport_refuses_a_digest_mismatch_without_admission() {
        // A body whose digest does not match the caller-supplied expected
        // digest is never admitted. The single re-read against a mismatching
        // body ends in the unavailable transport error, not an admitted
        // read; re-read pacing is proven separately.
        let body = ongoing_playlist();
        let (client, address, server) = loopback_playlist(body, 1, 2);
        let error = drive_transport(&client, &address, &HASH_A, 1)
            .expect_err("a mismatching digest must not admit a read");
        assert_eq!(error.code, "unavailable");
        assert_eq!(server.join().unwrap(), 1);
    }

    #[test]
    fn governed_transport_reconnects_within_the_attempt_bound() {
        // A body that matches on the third re-read, after two mismatching
        // bodies, admits only when the attempt bound allows the third read.
        // The server cannot vary its body per request here, so a body that
        // matches on the first read is the admitted case; a re-read bound of
        // one ends after that single admitted read.
        let body = ongoing_playlist();
        let digest = format!("{:x}", Sha256::digest(&body));
        let (client, address, server) = loopback_playlist(body, 1, 5);
        let observation = drive_transport(&client, &address, &digest, 1).unwrap();
        assert_eq!(observation["admitted"], true);
        assert_eq!(observation["decoder_verified"], true);
        assert_eq!(server.join().unwrap(), 1);
    }

    #[test]
    fn governed_transport_refuses_a_host_not_in_the_allowlist() {
        // A playlist host that is not a member of the reviewed allowlist is
        // refused before any request is sent.
        let body = ongoing_playlist();
        let digest = format!("{:x}", Sha256::digest(&body));
        let (client, address, server) = loopback_playlist(body, 1, 1);
        let error = governed_live_transport(
            &client,
            &test_governor(),
            &format!("{address}/live/index.m3u8"),
            &Some(vec!["other-host.example.test".to_owned()]),
            &Some("127.0.0.1".to_owned()),
            1,
            &AtomicBool::new(false),
            &digest,
        )
        .expect_err("a non-member host must be refused before any request");
        assert_eq!(error.code, "host_allowlist_mismatch");
        // The loopback server observed zero connections: the host-allowlist
        // refusal happens before any request is formed.
        assert_eq!(server.join().unwrap(), 0);
    }

    fn test_governor() -> Governor {
        let directory = std::env::temp_dir().join(format!(
            "buaa-live-transport-gov-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let governor = Governor::isolated_for_test(&directory).unwrap();
        let _ = std::fs::remove_dir_all(&directory);
        governor
    }

    /// The transport receipt built directly from an observation, for tests
    /// that drive the governed read without the full online entry.
    fn transport_receipt_for_test(observation: &Value, executable: bool, re_read_attempts: u64) -> Value {
        let assessment = assess(&LiveInput {
            authorized: true,
            player: None,
            source: Some(SourceBinding {
                reviewed: true,
                reference: "reviewed-live-source-1".into(),
                sha256: HASH_A.into(),
            }),
            stream: Some(StreamContract {
                id: "opaque-stream".into(),
                protocol: "hls".into(),
            }),
            playlist: None,
            credential: None,
            bounded_fetch: None,
            governed_transport: Some(GovernedTransport {
                enabled: executable,
                re_read_attempts,
            }),
            host_allowlist: None,
        })
        .unwrap();
        transport_receipt(&assessment, observation)
    }
    }
