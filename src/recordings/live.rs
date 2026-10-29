//! Offline HLS inspection. Online live playback is not admitted.
//!
//! Earlier hostname observations came from a temporary client outside the
//! production shared governor. They establish neither an authorized source
//! identity nor media rights and must not authorize production requests.
use crate::net::Error;
use serde_json::{json, Value};
use std::sync::atomic::AtomicBool;

fn invalid() -> Error {
    Error::new("invalid_input", "Unsupported or malformed offline HLS manifest.")
}

/// Fail closed without parsing credentials, opening storage, accessing the
/// network or starting a player. Input is deliberately ignored while blocked.
pub fn online(_input: &str) -> Result<Value, Error> {
    Ok(json!({
        "schema_version":1,
        "type":"recording_live",
        "result":"blocked",
        "reason":"live_source_and_exact_host_contract_not_admitted",
        "implementation_complete":false,
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
        "decoder_verified":false
    }))
}

/// The stop-aware entry is equally blocked; it cannot create a stream or
/// reconnect. An operator attestation alone cannot replace source admission.
pub fn online_with_stop(input: &str, _stop: &AtomicBool) -> Result<Value, Error> {
    online(input)
}

/// Inspect supplied bytes only. This does not resolve URIs, admit hosts,
/// establish stream identity, authorize media use or prove decoder support.
pub fn inspect_manifest(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > 2 * 1024 * 1024 { return Err(invalid()); }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let mut lines = text.lines();
    if lines.next() != Some("#EXTM3U") { return Err(invalid()); }
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
        if line.is_empty() { continue; }
        if let Some(value) = line.strip_prefix("#EXTINF:") {
            if duration.is_some() || variant { return Err(invalid()); }
            let value = value.split(',').next().unwrap_or("").parse::<f64>().map_err(|_| invalid())?;
            if !value.is_finite() || value <= 0.0 { return Err(invalid()); }
            duration = Some(value);
        } else if line.starts_with("#EXT-X-STREAM-INF:") {
            if variant || duration.is_some() { return Err(invalid()); }
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
            || line == "#EXT-X-I-FRAMES-ONLY" {
            unsupported = true;
        } else if !line.starts_with('#') {
            if end_list { return Err(invalid()); }
            if variant { variants += 1; variant = false; }
            else if let Some(value) = duration.take() { segments += 1; seconds += value; }
            else { return Err(invalid()); }
        }
    }
    if variant || duration.is_some() || (variants > 0 && segments > 0)
        || variants + segments == 0 || !seconds.is_finite() { return Err(invalid()); }
    Ok(json!({
        "kind":if variants > 0 {"master"} else {"media"},
        "variants":variants,"segments":segments,"duration_seconds":seconds,
        "is_live_manifest":variants == 0 && !end_list,"end_list":end_list,
        "key_declared":keys,"unsupported_features":unsupported,
        "decoder_verified":false,"media_rights_verified":false
    }))
}

pub fn schema() -> Value {
    let receipt = online("").expect("blocked receipt construction is infallible");
    let required: Vec<&str> = receipt.as_object().expect("blocked receipt is an object")
        .keys().map(String::as_str).collect();
    let properties: serde_json::Map<String, Value> = receipt.as_object()
        .expect("blocked receipt is an object").iter()
        .map(|(key, value)| (key.clone(), json!({"const":value}))).collect();
    json!({
        "input":{"description":"Online playback is blocked for every input; no credentials or source selection are consumed."},
        "output":{"type":"object","additionalProperties":false,
            "required":required,"properties":properties}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_is_unconditionally_blocked() {
        for input in ["", "not json", "{}", "{\"authorized\":true,\"cookie\":\"synthetic\"}"] {
            let receipt = online(input).unwrap();
            assert_eq!(receipt["result"], "blocked");
            for key in ["network_access", "credentials_read", "player_started",
                "source_objects_fetched", "implementation_complete",
                "media_rights_verified", "decoder_verified"] {
                assert_eq!(receipt[key], false);
            }
            assert_eq!(online_with_stop(input, &AtomicBool::new(true)).unwrap(), receipt);
        }
    }

    #[test]
    fn schema_describes_only_the_blocked_receipt() {
        let schema = schema();
        assert_eq!(schema["output"]["properties"]["result"]["const"], "blocked");
        assert_eq!(schema["output"]["properties"]["network_access"]["const"], false);
        assert_eq!(schema["output"]["additionalProperties"], false);
    }

    #[test]
    fn manifest_analysis_and_key_disclosure() {
        let master = inspect_manifest(b"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=100\nlow.m3u8\n").unwrap();
        assert_eq!(master["variants"], 1);
        let media = inspect_manifest(b"#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=\"key\"\n#EXTINF:2.5,\na.ts\n#EXTINF:3,\nb.ts\n").unwrap();
        assert_eq!(media["segments"], 2);
        assert_eq!(media["duration_seconds"], 5.5);
        assert_eq!(media["key_declared"], true);
        assert_eq!(media["unsupported_features"], true);
        assert_eq!(media["is_live_manifest"], true);
        assert_eq!(media["decoder_verified"], false);
        assert!(inspect_manifest(b"#EXTM3U\n#EXTINF:2,\n").is_err());
    }
}
