//! Explicit native classroom subtitle selection, with separate supplied and
//! fixed-origin governed HTTP originals. Neither path fetches recording media.
use super::digest;
use crate::net::{
    CLASSROOM_ORIGIN, CLASSROOM_TRANSCRIPT_PATH, CacheMode, CacheStatus, ClassroomClient, Error,
    Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::io::{self, Write};
use url::Url;
use zeroize::Zeroizing;

pub(crate) const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_INPUT: usize = MAX_BODY.div_ceil(3) * 4 + 8 * 1024;
const MAX_TRACKS: usize = 256;
const MAX_SEGMENTS: usize = 20_000;
const MAX_TEXT: usize = 8 * 1024;
const MAX_ID: usize = 256;
const MAX_SECONDS: u64 = i64::MAX as u64 / 1000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input<'a> {
    #[serde(default)]
    authorized: bool,
    format: Cow<'a, str>,
    #[serde(borrow)]
    body_base64: Cow<'a, str>,
    source_sha256: Cow<'a, str>,
    selection: Selection<'a>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection<'a> {
    #[serde(borrow)]
    sub_id: Cow<'a, str>,
    #[serde(borrow)]
    resource_guid: Cow<'a, str>,
}

#[derive(Deserialize)]
struct NativeResponse<'a> {
    status: u16,
    #[serde(borrow)]
    data: NativeData<'a>,
}

#[derive(Deserialize)]
struct NativeData<'a> {
    code: i64,
    #[serde(borrow, default)]
    list: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct Track<'a> {
    #[serde(borrow)]
    sub_id: Cow<'a, str>,
    #[serde(borrow)]
    resource_guid: Cow<'a, str>,
    #[serde(borrow)]
    all_content: &'a RawValue,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cue<'a> {
    #[serde(skip_deserializing)]
    source_order: usize,
    #[serde(rename(deserialize = "BeginSec"), deserialize_with = "milliseconds")]
    start_ms: u64,
    #[serde(rename(deserialize = "EndSec"), deserialize_with = "milliseconds")]
    end_ms: u64,
    #[serde(borrow, rename(deserialize = "Text"))]
    text: Cow<'a, str>,
    #[serde(borrow, rename(deserialize = "TransText"))]
    translation: Cow<'a, str>,
}

fn milliseconds<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let seconds = u64::deserialize(deserializer)?;
    if seconds > MAX_SECONDS {
        return Err(serde::de::Error::custom("unsupported subtitle time"));
    }
    Ok(seconds * 1000)
}

fn invalid() -> Error {
    Error::new(
        "invalid_input",
        "Native subtitle input or selected track is invalid.",
    )
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ID && !value.chars().any(char::is_control)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OnlineInput<'a> {
    #[serde(default)]
    authorized: bool,
    #[serde(borrow)]
    selection: Selection<'a>,
    #[serde(deserialize_with = "deserialize_cookie")]
    cookie: Zeroizing<String>,
}

fn deserialize_cookie<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

struct DigestWriter(Sha256);
impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Import a supplied native response, never a URL, catalog path or login token.
/// Authorization is attested by the caller, not a proof of media rights.
pub fn import(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: Input<'_> = serde_json::from_str(input).map_err(|_| invalid())?;
    if !request.authorized {
        return Err(Error::new(
            "permission",
            "Explicit authorization for the supplied subtitles is required.",
        ));
    }
    if request.format != "classroom-native-v1"
        || request.body_base64.len() > MAX_BODY.div_ceil(3) * 4
        || !valid_id(&request.selection.sub_id)
        || request.selection.resource_guid.len() > MAX_ID
        || request
            .selection
            .resource_guid
            .chars()
            .any(char::is_control)
        || request.source_sha256.len() != 64
        || !request
            .source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid());
    }
    let bytes = STANDARD
        .decode(request.body_base64.as_bytes())
        .map_err(|_| invalid())?;
    if bytes.is_empty() || bytes.len() > MAX_BODY || digest(&bytes) != request.source_sha256 {
        return Err(invalid());
    }
    let response: NativeResponse<'_> = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if response.status != 200 || response.data.code != 0 {
        return Err(Error::new(
            "unavailable",
            "Supplied native subtitle response was not successful.",
        ));
    }
    let (segments, derived_sha256) = normalize_track(response.data, &request.selection)?;
    Ok(json!({
        "schema_version":1,"type":"recording_subtitles","result":"selected_track_imported",
        "authorization":{"basis":"operator_attestation","media_rights_verified":false},
        "selection":request.selection,
        "original":{"sha256":request.source_sha256,"bytes":bytes.len(),"hash_scope":"entire_supplied_response_bytes","storage":"caller_owned_input_not_persisted"},
        "provenance":{"status":"operator_asserted","format":"classroom-native-v1","capture_timestamp":null,"media_bytes_verified":false,"resource_guid_status":if request.selection.resource_guid.is_empty() { "absent_in_native_track" } else { "native_declared_not_media_verified" }},
        "derivation":{"sha256":derived_sha256,"hash_scope":"compact_utf8_segments_json_in_output_field_order","time_conversion":"exact_integer_seconds_to_milliseconds","text_normalization":"none"},
        "segments":segments,
        "completeness":{"scope":"selected_track_in_supplied_response","complete_history":false,"source_order_preserved":true,"unsegmented_trans_content_used":false},
        "network_access":false,"source_objects_fetched":false,"catalog_modified":false,
    }))
}

fn normalize_track(
    data: NativeData<'_>,
    selection: &Selection<'_>,
) -> Result<(Value, String), Error> {
    let tracks: Vec<Track<'_>> =
        serde_json::from_str(data.list.ok_or_else(invalid)?.get()).map_err(|_| invalid())?;
    if tracks.len() > MAX_TRACKS {
        return Err(invalid());
    }
    let mut tracks = tracks.iter().filter(|track| {
        track.sub_id == selection.sub_id && track.resource_guid == selection.resource_guid
    });
    let track = tracks
        .next()
        .filter(|_| tracks.next().is_none())
        .ok_or_else(invalid)?;
    let mut segments: Vec<Cue<'_>> =
        serde_json::from_str(track.all_content.get()).map_err(|_| invalid())?;
    if segments.is_empty() || segments.len() > MAX_SEGMENTS {
        return Err(invalid());
    }
    for (index, cue) in segments.iter_mut().enumerate() {
        if cue.start_ms > cue.end_ms
            || cue.text.len() > MAX_TEXT
            || cue.translation.len() > MAX_TEXT
        {
            return Err(invalid());
        }
        cue.source_order = index + 1;
    }
    let segments = serde_json::to_value(segments).map_err(|_| invalid())?;
    let mut writer = DigestWriter(Sha256::new());
    serde_json::to_writer(&mut writer, &segments).map_err(|_| invalid())?;
    let derived_sha256 = format!("{:x}", writer.0.finalize());
    Ok((segments, derived_sha256))
}

fn rejected_session() -> Error {
    Error::new(
        "auth_latched",
        "Native classroom session was rejected or indeterminate; deliberate review is required.",
    )
}

fn require_application_success(code: i64) -> Result<(), Error> {
    if code != 0 {
        return Err(rejected_session());
    }
    Ok(())
}

/// A fresh body can be an expired-session reply even when an immutable original
/// exists. Admit its application status before comparing or retaining old bytes.
pub(crate) fn validate_http_application(body: &[u8]) -> Result<(), Error> {
    let data: NativeData<'_> = serde_json::from_slice(body).map_err(|_| rejected_session())?;
    require_application_success(data.code)
}

pub(crate) fn validate_http_metadata(
    status: u16,
    content_type: Option<&str>,
    bytes: usize,
) -> Result<(), Error> {
    if status != 200 || bytes > MAX_BODY {
        return Err(Error::new(
            "unavailable",
            "Native subtitle response metadata is unsupported.",
        ));
    }
    if bytes == 0 {
        return Err(rejected_session());
    }
    let mime = content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if mime.is_none_or(|mime| !mime.eq_ignore_ascii_case("application/json")) {
        return Err(rejected_session());
    }
    Ok(())
}

pub(crate) fn process_http(
    response: &Response,
    sub_id: &str,
    resource_guid: &str,
) -> Result<Result<Value, Error>, Error> {
    let selection = Selection {
        sub_id: Cow::Borrowed(sub_id),
        resource_guid: Cow::Borrowed(resource_guid),
    };
    validate_http_metadata(
        response.status,
        response.headers.get("content-type").map(String::as_str),
        response.body.len(),
    )?;
    let data: NativeData<'_> =
        serde_json::from_slice(&response.body).map_err(|_| rejected_session())?;
    require_application_success(data.code)?;
    // Valid authenticated source bytes survive layout/selection failure for a
    // cache-only correction; unsuccessful application replies never enter cache.
    let normalized = normalize_track(data, &selection);
    Ok(normalized.map(|(segments, derived_sha256)| {
        let fetched = response.cache_status != CacheStatus::Hit;
        let body_fetched = fetched && response.revalidation_status != Some(304);
        json!({
            "schema_version":1,"type":"recording_subtitles","result":"selected_track_observed",
            "authorization":{"basis":"operator_attestation","media_rights_verified":false},
            "selection":selection,
            "original":{"sha256":response.sha256,"bytes":response.body.len(),"hash_scope":"entire_http_response_body","storage":"private_immutable_byte_cache"},
            "provenance":{"status":"governed_read","format":"classroom-native-v1","capture_timestamp":null,"media_bytes_verified":false,"resource_guid_status":if selection.resource_guid.is_empty() { "absent_in_native_track" } else { "native_declared_not_media_verified" }},
            "derivation":{"sha256":derived_sha256,"hash_scope":"compact_utf8_segments_json_in_output_field_order","time_conversion":"exact_integer_seconds_to_milliseconds","text_normalization":"none"},
            "segments":segments,
            "retrieval":{"source_url":response.url,"fetched_at_unix_ms":response.fetched_at_unix_ms,"cache_status":response.cache_status,"revalidated_at_unix_ms":response.revalidated_at_unix_ms,"revalidation_status":response.revalidation_status},
            "completeness":{"scope":"selected_track_in_observed_response","complete_history":false,"source_order_preserved":true,"unsegmented_trans_content_used":false},
            "network_access":fetched,"source_objects_fetched":body_fetched,"source_object_scope":"native_subtitle_response_only_not_recording_media","catalog_modified":false,
        })
    }))
}

/// Read exactly one source-bound native subtitle response with an explicitly
/// supplied session. No login, redirect, authentication refresh or retry exists.
pub fn online(mode: CacheMode, input: &str) -> Result<Value, Error> {
    if input.len() > 32 * 1024 {
        return Err(invalid());
    }
    let request: OnlineInput<'_> = serde_json::from_str(input).map_err(|_| invalid())?;
    if !request.authorized {
        return Err(Error::new(
            "permission",
            "Explicit authorization for the selected native subtitles is required.",
        ));
    }
    if request.selection.sub_id.is_empty()
        || request.selection.sub_id.len() > 20
        || !request
            .selection
            .sub_id
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        || request.selection.resource_guid.len() > MAX_ID
        || request
            .selection
            .resource_guid
            .chars()
            .any(char::is_control)
    {
        return Err(invalid());
    }
    let mut url = Url::parse(CLASSROOM_ORIGIN).map_err(|_| invalid())?;
    url.set_path(CLASSROOM_TRANSCRIPT_PATH);
    url.query_pairs_mut()
        .append_pair("format", "json")
        .append_pair("sub_id", &request.selection.sub_id);
    let client = ClassroomClient::open(mode, &request.cookie)?;
    client.get(&url, |response| {
        process_http(
            response,
            &request.selection.sub_id,
            &request.selection.resource_guid,
        )
    })?
}

pub fn online_schema() -> Value {
    let offline = schema();
    let mut output = offline["output"].clone();
    output["properties"]["result"] = json!({"const":"selected_track_observed"});
    output["properties"]["original"]["properties"]["hash_scope"] =
        json!({"const":"entire_http_response_body"});
    output["properties"]["original"]["properties"]["storage"] =
        json!({"const":"private_immutable_byte_cache"});
    output["properties"]["provenance"]["properties"]["status"] = json!({"const":"governed_read"});
    output["properties"]["completeness"]["properties"]["scope"] =
        json!({"const":"selected_track_in_observed_response"});
    output["properties"]["network_access"] = json!({"type":"boolean"});
    output["properties"]["source_objects_fetched"] = json!({"type":"boolean"});
    output["properties"]["source_object_scope"] =
        json!({"const":"native_subtitle_response_only_not_recording_media"});
    output["properties"]["retrieval"] = json!({"type":"object","properties":{
        "source_url":{"type":"string"},"fetched_at_unix_ms":{"type":"integer","minimum":0},
        "cache_status":{"enum":["hit","miss","revalidated"]},"revalidated_at_unix_ms":{"type":["integer","null"]},"revalidation_status":{"type":["integer","null"]}
    }});
    output["description"] = json!(
        "Fixed-origin session-bound native subtitle GET/cache only. Credentials remain on stdin/in memory and are never sent to robots, redirects or another origin; no session/credential is included in cache or output. Body hash covers raw HTTP bytes, not a constructed wrapper. No login, media retrieval, catalog write, publisher/rights proof or course completion."
    );
    json!({
        "input":{"type":"object","additionalProperties":false,"required":["authorized","selection","cookie"],"properties":{
            "authorized":{"const":true},"cookie":{"type":"string","minLength":1,"maxLength":16384,"writeOnly":true,"description":"Explicit existing native session Cookie value via protected stdin only; never a master key/password or an arbitrary header map."},
            "selection":{"type":"object","additionalProperties":false,"required":["sub_id","resource_guid"],"properties":{"sub_id":{"type":"string","pattern":"^[0-9]{1,20}$"},"resource_guid":offline["input"]["properties"]["selection"]["properties"]["resource_guid"]}}
        }},
        "output":output,"network_policy":{"origin":CLASSROOM_ORIGIN,"path":CLASSROOM_TRANSCRIPT_PATH,"method":"GET","cache_first":true,"automatic_authentication_retry":false,"shared_governor":true,"robots_authenticated":false}
    })
}

pub fn schema() -> Value {
    let hash = json!({"type":"string","pattern":"^[0-9a-f]{64}$"});
    let id = json!({"type":"string","minLength":1,"maxLength":MAX_ID,"description":"Exact native identifier; UTF-8 byte bound applies, no control characters."});
    let resource_id = json!({"type":"string","maxLength":MAX_ID,"description":"Exact native resource_guid, including an empty string when the original track has no resource link; never inferred from another response. UTF-8 byte bound applies, no control characters."});
    json!({
        "input":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
            "required":["authorized","format","body_base64","source_sha256","selection"],
            "properties":{
                "authorized":{"const":true,"description":"Operator permission for these supplied private subtitles, not verified media rights."},
                "format":{"const":"classroom-native-v1"},
                "body_base64":{"type":"string","maxLength":MAX_BODY.div_ceil(3)*4,"description":"Exact original native response JSON encoded as Base64, at most4MiB decoded; retain the original separately. Selected track requires all_content rows with integer BeginSec/EndSec and string Text/TransText. Fractional or string times are unsupported, never rounded."},
                "source_sha256":hash,
                "selection":{"type":"object","additionalProperties":false,"required":["sub_id","resource_guid"],"properties":{"sub_id":id,"resource_guid":resource_id}},
            }},
        "output":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
            "required":["schema_version","type","result","authorization","selection","original","provenance","derivation","segments","completeness","network_access","source_objects_fetched","catalog_modified"],
            "properties":{
                "schema_version":{"const":1},"type":{"const":"recording_subtitles"},"result":{"const":"selected_track_imported"},
                "authorization":{"type":"object","properties":{"basis":{"const":"operator_attestation"},"media_rights_verified":{"const":false}}},
                "selection":{"type":"object","properties":{"sub_id":id,"resource_guid":resource_id}},
                "original":{"type":"object","properties":{"sha256":hash,"bytes":{"type":"integer","minimum":1,"maximum":MAX_BODY},"hash_scope":{"const":"entire_supplied_response_bytes"},"storage":{"const":"caller_owned_input_not_persisted"}}},
                "provenance":{"type":"object","properties":{"status":{"const":"operator_asserted"},"format":{"const":"classroom-native-v1"},"capture_timestamp":{"type":"null"},"media_bytes_verified":{"const":false},"resource_guid_status":{"enum":["absent_in_native_track","native_declared_not_media_verified"]}}},
                "derivation":{"type":"object","properties":{"sha256":hash,"hash_scope":{"const":"compact_utf8_segments_json_in_output_field_order"},"time_conversion":{"const":"exact_integer_seconds_to_milliseconds"},"text_normalization":{"const":"none"}}},
                "segments":{"type":"array","minItems":1,"maxItems":MAX_SEGMENTS,"items":{"type":"object","additionalProperties":false,"required":["source_order","start_ms","end_ms","text","translation"],"properties":{
                    "source_order":{"type":"integer","minimum":1,"maximum":MAX_SEGMENTS},
                    "start_ms":{"type":"integer","minimum":0,"maximum":MAX_SECONDS*1000},"end_ms":{"type":"integer","minimum":0,"maximum":MAX_SECONDS*1000},
                    "text":{"type":"string","maxLength":MAX_TEXT},"translation":{"type":"string","maxLength":MAX_TEXT}
                }}},
                "completeness":{"type":"object","properties":{"scope":{"const":"selected_track_in_supplied_response"},"complete_history":{"const":false},"source_order_preserved":{"const":true},"unsegmented_trans_content_used":{"const":false}}},
                "network_access":{"const":false},"source_objects_fetched":{"const":false},"catalog_modified":{"const":false},
            },
            "description":"Exact source text/translation and original ordering, including blank text, repeated or overlapping cues. No whitespace normalization, deduplication, speaker/language inference, media download or catalog write. Original response and derived segment hashes are distinct; neither establishes remote authenticity or course completion. Outputs may contain private text and identifiers, never forward them to public logs."
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native(cues: &str) -> String {
        format!(
            r#"{{"status":200,"data":{{"code":0,"list":[{{"sub_id":"lesson","resource_guid":"resource","all_content":{cues},"trans_content":"not a timed transcript"}}]}}}}"#
        )
    }

    fn input(source: &str) -> Value {
        json!({"authorized":true,"format":"classroom-native-v1","body_base64":STANDARD.encode(source),"source_sha256":digest(source.as_bytes()),"selection":{"sub_id":"lesson","resource_guid":"resource"}})
    }

    #[test]
    fn selected_track_preserves_source_text_order_translation_and_exact_times() {
        let source = native(
            r#"[{"BeginSec":3,"EndSec":5,"Text":"  一\n二  ","TransText":"first"},{"BeginSec":1,"EndSec":4,"Text":"same","TransText":"second"},{"BeginSec":4,"EndSec":4,"Text":"same","TransText":""}]"#,
        );
        let output = import(&input(&source).to_string()).unwrap();
        assert_eq!(
            output["segments"],
            json!([
                {"source_order":1,"start_ms":3000,"end_ms":5000,"text":"  一\n二  ","translation":"first"},
                {"source_order":2,"start_ms":1000,"end_ms":4000,"text":"same","translation":"second"},
                {"source_order":3,"start_ms":4000,"end_ms":4000,"text":"same","translation":""}
            ])
        );
        assert_eq!(output["original"]["sha256"], digest(source.as_bytes()));
        assert_eq!(
            output["derivation"]["sha256"],
            "7473e3ecf4486ea26d9703b1d7b6c9b88ae0a7c84edf3d317be78ee7fd5284ac"
        );
        assert_eq!(output["provenance"]["capture_timestamp"], Value::Null);
        assert_eq!(output["source_objects_fetched"], false);
    }

    #[test]
    fn selection_requires_both_identifiers_and_one_unambiguous_track() {
        let source = native(r#"[{"BeginSec":0,"EndSec":1,"Text":"selected","TransText":""}]"#);
        let mut request = input(&source);
        request["selection"]["resource_guid"] = json!("other");
        assert_eq!(
            import(&request.to_string()).unwrap_err().code,
            "invalid_input"
        );
        let mut response: Value = serde_json::from_str(&source).unwrap();
        let track = response["data"]["list"][0].clone();
        response["data"]["list"].as_array_mut().unwrap().push(track);
        assert_eq!(
            import(&input(&response.to_string()).to_string())
                .unwrap_err()
                .code,
            "invalid_input"
        );
        response["data"]["list"][0]["resource_guid"] = json!("unselected");
        response["data"]["list"][0]["all_content"] = json!("not timed cues");
        assert_eq!(
            import(&input(&response.to_string()).to_string()).unwrap()["segments"][0]["text"],
            "selected"
        );
    }

    #[test]
    fn authorization_original_digest_and_successful_response_are_required() {
        let source =
            native(r#"[{"BeginSec":0,"EndSec":1,"Text":"private sentinel","TransText":""}]"#);
        let mut request = input(&source);
        request["authorized"] = json!(false);
        request["body_base64"] = json!("not base64");
        assert_eq!(import(&request.to_string()).unwrap_err().code, "permission");
        request = input(&source);
        request["source_sha256"] = json!("0".repeat(64));
        assert_eq!(
            import(&request.to_string()).unwrap_err().code,
            "invalid_input"
        );
        let failed = source.replace("\"code\":0", "\"code\":401");
        let error = import(&input(&failed).to_string()).unwrap_err();
        assert_eq!(error.code, "unavailable");
        assert!(!error.message.contains("private sentinel"));
    }

    #[test]
    fn absent_native_resource_guid_is_preserved_without_fabricated_media_link() {
        let source = native(r#"[{"BeginSec":0,"EndSec":3,"Text":"source text","TransText":""}]"#)
            .replace("\"resource_guid\":\"resource\"", "\"resource_guid\":\"\"");
        let mut request = input(&source);
        request["selection"]["resource_guid"] = json!("");
        let output = import(&request.to_string()).unwrap();
        assert_eq!(output["selection"]["resource_guid"], "");
        assert_eq!(
            output["provenance"]["resource_guid_status"],
            "absent_in_native_track"
        );
        assert_eq!(output["provenance"]["media_bytes_verified"], false);
        request["selection"]["resource_guid"] = json!("inferred-from-another-response");
        assert_eq!(
            import(&request.to_string()).unwrap_err().code,
            "invalid_input"
        );
    }

    #[test]
    fn json_escaped_nul_text_survives_in_both_subtitle_fields() {
        let source = native(
            r#"[{"BeginSec":0,"EndSec":1,"Text":"before\u0000after","TransText":"translated\u0000text"}]"#,
        );
        let output = import(&input(&source).to_string()).unwrap();
        assert_eq!(output["segments"][0]["text"], "before\0after");
        assert_eq!(output["segments"][0]["translation"], "translated\0text");
        assert_eq!(
            output["derivation"]["sha256"],
            digest(&serde_json::to_vec(&output["segments"]).unwrap())
        );
    }

    #[test]
    fn malformed_timing_and_oversized_text_do_not_become_partial_success() {
        for cues in [
            r#"[{"BeginSec":-1,"EndSec":1,"Text":"x","TransText":""}]"#.to_owned(),
            r#"[{"BeginSec":0.5,"EndSec":1,"Text":"x","TransText":""}]"#.to_owned(),
            r#"[{"BeginSec":"0","EndSec":1,"Text":"x","TransText":""}]"#.to_owned(),
            r#"[{"BeginSec":2,"EndSec":1,"Text":"x","TransText":""}]"#.to_owned(),
            format!(
                r#"[{{"BeginSec":{},"EndSec":{},"Text":"x","TransText":""}}]"#,
                MAX_SECONDS + 1,
                MAX_SECONDS + 1
            ),
            format!(
                r#"[{{"BeginSec":0,"EndSec":1,"Text":"{}","TransText":""}}]"#,
                "x".repeat(MAX_TEXT + 1)
            ),
            "[]".to_owned(),
        ] {
            assert_eq!(
                import(&input(&native(&cues)).to_string()).unwrap_err().code,
                "invalid_input"
            );
        }
    }
}
