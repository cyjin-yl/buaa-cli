use crate::net::Error;
use serde_json::Value;
use std::fmt::Write as _;

const MAX_SEGMENTS: usize = 20_000;
const MAX_TEXT: usize = 8 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

struct Segment<'a> {
    start_ms: u64,
    end_ms: u64,
    text: &'a str,
}

fn invalid() -> Error {
    Error::new("invalid_input", "Subtitle segment is invalid for export.")
}

fn decimal_width(mut value: u64) -> usize {
    let mut width = 1;
    while value >= 10 {
        value /= 10;
        width += 1;
    }
    width
}

fn timestamp_width(milliseconds: u64) -> usize {
    let total_seconds = milliseconds / 1_000;
    let hours = total_seconds / 3_600;
    decimal_width(hours).max(2) + 10
}

fn is_character_reference(text: &str, ampersand: usize) -> bool {
    let bytes = text.as_bytes();
    let start = ampersand + 1;
    let Some(relative_end) = bytes[start..].iter().position(|byte| *byte == b';') else {
        return false;
    };
    let body = &bytes[start..start + relative_end];
    if body.is_empty() {
        return false;
    }
    if body[0] == b'#' {
        if body.len() == 1 {
            return false;
        }
        let digits = &body[1..];
        if matches!(digits[0], b'x' | b'X') {
            digits.len() > 1 && digits[1..].iter().all(|byte| byte.is_ascii_hexdigit())
        } else {
            digits.iter().all(|byte| byte.is_ascii_digit())
        }
    } else {
        body.iter().all(|byte| byte.is_ascii_alphanumeric())
    }
}

fn text_is_representable(text: &str) -> bool {
    if text.is_empty() || text.len() > MAX_TEXT {
        return false;
    }
    if text
        .chars()
        .any(|character| character != '\n' && character != '\t' && character.is_control())
    {
        return false;
    }
    if text.split('\n').any(|line| line.is_empty()) {
        return false;
    }

    // SRT and WebVTT have no shared literal-text escape mode.  Refuse
    // character references, HTML/WebVTT tags, ASS overrides and timing arrows
    // rather than emitting text that a player may interpret as syntax.
    if text.split('\n').any(|line| line.contains("-->")) {
        return false;
    }
    for (index, byte) in text.bytes().enumerate() {
        if matches!(byte, b'<' | b'>' | b'{' | b'}') {
            return false;
        }
        if byte == b'&' && is_character_reference(text, index) {
            return false;
        }
    }
    true
}

fn segment(value: &Value) -> Result<Segment<'_>, Error> {
    let object = value.as_object().ok_or_else(invalid)?;
    let start_ms = object
        .get("start_ms")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let end_ms = object
        .get("end_ms")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let text = object
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if end_ms <= start_ms || !text_is_representable(text) {
        return Err(invalid());
    }
    Ok(Segment {
        start_ms,
        end_ms,
        text,
    })
}

fn write_time(output: &mut String, milliseconds: u64, separator: char) -> Result<(), Error> {
    let millis = milliseconds % 1_000;
    let total_seconds = milliseconds / 1_000;
    let seconds = total_seconds % 60;
    let total_minutes = total_seconds / 60;
    let minutes = total_minutes % 60;
    let hours = total_minutes / 60;
    write!(
        output,
        "{hours:02}:{minutes:02}:{seconds:02}{separator}{millis:03}"
    )
    .map_err(|_| invalid())
}

struct BoundedOutput {
    body: String,
}

impl BoundedOutput {
    fn new() -> Self {
        Self {
            body: String::new(),
        }
    }

    fn reserve(&mut self, additional: usize) -> Result<(), Error> {
        let length = self
            .body
            .len()
            .checked_add(additional)
            .ok_or_else(invalid)?;
        if length > MAX_OUTPUT_BYTES {
            return Err(invalid());
        }
        self.body.try_reserve(additional).map_err(|_| invalid())
    }

    fn push_str(&mut self, text: &str) -> Result<(), Error> {
        self.reserve(text.len())?;
        self.body.push_str(text);
        Ok(())
    }

    fn push_time(&mut self, milliseconds: u64, separator: char) -> Result<(), Error> {
        self.reserve(timestamp_width(milliseconds))?;
        write_time(&mut self.body, milliseconds, separator)
    }

    fn push_index(&mut self, index: usize) -> Result<(), Error> {
        let index = index.checked_add(1).ok_or_else(invalid)?;
        self.reserve(decimal_width(index as u64) + 2)?;
        write!(self.body, "{index}\r\n").map_err(|_| invalid())
    }

    fn finish(self) -> String {
        self.body
    }
}

fn validate_count(segments: &[Value]) -> Result<(), Error> {
    if segments.len() > MAX_SEGMENTS {
        return Err(invalid());
    }
    Ok(())
}

/// Export normalized native subtitle segments as SubRip text.
pub fn srt(segments: &[Value]) -> Result<String, Error> {
    validate_count(segments)?;
    let mut output = BoundedOutput::new();
    for (index, value) in segments.iter().enumerate() {
        let segment = segment(value)?;
        output.push_index(index)?;
        output.push_time(segment.start_ms, ',')?;
        output.push_str(" --> ")?;
        output.push_time(segment.end_ms, ',')?;
        output.push_str("\r\n")?;
        output.push_str(segment.text)?;
        output.push_str("\r\n\r\n")?;
    }
    Ok(output.finish())
}

/// Export normalized native subtitle segments as WebVTT text.
pub fn vtt(segments: &[Value]) -> Result<String, Error> {
    validate_count(segments)?;
    let mut output = BoundedOutput::new();
    output.push_str("WEBVTT\r\n\r\n")?;
    for value in segments {
        let segment = segment(value)?;
        output.push_time(segment.start_ms, '.')?;
        output.push_str(" --> ")?;
        output.push_time(segment.end_ms, '.')?;
        output.push_str("\r\n")?;
        output.push_str(segment.text)?;
        output.push_str("\r\n\r\n")?;
    }
    Ok(output.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn srt_uses_source_order_and_crlf_blocks() {
        let segments = vec![
            json!({"start_ms":3_600_001,"end_ms":3_601_999,"text":"first"}),
            json!({"start_ms":0,"end_ms":1_234,"text":"second"}),
        ];
        assert_eq!(
            srt(&segments).unwrap(),
            "1\r\n01:00:00,001 --> 01:00:01,999\r\nfirst\r\n\r\n2\r\n00:00:00,000 --> 00:00:01,234\r\nsecond\r\n\r\n"
        );
    }

    #[test]
    fn vtt_uses_webvtt_header_and_no_cue_identifiers() {
        let segments = vec![json!({
            "start_ms":61_002,
            "end_ms":62_003,
            "text":"a cue"
        })];
        assert_eq!(
            vtt(&segments).unwrap(),
            "WEBVTT\r\n\r\n00:01:01.002 --> 00:01:02.003\r\na cue\r\n\r\n"
        );
    }

    #[test]
    fn millisecond_boundaries_are_not_rounded() {
        let segments = vec![json!({
            "start_ms":59_999,
            "end_ms":23 * 3_600_000 + 59 * 60_000 + 59_999,
            "text":"boundary"
        })];
        assert_eq!(
            srt(&segments).unwrap(),
            "1\r\n00:00:59,999 --> 23:59:59,999\r\nboundary\r\n\r\n"
        );
    }

    #[test]
    fn cue_text_allows_ordinary_multiline_text() {
        let text = " leading & text\nsecond\tline\nfinal ";
        let segments = vec![json!({"start_ms":0,"end_ms":1,"text":text})];
        assert_eq!(
            srt(&segments).unwrap(),
            format!("1\r\n00:00:00,000 --> 00:00:00,001\r\n{text}\r\n\r\n")
        );
        assert_eq!(
            vtt(&segments).unwrap(),
            format!("WEBVTT\r\n\r\n00:00:00.000 --> 00:00:00.001\r\n{text}\r\n\r\n")
        );
    }

    #[test]
    fn cue_text_refuses_unrepresentable_controls_and_empty_lines() {
        for text in [
            "before\0after",
            "before\rafter",
            "before\u{000b}after",
            "\nleading",
            "trailing\n",
            "first\n\nlast",
        ] {
            let value = json!({"start_ms":0,"end_ms":1,"text":text});
            assert_eq!(
                srt(std::slice::from_ref(&value)).unwrap_err().code,
                "invalid_input"
            );
            assert_eq!(
                vtt(std::slice::from_ref(&value)).unwrap_err().code,
                "invalid_input"
            );
        }
    }

    #[test]
    fn cue_text_refuses_markup_character_references_and_timing_syntax() {
        for text in [
            "<b>markup</b>",
            r"{\an8}override",
            "&lt;b&gt;reference&lt;/b&gt;",
            "00:00:01,000 --> 00:00:02,000",
        ] {
            let value = json!({"start_ms":0,"end_ms":1,"text":text});
            assert_eq!(
                srt(std::slice::from_ref(&value)).unwrap_err().code,
                "invalid_input"
            );
            assert_eq!(
                vtt(std::slice::from_ref(&value)).unwrap_err().code,
                "invalid_input"
            );
        }
    }

    #[test]
    fn export_requires_positive_duration() {
        for segments in [
            vec![json!({"start_ms":0,"end_ms":0,"text":"zero"})],
            vec![json!({"start_ms":2,"end_ms":1,"text":"backwards"})],
        ] {
            assert_eq!(srt(&segments).unwrap_err().code, "invalid_input");
            assert_eq!(vtt(&segments).unwrap_err().code, "invalid_input");
        }
    }

    #[test]
    fn export_refuses_output_over_the_bound() {
        let text = "x".repeat(MAX_TEXT);
        // Cue text alone exceeds the output budget; framing only adds bytes.
        let count = MAX_OUTPUT_BYTES / MAX_TEXT + 1;
        let segments = (0..count)
            .map(|index| {
                json!({
                    "start_ms":index,
                    "end_ms":index + 1,
                    "text":text.as_str(),
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            srt(&segments).err().map(|error| error.code),
            Some("invalid_input")
        );
        assert_eq!(
            vtt(&segments).err().map(|error| error.code),
            Some("invalid_input")
        );
    }

    #[test]
    fn malformed_segments_are_refused_with_sanitized_typed_errors() {
        let malformed = [
            json!({}),
            json!({"start_ms":0,"end_ms":1}),
            json!({"start_ms":0,"end_ms":1,"text":""}),
            json!({"start_ms":-1,"end_ms":1,"text":"negative"}),
            json!({"start_ms":0.5,"end_ms":1,"text":"fraction"}),
            json!({"start_ms":2,"end_ms":1,"text":"backwards"}),
            json!({"start_ms":0,"end_ms":1,"text":false}),
        ];
        for value in malformed {
            let srt_error = srt(std::slice::from_ref(&value)).unwrap_err();
            assert_eq!(srt_error.code, "invalid_input");
            assert!(!srt_error.message.contains("negative"));
            assert_eq!(
                vtt(std::slice::from_ref(&value)).unwrap_err().code,
                "invalid_input"
            );
        }
    }
}
