//! Offline timed-line replay. Each nonempty input row is `[seconds]text`.
//!
//! Seconds contain one or more ASCII integer digits, optionally followed by a
//! decimal point and one to nine digits. Offsets must be nondecreasing and at
//! most 24 hours (inclusive); at most 100,000 rows are accepted. Equal offsets
//! retain input order. LF and CRLF delimit rows; a final delimiter is optional
//! and does not introduce another row. Empty input is an empty schedule. Text
//! may be empty and is preserved verbatim, including tabs; other Unicode
//! control characters are rejected. Blank rows are rejected.
//!
//! Validation completes before any output. Default output is one JSON object
//! per row, with `type`, one-based `sequence`, integer `at_ns`, and `text`.
//! Explicit raw mode instead writes text followed by LF. Every row is flushed.
//! Dry-run emits the same JSON schedule without waiting and cannot be combined
//! with raw mode. Replay uses monotonic absolute deadlines and returns directly
//! after the final flush; scheduling and output can make delivery late, never
//! intentionally early. No subprocesses or network operations are performed.

use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

const MAX_OFFSET_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const MAX_ITEMS: usize = 100_000;
const OUTPUT_ERROR: &str = "could not write timed input output";

/// Sanitized failure category for machine-readable CLI errors.
#[derive(Debug)]
pub enum Error {
    InvalidInput(String),
    Unavailable(&'static str),
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::InvalidInput(message)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::Unavailable(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, PartialEq, Eq)]
struct Entry<'a> {
    at_ns: u64,
    text: &'a str,
}

#[derive(Serialize)]
struct Event<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    sequence: usize,
    at_ns: u64,
    text: &'a str,
}

/// Validate and replay a local schedule to stdout.
///
/// See the module documentation for the input grammar, limits, and output
/// contract. Errors contain only static descriptions and, for invalid rows,
/// one-based line numbers: input text is never included. Input size must be
/// bounded by the caller. This function does not close stdout; returning lets
/// a standalone CLI terminate immediately after its final output row.
pub fn run(input: &str, raw: bool, dry_run: bool) -> Result<(), Error> {
    let stdout = io::stdout();
    replay(input, raw, dry_run, &mut stdout.lock())
}

fn line_error(line: usize, reason: &'static str) -> String {
    format!("timed input line {line}: {reason}")
}

fn parse_seconds(seconds: &str) -> Option<u64> {
    let (integer, fractional) = match seconds.split_once('.') {
        Some((integer, fractional)) => (integer, Some(fractional)),
        None => (seconds, None),
    };
    if integer.is_empty() {
        return None;
    }
    let mut whole = 0_u64;
    for digit in integer.bytes() {
        if !digit.is_ascii_digit() {
            return None;
        }
        whole = whole
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
    }
    let mut nanos = 0_u64;
    if let Some(fractional) = fractional {
        if fractional.is_empty() || fractional.len() > 9 {
            return None;
        }
        for digit in fractional.bytes() {
            if !digit.is_ascii_digit() {
                return None;
            }
            nanos = nanos * 10 + u64::from(digit - b'0');
        }
        nanos *= 10_u64.pow(9 - fractional.len() as u32);
    }
    let at_ns = whole.checked_mul(1_000_000_000)?.checked_add(nanos)?;
    (at_ns <= MAX_OFFSET_NS).then_some(at_ns)
}

fn parse_schedule(input: &str) -> Result<Vec<Entry<'_>>, String> {
    let mut entries = Vec::new();
    let mut previous_ns = 0;
    for (index, row) in input.split_inclusive('\n').enumerate() {
        let line = index + 1;
        if index == MAX_ITEMS {
            return Err(line_error(line, "schedule exceeds 100000 rows"));
        }
        let row = match row.strip_suffix('\n') {
            Some(row) => row.strip_suffix('\r').unwrap_or(row),
            None => row,
        };
        let (seconds, text) = row
            .strip_prefix('[')
            .and_then(|row| row.split_once(']'))
            .ok_or_else(|| line_error(line, "expected [seconds]text"))?;
        let at_ns = parse_seconds(seconds)
            .ok_or_else(|| line_error(line, "invalid timestamp or offset exceeds 24 hours"))?;
        if at_ns < previous_ns {
            return Err(line_error(line, "timestamps must be nondecreasing"));
        }
        if text.chars().any(|ch| ch.is_control() && ch != '\t') {
            return Err(line_error(
                line,
                "text contains a prohibited control character",
            ));
        }
        entries.push(Entry { at_ns, text });
        previous_ns = at_ns;
    }
    Ok(entries)
}

fn emit<W: Write>(
    output: &mut W,
    entry: &Entry<'_>,
    sequence: usize,
    raw: bool,
) -> Result<(), Error> {
    if raw {
        output
            .write_all(entry.text.as_bytes())
            .map_err(|_| Error::Unavailable(OUTPUT_ERROR))?;
    } else {
        let event = Event {
            kind: "timed_input",
            sequence,
            at_ns: entry.at_ns,
            text: entry.text,
        };
        serde_json::to_writer(&mut *output, &event)
            .map_err(|_| Error::Unavailable(OUTPUT_ERROR))?;
    }
    output
        .write_all(b"\n")
        .map_err(|_| Error::Unavailable(OUTPUT_ERROR))?;
    output.flush().map_err(|_| Error::Unavailable(OUTPUT_ERROR))
}

fn replay<W: Write>(input: &str, raw: bool, dry_run: bool, output: &mut W) -> Result<(), Error> {
    if raw && dry_run {
        return Err(Error::InvalidInput(
            "--raw and --dry-run cannot be combined".to_owned(),
        ));
    }
    let entries = parse_schedule(input)?;
    let start = Instant::now();
    // Check the largest deadline before emitting anything, even on platforms
    // whose monotonic clock cannot represent the entire allowed interval.
    if let Some(last) = entries.last() {
        start
            .checked_add(Duration::from_nanos(last.at_ns))
            .ok_or_else(|| {
                "timed input deadline is outside the supported clock range".to_owned()
            })?;
    }
    for (index, entry) in entries.iter().enumerate() {
        if !dry_run {
            let deadline = start + Duration::from_nanos(entry.at_ns);
            while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                if remaining.is_zero() {
                    break;
                }
                thread::sleep(remaining);
            }
        }
        emit(output, entry, index + 1, raw)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decimals_are_exact_through_the_inclusive_runtime_boundary() {
        let entries = parse_schedule(
            "[0.000000001]a\n[1.000000001]b\n[86399.999999999]c\n[86400.000000000]d",
        )
        .unwrap();
        assert_eq!(
            entries.iter().map(|entry| entry.at_ns).collect::<Vec<_>>(),
            [1, 1_000_000_001, MAX_OFFSET_NS - 1, MAX_OFFSET_NS]
        );
        assert!(parse_schedule("[86400.000000001]x").is_err());
        assert!(parse_schedule("[0.0000000001]x").is_err());
        assert!(parse_schedule("[18446744073709551616]x").is_err());
        assert!(parse_schedule("[18446744073709551615]x").is_err());
    }

    #[test]
    fn dry_run_preserves_equal_time_order_crlf_and_empty_text() {
        let mut output = Vec::new();
        replay(
            "[0]  first\t\r\n[0]\r\n[0.000000001]雪\"\\",
            false,
            true,
            &mut output,
        )
        .unwrap();
        let events: Vec<serde_json::Value> = std::str::from_utf8(&output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            events,
            vec![
                json!({"type":"timed_input", "sequence":1, "at_ns":0, "text":"  first\t"}),
                json!({"type":"timed_input", "sequence":2, "at_ns":0, "text":""}),
                json!({"type":"timed_input", "sequence":3, "at_ns":1, "text":"雪\"\\"}),
            ]
        );
        assert_eq!(output.last(), Some(&b'\n'));
    }

    #[test]
    fn malformed_late_row_produces_no_partial_output_or_payload_leakage() {
        let mut output = Vec::new();
        let error = replay(
            "[0]valid\n[1]also valid\n[secret]sensitive-value",
            false,
            true,
            &mut output,
        )
        .unwrap_err()
        .to_string();
        assert!(output.is_empty());
        assert!(error.contains("line 3"));
        assert!(!error.contains("secret"));
        assert!(!error.contains("sensitive-value"));
        assert!(replay("[1]first\n[0.999999999]second", false, true, &mut output).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn rejects_nondecimal_times_and_embedded_controls() {
        for input in [
            "[-1]x", "[NaN]x", "[inf]x", "[1e2]x", "[.5]x", "[1.]x", "[+1]x", "[ 1]x",
        ] {
            assert!(parse_schedule(input).is_err());
        }
        for input in [
            "[0]x\0",
            "[0]x\r",
            "[0]x\u{1b}",
            "[0]x\u{7f}",
            "[0]x\u{85}",
            "[0]x\n\n",
        ] {
            assert!(parse_schedule(input).is_err());
        }
    }

    #[test]
    fn empty_input_and_item_limit_have_explicit_boundaries() {
        let mut output = Vec::new();
        replay("", false, true, &mut output).unwrap();
        assert!(output.is_empty());
        let mut input = "[0]\n".repeat(MAX_ITEMS);
        assert_eq!(parse_schedule(&input).unwrap().len(), MAX_ITEMS);
        input.push_str("[0]");
        let error = replay(&input, false, true, &mut output)
            .unwrap_err()
            .to_string();
        assert!(output.is_empty());
        assert!(error.contains("line 100001"));
    }

    #[test]
    fn raw_rows_preserve_text_and_flush_each_row() {
        #[derive(Default)]
        struct Sink {
            bytes: Vec<u8>,
            flushes: usize,
        }
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                Ok(())
            }
        }
        let mut output = Sink::default();
        emit(
            &mut output,
            &Entry {
                at_ns: 0,
                text: "  quoted \"雪\"\t",
            },
            1,
            true,
        )
        .unwrap();
        emit(&mut output, &Entry { at_ns: 0, text: "" }, 2, true).unwrap();
        assert_eq!(output.bytes, "  quoted \"雪\"\t\n\n".as_bytes());
        assert_eq!(output.flushes, 2);
        let mut invalid_output = Vec::new();
        assert!(replay("[0]x", true, true, &mut invalid_output).is_err());
        assert!(invalid_output.is_empty());
    }
}
