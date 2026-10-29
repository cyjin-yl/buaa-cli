//! Recognizes only complete, supported top-level viewer declarations.
//! No execution, expression evaluation or interpretation of inactive text.
use super::{failed_contract, unavailable};
use super::{MAX_HREF, inert_element};
use crate::html::{MAX_SCRIPT_BYTES, MAX_SCRIPT_DEPTH, script_quoted_end, script_trivia};
use crate::net::{Error, Response};
use scraper::{ElementRef, Selector};

const MAX_CALLS: usize = 32;

fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn argument(script: &str, offset: &mut usize, first: bool) -> Result<Option<String>, Error> {
    script_trivia(script.as_bytes(), offset).ok_or_else(unavailable)?;
    if !first && script[*offset..].starts_with("vsb_pdf_image_data") {
        let end = *offset + "vsb_pdf_image_data".len();
        if script
            .as_bytes()
            .get(end)
            .is_some_and(|byte| identifier_byte(*byte))
        {
            return Err(unavailable());
        }
        *offset = end;
        return Ok(None);
    }
    // The observed contract uses JSON string literals, not single-quoted,
    // interpolated, concatenated or executable argument expressions.
    if script.as_bytes().get(*offset) != Some(&b'"') {
        return Err(unavailable());
    }
    let mut stream = serde_json::Deserializer::from_str(&script[*offset..]).into_iter::<String>();
    let value = stream
        .next()
        .ok_or_else(unavailable)?
        .map_err(|_| unavailable())?;
    *offset += stream.byte_offset();
    Ok(Some(value))
}

fn call(script: &str, offset: &mut usize) -> Result<String, Error> {
    script_trivia(script.as_bytes(), offset).ok_or_else(unavailable)?;
    if script.as_bytes().get(*offset) != Some(&b'(') {
        return Err(unavailable());
    }
    *offset += 1;
    let path = argument(script, offset, true)?.ok_or_else(unavailable)?;
    let mut count = 1;
    loop {
        script_trivia(script.as_bytes(), offset).ok_or_else(unavailable)?;
        match script.as_bytes().get(*offset) {
            Some(b')') => {
                *offset += 1;
                break;
            }
            Some(b',') if count < 8 => {
                *offset += 1;
                argument(script, offset, false)?;
                count += 1;
            }
            _ => return Err(unavailable()),
        }
    }
    script_trivia(script.as_bytes(), offset).ok_or_else(unavailable)?;
    match script.as_bytes().get(*offset) {
        Some(b';') => *offset += 1,
        None => {}
        _ => return Err(unavailable()),
    }
    Ok(path)
}

pub(crate) fn declarations(script: &str) -> Result<Vec<String>, Error> {
    if !script.contains("showVsbpdfIframe") {
        return Ok(Vec::new());
    }
    if script.len() > MAX_SCRIPT_BYTES {
        return Err(unavailable());
    }
    let bytes = script.as_bytes();
    let mut offset = 0;
    let mut stack = Vec::new();
    let mut statement_start = true;
    let mut paths = Vec::new();
    loop {
        script_trivia(bytes, &mut offset).ok_or_else(unavailable)?;
        let Some(byte) = bytes.get(offset).copied() else {
            break;
        };
        match byte {
            b'"' | b'\'' | b'`' => {
                script_quoted_end(bytes, &mut offset).ok_or_else(unavailable)?;
                statement_start = false;
            }
            b'(' | b'[' | b'{' => {
                if stack.len() == MAX_SCRIPT_DEPTH {
                    return Err(unavailable());
                }
                stack.push(byte);
                offset += 1;
                statement_start = false;
            }
            b')' | b']' | b'}' => {
                let expected = match byte {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                if stack.pop() != Some(expected) {
                    return Err(unavailable());
                }
                offset += 1;
                statement_start = false;
            }
            b';' => {
                offset += 1;
                statement_start = stack.is_empty();
            }
            b'/' => return Err(unavailable()), // unsupported regex/division syntax
            _ if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') => {
                let start = offset;
                while bytes.get(offset).is_some_and(|byte| identifier_byte(*byte)) {
                    offset += 1;
                }
                if &script[start..offset] == "showVsbpdfIframe" {
                    if !stack.is_empty() || !statement_start || paths.len() == MAX_CALLS {
                        return Err(unavailable());
                    }
                    paths.push(call(script, &mut offset)?);
                    statement_start = true;
                } else {
                    statement_start = false;
                }
            }
            _ => {
                offset += 1;
                statement_start = false;
            }
        }
    }
    if !stack.is_empty() {
        return Err(unavailable());
    }
    Ok(paths)
}

pub(crate) fn validate_pdf(response: &Response) -> Result<(), Error> {
    validate_document_mime(response.headers.get("content-type").map(String::as_str))?;
    validate_document_body(&response.body)
}

/// Fresh-response body framing for reviewed original-PDF reads. Runs at the
/// transport admission arm (before immutable-cache equality) so bytes that
/// are not actually PDFs can never be persisted under a `__local` PDF path,
/// regardless of which command fetched them; consumers still re-validate
/// MIME and framing on every read.
pub(crate) fn validate_document_body(body: &[u8]) -> Result<(), Error> {
    let tail = &body[body.len().saturating_sub(1024)..];
    if !body.starts_with(b"%PDF-") || !tail.windows(5).any(|window| window == b"%%EOF") {
        return Err(failed_contract(
            "source document lacks reviewed PDF framing; bytes are not cached as a PDF",
            file!(),
            line!(),
        ));
    }
    Ok(())
}

/// Fresh-response MIME admission for reviewed original-PDF reads. Runs before
/// immutable-cache equality so a wrong MIME cannot hide behind identical
/// retained bytes; consumers still re-validate MIME and framing on every read.
pub(crate) fn validate_document_mime(content_type: Option<&str>) -> Result<(), Error> {
    let mime_ok = content_type.is_none_or(|value| {
        let media = value.split(';').next().unwrap_or_default().trim();
        media.eq_ignore_ascii_case("application/pdf")
            || media.eq_ignore_ascii_case("application/octet-stream")
    });
    if !mime_ok {
        return Err(failed_contract(
            "source document lacks reviewed PDF MIME",
            file!(),
            line!(),
        ));
    }
    Ok(())
}

/// Derived preview-image paths declared by a `vsb_pdf_image_data` array inside
/// the reviewed `div.v_news_content script` body of `scope`. Inert ancestors
/// (template/noscript/svg-style/script/style payloads) are excluded. The JSON
/// array is never evaluated; declaration order and bounds are preserved.
pub(crate) fn preview_paths(scope: ElementRef<'_>) -> Result<(bool, Vec<String>), Error> {
    let selector = Selector::parse("div.v_news_content script").map_err(|_| unavailable())?;
    for node in scope.select(&selector).filter(|node| !inert_element(*node)) {
        // Inspect a bounded JSON string array declared by this observed CMS;
        // never evaluate the script or treat its contents as article prose.
        for text in node.text() {
            let Some(marker) = text.find("vsb_pdf_image_data") else {
                continue;
            };
            let Some(tail) = text[marker..]
                .split_once('=')
                .map(|(_, tail)| tail.trim_start())
            else {
                continue;
            };
            if !tail.starts_with('[') {
                continue;
            }
            let Some(end) = tail.find(']') else {
                continue;
            };
            if end + 1 > 64 * 1024 {
                return Err(unavailable());
            }
            let paths: Vec<String> =
                serde_json::from_str(&tail[..=end]).map_err(|_| unavailable())?;
            if paths.len() > 128
                || paths.iter().any(|path| {
                    path.len() > MAX_HREF
                        || !path.starts_with("/__local/")
                        || path.chars().any(char::is_control)
                })
            {
                return Err(unavailable());
            }
            return Ok((true, paths));
        }
    }
    Ok((false, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;

    fn response(body: &[u8], content_type: Option<&str>) -> Response {
        Response {
            url: "https://scse.buaa.edu.cn/__local/C/C7/70/AAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBB_123.pdf".into(),
            status: 200,
            headers: content_type
                .map(|value| ("content-type".into(), value.into()))
                .into_iter()
                .collect(),
            body: body.to_vec(),
            sha256: "a".repeat(64),
            fetched_at_unix_ms: 0,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    #[test]
    fn declarations_keep_original_path_distinct_from_derived_images_and_inert_text() {
        let script = r#"var vsb_pdf_image_data=["/__local/preview.jpg"];showVsbpdfIframe("/__local/original.pdf","100%",vsb_pdf_image_data);"#;
        assert_eq!(
            declarations(script).unwrap(),
            vec!["/__local/original.pdf".to_owned()]
        );
        let inert = r#"var inert = 'showVsbpdfIframe("/__local/hidden.pdf");';"#;
        assert!(declarations(inert).unwrap().is_empty());
        assert!(declarations("showVsbpdfIframe(vsb_pdf_image_data);").is_err());
    }

    #[test]
    fn declarations_keep_existing_byte_depth_and_call_limits() {
        let call = r#"showVsbpdfIframe("/__local/original.pdf");"#;
        assert_eq!(declarations(&call.repeat(MAX_CALLS)).unwrap().len(), MAX_CALLS);
        assert!(declarations(&call.repeat(MAX_CALLS + 1)).is_err());
        let bounded = format!("{}{call}", " ".repeat(MAX_SCRIPT_BYTES - call.len()));
        assert_eq!(declarations(&bounded).unwrap().len(), 1);
        assert!(declarations(&format!(" {bounded}")).is_err());
        let bounded = format!(
            "{}0{};{call}",
            "(".repeat(MAX_SCRIPT_DEPTH),
            ")".repeat(MAX_SCRIPT_DEPTH)
        );
        assert_eq!(declarations(&bounded).unwrap().len(), 1);
        let excessive = format!(
            "{}0{};{call}",
            "(".repeat(MAX_SCRIPT_DEPTH + 1),
            ")".repeat(MAX_SCRIPT_DEPTH + 1)
        );
        assert!(declarations(&excessive).is_err());
    }

    #[test]
    fn pdf_validation_keeps_existing_mime_and_framing_requirements() {
        let pdf = b"%PDF-1.7\n%%EOF\n";
        for media in [
            None,
            Some("application/pdf"),
            Some("Application/PDF; fixture=synthetic"),
            Some("application/octet-stream"),
        ] {
            assert!(validate_pdf(&response(pdf, media)).is_ok());
        }
        for media in ["text/html", "image/png", ""] {
            assert_eq!(
                validate_pdf(&response(pdf, Some(media))).unwrap_err().code,
                "unavailable"
            );
        }
        for body in ["<html>Not a document</html>", "%PDF-1.7\ntruncated", "%%EOF"] {
            assert_eq!(
                validate_pdf(&response(body.as_bytes(), Some("application/pdf")))
                    .unwrap_err()
                    .code,
                "unavailable"
            );
        }
        let stale_eof = format!("%PDF-1.7\n%%EOF{}", "x".repeat(1024));
        assert_eq!(
            validate_pdf(&response(stale_eof.as_bytes(), None))
                .unwrap_err()
                .code,
            "unavailable"
        );
    }
}
