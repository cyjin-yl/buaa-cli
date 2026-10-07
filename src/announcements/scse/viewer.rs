//! Recognizes only complete, supported top-level viewer declarations.
//! No execution, expression evaluation or interpretation of inactive text.
use super::super::unavailable;
use crate::html::{MAX_SCRIPT_BYTES, MAX_SCRIPT_DEPTH, script_quoted_end, script_trivia};
use crate::net::Error;

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

pub(super) fn declarations(script: &str) -> Result<Vec<String>, Error> {
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
