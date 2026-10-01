//! Recognizes only complete, supported top-level viewer declarations.
//! No execution, expression evaluation or interpretation of inactive text.
use super::super::unavailable;
use crate::net::Error;

const MAX_SCRIPT: usize = 64 * 1024;
const MAX_DEPTH: usize = 128;
const MAX_CALLS: usize = 32;

fn line_end(bytes: &[u8], offset: usize) -> usize {
    if bytes
        .get(offset)
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return 1;
    }
    if matches!(
        bytes.get(offset..offset + 3),
        Some([0xe2, 0x80, 0xa8 | 0xa9])
    ) {
        return 3;
    }
    0
}

fn trivia(bytes: &[u8], offset: &mut usize) -> Result<(), Error> {
    loop {
        while bytes.get(*offset).is_some_and(u8::is_ascii_whitespace)
            || line_end(bytes, *offset) != 0
        {
            *offset += line_end(bytes, *offset).max(1);
        }
        if bytes.get(*offset..*offset + 2) == Some(b"//")
            || bytes.get(*offset..*offset + 4) == Some(b"<!--")
        {
            while *offset < bytes.len() && line_end(bytes, *offset) == 0 {
                *offset += 1;
            }
        } else if bytes.get(*offset..*offset + 3) == Some(b"-->") {
            // Annex-B closing comments are supported only at a line boundary.
            let mut start = *offset;
            while start > 0
                && bytes[start - 1].is_ascii_whitespace()
                && !matches!(bytes[start - 1], b'\r' | b'\n')
            {
                start -= 1;
            }
            if start != 0 && !matches!(bytes[start - 1], b'\r' | b'\n') {
                return Err(unavailable());
            }
            while *offset < bytes.len() && line_end(bytes, *offset) == 0 {
                *offset += 1;
            }
        } else if bytes.get(*offset..*offset + 2) == Some(b"/*") {
            *offset += 2;
            while bytes.get(*offset..*offset + 2) != Some(b"*/") {
                if *offset >= bytes.len() {
                    return Err(unavailable());
                }
                *offset += 1;
            }
            *offset += 2;
        } else {
            return Ok(());
        }
    }
}

fn quoted(bytes: &[u8], offset: &mut usize) -> Result<(), Error> {
    let quote = bytes[*offset];
    *offset += 1;
    while let Some(byte) = bytes.get(*offset) {
        *offset += 1;
        if *byte == quote {
            return Ok(());
        }
        if quote == b'`' && *byte == b'$' && bytes.get(*offset) == Some(&b'{') {
            return Err(unavailable()); // active interpolation is unsupported
        }
        if *byte == b'\\' {
            if *offset == bytes.len() {
                return Err(unavailable());
            }
            *offset += 1;
        }
    }
    Err(unavailable())
}

fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn argument(script: &str, offset: &mut usize, first: bool) -> Result<Option<String>, Error> {
    trivia(script.as_bytes(), offset)?;
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
    trivia(script.as_bytes(), offset)?;
    if script.as_bytes().get(*offset) != Some(&b'(') {
        return Err(unavailable());
    }
    *offset += 1;
    let path = argument(script, offset, true)?.ok_or_else(unavailable)?;
    let mut count = 1;
    loop {
        trivia(script.as_bytes(), offset)?;
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
    trivia(script.as_bytes(), offset)?;
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
    if script.len() > MAX_SCRIPT {
        return Err(unavailable());
    }
    let bytes = script.as_bytes();
    let mut offset = 0;
    let mut stack = Vec::new();
    let mut statement_start = true;
    let mut paths = Vec::new();
    loop {
        trivia(bytes, &mut offset)?;
        let Some(byte) = bytes.get(offset).copied() else {
            break;
        };
        match byte {
            b'"' | b'\'' | b'`' => {
                quoted(bytes, &mut offset)?;
                statement_start = false;
            }
            b'(' | b'[' | b'{' => {
                if stack.len() == MAX_DEPTH {
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
