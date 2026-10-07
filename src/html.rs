//! Shared non-executing HTML admission and active source text.
use scraper::{ElementRef, Node};

pub(crate) fn inert_element(element: ElementRef<'_>) -> bool {
    element.ancestors().any(|node| {
        node.value()
            .as_element()
            .is_some_and(|node| matches!(node.name(), "script" | "style" | "template" | "noscript"))
    })
}

/// Script/style/template/noscript payloads are not source prose.
pub(crate) fn element_text(element: ElementRef<'_>) -> String {
    if inert_element(element) {
        return String::new();
    }
    active_element_text(element)
}

/// Linear DOM walk after the caller has checked the outer context; no ancestor
/// rescans or subtree copies, including for active image-only attachment links.
pub(crate) fn active_element_text(element: ElementRef<'_>) -> String {
    let root = element.id();
    let mut current = element.first_child();
    let mut output = String::new();
    while let Some(node) = current {
        let skip = node.value().as_element().is_some_and(|node| {
            matches!(node.name(), "script" | "style" | "template" | "noscript")
        });
        if let Node::Text(text) = node.value() {
            for word in text.text.split_whitespace() {
                if !output.is_empty() {
                    output.push(' ');
                }
                output.push_str(word);
            }
        }
        if !skip && let Some(child) = node.first_child() {
            current = Some(child);
            continue;
        }
        let mut cursor = node;
        loop {
            if let Some(sibling) = cursor.next_sibling() {
                current = Some(sibling);
                break;
            }
            match cursor.parent() {
                Some(parent) if parent.id() != root => cursor = parent,
                _ => {
                    current = None;
                    break;
                }
            }
        }
    }
    output
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ScriptKind {
    Classic,
    Module,
}

pub(crate) const MAX_SCRIPT_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SCRIPT_DEPTH: usize = 128;

fn script_line_end(bytes: &[u8], offset: usize) -> usize {
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

/// Bounded recognizers share classic-script comment and line-ending rules.
/// This skips trivia only; it does not evaluate JavaScript.
pub(crate) fn script_trivia(bytes: &[u8], offset: &mut usize) -> Option<()> {
    loop {
        while let Some(byte) = bytes.get(*offset) {
            let line_end = script_line_end(bytes, *offset);
            if !byte.is_ascii_whitespace() && line_end == 0 {
                break;
            }
            *offset += line_end.max(1);
        }
        if bytes.get(*offset..*offset + 2) == Some(b"//")
            || bytes.get(*offset..*offset + 4) == Some(b"<!--")
        {
            while *offset < bytes.len() && script_line_end(bytes, *offset) == 0 {
                *offset += 1;
            }
        } else if bytes.get(*offset..*offset + 3) == Some(b"-->") {
            let mut start = *offset;
            while start > 0
                && bytes[start - 1].is_ascii_whitespace()
                && !matches!(bytes[start - 1], b'\r' | b'\n')
            {
                start -= 1;
            }
            if start != 0 && !matches!(bytes[start - 1], b'\r' | b'\n') {
                return None;
            }
            while *offset < bytes.len() && script_line_end(bytes, *offset) == 0 {
                *offset += 1;
            }
        } else if bytes.get(*offset..*offset + 2) == Some(b"/*") {
            *offset += 2;
            while bytes.get(*offset..*offset + 2) != Some(b"*/") {
                if *offset >= bytes.len() {
                    return None;
                }
                *offset += 1;
            }
            *offset += 2;
        } else {
            return Some(());
        }
    }
}

pub(crate) fn script_quoted_end(bytes: &[u8], offset: &mut usize) -> Option<()> {
    let quote = *bytes.get(*offset)?;
    if !matches!(quote, b'\'' | b'"' | b'`') {
        return None;
    }
    *offset += 1;
    while let Some(byte) = bytes.get(*offset) {
        *offset += 1;
        if *byte == quote {
            return Some(());
        }
        if quote == b'`' && *byte == b'$' && bytes.get(*offset) == Some(&b'{') {
            return None;
        }
        if *byte == b'\\' {
            if *offset == bytes.len() {
                return None;
            }
            *offset += 1;
        }
    }
    None
}

pub(crate) fn script_kind(element: ElementRef<'_>) -> Option<ScriptKind> {
    let explicit_type = element.value().attr("type");
    // An explicit empty type still takes precedence over the legacy language.
    if explicit_type.is_none()
        && element.value().attr("language").is_some_and(|language| {
            !language.is_empty() && !language.eq_ignore_ascii_case("javascript")
        })
    {
        return None;
    }
    let kind = explicit_type
        .unwrap_or_default()
        .trim_matches(|ch| matches!(ch, '\t' | '\n' | '\u{000c}' | '\r' | ' '));
    if kind.eq_ignore_ascii_case("module") {
        return Some(ScriptKind::Module);
    }
    if kind.is_empty()
        || [
            "text/javascript",
            "application/javascript",
            "text/ecmascript",
            "application/ecmascript",
            "application/x-javascript",
        ]
        .iter()
        .any(|allowed| kind.eq_ignore_ascii_case(allowed))
    {
        Some(ScriptKind::Classic)
    } else {
        None
    }
}
