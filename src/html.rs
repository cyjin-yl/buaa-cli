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
