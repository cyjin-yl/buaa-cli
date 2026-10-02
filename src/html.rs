//! Shared non-executing HTML script-type admission for source evidence.
use scraper::ElementRef;

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
