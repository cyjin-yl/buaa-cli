//! Shared non-executing HTML admission and active source text.
use scraper::{ElementRef, Node};

const HTML_NAMESPACE: &str = "http://www.w3.org/1999/xhtml";

pub(crate) fn is_html_element(element: ElementRef<'_>) -> bool {
    element.value().name.ns.as_ref() == HTML_NAMESPACE
}

/// Script/style payloads remain inactive in every namespace; template/noscript
/// inertness applies only to their HTML elements, not foreign local-name matches.
pub(crate) fn is_inert_context(element: ElementRef<'_>) -> bool {
    let name = element.value().name();
    matches!(name, "script" | "style")
        || (is_html_element(element) && matches!(name, "template" | "noscript"))
}

pub(crate) fn inert_element(element: ElementRef<'_>) -> bool {
    element
        .ancestors()
        .filter_map(ElementRef::wrap)
        .any(is_inert_context)
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
    let mut output = String::new();
    let _ = visit_active_text(
        element,
        |_| false,
        |text| {
            for word in text.split_whitespace() {
                if !output.is_empty() {
                    output.push(' ');
                }
                output.push_str(word);
            }
            false
        },
    );
    output
}

/// Visit active text nodes in document order, stopping when the visitor returns
/// true. Callers can add source-specific inertness without copying subtrees.
pub(crate) fn visit_active_text(
    element: ElementRef<'_>,
    should_skip: impl Fn(ElementRef<'_>) -> bool,
    visit: impl FnMut(&str) -> bool,
) -> bool {
    visit_text(
        element,
        |element| is_inert_text_element(element) || should_skip(element),
        visit,
    )
}

/// Walk text with caller-owned subtree exclusions. Directionality and source
/// prose use different rules, notably for HTML noscript text.
pub(crate) fn visit_text(
    element: ElementRef<'_>,
    should_skip: impl Fn(ElementRef<'_>) -> bool,
    mut visit: impl FnMut(&str) -> bool,
) -> bool {
    if should_skip(element) {
        return false;
    }
    let root = element.id();
    let mut current = element.first_child();
    while let Some(node) = current {
        let skip = ElementRef::wrap(node).is_some_and(&should_skip);
        if let Node::Text(text) = node.value()
            && visit(&text.text)
        {
            return true;
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
    false
}

fn is_inert_text_element(element: ElementRef<'_>) -> bool {
    is_inert_context(element)
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

#[cfg(test)]
mod tests {
    use super::*;
    use scraper::{Html, Selector};

    fn element_by_id<'a>(document: &'a Html, all: &Selector, id: &str) -> ElementRef<'a> {
        document
            .select(all)
            .find(|element| element.value().attr("id") == Some(id))
            .expect("element id")
    }

    #[test]
    fn template_and_noscript_inertness_is_html_namespace_scoped() {
        let document = Html::parse_document(
            r#"<html><body><template id="html-template"><span id="html-template-child">inactive template</span></template><noscript id="html-noscript">inactive noscript</noscript><svg><template id="svg-template"><foreignObject><span id="svg-template-child">active template</span></foreignObject></template><noscript id="svg-noscript"><foreignObject><span id="svg-noscript-child">active noscript</span></foreignObject></noscript></svg><span id="tail">active tail</span></body></html>"#,
        );
        let all = Selector::parse("*").expect("selector");
        let html_template = element_by_id(&document, &all, "html-template");
        let html_noscript = element_by_id(&document, &all, "html-noscript");
        let svg_template = element_by_id(&document, &all, "svg-template");
        let svg_noscript = element_by_id(&document, &all, "svg-noscript");
        assert!(is_inert_text_element(html_template));
        assert!(is_inert_text_element(html_noscript));
        assert!(!is_inert_text_element(svg_template));
        assert!(!is_inert_text_element(svg_noscript));
        assert!(inert_element(element_by_id(
            &document,
            &all,
            "html-template-child"
        )));
        assert!(!inert_element(element_by_id(
            &document,
            &all,
            "svg-template-child"
        )));

        let body = Selector::parse("body").expect("selector");
        let body = document.select(&body).next().expect("body");
        assert_eq!(
            active_element_text(body),
            "active template active noscript active tail"
        );
    }
}
