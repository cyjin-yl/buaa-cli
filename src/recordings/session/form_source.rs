//! Source parser ownership receipt for governed login form admission.
//!
//! The shared `scraper` sink parses with html5ever but does not record the
//! tree builder's native form pointer. Controls that the parser associates
//! with a form outside its final subtree (table insertion modes, foster
//! parenting) therefore have no receipt in the finished DOM. This module
//! replays the identical default parse through a sink wrapper that records
//! `associate_with_form` handles, so admission can reject parser-established
//! ownership it cannot represent with explicit-ID or ancestor ownership.

use ego_tree::NodeId;
use html5ever::tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::{Attribute, QualName, tendril};
use scraper::{Html, HtmlTreeSink};
use std::borrow::Cow;
use std::cell::{Ref, RefCell};

/// The form element the tree builder associated with a form-associatable
/// control while parsing the source.
#[derive(Debug)]
pub(super) struct FormAssociation {
    pub control: NodeId,
    pub form: NodeId,
}

/// Delegates every tree operation to scraper's public `HtmlTreeSink` and
/// records the native form-pointer associations html5ever reports.
#[derive(Debug)]
pub(super) struct RecordingTreeSink {
    inner: HtmlTreeSink,
    associations: RefCell<Vec<FormAssociation>>,
}

impl RecordingTreeSink {
    fn new(html: Html) -> Self {
        Self {
            inner: HtmlTreeSink::new(html),
            associations: RefCell::new(Vec::new()),
        }
    }
}

impl TreeSink for RecordingTreeSink {
    type Output = (Html, Vec<FormAssociation>);
    type Handle = NodeId;
    type ElemName<'a> = Ref<'a, QualName>;

    fn finish(self) -> Self::Output {
        let associations = self.associations.into_inner();
        let html = self.inner.finish();
        (html, associations)
    }

    fn parse_error(&self, msg: Cow<'static, str>) {
        self.inner.parse_error(msg);
    }

    fn get_document(&self) -> Self::Handle {
        self.inner.get_document()
    }

    fn get_template_contents(&self, target: &Self::Handle) -> Self::Handle {
        self.inner.get_template_contents(target)
    }

    fn set_quirks_mode(&self, mode: QuirksMode) {
        self.inner.set_quirks_mode(mode);
    }

    fn same_node(&self, x: &Self::Handle, y: &Self::Handle) -> bool {
        self.inner.same_node(x, y)
    }

    fn elem_name<'a>(&'a self, target: &'a Self::Handle) -> Self::ElemName<'a> {
        self.inner.elem_name(target)
    }

    fn create_element(
        &self,
        name: QualName,
        attrs: Vec<Attribute>,
        flags: ElementFlags,
    ) -> Self::Handle {
        self.inner.create_element(name, attrs, flags)
    }

    fn create_comment(&self, text: tendril::StrTendril) -> Self::Handle {
        self.inner.create_comment(text)
    }

    fn create_pi(&self, target: tendril::StrTendril, data: tendril::StrTendril) -> Self::Handle {
        self.inner.create_pi(target, data)
    }

    fn append(&self, parent: &Self::Handle, child: NodeOrText<Self::Handle>) {
        self.inner.append(parent, child);
    }

    fn append_before_sibling(&self, sibling: &Self::Handle, new_node: NodeOrText<Self::Handle>) {
        self.inner.append_before_sibling(sibling, new_node);
    }

    fn append_based_on_parent_node(
        &self,
        element: &Self::Handle,
        prev_element: &Self::Handle,
        child: NodeOrText<Self::Handle>,
    ) {
        self.inner
            .append_based_on_parent_node(element, prev_element, child);
    }

    fn append_doctype_to_document(
        &self,
        name: tendril::StrTendril,
        public_id: tendril::StrTendril,
        system_id: tendril::StrTendril,
    ) {
        self.inner
            .append_doctype_to_document(name, public_id, system_id);
    }

    fn mark_script_already_started(&self, node: &Self::Handle) {
        self.inner.mark_script_already_started(node);
    }

    fn remove_from_parent(&self, target: &Self::Handle) {
        self.inner.remove_from_parent(target);
    }

    fn reparent_children(&self, node: &Self::Handle, new_parent: &Self::Handle) {
        self.inner.reparent_children(node, new_parent);
    }

    fn add_attrs_if_missing(&self, target: &Self::Handle, attrs: Vec<Attribute>) {
        self.inner.add_attrs_if_missing(target, attrs);
    }

    fn associate_with_form(
        &self,
        target: &Self::Handle,
        form: &Self::Handle,
        _nodes: (&Self::Handle, Option<&Self::Handle>),
    ) {
        // html5ever already excludes controls whose listed `form` attribute
        // points at an explicit owner, so every callback here is a native
        // parser association that final-DOM ancestry cannot re-derive.
        self.associations.borrow_mut().push(FormAssociation {
            control: *target,
            form: *form,
        });
    }
}

/// Replays the shared `Html::parse_document` configuration (default parse
/// options, whole-document mode) through the recording sink. The byte-for-byte
/// replay produces the identical DOM and yields the parser's native form
/// associations alongside it.
pub(super) fn parse_document(html: &str) -> (Html, Vec<FormAssociation>) {
    use tendril::stream::TendrilSink;

    html5ever::driver::parse_document(
        RecordingTreeSink::new(Html::new_document()),
        Default::default(),
    )
    .one(html)
}
