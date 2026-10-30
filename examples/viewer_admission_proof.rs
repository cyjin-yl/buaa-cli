use buaa_cli::{announcements, net::{CacheStatus, Response}};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, process::ExitCode};

const ARTICLE: &str = "https://scse.buaa.edu.cn/info/1099/42.htm";
const ACTIVE: &str = "/__local/C/C7/70/AAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBB_123.pdf";
const OTHER: &str = "/__local/C/C7/70/AAAAAAAAAAAAAAAAAAAAAAAAAAA_CCCCCCCC_123.pdf";
const PREVIEW: &str = "/__local/active-preview.jpg";
const INERT_PREVIEW: &str = "/__local/inert-preview.jpg";

fn run(name: &str, content: &str, expected: Value) -> Value {
    let body = format!("<div class=\"d1\"><p class=\"bt\">Synthetic source</p></div><div class=\"v_news_content\">{content}</div>").into_bytes();
    let response = Response {
        url: ARTICLE.into(), status: 200,
        headers: BTreeMap::from([("content-type".into(), "text/html; charset=utf-8".into())]),
        sha256: format!("{:x}", Sha256::digest(&body)), body,
        fetched_at_unix_ms: 1_700_000_000_000,
        cache_status: CacheStatus::Miss, revalidated_at_unix_ms: None,
        revalidation_status: None,
    };
    let actual = match announcements::proof_scse_article(&response) {
        Ok(value) => json!({
            "result":value["result"],
            "paragraphs":value["body_paragraphs"],
            "present":value["embedded_document"]["present"],
            "original":value["embedded_document"]["original_pdf_url"],
            "previews":value["embedded_document"]["preview_paths"],
            "original_verified":value["embedded_document"]["original_document_verified"],
            "assets_fetched":value["embedded_document"]["assets_fetched"],
        }),
        Err(error) => json!({"error":error.code}),
    };
    json!({"case":name,"passed":actual==expected,"observed":actual,"expected":expected})
}

fn document(original: Option<&str>, previews: &[&str]) -> Value {
    json!({"result":"embedded_document","paragraphs":[],"present":true,
        "original":original,"previews":previews,"original_verified":false,"assets_fetched":false})
}

fn main() -> ExitCode {
    let original_url = format!("https://scse.buaa.edu.cn{ACTIVE}");
    let original = format!("<script>showVsbpdfIframe(\"{ACTIVE}\",\"100%\");</script>");
    let preview = format!("<script>var vsb_pdf_image_data=[\"{PREVIEW}\"];</script>");
    let prose = json!({"result":"full_text","paragraphs":["Source prose."],"present":false,
        "original":null,"previews":[],"original_verified":false,"assets_fetched":false});
    let mut rows = vec![
        run("active-original", &original, document(Some(&original_url), &[])),
        run("active-preview-distinct-from-original", &preview, document(None, &[PREVIEW])),
        run("prose-without-document", "<p>Source prose.</p>", prose.clone()),
    ];
    for (label, open, close) in [
        ("template-control", "<template>", "</template>"),
        ("noscript-control", "<noscript>", "</noscript>"),
        ("foreign-style", "<svg><style>", "</style></svg>"),
    ] {
        let inert_original = format!("{open}<script>showVsbpdfIframe(\"{OTHER}\",\"100%\");</script>{close}");
        let inert_preview = format!("{open}<script>var vsb_pdf_image_data=[\"{INERT_PREVIEW}\"];</script>{close}");
        let inert_both = format!("{open}<script>var vsb_pdf_image_data=[\"{INERT_PREVIEW}\"];showVsbpdfIframe(\"{OTHER}\",\"100%\");</script>{close}");
        rows.push(run(&format!("{label}-original-with-prose"), &format!("<p>Source prose.</p>{inert_original}"), prose.clone()));
        rows.push(run(&format!("{label}-preview-with-prose"), &format!("<p>Source prose.</p>{inert_preview}"), prose.clone()));
        rows.push(run(&format!("{label}-only-inert"), &inert_both, json!({"error":"unavailable"})));
        rows.push(run(&format!("{label}-cannot-conflict-with-active-original"), &format!("{inert_both}{original}"), document(Some(&original_url), &[])));
        rows.push(run(&format!("{label}-cannot-replace-active-preview"), &format!("{inert_preview}{preview}"), document(None, &[PREVIEW])));
    }
    let passed = rows.iter().all(|row| row["passed"] == true);
    println!("{}", json!({"scope":"actual-library-scse-normalizer-synthetic-consumer",
        "campus_requests":0,"cases":rows,"passed":passed}));
    if passed { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
