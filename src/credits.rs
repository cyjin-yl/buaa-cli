//! School-specific graduation credit calculation.
//!
//! The 2020-cohort general-major ("拟准出专业") policy for the School of
//! Economics and Management (school 8) is ported faithfully from the public
//! reference catalog. It is a deterministic, fully offline computation over
//! owner-supplied course selections: no campus read, no network, no state.
//!
//! Policy (general major, 25 required valid credits):
//!   - A course tagged 一般专业类 counts toward the 25 as "general".
//!   - A core-major course (tagged with one or more majors) that matches the
//!     student's major counts toward that major's requirement and is NOT part
//!     of the 25 ("core-major", 不计入).
//!   - A core-major course that does NOT match the student's major counts
//!     toward the 25 as "core-other".
//!   - remaining = 25 - (general + core-other).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const REQUIRED_CREDITS: f64 = 25.0;
const GENERAL_TAG: &str = "一般专业类";
// Derived from non-general major tags in the sourced 2020 school-8 catalog.
const SUPPORTED_MAJORS: &[&str] = &[
    "会计学",
    "信息管理与信息系统",
    "工业工程",
    "工商管理",
    "工程管理",
    "经济统计",
    "能源经济",
    "金融工程",
];

fn invalid() -> Value {
    json!({"error":"invalid_input","message":"credits input is invalid"})
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Course {
    name: String,
    credit: f64,
    #[serde(default)]
    grade: Option<String>,
    #[serde(default)]
    term: Option<String>,
    majors: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CalculateInput {
    #[serde(rename = "major")]
    major: String,
    #[serde(default)]
    selected: Vec<String>,
}

fn classify_course(course: &Course, major: &str) -> (&'static str, bool) {
    if course
        .majors
        .first()
        .is_some_and(|value| value == GENERAL_TAG)
    {
        ("general", true)
    } else if course.majors.iter().any(|value| value == major) {
        ("core_major", false)
    } else {
        ("core_other", true)
    }
}

#[derive(Debug, Serialize)]
struct CourseLine {
    name: String,
    credit: f64,
    category: &'static str,
    counts_toward_25: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    term: Option<String>,
}

pub fn calculate(input: &str) -> Value {
    let request: CalculateInput = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(_) => return invalid(),
    };
    if request.major.is_empty() || !SUPPORTED_MAJORS.contains(&request.major.as_str()) {
        return invalid();
    }
    let catalog: Value = match serde_json::from_str(include_str!("credits_catalog.json")) {
        Ok(value) => value,
        Err(_) => return json!({"error":"unavailable","message":"credits catalog is unavailable"}),
    };
    let courses: Vec<Course> = match serde_json::from_value(catalog["courses"].clone()) {
        Ok(value) => value,
        Err(_) => return json!({"error":"unavailable","message":"credits catalog is malformed"}),
    };

    // Build the selection set and detect source duplicates by name.
    let mut name_to_index: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for (index, course) in courses.iter().enumerate() {
        name_to_index
            .entry(course.name.clone())
            .or_default()
            .push(index);
    }

    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut lines: Vec<CourseLine> = Vec::new();
    let mut duplicate_names: Vec<String> = Vec::new();
    let mut general = 0.0;
    let mut core_major = 0.0;
    let mut core_other = 0.0;
    let mut total = 0.0;

    for name in request.selected.iter() {
        if !seen.insert(name.clone()) {
            // Repeated selection of the same course is a no-op, not a re-add.
            continue;
        }
        let Some(matches) = name_to_index.get(name) else {
            return json!({"error":"invalid_input","message":"unknown course in selection"});
        };
        let course = &courses[matches[0]];
        let (category, counts) = classify_course(course, &request.major);
        if matches.len() > 1 {
            let equivalent = matches.iter().skip(1).all(|index| {
                let candidate = &courses[*index];
                candidate.credit == course.credit
                    && candidate.grade == course.grade
                    && candidate.term == course.term
                    && classify_course(candidate, &request.major) == (category, counts)
            });
            if !equivalent {
                return invalid();
            }
            duplicate_names.push(name.clone());
        }
        let credit = course.credit;
        match category {
            "general" => general += credit,
            "core_major" => core_major += credit,
            _ => core_other += credit,
        }
        if counts {
            total += credit;
        }
        lines.push(CourseLine {
            name: name.clone(),
            credit,
            category,
            counts_toward_25: counts,
            grade: course.grade.clone(),
            term: course.term.clone(),
        });
    }

    let remaining = (REQUIRED_CREDITS - total).max(0.0);
    let satisfied = total >= REQUIRED_CREDITS - 1e-9;

    let mut warnings: Vec<String> = Vec::new();
    if !duplicate_names.is_empty() {
        warnings.push(format!(
            "equivalent duplicate course rows were collapsed: {}",
            duplicate_names.join(", ")
        ));
    }

    json!({
        "schema_version": 1,
        "type": "credits_calculate",
        "result": if satisfied { "satisfied" } else { "deficit" },
        "policy": {
            "school": "economics_management",
            "cohort": "2020",
            "track": "general_major",
            "required_credits": REQUIRED_CREDITS
        },
        "major": request.major,
        "categories": {
            "general": round2(general),
            "core_major_not_counted": round2(core_major),
            "core_other": round2(core_other)
        },
        "total_counted": round2(total),
        "remaining": round2(remaining),
        "satisfied": satisfied,
        "courses": lines,
        "warnings": warnings
    })
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

pub fn schema() -> Value {
    json!({"calculate": {
        "input": {"type":"object","additionalProperties":false,"required":["major","selected"],
            "properties":{"major":{"type":"string","enum":SUPPORTED_MAJORS},
                "selected":{"type":"array","items":{"type":"string","minLength":1}}}},
        "output": {"type":"object","additionalProperties":false,
            "required":["schema_version","type","result","policy","major","categories","total_counted","remaining","satisfied","courses","warnings"],
            "properties":{"schema_version":{"const":1},"type":{"const":"credits_calculate"},
                "result":{"enum":["satisfied","deficit"]},
                "categories":{"type":"object","additionalProperties":false,
                    "required":["general","core_major_not_counted","core_other"]},
                "total_counted":{"type":"number","minimum":0},
                "remaining":{"type":"number","minimum":0},
                "satisfied":{"type":"boolean"},
                "courses":{"type":"array"},
                "warnings":{"type":"array","items":{"type":"string"}}}}}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_and_matching_core_split_counts_only_general() {
        let out =
            calculate(r#"{"major":"信息管理与信息系统","selected":["运筹学（二）","健康经济学"]}"#);
        // 运筹学（二） matches the major → core_major (not counted); 健康经济学 is general (counted).
        assert_eq!(out["categories"]["general"], 2.0);
        assert_eq!(out["categories"]["core_major_not_counted"], 2.0);
        assert_eq!(out["total_counted"], 2.0);
        assert_eq!(out["remaining"], 23.0);
        assert_eq!(out["result"], "deficit");
    }

    #[test]
    fn unmatched_core_major_counts_as_core_other() {
        // 组织行为学 is 工商管理|会计学 core; major 工业工程 does not match → counted.
        let out = calculate(r#"{"major":"工业工程","selected":["组织行为学"]}"#);
        assert_eq!(out["categories"]["core_other"], 2.0);
        assert_eq!(out["categories"]["core_major_not_counted"], 0.0);
        assert_eq!(out["total_counted"], 2.0);
    }

    #[test]
    fn repeated_selection_is_not_double_counted() {
        let out = calculate(r#"{"major":"会计学","selected":["健康经济学","健康经济学"]}"#);
        assert_eq!(out["total_counted"], 2.0);
        assert_eq!(out["courses"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn unknown_course_is_invalid() {
        let out = calculate(r#"{"major":"会计学","selected":["不存在课程"]}"#);
        assert_eq!(out["error"], "invalid_input");
    }

    #[test]
    fn malformed_input_is_invalid() {
        let out = calculate(r#"{"major":""}"#);
        assert_eq!(out["error"], "invalid_input");
    }

    #[test]
    fn enough_general_credits_report_satisfied_with_zero_remaining() {
        let catalog: Value = serde_json::from_str(include_str!("credits_catalog.json")).unwrap();
        let mut names: Vec<String> = catalog["courses"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["majors"][0] == GENERAL_TAG)
            .map(|c| c["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        names.dedup();
        let selected: Vec<String> = names.into_iter().take(14).collect();
        let input = json!({"major":"会计学","selected":selected});
        let out = calculate(&input.to_string());
        assert!(out["total_counted"].as_f64().unwrap() >= REQUIRED_CREDITS);
        assert_eq!(out["satisfied"], true);
        assert_eq!(out["remaining"], 0.0);
        assert_eq!(out["result"], "satisfied");
    }

    #[test]
    fn unknown_major_rejects_previously_satisfied_core_selection() {
        let selected = [
            "运筹学（二）",
            "管理信息系统",
            "生产与运作管理",
            "现代程序设计",
            "计量经济学",
            "国际经济学",
            "货币金融学",
            "应用随机过程",
            "组织行为学",
            "市场营销",
            "财务报表分析",
        ];
        let catalog: Value = serde_json::from_str(include_str!("credits_catalog.json")).unwrap();
        let courses = catalog["courses"].as_array().unwrap();
        let selected_credits: f64 = selected
            .iter()
            .map(|name| {
                let course = courses
                    .iter()
                    .find(|course| course["name"] == *name)
                    .unwrap();
                assert_ne!(course["majors"][0], GENERAL_TAG);
                course["credit"].as_f64().unwrap()
            })
            .sum();
        assert_eq!(selected_credits, 25.0);
        let input = json!({"major":"NOT_A_REAL_MAJOR","selected":selected});
        let out = calculate(&input.to_string());
        assert_eq!(out["error"], "invalid_input");
        assert!(out.get("satisfied").is_none());
    }

    #[test]
    fn supported_major_schema_matches_catalog_tags() {
        let catalog: Value = serde_json::from_str(include_str!("credits_catalog.json")).unwrap();
        let catalog_majors: std::collections::BTreeSet<_> = catalog["courses"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|course| course["majors"].as_array().unwrap())
            .map(|major| major.as_str().unwrap())
            .filter(|major| *major != GENERAL_TAG)
            .collect();
        let contract_majors: std::collections::BTreeSet<_> =
            SUPPORTED_MAJORS.iter().copied().collect();
        assert_eq!(contract_majors, catalog_majors);
        assert_eq!(
            schema()["calculate"]["input"]["properties"]["major"]["enum"],
            json!(SUPPORTED_MAJORS)
        );
    }

    #[test]
    fn conflicting_duplicate_course_identity_is_rejected() {
        let out = calculate(r#"{"major":"经济统计","selected":["非参数统计"]}"#);
        assert_eq!(out["error"], "invalid_input");
        assert!(out.get("result").is_none());
    }

    #[test]
    fn equivalent_duplicate_catalog_rows_are_deduplicated_with_warning() {
        let out = calculate(r#"{"major":"会计学","selected":["健康经济学"]}"#);
        assert_eq!(out["total_counted"], 2.0);
        assert_eq!(out["courses"].as_array().unwrap().len(), 1);
        assert!(out["warnings"][0].as_str().unwrap().contains("健康经济学"));
    }
}
