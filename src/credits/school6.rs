//! Offline checks against a pinned community description of the 2020 CS plan.
//! Course classification and qualifying attributes are operator assertions,
//! not university records. No official graduation decision is produced.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const SOURCE: &str = "https://github.com/TrickEye/can_I_Graduate/blob/5e0f0355455d7eb7e69f953a23ca405e5af7ebed/src/App.vue#L450-L461";
const MAX_INPUT: usize = 256 * 1024;
const MAX_COURSES: usize = 512;
const REQUIRED_TOTAL: u32 = 15_000;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
// Variant order is the REQUIREMENTS order used by the fixed accumulator.
enum Category {
    MathScience,
    Engineering,
    Language,
    Ideology,
    Military,
    Sports,
    CoreGeneral,
    GeneralEducation,
    Boya,
    MathModeling,
    CoreMajor,
    GeneralMajor,
}

// Credit facts only; no upstream implementation or course catalog is copied.
const REQUIREMENTS: &[(Category, u32)] = &[
    (Category::MathScience, 3100),
    (Category::Engineering, 900),
    (Category::Language, 800),
    (Category::Ideology, 1200),
    (Category::Military, 200),
    (Category::Sports, 400),
    (Category::CoreGeneral, 1050),
    (Category::GeneralEducation, 0),
    (Category::Boya, 400),
    (Category::MathModeling, 200),
    (Category::CoreMajor, 4250),
    (Category::GeneralMajor, 2500),
];

#[derive(Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
struct Qualifications {
    english: bool,
    english_exchange: bool,
    cross_major: bool,
    humanities_core: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Course {
    id: String,
    name: String,
    credits: f64,
    category: Category,
    passed: bool,
    #[serde(default)]
    qualifications: Qualifications,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    cohort: String,
    courses: Vec<Course>,
}

fn invalid() -> Value {
    json!({"error":"invalid_input","message":"school6 credits input is invalid"})
}

fn credit_units(credits: f64) -> Option<u32> {
    // A bounded hundredth-credit representation keeps all aggregate arithmetic
    // exact. This is an input representation limit, not a university policy.
    if !credits.is_finite() || credits <= 0.0 || credits > 100.0 {
        return None;
    }
    let units = credits * 100.0;
    let rounded = units.round();
    // Canonical round-trip, not an epsilon that admits near-threshold inputs.
    if rounded < 1.0 || rounded / 100.0 != credits {
        return None;
    }
    Some(rounded as u32)
}

fn text_valid(text: &str, limit: usize) -> bool {
    !text.trim().is_empty() && text.len() <= limit && !text.chars().any(char::is_control)
}

/// Check explicitly classified, operator-supplied earned courses. Repeated
/// attempts count once if any passes; conflicting identity facts fail closed.
/// This deduplication rule is not an assertion of official retake policy.
pub fn calculate(input: &str) -> Value {
    if input.len() > MAX_INPUT {
        return invalid();
    }
    let request: Input = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(_) => return invalid(),
    };
    if request.cohort != "2020" || request.courses.len() > MAX_COURSES {
        return invalid();
    }
    let mut unique: BTreeMap<&str, (&Course, u32, bool)> = BTreeMap::new();
    let mut duplicate_attempts = 0;
    for course in &request.courses {
        let Some(units) = credit_units(course.credits) else {
            return invalid();
        };
        if !text_valid(&course.id, 256) || !text_valid(&course.name, 512) {
            return invalid();
        }
        match unique.get_mut(course.id.as_str()) {
            None => {
                unique.insert(&course.id, (course, units, course.passed));
            }
            Some((previous, previous_units, passed)) => {
                if previous.name != course.name
                    || *previous_units != units
                    || previous.category != course.category
                    || previous.qualifications != course.qualifications
                {
                    return invalid();
                }
                *passed |= course.passed;
                duplicate_attempts += 1;
            }
        }
    }
    let mut totals = [0_u32; REQUIREMENTS.len()];
    let mut english = Vec::new();
    let mut cross_major = Vec::new();
    let mut humanities = Vec::new();
    let mut earned = Vec::new();
    for (id, (course, units, passed)) in unique {
        if !passed {
            continue;
        }
        let index = course.category as usize;
        totals[index] += units;
        earned.push(id);
        if units == 200
            && (course.qualifications.english_exchange
                || (course.qualifications.english
                    && matches!(
                        course.category,
                        Category::CoreMajor | Category::GeneralMajor | Category::GeneralEducation
                    )))
        {
            english.push(id);
        }
        if course.qualifications.cross_major
            && units >= 200
            && matches!(
                course.category,
                Category::CoreMajor | Category::GeneralMajor
            )
        {
            cross_major.push(id);
        }
        if course.qualifications.humanities_core
            && units == 200
            && course.category == Category::CoreGeneral
        {
            humanities.push(id);
        }
    }
    let categories: Vec<Value> = REQUIREMENTS
        .iter()
        .zip(totals)
        .map(|((category, required), earned)| {
            json!({
                "category":category,
                "required":*required as f64 / 100.0,
                "earned":earned as f64 / 100.0,
                "remaining":required.saturating_sub(earned) as f64 / 100.0,
                "met":earned >= *required,
            })
        })
        .collect();
    let total: u32 = totals.into_iter().sum();
    let credit_requirements_met = total >= REQUIRED_TOTAL
        && REQUIREMENTS
            .iter()
            .zip(totals)
            .all(|((_, required), earned)| earned >= *required);
    let qualifications_met =
        !english.is_empty() && !cross_major.is_empty() && !humanities.is_empty();
    json!({
        "schema_version":1,
        "type":"credits_school6",
        "result":if credit_requirements_met && qualifications_met {"requirements_met"} else {"deficit"},
        "policy":{
            "school":"computer_science",
            "cohort":"2020",
            "source_url":SOURCE,
            "source_status":"community_reference_not_official_verification",
            "required_credits":150.0,
        },
        "categories":categories,
        "total_earned":total as f64 / 100.0,
        "total_remaining":REQUIRED_TOTAL.saturating_sub(total) as f64 / 100.0,
        "credit_requirements_met":credit_requirements_met,
        "qualifications":{
            "english":{"met":!english.is_empty(),"witness_course_ids":english},
            "cross_major":{"met":!cross_major.is_empty(),"witness_course_ids":cross_major},
            "humanities_core":{"met":!humanities.is_empty(),"witness_course_ids":humanities},
        },
        "earned_course_ids":earned,
        "duplicate_attempts_collapsed":duplicate_attempts,
        "graduation_eligibility":"not_verified",
        "limitations":[
            "Course identity, credit classification, passing status and qualifying attributes are operator assertions, not verified university records.",
            "Qualifying witnesses do not add credit a second time. One course identity is counted once if any listed attempt passes; conflicting identity metadata is rejected.",
            "Official retake, substitution, waiver and overlapping-requirement rules were not supplied; this reference check is not graduation certification.",
            "English attestation excludes language/writing/listening/translation/grammar courses and exchange practice/internships; cross-major attestation requires a non-economics STEM course distinct from CS; humanities attestation requires an eligible non-technical provider and excludes introductory/economics courses. These facts are not independently verified.",
        ],
        "network_access":false,
    })
}

pub fn schema() -> Value {
    let category_names = REQUIREMENTS
        .iter()
        .map(|(category, _)| category)
        .collect::<Vec<_>>();
    let ids = json!({"type":"array","maxItems":MAX_COURSES,"items":{"type":"string","minLength":1,"maxLength":256},"uniqueItems":true});
    let qualification = json!({"type":"object","additionalProperties":false,"required":["met","witness_course_ids"],"properties":{"met":{"type":"boolean"},"witness_course_ids":ids}});
    json!({
        "input":{
            "type":"object","additionalProperties":false,"required":["cohort","courses"],
            "properties":{
                "cohort":{"const":"2020"},
                "courses":{"type":"array","maxItems":MAX_COURSES,"items":{
                    "type":"object","additionalProperties":false,"required":["id","name","credits","category","passed"],
                    "properties":{
                        "id":{"type":"string","minLength":1,"maxLength":256},
                        "name":{"type":"string","minLength":1,"maxLength":512},
                        "credits":{"type":"number","exclusiveMinimum":0,"maximum":100,"multipleOf":0.01},
                        "category":{"enum":category_names},
                        "passed":{"type":"boolean"},
                        "qualifications":{"type":"object","additionalProperties":false,"properties":{
                            "english":{"type":"boolean","description":"Operator attests an eligible local all-English non-language course in core-major, general-major or general-education; requires one 2-credit witness."},
                            "english_exchange":{"type":"boolean","description":"Operator attests an eligible all-English exchange course, excluding practice/internships; requires one 2-credit witness regardless of primary credit category."},
                            "cross_major":{"type":"boolean","description":"Operator attests an eligible non-economics STEM course distinct from CS; requires one >=2-credit witness."},
                            "humanities_core":{"type":"boolean","description":"Operator attests an eligible provider/non-technical core-general course, excluding introductory/economics courses; requires one 2-credit witness."},
                        }},
                    },
                }},
            },
            "description":"Offline community-reference check. Credit amounts use exact hundredths; identifier/name bounds are UTF-8 bytes. Attempts with the same ID count once if any passes; conflicting name/credits/category/qualifications are invalid. No automatic course classification or official graduation decision.",
        },
        "output":{
            "type":"object","additionalProperties":false,
            "required":["schema_version","type","result","policy","categories","total_earned","total_remaining","credit_requirements_met","qualifications","earned_course_ids","duplicate_attempts_collapsed","graduation_eligibility","limitations","network_access"],
            "description":"Per-category and total deficits, operator-attested qualification witnesses, counted course IDs and collapsed attempts. Qualifications never add credit. Source remains a community reference and graduation_eligibility is always not_verified.",
            "properties":{
                "schema_version":{"const":1},"type":{"const":"credits_school6"},
                "result":{"enum":["requirements_met","deficit"]},
                "policy":{"type":"object","additionalProperties":false,"required":["school","cohort","source_url","source_status","required_credits"],"properties":{
                    "school":{"const":"computer_science"},"cohort":{"const":"2020"},"source_url":{"const":SOURCE},"source_status":{"const":"community_reference_not_official_verification"},"required_credits":{"const":150.0},
                }},
                "categories":{"type":"array","minItems":REQUIREMENTS.len(),"maxItems":REQUIREMENTS.len(),"items":{
                    "type":"object","additionalProperties":false,"required":["category","required","earned","remaining","met"],"properties":{
                        "category":{"enum":category_names},"required":{"type":"number","minimum":0},"earned":{"type":"number","minimum":0},"remaining":{"type":"number","minimum":0},"met":{"type":"boolean"},
                    },
                }},
                "total_earned":{"type":"number","minimum":0,"maximum":MAX_COURSES * 100},
                "total_remaining":{"type":"number","minimum":0,"maximum":150},
                "credit_requirements_met":{"type":"boolean"},
                "qualifications":{"type":"object","additionalProperties":false,"required":["english","cross_major","humanities_core"],"properties":{
                    "english":qualification,"cross_major":qualification,"humanities_core":qualification,
                }},
                "earned_course_ids":ids,
                "duplicate_attempts_collapsed":{"type":"integer","minimum":0,"maximum":MAX_COURSES - 1},
                "graduation_eligibility":{"const":"not_verified"},
                "limitations":{"type":"array","items":{"type":"string"}},
                "network_access":{"const":false},
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::calculate;
    use serde_json::{Value, json};

    // Synthetic earned-credit entries; independent fixture amounts total 150.
    fn fixture() -> Value {
        let rows = [
            ("math", "math_science", 31.0),
            ("engineering", "engineering", 9.0),
            ("language", "language", 8.0),
            ("ideology", "ideology", 12.0),
            ("military", "military", 2.0),
            ("sports", "sports", 4.0),
            ("core-general", "core_general", 8.5),
            ("humanities", "core_general", 2.0),
            ("boya", "boya", 4.0),
            ("modeling", "math_modeling", 2.0),
            ("core-major", "core_major", 42.5),
            ("general-major", "general_major", 23.0),
            ("english-cross", "general_major", 2.0),
        ];
        let mut courses: Vec<Value> = rows.into_iter().map(|(id, category, credits)| {
            json!({"id":id,"name":id,"category":category,"credits":credits,"passed":true})
        }).collect();
        courses[7]["qualifications"] = json!({"humanities_core":true});
        courses[12]["qualifications"] = json!({"english":true,"cross_major":true});
        json!({"cohort":"2020","courses":courses})
    }

    #[test]
    fn qualification_overlap_never_adds_credits_or_certifies_graduation() {
        let out = calculate(&fixture().to_string());
        assert_eq!(out["result"], "requirements_met");
        assert_eq!(out["total_earned"], 150.0);
        assert_eq!(
            out["qualifications"]["english"]["witness_course_ids"],
            json!(["english-cross"])
        );
        assert_eq!(
            out["qualifications"]["cross_major"]["witness_course_ids"],
            json!(["english-cross"])
        );
        assert_eq!(out["graduation_eligibility"], "not_verified");
    }

    #[test]
    fn total_excess_cannot_erase_a_category_deficit() {
        let mut input = fixture();
        input["courses"][0]["credits"] = json!(40.0);
        input["courses"].as_array_mut().unwrap().remove(1);
        let out = calculate(&input.to_string());
        assert_eq!(out["total_earned"], 150.0);
        assert_eq!(out["total_remaining"], 0.0);
        assert_eq!(out["result"], "deficit");
        let engineering = out["categories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|category| category["category"] == "engineering")
            .unwrap();
        assert_eq!(engineering["remaining"], 9.0);
    }

    #[test]
    fn failed_and_repeated_attempts_count_a_passed_identity_once() {
        let mut input = fixture();
        let original = input["courses"][0].clone();
        let courses = input["courses"].as_array_mut().unwrap();
        courses[0]["passed"] = json!(false);
        courses.push(original.clone());
        courses.push(original);
        let out = calculate(&input.to_string());
        assert_eq!(out["total_earned"], 150.0);
        assert_eq!(out["result"], "requirements_met");
        assert_eq!(out["duplicate_attempts_collapsed"], 2);
        input["courses"].as_array_mut().unwrap().last_mut().unwrap()["credits"] = json!(30.0);
        assert_eq!(calculate(&input.to_string())["error"], "invalid_input");
    }

    #[test]
    fn two_small_english_courses_do_not_replace_one_two_credit_witness() {
        let mut input = fixture();
        let mut small = input["courses"][12].clone();
        small["credits"] = json!(1.0);
        small["qualifications"] = json!({"english":true});
        input["courses"][12]["qualifications"] = json!({"cross_major":true});
        small["id"] = json!("small-a");
        input["courses"].as_array_mut().unwrap().push(small.clone());
        small["id"] = json!("small-b");
        input["courses"].as_array_mut().unwrap().push(small);
        let out = calculate(&input.to_string());
        assert_eq!(out["credit_requirements_met"], true);
        assert_eq!(out["qualifications"]["english"]["met"], false);
        assert_eq!(out["result"], "deficit");
    }

    #[test]
    fn exchange_english_witness_is_not_restricted_to_local_elective_categories() {
        let mut input = fixture();
        input["courses"][12]["qualifications"] = json!({"cross_major":true});
        input["courses"][9]["qualifications"] = json!({"english_exchange":true});
        let out = calculate(&input.to_string());
        assert_eq!(out["result"], "requirements_met");
        assert_eq!(
            out["qualifications"]["english"]["witness_course_ids"],
            json!(["modeling"])
        );
        assert_eq!(out["total_earned"], 150.0);
    }

    #[test]
    fn near_cent_and_near_zero_credits_do_not_round_into_valid_input() {
        for credits in [0.00000000001, 1.9999999999] {
            let mut input = fixture();
            input["courses"][12]["credits"] = json!(credits);
            assert_eq!(calculate(&input.to_string())["error"], "invalid_input");
        }
        let input = json!({"cohort":"2020","courses":[{"id":"fraction","name":"synthetic","category":"general_major","credits":0.29,"passed":true}]});
        assert_eq!(calculate(&input.to_string())["total_earned"], 0.29);
    }
}
