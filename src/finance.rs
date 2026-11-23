//! Local projection of operator-supplied personal income records.
//!
//! Year selection, search, totals, and month grouping follow the behavior
//! described by BUAASubnet/UBAA `docs/site/features/finance.md` at
//! `3ac2ebd6c30162cd1ce1fc50964caa25ed22092f` (MIT, © 2026 MooreFoss). This is
//! original code. It does not contact the campus finance service, does not
//! accept bank or identity material, and does not treat a failed refresh as an
//! empty income history. Amounts are integer cents and are not reconciled to a
//! bank settlement.

use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Read;
use zeroize::Zeroize;

use crate::civil_time::parse_date;
use crate::{
    governor::{FollowupError, Governor, Outcome, RequestKind, RequestLease},
    net::{self, Error},
    recordings::session::{self as cas, CasService, SsoCredentials},
    timetable::admit_session_read,
};

const FINANCE_PORTAL_URL: &str = "https://icw.buaa.edu.cn/Newindex.aspx";
const FINANCE_JUMP_URL: &str = "https://icw.buaa.edu.cn/jump.aspx?sysid=wscx";
const FINANCE_QUERY_HOST: &str = "chaxun.icw.buaa.edu.cn";
const FINANCE_LOGIN_URL: &str = "https://chaxun.icw.buaa.edu.cn/api-zhcx/login";
const FINANCE_INCOME_URL: &str = "https://chaxun.icw.buaa.edu.cn/api-zhcx/getStudentSRCX";
const FINANCE_LOGIN_PATH: &str = "/gxzhcxzhb/login";
const FINANCE_PAGE_SIZE: u64 = 100;
const FINANCE_MAX_PAGES: u32 = 20;
const FINANCE_BODY_LIMIT: u64 = 512 * 1024;

const CREDIT: &str =
    "BUAASubnet/UBAA@3ac2ebd6c30162cd1ce1fc50964caa25ed22092f (MIT, © 2026 MooreFoss)";
const MAX_RECORDS: usize = 500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    year: Option<i32>,
    query: Option<String>,
    refresh_error: Option<String>,
    records: Vec<Record>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    serial: String,
    project: String,
    summary: String,
    gross_cents: Option<i64>,
    tax_cents: Option<i64>,
    net_cents: Option<i64>,
    tax_rate: Option<String>,
    year: i32,
    month: u8,
    recorded_on: String,
}

pub fn query(input: &str) -> Value {
    let parsed = match serde_json::from_str::<Query>(input) {
        Ok(value) => value,
        Err(_) => return invalid("input must be one finance JSON object"),
    };
    match project(parsed) {
        Ok(value) => value,
        Err(message) => invalid(message),
    }
}

fn project(query: Query) -> Result<Value, &'static str> {
    if let Some(year) = query.year
        && !(1970..=2100).contains(&year)
    {
        return Err("year is outside the supported range");
    }
    if let Some(search) = query.query.as_deref()
        && (search.is_empty() || search.chars().count() > 100)
    {
        return Err("query must be a non-empty search of at most 100 characters");
    }
    let refresh_error = match query.refresh_error.as_deref() {
        Some("") => return Err("refresh_error must be a short non-empty reason"),
        Some(error) if error.chars().count() > 300 => {
            return Err("refresh_error must be a short non-empty reason");
        }
        other => other,
    };
    if query.records.len() > MAX_RECORDS {
        return Err("too many income records");
    }
    let mut records = Vec::with_capacity(query.records.len());
    let mut serials = std::collections::BTreeSet::new();
    for record in query.records {
        validate(&record)?;
        if !serials.insert(record.serial.clone()) {
            return Err("serial must be unique");
        }
        records.push(record);
    }
    if refresh_error.is_some() && records.is_empty() {
        return Ok(json!({
            "result": "refresh_failed",
            "record_state": "offline_retained",
            "refresh_error": refresh_error,
            "empty_means_no_income": false,
            "bank_settlement_known": false,
            "coverage": "supplied_records_only",
            "network_performed": false,
            "totals": null,
            "months": [],
            "credit": CREDIT
        }));
    }
    records.retain(|record| {
        query.year.is_none_or(|year| record.year == year)
            && query.query.as_ref().is_none_or(|search| {
                record.project.contains(search) || record.summary.contains(search)
            })
    });
    records.sort_by(|left, right| {
        (left.recorded_on.as_str(), left.serial.as_str())
            .cmp(&(right.recorded_on.as_str(), right.serial.as_str()))
    });
    let totals = totals(&records);
    let mut months: BTreeMap<(i32, u8), Vec<&Record>> = BTreeMap::new();
    for record in &records {
        months
            .entry((record.year, record.month))
            .or_default()
            .push(record);
    }
    let months = months
        .into_iter()
        .map(|((year, month), entries)| {
            json!({
                "year": year,
                "month": month,
                "net_cents": sum(entries.iter().map(|record| record.net_cents)),
                "count": entries.len(),
                "records": entries.iter().map(|record| detail(record)).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "result": "projected",
        "record_state": if refresh_error.is_some() { "offline_retained" } else { "supplied" },
        "refresh_error": refresh_error,
        "empty_means_no_income": false,
        "bank_settlement_known": false,
        "coverage": "supplied_records_only",
        "network_performed": false,
        "totals": totals,
        "months": months,
        "credit": CREDIT
    }))
}

fn validate(record: &Record) -> Result<(), &'static str> {
    if record.serial.is_empty() || record.serial.chars().count() > 64 {
        return Err("serial must be 1 to 64 characters");
    }
    if record.project.is_empty()
        || record.summary.is_empty()
        || record.project.chars().count() > 200
        || record.summary.chars().count() > 200
    {
        return Err("project and summary must be 1 to 200 characters");
    }
    for amount in [record.gross_cents, record.tax_cents, record.net_cents] {
        if amount.is_some_and(|amount| amount < 0) {
            return Err("amounts must be zero or positive cents");
        }
    }
    if let Some(rate) = record.tax_rate.as_deref()
        && !valid_rate(rate)
    {
        return Err("tax_rate must be a percentage from 0 to 100 with at most two decimals");
    }
    if !(1970..=2100).contains(&record.year) || !(1..=12).contains(&record.month) {
        return Err("record month is outside the supported range");
    }
    if parse_date(&record.recorded_on).is_none() {
        return Err("recorded_on must be a civil date");
    }
    Ok(())
}

fn valid_rate(value: &str) -> bool {
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    if whole.is_empty()
        || whole.len() > 3
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|fraction| {
            fraction.is_empty()
                || fraction.len() > 2
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return false;
    }
    let whole: u16 = whole.parse().unwrap_or(101);
    let fraction: u16 = fraction.unwrap_or("0").parse().unwrap_or(100);
    whole < 100 || (whole == 100 && fraction == 0)
}

fn totals(records: &[Record]) -> Value {
    json!({
        "count": records.len(),
        "gross_cents": sum(records.iter().map(|record| record.gross_cents)),
        "tax_cents": sum(records.iter().map(|record| record.tax_cents)),
        "net_cents": sum(records.iter().map(|record| record.net_cents))
    })
}

fn sum(values: impl Iterator<Item = Option<i64>>) -> Option<i64> {
    let mut total = 0;
    for value in values {
        total += value?;
    }
    Some(total)
}

fn detail(record: &Record) -> Value {
    let consistent = match (record.gross_cents, record.tax_cents, record.net_cents) {
        (Some(gross), Some(tax), Some(net)) => Some(net == gross - tax),
        _ => None,
    };
    json!({
        "serial": record.serial,
        "project": record.project,
        "summary": record.summary,
        "gross_cents": record.gross_cents,
        "tax_cents": record.tax_cents,
        "net_cents": record.net_cents,
        "amount_consistent": consistent,
        "tax_rate": record.tax_rate,
        "year": record.year,
        "month": record.month,
        "recorded_on": record.recorded_on
    })
}

fn invalid(message: &str) -> Value {
    json!({"error": "invalid_input", "message": message})
}

pub fn schema() -> Value {
    json!({
        "stdin": "one JSON object of operator-supplied income records in integer cents; no bank account, identity, or network request is accepted",
        "credit": CREDIT,
        "behavior": "https://github.com/BUAASubnet/UBAA/blob/3ac2ebd6c30162cd1ce1fc50964caa25ed22092f/docs/site/features/finance.md",
        "totals": "count, gross, tax, and net follow the selected year and search; a missing component makes only that total null",
        "failure": "refresh_error retains supplied records as offline_retained; with no retained records the result is refresh_failed and does not mean there was no income"
    })
}

#[cfg(test)]
mod tests {
    use super::{query, session};
    use serde_json::{Value, json};

    fn record(
        serial: &str,
        project: &str,
        summary: &str,
        gross: i64,
        tax: i64,
        net: i64,
        month: u8,
    ) -> serde_json::Value {
        json!({
            "serial": serial,
            "project": project,
            "summary": summary,
            "gross_cents": gross,
            "tax_cents": tax,
            "net_cents": net,
            "tax_rate": "3.00",
            "year": 2026,
            "month": month,
            "recorded_on": format!("2026-{month:02}-15")
        })
    }

    #[test]
    fn search_changes_totals_and_preserves_inconsistent_amounts() {
        let mut mismatched = record("S2", "助学金", "十一月", 100_000, 3_000, 100_000, 11);
        mismatched["recorded_on"] = json!("2026-12-02");
        let output = query(
            &json!({
                "year": 2026,
                "query": "助学",
                "records": [
                    record("S1", "酬金", "监考", 50_000, 5_000, 45_000, 11),
                    mismatched,
                    record("S3", "助学金", "十二月", 80_000, 0, 80_000, 12)
                ]
            })
            .to_string(),
        );
        assert_eq!(output["totals"]["count"], 2);
        assert_eq!(output["totals"]["net_cents"], 180_000);
        assert_eq!(output["months"][0]["month"], 11);
        assert_eq!(
            output["months"][0]["records"][0]["amount_consistent"],
            false
        );
        assert_eq!(output["months"][0]["records"][0]["net_cents"], 100_000);
        assert_eq!(
            output["months"][0]["records"][0]["recorded_on"],
            "2026-12-02"
        );
        assert_eq!(output["months"][1]["net_cents"], 80_000);
        assert_eq!(output["bank_settlement_known"], false);
    }

    #[test]
    fn missing_tax_nulls_only_that_total_and_failed_refresh_is_not_zero() {
        let mut partial = record("S1", "酬金", "监考", 50_000, 0, 50_000, 11);
        partial["tax_cents"] = Value::Null;
        let output = query(&json!({"records":[partial]}).to_string());
        assert_eq!(output["totals"]["count"], 1);
        assert_eq!(output["totals"]["gross_cents"], 50_000);
        assert!(output["totals"]["tax_cents"].is_null());
        let failed = query(&json!({"refresh_error":"timeout","records":[]}).to_string());
        assert_eq!(failed["result"], "refresh_failed");
        assert_eq!(failed["empty_means_no_income"], false);
        assert!(failed["totals"].is_null());
        let retained = query(
            &json!({
                "refresh_error":"timeout",
                "records":[record("S1", "酬金", "监考", 50_000, 0, 50_000, 11)]
            })
            .to_string(),
        );
        assert_eq!(retained["record_state"], "offline_retained");
        assert_eq!(retained["months"][0]["count"], 1);
    }

    #[test]
    fn rejects_negative_duplicate_and_implausible_rate_without_echo() {
        let duplicate = query(
            &json!({"records":[
                record("SAME", "酬金", "甲", 1, 0, 1, 11),
                record("SAME", "酬金", "乙", 1, 0, 1, 11)
            ]})
            .to_string(),
        );
        assert_eq!(duplicate["error"], "invalid_input");
        assert!(!duplicate.to_string().contains("SAME"));
        let negative = record("S1", "酬金", "甲", 1, -1, 1, 11);
        assert_eq!(
            query(&json!({"records":[negative]}).to_string())["error"],
            "invalid_input"
        );
        let mut rate = record("S1", "酬金", "甲", 1, 0, 1, 11);
        rate["tax_rate"] = json!("100.01");
        assert_eq!(
            query(&json!({"records":[rate]}).to_string())["error"],
            "invalid_input"
        );
    }

    #[test]
    fn session_without_online_does_not_authenticate() {
        let error = session(
            r#"{"authorized":true,"username":"student","password":"secret","intent":"LOGIN student finance"}"#,
            false,
        )
        .expect_err("offline session must refuse");
        assert_eq!(error.code, "online_required");
    }
}
