//! Offline physics experiment data processing.
//!
//! Implements documented, unit-explicit calculations for physics-lab data
//! reduction, verified against independent known-answer fixtures (computed by a
//! separate reference implementation):
//!
//! - `type_a` — Type A evaluation: sample mean and its standard uncertainty.
//! - `combined` — combined standard uncertainty for independent inputs
//!   (root-sum-square of sensitivity times standard uncertainty).
//! - `linear_fit` — ordinary least-squares line with parameter standard errors.
//! - `single_pendulum` — gravity determination `g = 4*pi^2*L/T^2` with propagated
//!   uncertainty.
//!
//! The command is offline: it performs no network access, no campus access and
//! no writes. Units are stated explicitly on every result (SI).

use serde_json::{Value, json};

/// Maximum number of data points accepted by a single data-reduction call.
/// Keeps pathological inputs bounded without truncating a legitimate dataset.
const MAX_POINTS: usize = 1_000_000;

/// Type A evaluation of a repeated measurement.
///
/// Returns `(mean, sample_standard_deviation, standard_uncertainty_of_mean)`.
/// The sample standard deviation uses the (n-1) denominator; the standard
/// uncertainty of the mean is `s / sqrt(n)`.
pub fn type_a(samples: &[f64]) -> Result<(f64, f64, f64), String> {
    let n = samples.len();
    if n < 2 {
        return Err("type_a requires at least 2 samples".into());
    }
    if n > MAX_POINTS {
        return Err("too many samples".into());
    }
    if samples.iter().any(|v| !v.is_finite()) {
        return Err("sample value must be finite".into());
    }
    let mean = samples.iter().sum::<f64>() / n as f64;
    let ss: f64 = samples.iter().map(|v| (v - mean) * (v - mean)).sum();
    let sample_std = (ss / (n as f64 - 1.0)).sqrt();
    let std_uncertainty = sample_std / (n as f64).sqrt();
    Ok((mean, sample_std, std_uncertainty))
}

/// Combined standard uncertainty for independent inputs (root-sum-square).
///
/// Each supplied term is a sensitivity coefficient multiplied by its standard
/// uncertainty, i.e. `c_i * u_i`. Returns `sqrt(sum(term_i^2))`.
pub fn combined(terms: &[f64]) -> f64 {
    terms.iter().map(|t| t * t).sum::<f64>().sqrt()
}

/// Ordinary least-squares linear regression `y = intercept + slope * x`.
///
/// Returns `(slope, intercept, se_slope, se_intercept, r_squared)`. The
/// parameter standard errors use the residual variance with (n-2) degrees of
/// freedom.
pub fn linear_fit(points: &[(f64, f64)]) -> Result<(f64, f64, f64, f64, f64), String> {
    let n = points.len();
    if n < 3 {
        return Err("linear_fit requires at least 3 points for standard errors".into());
    }
    if n > MAX_POINTS {
        return Err("too many points".into());
    }
    if points.iter().any(|(x, y)| !x.is_finite() || !y.is_finite()) {
        return Err("point value must be finite".into());
    }
    let mx: f64 = points.iter().map(|(x, _)| x).sum::<f64>() / n as f64;
    let my: f64 = points.iter().map(|(_, y)| y).sum::<f64>() / n as f64;
    let sxx: f64 = points.iter().map(|(x, _)| (x - mx) * (x - mx)).sum();
    if sxx == 0.0 {
        return Err("linear_fit requires distinct x values".into());
    }
    let sxy: f64 = points.iter().map(|(x, y)| (x - mx) * (y - my)).sum();
    let slope = sxy / sxx;
    let intercept = my - slope * mx;
    let ss_res: f64 = points
        .iter()
        .map(|(x, y)| {
            let r = y - (intercept + slope * x);
            r * r
        })
        .sum();
    let ss_tot: f64 = points.iter().map(|(_, y)| (y - my) * (y - my)).sum();
    let r_squared = if ss_tot == 0.0 {
        1.0
    } else {
        1.0 - ss_res / ss_tot
    };
    let s2 = ss_res / (n as f64 - 2.0);
    let se_slope = (s2 / sxx).sqrt();
    let se_intercept = (s2 * (1.0 / n as f64 + mx * mx / sxx)).sqrt();
    Ok((slope, intercept, se_slope, se_intercept, r_squared))
}

/// Single pendulum gravity determination.
///
/// `g = 4*pi^2*L/T^2` with `T = total_time_s / cycles` (the cycle count is
/// exact, so it carries no uncertainty). Lengths are metres, times seconds, and
/// `g` is in m/s^2.
///
/// Returns `(g, g_uncertainty, period_s, period_uncertainty_s)`.
pub fn single_pendulum(
    length_m: f64,
    length_uncertainty_m: f64,
    cycles: u32,
    total_time_s: f64,
    total_time_uncertainty_s: f64,
) -> Result<(f64, f64, f64, f64), String> {
    if cycles == 0 {
        return Err("cycles must be >= 1".into());
    }
    for (name, v) in [
        ("length_m", length_m),
        ("length_uncertainty_m", length_uncertainty_m),
        ("total_time_s", total_time_s),
        ("total_time_uncertainty_s", total_time_uncertainty_s),
    ] {
        if !v.is_finite() || v < 0.0 {
            return Err(format!("{name} must be a finite non-negative value"));
        }
    }
    if length_m == 0.0 || total_time_s == 0.0 {
        return Err("length_m and total_time_s must be > 0".into());
    }
    let period = total_time_s / cycles as f64;
    let period_uncertainty = total_time_uncertainty_s / cycles as f64;
    let g = 4.0 * std::f64::consts::PI * std::f64::consts::PI * length_m / (period * period);
    // Sensitivity coefficients from ln g = ln(4*pi^2) + ln L - 2 ln T:
    // dg/dL = g/L, dg/dT = -2*g/T.
    let dg_dl = g / length_m;
    let dg_dt = -2.0 * g / period;
    let g_uncertainty = combined(&[dg_dl * length_uncertainty_m, dg_dt * period_uncertainty]);
    Ok((g, g_uncertainty, period, period_uncertainty))
}

fn invalid(message: &str) -> Value {
    json!({
        "schema_version": 1,
        "type": "physics_result",
        "error": "invalid_input",
        "message": message
    })
}

fn as_f64(value: &Value, field: &str) -> Option<f64> {
    value.get(field).and_then(Value::as_f64)
}

/// Run one physics data-reduction method on a JSON stdin input.
///
/// `method` is `pendulum`, `fit` or `type-a`. Returns a typed result object, or
/// an `invalid_input` error on malformed/invalid input.
pub fn check(input: &str, method: &str) -> Value {
    let parsed: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => return invalid("input must be a JSON object"),
    };
    if !parsed.is_object() {
        return invalid("input must be a JSON object");
    }
    match method {
        "pendulum" => {
            let length_m = match as_f64(&parsed, "length_m") {
                Some(v) => v,
                None => return invalid("length_m is required (metres)"),
            };
            let length_uncertainty_m = match as_f64(&parsed, "length_uncertainty_m") {
                Some(v) => v,
                None => return invalid("length_uncertainty_m is required (metres)"),
            };
            let cycles = match parsed.get("cycles").and_then(Value::as_u64) {
                Some(v) if v <= u32::MAX as u64 => v as u32,
                _ => return invalid("cycles is required (positive integer)"),
            };
            let total_time_s = match as_f64(&parsed, "total_time_s") {
                Some(v) => v,
                None => return invalid("total_time_s is required (seconds)"),
            };
            let total_time_uncertainty_s = match as_f64(&parsed, "total_time_uncertainty_s") {
                Some(v) => v,
                None => return invalid("total_time_uncertainty_s is required (seconds)"),
            };
            match single_pendulum(
                length_m,
                length_uncertainty_m,
                cycles,
                total_time_s,
                total_time_uncertainty_s,
            ) {
                Ok((g, g_u, period, period_u)) => {
                    let relative = if g != 0.0 {
                        Value::from(g_u / g)
                    } else {
                        Value::Null
                    };
                    json!({
                        "schema_version": 1,
                        "type": "physics_pendulum",
                        "model": "g = 4*pi^2*L/T^2, T = total_time_s / cycles",
                        "units": {"length": "m", "time": "s", "g": "m/s^2"},
                        "period_s": period,
                        "period_uncertainty_s": period_u,
                        "g_m_s2": g,
                        "g_uncertainty_m_s2": g_u,
                        "relative_uncertainty": relative
                    })
                }
                Err(message) => invalid(&message),
            }
        }
        "fit" => {
            let points_value = match parsed.get("points").and_then(Value::as_array) {
                Some(v) => v,
                None => return invalid("points is required (array of [x, y] pairs)"),
            };
            let mut points: Vec<(f64, f64)> = Vec::with_capacity(points_value.len());
            for (i, pair) in points_value.iter().enumerate() {
                let (x, y) = match pair.as_array() {
                    Some(a) if a.len() == 2 => (a[0].as_f64(), a[1].as_f64()),
                    _ => return invalid(&format!("points[{i}] must be a [x, y] pair of numbers")),
                };
                match (x, y) {
                    (Some(x), Some(y)) => points.push((x, y)),
                    _ => return invalid(&format!("points[{i}] must be a [x, y] pair of numbers")),
                }
            }
            match linear_fit(&points) {
                Ok((slope, intercept, se_slope, se_intercept, r2)) => json!({
                    "schema_version": 1,
                    "type": "physics_fit",
                    "model": "y = intercept + slope * x",
                    "n": points.len(),
                    "slope": slope,
                    "intercept": intercept,
                    "slope_se": se_slope,
                    "intercept_se": se_intercept,
                    "r_squared": r2
                }),
                Err(message) => invalid(&message),
            }
        }
        "type-a" => {
            let samples_value = match parsed.get("samples").and_then(Value::as_array) {
                Some(v) => v,
                None => return invalid("samples is required (array of numbers)"),
            };
            let mut samples: Vec<f64> = Vec::with_capacity(samples_value.len());
            for (i, v) in samples_value.iter().enumerate() {
                match v.as_f64() {
                    Some(x) => samples.push(x),
                    None => return invalid(&format!("samples[{i}] must be a number")),
                }
            }
            match type_a(&samples) {
                Ok((mean, sample_std, std_uncertainty)) => json!({
                    "schema_version": 1,
                    "type": "physics_type_a",
                    "n": samples.len(),
                    "mean": mean,
                    "sample_std": sample_std,
                    "std_uncertainty": std_uncertainty
                }),
                Err(message) => invalid(&message),
            }
        }
        _ => invalid("unknown physics method"),
    }
}

/// Describe the command's input/output contract for `buaa schema`.
pub fn schema() -> Value {
    json!({
        "pendulum": {
            "input": {
                "type": "object",
                "required": ["length_m", "length_uncertainty_m", "cycles", "total_time_s", "total_time_uncertainty_s"],
                "properties": {
                    "length_m": {"type": "number", "description": "pendulum length in metres (> 0)"},
                    "length_uncertainty_m": {"type": "number", "description": "standard uncertainty of length in metres (>= 0)"},
                    "cycles": {"type": "integer", "description": "oscillation count (>= 1, exact)"},
                    "total_time_s": {"type": "number", "description": "total elapsed time for the count in seconds (> 0)"},
                    "total_time_uncertainty_s": {"type": "number", "description": "standard uncertainty of total time in seconds (>= 0)"}
                }
            },
            "output": {
                "type": "object",
                "required": ["schema_version", "type", "period_s", "g_m_s2", "g_uncertainty_m_s2"],
                "properties": {
                    "schema_version": {"const": 1},
                    "type": {"const": "physics_pendulum"},
                    "period_s": {"type": "number"},
                    "period_uncertainty_s": {"type": "number"},
                    "g_m_s2": {"type": "number"},
                    "g_uncertainty_m_s2": {"type": "number"},
                    "relative_uncertainty": {"type": ["number", "null"]}
                }
            }
        },
        "fit": {
            "input": {
                "type": "object",
                "required": ["points"],
                "properties": {
                    "points": {"type": "array", "description": "array of [x, y] number pairs (>= 3)"}
                }
            },
            "output": {
                "type": "object",
                "required": ["schema_version", "type", "slope", "intercept", "r_squared"],
                "properties": {
                    "schema_version": {"const": 1},
                    "type": {"const": "physics_fit"},
                    "slope": {"type": "number"},
                    "intercept": {"type": "number"},
                    "slope_se": {"type": "number"},
                    "intercept_se": {"type": "number"},
                    "r_squared": {"type": "number"}
                }
            }
        },
        "type-a": {
            "input": {
                "type": "object",
                "required": ["samples"],
                "properties": {
                    "samples": {"type": "array", "description": "repeated measurements, numbers (>= 2)"}
                }
            },
            "output": {
                "type": "object",
                "required": ["schema_version", "type", "mean", "sample_std", "std_uncertainty"],
                "properties": {
                    "schema_version": {"const": 1},
                    "type": {"const": "physics_type_a"},
                    "mean": {"type": "number"},
                    "sample_std": {"type": "number"},
                    "std_uncertainty": {"type": "number"}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent reference values computed by a separate implementation
    // (pure-Python statistics), used as known-answer fixtures.

    #[test]
    fn type_a_matches_independent_fixture() {
        let samples = [0.980, 0.978, 0.981, 0.979, 0.980];
        let (mean, sample_std, std_uncertainty) = type_a(&samples).unwrap();
        assert!((mean - 0.9795999999999999).abs() < 1e-12);
        assert!((sample_std - 0.001140175425099139).abs() < 1e-12);
        assert!((std_uncertainty - 0.0005099019513592789).abs() < 1e-12);
    }

    #[test]
    fn combined_matches_independent_fixture() {
        // Trivially verifiable: sqrt(3^2 + 4^2) = 5.
        assert!((combined(&[3.0, 4.0]) - 5.0).abs() < 1e-12);
        // Root-sum-square of the two pendulum sensitivity terms (independent
        // Python reference), matching the pendulum fixture's g uncertainty.
        let terms = [0.009969045631261187, -0.009818758511191924];
        let value = combined(&terms);
        assert!((value - 0.013992494041423482).abs() < 1e-12);
    }

    #[test]
    fn linear_fit_matches_independent_fixture() {
        let points = [
            (0.0, 0.2),
            (1.0, 0.9),
            (2.0, 2.1),
            (3.0, 3.0),
            (4.0, 4.2),
            (5.0, 4.9),
        ];
        let (slope, intercept, se_slope, se_intercept, r2) = linear_fit(&points).unwrap();
        assert!((slope - 0.9799999999999999).abs() < 1e-9);
        assert!((intercept - 0.10000000000000053).abs() < 1e-9);
        assert!((se_slope - 0.035456210417116774).abs() < 1e-9);
        assert!((se_intercept - 0.10734900802433876).abs() < 1e-9);
        assert!((r2 - 0.9947913583900562).abs() < 1e-9);
    }

    #[test]
    fn single_pendulum_matches_independent_fixture() {
        let (g, g_u, period, period_u) = single_pendulum(0.980, 0.001, 50, 99.50, 0.05).unwrap();
        assert!((period - 1.99).abs() < 1e-12);
        assert!((period_u - 0.001).abs() < 1e-12);
        assert!((g - 9.769664718635964).abs() < 1e-9);
        assert!((g_u - 0.013992494041423482).abs() < 1e-9);
    }

    #[test]
    fn pendulum_cli_reports_units_and_result() {
        let out = check(
            r#"{"length_m":0.980,"length_uncertainty_m":0.001,"cycles":50,"total_time_s":99.50,"total_time_uncertainty_s":0.05}"#,
            "pendulum",
        );
        assert_eq!(out["type"], "physics_pendulum");
        assert_eq!(out["units"]["g"], "m/s^2");
        assert!((out["g_m_s2"].as_f64().unwrap() - 9.769664718635964).abs() < 1e-9);
        assert!(out["relative_uncertainty"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn fit_cli_reports_model_and_result() {
        let out = check(
            r#"{"points":[[0,0.2],[1,0.9],[2,2.1],[3,3.0],[4,4.2],[5,4.9]]}"#,
            "fit",
        );
        assert_eq!(out["type"], "physics_fit");
        assert_eq!(out["n"], 6);
        assert!((out["slope"].as_f64().unwrap() - 0.98).abs() < 1e-9);
    }

    #[test]
    fn type_a_cli_reports_result() {
        let out = check(r#"{"samples":[0.980,0.978,0.981,0.979,0.980]}"#, "type-a");
        assert_eq!(out["type"], "physics_type_a");
        assert_eq!(out["n"], 5);
        assert!((out["mean"].as_f64().unwrap() - 0.9796).abs() < 1e-9);
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        // Not JSON.
        assert_eq!(check("not json", "pendulum")["error"], "invalid_input");
        // Missing required field.
        assert_eq!(
            check(r#"{"length_m":0.980}"#, "pendulum")["error"],
            "invalid_input"
        );
        // Non-positive length.
        assert_eq!(
            check(
                r#"{"length_m":0.0,"length_uncertainty_m":0.001,"cycles":50,"total_time_s":99.50,"total_time_uncertainty_s":0.05}"#,
                "pendulum"
            )["error"],
            "invalid_input"
        );
        // Zero cycles.
        assert_eq!(
            check(
                r#"{"length_m":0.980,"length_uncertainty_m":0.001,"cycles":0,"total_time_s":99.50,"total_time_uncertainty_s":0.05}"#,
                "pendulum"
            )["error"],
            "invalid_input"
        );
        // Single sample for type-a.
        assert_eq!(
            check(r#"{"samples":[1.0]}"#, "type-a")["error"],
            "invalid_input"
        );
        // Too few points for fit (need >= 3 for standard errors).
        assert_eq!(
            check(r#"{"points":[[0,1]]}"#, "fit")["error"],
            "invalid_input"
        );
        assert_eq!(
            check(r#"{"points":[[0,1],[1,2]]}"#, "fit")["error"],
            "invalid_input"
        );
        // Malformed pair.
        assert_eq!(
            check(r#"{"points":[[0,1,2]]}"#, "fit")["error"],
            "invalid_input"
        );
        // Unknown method.
        assert_eq!(check(r#"{}"#, "nope")["error"], "invalid_input");
    }

    #[test]
    fn fit_rejects_non_finite_points() {
        assert!(linear_fit(&[(0.0, f64::NAN), (1.0, 1.0)]).is_err());
        assert!(linear_fit(&[(0.0, 1.0), (0.0, 2.0)]).is_err()); // non-distinct x
    }
}
