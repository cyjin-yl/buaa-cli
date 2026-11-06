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
    let nf = n as f64;
    // Divide each sample by n before accumulating so the running sum cannot
    // overflow even at the f64 range boundary (every term is at most MAX/n).
    let mean = samples.iter().map(|v| v / nf).sum::<f64>();
    // Scaled squared deviations: halving both operands keeps every difference
    // within [-MAX, MAX], and normalizing by the largest half-deviation keeps
    // squared terms in [0, 1]. Tiny representable deviations (e.g. 1e-200)
    // are therefore not zeroed by premature squaring, and huge ones do not
    // overflow.
    let half_dev = |v: f64| v * 0.5 - mean * 0.5;
    let max_hd = samples.iter().map(|v| half_dev(*v).abs()).fold(0.0, f64::max);
    let sample_std = if max_hd == 0.0 {
        0.0
    } else {
        let ssn: f64 = samples
            .iter()
            .map(|v| {
                let d = half_dev(*v) / max_hd;
                d * d
            })
            .sum();
        // std = 2*max_hd * sqrt(ssn/(n-1)) reordered to defer the range check.
        max_hd * (4.0 * ssn / (nf - 1.0)).sqrt()
    };
    let std_uncertainty = sample_std / nf.sqrt();
    if ![mean, sample_std, std_uncertainty]
        .iter()
        .all(|v| v.is_finite())
    {
        return Err("type_a result is outside the finite f64 range".into());
    }
    Ok((mean, sample_std, std_uncertainty))
}

/// Combined standard uncertainty for independent inputs (root-sum-square).
///
/// Each supplied term is a sensitivity coefficient multiplied by its standard
/// uncertainty, i.e. `c_i * u_i`. Returns `sqrt(sum(term_i^2))`.
pub fn combined(terms: &[f64]) -> f64 {
    // hypot computes a scaled root-sum-square: a 1e-200 term survives (its
    // square would underflow to zero) and large terms do not overflow.
    terms.iter().fold(0.0f64, |acc, t| acc.hypot(*t))
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
    let nf = n as f64;
    // Per-term division before accumulating keeps means inside [-MAX, MAX].
    let mx: f64 = points.iter().map(|(x, _)| x / nf).sum::<f64>();
    let my: f64 = points.iter().map(|(_, y)| y / nf).sum::<f64>();
    // Halving both operands keeps every deviation within [-MAX, MAX] even for
    // opposite-sign inputs near the f64 boundary; normalizing by the largest
    // half-deviation keeps squared terms in [0, 1] so representable tiny
    // deviations are not zeroed by premature squaring.
    let hx: Vec<f64> = points.iter().map(|(x, _)| x * 0.5 - mx * 0.5).collect();
    let hy: Vec<f64> = points.iter().map(|(_, y)| y * 0.5 - my * 0.5).collect();
    let sx = hx.iter().fold(0.0f64, |a, d| a.max(d.abs()));
    if sx == 0.0 {
        return Err("linear_fit requires distinct x values".into());
    }
    let ssx_norm: f64 = hx.iter().map(|d| (d / sx) * (d / sx)).sum();
    let sy = hy.iter().fold(0.0f64, |a, d| a.max(d.abs()));
    let (sy_eff, sxy_norm, ssy_norm) = if sy == 0.0 {
        // Every y equals my: sxy and ssy are exactly zero and slope is zero.
        (1.0, 0.0, 0.0)
    } else {
        let sxy: f64 = hx
            .iter()
            .zip(hy.iter())
            .map(|(dx, dy)| (dx / sx) * (dy / sy))
            .sum();
        let ssy: f64 = hy.iter().map(|d| (d / sy) * (d / sy)).sum();
        (sy, sxy, ssy)
    };
    // True sums are 4*sx^2*ssx_norm, 4*sx*sy*sxy_norm, 4*sy^2*ssy_norm;
    // the dimensionless ratios below use them without computing them.
    let slope = if sxy_norm == 0.0 {
        0.0
    } else {
        (sy_eff / sx) * (sxy_norm / ssx_norm)
    };
    let intercept = 2.0 * (my * 0.5 - slope * (mx * 0.5));
    // ss_res = ss_tot - sxy^2/sxx, evaluated on normalized sums.
    let residual_norm = if ssy_norm == 0.0 {
        0.0
    } else {
        (ssy_norm - sxy_norm * sxy_norm / ssx_norm).max(0.0)
    };
    let r_squared = if ssy_norm == 0.0 {
        1.0
    } else {
        1.0 - residual_norm / ssy_norm
    };
    // s2 = 4*sy^2*residual_norm/(n-2); se_slope = sqrt(s2/sxx) factors to
    // (sy/sx)*sqrt(residual_norm/((n-2)*ssx_norm)). Multiply sy by the
    // dimensionless factor before dividing by sx to dodge range artifacts.
    let se_slope = sy_eff * (residual_norm / ((nf - 2.0) * ssx_norm)).sqrt() / sx;
    // se_intercept = sy*sqrt(4*residual_norm/(n-2) * (1/n + t^2/ssx_norm))
    // with t = mx/(2*sx), all dimensionless except the leading sy.
    let se_intercept = if residual_norm == 0.0 {
        0.0
    } else {
        let t = mx / (2.0 * sx);
        sy_eff
            * (4.0 * residual_norm / (nf - 2.0) * (1.0 / nf + t * t / ssx_norm)).sqrt()
    };
    if ![slope, intercept, se_slope, se_intercept, r_squared]
        .iter()
        .all(|v| v.is_finite())
    {
        return Err("linear_fit result is outside the finite f64 range".into());
    }
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
    // g = 4*pi^2*L/T^2 = 4*pi^2 * (L/T) / T: forming L/T first avoids a
    // premature overflow of period*period and only overflows when g itself
    // is unrepresentable.
    let g = 4.0 * std::f64::consts::PI * std::f64::consts::PI * (length_m / period) / period;
    if !g.is_finite() {
        return Err("pendulum result g is outside the finite f64 range".into());
    }
    // Sensitivity coefficients from ln g = ln(4*pi^2) + ln L - 2 ln T:
    // dg/dL = g/L, dg/dT = -2*g/T.
    // The propagation terms are formed as g * (u_L / L) and -2 * g * (u_T / T)
    // so a zero uncertainty cannot produce inf * 0 = NaN.
    let term_l = g * (length_uncertainty_m / length_m);
    let term_t = -2.0 * g * (period_uncertainty / period);
    let g_uncertainty = combined(&[term_l, term_t]);
    if !g_uncertainty.is_finite() {
        return Err("pendulum result g uncertainty is outside the finite f64 range".into());
    }
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
                    let ratio = if g != 0.0 { g_u / g } else { f64::NAN };
                    let relative = if ratio.is_finite() {
                        Value::from(ratio)
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

    #[test]
    fn type_a_never_emits_non_finite_or_null_result() {
        // Summing 1e308 + 1e308 overflows a naive running sum to inf, which
        // serde_json would then serialize as a successful null. The mean must
        // come back as the finite 1e308.
        let out = check(r#"{"samples":[1e308,1e308]}"#, "type-a");
        assert_eq!(out["type"], "physics_type_a");
        assert_eq!(out["mean"].as_f64(), Some(1e308));
        assert_eq!(out["sample_std"].as_f64(), Some(0.0));
        assert_eq!(out["std_uncertainty"].as_f64(), Some(0.0));
        // The serialized document must contain no null/infinite success field.
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("null"));
        // Opposite-sign extremes whose true standard deviation exceeds the
        // f64 range must be refused, not emitted as null/inf.
        let out = check(r#"{"samples":[-1.7e308,1.7e308]}"#, "type-a");
        assert_eq!(out["error"], "invalid_input");
    }

    #[test]
    fn type_a_preserves_tiny_representable_deviations() {
        // (1e-200)^2 underflows to zero; a premature-squaring implementation
        // reports std 0. Scaled accumulation must keep ~7.07e-201.
        let (mean, sample_std, std_uncertainty) = type_a(&[0.0, 1e-200]).unwrap();
        assert_eq!(mean, 5e-201);
        assert!((sample_std - 1e-200 / 2f64.sqrt()).abs() / sample_std < 1e-12);
        assert!((std_uncertainty - 5e-201).abs() / std_uncertainty < 1e-12);
    }

    #[test]
    fn pendulum_preserves_tiny_uncertainty_and_rejects_unrepresentable() {
        // (1e-200)^2 underflows to zero: the combined uncertainty must stay
        // nonzero via the hypot-based root-sum-square.
        let (g, g_u, _, _) = single_pendulum(1.0, 0.0, 1, 2.0, 1e-200).unwrap();
        assert!(g.is_finite() && g > 0.0);
        assert!(g_u.is_finite() && g_u > 0.0);
        assert!((g_u - g * 1e-200).abs() / g_u < 1e-12);
        // An unrepresentable g (L/T overflows the f64 range) must be refused.
        assert!(single_pendulum(1e308, 0.0, 1, 1e-200, 0.0).is_err());
    }

    #[test]
    fn linear_fit_never_emits_non_finite_or_null_result() {
        // Exact line through extreme opposite-sign points: a naive Sxx
        // overflows to inf, giving NaN slope serialized as null.
        let out = check(r#"{"points":[[-1e308,-1e308],[0,0],[1e308,1e308]]}"#, "fit");
        assert_eq!(out["type"], "physics_fit");
        assert!((out["slope"].as_f64().unwrap() - 1.0).abs() < 1e-12);
        assert!(out["intercept"].as_f64().unwrap().abs() < 1e290);
        assert_eq!(out["slope_se"].as_f64(), Some(0.0));
        assert_eq!(out["r_squared"].as_f64(), Some(1.0));
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("null"));
    }
}
