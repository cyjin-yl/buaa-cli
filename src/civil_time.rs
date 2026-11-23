//! Beijing civil time for operator-supplied records.
//!
//! The calendar conversion is Howard Hinnant's public-domain algorithm, already
//! used by the timetable mapper. Timestamps must be exact `+08:00` seconds;
//! other offsets are rejected instead of being shifted.

const BEIJING_OFFSET: i64 = 8 * 3600;

pub(crate) fn parse_date(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let year: i64 = value[..4].parse().ok()?;
    let month: u32 = value[5..7].parse().ok()?;
    let day: u32 = value[8..].parse().ok()?;
    if !(1970..=2100).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
    {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

pub(crate) fn parse_beijing(value: &str) -> Option<i64> {
    let (date, clock) = value.split_once('T')?;
    let clock = clock.strip_suffix("+08:00")?;
    let days = parse_date(date)?;
    let bytes = clock.as_bytes();
    if bytes.len() != 8 || bytes[2] != b':' || bytes[5] != b':' {
        return None;
    }
    let hour: u32 = clock[..2].parse().ok()?;
    let minute: u32 = clock[3..5].parse().ok()?;
    let second: u32 = clock[6..].parse().ok()?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(days * 86_400 + i64::from(hour * 3600 + minute * 60 + second) - BEIJING_OFFSET)
}

pub(crate) fn format_beijing(unix: i64) -> String {
    let local = unix + BEIJING_OFFSET;
    let days = floor_div(local, 86_400);
    let seconds = local - days * 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3600;
    let minute = (seconds % 3600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+08:00")
}

pub(crate) fn format_utc(unix: i64) -> String {
    let days = floor_div(unix, 86_400);
    let seconds = unix - days * 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3600;
    let minute = (seconds % 3600) / 60;
    let second = seconds % 60;
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

pub(crate) fn format_date(days: i64) -> String {
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

pub(crate) fn beijing_days(unix: i64) -> i64 {
    floor_div(unix + BEIJING_OFFSET, 86_400)
}

pub(crate) fn clock_seconds(unix: i64) -> i64 {
    (unix + BEIJING_OFFSET).rem_euclid(86_400)
}

pub(crate) fn at_clock(days: i64, clock: i64) -> i64 {
    days * 86_400 + clock - BEIJING_OFFSET
}

/// Monday is 0 and Sunday is 6.
pub(crate) fn weekday(days: i64) -> u32 {
    i64::from(((days + 3) % 7 + 7) % 7) as u32
}

pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let mut year = year;
    let month = i64::from(month);
    if month <= 2 {
        year -= 1;
    }
    let era = floor_div(year, 400);
    let year_of_era = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(mut z: i64) -> (i64, u32, u32) {
    z += 719_468;
    let era = floor_div(z, 146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day)
}

fn floor_div(value: i64, divisor: i64) -> i64 {
    let quotient = value / divisor;
    let remainder = value % divisor;
    if remainder != 0 && (remainder < 0) != (divisor < 0) {
        quotient - 1
    } else {
        quotient
    }
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::{format_beijing, parse_beijing, parse_date, weekday};

    #[test]
    fn beijing_timestamp_round_trips_and_known_weekdays_hold() {
        let stamp = "2026-11-22T09:30:00+08:00";
        assert_eq!(format_beijing(parse_beijing(stamp).unwrap()), stamp);
        assert_eq!(weekday(parse_date("2026-09-07").unwrap()), 0);
        assert_eq!(weekday(parse_date("2026-11-22").unwrap()), 6);
        assert!(parse_date("2024-02-29").is_some());
        assert!(parse_date("2026-02-29").is_none());
        assert!(parse_beijing("2026-11-22T09:30:00Z").is_none());
        assert!(parse_beijing("2026-11-22T09:30:00+00:00").is_none());
    }
}
