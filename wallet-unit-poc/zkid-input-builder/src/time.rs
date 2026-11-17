//! `currentTime` for the cert-chain circuit: the decimal integer
//! `YYMMDDHHMMSS` in UTC, the same 12 digits a DER `UTCTime` carries.
//! See `wallet-unit-poc/circom/SPEC.md` §"Validity period".

/// Formats seconds since the Unix epoch as `YYMMDDHHMMSS` (UTC).
///
/// Only years 2000..=2049 are representable, matching the `UTCTime` range the
/// circuit accepts.
pub fn format_current_time(unix_seconds: u64) -> Result<String, String> {
    let days = unix_seconds / 86_400;
    let secs = unix_seconds % 86_400;

    // Civil-from-days (Howard Hinnant), valid for all dates on or after 1970-01-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);

    if !(2000..=2049).contains(&year) {
        return Err(format!("year {year} is outside the UTCTime range 2000..=2049"));
    }
    Ok(format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}",
        year - 2000,
        month,
        day,
        secs / 3_600,
        (secs % 3_600) / 60,
        secs % 60
    ))
}

/// The system clock as `YYMMDDHHMMSS` (UTC). Not available on wasm32, where
/// the caller passes the time in from JS.
///
/// Returns an error when the clock is outside 2000..=2049, for example on a
/// device whose clock was reset to 1970.
#[cfg(not(target_arch = "wasm32"))]
pub fn current_time_utc() -> Result<String, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_secs();
    format_current_time(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        // 2026-11-14 15:59:59 UTC
        assert_eq!(format_current_time(1_794_671_999).unwrap(), "261114155959");
        // 2000-01-01 00:00:00 UTC
        assert_eq!(format_current_time(946_684_800).unwrap(), "000101000000");
        // 2024-02-29 12:00:00 UTC (leap day)
        assert_eq!(format_current_time(1_709_208_000).unwrap(), "240229120000");
        // 2049-12-31 23:59:59 UTC
        assert_eq!(format_current_time(2_524_607_999).unwrap(), "491231235959");
    }

    #[test]
    fn rejects_a_clock_reset_to_the_epoch() {
        assert!(format_current_time(0).is_err()); // 1970-01-01 00:00:00
    }

    #[test]
    fn rejects_years_outside_utctime_range() {
        assert!(format_current_time(946_684_799).is_err()); // 1999-12-31 23:59:59
        assert!(format_current_time(2_524_608_000).is_err()); // 2050-01-01 00:00:00
    }
}
