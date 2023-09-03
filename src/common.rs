use chrono::{DateTime, LocalResult, NaiveDate, TimeZone, Utc};

use anyhow::{anyhow, Result};

/// Helpers to parse date with clap
pub(crate) fn parse_date(input: &str) -> Result<DateTime<Utc>> {
    NaiveDate::parse_from_str(input, "%Y-%m-%d")
        .map_err(|e| anyhow!(e))
        .and_then(|dt| match Utc.from_local_datetime(&dt.and_hms_opt(0, 0, 0).expect("Static valid values")) {
            LocalResult::None => Err(anyhow!("No such local time")),
            LocalResult::Single(t) => Ok(t),
            LocalResult::Ambiguous(t1, t2) => Err(anyhow!(
                "Ambiguous local time, ranging from {:?} to {:?}",
                t1, t2
            )),
        })
}

/// Helpers to parse duration with clap
pub(crate) use humantime::parse_duration;
