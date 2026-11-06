use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Error;

pub(crate) fn bad_header(value: &str) -> bool {
    value.chars().any(|item| item == '\r' || item == '\n' || item == '\0')
}

pub(crate) fn raw_authority(raw: &str) -> Result<&str, Error> {
    let Some(scheme) = raw.find("://") else {
        return Err(Error::invalid("baseUrl must be an absolute URL."));
    };
    let start = scheme + 3;
    let rest = &raw[start..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return Err(Error::invalid("baseUrl must be an absolute URL."));
    }
    Ok(authority)
}

pub(crate) fn host_of(authority: &str) -> Result<&str, Error> {
    if authority.contains('@') {
        return Err(Error::invalid("baseUrl must be an absolute URL."));
    }
    if let Some(stripped) = authority.strip_prefix('[') {
        let Some(end) = stripped.find(']') else {
            return Err(Error::invalid("baseUrl must be an absolute URL."));
        };
        return Ok(&authority[..=end + 1]);
    }
    if let Some(colon) = authority.rfind(':') {
        if !authority[..colon].contains(':') && authority[colon + 1..].chars().all(|item| item.is_ascii_digit()) {
            return Ok(&authority[..colon]);
        }
    }
    Ok(authority)
}

pub(crate) fn fill_path(template: &str, params: &HashMap<String, String>) -> Result<String, Error> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let end = rest[start + 1..].find('}').ok_or_else(|| Error::invalid("invalid path"))?;
        out.push_str(&rest[..start]);
        let token = &rest[start + 1..start + 1 + end];
        let name = token.split_once('=').map(|(left, _)| left).unwrap_or(token);
        let short = name.rsplit_once('.').map(|(_, right)| right).unwrap_or(name);
        let mut value = params.get(name).map(String::as_str).unwrap_or("");
        if value.is_empty() {
            value = params.get(short).map(String::as_str).unwrap_or("");
        }
        if value.is_empty() && (short == "name" || short.starts_with("name_")) {
            value = params.get("name").map(String::as_str).unwrap_or("");
        }
        if value.is_empty() {
            return Err(Error::invalid(format!("missing path param {short}")));
        }
        let mut escaped = Vec::new();
        for part in value.split('/') {
            if !part.chars().all(|item| item.is_ascii_alphanumeric() || item == '_' || item == '-') || part.is_empty() {
                return Err(Error::invalid(format!("invalid path param {short}")));
            }
            escaped.push(part);
        }
        out.push_str(&escaped.join("/"));
        rest = &rest[start + 1 + end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

pub(crate) fn resolve_url(base_url: &str, path: &str, query: &HashMap<String, String>) -> Result<String, Error> {
    let base = url::Url::parse(base_url).map_err(|_| Error::invalid("invalid path"))?;
    let joined = base.join(path).map_err(|_| Error::invalid("invalid path"))?;
    if joined.scheme() != base.scheme() || host_of(raw_authority(joined.as_str())?)? != host_of(raw_authority(base.as_str())?)? {
        return Err(Error::invalid("invalid path"));
    }
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    let mut url = joined;
    if !pairs.is_empty() {
        let mut serializer = url.query_pairs_mut();
        for (key, value) in pairs {
            serializer.append_pair(&key, &value);
        }
        drop(serializer);
    }
    Ok(url.to_string())
}

pub(crate) fn query_contains_secret(raw_query: &str, secret: &str) -> bool {
    if secret.is_empty() || raw_query.is_empty() {
        return false;
    }
    if raw_query.contains(secret) {
        return true;
    }
    let encoded: String = url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
    if raw_query.contains(&encoded) {
        return true;
    }
    if bad_percent(raw_query) {
        return true;
    }
    for part in raw_query.split('&') {
        let value = part.split_once('=').map(|(_, item)| item).unwrap_or(part);
        if decoded(value, false).contains(secret) || decoded(value, true).contains(secret) {
            return true;
        }
    }
    false
}

pub(crate) fn allowed_upload_url(raw: &str, hosts: &[String]) -> Result<String, Error> {
    if raw.contains('\0') {
        return Err(Error::invalid("upload url rejected"));
    }
    let authority = raw_authority(raw).map_err(|_| Error::invalid("upload url rejected"))?;
    if authority.contains('@') {
        return Err(Error::invalid("upload url rejected"));
    }
    if !raw.starts_with("https://") {
        return Err(Error::invalid("upload url must be https"));
    }
    let host = host_of(authority).map_err(|_| Error::invalid("upload url rejected"))?;
    if host.ends_with('.') {
        return Err(Error::invalid("upload url rejected"));
    }
    let lower = host.to_ascii_lowercase();
    let allowed = hosts.iter().any(|item| lower == *item || lower.ends_with(&format!(".{item}")));
    if !allowed {
        return Err(Error::invalid("upload host rejected"));
    }
    Ok(raw.to_owned())
}

pub(crate) fn retry_delay(retry_after: &str, reset_after: &str, now: SystemTime) -> Duration {
    let when = parse_time(retry_after).or_else(|| parse_time(reset_after));
    let Some(when) = when else {
        return Duration::ZERO;
    };
    let Ok(delay) = when.duration_since(now) else {
        return Duration::ZERO;
    };
    delay.min(Duration::from_secs(60))
}

pub(crate) fn parse_time(value: &str) -> Option<SystemTime> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let text = if value.ends_with('Z') { format!("{}+00:00", &value[..value.len() - 1]) } else { value.to_owned() };
    let (date, time_and_zone) = text.split_once('T')?;
    let (year, rest) = date.split_once('-')?;
    let (month, day) = rest.split_once('-')?;
    let zone_at = time_and_zone.rfind(['+', '-'])?;
    let clock = &time_and_zone[..zone_at];
    let zone = &time_and_zone[zone_at..];
    let mut parts = clock.split(':');
    let hour = parts.next()?;
    let minute = parts.next()?;
    let second = parts.next()?;
    let (second, _fraction) = second.split_once('.').unwrap_or((second, ""));
    let year: i32 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    let day: u32 = day.parse().ok()?;
    let hour: u32 = hour.parse().ok()?;
    let minute: u32 = minute.parse().ok()?;
    let second: u32 = second.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let zone_seconds = zone_offset(zone)?;
    let epoch = days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second) - zone_seconds;
    UNIX_EPOCH.checked_add(Duration::from_secs(epoch as u64)).or_else(|| {
        let before = epoch.unsigned_abs();
        UNIX_EPOCH.checked_sub(Duration::from_secs(before))
    })
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = (year - era * 400) as u64;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + u64::from(day_of_year);
    Some(i64::from(era) * 146_097 + day_of_era as i64 - 719_468)
}

fn zone_offset(zone: &str) -> Option<i64> {
    let sign = if zone.starts_with('+') {
        1
    } else if zone.starts_with('-') {
        -1
    } else {
        return None;
    };
    let digits = &zone[1..];
    let (hour, minute) = if let Some((hour, minute)) = digits.split_once(':') {
        (hour, minute)
    } else if digits.len() == 4 {
        (&digits[..2], &digits[2..])
    } else {
        return None;
    };
    let hour: i64 = hour.parse().ok()?;
    let minute: i64 = minute.parse().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some(sign * (hour * 3600 + minute * 60))
}

fn bad_percent(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() || !bytes[index + 1].is_ascii_hexdigit() || !bytes[index + 2].is_ascii_hexdigit() {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

fn decoded(value: &str, plus: bool) -> String {
    let text = if plus { value.replace('+', " ") } else { value.to_owned() };
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn sent_during(sent: SystemTime, started: SystemTime, now: SystemTime) -> bool {
    sent >= started && sent <= started + Duration::from_secs(120) && sent <= now + Duration::from_secs(60)
}
