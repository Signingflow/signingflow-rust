use crate::error::FieldViolation;

pub(crate) fn redact_message(value: &str, secret: &str) -> String {
    let mut cleaned = exact(value, secret);
    cleaned = secret_key(&cleaned);
    cleaned = bearer(&cleaned);
    cleaned = signed_query(&cleaned);
    if cleaned.chars().count() <= 500 {
        return cleaned;
    }
    let mut end = cleaned.char_indices().nth(500).map(|(index, _)| index).unwrap_or(cleaned.len());
    if !cleaned.is_char_boundary(end) {
        end = cleaned.len();
    }
    format!("{}…", &cleaned[..end])
}

fn exact(value: &str, secret: &str) -> String {
    if secret.is_empty() {
        return value.to_owned();
    }
    let encoded: String = url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
    let raw = percent_encode(secret);
    value.replace(secret, "[redacted]").replace(&encoded, "[redacted]").replace(&raw, "[redacted]")
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn secret_key(value: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = value.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index..].starts_with(&['d', 'f', '_', 's', 'k', '_']) {
            let start = index;
            index += 6;
            while index < chars.len() && (chars[index].is_ascii_alphanumeric() || chars[index] == '_' || chars[index] == '-') {
                index += 1;
            }
            if index > start + 6 {
                out.push_str("df_sk_redacted");
                continue;
            }
            index = start;
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

fn bearer(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let mut out = String::new();
    let mut index = 0;
    let bytes = value.as_bytes();
    let lower_bytes = lower.as_bytes();
    while index < bytes.len() {
        if lower_bytes[index..].starts_with(b"bearer ") {
            out.push_str("Bearer [redacted]");
            index += 7;
            while index < bytes.len() && !lower_bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            continue;
        }
        out.push(bytes[index] as char);
        index += 1;
    }
    out
}

fn signed_query(value: &str) -> String {
    let mut out = String::new();
    let lower = value.to_ascii_lowercase();
    let mut index = 0;
    let bytes = value.as_bytes();
    while index < bytes.len() {
        if matches!(bytes[index], b'?' | b'&') {
            let rest = &lower[index + 1..];
            let key = ["x-goog-signature=", "signature=", "sig=", "token="].iter().find(|key| rest.starts_with(*key));
            if let Some(key) = key {
                out.push(bytes[index] as char);
                out.push_str(&value[index + 1..index + 1 + key.len()]);
                out.push_str("[redacted]");
                index += 1 + key.len();
                while index < bytes.len() && bytes[index] != b'&' && !bytes[index].is_ascii_whitespace() && bytes[index] != b'"' {
                    index += 1;
                }
                continue;
            }
        }
        out.push(bytes[index] as char);
        index += 1;
    }
    out
}

pub(crate) fn redact_violations(list: Vec<FieldViolation>, secret: &str) -> Vec<FieldViolation> {
    list.into_iter()
        .map(|item| FieldViolation {
            field: redact_message(&item.field, secret),
            description: redact_message(&item.description, secret),
        })
        .collect()
}
