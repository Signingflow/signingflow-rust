use serde_json::{Map, Value};

use crate::error::FieldViolation;

pub(crate) fn as_map(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

pub(crate) fn as_str(value: &Value) -> String {
    value.as_str().unwrap_or("").to_owned()
}

pub(crate) fn first_string(record: &Map<String, Value>, keys: &[&str]) -> String {
    for key in keys {
        if let Some(value) = record.get(*key) {
            let text = as_str(value);
            if !text.is_empty() {
                return text;
            }
        }
    }
    String::new()
}

pub(crate) fn as_int(value: &Value) -> Option<i32> {
    match value {
        Value::Number(number) => number.as_i64().and_then(|item| i32::try_from(item).ok()).or_else(|| {
            number.as_f64().and_then(|item| if item.fract() == 0.0 { i32::try_from(item as i64).ok() } else { None })
        }),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

pub(crate) fn grpc_code(body: &Value) -> Option<i32> {
    as_int(as_map(body)?.get("code")?)
}

pub(crate) fn server_message(body: &Value) -> String {
    if let Some(text) = body.as_str() {
        return text.to_owned();
    }
    as_map(body).and_then(|record| record.get("message")).map(as_str).unwrap_or_default()
}

pub(crate) fn trace_code(body: &Value) -> String {
    find_meta(body, "trace_code")
}

pub(crate) fn resource_name(body: &Value) -> String {
    let url = find_meta(body, "resource_url");
    if !url.is_empty() {
        return url;
    }
    find_meta(body, "resource_id")
}

pub(crate) fn mentions_idempotency(body: &Value) -> bool {
    serde_json::to_string(body).unwrap_or_default().to_ascii_lowercase().contains("idempotency")
}

pub(crate) fn field_violations(body: &Value) -> Vec<FieldViolation> {
    let mut found = Vec::new();
    walk(body, &mut |record| {
        let list = record.get("fieldViolations").or_else(|| record.get("field_violations"));
        let Some(Value::Array(items)) = list else {
            return;
        };
        for item in items {
            let Some(row) = as_map(item) else {
                continue;
            };
            let field = row.get("field").map(as_str).unwrap_or_default();
            let description = row.get("description").map(as_str).unwrap_or_default();
            if !field.is_empty() || !description.is_empty() {
                found.push(FieldViolation { field, description });
            }
        }
    });
    found
}

fn find_meta(body: &Value, key: &str) -> String {
    let mut found = String::new();
    walk(body, &mut |record| {
        if !found.is_empty() {
            return;
        }
        let Some(meta) = record.get("metadata").and_then(as_map) else {
            return;
        };
        if let Some(value) = meta.get(key) {
            let text = as_str(value);
            if !text.is_empty() {
                found = text;
            }
        }
    });
    found
}

fn walk(value: &Value, visit: &mut dyn FnMut(&Map<String, Value>)) {
    match value {
        Value::Object(record) => {
            visit(record);
            for child in record.values() {
                walk(child, visit);
            }
        }
        Value::Array(items) => {
            for child in items {
                walk(child, visit);
            }
        }
        _ => {}
    }
}

pub(crate) fn next_token(body: &Map<String, Value>) -> String {
    let snake = body.get("next_page_token").map(as_str).unwrap_or_default();
    if !snake.is_empty() {
        return snake;
    }
    body.get("nextPageToken").map(as_str).unwrap_or_default()
}

pub(crate) fn list_items(body: &Map<String, Value>, key: &str) -> Vec<Map<String, Value>> {
    let Some(Value::Array(raw)) = body.get(key) else {
        return Vec::new();
    };
    raw.iter().filter_map(|item| item.as_object().cloned()).collect()
}
