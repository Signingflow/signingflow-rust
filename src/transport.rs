use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::allowlist::{self, Operation};
use crate::clock::{now, sleep_for};
use crate::config::Resolved;
use crate::error::{Error, ErrorInfo, ErrorKind};
use crate::pathutil::{allowed_upload_url, fill_path, query_contains_secret, resolve_url, retry_delay};
use crate::redact::{redact_message, redact_violations};
use crate::status::{field_violations, grpc_code, mentions_idempotency, resource_name, server_message, trace_code};
use crate::SOURCE;

const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct Sender {
    pub(crate) cfg: Arc<Resolved>,
    agent: ureq::Agent,
}

impl Sender {
    pub(crate) fn new(cfg: Resolved) -> Result<Self, Error> {
        let tls = tls_config(&cfg.ca_pem)?;
        let agent = ureq::AgentBuilder::new()
            .timeout(cfg.timeout)
            .redirects(0)
            .tls_config(Arc::new(tls))
            .build();
        Ok(Self { cfg: Arc::new(cfg), agent })
    }

    pub(crate) fn call(&self, operation_id: &str, path_params: HashMap<String, String>, query: HashMap<String, String>, mut body: Option<Map<String, Value>>, idempotency_key: &str) -> Result<Value, Error> {
        let operation = allowlist::operation(operation_id);
        let mut key = String::new();
        if operation.idempotent {
            key = key_for(idempotency_key, body.as_ref())?;
            let payload = body.get_or_insert_with(Map::new);
            payload.insert("idempotencyKey".to_owned(), Value::String(key.clone()));
        }
        if operation.http == "GET" {
            body = None;
        }
        let path = fill_path(&operation.path, &path_params).map_err(|err| {
            let mut err = err;
            err.info.idempotency_key = key.clone();
            err
        })?;
        let uri = resolve_url(&self.cfg.base_url, &path, &query).map_err(|_| Error::invalid("invalid path"))?;
        let raw_query = uri.split_once('?').map(|(_, item)| item).unwrap_or("");
        if query_contains_secret(raw_query, &self.cfg.api_key) {
            let mut err = Error::invalid("The API key must not be sent in the query string.");
            err.info.idempotency_key = key;
            return Err(err);
        }
        let retries = if operation.http == "GET" || operation.idempotent { self.cfg.retries } else { 0 };
        let encoded = match &body {
            Some(payload) => Some(serde_json::to_vec(payload).map_err(|_| Error::invalid("invalid request body"))?),
            None => None,
        };
        self.exchange(&operation, &uri, encoded.as_deref(), retries, &key)
    }

    pub(crate) fn put_bytes(&self, uri: &str, content_type: &str, data: &[u8]) -> Result<(), Error> {
        let allowed = allowed_upload_url(uri, &self.cfg.upload_hosts)?;
        let mut attempt = 0u32;
        loop {
            let response = self.agent.request("PUT", &allowed).set("Content-Type", content_type).set("x-goog-if-generation-match", "0").send_bytes(data);
            match response {
                Ok(response) => {
                    let status = response.status();
                    if let Err(err) = read_limited(response) {
                        if attempt < self.cfg.retries && err.kind() == ErrorKind::Connection {
                            attempt += 1;
                            continue;
                        }
                        return Err(err);
                    }
                    if (200..300).contains(&status) || status == 412 {
                        return Ok(());
                    }
                    if attempt < self.cfg.retries && status >= 500 {
                        attempt += 1;
                        continue;
                    }
                    if status < 200 {
                        return Err(Error::connection("The upload could not be reached.", 0, ""));
                    }
                    return Err(Error::api_status("Uploading the file to storage failed.", status));
                }
                Err(ureq::Error::Status(status, response)) => {
                    let _ = read_limited(response);
                    if status == 412 {
                        return Ok(());
                    }
                    if attempt < self.cfg.retries && status >= 500 {
                        attempt += 1;
                        continue;
                    }
                    if status < 200 {
                        return Err(Error::connection("The upload could not be reached.", 0, ""));
                    }
                    return Err(Error::api_status("Uploading the file to storage failed.", status));
                }
                Err(_) => {
                    if attempt < self.cfg.retries {
                        attempt += 1;
                        continue;
                    }
                    return Err(Error::connection("The upload could not be reached.", 0, ""));
                }
            }
        }
    }

    fn exchange(&self, operation: &Operation, uri: &str, body: Option<&[u8]>, retries: u32, key: &str) -> Result<Value, Error> {
        let mut attempt = 0u32;
        loop {
            let mut request = self.agent.request(&operation.http, uri);
            for (name, value) in self.headers(&operation.http) {
                request = request.set(&name, &value);
            }
            let sent = match body {
                Some(bytes) => request.send_bytes(bytes),
                None => request.call(),
            };
            match sent {
                Ok(response) => {
                    let status = response.status();
                    let content_type = response.header("content-type").unwrap_or("").to_owned();
                    let retry_after = response.header("Rate-Limit-Retry-After").unwrap_or("").to_owned();
                    let reset_after = response.header("Rate-Limit-Reset-After").unwrap_or("").to_owned();
                    let request_id = response.header("X-Request-Id").unwrap_or("").to_owned();
                    let read = read_limited(response);
                    let bytes = match read {
                        Ok(bytes) => bytes,
                        Err(err) if err.kind() == ErrorKind::Connection && attempt < retries => {
                            attempt += 1;
                            continue;
                        }
                        Err(err) => return Err(stamp_key(err, key)),
                    };
                    if (200..300).contains(&status) {
                        return parse_success(status, &content_type, &bytes);
                    }
                    if attempt < retries && retryable(status) {
                        attempt += 1;
                        sleep_for(retry_delay(&retry_after, &reset_after, now()));
                        continue;
                    }
                    return Err(failure(status, &request_id, &retry_after, &reset_after, &bytes, &operation.capability, key, &self.cfg.api_key));
                }
                Err(ureq::Error::Status(status, response)) => {
                    let content_type = response.header("content-type").unwrap_or("").to_owned();
                    let retry_after = response.header("Rate-Limit-Retry-After").unwrap_or("").to_owned();
                    let reset_after = response.header("Rate-Limit-Reset-After").unwrap_or("").to_owned();
                    let request_id = response.header("X-Request-Id").unwrap_or("").to_owned();
                    let bytes = read_limited(response).unwrap_or_default();
                    if attempt < retries && retryable(status) {
                        attempt += 1;
                        sleep_for(retry_delay(&retry_after, &reset_after, now()));
                        continue;
                    }
                    let _ = content_type;
                    return Err(failure(status, &request_id, &retry_after, &reset_after, &bytes, &operation.capability, key, &self.cfg.api_key));
                }
                Err(err) => {
                    if attempt < retries {
                        attempt += 1;
                        continue;
                    }
                    return Err(connection_from(&err, key));
                }
            }
        }
    }

    fn headers(&self, method: &str) -> Vec<(String, String)> {
        let mut header = vec![
            ("Authorization".to_owned(), format!("Bearer {}", self.cfg.api_key)),
            ("X-Request-Workspace-Id".to_owned(), self.cfg.workspace_id.clone()),
            ("X-Request-Env".to_owned(), self.cfg.wire_env.clone()),
            ("X-Request-Source".to_owned(), SOURCE.to_owned()),
            ("Accept".to_owned(), "application/json".to_owned()),
            ("User-Agent".to_owned(), SOURCE.to_owned()),
            ("Accept-Encoding".to_owned(), "identity".to_owned()),
        ];
        if !self.cfg.channel.is_empty() {
            header.push(("X-Request-Channel".to_owned(), self.cfg.channel.clone()));
        }
        if !self.cfg.funnel.is_empty() {
            header.push(("X-Request-Funnel".to_owned(), self.cfg.funnel.clone()));
        }
        if method != "GET" {
            header.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        header
    }
}

fn key_for(supplied: &str, body: Option<&Map<String, Value>>) -> Result<String, Error> {
    let mut raw = supplied.trim().to_owned();
    if raw.is_empty() {
        if let Some(body) = body {
            if let Some(value) = body.get("idempotencyKey").and_then(|item| item.as_str()) {
                raw = value.trim().to_owned();
            }
        }
    }
    if raw.is_empty() {
        return Ok(crate::clock::new_uuid());
    }
    if !is_uuid(&raw) {
        return Err(Error::invalid("idempotencyKey must be a UUID."));
    }
    Ok(raw)
}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    let hex = |index: usize| bytes[index].is_ascii_hexdigit();
    let dash = |index: usize| bytes[index] == b'-';
    (0..8).all(hex) && dash(8) && (9..13).all(hex) && dash(13) && (14..18).all(hex) && dash(18) && (19..23).all(hex) && dash(23) && (24..36).all(hex)
        && (b'1'..=b'8').contains(&bytes[14].to_ascii_lowercase())
        && matches!(bytes[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b')
}

fn retryable(status: u16) -> bool {
    status == 408 || status == 429 || status >= 500
}

fn connection_from(err: &ureq::Error, key: &str) -> Error {
    let text = err.to_string().to_ascii_lowercase();
    if text.contains("timed out") || text.contains("timeout") {
        return Error::connection("The API timed out.", 408, key);
    }
    Error::connection("The API could not be reached.", 0, key)
}

fn stamp_key(mut err: Error, key: &str) -> Error {
    if err.info.idempotency_key.is_empty() {
        err.info.idempotency_key = key.to_owned();
    }
    err
}

fn read_limited(response: ureq::Response) -> Result<Vec<u8>, Error> {
    if let Some(raw) = response.header("content-length") {
        if raw.is_empty() || raw.len() > 7 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::api("The API response is larger than 8 MB."));
        }
        let length: u64 = raw.parse().unwrap_or(u64::MAX);
        if length > MAX_RESPONSE_BYTES {
            return Err(Error::api("The API response is larger than 8 MB."));
        }
    }
    let mut buf = Vec::new();
    let mut reader = response.into_reader().take(MAX_RESPONSE_BYTES + 1);
    reader.read_to_end(&mut buf).map_err(|_| Error::connection("The API could not be reached.", 0, ""))?;
    if buf.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(Error::api("The API response is larger than 8 MB."));
    }
    Ok(buf)
}

fn parse_success(status: u16, content_type: &str, body: &[u8]) -> Result<Value, Error> {
    if body.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(Value::Object(Map::new()));
    }
    if !content_type.is_empty() && !content_type.contains("json") && !content_type.contains("text/") {
        return Err(Error::api_status("The API returned a non-JSON body.", status));
    }
    serde_json::from_slice(body).map_err(|_| Error::api_status("The API returned invalid JSON.", status))
}

fn failure(status: u16, request_id: &str, retry_after: &str, reset_after: &str, body: &[u8], capability: &str, key: &str, secret: &str) -> Error {
    let parsed = if body.iter().all(|byte| byte.is_ascii_whitespace()) {
        Value::String(String::new())
    } else {
        serde_json::from_slice(body).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into_owned()))
    };
    let mut message = server_message(&parsed);
    if message.is_empty() {
        message = if body.is_empty() {
            format!("Request failed with status {status}.")
        } else {
            String::from_utf8_lossy(body).into_owned()
        };
    }
    let mut info = ErrorInfo::new(redact_message(&message, secret));
    info.status_code = status;
    info.grpc_code = grpc_code(&parsed);
    info.trace_code = trace_code(&parsed);
    info.request_id = request_id.to_owned();
    info.idempotency_key = key.to_owned();
    info.capability = capability.to_owned();
    info.field_violations = redact_violations(field_violations(&parsed), secret);
    info.retry_after = if !retry_after.is_empty() { retry_after.to_owned() } else { reset_after.to_owned() };
    let kind = if status == 401 {
        ErrorKind::Authentication
    } else if status == 403 {
        ErrorKind::Permission
    } else if status == 409 && mentions_idempotency(&parsed) {
        info.resource_name = resource_name(&parsed);
        ErrorKind::Idempotency
    } else if status == 429 {
        ErrorKind::RateLimit
    } else if (400..500).contains(&status) {
        ErrorKind::InvalidRequest
    } else {
        ErrorKind::Api
    };
    Error::with_kind(kind, info)
}

fn tls_config(ca_pem: &str) -> Result<rustls::ClientConfig, Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    if ca_pem.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else {
        let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut cursor).collect::<Result<Vec<_>, _>>().map_err(|_| Error::invalid("The CA bundle could not be read."))?;
        if certs.is_empty() {
            return Err(Error::invalid("The CA bundle could not be read."));
        }
        for cert in certs {
            roots.add(cert).map_err(|_| Error::invalid("The CA bundle could not be read."))?;
        }
    }
    Ok(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
}

impl Error {
    fn api_status(message: &str, status: u16) -> Self {
        let mut err = Self::api(message);
        err.info.status_code = status;
        err
    }
}
