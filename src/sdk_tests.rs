use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::clock::{self, now};
use crate::page::Page;
use crate::pathutil::{allowed_upload_url, parse_time, query_contains_secret, retry_delay, sent_during};
use crate::redact::redact_message;
use crate::{
    construct_event, Client, ClientOptions, ConstructOptions, Env, ErrorKind, FileCreateParams, PrepareDraftParams, Recipient,
    SendDocumentParams, SendFromTemplateParams, WebhookListParams, WebhookUrlCreateParams,
};

const ID: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const KEY: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

struct Spec {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    drop: bool,
}

#[derive(Clone)]
struct Seen {
    request: String,
    body: String,
}

struct Mock {
    base: String,
    pem: String,
    state: Arc<Mutex<State>>,
    port: u16,
}

struct State {
    rules: VecDeque<Spec>,
    seen: Vec<Seen>,
    stop: bool,
}

impl Mock {
    fn start() -> Self {
        let Certified { pem, certs, key } = issue();
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config");
        let config = Arc::new(config);
        let state = Arc::new(Mutex::new(State { rules: VecDeque::new(), seen: Vec::new(), stop: false }));
        let shared = Arc::clone(&state);
        thread::spawn(move || serve(listener, config, shared));
        Self { base: format!("https://127.0.0.1:{port}"), pem, state, port }
    }

    fn push_json(&self, status: u16, body: Value) {
        self.push(status, vec![], serde_json::to_vec(&body).expect("json"), false);
    }

    fn push(&self, status: u16, headers: Vec<(String, String)>, body: Vec<u8>, drop: bool) {
        self.state.lock().expect("state").rules.push_back(Spec { status, headers, body, drop });
    }

    fn seen(&self) -> Vec<Seen> {
        self.state.lock().expect("state").seen.clone()
    }

    fn client(&self) -> Client {
        self.client_with(ClientOptions::new("ws", Env::Sandbox))
    }

    fn client_with(&self, options: ClientOptions) -> Client {
        Client::new(
            "df_sk_live",
            options.base_url(&self.base).allow_custom_base_url().ca_pem(&self.pem).upload_hosts(vec!["0.0.1".to_owned()]).timeout(Duration::from_secs(2)),
        )
        .expect("client")
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.state.lock().expect("state").stop = true;
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

struct Certified {
    pem: String,
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

fn issue() -> Certified {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    params.subject_alt_names.push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let key_pair = rcgen::KeyPair::generate().expect("key");
    let cert = params.self_signed(&key_pair).expect("cert");
    Certified {
        pem: cert.pem(),
        certs: vec![cert.der().clone()],
        key: rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
    }
}

fn serve(listener: TcpListener, config: Arc<rustls::ServerConfig>, state: Arc<Mutex<State>>) {
    listener.set_nonblocking(false).ok();
    for stream in listener.incoming() {
        if state.lock().expect("state").stop {
            break;
        }
        let Ok(mut stream) = stream else {
            continue;
        };
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
        let mut connection = match rustls::ServerConnection::new(Arc::clone(&config)) {
            Ok(connection) => connection,
            Err(_) => continue,
        };
        let mut tls = rustls::Stream::new(&mut connection, &mut stream);
        let Some((head, body)) = read_http(&mut tls) else {
            continue;
        };
        state.lock().expect("state").seen.push(Seen { request: head.clone(), body: String::from_utf8_lossy(&body).into_owned() });
        let spec = state.lock().expect("state").rules.pop_front();
        let Some(spec) = spec else {
            let _ = write_http(&mut tls, 500, &[], b"missing");
            continue;
        };
        if spec.drop {
            continue;
        }
        let _ = write_http(&mut tls, spec.status, &spec.headers, &spec.body);
    }
}

fn read_http(stream: &mut impl Read) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let size = stream.read(&mut tmp).ok()?;
        if size == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..size]);
        let Some(split) = buf.windows(4).position(|item| item == b"\r\n\r\n") else {
            if buf.len() > 1_000_000 {
                return None;
            }
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..split]).into_owned();
        let mut rest = buf[split + 4..].to_vec();
        let length = content_length(&head);
        while rest.len() < length {
            let size = stream.read(&mut tmp).ok()?;
            if size == 0 {
                break;
            }
            rest.extend_from_slice(&tmp[..size]);
        }
        rest.truncate(length);
        return Some((head, rest));
    }
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| line.split_once(':').and_then(|(name, value)| name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().ok())))
        .flatten()
        .unwrap_or(0)
}

fn write_http(stream: &mut impl Write, status: u16, headers: &[(String, String)], body: &[u8]) -> std::io::Result<()> {
    let reason = if (200..300).contains(&status) { "OK" } else { "ERR" };
    let mut extra = String::new();
    let mut has_type = false;
    let mut has_length = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-type") {
            has_type = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            has_length = true;
        }
        extra.push_str(name);
        extra.push_str(": ");
        extra.push_str(value);
        extra.push_str("\r\n");
    }
    if !has_type {
        extra.push_str("Content-Type: application/json\r\n");
    }
    if !has_length {
        extra.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    let head = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n{extra}\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn envelope(name: &str) -> Value {
    json!({
        "envelope": {
            "name": name,
            "uid": ID,
            "display_name": "NDA",
            "description": "Please sign",
            "documents": [{"uid": "doc-1", "display_name": "NDA"}],
            "compliance": {"profile": "STANDARD"}
        }
    })
}

fn storage(mock: &Mock) -> Value {
    json!({
        "storages": [{
            "name": format!("storages/{ID}"),
            "preSignedUrl": format!("{}/upload", mock.base)
        }]
    })
}

fn must_client(result: Result<Client, crate::Error>) -> Client {
    match result {
        Ok(client) => client,
        Err(err) => panic!("{err}"),
    }
}

fn must_err<T>(result: Result<T, crate::Error>) -> crate::Error {
    match result {
        Err(err) => err,
        Ok(_) => panic!("accepted a value"),
    }
}

#[test]
fn config_rejects_unsafe_values() {
    let missing = must_err(Client::new("", ClientOptions::new("ws", Env::Sandbox)));
    assert_eq!(missing.to_string(), "API key is required.");
    let workspace = must_err(Client::new("df_sk_live", ClientOptions::new("  ", Env::Live)));
    assert_eq!(workspace.to_string(), "workspaceId is required.");
    let http = must_err(Client::new("df_sk_live", ClientOptions::new("ws", Env::Sandbox).base_url("http://api.signingflow.com")));
    assert_eq!(http.to_string(), "baseUrl must be https.");
    let user = must_err(Client::new("df_sk_live", ClientOptions::new("ws", Env::Sandbox).base_url("https://user:pass@api.signingflow.com")));
    assert_eq!(user.to_string(), "baseUrl must not include a username or password.");
    let upper = must_err(Client::new("df_sk_live", ClientOptions::new("ws", Env::Sandbox).base_url("https://API.SIGNINGFLOW.COM")));
    assert_eq!(upper.to_string(), "baseUrl host must be api.signingflow.com, or set allowCustomBaseUrl.");
    let evil = must_err(Client::new("df_sk_live", ClientOptions::new("ws", Env::Sandbox).base_url("https://evil.example")));
    assert_eq!(evil.kind(), ErrorKind::InvalidRequest);
    let nul = must_err(Client::new("df_sk_live", ClientOptions::new("ws", Env::Sandbox).base_url("https://api.signingflow.com\0/x")));
    assert_eq!(nul.to_string(), "baseUrl must be an absolute URL.");
    let header = must_err(Client::new("df_sk_\nlive", ClientOptions::new("ws", Env::Sandbox)));
    assert_eq!(header.to_string(), "invalid header value");
    let timeout = must_err(Client::new("df_sk_live", ClientOptions::new("ws", Env::Sandbox).timeout(Duration::ZERO)));
    assert_eq!(timeout.to_string(), "timeout must be positive.");
    let hosts = must_err(Client::new("df_sk_live", ClientOptions::new("ws", Env::Sandbox).upload_hosts(vec![".bad.com".to_owned()])));
    assert!(hosts.to_string().contains("uploadHosts"));
    let allowed = must_client(Client::new("df_sk_live", ClientOptions::new("ws", Env::Live).base_url("https://files.example.com").allow_custom_base_url().channel("desk").funnel("web")));
    assert_eq!(allowed.files.create(FileCreateParams::default()).unwrap_err().to_string(), "Pass file bytes or a path.");
}

#[test]
fn path_redact_and_retry_helpers() {
    let secret = "df_sk_a/b c+";
    assert!(query_contains_secret(&format!("pageToken={}", urlencoding_of(secret)), secret));
    assert!(query_contains_secret("readMask=%zz", secret));
    assert!(!query_contains_secret("directory=needAction", secret));
    assert_eq!(allowed_upload_url("https://storage.googleapis.com/bucket/a?sig=1", &["storage.googleapis.com".to_owned()]).unwrap(), "https://storage.googleapis.com/bucket/a?sig=1");
    assert_eq!(allowed_upload_url("https://storage.googleapis.com#@evil.com", &["storage.googleapis.com".to_owned()]).unwrap().contains('#'), true);
    assert!(allowed_upload_url("https://user:pass@storage.googleapis.com/x", &["storage.googleapis.com".to_owned()]).is_err());
    assert!(allowed_upload_url("http://storage.googleapis.com/x", &["storage.googleapis.com".to_owned()]).is_err());
    assert!(allowed_upload_url("https://evil.com/x", &["storage.googleapis.com".to_owned()]).is_err());
    let past = UNIX_EPOCH + Duration::from_secs(1_000);
    let future = UNIX_EPOCH + Duration::from_secs(10_000_000_000);
    assert_eq!(retry_delay("2020-01-01T00:00:00Z", "", future), Duration::ZERO);
    assert_eq!(retry_delay("2099-01-01T00:00:00Z", "", past), Duration::from_secs(60));
    assert_eq!(retry_delay("not-a-date", "", past), Duration::ZERO);
    let text = redact_message(&format!("{secret} Bearer abc df_sk_other ?sig=abc"), secret);
    assert!(!text.contains(secret));
    assert!(text.contains("df_sk_redacted"));
    assert!(text.contains("Bearer [redacted]"));
    assert!(text.contains("sig=[redacted]"));
    let long = redact_message(&"A".repeat(600), "");
    assert!(long.ends_with('…'));
    assert!(long.chars().count() <= 501);
    let started = UNIX_EPOCH + Duration::from_secs(1_000);
    let sent = started + Duration::from_secs(30);
    assert!(sent_during(sent, started, started + Duration::from_secs(40)));
    assert!(!sent_during(started - Duration::from_secs(1), started, started));
}

fn urlencoding_of(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[test]
fn pagination_keeps_the_loader() {
    let pages = Arc::new(Mutex::new(0u32));
    let counter = Arc::clone(&pages);
    let mut page = Page::new(vec![1], "a".to_owned());
    page.load = Some(Arc::new(move |token: &str| {
        *counter.lock().expect("count") += 1;
        if token == "a" {
            Ok(Page::new(vec![2], "b".to_owned()))
        } else if token == "b" {
            Ok(Page::new(vec![3], String::new()))
        } else {
            Ok(Page::new(vec![], String::new()))
        }
    }));
    let seen: Result<Vec<_>, _> = page.into_iter().collect();
    assert_eq!(seen.expect("pages"), vec![1, 2, 3]);
    let mut repeated = Page::new(vec![1], "a".to_owned());
    repeated.load = Some(Arc::new(|token: &str| Ok(Page::new(vec![2], token.to_owned()))));
    let values: Vec<_> = repeated.into_iter().collect();
    assert_eq!(values.len(), 2);
    let mut many = Page::new(vec![0], "t".to_owned());
    many.load = Some(Arc::new(|token: &str| Ok(Page::new(vec![1], format!("{token}x")))));
    let err = many.into_iter().find_map(|item| item.err()).expect("limit");
    assert_eq!(err.to_string(), "Too many pages.");
}

#[test]
fn webhook_signatures() {
    let body = br#"{"event":"DOC_ENVELOPE_COMPLETED"}"#;
    let secret = "whsec_current";
    let signature = sign(secret, body);
    let event = construct_event(body, &signature, secret, ConstructOptions::default()).expect("event");
    assert_eq!(event.payload["event"], "DOC_ENVELOPE_COMPLETED");
    assert_eq!(event.body_sha256.len(), 64);
    let previous = sign("whsec_old", body);
    let rotated = construct_event(body, "nope", secret, ConstructOptions { previous_secret: "whsec_old".into(), previous_signature: previous }).expect("rotated");
    assert_eq!(rotated.body_sha256, event.body_sha256);
    assert_eq!(construct_event(body, "00", secret, ConstructOptions::default()).unwrap_err().kind(), ErrorKind::Signature);
    assert_eq!(construct_event(body, &signature, "", ConstructOptions::default()).unwrap_err().to_string(), "Webhook secret is required.");
    assert_eq!(construct_event(b"not-json", &sign(secret, b"not-json"), secret, ConstructOptions::default()).unwrap_err().to_string(), "The webhook body is not JSON.");
}

fn sign(secret: &str, body: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("mac");
    mac.update(body);
    hex_encode(&mac.finalize().into_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn requests_auth_errors_and_retries() {
    let mock = Mock::start();
    mock.push_json(401, json!({"message": "nope", "code": 16}));
    let err = must_err(mock.client().envelopes.retrieve(&format!("envelopes/{ID}"), ""));
    assert_eq!(err.kind(), ErrorKind::Authentication);
    assert_eq!(err.info().grpc_code, Some(16));
    let seen = mock.seen();
    assert!(seen[0].request.contains("GET "));
    assert!(seen[0].request.contains("Authorization: Bearer df_sk_live"));
    assert!(seen[0].request.contains("X-Request-Env: SANDBOX"));
    assert!(seen[0].request.contains("X-Request-Workspace-Id: ws"));
    assert!(seen[0].request.contains("Accept-Encoding: identity"));

    mock.push_json(403, json!({"message": "forbidden"}));
    assert_eq!(must_err(mock.client().envelopes.retrieve(&format!("envelopes/{ID}"), "")).kind(), ErrorKind::Permission);
    mock.push_json(409, json!({"message": "Idempotency conflict", "error": {"details": [{"metadata": {"resource_id": format!("envelopes/{ID}")}}]}}));
    let conflict = must_err(mock.client().envelopes.send(&format!("envelopes/{ID}"), KEY));
    assert_eq!(conflict.kind(), ErrorKind::Idempotency);
    assert_eq!(conflict.info().resource_name, format!("envelopes/{ID}"));
    mock.push(429, vec![("Rate-Limit-Retry-After".into(), "2020-01-01T00:00:00Z".into())], br#"{"message":"slow"}"#.to_vec(), false);
    clock::record_sleeps();
    let reminded = mock.client_with(ClientOptions::new("ws", Env::Sandbox).max_network_retries(0)).envelopes.remind(&format!("envelopes/{ID}"));
    let _ = clock::take_sleeps();
    assert_eq!(must_err(reminded).kind(), ErrorKind::RateLimit);

    mock.push_json(500, json!({"message": "again"}));
    mock.push_json(200, envelope(&format!("envelopes/{ID}")));
    let sent = mock.client().envelopes.send(&format!("envelopes/{ID}"), "").expect("retried");
    assert_eq!(sent.name, format!("envelopes/{ID}"));
    mock.push_json(500, json!({"message": "once"}));
    assert_eq!(must_err(mock.client().envelopes.update(&format!("envelopes/{ID}"), serde_json::Map::new())).kind(), ErrorKind::Api);
    mock.push_json(302, json!({"message": "away"}));
    assert_eq!(must_err(mock.client().envelopes.retrieve(&format!("envelopes/{ID}"), "")).kind(), ErrorKind::Api);
}

#[test]
fn upload_send_download_and_webhooks() {
    let mock = Mock::start();
    let name = format!("envelopes/{ID}");
    mock.push_json(200, storage(&mock));
    mock.push(412, vec![], Vec::new(), false);
    mock.push_json(200, json!({}));
    mock.push_json(200, envelope(&name));
    mock.push_json(200, envelope(&name));
    mock.push_json(200, envelope(&name));
    mock.push_json(200, json!({"name": name, "sent_time": "2026-11-06T00:00:00Z", "progress": {"state": "COMPLETED"}}));
    let envelope = mock.client().envelopes.send_document(SendDocumentParams {
        title: "NDA".into(),
        file: Some(b"%PDF".to_vec()),
        filename: "contract.pdf".into(),
        recipients: vec![Recipient { name: "Ada".into(), email: "ada@example.com".into() }],
        message: "Please sign".into(),
        ..SendDocumentParams::default()
    }).expect("sent");
    assert_eq!(envelope.name, name);
    let seen = mock.seen();
    assert!(seen.iter().any(|item| item.request.starts_with("PUT ") && item.request.contains("x-goog-if-generation-match: 0")));
    assert!(seen.iter().any(|item| item.body.contains("idempotencyKey")));

    mock.push_json(200, json!({"progress": {"state": "COMPLETED"}}));
    mock.push_json(200, json!({"uri": "https://files.example/done", "downloadTime": "2026-11-06T00:00:00Z", "etag": "abc"}));
    let download = mock.client().envelopes.download_completed(&name).expect("download");
    assert_eq!(download.uri, "https://files.example/done");
    assert!(mock.seen().iter().all(|item| !item.request.contains("files.example")));

    mock.push_json(200, json!({"state": "SENT"}));
    assert_eq!(must_err(mock.client().envelopes.download_completed(&name)).to_string(), "The signed file is not ready.");

    mock.push_json(200, json!({"name": format!("webhookUrls/{ID}"), "signingSecret": "whsec_once", "events": ["DOC_ENVELOPE_COMPLETED"]}));
    let destination = mock.client().webhook_urls.create(WebhookUrlCreateParams {
        display_name: "Envelope events".into(),
        http_request_uri: "https://example.com/hooks".into(),
        events: vec!["DOC_ENVELOPE_COMPLETED".into()],
        ..WebhookUrlCreateParams::default()
    }).expect("webhook");
    assert_eq!(destination.signing_secret, "whsec_once");
    mock.push_json(200, json!({"name": format!("webhookUrls/{ID}"), "signingSecret": "whsec_hidden"}));
    assert!(mock.client().webhook_urls.retrieve(&format!("webhookUrls/{ID}")).expect("view").signing_secret.is_empty());
    let none = WebhookUrlCreateParams { http_config: Some(crate::api::HttpConfig { auth: "NONE".into() }), display_name: "x".into(), http_request_uri: "https://example.com".into(), events: vec!["DOC_ENVELOPE_COMPLETED".into()], ..WebhookUrlCreateParams::default() };
    assert!(must_err(mock.client().webhook_urls.create(none)).to_string().contains("NONE"));

    mock.push_json(200, json!({"webhooks": [{"name": format!("webhooks/{ID}"), "event": "DOC_ENVELOPE_COMPLETED"}], "nextPageToken": "next"}));
    mock.push_json(200, json!({"webhooks": [{"name": format!("webhooks/{ID}"), "event": "DOC_ENVELOPE_COMPLETED"}], "nextPageToken": ""}));
    let page = mock.client().webhook_deliveries.list(WebhookListParams::default()).expect("list");
    assert_eq!(page.into_iter().count(), 2);
}

#[test]
fn send_recovery_uses_the_send_window() {
    let mock = Mock::start();
    let name = format!("envelopes/{ID}");
    let started = UNIX_EPOCH + Duration::from_secs(1_767_000_000);
    clock::set_now(Some(started));
    mock.push_json(200, storage(&mock));
    mock.push(200, vec![], Vec::new(), false);
    mock.push_json(200, json!({}));
    mock.push_json(200, envelope(&name));
    mock.push_json(200, envelope(&name));
    mock.push_json(200, envelope(&name));
    mock.push(599, vec![], Vec::new(), true);
    let sent_at = started + Duration::from_secs(20);
    mock.push_json(200, json!({"name": name, "sent_time": stamp(sent_at)}));
    let sent = mock.client_with(ClientOptions::new("ws", Env::Sandbox).max_network_retries(0)).envelopes.send_document(SendDocumentParams {
        title: "NDA".into(),
        file: Some(b"%PDF".to_vec()),
        filename: "a.pdf".into(),
        recipients: vec![Recipient { name: "Ada".into(), email: "ada@example.com".into() }],
        ..SendDocumentParams::default()
    }).expect("recovered");
    assert_eq!(sent.name, name);
    clock::set_now(None);

    clock::set_now(Some(started));
    mock.push_json(200, storage(&mock));
    mock.push(200, vec![], Vec::new(), false);
    mock.push_json(200, json!({}));
    mock.push_json(200, envelope(&name));
    mock.push_json(200, envelope(&name));
    mock.push_json(200, envelope(&name));
    mock.push(599, vec![], Vec::new(), true);
    mock.push_json(200, json!({"name": name, "sent_time": "2020-01-01T00:00:00Z"}));
    assert_eq!(must_err(mock.client_with(ClientOptions::new("ws", Env::Sandbox).max_network_retries(0)).envelopes.send_document(SendDocumentParams {
        title: "NDA".into(),
        file: Some(b"%PDF".to_vec()),
        filename: "a.pdf".into(),
        recipients: vec![Recipient { name: "Ada".into(), email: "ada@example.com".into() }],
        ..SendDocumentParams::default()
    })).kind(), ErrorKind::Connection);
    clock::set_now(None);
}

fn stamp(time: SystemTime) -> String {
    let seconds = time.duration_since(UNIX_EPOCH).expect("time").as_secs();
    let days = (seconds / 86_400) as i64;
    let time_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60)
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let era_day = days + 719_468;
    let era = era_day.div_euclid(146_097);
    let day_of_era = era_day.rem_euclid(146_097) as u64;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 { month_prime + 3 } else { month_prime - 9 };
    let year = year_of_era as i32 + era as i32 * 400 + if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
}

#[test]
fn filesystem_jail_and_limits() {
    let root = std::env::temp_dir().join(format!("sf-rust-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("dir");
    std::fs::write(root.join("ok.pdf"), b"OK").expect("file");
    let mock = Mock::start();
    mock.push_json(200, storage(&mock));
    mock.push(200, vec![], Vec::new(), false);
    mock.push_json(200, json!({}));
    let stored = mock.client_with(ClientOptions::new("ws", Env::Sandbox).upload_root(root.to_string_lossy().to_string())).files.create(FileCreateParams {
        path: "ok.pdf".into(),
        ..FileCreateParams::default()
    }).expect("stored");
    assert_eq!(stored.id, ID);
    let outside = mock.client_with(ClientOptions::new("ws", Env::Sandbox).upload_root(root.to_string_lossy().to_string())).files.create(FileCreateParams { path: "../ok.pdf".into(), ..FileCreateParams::default() });
    assert_eq!(must_err(outside).to_string(), "The path is outside uploadRoot.");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("ok.pdf", root.join("link.pdf")).expect("symlink");
        let linked = mock.client_with(ClientOptions::new("ws", Env::Sandbox).upload_root(root.to_string_lossy().to_string())).files.create(FileCreateParams { path: "link.pdf".into(), ..FileCreateParams::default() });
        assert_eq!(must_err(linked).to_string(), "The file could not be read.");
        std::fs::hard_link(root.join("ok.pdf"), root.join("hard.pdf")).expect("hard");
        let hard = mock.client_with(ClientOptions::new("ws", Env::Sandbox).upload_root(root.to_string_lossy().to_string())).files.create(FileCreateParams { path: "hard.pdf".into(), ..FileCreateParams::default() });
        assert_eq!(must_err(hard).to_string(), "The file must not be a hard link.");
        let fifo = root.join("wait.fifo");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().expect("mkfifo").success());
        let client = mock.client_with(ClientOptions::new("ws", Env::Sandbox).upload_root(root.to_string_lossy().to_string()));
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let result = client.files.create(FileCreateParams { path: "wait.fifo".into(), ..FileCreateParams::default() });
            let _ = tx.send(match result {
                Err(err) => err.to_string(),
                Ok(_) => "acked".to_owned(),
            });
        });
        let text = match rx.recv_timeout(Duration::from_millis(800)) {
            Ok(text) => text,
            Err(_) => {
                let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
                let _ = rx.recv_timeout(Duration::from_secs(2));
                panic!("fifo open blocked");
            }
        };
        assert_eq!(text, "The file could not be read.");
    }
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(must_err(mock.client().files.create(FileCreateParams { path: "ok.pdf".into(), ..FileCreateParams::default() })).to_string(), "A filesystem path requires uploadRoot.");
    assert_eq!(must_err(mock.client().envelopes.list(crate::EnvelopeListParams { directory: "needAction".into(), page_size: Some(0), ..crate::EnvelopeListParams::default() })).to_string(), "pageSize must be a whole number from 1 to 1000.");
    mock.push(200, vec![("Content-Length".into(), "99999999".into()), ("Content-Type".into(), "application/json".into())], Vec::new(), false);
    assert!(must_err(mock.client().envelopes.retrieve(&format!("envelopes/{ID}"), "")).to_string().contains("8 MB"));
    mock.push(200, vec![("Content-Type".into(), "image/png".into())], b"png".to_vec(), false);
    assert!(must_err(mock.client().envelopes.retrieve(&format!("envelopes/{ID}"), "")).to_string().contains("non-JSON"));
    let _ = now();
    let _ = parse_time("2026-11-06T00:00:00Z");
    let _ = PathBuf::from(&root);
}

#[test]
fn template_list_and_guards() {
    let mock = Mock::start();
    let name = format!("envelopes/{ID}");
    mock.push_json(200, envelope(&name));
    mock.push_json(200, envelope(&name));
    mock.push_json(200, envelope(&name));
    mock.push_json(200, json!({"name": name, "sent_time": "2026-11-06T00:00:00Z"}));
    let sent = mock.client().envelopes.send_from_template(SendFromTemplateParams {
        template: format!("templates/{ID}"),
        recipients: vec![Recipient { name: "Ada".into(), email: "ada@example.com".into() }],
        message: String::new(),
    }).expect("template");
    assert_eq!(sent.name, name);
    mock.push_json(200, json!({"envelopes": [envelope(&name)["envelope"]], "nextPageToken": "p2"}));
    mock.push_json(200, json!({"envelopes": [], "nextPageToken": "p2"}));
    let page = mock.client().envelopes.list(crate::EnvelopeListParams { directory: "needAction".into(), ..crate::EnvelopeListParams::default() }).expect("list");
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.into_iter().filter_map(Result::ok).count(), 1);
    mock.push_json(200, storage(&mock));
    mock.push(200, vec![], Vec::new(), false);
    mock.push_json(200, json!({}));
    mock.push_json(200, envelope(&name));
    let draft = mock.client().envelopes.prepare_draft(PrepareDraftParams { title: "NDA".into(), file: Some(b"%PDF".to_vec()), filename: "a.pdf".into(), message: "note".into(), ..PrepareDraftParams::default() }).expect("draft");
    assert_eq!(draft.display_name, "NDA");
    assert!(must_err(mock.client().envelopes.create(crate::EnvelopeCreateParams::default())).to_string().contains("title"));
    assert!(must_err(mock.client().templates.use_template("templates/not-a-uuid", "")).to_string().contains("template"));
    assert!(must_err(mock.client().webhook_urls.test("nope")).to_string().contains("webhook"));
    let secret_query = must_err(mock.client().envelopes.list(crate::EnvelopeListParams { directory: "df_sk_live".into(), ..crate::EnvelopeListParams::default() }));
    assert!(secret_query.to_string().contains("query"));
}
