use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::clock::now;
use crate::error::Error;
use crate::jail::{self, JailError};
use crate::page::{page_size, Page};
use crate::pathutil::{parse_time, sent_during};
use crate::status::{as_map, as_str, first_string, list_items, next_token};
use crate::transport::Sender;

const MAX_UPLOAD: u64 = 25 * 1024 * 1024;

fn mime_of(extension: &str) -> Option<&'static str> {
    match extension {
        "pdf" => Some("application/pdf"),
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "txt" => Some("text/plain"),
        "json" => Some("application/json"),
        _ => None,
    }
}

/// A file that has been uploaded and acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    pub name: String,
    pub id: String,
}

/// Uploads bytes or a path inside `upload_root`. Pass one of `file` or `path`.
#[derive(Debug, Clone, Default)]
pub struct FileCreateParams {
    pub file: Option<Vec<u8>>,
    pub path: String,
    pub filename: String,
    pub mime_type: String,
    pub idempotency_key: String,
}

/// Uploads documents.
#[derive(Clone)]
pub struct Files {
    sender: Sender,
}

impl Files {
    pub(crate) fn new(sender: Sender) -> Self {
        Self { sender }
    }

    pub fn create(&self, params: FileCreateParams) -> Result<StoredFile, Error> {
        let loaded = load_file(&params, &self.sender.cfg.upload_root)?;
        let added = self.sender.call(
            "StorageService_BatchAddStorage",
            HashMap::new(),
            HashMap::new(),
            Some(object(&[
                ("storages", json!([{
                    "originalName": loaded.filename,
                    "displayName": loaded.filename,
                    "size": loaded.bytes.len().to_string(),
                    "extension": loaded.extension,
                    "mimeType": loaded.mime_type,
                }])),
            ])),
            &params.idempotency_key,
        )?;
        let (name, id, raw_url) = find_storage(&added).ok_or_else(|| Error::api("Storage did not return an upload URL."))?;
        let upload_url = crate::pathutil::allowed_upload_url(&raw_url, &self.sender.cfg.upload_hosts)?;
        self.sender.put_bytes(&upload_url, &loaded.mime_type, &loaded.bytes)?;
        self.sender.call(
            "StorageService_BatchAcknowledgeUpload",
            HashMap::new(),
            HashMap::new(),
            Some(object(&[("names", json!([name]))])),
            "",
        )?;
        Ok(StoredFile { name, id })
    }
}

struct LoadedFile {
    bytes: Vec<u8>,
    filename: String,
    extension: String,
    mime_type: String,
}

fn load_file(params: &FileCreateParams, upload_root: &str) -> Result<LoadedFile, Error> {
    let has_file = params.file.is_some();
    let has_path = !params.path.trim().is_empty();
    if has_file && has_path {
        return Err(Error::invalid("Pass file bytes or a path, not both."));
    }
    if !has_file && !has_path {
        return Err(Error::invalid("Pass file bytes or a path."));
    }
    let data = if let Some(bytes) = &params.file {
        bytes.clone()
    } else {
        read_path(upload_root, params.path.trim())?
    };
    if data.len() as u64 > MAX_UPLOAD {
        return Err(Error::invalid("The file is larger than 25 MB."));
    }
    let mut filename = params.filename.trim().to_owned();
    if filename.is_empty() && has_path {
        filename = Path::new(params.path.trim()).file_name().and_then(|item| item.to_str()).unwrap_or("").to_owned();
    }
    if filename.is_empty() || filename == "." || filename == "/" {
        return Err(Error::invalid("filename is required when file is not a path."));
    }
    let extension = Path::new(&filename).extension().and_then(|item| item.to_str()).unwrap_or("").to_ascii_lowercase();
    let mut mime_type = params.mime_type.trim().to_owned();
    if mime_type.is_empty() {
        mime_type = mime_of(&extension).unwrap_or("application/octet-stream").to_owned();
    }
    Ok(LoadedFile { bytes: data, filename, extension, mime_type })
}

fn read_path(upload_root: &str, requested: &str) -> Result<Vec<u8>, Error> {
    if upload_root.trim().is_empty() {
        return Err(Error::invalid("A filesystem path requires uploadRoot."));
    }
    match jail::read_jailed(upload_root, requested, MAX_UPLOAD) {
        Ok(bytes) => Ok(bytes),
        Err(JailError::TooLarge) => Err(Error::invalid("The file is larger than 25 MB.")),
        Err(JailError::Outside) => Err(Error::invalid("The path is outside uploadRoot.")),
        Err(JailError::HardLink) => Err(Error::invalid("The file must not be a hard link.")),
        Err(JailError::Nofollow | JailError::Read) => Err(Error::invalid("The file could not be read.")),
    }
}

/// A person who signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub name: String,
    pub email: String,
}

/// A draft or sent envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    pub name: String,
    pub uid: String,
    pub display_name: String,
    pub description: String,
    pub progress_status: String,
    pub state: String,
    pub condition: String,
    pub sent_time: String,
    pub documents: Vec<Map<String, Value>>,
    pub compliance: Option<Map<String, Value>>,
    pub progress: Option<Map<String, Value>>,
}

/// The JSON download record. `uri` is not fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Download {
    pub uri: String,
    pub download_time: String,
    pub etag: String,
}

#[derive(Debug, Clone, Default)]
pub struct EnvelopeCreateParams {
    pub display_name: String,
    pub description: String,
    pub storage_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Default)]
pub struct EnvelopeListParams {
    pub directory: String,
    pub page_size: Option<u32>,
    pub page_token: String,
    pub read_mask: String,
}

#[derive(Debug, Clone, Default)]
pub struct PrepareDraftParams {
    pub title: String,
    pub file: Option<Vec<u8>>,
    pub path: String,
    pub filename: String,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct SendDocumentParams {
    pub title: String,
    pub file: Option<Vec<u8>>,
    pub path: String,
    pub filename: String,
    pub recipients: Vec<Recipient>,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct SendFromTemplateParams {
    pub template: String,
    pub recipients: Vec<Recipient>,
    pub message: String,
}

/// Creates, sends, and reads envelopes.
#[derive(Clone)]
pub struct Envelopes {
    sender: Sender,
    files: Files,
    templates: Templates,
}

impl Envelopes {
    pub(crate) fn new(sender: Sender, files: Files, templates: Templates) -> Self {
        Self { sender, files, templates }
    }

    pub fn create(&self, params: EnvelopeCreateParams) -> Result<Envelope, Error> {
        let title = params.display_name.trim();
        if title.is_empty() {
            return Err(Error::invalid("Name the draft title."));
        }
        let storage_id = params.storage_id.trim();
        if storage_id.is_empty() {
            return Err(Error::invalid("storageId is required."));
        }
        let created = self.sender.call(
            "EnvelopeService_AddEnvelope",
            HashMap::new(),
            HashMap::new(),
            Some(object(&[(
                "envelope",
                json!({
                    "display_name": title,
                    "description": params.description.trim(),
                    "documents": [{
                        "display_name": title,
                        "attachments": [{"storage_id": storage_id}],
                        "supplemental": false
                    }]
                }),
            )])),
            &params.idempotency_key,
        )?;
        Ok(created_envelope(&created))
    }

    pub fn retrieve(&self, name: &str, read_mask: &str) -> Result<Envelope, Error> {
        let envelope = require_name(name, NameKind::Envelope)?;
        let mut query = HashMap::new();
        query.insert("readMask".to_owned(), read_mask.to_owned());
        let viewed = self.sender.call("EnvelopeService_ViewEnvelope", name_params(&envelope), query, None, "")?;
        let mut decoded = decode_envelope(&viewed);
        if decoded.name.is_empty() {
            decoded.name = envelope;
        }
        Ok(decoded)
    }

    /// Patches an envelope. The call is not retried.
    pub fn update(&self, name: &str, mut body: Map<String, Value>) -> Result<Envelope, Error> {
        let envelope = require_name(name, NameKind::Envelope)?;
        if as_str(body.get("name").unwrap_or(&Value::Null)).is_empty() {
            body.insert("name".to_owned(), Value::String(envelope.clone()));
        }
        let updated = self.sender.call("EnvelopeService_UpdateEnvelope", name_params(&envelope), HashMap::new(), Some(body), "")?;
        Ok(decode_envelope(&updated))
    }

    pub fn send(&self, name: &str, idempotency_key: &str) -> Result<Envelope, Error> {
        let envelope = require_name(name, NameKind::Envelope)?;
        let sent = self.sender.call(
            "EnvelopeService_SendEnvelope",
            name_params(&envelope),
            HashMap::new(),
            Some(Map::new()),
            idempotency_key,
        )?;
        let mut decoded = decode_envelope(&sent);
        if decoded.name.is_empty() {
            decoded.name = envelope;
        }
        Ok(decoded)
    }

    pub fn list(&self, params: EnvelopeListParams) -> Result<Page<Envelope>, Error> {
        let directory = params.directory.trim().to_owned();
        if directory.is_empty() {
            return Err(Error::invalid("directory is required."));
        }
        let size = page_size(params.page_size)?;
        let sender = self.sender.clone();
        let read_mask = params.read_mask.clone();
        let load = Arc::new(move |token: &str| list_envelopes(&sender, &directory, size, token, &read_mask));
        let mut page = load(&params.page_token)?;
        page.load = Some(load);
        Ok(page)
    }

    /// Notifies people who can still sign. The call is not retried.
    pub fn remind(&self, name: &str) -> Result<Envelope, Error> {
        let envelope = require_name(name, NameKind::Envelope)?;
        let reminded = self.sender.call(
            "EnvelopeService_RemindEnvelopeSigners",
            name_params(&envelope),
            HashMap::new(),
            Some(Map::new()),
            "",
        )?;
        let mut decoded = decode_envelope(&reminded);
        if decoded.name.is_empty() {
            decoded.name = envelope;
        }
        Ok(decoded)
    }

    /// Returns the download record and does not GET `uri`.
    pub fn download(&self, name: &str) -> Result<Download, Error> {
        let envelope = require_name(name, NameKind::Envelope)?;
        let downloaded = self.sender.call("EnvelopeService_DownloadEnvelope", name_params(&envelope), HashMap::new(), None, "")?;
        let record = as_map(&downloaded);
        Ok(Download {
            uri: record.and_then(|item| item.get("uri")).map(as_str).unwrap_or_default(),
            download_time: record.map(|item| first_string(item, &["download_time", "downloadTime"])).unwrap_or_default(),
            etag: record.and_then(|item| item.get("etag")).map(as_str).unwrap_or_default(),
        })
    }

    /// Stores one PDF and creates a draft. It does not email anyone.
    pub fn prepare_draft(&self, params: PrepareDraftParams) -> Result<Envelope, Error> {
        let title = params.title.trim();
        if title.is_empty() {
            return Err(Error::invalid("Name the PDF and the draft title."));
        }
        let stored = self.files.create(FileCreateParams {
            file: params.file,
            path: params.path,
            filename: params.filename,
            ..FileCreateParams::default()
        })?;
        self.create(EnvelopeCreateParams {
            display_name: title.to_owned(),
            description: params.message,
            storage_id: stored.id,
            ..EnvelopeCreateParams::default()
        })
    }

    /// Stores the PDF, addresses the first document, and sends.
    pub fn send_document(&self, params: SendDocumentParams) -> Result<Envelope, Error> {
        let title = params.title.trim();
        if title.is_empty() {
            return Err(Error::invalid("Name the PDF, the title, and the recipients."));
        }
        let people = clean_recipients(params.recipients)?;
        let stored = self.files.create(FileCreateParams {
            file: params.file,
            path: params.path,
            filename: params.filename,
            ..FileCreateParams::default()
        })?;
        let created = self.create(EnvelopeCreateParams {
            display_name: title.to_owned(),
            description: params.message.clone(),
            storage_id: stored.id,
            ..EnvelopeCreateParams::default()
        })?;
        self.finish_send(created, people, &params.message, title)
    }

    /// Starts from `templates/{id}`.
    pub fn send_from_template(&self, params: SendFromTemplateParams) -> Result<Envelope, Error> {
        let template = require_name(&params.template, NameKind::Template)?;
        let people = clean_recipients(params.recipients)?;
        let created = self.templates.use_template(&template, "")?;
        self.finish_send(created, people, &params.message, &template)
    }

    /// Requests the download URL only when the state is `COMPLETED`.
    pub fn download_completed(&self, name: &str) -> Result<Download, Error> {
        let envelope = require_name(name, NameKind::Envelope)?;
        let viewed = self.retrieve(&envelope, "")?;
        if envelope_state(&viewed).trim().to_ascii_uppercase() != "COMPLETED" {
            return Err(Error::invalid("The signed file is not ready.").attach(&envelope));
        }
        self.download(&envelope)
    }

    fn finish_send(&self, created: Envelope, people: Vec<Recipient>, message: &str, label: &str) -> Result<Envelope, Error> {
        let name = created.name.clone();
        if require_name(&name, NameKind::Envelope).is_err() {
            return Err(Error::api(format!("{label} was saved without an envelope name.")));
        }
        let viewed = self.retrieve(&name, "documents,compliance").map_err(|err| err.attach(&name))?;
        let Some(patched) = with_recipients(&viewed, &people, message) else {
            return Err(Error::invalid("The draft has no document to address.").attach(&name));
        };
        self.update(&name, patched).map_err(|err| err.attach(&name))?;
        self.send_or_view(&name)
    }

    fn send_or_view(&self, name: &str) -> Result<Envelope, Error> {
        let started = now();
        match self.send(name, "") {
            Ok(sent) => Ok(sent),
            Err(err) if err.kind() == crate::error::ErrorKind::Idempotency && err.info.resource_name == name => {
                match self.retrieve(name, "") {
                    Ok(viewed) => Ok(viewed),
                    Err(_) => Err(err.attach(name)),
                }
            }
            Err(err) if err.kind() == crate::error::ErrorKind::Connection => match self.retrieve(name, "") {
                Ok(viewed) => match parse_time(&viewed.sent_time) {
                    Some(sent) if sent_during(sent, started, now()) => Ok(viewed),
                    _ => Err(err.attach(name)),
                },
                Err(_) => Err(err.attach(name)),
            },
            Err(err) => Err(err.attach(name)),
        }
    }
}

fn list_envelopes(sender: &Sender, directory: &str, page_size: u32, page_token: &str, read_mask: &str) -> Result<Page<Envelope>, Error> {
    let mut query = HashMap::new();
    query.insert("directory".to_owned(), directory.to_owned());
    query.insert("pageSize".to_owned(), page_size.to_string());
    query.insert("pageToken".to_owned(), page_token.to_owned());
    query.insert("readMask".to_owned(), read_mask.to_owned());
    let body = sender.call("EnvelopeService_ListEnvelopes", parent_params("envelopes"), query, None, "")?;
    let record = as_map(&body);
    let data = record.map(|item| list_items(item, "envelopes")).unwrap_or_default().iter().map(|item| decode_envelope(&Value::Object(item.clone()))).collect();
    let token = record.map(next_token).unwrap_or_default();
    Ok(Page::new(data, token))
}

fn with_recipients(envelope: &Envelope, people: &[Recipient], message: &str) -> Option<Map<String, Value>> {
    let mut refs = Vec::new();
    for item in &envelope.documents {
        let uid = first_string(item, &["uid", "id"]);
        if uid.is_empty() {
            continue;
        }
        refs.push((uid, first_string(item, &["display_name", "displayName"])));
    }
    if refs.is_empty() {
        return None;
    }
    let participants: Vec<Value> = people
        .iter()
        .enumerate()
        .map(|(index, person)| {
            json!({
                "uid": crate::clock::new_uuid(),
                "display_name": person.name,
                "alternate_email": person.email,
                "role": "SIGNER",
                "type": "PERSONAL",
                "action_order_type": "SERIAL",
                "action_order_number": index + 1,
            })
        })
        .collect();
    let profile = envelope.compliance.as_ref().and_then(|item| item.get("profile")).map(as_str).filter(|item| !item.is_empty()).unwrap_or_else(|| "STANDARD".to_owned());
    let description = if message.trim().is_empty() { envelope.description.clone() } else { message.trim().to_owned() };
    let documents: Vec<Value> = refs
        .into_iter()
        .enumerate()
        .map(|(index, (uid, display_name))| {
            let mut item = json!({ "uid": uid, "display_name": display_name });
            if index == 0 {
                item["participants"] = Value::Array(participants.clone());
            }
            item
        })
        .collect();
    Some(object(&[
        ("name", Value::String(envelope.name.clone())),
        ("display_name", Value::String(envelope.display_name.clone())),
        ("description", Value::String(description)),
        ("compliance", json!({ "profile": profile })),
        ("documents", Value::Array(documents)),
    ]))
}

/// Starts an envelope from a template.
#[derive(Clone)]
pub struct Templates {
    sender: Sender,
}

impl Templates {
    pub(crate) fn new(sender: Sender) -> Self {
        Self { sender }
    }

    pub fn use_template(&self, name: &str, idempotency_key: &str) -> Result<Envelope, Error> {
        let template = require_name(name, NameKind::Template)?;
        let used = self.sender.call("TemplateService_UseTemplate", name_params(&template), HashMap::new(), Some(Map::new()), idempotency_key)?;
        Ok(created_envelope(&used))
    }
}

/// Rejected. Leave it unset so the destination uses HMAC.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub auth: String,
}

/// A webhook destination. `signing_secret` is returned once, from `create`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookUrl {
    pub name: String,
    pub display_name: String,
    pub http_request_uri: String,
    pub events: Vec<String>,
    pub signing_secret: String,
}

#[derive(Debug, Clone, Default)]
pub struct WebhookUrlCreateParams {
    pub display_name: String,
    pub http_request_uri: String,
    pub events: Vec<String>,
    pub idempotency_key: String,
    pub http_config: Option<HttpConfig>,
}

/// One stored webhook delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookDelivery {
    pub name: String,
    pub event: String,
}

#[derive(Debug, Clone, Default)]
pub struct WebhookListParams {
    pub page_size: Option<u32>,
    pub page_token: String,
}

/// Manages webhook destinations.
#[derive(Clone)]
pub struct WebhookUrls {
    sender: Sender,
}

impl WebhookUrls {
    pub(crate) fn new(sender: Sender) -> Self {
        Self { sender }
    }

    pub fn create(&self, params: WebhookUrlCreateParams) -> Result<WebhookUrl, Error> {
        let display_name = params.display_name.trim();
        if !(1..=100).contains(&display_name.chars().count()) {
            return Err(Error::invalid("displayName must be 1 to 100 characters."));
        }
        let parsed = url::Url::parse(&params.http_request_uri).map_err(|_| Error::invalid("httpRequestUri must be an https URL."))?;
        if parsed.scheme() != "https" || parsed.host_str().unwrap_or("").is_empty() {
            return Err(Error::invalid("httpRequestUri must be an https URL."));
        }
        if params.events.is_empty() {
            return Err(Error::invalid("events is required."));
        }
        if let Some(config) = &params.http_config {
            if config.auth.eq_ignore_ascii_case("NONE") {
                return Err(Error::invalid("auth NONE has no signature. Leave httpConfig empty."));
            }
            return Err(Error::invalid("Leave httpConfig empty so the destination uses HMAC."));
        }
        let created = self.sender.call(
            "WebhookUrlService_AddWebhookUrl",
            HashMap::new(),
            HashMap::new(),
            Some(object(&[(
                "webhookUrl",
                json!({
                    "displayName": display_name,
                    "httpRequestUri": params.http_request_uri,
                    "events": params.events,
                }),
            )])),
            &params.idempotency_key,
        )?;
        Ok(decode_webhook(&created, false))
    }

    /// Reads a destination and omits the signing secret.
    pub fn retrieve(&self, name: &str) -> Result<WebhookUrl, Error> {
        let destination = require_name(name, NameKind::WebhookUrl)?;
        let viewed = self.sender.call("WebhookUrlService_ViewWebhookUrl", name_params(&destination), HashMap::new(), None, "")?;
        Ok(decode_webhook(&viewed, true))
    }

    /// Asks the API to send a sample event. The call is not retried.
    pub fn test(&self, name: &str) -> Result<WebhookUrl, Error> {
        let destination = require_name(name, NameKind::WebhookUrl)?;
        let tested = self.sender.call(
            "WebhookUrlService_TestWebhookUrl",
            name_params(&destination),
            HashMap::new(),
            Some(Map::new()),
            "",
        )?;
        Ok(decode_webhook(&tested, false))
    }
}

/// Reads stored deliveries.
#[derive(Clone)]
pub struct WebhookDeliveries {
    sender: Sender,
}

impl WebhookDeliveries {
    pub(crate) fn new(sender: Sender) -> Self {
        Self { sender }
    }

    pub fn list(&self, params: WebhookListParams) -> Result<Page<WebhookDelivery>, Error> {
        let size = page_size(params.page_size)?;
        let sender = self.sender.clone();
        let load = Arc::new(move |token: &str| list_deliveries(&sender, size, token));
        let mut page = load(&params.page_token)?;
        page.load = Some(load);
        Ok(page)
    }

    pub fn retrieve(&self, name: &str) -> Result<WebhookDelivery, Error> {
        let delivery = require_name(name, NameKind::Delivery)?;
        let viewed = self.sender.call("WebhookService_ViewWebhook", name_params(&delivery), HashMap::new(), None, "")?;
        Ok(decode_delivery(&viewed))
    }
}

fn list_deliveries(sender: &Sender, page_size: u32, page_token: &str) -> Result<Page<WebhookDelivery>, Error> {
    let mut query = HashMap::new();
    query.insert("pageSize".to_owned(), page_size.to_string());
    query.insert("pageToken".to_owned(), page_token.to_owned());
    let body = sender.call("WebhookService_ListWebhooks", parent_params("webhooks"), query, None, "")?;
    let record = as_map(&body);
    let data = record.map(|item| list_items(item, "webhooks")).unwrap_or_default().iter().map(|item| decode_delivery(&Value::Object(item.clone()))).collect();
    Ok(Page::new(data, record.map(next_token).unwrap_or_default()))
}

fn object(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs.iter().map(|(key, value)| ((*key).to_owned(), value.clone())).collect()
}

fn name_params(name: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    params.insert("name".to_owned(), name.to_owned());
    params
}

fn parent_params(parent: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    params.insert("parent".to_owned(), parent.to_owned());
    params
}

#[derive(Clone, Copy)]
enum NameKind {
    Envelope,
    Template,
    WebhookUrl,
    Delivery,
}

fn require_name(name: &str, kind: NameKind) -> Result<String, Error> {
    let name = name.trim();
    let (pattern_ok, message) = match kind {
        NameKind::Envelope => (is_resource(name, "envelopes/"), "envelope must look like envelopes/{id}."),
        NameKind::Template => (is_resource(name, "templates/"), "template must look like templates/{id}."),
        NameKind::WebhookUrl => (is_resource(name, "webhookUrls/"), "webhook url must look like webhookUrls/{id}."),
        NameKind::Delivery => (is_resource(name, "webhooks/"), "webhook delivery must look like webhooks/{id}."),
    };
    if !pattern_ok {
        return Err(Error::invalid(message));
    }
    Ok(name.to_owned())
}

fn is_resource(name: &str, prefix: &str) -> bool {
    let Some(id) = name.strip_prefix(prefix) else {
        return false;
    };
    is_loose_uuid(id)
}

fn valid_email(email: &str) -> bool {
    let Some((left, right)) = email.split_once('@') else {
        return false;
    };
    !left.is_empty()
        && !right.is_empty()
        && !right.contains('@')
        && !left.chars().any(char::is_whitespace)
        && !right.chars().any(char::is_whitespace)
}

fn is_loose_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && (0..8).all(|index| bytes[index].is_ascii_hexdigit())
        && bytes[8] == b'-'
        && (9..13).all(|index| bytes[index].is_ascii_hexdigit())
        && bytes[13] == b'-'
        && (14..18).all(|index| bytes[index].is_ascii_hexdigit())
        && bytes[18] == b'-'
        && (19..23).all(|index| bytes[index].is_ascii_hexdigit())
        && bytes[23] == b'-'
        && (24..36).all(|index| bytes[index].is_ascii_hexdigit())
}

fn clean_recipients(recipients: Vec<Recipient>) -> Result<Vec<Recipient>, Error> {
    let people: Vec<Recipient> = recipients
        .into_iter()
        .map(|person| Recipient { name: person.name.trim().to_owned(), email: person.email.trim().to_owned() })
        .collect();
    if people.is_empty() || people.iter().any(|person| person.name.is_empty() || !valid_email(&person.email)) {
        return Err(Error::invalid("Each recipient needs a name and an email."));
    }
    Ok(people)
}

fn decode_envelope(body: &Value) -> Envelope {
    let Some(mut record) = as_map(body).cloned() else {
        return empty_envelope();
    };
    if let Some(nested) = record.get("envelope").and_then(as_map).cloned() {
        record = nested;
    }
    Envelope {
        name: record.get("name").map(as_str).unwrap_or_default(),
        uid: record.get("uid").map(as_str).unwrap_or_default(),
        display_name: first_string(&record, &["display_name", "displayName"]),
        description: record.get("description").map(as_str).unwrap_or_default(),
        progress_status: first_string(&record, &["progress_status", "progressStatus"]),
        state: record.get("state").map(as_str).unwrap_or_default(),
        condition: record.get("condition").map(as_str).unwrap_or_default(),
        sent_time: first_string(&record, &["sent_time", "sentTime"]),
        documents: record.get("documents").and_then(|item| item.as_array()).map(|items| items.iter().filter_map(|item| item.as_object().cloned()).collect()).unwrap_or_default(),
        compliance: record.get("compliance").and_then(|item| item.as_object().cloned()),
        progress: record.get("progress").and_then(|item| item.as_object().cloned()),
    }
}

fn empty_envelope() -> Envelope {
    Envelope {
        name: String::new(),
        uid: String::new(),
        display_name: String::new(),
        description: String::new(),
        progress_status: String::new(),
        state: String::new(),
        condition: String::new(),
        sent_time: String::new(),
        documents: Vec::new(),
        compliance: None,
        progress: None,
    }
}

fn created_envelope(body: &Value) -> Envelope {
    let mut envelope = decode_envelope(body);
    if let Some(name) = envelope_name_of(body) {
        envelope.name = name;
    } else if envelope.name.is_empty() && !envelope.uid.is_empty() {
        envelope.name = format!("envelopes/{}", envelope.uid);
    }
    envelope
}

fn envelope_name_of(body: &Value) -> Option<String> {
    let record = as_map(body)?;
    let nested = record.get("envelope").and_then(as_map);
    let mut name = nested.and_then(|item| item.get("name")).map(as_str).unwrap_or_default();
    if name.is_empty() {
        name = record.get("name").map(as_str).unwrap_or_default();
    }
    if name.starts_with("envelopes/") {
        return Some(name);
    }
    let mut uid = nested.and_then(|item| item.get("uid")).map(as_str).unwrap_or_default();
    if uid.is_empty() {
        uid = record.get("uid").map(as_str).unwrap_or_default();
    }
    if uid.is_empty() {
        None
    } else {
        Some(format!("envelopes/{uid}"))
    }
}

fn envelope_state(envelope: &Envelope) -> String {
    if let Some(progress) = &envelope.progress {
        if let Some(state) = progress.get("state") {
            let text = as_str(state);
            if !text.is_empty() {
                return text;
            }
        }
    }
    if !envelope.progress_status.is_empty() {
        return envelope.progress_status.clone();
    }
    if !envelope.state.is_empty() {
        return envelope.state.clone();
    }
    envelope.condition.clone()
}

fn decode_webhook(body: &Value, drop_secret: bool) -> WebhookUrl {
    let mut record = as_map(body).cloned().unwrap_or_default();
    if drop_secret {
        record.remove("signing_secret");
        record.remove("signingSecret");
    }
    let events = record
        .get("events")
        .and_then(|item| item.as_array())
        .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_owned)).filter(|item| !item.is_empty()).collect())
        .unwrap_or_default();
    WebhookUrl {
        name: record.get("name").map(as_str).unwrap_or_default(),
        display_name: first_string(&record, &["displayName", "display_name"]),
        http_request_uri: first_string(&record, &["httpRequestUri", "http_request_uri"]),
        events,
        signing_secret: signing_secret(&record),
    }
}

fn signing_secret(record: &Map<String, Value>) -> String {
    let snake = record.get("signing_secret").map(as_str).unwrap_or_default();
    if !snake.is_empty() {
        return snake;
    }
    record.get("signingSecret").map(as_str).unwrap_or_default()
}

fn decode_delivery(body: &Value) -> WebhookDelivery {
    let record = as_map(body);
    WebhookDelivery {
        name: record.and_then(|item| item.get("name")).map(as_str).unwrap_or_default(),
        event: record.and_then(|item| item.get("event")).map(as_str).unwrap_or_default(),
    }
}

fn find_storage(body: &Value) -> Option<(String, String, String)> {
    if let Some(record) = as_map(body) {
        if let Some(list) = record.get("storages") {
            if let Some(found) = find_storage(list) {
                return Some(found);
            }
        }
    }
    find_storage_walk(body)
}

fn find_storage_walk(body: &Value) -> Option<(String, String, String)> {
    match body {
        Value::Object(record) => {
            let raw_url = first_string(record, &["pre_signed_url", "preSignedUrl"]);
            let name = record.get("name").map(as_str).unwrap_or_default();
            let id = name.rsplit_once('/').map(|(_, item)| item.to_owned()).unwrap_or_else(|| name.clone());
            if name.starts_with("storages/") && is_loose_uuid(&id) && !raw_url.is_empty() {
                return Some((name, id, raw_url));
            }
            for (key, child) in record {
                if key == "storages" {
                    continue;
                }
                if let Some(found) = find_storage_walk(child) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(find_storage_walk),
        _ => None,
    }
}

