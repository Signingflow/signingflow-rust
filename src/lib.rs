//! Official Rust SDK for the Signingflow calls that send a document, read envelope status, and verify webhooks.
//!
//! Create a [`Client`] with an API key. There is no process-wide key.

#![forbid(unsafe_code)]

mod allowlist;
mod api;
mod clock;
mod config;
mod error;
mod jail;
mod page;
mod pathutil;
mod redact;
mod status;
mod transport;
mod verify;

pub use api::{
    Download, Envelope, EnvelopeCreateParams, EnvelopeListParams, FileCreateParams, Files,
    PrepareDraftParams, Recipient, SendDocumentParams, SendFromTemplateParams, StoredFile,
    Templates, WebhookDelivery, WebhookDeliveries, WebhookListParams, WebhookUrl,
    WebhookUrlCreateParams, WebhookUrls,
};
pub use config::{ClientOptions, Env};
pub use error::{Error, ErrorInfo, ErrorKind, FieldViolation};
pub use page::Page;
pub use verify::{construct_event, ConstructOptions, Event};

/// HTTP client for `https://api.signingflow.com`.
///
/// The key is sent only as `Authorization: Bearer`.
pub struct Client {
    pub files: Files,
    pub templates: Templates,
    pub envelopes: api::Envelopes,
    pub webhook_urls: WebhookUrls,
    pub webhook_deliveries: WebhookDeliveries,
}

impl Client {
    /// Checks the API key, workspace, and environment, then builds a client.
    pub fn new(api_key: impl Into<String>, options: ClientOptions) -> Result<Self, Error> {
        let sender = transport::Sender::new(config::resolve(api_key.into(), options)?)?;
        let files = Files::new(sender.clone());
        let templates = Templates::new(sender.clone());
        let envelopes = api::Envelopes::new(sender.clone(), files.clone(), templates.clone());
        Ok(Self {
            files,
            templates,
            envelopes,
            webhook_urls: WebhookUrls::new(sender.clone()),
            webhook_deliveries: WebhookDeliveries::new(sender),
        })
    }
}

pub const VERSION: &str = "0.1.0";
pub(crate) const SOURCE: &str = "signingflow-rust/0.1.0";

#[cfg(test)]
mod sdk_tests;
