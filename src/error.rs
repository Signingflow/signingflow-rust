use std::fmt;

/// One field error from the API, with secrets removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldViolation {
    pub field: String,
    pub description: String,
}

/// Fields shared by every SDK error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorInfo {
    pub message: String,
    pub status_code: u16,
    pub grpc_code: Option<i32>,
    pub trace_code: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub capability: String,
    pub resource_name: String,
    pub envelope_name: String,
    pub retry_after: String,
    pub field_violations: Vec<FieldViolation>,
}

impl ErrorInfo {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status_code: 0,
            grpc_code: None,
            trace_code: String::new(),
            request_id: String::new(),
            idempotency_key: String::new(),
            capability: String::new(),
            resource_name: String::new(),
            envelope_name: String::new(),
            retry_after: String::new(),
            field_violations: Vec::new(),
        }
    }
}

/// Which call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// A rejected caller argument that is not an HTTP status.
    InvalidRequest,
    /// HTTP 401.
    Authentication,
    /// HTTP 403.
    Permission,
    /// HTTP 409 when the body says the key was already used.
    Idempotency,
    /// HTTP 429.
    RateLimit,
    /// HTTP 5xx, or a body the client will not parse.
    Api,
    /// The API was not reached, including a timeout.
    Connection,
    /// A webhook MAC did not match.
    Signature,
}

/// A Signingflow SDK error. Match on [`Error::kind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    pub(crate) info: ErrorInfo,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn info(&self) -> &ErrorInfo {
        &self.info
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self { kind: ErrorKind::InvalidRequest, info: ErrorInfo::new(message) }
    }

    pub(crate) fn api(message: impl Into<String>) -> Self {
        Self { kind: ErrorKind::Api, info: ErrorInfo::new(message) }
    }

    pub(crate) fn connection(message: impl Into<String>, status: u16, key: &str) -> Self {
        let mut info = ErrorInfo::new(message);
        info.status_code = status;
        info.idempotency_key = key.to_owned();
        Self { kind: ErrorKind::Connection, info }
    }

    pub(crate) fn signature(message: impl Into<String>) -> Self {
        Self { kind: ErrorKind::Signature, info: ErrorInfo::new(message) }
    }

    pub(crate) fn with_kind(kind: ErrorKind, info: ErrorInfo) -> Self {
        Self { kind, info }
    }

    pub(crate) fn attach(mut self, envelope_name: &str) -> Self {
        self.info.envelope_name = envelope_name.to_owned();
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.info.message)
    }
}

impl std::error::Error for Error {}
