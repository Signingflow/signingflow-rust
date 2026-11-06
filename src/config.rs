use std::time::Duration;

use crate::error::Error;
use crate::pathutil::{bad_header, host_of, raw_authority};

/// Sandbox or live. The client always sends `X-Request-Env`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Env {
    Sandbox,
    Live,
}

impl Env {
    pub(crate) fn wire(self) -> &'static str {
        match self {
            Self::Sandbox => "SANDBOX",
            Self::Live => "LIVE",
        }
    }
}

/// Settings for [`crate::Client::new`]. The API key is a separate argument.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub(crate) workspace_id: String,
    pub(crate) env: Env,
    pub(crate) base_url: Option<String>,
    pub(crate) allow_custom_base_url: bool,
    pub(crate) timeout: Option<Duration>,
    pub(crate) max_network_retries: Option<u32>,
    pub(crate) channel: Option<String>,
    pub(crate) funnel: Option<String>,
    pub(crate) upload_hosts: Option<Vec<String>>,
    pub(crate) upload_root: Option<String>,
    pub(crate) ca_pem: Option<String>,
}

impl ClientOptions {
    pub fn new(workspace_id: impl Into<String>, env: Env) -> Self {
        Self {
            workspace_id: workspace_id.into(),
            env,
            base_url: None,
            allow_custom_base_url: false,
            timeout: None,
            max_network_retries: None,
            channel: None,
            funnel: None,
            upload_hosts: None,
            upload_root: None,
            ca_pem: None,
        }
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Permits a non-official HTTPS host. The API key is sent to that host.
    pub fn allow_custom_base_url(mut self) -> Self {
        self.allow_custom_base_url = true;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn max_network_retries(mut self, retries: u32) -> Self {
        self.max_network_retries = Some(retries);
        self
    }

    pub fn channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    pub fn funnel(mut self, funnel: impl Into<String>) -> Self {
        self.funnel = Some(funnel.into());
        self
    }

    pub fn upload_hosts(mut self, hosts: Vec<String>) -> Self {
        self.upload_hosts = Some(hosts);
        self
    }

    /// The only directory a `path` argument may be read from.
    pub fn upload_root(mut self, root: impl Into<String>) -> Self {
        self.upload_root = Some(root.into());
        self
    }

    /// PEM certificates added to the trust store. When set, the default public roots are not used.
    pub fn ca_pem(mut self, pem: impl Into<String>) -> Self {
        self.ca_pem = Some(pem.into());
        self
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Resolved {
    pub api_key: String,
    pub workspace_id: String,
    pub wire_env: String,
    pub base_url: String,
    pub timeout: Duration,
    pub retries: u32,
    pub channel: String,
    pub funnel: String,
    pub upload_hosts: Vec<String>,
    pub upload_root: String,
    pub ca_pem: String,
}

const OFFICIAL_HOST: &str = "api.signingflow.com";

pub(crate) fn resolve(api_key: String, options: ClientOptions) -> Result<Resolved, Error> {
    let api_key = api_key.trim().to_owned();
    if api_key.is_empty() {
        return Err(Error::invalid("API key is required."));
    }
    let workspace_id = options.workspace_id.trim().to_owned();
    if workspace_id.is_empty() {
        return Err(Error::invalid("workspaceId is required."));
    }
    let mut base = options.base_url.unwrap_or_else(|| "https://api.signingflow.com".to_owned());
    base = base.trim().trim_end_matches('/').to_owned();
    if base.contains('\0') {
        return Err(Error::invalid("baseUrl must be an absolute URL."));
    }
    let authority = raw_authority(&base)?;
    if authority.contains('@') {
        return Err(Error::invalid("baseUrl must not include a username or password."));
    }
    let host = host_of(authority)?;
    if !base.starts_with("https://") {
        return Err(Error::invalid("baseUrl must be https."));
    }
    if host != OFFICIAL_HOST && !options.allow_custom_base_url {
        return Err(Error::invalid("baseUrl host must be api.signingflow.com, or set allowCustomBaseUrl."));
    }
    let timeout = options.timeout.unwrap_or(Duration::from_secs(30));
    if timeout.is_zero() {
        return Err(Error::invalid("timeout must be positive."));
    }
    let channel = options.channel.unwrap_or_default().trim().to_owned();
    let funnel = options.funnel.unwrap_or_default().trim().to_owned();
    if bad_header(&api_key) || bad_header(&workspace_id) || bad_header(&channel) || bad_header(&funnel) {
        return Err(Error::invalid("invalid header value"));
    }
    Ok(Resolved {
        api_key,
        workspace_id,
        wire_env: options.env.wire().to_owned(),
        base_url: base,
        timeout,
        retries: options.max_network_retries.unwrap_or(2),
        channel,
        funnel,
        upload_hosts: upload_hosts(options.upload_hosts)?,
        upload_root: options.upload_root.unwrap_or_default().trim().to_owned(),
        ca_pem: options.ca_pem.unwrap_or_default(),
    })
}

fn upload_hosts(hosts: Option<Vec<String>>) -> Result<Vec<String>, Error> {
    let hosts = hosts.unwrap_or_else(|| vec!["storage.googleapis.com".to_owned()]);
    let mut list = Vec::new();
    for host in hosts {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            continue;
        }
        let dots = host.matches('.').count();
        if dots < 2 || host.starts_with('.') || host.ends_with('.') || host.contains("..") {
            return Err(Error::invalid("Each uploadHosts entry must be a specific host, not a public suffix."));
        }
        list.push(host);
    }
    Ok(list)
}
