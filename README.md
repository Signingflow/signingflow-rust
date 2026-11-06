# signingflow

[![CI](https://github.com/Signingflow/signingflow-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/Signingflow/signingflow-rust/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FSigningflow%2Fsigningflow-rust%2Fbadges%2Fcoverage.json)](https://github.com/Signingflow/signingflow-rust/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Rust SDK for the Signingflow calls used to send a document, read envelope status, and receive webhooks.

The crate talks to `https://api.signingflow.com`. Keep the API key on your server. Rust 1.85 or newer is required.

```bash
cargo add --git https://github.com/Signingflow/signingflow-rust
```

Install it from [GitHub](https://github.com/Signingflow/signingflow-rust) until a version is published to crates.io.

```rust
let client = signingflow::Client::new(
    std::env::var("SIGNINGFLOW_API_KEY").expect("api key"),
    signingflow::ClientOptions::new(std::env::var("SIGNINGFLOW_WORKSPACE_ID").expect("workspace"), signingflow::Env::Sandbox),
)?;

let envelope = client.envelopes.send_document(signingflow::SendDocumentParams {
    title: "NDA".into(),
    file: Some(pdf_bytes),
    filename: "contract.pdf".into(),
    recipients: vec![signingflow::Recipient { name: "Ada Lovelace".into(), email: "ada@example.com".into() }],
    message: "Please sign".into(),
    ..signingflow::SendDocumentParams::default()
})?;
```

`file` is the raw bytes. A disk path is `path`, and it is read only from `upload_root`. That directory must be one this process writes. The open refuses a symlink, a hard link, a FIFO, and a path that leaves the directory. A FIFO is refused without waiting for a writer. If this operating system cannot open a path without following a symlink, the read is refused. Do not pass a path from a request field.

`Env` is `Sandbox` or `Live`. The client always sends `X-Request-Env`. A missing environment header is treated as live by the API, so the client rejects a missing environment.

`base_url` must be `https`. The host is `api.signingflow.com` unless `allow_custom_base_url` is set. A username or password on the URL is rejected. There is no process-wide API key.

The client sends `Accept-Encoding: identity`, does not follow redirects, and stops reading once an API response passes 8 MB.

## Send and read

`envelopes.prepare_draft` stores one PDF and creates a draft. It does not email anyone.

`envelopes.send_document` stores the PDF, creates the draft, adds the recipients to the first document, and sends. `envelopes.send_from_template` starts from `templates/{id}`.

If update or send fails, the error includes `envelope_name` for the draft that was saved. After a timeout, the client returns the envelope only when `sent_time` is within two minutes after the call started and not more than a minute ahead of this clock. An older or far-future timestamp is an error.

`envelopes.list` with `directory: "needAction"` or `"waitingOthers"` reads pages of 10. `page_size` can be from 1 to 1000. Iteration walks later pages and stops after 100 follow-up pages or a repeated token.

`envelopes.download_completed` reads the envelope first. It requests the download URL only when the state is `COMPLETED`. The download call returns `uri`, `download_time`, and `etag`. This client does not GET `uri`. Treat that URL as untrusted until your application checks the host. Do not send the API key to it.

`envelopes.remind` notifies people who can still sign. The call is not idempotent.

## Idempotency

Creates and sends send a UUID `idempotencyKey` in the JSON body. The same key is stored for the whole environment. A repeat returns HTTP 409 and does not return the original resource. The SDK returns `ErrorKind::Idempotency` with `resource_name` when the error includes one. It does not treat that response as success.

Pass the same idempotency key only to retry one request after a timeout. `update` and `remind` are not retried automatically.

## Webhooks

```rust
let destination = client.webhook_urls.create(signingflow::WebhookUrlCreateParams {
    display_name: "Envelope events".into(),
    http_request_uri: "https://example.com/webhooks/signingflow".into(),
    events: vec!["DOC_ENVELOPE_COMPLETED".into()],
    ..signingflow::WebhookUrlCreateParams::default()
})?;
```

Store `destination.signing_secret` from that response. A later `retrieve` does not include it. Do not set `http_config`. `auth: "NONE"` is rejected.

```rust
let event = signingflow::construct_event(raw_body, signature_header, secret, signingflow::ConstructOptions {
    previous_secret,
    previous_signature,
})?;
```

The signature is lowercase hex HMAC-SHA256 of the raw body. There is no timestamp. Compare `X-Signingflow-Signature` or `X-Webhook-Signature`. During a grace window, also pass the previous header and secret. Parse JSON only after the MAC matches. `body_sha256` is the SHA-256 of those raw bytes. Store it and reject a delivery you have already seen. Do not hash a re-serialized body. A captured request stays valid until you record that hash or the secret rotates.

## Errors

Match `error.kind()`.

| Kind | When |
| --- | --- |
| `Authentication` | HTTP 401 |
| `Permission` | HTTP 403 |
| `Idempotency` | HTTP 409 whose body says the key was already used |
| `RateLimit` | HTTP 429 |
| `InvalidRequest` | A rejected argument |
| `Api` | HTTP 5xx, or a body the client will not parse |
| `Connection` | The API was not reached, including a timeout |
| `Signature` | A webhook MAC did not match |
