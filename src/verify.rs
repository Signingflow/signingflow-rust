use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::Error;

type HmacSha256 = Hmac<Sha256>;

/// Previous webhook secret during a rotation grace window.
#[derive(Debug, Clone, Default)]
pub struct ConstructOptions {
    pub previous_secret: String,
    pub previous_signature: String,
}

/// A verified webhook. `body_sha256` is the SHA-256 of the raw bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub payload: Value,
    pub body_sha256: String,
}

/// Checks the HMAC of the raw body, then parses JSON.
///
/// Compare `X-Signingflow-Signature` or `X-Webhook-Signature`. Pass the previous
/// header only together with the previous secret. There is no timestamp.
pub fn construct_event(payload: &[u8], signature: &str, secret: &str, options: ConstructOptions) -> Result<Event, Error> {
    if secret.is_empty() {
        return Err(Error::signature("Webhook secret is required."));
    }
    let current = !signature.is_empty() && constant_hex(signature, &mac(secret, payload));
    let previous = !options.previous_secret.is_empty()
        && !options.previous_signature.is_empty()
        && constant_hex(&options.previous_signature, &mac(&options.previous_secret, payload));
    if !current && !previous {
        return Err(Error::signature("Webhook signature did not match."));
    }
    let payload_json: Value = serde_json::from_slice(payload).map_err(|_| Error::invalid("The webhook body is not JSON."))?;
    Ok(Event { payload: payload_json, body_sha256: hex(&Sha256::digest(payload)) })
}

fn mac(secret: &str, body: &[u8]) -> Vec<u8> {
    let mut hasher = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    hasher.update(body);
    hasher.finalize().into_bytes().to_vec()
}

fn constant_hex(given: &str, expected: &[u8]) -> bool {
    let given = given.trim().to_ascii_lowercase();
    let expected = hex(expected);
    let mut diff = u8::from(given.len() != expected.len());
    let length = given.len().max(expected.len());
    let given_bytes = given.as_bytes();
    let expected_bytes = expected.as_bytes();
    for index in 0..length {
        let left = given_bytes.get(index).copied().unwrap_or(0);
        let right = expected_bytes.get(index).copied().unwrap_or(0);
        diff |= left ^ right;
    }
    diff == 0
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
