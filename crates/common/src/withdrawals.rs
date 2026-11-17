//! The withdrawal list: which published releases the updater must not offer.
//!
//! The list is `static/hole.yaml` on `main`, a signed envelope:
//!
//! ```yaml
//! payload: |
//!   withdrawn:
//!     - version: 0.7.0
//!       platforms: [windows-amd64]
//!       reason: Uninstalling from Settings fails and rolls back.
//!       url: https://github.com/bindreams/hole/issues/1342
//! signatures:
//!   - |
//!     <the lines minisign writes>
//! ```
//!
//! Each signature covers the exact string the YAML parser returns for `payload`; the list is valid for a
//! client when at least one of them verifies under its key; entries that do not verify belong to another
//! key (a signing-key rotation signs with both). Keys this client
//! does not know are ignored, so the list can grow without breaking a shipped client. A list that cannot be
//! read is an error, never an empty list: the file always exists.

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::verify::{verify_minisig_data, VerifyError, MINISIGN_PUBLIC_KEY};
use crate::version::ReleaseVersion;

// Platforms ===========================================================================================================

/// The release platform ids, the names a withdrawal's `platforms` and the release assets use. The client
/// and the signing tool share this list: an app build names its own id through it and the tool refuses any
/// other. The release staging (`xtask_lib::asset::update_asset_suffix`) builds its own `<os>-<arch>`.
pub const WINDOWS_AMD64: &str = "windows-amd64";
pub const DARWIN_ARM64: &str = "darwin-arm64";
pub const DARWIN_AMD64: &str = "darwin-amd64";
pub const PLATFORM_IDS: [&str; 3] = [WINDOWS_AMD64, DARWIN_ARM64, DARWIN_AMD64];

// Keys ================================================================================================================

/// The keys of the payload a client reads. A client ignores any other key, so the list can grow; the
/// signing tool refuses them, since a misspelled key is read as no key.
pub const PAYLOAD_KEYS: &[&str] = &["withdrawn"];

/// The keys of one entry a client reads: see [`PAYLOAD_KEYS`].
pub const ENTRY_KEYS: &[&str] = &["version", "platforms", "reason", "url"];

// Types ===============================================================================================================

/// One withdrawn release.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Withdrawal {
    #[serde(deserialize_with = "release_version")]
    pub version: ReleaseVersion,
    /// The platform ids the withdrawal covers; `None` covers every platform. Plain strings: an id this
    /// build does not know matches nothing.
    #[serde(default)]
    pub platforms: Option<Vec<String>>,
    pub reason: String,
    /// An `https` link to the issue or release page the entry is about.
    #[serde(deserialize_with = "https_url")]
    pub url: String,
}

impl Withdrawal {
    fn covers(&self, platform_id: &str) -> bool {
        self.platforms
            .as_ref()
            .is_none_or(|ids| ids.iter().any(|id| id == platform_id))
    }
}

/// A verified list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Withdrawals {
    entries: Vec<Withdrawal>,
}

impl Withdrawals {
    pub fn new(entries: Vec<Withdrawal>) -> Self {
        Self { entries }
    }

    /// Every entry, in file order.
    pub fn entries(&self) -> &[Withdrawal] {
        &self.entries
    }

    /// The entry withdrawing `version` on the platform `platform_id`, if there is one.
    pub fn for_version(&self, version: &ReleaseVersion, platform_id: &str) -> Option<&Withdrawal> {
        self.entries
            .iter()
            .find(|w| w.version == *version && w.covers(platform_id))
    }
}

/// Why a fetched list is unreadable.
#[derive(Debug, Error)]
pub enum WithdrawalListError {
    #[error("the withdrawal list is not a signed envelope")]
    Envelope(#[source] yaml_serde::Error),
    #[error("the withdrawal list's signature does not verify")]
    Signature(#[source] VerifyError),
    #[error("the withdrawal list's payload is not a list of withdrawals")]
    Payload(#[source] yaml_serde::Error),
}

impl WithdrawalListError {
    /// Whether the list was refused because no signature verifies, as opposed to not being the envelope or
    /// the payload it should be.
    pub fn is_signature_failure(&self) -> bool {
        match self {
            Self::Signature(_) => true,
            Self::Envelope(_) => false,
            Self::Payload(_) => false,
        }
    }
}

// Parsing =============================================================================================================

/// The signed envelope `static/hole.yaml` holds: a payload and the minisign signatures over its exact text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub payload: String,
    /// One `.minisig` text per signing key. A missing key reads as no signatures.
    #[serde(default)]
    pub signatures: Vec<String>,
}

impl Envelope {
    /// The file text. Parsing it with [`parse_envelope`] gives back this envelope.
    pub fn render(&self) -> Result<String, yaml_serde::Error> {
        yaml_serde::to_string(self)
    }
}

#[derive(Deserialize)]
struct Payload {
    withdrawn: Vec<Withdrawal>,
}

fn release_version<'de, D: Deserializer<'de>>(deserializer: D) -> Result<ReleaseVersion, D::Error> {
    let text = String::deserialize(deserializer)?;
    ReleaseVersion::parse(&text).map_err(serde::de::Error::custom)
}

fn https_url<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let text = String::deserialize(deserializer)?;
    if !is_https_url(&text) {
        return Err(serde::de::Error::custom(format!("not an https URL: {text}")));
    }
    Ok(text)
}

/// Whether `text` is an `https` URL with a host: the only kind of link the app hands to the system's
/// opener.
pub fn is_https_url(text: &str) -> bool {
    text.parse::<http::Uri>()
        .is_ok_and(|uri| uri.scheme() == Some(&http::uri::Scheme::HTTPS) && uri.authority().is_some())
}

/// Parse the withdrawal list text, locked to the key embedded in the binary.
pub fn parse_signed(text: &str) -> Result<Withdrawals, WithdrawalListError> {
    parse_signed_with_key(text, MINISIGN_PUBLIC_KEY)
}

/// [`parse_signed`] with the key injectable: tests pass a test key. Production callers use the wrapper.
pub fn parse_signed_with_key(text: &str, public_key: &str) -> Result<Withdrawals, WithdrawalListError> {
    let envelope = parse_envelope(text)?;
    verify_any(&envelope, public_key).map_err(WithdrawalListError::Signature)?;
    parse_payload(&envelope.payload)
}

/// Whether at least one of the envelope's signatures verifies its payload under `public_key`. With none
/// that does, the error is the first signature's.
fn verify_any(envelope: &Envelope, public_key: &str) -> Result<(), VerifyError> {
    let mut first_error = None;
    for signature in &envelope.signatures {
        match verify_minisig_data(envelope.payload.as_bytes(), signature, public_key) {
            Ok(()) => return Ok(()),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error.unwrap_or_else(|| VerifyError::SignatureInvalid("the list carries no signature".to_string())))
}

/// Parse the envelope without checking its signature.
pub fn parse_envelope(text: &str) -> Result<Envelope, WithdrawalListError> {
    yaml_serde::from_str(text).map_err(WithdrawalListError::Envelope)
}

/// Parse a payload without checking any signature. The client calls it after verifying; `sign-static` calls
/// it before signing.
pub fn parse_payload(payload: &str) -> Result<Withdrawals, WithdrawalListError> {
    let payload: Payload = yaml_serde::from_str(payload).map_err(WithdrawalListError::Payload)?;
    Ok(Withdrawals::new(payload.withdrawn))
}

#[cfg(test)]
#[path = "withdrawals_tests.rs"]
mod withdrawals_tests;
