//! Validated transport-neutral domain records.

use std::fmt::{self, Display, Formatter};

use crate::{DataDomain, ValidationError};

/// Stable identifier for one encrypted clipboard record.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClipId(String);

impl ClipId {
    /// Parses and trims a non-empty clipboard identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyIdentifier`] when the value is blank.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        parse_identifier(value, "clip_id").map(Self)
    }

    /// Returns the validated identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ClipId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable identifier for one authenticated ClipTown device.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(String);

impl DeviceId {
    /// Parses and trims a non-empty device identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyIdentifier`] when the value is blank.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        parse_identifier(value, "device_id").map(Self)
    }

    /// Returns the validated identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for DeviceId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable identifier for a product using the isolated application vault.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApplicationId(String);

impl ApplicationId {
    /// Parses and trims a non-empty application identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyIdentifier`] when the value is blank.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        parse_identifier(value, "application_id").map(Self)
    }

    /// Returns the validated identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ApplicationId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable identifier for one opaque application-vault record.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VaultRecordId(String);

impl VaultRecordId {
    /// Parses and trims a non-empty vault-record identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyIdentifier`] when the value is blank.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        parse_identifier(value, "vault_record_id").map(Self)
    }

    /// Returns the validated identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for VaultRecordId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn parse_identifier(
    value: impl Into<String>,
    field: &'static str,
) -> Result<String, ValidationError> {
    let value = value.into();
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::EmptyIdentifier { field });
    }
    Ok(value.to_owned())
}

/// A fixed-size digest of the plaintext, computed on a trusted device.
///
/// The digest supports integrity and deduplication decisions but does not imply
/// a particular hashing algorithm at this layer; the versioned interface
/// contract owns that selection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Wraps exactly 32 digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// User-visible representation carried by an encrypted clipboard record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipKind {
    /// UTF-8 or another contract-declared text representation.
    Text,
    /// Encoded image data.
    Image,
    /// File or file-manifest data.
    File,
    /// Sanitized HTML representation paired with safe fallbacks.
    Html,
    /// Contract-versioned custom representation.
    Custom,
}

/// Validated inputs used to construct an [`EncryptedClip`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedClipInput {
    /// Stable clip identifier.
    pub id: ClipId,
    /// Device that authored this revision.
    pub origin_device: DeviceId,
    /// User-visible clip representation.
    pub kind: ClipKind,
    /// Authenticated ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// Device-computed content digest.
    pub content_hash: ContentHash,
    /// Creation timestamp expressed as Unix epoch milliseconds.
    pub created_at_unix_ms: u64,
    /// Monotonic logical revision for conflict resolution.
    pub logical_revision: u64,
}

/// An encrypted record in ordinary clipboard history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedClip {
    id: ClipId,
    origin_device: DeviceId,
    kind: ClipKind,
    ciphertext: Vec<u8>,
    content_hash: ContentHash,
    created_at_unix_ms: u64,
    logical_revision: u64,
}

impl EncryptedClip {
    /// Constructs an encrypted clipboard record.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyCiphertext`] when no ciphertext bytes
    /// are supplied.
    pub fn from_input(input: EncryptedClipInput) -> Result<Self, ValidationError> {
        if input.ciphertext.is_empty() {
            return Err(ValidationError::EmptyCiphertext);
        }
        Ok(Self {
            id: input.id,
            origin_device: input.origin_device,
            kind: input.kind,
            ciphertext: input.ciphertext,
            content_hash: input.content_hash,
            created_at_unix_ms: input.created_at_unix_ms,
            logical_revision: input.logical_revision,
        })
    }

    /// Returns the stable clip identifier.
    #[must_use]
    pub fn id(&self) -> &ClipId {
        &self.id
    }

    /// Returns the authoring device.
    #[must_use]
    pub fn origin_device(&self) -> &DeviceId {
        &self.origin_device
    }

    /// Returns the user-visible representation kind.
    #[must_use]
    pub const fn kind(&self) -> ClipKind {
        self.kind
    }

    /// Returns the authenticated ciphertext bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the device-computed content digest.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the creation timestamp as Unix epoch milliseconds.
    #[must_use]
    pub const fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }

    /// Returns the logical revision.
    #[must_use]
    pub const fn logical_revision(&self) -> u64 {
        self.logical_revision
    }

    /// Returns the record's immutable trust domain.
    #[must_use]
    pub const fn domain(&self) -> DataDomain {
        DataDomain::Clipboard
    }
}

/// Validated inputs used to construct an [`EncryptedVaultRecord`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedVaultRecordInput {
    /// Stable record identifier within the owning application.
    pub id: VaultRecordId,
    /// Product that owns and interprets the opaque ciphertext.
    pub application_id: ApplicationId,
    /// Device that authored this revision.
    pub origin_device: DeviceId,
    /// Authenticated ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// Device-computed content digest.
    pub content_hash: ContentHash,
    /// Monotonic logical revision for conflict resolution.
    pub logical_revision: u64,
}

/// Opaque encrypted product data that must never become clipboard history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedVaultRecord {
    id: VaultRecordId,
    application_id: ApplicationId,
    origin_device: DeviceId,
    ciphertext: Vec<u8>,
    content_hash: ContentHash,
    logical_revision: u64,
}

impl EncryptedVaultRecord {
    /// Constructs an isolated application-vault record.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyCiphertext`] when no ciphertext bytes
    /// are supplied.
    pub fn from_input(input: EncryptedVaultRecordInput) -> Result<Self, ValidationError> {
        if input.ciphertext.is_empty() {
            return Err(ValidationError::EmptyCiphertext);
        }
        Ok(Self {
            id: input.id,
            application_id: input.application_id,
            origin_device: input.origin_device,
            ciphertext: input.ciphertext,
            content_hash: input.content_hash,
            logical_revision: input.logical_revision,
        })
    }

    /// Returns the stable vault-record identifier.
    #[must_use]
    pub fn id(&self) -> &VaultRecordId {
        &self.id
    }

    /// Returns the application that owns the record.
    #[must_use]
    pub fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    /// Returns the authoring device.
    #[must_use]
    pub fn origin_device(&self) -> &DeviceId {
        &self.origin_device
    }

    /// Returns the authenticated ciphertext bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the device-computed content digest.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the logical revision.
    #[must_use]
    pub const fn logical_revision(&self) -> u64 {
        self.logical_revision
    }

    /// Returns the record's immutable trust domain.
    #[must_use]
    pub const fn domain(&self) -> DataDomain {
        DataDomain::ApplicationVault
    }
}

/// Monotonic position in a device or account sync stream.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct SyncCursor(u64);

impl SyncCursor {
    /// Returns the initial cursor before any records have been observed.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Returns the raw monotonic cursor value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Advances to a cursor at or beyond the current value.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::CursorRegression`] when `proposed` is less
    /// than the current value.
    pub const fn advance_to(self, proposed: u64) -> Result<Self, ValidationError> {
        if proposed < self.0 {
            return Err(ValidationError::CursorRegression {
                current: self.0,
                proposed,
            });
        }
        Ok(Self(proposed))
    }
}

/// One bounded page of encrypted clipboard records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncPage {
    records: Vec<EncryptedClip>,
    next_cursor: SyncCursor,
}

impl SyncPage {
    /// Creates a page whose cursor represents all included records.
    #[must_use]
    pub fn from_records(records: Vec<EncryptedClip>, next_cursor: SyncCursor) -> Self {
        Self {
            records,
            next_cursor,
        }
    }

    /// Returns the encrypted records in server order.
    #[must_use]
    pub fn records(&self) -> &[EncryptedClip] {
        &self.records
    }

    /// Returns whether this page contains no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the cursor to persist after processing the page.
    #[must_use]
    pub const fn next_cursor(&self) -> SyncCursor {
        self.next_cursor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clip_input(ciphertext: Vec<u8>) -> EncryptedClipInput {
        EncryptedClipInput {
            id: ClipId::parse(" clip-1 ").expect("valid clip id"),
            origin_device: DeviceId::parse("device-1").expect("valid device id"),
            kind: ClipKind::Text,
            ciphertext,
            content_hash: ContentHash::from_bytes([7; 32]),
            created_at_unix_ms: 123,
            logical_revision: 4,
        }
    }

    #[test]
    fn identifiers_are_trimmed_and_blank_values_are_rejected() {
        let identifier = ClipId::parse(" clip-1 ").expect("valid identifier");
        assert_eq!(identifier.as_str(), "clip-1");
        assert_eq!(
            DeviceId::parse("  "),
            Err(ValidationError::EmptyIdentifier { field: "device_id" })
        );
    }

    #[test]
    fn encrypted_clip_rejects_empty_ciphertext() {
        assert_eq!(
            EncryptedClip::from_input(clip_input(Vec::new())),
            Err(ValidationError::EmptyCiphertext)
        );
    }

    #[test]
    fn sync_cursor_is_monotonic() {
        let cursor = SyncCursor::initial().advance_to(9).expect("advance cursor");
        assert_eq!(cursor.value(), 9);
        assert_eq!(
            cursor.advance_to(8),
            Err(ValidationError::CursorRegression {
                current: 9,
                proposed: 8
            })
        );
    }

    #[test]
    fn record_types_keep_their_domains() {
        let clip = EncryptedClip::from_input(clip_input(vec![1])).expect("valid clip");
        assert_eq!(clip.domain(), DataDomain::Clipboard);

        let vault = EncryptedVaultRecord::from_input(EncryptedVaultRecordInput {
            id: VaultRecordId::parse("record-1").expect("valid record id"),
            application_id: ApplicationId::parse("3fa").expect("valid application id"),
            origin_device: DeviceId::parse("device-1").expect("valid device id"),
            ciphertext: vec![2],
            content_hash: ContentHash::from_bytes([8; 32]),
            logical_revision: 1,
        })
        .expect("valid vault record");
        assert_eq!(vault.domain(), DataDomain::ApplicationVault);
    }
}
