//! Dependency-inversion ports implemented by concrete ClipTown adapters.

use std::error::Error;

use crate::{
    ApplicationId, ClipId, EncryptedClip, EncryptedVaultRecord, SyncCursor,
    SyncPage, VaultRecordId,
};

/// Persistence operations for ordinary encrypted clipboard history.
pub trait ClipStore: Send + Sync {
    /// Adapter-specific failure type.
    type Error: Error + Send + Sync + 'static;

    /// Stores one encrypted clipboard revision idempotently.
    ///
    /// # Errors
    ///
    /// Returns the adapter's error when persistence fails.
    fn put_clip(&self, clip: &EncryptedClip) -> Result<(), Self::Error>;

    /// Loads a bounded page strictly after `cursor`.
    ///
    /// # Errors
    ///
    /// Returns the adapter's error when the page cannot be loaded.
    fn load_clips_since(
        &self,
        cursor: SyncCursor,
        limit: usize,
    ) -> Result<SyncPage, Self::Error>;

    /// Deletes one encrypted clipboard record if it exists.
    ///
    /// # Errors
    ///
    /// Returns the adapter's error when deletion cannot be completed.
    fn delete_clip(&self, id: &ClipId) -> Result<bool, Self::Error>;
}

/// Persistence operations reserved for opaque application-vault ciphertext.
///
/// Keeping this separate from [`ClipStore`] prevents vault records from entering
/// clipboard retention, preview, search, paste, export, or notification paths.
pub trait VaultStore: Send + Sync {
    /// Adapter-specific failure type.
    type Error: Error + Send + Sync + 'static;

    /// Stores one encrypted application-vault revision idempotently.
    ///
    /// # Errors
    ///
    /// Returns the adapter's error when persistence fails.
    fn put_vault_record(&self, record: &EncryptedVaultRecord) -> Result<(), Self::Error>;

    /// Loads one opaque vault record for its owning application.
    ///
    /// # Errors
    ///
    /// Returns the adapter's error when the record cannot be loaded.
    fn load_vault_record(
        &self,
        application_id: &ApplicationId,
        record_id: &VaultRecordId,
    ) -> Result<Option<EncryptedVaultRecord>, Self::Error>;

    /// Deletes one opaque vault record if it exists.
    ///
    /// # Errors
    ///
    /// Returns the adapter's error when deletion cannot be completed.
    fn delete_vault_record(
        &self,
        application_id: &ApplicationId,
        record_id: &VaultRecordId,
    ) -> Result<bool, Self::Error>;
}

/// Remote transport for encrypted clipboard pages.
///
/// Implementations may use HTTP, WebSocket, peer-to-peer delivery, or another
/// reviewed transport, but they must not receive plaintext or private keys.
pub trait SyncTransport: Send + Sync {
    /// Adapter-specific failure type.
    type Error: Error + Send + Sync + 'static;

    /// Pushes encrypted clipboard revisions and returns the acknowledged cursor.
    ///
    /// # Errors
    ///
    /// Returns the adapter's error when the remote endpoint rejects or cannot
    /// acknowledge the batch.
    fn push_clips(
        &self,
        clips: &[EncryptedClip],
        base_cursor: SyncCursor,
    ) -> Result<SyncCursor, Self::Error>;

    /// Pulls a bounded encrypted page strictly after `cursor`.
    ///
    /// # Errors
    ///
    /// Returns the adapter's error when the remote page cannot be retrieved.
    fn pull_clips(
        &self,
        cursor: SyncCursor,
        limit: usize,
    ) -> Result<SyncPage, Self::Error>;
}
