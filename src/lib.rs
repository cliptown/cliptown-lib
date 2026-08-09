//! Transport-neutral domain types and policy invariants shared by ClipTown.
//!
//! The crate intentionally contains no concrete database, network, UI, or
//! cryptographic implementation. Those details live behind the ports exposed
//! here so applications cannot accidentally weaken the clipboard/application-
//! vault separation.

#![forbid(unsafe_code)]

mod error;
mod model;
mod policy;
mod ports;

pub use error::ValidationError;
pub use model::{
    ApplicationId, ClipId, ClipKind, ContentHash, DeviceId, EncryptedClip,
    EncryptedClipInput, EncryptedVaultRecord, EncryptedVaultRecordInput,
    SyncCursor, SyncPage, VaultRecordId,
};
pub use policy::{ClipboardCapability, DataDomain, RetentionPolicy};
pub use ports::{ClipStore, SyncTransport, VaultStore};
