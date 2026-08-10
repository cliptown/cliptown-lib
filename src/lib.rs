//! Transport-neutral domain types and policy invariants shared by ClipTown.
//!
//! The crate owns deterministic, side-effect-free policy that should behave the
//! same in servers, CLIs, desktop applications, and SDKs. Concrete database,
//! network, UI, cryptographic-key, token-verification, and operating-system
//! adapters remain in their owning repositories.

#![forbid(unsafe_code)]

pub mod api;
pub mod contract;
pub mod convergence;
pub mod crypto;
mod delegation;
mod error;
mod model;
mod policy;
mod ports;
pub mod search;
mod transfer;

/// Canonical versioned ClipTown wire contracts pinned by this crate.
pub use cliptown_interfaces_rust as interfaces;

pub use delegation::{
    AuthorizedSubject, CLIPTOWN_API_AUDIENCE, DelegatedClaims, DelegationError, DelegationPolicy,
    LOA2_ASSURANCE_CONTEXT, MEMEBANK_CLIENT_ID, MEMEBANK_DELETE_SCOPE, MEMEBANK_READ_SCOPE,
    MEMEBANK_WRITE_SCOPE, Operation, authorize_delegated_operation,
};
pub use error::ValidationError;
pub use model::{
    ApplicationId, ClipId, ClipKind, ContentHash, DeviceId, EncryptedClip, EncryptedClipInput,
    EncryptedVaultRecord, EncryptedVaultRecordInput, SyncCursor, SyncPage, VaultRecordId,
};
pub use policy::{ClipboardCapability, DataDomain, RetentionPolicy};
pub use ports::{ClipStore, SyncTransport, VaultStore};
pub use transfer::{
    AcknowledgementDisposition, IdempotencyBinding, IdempotencyDecision, IdempotencyError,
    IdempotentOperation, TransferState, TransferTransitionError, acknowledge_transfer,
    cancel_transfer, effective_state, evaluate_idempotency,
};
