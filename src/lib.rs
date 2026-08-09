//! Shared transport-neutral domain and application-policy primitives for ClipTown.
//!
//! Concrete database, HTTP, UI, key-store, and cryptographic implementations
//! live behind the ports exposed here. Service adapters also verify credentials
//! through shared-auth before passing normalized claims into the fail-closed
//! delegated-authorization policy.

#![forbid(unsafe_code)]

pub mod delegation;
pub mod error;
pub mod model;
pub mod policy;
pub mod ports;
pub mod transfer;

pub use delegation::{
    AuthorizedSubject, CLIPTOWN_API_AUDIENCE, DelegatedClaims, DelegationError,
    DelegationPolicy, LOA2_ASSURANCE_CONTEXT, MEMEBANK_CLIENT_ID, MEMEBANK_DELETE_SCOPE,
    MEMEBANK_READ_SCOPE, MEMEBANK_WRITE_SCOPE, Operation, authorize_delegated_operation,
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
