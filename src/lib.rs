//! Transport-neutral domain types and policy invariants shared by ClipTown.
//!
//! The crate intentionally contains no concrete database, network, UI, token-
//! verification, or cryptographic implementation. Those details live behind
//! adapters and ports so applications cannot weaken the clipboard/application-
//! vault separation or delegated product authorization.

#![forbid(unsafe_code)]

mod delegation;
mod error;
mod model;
mod policy;
mod ports;
mod transfer;

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
