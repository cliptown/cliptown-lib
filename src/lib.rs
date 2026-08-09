#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Shared Rust domain and application primitives for ClipTown.
//!
//! This crate deliberately does not decode or verify bearer tokens. Service
//! adapters must verify credentials through shared-auth and then pass normalized
//! claims into the fail-closed policy functions in [`delegation`].

pub mod delegation;
pub mod transfer;

pub use delegation::{
    authorize_delegated_operation, AuthorizedSubject, DelegatedClaims, DelegationError,
    DelegationPolicy, Operation,
};
pub use transfer::{
    acknowledge_transfer, cancel_transfer, effective_state, evaluate_idempotency,
    AcknowledgementDisposition, IdempotencyBinding, IdempotencyDecision, IdempotencyError,
    IdempotentOperation, TransferState, TransferTransitionError,
};
