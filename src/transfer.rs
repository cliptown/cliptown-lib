//! Subject-owned transfer state and digest-bound idempotency primitives.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

/// Durable state of an encrypted cross-product transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    /// Transfer is available for a terminal action.
    Pending,
    /// Recipient imported the transfer.
    Acknowledged,
    /// Recipient intentionally ignored the transfer.
    Ignored,
    /// Recipient rejected the transfer.
    Rejected,
    /// Retention elapsed before a terminal user action.
    Expired,
    /// Sender cancelled a still-pending transfer.
    Cancelled,
}

/// User-mediated acknowledgement outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementDisposition {
    /// Recipient imported the transfer.
    Acknowledged,
    /// Recipient ignored the transfer.
    Ignored,
    /// Recipient rejected the transfer.
    Rejected,
}

impl AcknowledgementDisposition {
    const fn target_state(self) -> TransferState {
        match self {
            Self::Acknowledged => TransferState::Acknowledged,
            Self::Ignored => TransferState::Ignored,
            Self::Rejected => TransferState::Rejected,
        }
    }
}

/// Stable failure returned by a transfer state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferTransitionError {
    /// Clock or retention inputs are invalid.
    InvalidClock,
    /// Retention elapsed before the requested action.
    TransferExpired,
    /// Existing terminal state cannot transition to the requested state.
    InvalidTransition,
}

impl fmt::Display for TransferTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidClock => "invalid_clock",
            Self::TransferExpired => "transfer_expired",
            Self::InvalidTransition => "invalid_transition",
        })
    }
}

impl Error for TransferTransitionError {}

/// Return the externally visible state at a trusted time.
pub fn effective_state(
    now_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    stored_state: TransferState,
) -> Result<TransferState, TransferTransitionError> {
    validate_clock(now_unix_seconds, expires_at_unix_seconds)?;
    if stored_state == TransferState::Pending && expires_at_unix_seconds <= now_unix_seconds {
        return Ok(TransferState::Expired);
    }
    Ok(stored_state)
}

/// Apply an idempotent acknowledgement transition.
pub fn acknowledge_transfer(
    now_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    stored_state: TransferState,
    disposition: AcknowledgementDisposition,
) -> Result<TransferState, TransferTransitionError> {
    let current = effective_state(now_unix_seconds, expires_at_unix_seconds, stored_state)?;
    let target = disposition.target_state();
    if current == TransferState::Expired {
        return Err(TransferTransitionError::TransferExpired);
    }
    if current == target {
        return Ok(current);
    }
    if current != TransferState::Pending {
        return Err(TransferTransitionError::InvalidTransition);
    }
    Ok(target)
}

/// Apply an idempotent sender cancellation transition.
pub fn cancel_transfer(
    now_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    stored_state: TransferState,
) -> Result<TransferState, TransferTransitionError> {
    let current = effective_state(now_unix_seconds, expires_at_unix_seconds, stored_state)?;
    if current == TransferState::Expired {
        return Err(TransferTransitionError::TransferExpired);
    }
    if current == TransferState::Cancelled {
        return Ok(current);
    }
    if current != TransferState::Pending {
        return Err(TransferTransitionError::InvalidTransition);
    }
    Ok(TransferState::Cancelled)
}

/// Operation bound to an idempotency key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotentOperation {
    /// Create a new transfer.
    Create,
    /// Acknowledge an existing transfer.
    Acknowledge,
}

/// Existing idempotency record loaded under the delegated subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdempotencyBinding<'a> {
    /// Delegated resource owner.
    pub subject: &'a str,
    /// Opaque caller-provided key.
    pub key: &'a str,
    /// Bound operation.
    pub operation: IdempotentOperation,
    /// Normalized route without query or fragment.
    pub normalized_route: &'a str,
    /// Canonical request digest encoded as unpadded base64url SHA-256.
    pub request_digest: &'a str,
    /// Time after which this binding can be replaced.
    pub expires_at_unix_seconds: i64,
}

/// Result of evaluating an idempotency key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyDecision {
    /// No active binding exists and a new request may proceed.
    New,
    /// Active binding matches exactly and its stored result should be replayed.
    Replay,
}

/// Stable failure returned by idempotency evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyError {
    /// Request inputs are malformed or unbounded.
    InvalidInput,
    /// Active key is bound to a different request.
    Conflict,
}

impl fmt::Display for IdempotencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid_idempotency_input",
            Self::Conflict => "idempotency_conflict",
        })
    }
}

impl Error for IdempotencyError {}

/// Evaluate a request against an optional existing subject-owned binding.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_idempotency(
    now_unix_seconds: i64,
    existing: Option<IdempotencyBinding<'_>>,
    subject: &str,
    key: &str,
    operation: IdempotentOperation,
    normalized_route: &str,
    request_digest: &str,
) -> Result<IdempotencyDecision, IdempotencyError> {
    if now_unix_seconds < 0
        || !valid_identifier(subject, 256)
        || !valid_key(key)
        || !valid_route(normalized_route)
        || !valid_sha256_base64url(request_digest)
    {
        return Err(IdempotencyError::InvalidInput);
    }

    let Some(binding) = existing else {
        return Ok(IdempotencyDecision::New);
    };
    if binding.expires_at_unix_seconds <= now_unix_seconds {
        return Ok(IdempotencyDecision::New);
    }
    if binding.subject != subject
        || binding.key != key
        || binding.operation != operation
        || binding.normalized_route != normalized_route
        || binding.request_digest != request_digest
    {
        return Err(IdempotencyError::Conflict);
    }
    Ok(IdempotencyDecision::Replay)
}

fn validate_clock(now: i64, expires_at: i64) -> Result<(), TransferTransitionError> {
    if now < 0 || expires_at < 0 {
        return Err(TransferTransitionError::InvalidClock);
    }
    Ok(())
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_key(value: &str) -> bool {
    (8..=128).contains(&value.len()) && valid_identifier(value, 128)
}

fn valid_route(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 256
        || !value.starts_with('/')
        || value.contains('?')
        || value.contains('#')
        || value.contains("//")
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }
    value
        .split('/')
        .skip(1)
        .all(|segment| !matches!(segment, "." | ".."))
}

fn valid_sha256_base64url(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const DIGEST: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn pending_transfer_expires_without_persisted_rewrite() {
        assert_eq!(
            effective_state(NOW, NOW, TransferState::Pending).unwrap(),
            TransferState::Expired
        );
        assert_eq!(
            effective_state(NOW, NOW - 1, TransferState::Acknowledged).unwrap(),
            TransferState::Acknowledged
        );
    }

    #[test]
    fn acknowledgement_and_cancel_are_terminal_and_idempotent() {
        let acknowledged = acknowledge_transfer(
            NOW,
            NOW + 60,
            TransferState::Pending,
            AcknowledgementDisposition::Acknowledged,
        )
        .unwrap();
        assert_eq!(acknowledged, TransferState::Acknowledged);
        assert_eq!(
            acknowledge_transfer(
                NOW,
                NOW + 60,
                acknowledged,
                AcknowledgementDisposition::Acknowledged,
            )
            .unwrap(),
            acknowledged
        );
        assert_eq!(
            cancel_transfer(NOW, NOW + 60, acknowledged),
            Err(TransferTransitionError::InvalidTransition)
        );
    }

    #[test]
    fn expired_transfer_rejects_late_terminal_action() {
        assert_eq!(
            acknowledge_transfer(
                NOW,
                NOW,
                TransferState::Pending,
                AcknowledgementDisposition::Rejected,
            ),
            Err(TransferTransitionError::TransferExpired)
        );
        assert_eq!(
            cancel_transfer(NOW, NOW, TransferState::Pending),
            Err(TransferTransitionError::TransferExpired)
        );
    }

    #[test]
    fn matching_active_idempotency_binding_replays() {
        let binding = IdempotencyBinding {
            subject: "subject-0001",
            key: "operation-key-0001",
            operation: IdempotentOperation::Create,
            normalized_route: "/v1/integrations/memebank/transfers",
            request_digest: DIGEST,
            expires_at_unix_seconds: NOW + 60,
        };
        assert_eq!(
            evaluate_idempotency(
                NOW,
                Some(binding),
                binding.subject,
                binding.key,
                binding.operation,
                binding.normalized_route,
                binding.request_digest,
            )
            .unwrap(),
            IdempotencyDecision::Replay
        );
    }

    #[test]
    fn digest_mismatch_conflicts_and_expired_binding_can_be_replaced() {
        let binding = IdempotencyBinding {
            subject: "subject-0001",
            key: "operation-key-0001",
            operation: IdempotentOperation::Acknowledge,
            normalized_route: "/v1/integrations/memebank/transfers/id/ack",
            request_digest: DIGEST,
            expires_at_unix_seconds: NOW + 60,
        };
        let other_digest = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        assert_eq!(
            evaluate_idempotency(
                NOW,
                Some(binding),
                binding.subject,
                binding.key,
                binding.operation,
                binding.normalized_route,
                other_digest,
            ),
            Err(IdempotencyError::Conflict)
        );

        let expired = IdempotencyBinding {
            expires_at_unix_seconds: NOW,
            ..binding
        };
        assert_eq!(
            evaluate_idempotency(
                NOW,
                Some(expired),
                expired.subject,
                expired.key,
                expired.operation,
                expired.normalized_route,
                other_digest,
            )
            .unwrap(),
            IdempotencyDecision::New
        );
    }
}
