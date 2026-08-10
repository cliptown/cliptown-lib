//! Shared API idempotency and bounded retry decisions.

use crate::ValidationError;

/// A bounded header-safe key used to make a mutation replayable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Parses an ASCII identifier from 16 through 128 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidIdempotencyKey`] for whitespace,
    /// control characters, unsupported punctuation, or an invalid length.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if !(16..=128).contains(&value.len())
            || value.trim() != value
            || !value.bytes().all(is_idempotency_byte)
        {
            return Err(ValidationError::InvalidIdempotencyKey);
        }
        Ok(Self(value))
    }

    /// Returns the validated key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the validated key.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// HTTP method class relevant to retry safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMethod {
    /// Read a resource.
    Get,
    /// Read response metadata only.
    Head,
    /// Create or invoke a non-idempotent operation.
    Post,
    /// Replace a resource idempotently.
    Put,
    /// Partially mutate a resource.
    Patch,
    /// Delete a resource idempotently.
    Delete,
}

impl RequestMethod {
    /// Returns whether the method is idempotent without an explicit key.
    #[must_use]
    pub const fn is_intrinsically_idempotent(self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Put | Self::Delete)
    }
}

/// Bounded exponential-backoff policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts, including the first request.
    pub max_attempts: u8,
    /// Initial delay before the first retry.
    pub base_delay_ms: u64,
    /// Maximum delay after exponential growth.
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay_ms: 200,
            max_delay_ms: 5_000,
        }
    }
}

impl RetryPolicy {
    /// Validates the attempt and delay bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidRetryPolicy`] for zero, inverted, or
    /// excessive bounds.
    pub fn validate(self) -> Result<Self, ValidationError> {
        if !(1..=10).contains(&self.max_attempts)
            || self.base_delay_ms == 0
            || self.base_delay_ms > self.max_delay_ms
            || self.max_delay_ms > 60_000
        {
            return Err(ValidationError::InvalidRetryPolicy);
        }
        Ok(self)
    }
}

/// Stable reason why a request must not be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryStopReason {
    /// The HTTP status represents a permanent result.
    PermanentStatus,
    /// The mutation is unsafe without an idempotency key.
    UnsafeMutation,
    /// The configured attempt budget is exhausted or invalid for a retry.
    MaxAttempts,
}

/// Retry decision for one failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Retry after the bounded delay.
    Retry {
        /// Delay before the next attempt.
        delay_ms: u64,
    },
    /// Stop without another network request.
    DoNotRetry {
        /// Stable non-secret reason.
        reason: RetryStopReason,
    },
}

/// Decides whether an HTTP result may be retried without duplicating a mutation.
///
/// `attempt` is one-based and identifies the attempt that just failed.
///
/// # Errors
///
/// Returns [`ValidationError::InvalidRetryPolicy`] when `policy` is invalid.
pub fn decide_http_retry(
    method: RequestMethod,
    status: u16,
    attempt: u8,
    has_idempotency_key: bool,
    policy: RetryPolicy,
) -> Result<RetryDecision, ValidationError> {
    let policy = policy.validate()?;
    if attempt == 0 || attempt >= policy.max_attempts {
        return Ok(RetryDecision::DoNotRetry {
            reason: RetryStopReason::MaxAttempts,
        });
    }
    if !matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504) {
        return Ok(RetryDecision::DoNotRetry {
            reason: RetryStopReason::PermanentStatus,
        });
    }
    if !method.is_intrinsically_idempotent() && !has_idempotency_key {
        return Ok(RetryDecision::DoNotRetry {
            reason: RetryStopReason::UnsafeMutation,
        });
    }
    Ok(RetryDecision::Retry {
        delay_ms: exponential_delay(attempt, policy),
    })
}

/// Decides whether a transport failure may be retried under the same mutation
/// safety rule.
///
/// # Errors
///
/// Returns [`ValidationError::InvalidRetryPolicy`] when `policy` is invalid.
pub fn decide_transport_retry(
    method: RequestMethod,
    attempt: u8,
    has_idempotency_key: bool,
    policy: RetryPolicy,
) -> Result<RetryDecision, ValidationError> {
    let policy = policy.validate()?;
    if attempt == 0 || attempt >= policy.max_attempts {
        return Ok(RetryDecision::DoNotRetry {
            reason: RetryStopReason::MaxAttempts,
        });
    }
    if !method.is_intrinsically_idempotent() && !has_idempotency_key {
        return Ok(RetryDecision::DoNotRetry {
            reason: RetryStopReason::UnsafeMutation,
        });
    }
    Ok(RetryDecision::Retry {
        delay_ms: exponential_delay(attempt, policy),
    })
}

fn exponential_delay(attempt: u8, policy: RetryPolicy) -> u64 {
    let exponent = u32::from(attempt.saturating_sub(1)).min(20);
    policy
        .base_delay_ms
        .saturating_mul(1_u64 << exponent)
        .min(policy.max_delay_ms)
}

fn is_idempotency_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_keys_are_bounded_and_header_safe() {
        let key = IdempotencyKey::parse("operation-00000001").expect("valid key");
        assert_eq!(key.as_str(), "operation-00000001");
        assert_eq!(
            IdempotencyKey::parse("short"),
            Err(ValidationError::InvalidIdempotencyKey)
        );
        assert_eq!(
            IdempotencyKey::parse("operation key with spaces"),
            Err(ValidationError::InvalidIdempotencyKey)
        );
    }

    #[test]
    fn unsafe_mutations_never_retry_without_a_key() {
        let decision =
            decide_http_retry(RequestMethod::Post, 503, 1, false, RetryPolicy::default())
                .expect("valid policy");
        assert_eq!(
            decision,
            RetryDecision::DoNotRetry {
                reason: RetryStopReason::UnsafeMutation
            }
        );
    }

    #[test]
    fn retryable_results_use_bounded_exponential_backoff() {
        let policy = RetryPolicy {
            max_attempts: 6,
            base_delay_ms: 250,
            max_delay_ms: 1_000,
        };
        assert_eq!(
            decide_http_retry(RequestMethod::Post, 503, 1, true, policy),
            Ok(RetryDecision::Retry { delay_ms: 250 })
        );
        assert_eq!(
            decide_http_retry(RequestMethod::Post, 503, 4, true, policy),
            Ok(RetryDecision::Retry { delay_ms: 1_000 })
        );
    }

    #[test]
    fn authorization_and_contract_errors_are_permanent() {
        for status in [400, 401, 403, 404, 409, 422] {
            assert_eq!(
                decide_http_retry(RequestMethod::Get, status, 1, false, RetryPolicy::default(),),
                Ok(RetryDecision::DoNotRetry {
                    reason: RetryStopReason::PermanentStatus
                })
            );
        }
    }
}
