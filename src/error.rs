//! Validation failures produced by the domain core.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// A rejected domain value, contract value, or state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// A required identifier was empty after trimming.
    EmptyIdentifier {
        /// Stable field name suitable for logs and API error mapping.
        field: &'static str,
    },
    /// A ciphertext payload was empty.
    EmptyCiphertext,
    /// A sync cursor attempted to move backward.
    CursorRegression {
        /// Cursor value currently held by the caller.
        current: u64,
        /// Cursor value proposed by the caller.
        proposed: u64,
    },
    /// A retention policy used an unbounded zero value.
    InvalidRetention {
        /// Proposed maximum number of retained items.
        max_items: usize,
        /// Proposed maximum item age in seconds.
        max_age_seconds: u64,
    },
    /// A canonical interface value failed its versioned validation contract.
    InterfaceContract,
    /// A cipher algorithm is not in the reviewed interface allow-list.
    UnsupportedCipher,
    /// An encoded cipher envelope is malformed, incomplete, or oversized.
    InvalidCipherEnvelope,
    /// Search artifacts do not match the declared privacy mode.
    SearchModeMismatch,
    /// A search request exceeds shared bounds or contains malformed artifacts.
    InvalidSearchRequest,
    /// Two versions describe different logical clipboard records.
    DifferentClipIds,
    /// One replica supplied conflicting content at an identical version.
    ReplicaEquivocation,
    /// An opaque interface cursor is malformed or changes without advancement.
    InvalidOpaqueCursor,
    /// An HTTP idempotency key is malformed or unsafe for a header.
    InvalidIdempotencyKey,
    /// A retry policy is zero, inverted, or outside shared bounds.
    InvalidRetryPolicy,
    /// A version or timestamp cannot be represented by the domain model.
    NumericDomainOverflow,
}

impl Display for ValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier { field } => {
                write!(formatter, "{field} must not be empty")
            }
            Self::EmptyCiphertext => formatter.write_str("ciphertext must not be empty"),
            Self::CursorRegression { current, proposed } => write!(
                formatter,
                "sync cursor cannot regress from {current} to {proposed}"
            ),
            Self::InvalidRetention {
                max_items,
                max_age_seconds,
            } => write!(
                formatter,
                "retention bounds must be positive (items={max_items}, age_seconds={max_age_seconds})"
            ),
            Self::InterfaceContract => {
                formatter.write_str("canonical interface contract rejected the value")
            }
            Self::UnsupportedCipher => formatter.write_str("unsupported cipher algorithm"),
            Self::InvalidCipherEnvelope => {
                formatter.write_str("cipher envelope is incomplete, malformed, or oversized")
            }
            Self::SearchModeMismatch => {
                formatter.write_str("search request does not match its privacy mode")
            }
            Self::InvalidSearchRequest => {
                formatter.write_str("search request exceeds shared bounds")
            }
            Self::DifferentClipIds => {
                formatter.write_str("clip versions describe different logical records")
            }
            Self::ReplicaEquivocation => {
                formatter.write_str("replica supplied conflicting content at the same version")
            }
            Self::InvalidOpaqueCursor => {
                formatter.write_str("opaque sync cursor is malformed or inconsistent")
            }
            Self::InvalidIdempotencyKey => formatter.write_str("idempotency key is malformed"),
            Self::InvalidRetryPolicy => {
                formatter.write_str("retry policy is outside shared bounds")
            }
            Self::NumericDomainOverflow => {
                formatter.write_str("contract value exceeds domain representation")
            }
        }
    }
}

impl Error for ValidationError {}
