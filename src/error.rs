//! Validation failures produced by the domain core.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// A rejected domain value or state transition.
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
        }
    }
}

impl Error for ValidationError {}
