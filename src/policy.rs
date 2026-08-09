//! Domain policy that remains independent of storage and transport adapters.

use crate::ValidationError;

/// The immutable trust domain of encrypted data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataDomain {
    /// Ordinary encrypted clipboard history.
    Clipboard,
    /// Opaque product data stored through the isolated application vault.
    ApplicationVault,
}

/// A user-visible clipboard operation that must be denied to vault data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardCapability {
    /// Render a local preview after authorized device-side decryption.
    Preview,
    /// Add authorized plaintext to local search or retrieval indexes.
    Index,
    /// Write authorized plaintext to the operating-system clipboard.
    Paste,
    /// Export authorized plaintext or a standard representation.
    Export,
    /// Include the item in ordinary clipboard retention behavior.
    Retain,
    /// Surface the item in clipboard notifications or history UI.
    Notify,
}

impl DataDomain {
    /// Returns whether this data domain may participate in a clipboard action.
    ///
    /// Application-vault data always returns `false`; the explicit capability
    /// parameter keeps call sites auditable when new operations are introduced.
    #[must_use]
    pub const fn permits_clipboard(self, _capability: ClipboardCapability) -> bool {
        matches!(self, Self::Clipboard)
    }
}

/// Positive bounds applied to ordinary clipboard history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    max_items: usize,
    max_age_seconds: u64,
}

impl RetentionPolicy {
    /// Creates a finite item-count and age policy.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidRetention`] when either bound is zero.
    pub const fn bounded(max_items: usize, max_age_seconds: u64) -> Result<Self, ValidationError> {
        if max_items == 0 || max_age_seconds == 0 {
            return Err(ValidationError::InvalidRetention {
                max_items,
                max_age_seconds,
            });
        }
        Ok(Self {
            max_items,
            max_age_seconds,
        })
    }

    /// Returns the maximum number of retained items.
    #[must_use]
    pub const fn max_items(self) -> usize {
        self.max_items
    }

    /// Returns the maximum item age in seconds.
    #[must_use]
    pub const fn max_age_seconds(self) -> u64 {
        self.max_age_seconds
    }

    /// Returns whether an item fits both current count and age bounds.
    #[must_use]
    pub const fn permits(self, current_items: usize, age_seconds: u64) -> bool {
        current_items < self.max_items && age_seconds <= self.max_age_seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_data_never_receives_clipboard_capabilities() {
        for capability in [
            ClipboardCapability::Preview,
            ClipboardCapability::Index,
            ClipboardCapability::Paste,
            ClipboardCapability::Export,
            ClipboardCapability::Retain,
            ClipboardCapability::Notify,
        ] {
            assert!(!DataDomain::ApplicationVault.permits_clipboard(capability));
            assert!(DataDomain::Clipboard.permits_clipboard(capability));
        }
    }

    #[test]
    fn retention_requires_positive_bounds() {
        assert_eq!(
            RetentionPolicy::bounded(0, 86_400),
            Err(ValidationError::InvalidRetention {
                max_items: 0,
                max_age_seconds: 86_400
            })
        );
        let policy = RetentionPolicy::bounded(100, 86_400).expect("valid policy");
        assert!(policy.permits(99, 86_400));
        assert!(!policy.permits(100, 1));
        assert!(!policy.permits(1, 86_401));
    }
}
