//! Deterministic canonical clip convergence and opaque cursor policy.

use crate::ValidationError;
use crate::crypto::validate_interface_clip;
use crate::interfaces::{ClipEnvelope, SyncCursor as InterfaceSyncCursor};

/// Stable reason one canonical clip version won a merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeResolution {
    /// Both values are identical.
    Identical,
    /// The left value has the greater logical clock.
    LeftNewerClock,
    /// The right value has the greater logical clock.
    RightNewerClock,
    /// Clocks tie and the left value has the later timestamp.
    LeftNewerTimestamp,
    /// Clocks tie and the right value has the later timestamp.
    RightNewerTimestamp,
    /// Version fields tie and the left device identifier wins deterministically.
    LeftDeviceTieBreak,
    /// Version fields tie and the right device identifier wins deterministically.
    RightDeviceTieBreak,
}

/// Deterministic merge result for one logical canonical clip.
#[derive(Debug, Clone, PartialEq)]
pub struct MergeOutcome {
    /// Winning complete canonical value.
    pub winner: ClipEnvelope,
    /// Stable resolution category.
    pub resolution: MergeResolution,
}

/// Merges two versions of one canonical clip without relying on arrival order.
///
/// # Errors
///
/// Returns a validation error for malformed encoded clips, different clip IDs,
/// or conflicting content at an identical device/version/timestamp tuple.
pub fn merge_clip_versions(
    left: &ClipEnvelope,
    right: &ClipEnvelope,
) -> Result<MergeOutcome, ValidationError> {
    validate_interface_clip(left)?;
    validate_interface_clip(right)?;
    if left.clip_id != right.clip_id {
        return Err(ValidationError::DifferentClipIds);
    }
    if left == right {
        return Ok(MergeOutcome {
            winner: left.clone(),
            resolution: MergeResolution::Identical,
        });
    }

    if left.logical_clock != right.logical_clock {
        return Ok(if left.logical_clock > right.logical_clock {
            outcome(left, MergeResolution::LeftNewerClock)
        } else {
            outcome(right, MergeResolution::RightNewerClock)
        });
    }
    if left.updated_at != right.updated_at {
        return Ok(if left.updated_at > right.updated_at {
            outcome(left, MergeResolution::LeftNewerTimestamp)
        } else {
            outcome(right, MergeResolution::RightNewerTimestamp)
        });
    }
    if left.source_device_id != right.source_device_id {
        return Ok(
            if left.source_device_id.as_bytes() > right.source_device_id.as_bytes() {
                outcome(left, MergeResolution::LeftDeviceTieBreak)
            } else {
                outcome(right, MergeResolution::RightDeviceTieBreak)
            },
        );
    }

    Err(ValidationError::ReplicaEquivocation)
}

fn outcome(winner: &ClipEnvelope, resolution: MergeResolution) -> MergeOutcome {
    MergeOutcome {
        winner: winner.clone(),
        resolution,
    }
}

/// Monotonic wrapper around the canonical opaque server cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceMonotonicCursor {
    cursor: Option<String>,
    server_sequence: i64,
}

/// Result of applying one canonical cursor update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorAdvance {
    /// Sequence and opaque cursor are unchanged.
    Unchanged,
    /// Sequence advanced by the positive delta.
    Advanced {
        /// Number of newly acknowledged server positions.
        by: i64,
    },
}

impl InterfaceMonotonicCursor {
    /// Constructs a monotonic cursor from the canonical contract.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidOpaqueCursor`] for negative sequences,
    /// blank/oversized cursors, control characters, or surrounding whitespace.
    pub fn new(cursor: InterfaceSyncCursor) -> Result<Self, ValidationError> {
        validate_cursor(&cursor)?;
        Ok(Self {
            cursor: cursor.cursor,
            server_sequence: cursor.server_sequence,
        })
    }

    /// Returns the latest acknowledged server sequence.
    #[must_use]
    pub const fn server_sequence(&self) -> i64 {
        self.server_sequence
    }

    /// Returns the current opaque cursor, when supplied by the service.
    #[must_use]
    pub fn opaque_cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Applies a forward-only cursor update.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidOpaqueCursor`] when the sequence moves
    /// backward or an unchanged sequence substitutes a different cursor.
    pub fn advance(&mut self, next: InterfaceSyncCursor) -> Result<CursorAdvance, ValidationError> {
        validate_cursor(&next)?;
        if next.server_sequence < self.server_sequence {
            return Err(ValidationError::InvalidOpaqueCursor);
        }
        if next.server_sequence == self.server_sequence {
            if next.cursor != self.cursor {
                return Err(ValidationError::InvalidOpaqueCursor);
            }
            return Ok(CursorAdvance::Unchanged);
        }

        let by = next.server_sequence - self.server_sequence;
        self.server_sequence = next.server_sequence;
        self.cursor = next.cursor;
        Ok(CursorAdvance::Advanced { by })
    }

    /// Returns a canonical cursor snapshot.
    #[must_use]
    pub fn snapshot(&self) -> InterfaceSyncCursor {
        InterfaceSyncCursor {
            cursor: self.cursor.clone(),
            server_sequence: self.server_sequence,
        }
    }
}

fn validate_cursor(cursor: &InterfaceSyncCursor) -> Result<(), ValidationError> {
    if cursor.server_sequence < 0 {
        return Err(ValidationError::InvalidOpaqueCursor);
    }
    if let Some(value) = cursor.cursor.as_deref()
        && (value.is_empty()
            || value.len() > 1024
            || value.chars().any(char::is_control)
            || value.trim() != value)
    {
        return Err(ValidationError::InvalidOpaqueCursor);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use crate::interfaces::{CipherEnvelope, ClipEnvelope, ClipKind};

    use super::*;

    fn clip(device: u128, clock: i64) -> ClipEnvelope {
        ClipEnvelope {
            clip_id: Uuid::from_u128(10),
            kind: ClipKind::Text,
            payload: CipherEnvelope {
                algorithm: "aes-256-gcm-v1".into(),
                nonce: STANDARD.encode([0_u8; 12]),
                ciphertext: STANDARD.encode(format!("cipher-{device}-{clock}")),
                associated_data_hash: None,
                key_id: "key-1".into(),
            },
            pinned: false,
            deleted: false,
            blind_terms: vec![],
            opt_in_embedding: None,
            source_app: None,
            source_device_id: Uuid::from_u128(device),
            logical_clock: clock,
            created_at: Utc.timestamp_opt(1_700_000_000, 0).single().expect("time"),
            updated_at: Utc
                .timestamp_opt(1_700_000_000 + clock, 0)
                .single()
                .expect("time"),
        }
    }

    #[test]
    fn logical_clock_wins_before_timestamp_or_arrival_order() {
        let left = clip(1, 3);
        let right = clip(2, 4);
        let result = merge_clip_versions(&left, &right).expect("merge");
        assert_eq!(result.winner, right);
        assert_eq!(result.resolution, MergeResolution::RightNewerClock);
    }

    #[test]
    fn same_device_same_version_with_different_payload_is_rejected() {
        let left = clip(1, 3);
        let mut right = left.clone();
        right.payload.ciphertext = STANDARD.encode(b"different");
        assert_eq!(
            merge_clip_versions(&left, &right),
            Err(ValidationError::ReplicaEquivocation)
        );
    }

    #[test]
    fn cursors_advance_monotonically() {
        let mut cursor = InterfaceMonotonicCursor::new(InterfaceSyncCursor {
            cursor: Some("page-a".into()),
            server_sequence: 7,
        })
        .expect("cursor");
        assert_eq!(
            cursor.advance(InterfaceSyncCursor {
                cursor: Some("page-b".into()),
                server_sequence: 10,
            }),
            Ok(CursorAdvance::Advanced { by: 3 })
        );
        assert_eq!(cursor.server_sequence(), 10);
        assert_eq!(
            cursor.advance(InterfaceSyncCursor {
                cursor: Some("older".into()),
                server_sequence: 9,
            }),
            Err(ValidationError::InvalidOpaqueCursor)
        );
    }
}
