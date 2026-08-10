//! Explicit adapters from versioned interface values into domain records.

use crate::crypto::{decoded_ciphertext, validate_interface_clip};
use crate::interfaces::{ClipEnvelope as InterfaceClipEnvelope, ClipKind as InterfaceClipKind};
use crate::{
    ClipId, ClipKind, ContentHash, DeviceId, EncryptedClip, EncryptedClipInput, ValidationError,
};

/// Converts a canonical interface clip into the transport-neutral domain model.
///
/// The caller supplies the trusted-device plaintext digest because the wire
/// envelope intentionally does not let this library invent or infer one from
/// ciphertext.
///
/// # Errors
///
/// Returns a validation error for a rejected interface envelope, malformed
/// ciphertext, unrepresentable timestamp/revision, or invalid domain value.
pub fn adapt_interface_clip(
    clip: &InterfaceClipEnvelope,
    trusted_content_hash: ContentHash,
) -> Result<EncryptedClip, ValidationError> {
    validate_interface_clip(clip)?;
    let logical_revision =
        u64::try_from(clip.logical_clock).map_err(|_| ValidationError::NumericDomainOverflow)?;
    let created_at_unix_ms = u64::try_from(clip.created_at.timestamp_millis())
        .map_err(|_| ValidationError::NumericDomainOverflow)?;

    EncryptedClip::from_input(EncryptedClipInput {
        id: ClipId::parse(clip.clip_id.to_string())?,
        origin_device: DeviceId::parse(clip.source_device_id.to_string())?,
        kind: domain_clip_kind(&clip.kind),
        ciphertext: decoded_ciphertext(&clip.payload)?,
        content_hash: trusted_content_hash,
        created_at_unix_ms,
        logical_revision,
    })
}

/// Maps the canonical representation set into the deliberately smaller domain
/// capability set.
#[must_use]
pub const fn domain_clip_kind(kind: &InterfaceClipKind) -> ClipKind {
    match kind {
        InterfaceClipKind::Text => ClipKind::Text,
        InterfaceClipKind::Html => ClipKind::Html,
        InterfaceClipKind::Image => ClipKind::Image,
        InterfaceClipKind::File | InterfaceClipKind::FileList => ClipKind::File,
        InterfaceClipKind::Rtf
        | InterfaceClipKind::Url
        | InterfaceClipKind::Color
        | InterfaceClipKind::Json => ClipKind::Custom,
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use crate::DataDomain;
    use crate::interfaces::{CipherEnvelope, ClipEnvelope, ClipKind as InterfaceClipKind};

    use super::*;

    #[test]
    fn canonical_clip_adapts_without_crossing_the_domain_boundary() {
        let value = ClipEnvelope {
            clip_id: Uuid::from_u128(3),
            kind: InterfaceClipKind::FileList,
            payload: CipherEnvelope {
                algorithm: "aes-256-gcm-v1".into(),
                nonce: STANDARD.encode([0_u8; 12]),
                ciphertext: STANDARD.encode(b"opaque"),
                associated_data_hash: None,
                key_id: "device-key-3".into(),
            },
            pinned: false,
            deleted: false,
            blind_terms: vec![],
            opt_in_embedding: None,
            source_app: None,
            source_device_id: Uuid::from_u128(4),
            logical_clock: 8,
            created_at: Utc.timestamp_opt(1_700_000_000, 0).single().expect("time"),
            updated_at: Utc.timestamp_opt(1_700_000_001, 0).single().expect("time"),
        };

        let adapted = adapt_interface_clip(&value, ContentHash::from_bytes([5_u8; 32]))
            .expect("adapted clip");
        assert_eq!(adapted.domain(), DataDomain::Clipboard);
        assert_eq!(adapted.kind(), ClipKind::File);
        assert_eq!(adapted.ciphertext(), b"opaque");
        assert_eq!(adapted.logical_revision(), 8);
    }

    #[test]
    fn richer_interface_kinds_map_explicitly_to_custom_domain_content() {
        assert_eq!(domain_clip_kind(&InterfaceClipKind::Rtf), ClipKind::Custom);
        assert_eq!(domain_clip_kind(&InterfaceClipKind::Url), ClipKind::Custom);
        assert_eq!(
            domain_clip_kind(&InterfaceClipKind::Color),
            ClipKind::Custom
        );
        assert_eq!(domain_clip_kind(&InterfaceClipKind::Json), ClipKind::Custom);
    }
}
