//! Encoded interface-envelope validation and opaque fingerprints.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use sha2::{Digest, Sha256};

use crate::ValidationError;
use crate::interfaces::{CipherEnvelope, ClipEnvelope};

/// Maximum decoded ciphertext accepted by shared in-memory policy.
pub const MAX_INLINE_CIPHERTEXT_BYTES: usize = 32 * 1024 * 1024;
const MAX_CIPHERTEXT_BASE64_BYTES: usize = (MAX_INLINE_CIPHERTEXT_BYTES * 4 / 3) + 8;

/// Cipher suites represented by the versioned ClipTown interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    /// XChaCha20-Poly1305 with a 24-byte nonce.
    XChaCha20Poly1305V1,
    /// AES-256-GCM with a 12-byte nonce.
    Aes256GcmV1,
}

impl CipherAlgorithm {
    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305V1 => "xchacha20poly1305-v1",
            Self::Aes256GcmV1 => "aes-256-gcm-v1",
        }
    }

    const fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305V1 => 24,
            Self::Aes256GcmV1 => 12,
        }
    }
}

impl TryFrom<&str> for CipherAlgorithm {
    type Error = ValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "xchacha20poly1305-v1" => Ok(Self::XChaCha20Poly1305V1),
            "aes-256-gcm-v1" => Ok(Self::Aes256GcmV1),
            _ => Err(ValidationError::UnsupportedCipher),
        }
    }
}

/// Stable digest over opaque interface identity and ciphertext fields.
///
/// This is an integrity and encrypted-payload deduplication identifier, not a
/// plaintext content hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClipFingerprint(String);

impl ClipFingerprint {
    /// Returns the base64url-encoded digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the digest text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Validates an interface cipher envelope without decrypting it.
///
/// # Errors
///
/// Returns a bounded validation category for unsupported algorithms, malformed
/// base64, invalid nonce length, empty ciphertext, invalid key identifiers, or
/// excessive decoded content.
pub fn validate_cipher_envelope(
    envelope: &CipherEnvelope,
) -> Result<CipherAlgorithm, ValidationError> {
    let algorithm = CipherAlgorithm::try_from(envelope.algorithm.as_str())?;
    if envelope.key_id.is_empty()
        || envelope.key_id.len() > 128
        || !envelope.key_id.bytes().all(is_portable_identifier_byte)
        || envelope.nonce.is_empty()
        || envelope.nonce.len() > 128
        || envelope.ciphertext.is_empty()
        || envelope.ciphertext.len() > MAX_CIPHERTEXT_BASE64_BYTES
    {
        return Err(ValidationError::InvalidCipherEnvelope);
    }

    let nonce = decode_base64(&envelope.nonce, 64)?;
    if nonce.len() != algorithm.nonce_len() {
        return Err(ValidationError::InvalidCipherEnvelope);
    }
    let ciphertext = decoded_ciphertext(envelope)?;
    if ciphertext.is_empty() {
        return Err(ValidationError::InvalidCipherEnvelope);
    }
    if let Some(hash) = envelope.associated_data_hash.as_deref()
        && decode_base64(hash, 32)?.len() != 32
    {
        return Err(ValidationError::InvalidCipherEnvelope);
    }
    Ok(algorithm)
}

/// Validates the canonical clip contract and its encoded cipher fields.
///
/// # Errors
///
/// Returns [`ValidationError::InterfaceContract`] for a rejected canonical
/// value, or an encoded-envelope error from [`validate_cipher_envelope`].
pub fn validate_interface_clip(clip: &ClipEnvelope) -> Result<(), ValidationError> {
    clip.validate()
        .map_err(|_| ValidationError::InterfaceContract)?;
    validate_cipher_envelope(&clip.payload)?;
    Ok(())
}

/// Produces a domain-separated digest without exposing or decrypting content.
///
/// # Errors
///
/// Returns a validation error when the canonical clip or encoded envelope is
/// malformed.
pub fn fingerprint_interface_clip(clip: &ClipEnvelope) -> Result<ClipFingerprint, ValidationError> {
    validate_interface_clip(clip)?;

    let mut digest = Sha256::new();
    add_field(&mut digest, b"cliptown.clip-fingerprint/v1");
    add_field(&mut digest, clip.clip_id.as_bytes());
    add_field(&mut digest, clip.kind.as_str().as_bytes());
    add_field(&mut digest, clip.source_device_id.as_bytes());
    add_field(&mut digest, &clip.logical_clock.to_be_bytes());
    add_field(&mut digest, clip.payload.algorithm.as_bytes());
    add_field(&mut digest, clip.payload.nonce.as_bytes());
    add_field(&mut digest, clip.payload.ciphertext.as_bytes());
    add_field(
        &mut digest,
        clip.payload
            .associated_data_hash
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    add_field(&mut digest, clip.payload.key_id.as_bytes());

    Ok(ClipFingerprint(URL_SAFE_NO_PAD.encode(digest.finalize())))
}

pub(crate) fn decoded_ciphertext(envelope: &CipherEnvelope) -> Result<Vec<u8>, ValidationError> {
    decode_base64(&envelope.ciphertext, MAX_INLINE_CIPHERTEXT_BYTES)
}

fn decode_base64(value: &str, maximum_decoded_bytes: usize) -> Result<Vec<u8>, ValidationError> {
    let engines = [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD];
    for engine in engines {
        if let Ok(decoded) = engine.decode(value) {
            if decoded.len() <= maximum_decoded_bytes {
                return Ok(decoded);
            }
            return Err(ValidationError::InvalidCipherEnvelope);
        }
    }
    Err(ValidationError::InvalidCipherEnvelope)
}

fn add_field(digest: &mut Sha256, field: &[u8]) {
    let length = u64::try_from(field.len()).expect("bounded field length fits in u64");
    digest.update(length.to_be_bytes());
    digest.update(field);
}

fn is_portable_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use crate::interfaces::{CipherEnvelope, ClipEnvelope, ClipKind};

    use super::*;

    fn clip() -> ClipEnvelope {
        ClipEnvelope {
            clip_id: Uuid::from_u128(1),
            kind: ClipKind::Image,
            payload: CipherEnvelope {
                algorithm: "xchacha20poly1305-v1".into(),
                nonce: STANDARD.encode([7_u8; 24]),
                ciphertext: STANDARD.encode(b"opaque ciphertext"),
                associated_data_hash: Some(URL_SAFE_NO_PAD.encode([9_u8; 32])),
                key_id: "device-key:1".into(),
            },
            pinned: false,
            deleted: false,
            blind_terms: vec![],
            opt_in_embedding: None,
            source_app: Some("tests".into()),
            source_device_id: Uuid::from_u128(2),
            logical_clock: 4,
            created_at: Utc.timestamp_opt(1_700_000_000, 0).single().expect("time"),
            updated_at: Utc.timestamp_opt(1_700_000_001, 0).single().expect("time"),
        }
    }

    #[test]
    fn valid_envelopes_and_fingerprints_are_deterministic() {
        let clip = clip();
        assert_eq!(
            validate_cipher_envelope(&clip.payload),
            Ok(CipherAlgorithm::XChaCha20Poly1305V1)
        );
        assert_eq!(
            fingerprint_interface_clip(&clip),
            fingerprint_interface_clip(&clip)
        );
        assert_eq!(
            fingerprint_interface_clip(&clip)
                .expect("fingerprint")
                .as_str()
                .len(),
            43
        );
    }

    #[test]
    fn nonce_length_and_algorithm_are_fail_closed() {
        let mut value = clip();
        value.payload.nonce = STANDARD.encode([0_u8; 12]);
        assert_eq!(
            validate_cipher_envelope(&value.payload),
            Err(ValidationError::InvalidCipherEnvelope)
        );

        value.payload.algorithm = "unknown-v1".into();
        assert_eq!(
            validate_cipher_envelope(&value.payload),
            Err(ValidationError::UnsupportedCipher)
        );
    }

    #[test]
    fn fingerprint_changes_when_ciphertext_changes() {
        let left = clip();
        let mut right = left.clone();
        right.payload.ciphertext = STANDARD.encode(b"different ciphertext");
        assert_ne!(
            fingerprint_interface_clip(&left),
            fingerprint_interface_clip(&right)
        );
    }
}
