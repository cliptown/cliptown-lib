//! Privacy-mode validation for canonical search requests.

use std::collections::HashSet;

use crate::ValidationError;
use crate::interfaces::{SearchPrivacyMode, SearchRequest};

/// Maximum result count accepted by shared search policy.
pub const MAX_SEARCH_LIMIT: u32 = 100;
/// Exact embedding size supported by the current contract.
pub const EMBEDDING_DIMENSIONS: usize = 1536;

/// Validated search execution plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchPlan {
    /// Execute entirely on the trusted device with no remote artifacts.
    LocalOnly {
        /// Maximum returned results.
        limit: u32,
        /// Whether only pinned items may be considered.
        pinned_only: bool,
    },
    /// Query with bounded opaque blind-index terms.
    BlindIndex {
        /// Maximum returned results.
        limit: u32,
        /// Whether only pinned items may be considered.
        pinned_only: bool,
        /// Number of unique blind terms.
        term_count: usize,
    },
    /// Query with an explicitly opted-in fixed-size vector.
    OptInVector {
        /// Maximum returned results.
        limit: u32,
        /// Whether only pinned items may be considered.
        pinned_only: bool,
        /// Number of vector dimensions.
        dimensions: usize,
    },
}

/// Validates that a request contains only artifacts allowed by its privacy mode.
///
/// # Errors
///
/// Returns a mode-mismatch error for mixed local/blind/vector artifacts and an
/// invalid-request error for bounds, duplicates, malformed terms, dimensions,
/// or non-finite vector values.
pub fn validate_search_request(request: &SearchRequest) -> Result<SearchPlan, ValidationError> {
    if !(1..=MAX_SEARCH_LIMIT).contains(&request.limit) {
        return Err(ValidationError::InvalidSearchRequest);
    }

    match &request.privacy_mode {
        SearchPrivacyMode::LocalOnly => {
            if !request.blind_terms.is_empty() || request.query_embedding.is_some() {
                return Err(ValidationError::SearchModeMismatch);
            }
            Ok(SearchPlan::LocalOnly {
                limit: request.limit,
                pinned_only: request.pinned_only,
            })
        }
        SearchPrivacyMode::BlindIndex => {
            if request.blind_terms.is_empty()
                || request.blind_terms.len() > 256
                || request.query_embedding.is_some()
            {
                return Err(ValidationError::SearchModeMismatch);
            }
            if request.blind_terms.iter().any(|term| {
                !(16..=128).contains(&term.len()) || !term.bytes().all(is_blind_term_byte)
            }) {
                return Err(ValidationError::InvalidSearchRequest);
            }
            let unique: HashSet<_> = request.blind_terms.iter().map(String::as_str).collect();
            if unique.len() != request.blind_terms.len() {
                return Err(ValidationError::InvalidSearchRequest);
            }
            Ok(SearchPlan::BlindIndex {
                limit: request.limit,
                pinned_only: request.pinned_only,
                term_count: request.blind_terms.len(),
            })
        }
        SearchPrivacyMode::OptInVector => {
            if !request.blind_terms.is_empty() {
                return Err(ValidationError::SearchModeMismatch);
            }
            let embedding = request
                .query_embedding
                .as_ref()
                .ok_or(ValidationError::SearchModeMismatch)?;
            if embedding.len() != EMBEDDING_DIMENSIONS
                || embedding.iter().any(|value| !value.is_finite())
            {
                return Err(ValidationError::InvalidSearchRequest);
            }
            Ok(SearchPlan::OptInVector {
                limit: request.limit,
                pinned_only: request.pinned_only,
                dimensions: embedding.len(),
            })
        }
    }
}

fn is_blind_term_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'=')
}

#[cfg(test)]
mod tests {
    use crate::interfaces::{SearchPrivacyMode, SearchRequest};

    use super::*;

    #[test]
    fn local_only_never_accepts_remote_artifacts() {
        let valid = SearchRequest {
            blind_terms: vec![],
            query_embedding: None,
            privacy_mode: SearchPrivacyMode::LocalOnly,
            limit: 20,
            pinned_only: false,
        };
        assert!(matches!(
            validate_search_request(&valid),
            Ok(SearchPlan::LocalOnly { .. })
        ));

        let mut leaking = valid;
        leaking.blind_terms.push("A234567890123456".into());
        assert_eq!(
            validate_search_request(&leaking),
            Err(ValidationError::SearchModeMismatch)
        );
    }

    #[test]
    fn blind_terms_are_bounded_and_unique() {
        let term = "A234567890123456".to_owned();
        let valid = SearchRequest {
            blind_terms: vec![term.clone()],
            query_embedding: None,
            privacy_mode: SearchPrivacyMode::BlindIndex,
            limit: 25,
            pinned_only: true,
        };
        assert_eq!(
            validate_search_request(&valid),
            Ok(SearchPlan::BlindIndex {
                limit: 25,
                pinned_only: true,
                term_count: 1,
            })
        );

        let duplicate = SearchRequest {
            blind_terms: vec![term.clone(), term],
            ..valid
        };
        assert_eq!(
            validate_search_request(&duplicate),
            Err(ValidationError::InvalidSearchRequest)
        );
    }

    #[test]
    fn vectors_require_explicit_opt_in_and_exact_dimensions() {
        let valid = SearchRequest {
            blind_terms: vec![],
            query_embedding: Some(vec![0.0; EMBEDDING_DIMENSIONS]),
            privacy_mode: SearchPrivacyMode::OptInVector,
            limit: 10,
            pinned_only: false,
        };
        assert!(matches!(
            validate_search_request(&valid),
            Ok(SearchPlan::OptInVector { .. })
        ));

        let mut invalid = valid;
        invalid.query_embedding = Some(vec![0.0; 12]);
        assert_eq!(
            validate_search_request(&invalid),
            Err(ValidationError::InvalidSearchRequest)
        );
    }
}
