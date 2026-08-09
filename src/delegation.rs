//! Fail-closed policy for shared-auth delegated product tokens.
//!
//! A trusted service adapter verifies signatures, exact-audience introspection,
//! and session revocation before constructing [`DelegatedClaims`]. This module
//! performs product authorization only; it never parses a bearer or contacts a
//! factor application.

use std::{error::Error, fmt};

/// Audience required by the ClipTown resource server.
pub const CLIPTOWN_API_AUDIENCE: &str = "cliptown-api";
/// Authorized party for MemeBank product delegation.
pub const MEMEBANK_CLIENT_ID: &str = "memebank-api";
/// Scope for subject-owned transfer reads.
pub const MEMEBANK_READ_SCOPE: &str = "cliptown:memebank:read";
/// Scope for subject-owned transfer writes.
pub const MEMEBANK_WRITE_SCOPE: &str = "cliptown:memebank:write";
/// Scope for subject-owned transfer deletion.
pub const MEMEBANK_DELETE_SCOPE: &str = "cliptown:memebank:delete";
/// Assurance context required for sensitive operations.
pub const LOA2_ASSURANCE_CONTEXT: &str = "urn:oresoftware:loa:2";

/// A resource operation authorized by one exact delegated scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Read a subject-owned resource.
    Read,
    /// Create or mutate a subject-owned resource.
    Write,
    /// Delete or cancel a subject-owned resource.
    Delete,
}

impl Operation {
    /// Returns the one and only scope accepted for this operation.
    #[must_use]
    pub const fn required_scope(self) -> &'static str {
        match self {
            Self::Read => MEMEBANK_READ_SCOPE,
            Self::Write => MEMEBANK_WRITE_SCOPE,
            Self::Delete => MEMEBANK_DELETE_SCOPE,
        }
    }

    /// Returns whether the operation requires recent level-two assurance.
    #[must_use]
    pub const fn requires_recent_loa2(self) -> bool {
        matches!(self, Self::Write | Self::Delete)
    }
}

/// Normalized claims produced by a trusted shared-auth verification adapter.
#[derive(Debug, Clone, Copy)]
pub struct DelegatedClaims<'a> {
    /// Exact token issuer.
    pub issuer: &'a str,
    /// Sole resource audience.
    pub audience: &'a str,
    /// Public product client that requested delegation.
    pub authorized_party: &'a str,
    /// Stable delegated subject.
    pub subject: &'a str,
    /// Revocation-aware session identifier.
    pub session_id: &'a str,
    /// Identifier of the current delegated token.
    pub token_id: &'a str,
    /// Identifier of the parent token used for delegation.
    pub parent_token_id: &'a str,
    /// Space-delimited delegated scopes.
    pub scope: &'a str,
    /// Token issue time as Unix seconds.
    pub issued_at_unix_seconds: i64,
    /// Token not-before time as Unix seconds.
    pub not_before_unix_seconds: i64,
    /// Token expiration time as Unix seconds.
    pub expires_at_unix_seconds: i64,
    /// Time of the most recent authoritative authentication ceremony.
    pub authenticated_at_unix_seconds: Option<i64>,
    /// Normalized numeric assurance level.
    pub assurance_level: u8,
    /// Normalized assurance context.
    pub assurance_context: Option<&'a str>,
    /// Normalized authentication methods used by the ceremony.
    pub authentication_methods: &'a [&'a str],
    /// Whether the authoritative session remains active.
    pub session_active: bool,
    /// Whether the token is a product delegation rather than a base token.
    pub delegated: bool,
}

/// Operator-controlled limits used to authorize delegated claims.
#[derive(Debug, Clone, Copy)]
pub struct DelegationPolicy<'a> {
    /// Exact accepted issuer.
    pub issuer: &'a str,
    /// Current trusted Unix time.
    pub now_unix_seconds: i64,
    /// Maximum delegated token lifetime.
    pub maximum_token_lifetime_seconds: i64,
    /// Maximum age of assurance for sensitive operations.
    pub maximum_authentication_age_seconds: i64,
    /// Allowed clock skew for temporal comparisons.
    pub clock_skew_seconds: i64,
}

/// Subject and session context returned after successful authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedSubject {
    /// Stable resource-owner subject.
    pub subject: String,
    /// Active session used for authorization.
    pub session_id: String,
    /// Exact scope accepted for the operation.
    pub scope: &'static str,
}

/// Stable, non-secret reason for a delegated authorization failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationError {
    /// Policy configuration is invalid.
    InvalidPolicy,
    /// Claims contain an invalid identifier or time range.
    InvalidClaims,
    /// Token issuer does not match policy.
    WrongIssuer,
    /// Token audience is not the ClipTown API.
    WrongAudience,
    /// Authorized party is not the MemeBank product client.
    WrongAuthorizedParty,
    /// Token is not a non-recursive delegated grant.
    InvalidDelegation,
    /// Authoritative session is inactive.
    InactiveSession,
    /// Token is not yet valid.
    TokenNotYetValid,
    /// Token is expired.
    TokenExpired,
    /// Token lifetime exceeds policy.
    TokenLifetimeExceeded,
    /// Scope is missing, widened, or wrong for the operation.
    WrongScope,
    /// Sensitive operation lacks fresh level-two assurance.
    AssuranceRequired,
}

impl fmt::Display for DelegationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "invalid_policy",
            Self::InvalidClaims => "invalid_claims",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongAudience => "wrong_audience",
            Self::WrongAuthorizedParty => "wrong_authorized_party",
            Self::InvalidDelegation => "invalid_delegation",
            Self::InactiveSession => "inactive_session",
            Self::TokenNotYetValid => "token_not_yet_valid",
            Self::TokenExpired => "token_expired",
            Self::TokenLifetimeExceeded => "token_lifetime_exceeded",
            Self::WrongScope => "wrong_scope",
            Self::AssuranceRequired => "assurance_required",
        })
    }
}

impl Error for DelegationError {}

/// Authorizes one operation against exact delegated claims.
///
/// Signature verification and revocation I/O belong to the trusted adapter that
/// constructs [`DelegatedClaims`].
pub fn authorize_delegated_operation(
    claims: DelegatedClaims<'_>,
    operation: Operation,
    policy: DelegationPolicy<'_>,
) -> Result<AuthorizedSubject, DelegationError> {
    validate_policy(policy)?;
    validate_claim_shape(claims)?;

    if claims.issuer != policy.issuer {
        return Err(DelegationError::WrongIssuer);
    }
    if claims.audience != CLIPTOWN_API_AUDIENCE {
        return Err(DelegationError::WrongAudience);
    }
    if claims.authorized_party != MEMEBANK_CLIENT_ID {
        return Err(DelegationError::WrongAuthorizedParty);
    }
    if !claims.delegated || claims.token_id == claims.parent_token_id {
        return Err(DelegationError::InvalidDelegation);
    }
    if !claims.session_active {
        return Err(DelegationError::InactiveSession);
    }

    let latest_not_before = policy
        .now_unix_seconds
        .checked_add(policy.clock_skew_seconds)
        .ok_or(DelegationError::InvalidPolicy)?;
    if claims.not_before_unix_seconds > latest_not_before {
        return Err(DelegationError::TokenNotYetValid);
    }
    let earliest_expiry = policy
        .now_unix_seconds
        .checked_sub(policy.clock_skew_seconds)
        .ok_or(DelegationError::InvalidPolicy)?;
    if claims.expires_at_unix_seconds <= earliest_expiry {
        return Err(DelegationError::TokenExpired);
    }

    let lifetime = claims
        .expires_at_unix_seconds
        .checked_sub(claims.issued_at_unix_seconds)
        .ok_or(DelegationError::InvalidClaims)?;
    if lifetime <= 0 || lifetime > policy.maximum_token_lifetime_seconds {
        return Err(DelegationError::TokenLifetimeExceeded);
    }

    let mut scopes = claims.scope.split_ascii_whitespace();
    if scopes.next() != Some(operation.required_scope()) || scopes.next().is_some() {
        return Err(DelegationError::WrongScope);
    }
    if operation.requires_recent_loa2() {
        validate_recent_loa2(claims, policy)?;
    }

    Ok(AuthorizedSubject {
        subject: claims.subject.to_owned(),
        session_id: claims.session_id.to_owned(),
        scope: operation.required_scope(),
    })
}

fn validate_policy(policy: DelegationPolicy<'_>) -> Result<(), DelegationError> {
    if policy.issuer.is_empty()
        || policy.now_unix_seconds < 0
        || policy.maximum_token_lifetime_seconds <= 0
        || policy.maximum_authentication_age_seconds <= 0
        || policy.clock_skew_seconds < 0
    {
        return Err(DelegationError::InvalidPolicy);
    }
    Ok(())
}

fn validate_claim_shape(claims: DelegatedClaims<'_>) -> Result<(), DelegationError> {
    if !valid_identifier(claims.subject)
        || !valid_identifier(claims.session_id)
        || !valid_identifier(claims.token_id)
        || !valid_identifier(claims.parent_token_id)
        || claims.issued_at_unix_seconds < 0
        || claims.not_before_unix_seconds < claims.issued_at_unix_seconds
        || claims.expires_at_unix_seconds <= claims.not_before_unix_seconds
        || claims
            .authentication_methods
            .iter()
            .any(|method| !valid_identifier(method))
    {
        return Err(DelegationError::InvalidClaims);
    }
    Ok(())
}

fn validate_recent_loa2(
    claims: DelegatedClaims<'_>,
    policy: DelegationPolicy<'_>,
) -> Result<(), DelegationError> {
    if claims.assurance_level < 2
        || claims.assurance_context != Some(LOA2_ASSURANCE_CONTEXT)
        || claims.authentication_methods.is_empty()
    {
        return Err(DelegationError::AssuranceRequired);
    }

    let authenticated_at = claims
        .authenticated_at_unix_seconds
        .ok_or(DelegationError::AssuranceRequired)?;
    let latest_authentication = policy
        .now_unix_seconds
        .checked_add(policy.clock_skew_seconds)
        .ok_or(DelegationError::InvalidPolicy)?;
    let maximum_age = policy
        .maximum_authentication_age_seconds
        .checked_add(policy.clock_skew_seconds)
        .ok_or(DelegationError::InvalidPolicy)?;
    let age = policy
        .now_unix_seconds
        .checked_sub(authenticated_at)
        .ok_or(DelegationError::AssuranceRequired)?;
    if authenticated_at < 0 || authenticated_at > latest_authentication || age > maximum_age {
        return Err(DelegationError::AssuranceRequired);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn policy() -> DelegationPolicy<'static> {
        DelegationPolicy {
            issuer: "https://auth.example.test",
            now_unix_seconds: NOW,
            maximum_token_lifetime_seconds: 300,
            maximum_authentication_age_seconds: 600,
            clock_skew_seconds: 30,
        }
    }

    fn claims(scope: &'static str) -> DelegatedClaims<'static> {
        DelegatedClaims {
            issuer: "https://auth.example.test",
            audience: CLIPTOWN_API_AUDIENCE,
            authorized_party: MEMEBANK_CLIENT_ID,
            subject: "00000000-0000-4000-8000-000000000001",
            session_id: "00000000-0000-4000-8000-000000000002",
            token_id: "delegated-token-0001",
            parent_token_id: "parent-token-0001",
            scope,
            issued_at_unix_seconds: NOW - 10,
            not_before_unix_seconds: NOW - 10,
            expires_at_unix_seconds: NOW + 290,
            authenticated_at_unix_seconds: Some(NOW - 60),
            assurance_level: 2,
            assurance_context: Some(LOA2_ASSURANCE_CONTEXT),
            authentication_methods: &["passkey"],
            session_active: true,
            delegated: true,
        }
    }

    #[test]
    fn read_accepts_base_assurance_with_exact_scope() {
        let mut value = claims(MEMEBANK_READ_SCOPE);
        value.assurance_level = 1;
        value.assurance_context = None;
        value.authentication_methods = &["password"];
        value.authenticated_at_unix_seconds = None;
        let authorized = authorize_delegated_operation(value, Operation::Read, policy()).unwrap();
        assert_eq!(authorized.scope, MEMEBANK_READ_SCOPE);
    }

    #[test]
    fn sensitive_operations_require_fresh_loa2() {
        let mut stale = claims(MEMEBANK_WRITE_SCOPE);
        stale.authenticated_at_unix_seconds = Some(NOW - 1_000);
        assert_eq!(
            authorize_delegated_operation(stale, Operation::Write, policy()),
            Err(DelegationError::AssuranceRequired)
        );
        assert_eq!(
            authorize_delegated_operation(
                claims(MEMEBANK_DELETE_SCOPE),
                Operation::Delete,
                policy(),
            )
            .unwrap()
            .scope,
            MEMEBANK_DELETE_SCOPE
        );
    }

    #[test]
    fn audience_lineage_and_session_fail_closed() {
        let mut wrong_audience = claims(MEMEBANK_READ_SCOPE);
        wrong_audience.audience = "other-api";
        assert_eq!(
            authorize_delegated_operation(wrong_audience, Operation::Read, policy()),
            Err(DelegationError::WrongAudience)
        );

        let mut recursive = claims(MEMEBANK_READ_SCOPE);
        recursive.parent_token_id = recursive.token_id;
        assert_eq!(
            authorize_delegated_operation(recursive, Operation::Read, policy()),
            Err(DelegationError::InvalidDelegation)
        );

        let mut inactive = claims(MEMEBANK_READ_SCOPE);
        inactive.session_active = false;
        assert_eq!(
            authorize_delegated_operation(inactive, Operation::Read, policy()),
            Err(DelegationError::InactiveSession)
        );
    }

    #[test]
    fn widened_or_mismatched_scope_is_rejected() {
        assert_eq!(
            authorize_delegated_operation(
                claims("cliptown:memebank:read cliptown:memebank:write"),
                Operation::Read,
                policy(),
            ),
            Err(DelegationError::WrongScope)
        );
        assert_eq!(
            authorize_delegated_operation(
                claims(MEMEBANK_READ_SCOPE),
                Operation::Write,
                policy(),
            ),
            Err(DelegationError::WrongScope)
        );
    }
}
