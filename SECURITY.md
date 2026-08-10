# Security policy

Report suspected vulnerabilities privately through the ClipTown organization
security process. Do not open a public issue containing tokens, keys, private
URLs, plaintext clipboard data, customer identifiers, or reproduction
credentials.

## Non-negotiable rules

- Never commit credentials, plaintext clipboard captures, device keys, OTP
  material, biometric data, private Signal state, or production identifiers.
- Treat all payload bytes accepted by this crate as ciphertext. Encryption and
  authentication happen on trusted devices before persistence or sync.
- Keep application-vault ciphertext outside clipboard preview, indexing, paste,
  export, notification, and retention paths.
- Bind step-up proofs to a single audience, action, challenge, device, subject,
  and expiry; reusable bearer credentials are not valid proof material.
- Preserve independently revocable per-installation credentials at adapter
  boundaries.
- Keep service authentication, subject ownership, session revocation, assurance,
  database RLS, transport TLS, and key management in their owning boundaries.
- Strictly validate canonical encoded cipher envelopes without decrypting them.
- Treat opaque fingerprints as ciphertext-integrity identifiers, not plaintext
  hashes.
- Keep local-only search free of blind-index and vector artifacts; vector search
  requires explicit opt-in and the exact versioned dimension.
- Reject replica equivocation at an identical device/version/timestamp tuple and
  prevent both numeric and opaque sync cursors from moving backward.
- Require idempotency keys before retrying non-idempotent mutations.
- Keep errors bounded and free of bearers, ciphertext, key material, source
  metadata, and upstream response bodies.
- Cross-product integration is API/SDK-only: no shared database, credential,
  mobile co-installation, deep link, local IPC, or clipboard fallback.

Supported releases and disclosure contacts will be documented before the first
public package release.
