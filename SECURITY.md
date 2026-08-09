# Security policy

Report suspected vulnerabilities privately to the ClipTown maintainers rather
than opening a public issue with exploit details or secrets.

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

Supported releases and disclosure contacts will be documented before the first
public package release.
