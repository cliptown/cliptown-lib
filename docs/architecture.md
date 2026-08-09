# ClipTown library architecture

## Dependency direction

Applications and adapters depend on `cliptown-lib`. Versioned wire contracts
remain in `cliptown-interfaces`; generated models are adapted at repository
boundaries rather than copied into this crate.

```text
cliptown-interfaces  -> generated/wire adapters
                              |
                              v
                       cliptown-lib
                  /       |        |       \
            storage     sync   authorization  transfer policy
               |          |        |              |
               v          v        v              v
              backend / desktop / Flutter / extension / CLI
```

The crate uses `serde` only for stable enum representations. It does not own
HTTP, database, object-store, UI, key-store, token-verification, or cryptographic
adapters.

## Trust domains

### Clipboard domain

An `EncryptedClip` represents ciphertext that a user intentionally placed in
ordinary clipboard history. Adapters may apply retention, sync, preview, paste,
indexing, and export only after device-side decryption and local user policy
permit it.

### Application-vault domain

An `EncryptedVaultRecord` is opaque product data stored through ClipTown's
authenticated device substrate. It is not clipboard content. The type exposes
no conversion into `EncryptedClip`, `DataDomain::ApplicationVault` denies all
clipboard capabilities, and adapters route it through `VaultStore`, never
`ClipStore`.

## Delegated authorization boundary

This library does not parse JWTs, fetch JWKS, contact shared-auth, or inspect a
factor application. A trusted service adapter verifies signatures, exact
audience, and revocation-aware session state, then passes normalized claims to
`authorize_delegated_operation`.

The policy requires exact configured issuer, `aud=cliptown-api`, authorized
party `memebank-api`, an active session, non-recursive token lineage, exactly
one operation scope, bounded token time, and fresh normalized LOA2 for writes
and deletes. No rule depends on which authenticator product supplied the
ceremony.

## Transfer semantics

The encrypted cross-product transfer state machine is terminal:

```text
pending -> acknowledged
        -> ignored
        -> rejected
        -> cancelled
        -> expired
```

A terminal transfer cannot be reopened. Repeating the same acknowledgement or
cancellation is idempotent. Expiry is computed from trusted time without
requiring a rewrite of every pending row.

Idempotency keys bind delegated subject, normalized route, operation, canonical
request digest, and expiry. An exact active match replays; a mismatched active
binding conflicts; an expired binding may be replaced. Storage adapters remain
responsible for transaction isolation and advisory locking.

## Conflict-resolution invariants

Sync cursors and logical revisions are monotonic. An adapter may merge
concurrent records according to the versioned contract, but it must never move
a cursor backward, reopen a terminal transfer, widen an authorization scope, or
substitute application-vault data for clipboard data. Git and schema conflicts
must preserve the conceptual union of valid ownership, security, state, and
compatibility work rather than choosing one side mechanically.

## Compatibility and package provenance

Breaking changes require a major crate version and coordinated contract review.
Additive wire fields belong first in `cliptown-interfaces`; adapters map them to
new behavior without changing existing field meaning. `.zpkg.lock` is generated
only by the reviewed resolver and is never fabricated manually.
