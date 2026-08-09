# Architecture and ownership

## Dependency direction

Applications and adapters depend on `cliptown-lib`; this library depends only
on the Rust standard library. Generated contract models may be adapted at the
repository boundary, but wire-format concerns do not leak into the domain core.

```text
cliptown-interfaces  -> generated/wire adapters
                              |
                              v
                       cliptown-lib
                /       |       |        \
          storage      sync   policy   delegation/transfer
             |           |       |          |
             v           v       v          v
       backend / desktop / Flutter / extension / CLI
```

## Trust domains

### Clipboard domain

An `EncryptedClip` represents ciphertext that a user intentionally placed in
ordinary clipboard history. Adapters may apply retention, sync, preview, paste,
indexing, and export behavior only after device-side decryption and local user
policy permit it.

### Application-vault domain

An `EncryptedVaultRecord` is opaque product data stored through ClipTown's
authenticated device substrate. It is not clipboard content. The type exposes
no conversion into `EncryptedClip`, and `DataDomain::ApplicationVault` denies
all clipboard capabilities. Adapters must route it through `VaultStore`, never
`ClipStore`.

### Delegated product authorization

`cliptown-lib` does not verify a bearer. A trusted resource-server adapter must
verify the shared-auth signature or protected exact-audience introspection,
confirm session revocation, and map the result into `DelegatedClaims`.

The library then requires:

- exact configured issuer;
- sole audience `cliptown-api`;
- authorized party `memebank-api`;
- an active revocation-aware session;
- a current token identifier distinct from its parent;
- exactly one operation-appropriate scope;
- bounded issue, not-before, expiry, and lifetime values;
- fresh normalized LOA2 for write and delete operations.

The policy consumes normalized `aal`, `acr`, `amr`, and authoritative ceremony
time. It never identifies or contacts the factor application.

### Transfer and idempotency state

The encrypted-transfer state machine is terminal:

```text
pending -> acknowledged
        -> ignored
        -> rejected
        -> cancelled
        -> expired
```

Repeating the same terminal action is idempotent; a different terminal action
cannot reopen or rewrite the transfer. Expiry is computed from trusted time and
does not require a bulk persisted-state rewrite.

Idempotency keys bind the delegated subject, normalized route, operation,
canonical request digest, and expiry. An exact active match replays, an active
mismatch conflicts, and an expired binding may be replaced. Persistence
adapters are still responsible for transactions and concurrency locking.

## Conflict-resolution invariant

Sync cursors and logical revisions are monotonic. An adapter may merge
concurrent records according to the versioned contract, but it must never move
a cursor backward, substitute application-vault data for clipboard data, widen
a delegated scope, renew assurance from token-mint time, or reopen a terminal
transfer.

Git, schema, and generated-contract conflicts must be resolved from these
ownership and trust boundaries rather than by choosing one side mechanically.
The DEN-3287 foundation itself is the conceptual union of the initial encrypted
domain/ports implementation and the independently developed delegation and
transfer policy implementation.

## Compatibility and packaging

Breaking changes require a major crate version and coordinated contract review.
Additive wire fields belong first in `cliptown-interfaces`; adapters then map
them to domain behavior without changing existing meaning.

The Cargo crate remains dependency-free. The Zed package declares the versioned
interface dependency at the package graph level. Do not copy generated models
or fabricate `.zpkg.lock`; use the reviewed resolver and retain provenance.
