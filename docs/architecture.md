# Architecture and ownership

## Dependency direction

Applications and adapters depend on `cliptown-lib`; this library depends only
on the Rust standard library. Generated contract models may be adapted at the
repository boundary, but wire-format concerns do not leak into the domain
core.

```text
cliptown-interfaces  -> generated/wire adapters
                              |
                              v
                       cliptown-lib
                       /    |     \
                 storage  sync   application policy
                    |       |          |
                    v       v          v
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

## Conflict-resolution invariant

Sync cursors and logical revisions are monotonic. An adapter may merge
concurrent records according to the versioned contract, but it must never move
a cursor backward or silently substitute application-vault data for clipboard
data. Git or schema conflicts must be resolved from these ownership and trust
boundaries rather than by choosing one side mechanically.

## Compatibility

Breaking changes require a major crate version and coordinated contract review.
Additive fields belong first in `cliptown-interfaces`; adapters then map them to
new domain behavior without changing the interpretation of existing fields.
