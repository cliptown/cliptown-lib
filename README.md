# ClipTown Lib

Shared Rust library for ClipTown domain logic, authorization-safe primitives,
policy invariants, and reusable application services.

This repository is the independent library boundary in the canonical dependency
graph:

```text
cliptown-interfaces
        ↓
   cliptown-lib
      ↙      ↘
clients      CLI
```

- [`cliptown/cliptown-interfaces`](https://github.com/cliptown/cliptown-interfaces)
  owns versioned Protobuf, OpenAPI, and JSON Schema contracts.
- `cliptown-lib` owns transport-neutral Rust domain types, validation,
  authorization and transition policy, storage/transport ports, and invariants.
- [`cliptown/cliptown-clients`](https://github.com/cliptown/cliptown-clients)
  owns public language clients and runtime adapters.
- Backend, Flutter, native GPUI desktop, extension, and CLI repositories own
  concrete persistence, HTTP, UI, operating-system, and key-store adapters.

The first implementation milestone is tracked by Linear **DEN-3287**.

## Initial surfaces

### Encrypted clipboard and application-vault data

`EncryptedClip` and `EncryptedVaultRecord` are intentionally different types.
Clipboard records support bounded history and monotonic sync. Application-vault
records are opaque product data and cannot be previewed, indexed, pasted,
exported, notified, or retained through clipboard policy or `ClipStore`.

### Delegated authorization

`authorize_delegated_operation` accepts normalized claims only after a trusted
service adapter verifies the bearer and active session through shared-auth. It
enforces exact issuer, audience, authorized party, active session, token
lineage, sole operation scope, bounded time, and fresh LOA2 for writes/deletes.
The crate never parses JWTs, contacts an authenticator, or depends on which
factor application completed the ceremony.

### Transfer and idempotency state

The transfer primitives provide effective pending-to-expired state, terminal
acknowledge/ignore/reject/cancel transitions, idempotent repeated terminal
actions, and subject/route/operation/digest/expiry-bound idempotency decisions.
Storage adapters retain responsibility for transaction isolation, advisory
locks, and durable persistence.

## Security boundary

The library models encrypted payloads only. Clipboard plaintext, encryption
keys, OTP seeds or codes, PINs, biometric templates, voiceprints, private
Signal state, bearer tokens, cloud credentials, and signed upload URLs must not
cross its persistence or sync ports.

The reciprocal 3FA integration stays API/SDK-only: 3FA may use ClipTown's
authenticated device substrate through opaque application-vault ciphertext,
while ClipTown may use 3FA only through short-lived, single-use,
request-context-bound step-up proofs defined by versioned interfaces.

Cross-product interoperability introduces no shared database or cloud
credentials, app-presence checks, deep-link transport, local IPC/loopback,
shared clipboard monitoring, generated-interface source copies, or clipboard
fallback into MemeBank or another product.

## Modules

- `model`: validated identifiers, encrypted clipboard/application-vault records,
  monotonic sync cursors, and bounded sync pages.
- `policy`: retention constraints and capability decisions that keep vault data
  out of clipboard behavior.
- `ports`: separate clipboard/vault persistence and encrypted sync ports.
- `delegation`: normalized, fail-closed product authorization policy.
- `transfer`: terminal transfer state and digest-bound idempotency policy.
- `error`: validation failures shared across the domain core.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps
cargo package --allow-dirty --list
```

Review `.zpkg.toml` whenever package ownership, version, targets, or interface
dependencies change. Do not hand-author `.zpkg.lock`; generate it with the
reviewed resolver and commit its provenance when lock generation is introduced.
