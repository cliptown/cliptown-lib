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
- `cliptown-lib` owns transport-neutral Rust domain types, validation, policy,
  storage/transport ports, and invariants.
- [`cliptown/cliptown-clients`](https://github.com/cliptown/cliptown-clients)
  owns public language clients and runtime adapters.
- Backend, Flutter, native GPUI desktop, extension, and CLI repositories own
  concrete persistence, HTTP, UI, operating-system, and key-store adapters.

The first implementation milestone is tracked by Linear **DEN-3287**.

## Security boundary

The library models encrypted payloads only. Clipboard plaintext, encryption
keys, OTP seeds or codes, PINs, biometric templates, voiceprints, private
Signal state, bearer tokens, cloud credentials, and signed upload URLs must not
cross its persistence or sync ports.

Clipboard records and isolated application-vault records are different Rust
types. Application-vault records cannot be previewed, indexed, pasted,
exported, notified, or retained through the clipboard policy API. This
preserves the reciprocal 3FA integration boundary: 3FA may use ClipTown's
authenticated device substrate through opaque application-vault ciphertext,
while ClipTown may use 3FA only through short-lived, single-use,
request-context-bound step-up proofs defined by versioned interfaces.

Cross-product interoperability remains API/SDK-only. This library introduces
no shared database or cloud credentials, app-presence checks, deep-link
transport, local IPC/loopback, shared clipboard monitoring, or clipboard
fallback into MemeBank or another product.

## Initial modules

- `model`: validated identifiers, encrypted clipboard and application-vault
  records, monotonic sync cursors, and bounded sync pages.
- `policy`: retention constraints and capability decisions that keep vault data
  out of clipboard behavior.
- `ports`: dependency-inversion traits for persistence and sync adapters.
- `error`: dependency-free validation errors shared across the crate.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
```

The crate intentionally starts with no third-party Cargo dependencies. Concrete
cryptography, Postgres/Supabase, R2, HTTP, GPUI/Flutter, and operating-system
adapters belong in their owning repositories and must implement these ports
without weakening the domain boundary.
