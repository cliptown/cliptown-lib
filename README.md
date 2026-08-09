# ClipTown Lib

Shared Rust library for ClipTown domain logic, authorization-safe primitives, and reusable application services.

This repository is the independent library boundary in the canonical dependency graph:

```text
cliptown-interfaces
        ↓
   cliptown-lib
      ↙      ↘
clients      CLI
```

The first implementation milestone is tracked by Linear **DEN-3287**. Public APIs, Zed package metadata, tests, and consumer migrations land through reviewed pull requests rather than being embedded in `cliptown-clients` or the monorepo.

## Initial surfaces

### Delegated authorization

`authorize_delegated_operation` accepts normalized claims only after a trusted service adapter has verified the bearer and active session through shared-auth. It enforces:

- exact issuer, `aud=cliptown-api`, and `azp=memebank-api`;
- active revocation-aware session;
- a current token ID distinct from its parent;
- exactly one read, write, or delete scope;
- bounded token time;
- recent normalized LOA2 for writes and deletes.

The crate does not parse JWTs, contact an authenticator, or distinguish which factor application completed the ceremony.

### Transfer and idempotency state

The transfer primitives provide:

- effective pending-to-expired state;
- terminal acknowledge, ignore, reject, and cancel transitions;
- idempotent repeated terminal actions;
- subject-, route-, operation-, digest-, and expiry-bound idempotency decisions.

Storage adapters retain responsibility for transaction isolation, advisory locks, and persistence.

## Security boundary

- No direct access to another product's database or cloud credentials.
- Authentication and assurance inputs are normalized by shared-auth at service boundaries.
- Cross-repository dependencies use versioned interfaces, SDKs, or immutable package artifacts.
- The library must not introduce mobile-app installation checks, deep-link transport, local IPC, or clipboard fallback into MemeBank interoperability.
- Generated interface source is not copied into this repository.
- `.zpkg.lock` is generated only by the reviewed resolver, never fabricated manually.

See [the architecture contract](docs/architecture.md) for ownership and transition details.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps
```
