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

## Security boundary

- No direct access to another product's database or cloud credentials.
- Authentication and assurance inputs are normalized by shared-auth at service boundaries.
- Cross-repository dependencies use versioned interfaces, SDKs, or immutable package artifacts.
- The library must not introduce mobile-app installation checks, deep-link transport, local IPC, or clipboard fallback into MemeBank interoperability.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```
