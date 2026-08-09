# Contributing to ClipTown Lib

Changes should preserve the repository boundary described in `docs/architecture.md` and `AGENTS.md`.

## Before opening a pull request

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps
```

Review `.zpkg.toml` whenever package ownership, version, targets, or interface dependencies change. Do not create `.zpkg.lock` manually; use the reviewed resolver and include its provenance.

## Policy changes

Authorization, assurance, transfer-state, expiry, or idempotency changes require negative tests as well as successful-path tests. Keep transport verification, HTTP, persistence, secrets, and UI adapters out of this crate.

## Cross-repository changes

Land this repository first with green checks, then update clients, CLI, backend, and monorepo pointers in separate PRs pinned to the exact merged commit or released package version.
