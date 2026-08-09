# DEN-3287 foundation evidence

## Repository creation

`cliptown/cliptown-lib` is the independent public shared-library repository in
the canonical ClipTown dependency graph. It was created through a one-time,
encrypted owner-credential workflow; no plaintext owner token, deploy key, or
long-lived repository secret was committed. The temporary creator workflows and
encrypted handoff files were removed after repository verification.

## Semantic history reconciliation

Multiple agents produced valid foundations concurrently:

1. encrypted clipboard/application-vault domain models, retention policy, ports,
   Cargo lock, Rust 2024/1.88 configuration, and initial Zed packaging;
2. exact shared-auth delegated authorization, terminal transfer/idempotency
   policy, architecture and agent rules, and stronger CI;
3. resolver-lock retention and canonical Rust formatting.

The resulting `main` history uses real multi-parent merge commits rather than
selecting all of one side:

- `eeca867a46f2b56057bd123f198d1b6564b3f320` combines the encrypted domain
  foundation with delegation/transfer policy;
- `23dc268cb2e680b13df62ff79bf0cad2e4d8b425` reconciles the two parallel
  semantic merges;
- `da326fca089baedc9fcd1094b92eb542e3002253` retains the resolver-produced Zed
  lock while preserving the latest merged source;
- `279ef85bc1e4f818a26f32a605aea5e19a98b0a3` applies bounded Rust 1.88
  formatting and removes its one-shot formatter.

## Preserved invariants

The combined foundation retains:

- a dependency-free Cargo domain crate;
- encrypted clipboard and isolated application-vault types;
- separate clipboard, vault, and sync ports;
- exact issuer/audience/client/session/current-parent-lineage/scope policy;
- fresh normalized LOA2 for delegated writes and deletes;
- terminal transfer transitions and digest-bound idempotency;
- Cargo lock version 4 and Zed resolver lock version 1;
- versioned `cliptown/cliptown-interfaces` Zed dependency;
- no copied generated interface source;
- no JWT, HTTP, database, cloud, mobile-discovery, deep-link, local-IPC, or
  clipboard-fallback implementation in the domain crate.

## Required permanent validation

The permanent `CI` workflow, rather than any temporary formatter, is the merge
and release evidence. It must pass:

```sh
cargo metadata --locked --format-version 1 --no-deps
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps --all-features
cargo package --allow-dirty --list
```

CI also checks Cargo/Zed metadata and locks and rejects credential-shaped tracked
content.
