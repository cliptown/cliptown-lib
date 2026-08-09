# ClipTown library architecture

## Position in the dependency graph

```text
cliptown-interfaces
        ↓
   cliptown-lib
      ↙      ↘
clients      CLI
```

`cliptown-interfaces` owns versioned wire types and schemas. `cliptown-lib` owns reusable domain rules and application-policy primitives. Transport clients and command-line presentation remain in their own repositories.

The Zed package declares the interface dependency immediately. The Rust crate does not copy generated interface models into this repository; a reviewed registry or workspace adapter will bind those models to these domain primitives without making source-tree layout a runtime dependency.

## Security boundary

The library does not parse JWTs, fetch JWKS, contact shared-auth, or inspect a factor application. A trusted service adapter verifies the bearer, performs revocation-aware exact-audience introspection, and passes normalized claims into `authorize_delegated_operation`.

That policy then requires:

- exact configured issuer;
- sole audience `cliptown-api`;
- authorized party `memebank-api`;
- active revocation-aware session;
- a current token identifier distinct from its parent;
- exactly one operation scope;
- bounded not-before, expiry, and lifetime;
- fresh normalized LOA2 for write and delete operations.

No rule depends on which authenticator product supplied the ceremony. The library accepts normalized `aal`, `acr`, `amr`, and authoritative authentication time only.

## Transfer semantics

The transfer state machine is deliberately small and terminal:

```text
pending → acknowledged
        → ignored
        → rejected
        → cancelled
        → expired
```

A terminal transfer cannot be reopened. Repeating the same acknowledgement or cancellation is idempotent. Expiry is computed from trusted time and does not require rewriting every pending row.

Idempotency keys bind the delegated subject, normalized route, operation, canonical request digest, and expiry. An exact active match replays; a mismatched active binding conflicts; an expired binding may be replaced. Storage adapters remain responsible for transaction isolation and advisory locking.

## Repository boundaries

This repository must not acquire:

- database or object-store credentials;
- direct access to another product's persistence layer;
- HTTP route handlers or UI code;
- mobile application discovery or deep-link transport;
- clipboard monitoring or API-failure clipboard fallback;
- handwritten generated interface copies;
- fabricated `.zpkg.lock` files.

Material changes require tests here and coordinated consumer PRs in clients, CLI, backend, and monorepo pointers as applicable.
