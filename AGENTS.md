# ClipTown Lib agent policy

These instructions apply to automation and coding agents in this repository.

## Repository ownership

- `cliptown-interfaces` owns wire schemas and generated transport models.
- `cliptown-lib` owns transport-independent domain and application policy.
- `cliptown-clients` owns official network SDKs.
- `cliptown-cli` owns command-line presentation and orchestration.
- Backends own database, HTTP, secret, and deployment adapters.

Do not move those responsibilities into this crate merely to avoid a coordinated pull request.

## Required engineering workflow

1. Read the affected module, tests, architecture contract, and relevant consumer code.
2. Inspect both sides and the merge base when resolving conflicts. Preserve the conceptual union of independently valid security, state, and compatibility work; never select all of `ours` or all of `theirs` without analysis.
3. Add or update focused unit tests for every material policy or transition change.
4. Run formatting, Clippy with warnings denied, tests, documentation with warnings denied, and Zed metadata validation.
5. Use versioned interfaces, official SDKs, or immutable package artifacts for cross-repository integration.
6. Report exact validation evidence and remaining uncertainty.

## Security rules

- Never commit access tokens, private keys, customer data, raw private media, service credentials, or signed private URLs.
- Never parse or verify a bearer in this library. Accept normalized claims from a trusted service adapter.
- Never add direct database, object-store, browser, mobile-app discovery, deep-link, clipboard-monitoring, or local-IPC dependencies.
- Never weaken exact audience, client, session, scope, token-lineage, or fresh-assurance checks to make a consumer test pass.
- Never hand-author `.zpkg.lock`; use the reviewed resolver and commit its provenance when lock generation is introduced.

## Merge policy

Pull requests require green repository checks. Security-sensitive changes must include negative tests. Consumer migrations should be separate PRs that pin the exact merged library version or commit.
