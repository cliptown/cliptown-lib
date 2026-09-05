# ClipTown Lib agent policy

## Parent / root agent contract

The fleet-wide parent lives at:

- GitHub: https://github.com/oresoftware/my-ai/AGENTS.md
- Canonical disk path: `~/codes/oresoftware/my-ai/AGENTS.md`
- `~/codes/AGENTS.md` is a symlink to `~/codes/oresoftware/my-ai/AGENTS.md` (installed by `~/codes/oresoftware/my-ai/setup-final.sh`)

When this file and the parent disagree: follow this file for this repository's local layout and tools; follow the parent for org-wide conventions and the functional programming rules.

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

## Code style and coding patterns

remember to modularize the rust, typescript and dart - not everything belongs in main.rs, main.ts and main.dart; also follow functional coding principles - fewer side-effects (use pure functions more), more immutability (immutable variables); but for stateful apps like the client or stateful servers like websockets or tcp connections, sometimes classes and oop make more sense than functional programming perse, but we can still adhere to functional programming more than usual. Favor exhaustive pattern matching and use formal methods checking too. Favor composability and re-use , so basically create more utility functions and routines for shared use. You can follow a medium level of D.R.Y. (don't repeat yourself) - in other words you can repeat yourself at medium amount (not too much not too little). Some chaining is totally fine, so either method-chaining (immutable sometimes although with classes can be mutable too for performance), and chaining via the pipe operator is ok in languages like gleamlang.

Functional programming is mostly the following:

+ explicit inputs
+ explicit outputs
+ immutable values
+ pure transformations
+ typed errors
+ explicit state transitions
+ composition
+ effects pushed outward
+ illegal states excluded by types

## Repository-local Git worktrees

- Create or use a Git worktree only when the human operator explicitly authorizes it for the current task. Concurrency or a dirty checkout is not permission by itself.
- Put every authorized worktree at `<repository-root>/tmp/worktrees/<name>`; from the repository root, use `./tmp/worktrees/<name>`. Never place worktrees beside repositories or organization directories.
- Keep `tmp`, `temp`, `tmp/worktrees`, and `temp/worktrees` ignored in the repository-root `.gitignore`. Do not commit files from those directories.
- Relocate or remove a worktree only when the operator explicitly requests it. Before removal, preserve and publish intended changes, verify its commit is represented on the target branch, and confirm there are no tracked, untracked, ignored-sensitive, or in-use files that must survive. Remove it with `git worktree remove <path>` without `--force`; never delete a worktree directory with `rm`.
