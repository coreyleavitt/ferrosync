# Contributing to ferrosync

## Issue labels

Every issue gets exactly one label describing what kind of work it is:

| Label | Use for |
|-------|---------|
| `bug` | Something that's broken -- incorrect behavior, crash, data corruption |
| `feature` | New user-facing capability -- a flag, protocol mode, or integration |
| `performance` | Speed, memory, or throughput optimization -- no behavioral change |
| `architecture` | Internal structure improvement -- refactoring, crate splits, API cleanup |
| `testing` | Test coverage, test infrastructure, CI improvements |
| `security` | Security vulnerability fix -- unbounded allocation, path traversal, etc. |
| `documentation` | Documentation only -- no code changes |
| `platform` | Platform-specific work -- macOS, Windows, BSD support |

**Don't use:**
- `enhancement` (too vague -- use `feature`, `performance`, or `architecture`)
- Compound labels like `enhancement/performance` (pick the primary concern)

## Milestones

Issues are grouped by release milestone reflecting when they'll ship:

| Milestone | Scope |
|-----------|-------|
| **v1.0 - Feature Complete** | rsync feature parity -- all flags working, test coverage, solid architecture |
| **v1.1 - Cross-Platform** | macOS, Windows, BSD platform support for platform-dependent features |
| **v2.0 - Performance** | Parallelism (rayon), async I/O (io_uring/IOCP), zero-copy, memory optimization |
| **v3.0 - Native Protocol** | ferrosync-to-ferrosync protocol extensions beyond rsync compatibility |
| **v4.0 - Research** | Speculative features that may never ship (dedup, P2P, WASM) |

Closed milestones (historical, all issues resolved):
- **v0.x - Foundation** -- initial security audit, core protocol correctness
- **v0.x - Wire Interop** -- rsync wire compatibility, first interop tests

**Choosing a milestone:** Ask "when does this need to ship?" If it blocks rsync parity → v1.0. If it's platform-specific → v1.1. If it's about speed → v2.0. If it requires both sides to be ferrosync → v3.0. If it's speculative → v4.0.

## Crate structure

```
                      ferrosync-types (foundation)
                           │
            ┌──────┬───────┼───────┬──────────┐
            │      │       │       │          │
         delta    fs    filter  protocol  transport
            │      │       │       │      (client only)
            │      └───┬───┘       │          │
            │          │           │          │
            │     scanner       codec        │
            │          │           │          │
            └──────────┴─────┬─────┴──────────┘
                             │
                          engine
                             │
                    ┌────────┴────────┐
                    │                 │
              core (facade)      server
```

See [design-philosophy.md](design-philosophy.md) for architectural decisions and [testing.md](testing.md) for test conventions.

## Commit messages

- Lead with what changed, not how
- Reference issue numbers (`#123`)
- No AI/automation attribution
- Keep the first line under 72 characters

## Code style

- `cargo fmt` and `cargo clippy -- -D warnings` must pass
- Prefer safe, correct, elegant code over simple code (see design-philosophy.md)
- Every test must answer: "what would be different if this flag were silently ignored?"
