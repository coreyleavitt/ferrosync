# Design philosophy

This document captures architectural decisions and the reasoning behind them. These are not arbitrary preferences -- each reflects a specific trade-off evaluation.

## Safety and correctness over simplicity

When choosing between design approaches, prioritize safety, correctness, elegance, maintainability, and architectural soundness over simplicity or expediency. An enum dispatch may be "simpler" but a trait may be more correct if it enforces separation of concerns. Three similar lines of code is better than a premature abstraction. Be bold in pursuing the right design -- "safe" means structurally sound and secure, not timid.

## Embrace breaking changes

The API is not set in stone. If a breaking change results in better code -- cleaner interfaces, stronger invariants, better separation of concerns -- make the breaking change. Do not preserve a suboptimal API out of inertia. The cost of carrying a bad interface forward always exceeds the cost of fixing callers now.

## Fix the architecture, don't patch symptoms

When a design is fundamentally wrong, fix the design instead of adding workarounds. Increasing a buffer size to avoid a deadlock moves the threshold, not the root cause. Don't defer correctness to future versions.

## SSH transport architecture

Ferrosync uses an asymmetric SSH architecture:

**Client side: russh (integrated Rust library).** No dependency on the user having OpenSSH installed, no `ssh` subprocess to manage, no shell quoting issues on the local side, full control over connection lifecycle in async Rust. This is strictly better than shelling out to `ssh`.

**Server side: sshd (external, via `--server` mode over stdio).** When a remote host runs `ferrosync --server`, it is invoked by the host's existing sshd, reading and writing the rsync wire protocol over stdin/stdout. This is the same architecture rsync, git, and scp use.

The asymmetry is intentional because the concerns differ:

- The **client** wants tight integration -- connection pooling, async I/O, structured error handling. russh delivers that.
- The **server** wants to inherit the host's existing security posture -- key management, PAM, privilege separation, chroot, audit logging. sshd delivers that with decades of hardening that no embedded SSH server can match.

A built-in russh SSH server would mean owning a pre-auth attack surface forever, re-implementing key management, losing compatibility with users' existing SSH configs (agent forwarding, ProxyJump, authorized_keys), and duplicating security work that OpenSSH already handles. The only case where it would make sense is embedded/appliance use where sshd cannot be installed.

### Remote shell exec is unavoidable

The SSH protocol (RFC 4254) defines exec channels as shell command strings. Even a clean `ferrosync --server --sender -logDtprze.LsfxCIvu . /path` is passed through the remote user's login shell by sshd. This is inherent to SSH exec channels and cannot be bypassed. The `command -v ferrosync ... || rsync ...` fallback is a convenience layer on top of something that is already a shell command.

## Daemon mode

The `--daemon` mode listens on TCP with the rsync daemon text protocol (module listing, challenge-response auth). This is unencrypted, matching rsync's own `rsyncd`. It exists for rsync protocol compatibility, not as a recommended production deployment. For production use, SSH transport is the primary path.

## Crate architecture

Ferrosync is split into 13 crates in a layered DAG. Each crate has a single responsibility and clean dependency boundaries enforced by the compiler.

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

**Key boundary decisions:**

- **types** contains traits (FileSystem) and data types (FileEntry), not implementations. The compiler enforces that implementations can't accidentally depend on each other.
- **transport is client-only.** The server accepts connections (TCP/stdio), it doesn't initiate them. This keeps russh, rustls, quinn, and snow out of server deployments.
- **scanner and codec are peers**, not parent-child. Scanner needs filesystem + filter (to discover files). Codec needs protocol + delta (to encode files). They share FileEntry via types but don't depend on each other.
- **engine is the honest integration point.** Orchestration IS integration. It depends on most crates, and that's correct -- the key is that each dependency flows through a clean crate API.

## Connection-driven concurrent I/O

MuxConnection owns both halves of a multiplexed connection and drives them concurrently at the frame level. flush() uses `tokio::select!` to drain incoming reads while waiting for writes to complete, preventing deadlock without background tasks, channels, or unbounded buffers. This follows the HTTP/2 and QUIC model: concurrent I/O belongs in the connection layer, not bolted on via tasks.

## Decision/I/O separation

`dispatch_entry()` on ReceiverEngine makes ALL per-file decisions (directory creation, symlink handling, skip checks, link-dest, copy-dest, hardlink deferral, dry-run) and returns an `EntryAction` telling the caller what to do about data. The caller handles I/O differently per transfer path:

- Local engine: computes delta inline from source files
- Wire pipelined generator: sends signatures on wire, runs ahead
- Wire pipelined receiver: reads deltas from wire, applies transfers

One decision function, multiple I/O strategies. No feature gaps between paths.

## Composable enrichment pipeline

FileListScanner processes directory children through pluggable enrichers. Each enricher adds per-file metadata independently: SymlinkEnricher reads symlink targets, AclEnricher reads POSIX ACLs, XattrEnricher reads extended attributes, HardLinkGrouper detects hardlink groups. Adding a new metadata type means implementing one enricher, not modifying the scanner.

## Testing

See [testing.md](testing.md) for the test architecture. The key principle: every test proves something specific. "Transfer completed without error" is not a test.
