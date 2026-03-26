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

## Testing

See [testing.md](testing.md) for the test architecture. The key principle: every test proves something specific. "Transfer completed without error" is not a test.
