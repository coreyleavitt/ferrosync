# Testing guide

This document defines how ferrosync is tested, where each kind of test lives, and how to write new tests. Every test must prove something specific -- if you can't say what would break if the test were deleted, the test shouldn't exist.

## Two things we prove

**Correctness** -- our code does what we intend. Tested locally, no rsync binary needed, fast feedback.

**Conformance** -- our code interoperates with rsync. Tested against the real rsync binary in Docker, slower.

Every test is one or the other. Never both.

## Test categories

### 1. Unit tests (`#[cfg(test)]` inline in source files)

**Purpose:** Individual functions and types work correctly in isolation.

**Location:** Inline in the source file being tested (e.g., `src/filelist/codec/tests.rs`, `src/protocol/varint.rs`).

**Dependencies:** None. No filesystem, no network, no Docker.

**When to add:** Any time you write or modify a function with non-trivial logic. Codec field functions, varint encoding, checksum computation, filter pattern matching, flag computation -- all belong here.

**Assertion standard:** Input-output equality, invariant checks.

**Property tests:** Use `proptest` for encode/decode roundtrips and functions with large input spaces. Existing property tests cover varint (6 tests) and codec entry roundtrip (2 tests). Add property tests when:
- A function has a roundtrip invariant (encode then decode = identity)
- The input space is too large for manual test cases (e.g., all u32 values)
- You've found a bug that was caused by an edge case a hand-written test missed

**Run:** `cargo test -p ferrosync-core --lib`

### 2. Engine tests (`tests/engine.rs`)

**Purpose:** The transfer engine produces the correct filesystem state for every flag/option we support. These test OUR code. If a flag is silently ignored, these tests catch it.

**Location:** `crates/ferrosync-core/tests/engine.rs`

**Dependencies:** Local filesystem only. No network, no Docker. Runs on all platforms (some metadata tests are Unix-only).

**When to add:** Any time you implement a new flag or modify transfer behavior. Every supported flag needs at least one engine test that verifies the flag's actual effect.

**Assertion standard:** Always verify the actual effect of the flag being tested. Ask: "what would be different if this flag were silently ignored?" and assert on THAT difference.

Examples:
- `--delete`: assert the extra file in dst is gone, not just that the transfer succeeded
- `--update`: assert the newer local file was NOT overwritten
- `--inplace`: assert the inode didn't change (same file was modified in place)
- `--checksum`: assert a same-size/same-mtime file WAS retransferred
- `--exclude`: assert the excluded file does NOT exist in dst, AND that included files DO exist

Use `assert_trees_match` with `TreeMatchOpts` for metadata-aware comparison:
```rust
assert_trees_match(&env.src(), &env.dst(), &TreeMatchOpts::archive());
```

Use `TestEnv::builder()` for test setup:
```rust
let env = TestEnv::builder()
    .with_src_file("keep.txt", b"content", Some(1700000000))
    .with_src_file("skip.txt", b"excluded", Some(1700000000))
    .with_dst_file("extra.txt", b"should be deleted", None)
    .build();
```

**Run:** `cargo test -p ferrosync-core --test engine`

### 3. Daemon tests (`tests/daemon.rs`)

**Purpose:** The daemon transport layer works: TCP connection, module resolution, handshake. NOT general transfer correctness (that's engine.rs).

**Location:** `crates/ferrosync-core/tests/daemon.rs`

**Dependencies:** Localhost TCP. No Docker.

**When to add:** Only for daemon-specific behavior: module auth, read-only enforcement, module listing, max connections, MOTD. Do NOT add transfer correctness tests here -- use engine.rs.

**Run:** `cargo test -p ferrosync-core --test daemon`

### 4. Wire conformance tests (`tests/wire.rs`)

**Purpose:** Our encoder produces byte-identical output to rsync for the same input. Field-by-field comparison using the diagnostic decoder. The strongest interop guarantee: if the bytes match, the protocol is correct.

**Location:** `crates/ferrosync-core/tests/wire.rs`

**Dependencies:** Docker (SSH to real rsync). Gated behind `FERROSYNC_SSH_TEST=1`.

**When to add:** When implementing or modifying any wire encoding (new XMIT flags, new field types, protocol version changes). Every wire format change should have a conformance test.

**Docker is your workbench:** The test containers are fully under our control. Install packages, create users, configure services, lay down fixtures -- whatever the test requires. Do not weaken a test or skip a scenario because the container "doesn't have X." Add X.

**How it works:**
1. Creates files on the remote rsync server via SSH
2. Connects as a pull client, captures raw file list bytes from rsync via `SpyReader`
3. Decodes entries in wire order (no sorting) using our decoder
4. Re-encodes those entries through our encoder
5. Diagnostic-decodes both byte streams and compares field by field

On divergence, the test reports exactly which field differs, at what byte offset, with hex dumps:
```
DIVERGENCE at field "mtime" (entry 2):
  rsync:     offset=47, bytes=[a0 b8 c1 94 0c], decoded=1700000000
  ferrosync: offset=47, bytes=[a0 b8 c1 94 0d], decoded=1700000001
```

**Run:** `docker compose -f docker-compose.test.yml run --rm ferrosync-dev cargo test -p ferrosync-core --test wire`

### 5. Interop tests (`tests/interop/`)

**Purpose:** End-to-end transfers against real rsync produce correct results. Files arrive with correct content and metadata.

**Location:** Split by direction and purpose:
```
tests/interop.rs              -- module root, shared imports
tests/interop/push.rs         -- ferrosync client pushes to rsync server
tests/interop/pull.rs         -- ferrosync client pulls from rsync server
tests/interop/reverse.rs      -- rsync client -> ferrosync --server
tests/interop/native.rs       -- ferrosync client -> ferrosync --server
tests/interop/scenarios.rs    -- multi-step real-world patterns
```

**Dependencies:** Docker (SSH to real rsync). Gated behind `FERROSYNC_SSH_TEST=1` or `skip_if_no_reverse!()`.

**Docker is your workbench:** Same principle as wire tests -- install whatever you need, create whatever filesystem state the scenario demands. Need ACLs? Install `acl`. Need a specific user/group? Create them. Need sparse files or hardlink farms? Build them in the container setup. The container exists to serve the test, not constrain it.

**When to add:** When you need to verify that a flag works end-to-end against real rsync -- not just that our engine handles it (engine.rs), but that the wire encoding, handshake, and remote rsync all agree.

**Where to put a new test:**
- Ferrosync pushing to rsync: `push.rs`
- Ferrosync pulling from rsync: `pull.rs`
- Rsync client to ferrosync server: `reverse.rs`
- Ferrosync to ferrosync: `native.rs`
- Multi-step workflows (backup rotation, mirror + delete, etc.): `scenarios.rs`

**Assertion standard:** MUST verify actual file content and relevant metadata. A `files_transferred` count is allowed as a supplementary check, never the primary assertion. Every test must answer: "what would be different if this flag were silently ignored?"

For push tests, verify remote content:
```rust
assert_remote_content(&format!("{remote_dir}/file.txt"), "expected content").await;
assert_remote_absent(&format!("{remote_dir}/deleted.txt")).await;
```

For pull tests, verify local content:
```rust
assert_file_content(&env.dst().join("file.txt"), b"expected content");
assert_file_absent(&env.dst().join("excluded.txt"));
```

**Run:** `docker compose -f docker-compose.test.yml run --rm ferrosync-dev cargo test -p ferrosync-core --test interop`

## Decision tree: where does my test go?

```
Is it testing a single function/type in isolation?
  YES -> unit test (inline #[cfg(test)])

Does it need to verify filesystem state after a transfer?
  YES -> Does it need real rsync?
    NO  -> engine.rs
    YES -> Does it need to verify wire bytes?
      YES -> wire.rs
      NO  -> interop/ (pick the right submodule by direction)

Is it testing daemon-specific behavior (auth, modules, TCP)?
  YES -> daemon.rs
```

## Shared test infrastructure

### `tests/common/env.rs` -- test environment builder

```rust
let env = TestEnv::builder()
    .with_src_file("path/to/file.txt", b"content", Some(unix_mtime))
    .with_src_dir("empty_dir")
    .with_src_symlink("target.txt", "link.txt")      // Unix only
    .with_dst_file("existing.txt", b"old", Some(mtime))  // pre-existing dest
    .with_prev_file("snapshot.txt", b"prev", Some(mtime)) // for --link-dest
    .build();

env.src()  // -> PathBuf to src/
env.dst()  // -> PathBuf to dst/
env.prev() // -> PathBuf to prev/
```

### `tests/common/assertions.rs` -- assertion helpers

**Local file assertions:**
- `assert_file_content(path, expected_bytes)` -- file has expected content
- `assert_file_exists(path)` -- file exists
- `assert_file_absent(path)` -- file does not exist
- `assert_mtime(path, expected_unix, tolerance_secs)` -- mtime matches
- `assert_permissions(path, expected_mode)` -- Unix permissions match
- `assert_hard_linked(a, b)` -- same inode
- `assert_not_hard_linked(a, b)` -- different inodes

**Tree assertions:**
- `assert_trees_equal(expected, actual)` -- content only
- `assert_trees_match(expected, actual, &TreeMatchOpts)` -- content + optional metadata

```rust
TreeMatchOpts::content_only()  // just file content
TreeMatchOpts::with_perms()    // content + permissions
TreeMatchOpts::with_mtime()    // content + mtime
TreeMatchOpts::archive()       // content + perms + mtime
```

**Remote (SSH) assertions:**
- `assert_remote_content(path, expected_str).await`
- `assert_remote_exists(path).await`
- `assert_remote_absent(path).await`

### `tests/common/ssh.rs` -- SSH/Docker helpers

- `skip_if_no_ssh!()` -- skip test if `FERROSYNC_SSH_TEST` not set
- `skip_if_no_reverse!()` -- skip if ferrosync binary not on target
- `ssh_cmd(args)` -- run SSH command on target
- `remote_tmpdir()` -- create temp dir on target
- `remote_cleanup(dir)` -- remove remote dir
- `remote_cat(path)` -- read remote file
- `remote_exists(path)` -- check remote file exists
- `push_with_opts(opts, remote_dir, timeout)` -- push transfer
- `pull_with_opts(opts, remote_path, timeout)` -- pull transfer

## Running tests

```bash
# Fast local tests (no Docker)
cargo test -p ferrosync-core --lib
cargo test -p ferrosync-core --test engine
cargo test -p ferrosync-core --test daemon

# Docker tests (requires containers running)
docker compose -f docker-compose.test.yml up -d --build
docker compose -f docker-compose.test.yml run --rm ferrosync-dev \
    cargo test -p ferrosync-core --test wire
docker compose -f docker-compose.test.yml run --rm ferrosync-dev \
    cargo test -p ferrosync-core --test interop

# Everything
docker compose -f docker-compose.test.yml run --rm ferrosync-dev \
    cargo test -p ferrosync-core
```

## CI

The GitHub Actions CI runs tests in two jobs:

**`test` job** (3-platform matrix: Linux, macOS, Windows):
- `cargo test --lib` -- unit tests
- `cargo test --test engine` -- engine tests (Unix only)
- `cargo test --test daemon` -- daemon tests

**`interop` job** (Linux only, Docker):
- `cargo test --test wire` -- wire conformance
- `cargo test --test interop` -- interop tests

## Adding a new flag: checklist

1. **Engine test (required):** Add a test in `tests/engine.rs` that verifies the flag's actual effect on the local filesystem. This is the primary correctness test -- it runs fast, needs no Docker, and catches regressions immediately. The test must answer: "what would be different if this flag were silently ignored?" Assert on THAT difference, not just "transfer completed." For example:
   - `--delete`: assert the extra dest file is gone
   - `--update`: assert the newer dest file was NOT overwritten
   - `--inplace`: assert the inode didn't change
   - `--hard-links`: assert linked files share an inode at destination

   Some flags only affect the SSH wire path (e.g., `--bwlimit` throttles remote rsync output). These still need an engine test if they have any local behavior, even partial. Document in the test what is and isn't covered locally.

2. Add wire conformance test in `tests/wire.rs` if the flag affects file list encoding (new XMIT flag bits, new wire fields). Use the `run_conformance` helper.

3. Add interop test in the appropriate `tests/interop/` submodule if the flag needs end-to-end validation against real rsync.

4. Add unit tests for any new codec functions (encode/decode pair) inline in the source.

5. Consider a proptest if the new encoding has a roundtrip invariant.
