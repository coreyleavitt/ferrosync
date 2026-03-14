"""Tests for the ferrosync Python bindings."""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import pytest

import ferrosync
from ferrosync import (
    ChecksumType,
    DeleteMode,
    SyncResult,
    TransferOptions,
    Verbosity,
    async_sync_files,
    sync_files,
)


# ---------------------------------------------------------------------------
# TransferOptions
# ---------------------------------------------------------------------------


class TestTransferOptions:
    def test_defaults(self) -> None:
        opts = TransferOptions(source=["/src"], dest="/dst")
        assert not opts.recursive
        assert not opts.compress
        assert not opts.dry_run
        assert opts.delete == getattr(DeleteMode, "None")
        assert opts.verbosity == Verbosity.Normal
        assert opts.source == ["/src"]
        assert opts.dest == "/dst"

    def test_archive_mode(self) -> None:
        opts = TransferOptions(source=[], dest="/dst", archive=True)
        assert opts.is_archive()
        assert opts.recursive
        assert opts.preserve_links
        assert opts.preserve_perms
        assert opts.preserve_times
        assert opts.preserve_group
        assert opts.preserve_owner
        assert opts.preserve_devices
        assert opts.preserve_specials

    def test_individual_flags(self) -> None:
        opts = TransferOptions(
            source=["/a", "/b"],
            dest="/dst",
            recursive=True,
            compress=True,
            compress_level=3,
            delete=DeleteMode.During,
            dry_run=True,
            verbosity=Verbosity.Verbose,
            exclude=["*.tmp", "*.log"],
        )
        assert opts.recursive
        assert opts.compress
        assert opts.compress_level == 3
        assert opts.delete == DeleteMode.During
        assert opts.dry_run
        assert opts.verbosity == Verbosity.Verbose
        assert opts.exclude == ["*.tmp", "*.log"]
        assert opts.source == ["/a", "/b"]

    def test_compress_level_clamped(self) -> None:
        opts = TransferOptions(source=[], compress_level=99)
        assert opts.compress_level == 9
        opts = TransferOptions(source=[], compress_level=0)
        assert opts.compress_level == 1

    def test_optional_fields(self) -> None:
        opts = TransferOptions(
            source=[],
            bwlimit=1024,
            max_size=1_000_000,
            min_size=100,
            timeout=30,
        )
        assert opts.bwlimit == 1024
        assert opts.max_size == 1_000_000
        assert opts.min_size == 100
        assert opts.timeout == 30

    def test_no_optional_fields(self) -> None:
        opts = TransferOptions(source=[])
        assert opts.bwlimit is None
        assert opts.max_size is None
        assert opts.dest is None

    def test_repr(self) -> None:
        opts = TransferOptions(source=["/src"], dest="/dst", dry_run=True)
        r = repr(opts)
        assert "TransferOptions" in r
        assert "/src" in r
        assert "/dst" in r


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_delete_mode_values(self) -> None:
        assert getattr(DeleteMode, "None") == 0
        assert DeleteMode.Before == 1
        assert DeleteMode.During == 2
        assert DeleteMode.After == 3
        assert DeleteMode.Excluded == 4

    def test_verbosity_values(self) -> None:
        assert Verbosity.Quiet == 0
        assert Verbosity.Normal == 1
        assert Verbosity.Verbose == 2
        assert Verbosity.VeryVerbose == 3
        assert Verbosity.Debug == 4

    def test_checksum_type_values(self) -> None:
        assert getattr(ChecksumType, "None") == 0
        assert ChecksumType.Md4 == 1
        assert ChecksumType.Md5 == 2


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TestExceptions:
    def test_hierarchy(self) -> None:
        assert issubclass(ferrosync.ProtocolError, ferrosync.FerrosyncError)
        assert issubclass(ferrosync.TransportError, ferrosync.FerrosyncError)
        assert issubclass(ferrosync.FilesystemError, ferrosync.FerrosyncError)
        assert issubclass(ferrosync.FilterError, ferrosync.FerrosyncError)
        assert issubclass(
            ferrosync.ChecksumMismatchError, ferrosync.ProtocolError
        )

    def test_catchable(self) -> None:
        with pytest.raises(ferrosync.FerrosyncError):
            raise ferrosync.ProtocolError("test")

        with pytest.raises(ferrosync.ProtocolError):
            raise ferrosync.ChecksumMismatchError("test")


# ---------------------------------------------------------------------------
# sync_files -- real transfers
# ---------------------------------------------------------------------------


class TestSyncFiles:
    def test_single_file(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
        dst.mkdir()
        (src / "hello.txt").write_text("hello world")

        opts = TransferOptions(
            source=[str(src / "hello.txt")],
            dest=str(dst),
        )
        result = sync_files(opts)
        assert isinstance(result, SyncResult)
        assert result.files_transferred == 1
        assert (dst / "hello.txt").read_text() == "hello world"

    def test_recursive_directory(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        (src / "sub").mkdir(parents=True)
        dst.mkdir()
        (src / "a.txt").write_text("aaa")
        (src / "sub" / "b.txt").write_text("bbb")

        opts = TransferOptions(
            source=[str(src)],
            dest=str(dst),
            recursive=True,
        )
        result = sync_files(opts)
        assert result.files_transferred == 2
        assert (dst / "a.txt").read_text() == "aaa"
        assert (dst / "sub" / "b.txt").read_text() == "bbb"

    def test_dry_run(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
        dst.mkdir()
        (src / "file.txt").write_text("data")

        opts = TransferOptions(
            source=[str(src / "file.txt")],
            dest=str(dst),
            dry_run=True,
        )
        result = sync_files(opts)
        assert result.files_transferred == 1
        assert not (dst / "file.txt").exists()

    def test_exclude_pattern(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
        dst.mkdir()
        (src / "keep.txt").write_text("keep")
        (src / "skip.tmp").write_text("skip")

        opts = TransferOptions(
            source=[str(src)],
            dest=str(dst),
            recursive=True,
            exclude=["*.tmp"],
        )
        result = sync_files(opts)
        assert result.files_transferred == 1
        assert (dst / "keep.txt").exists()
        assert not (dst / "skip.tmp").exists()

    def test_delete_before(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
        dst.mkdir()
        (src / "keep.txt").write_text("keep")
        (dst / "extra.txt").write_text("extra")

        opts = TransferOptions(
            source=[str(src)],
            dest=str(dst),
            recursive=True,
            delete=DeleteMode.Before,
        )
        result = sync_files(opts)
        assert result.files_deleted == 1
        assert not (dst / "extra.txt").exists()

    def test_preserve_permissions(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
        dst.mkdir()
        script = src / "exec.sh"
        script.write_text("#!/bin/sh")
        os.chmod(script, 0o755)

        opts = TransferOptions(
            source=[str(script)],
            dest=str(dst),
            preserve_perms=True,
        )
        sync_files(opts)
        mode = os.stat(dst / "exec.sh").st_mode & 0o777
        assert mode == 0o755

    def test_stats_properties(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
        dst.mkdir()
        (src / "file.txt").write_text("some data here")

        opts = TransferOptions(
            source=[str(src / "file.txt")],
            dest=str(dst),
        )
        result = sync_files(opts)
        assert result.files_transferred == 1
        assert result.total_files == 1
        assert result.bytes_sent > 0
        assert result.total_size > 0
        assert result.elapsed_secs >= 0.0
        assert result.speedup >= 0.0
        assert "SyncResult" in repr(result)

    def test_missing_dest_raises(self) -> None:
        opts = TransferOptions(source=["/nonexistent"])
        with pytest.raises(ferrosync.FerrosyncError):
            sync_files(opts)

    def test_missing_source_raises(self, tmp_path: Path) -> None:
        opts = TransferOptions(
            source=[str(tmp_path / "nonexistent")],
            dest=str(tmp_path),
        )
        with pytest.raises(ferrosync.FilesystemError):
            sync_files(opts)


# ---------------------------------------------------------------------------
# Progress callback
# ---------------------------------------------------------------------------


class TestProgressCallback:
    def test_callback_receives_events(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
        dst.mkdir()
        (src / "file.txt").write_text("hello")

        events: list[dict] = []
        opts = TransferOptions(
            source=[str(src / "file.txt")],
            dest=str(dst),
        )
        sync_files(opts, progress_callback=lambda e: events.append(e))

        types = [e["type"] for e in events]
        assert "file_start" in types
        assert "file_complete" in types

    def test_logging_callback(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
        dst.mkdir()
        (src / "file.txt").write_text("hello")

        opts = TransferOptions(
            source=[str(src / "file.txt")],
            dest=str(dst),
        )
        # Should not raise.
        sync_files(
            opts,
            progress_callback=ferrosync.logging_progress_callback,
        )


# ---------------------------------------------------------------------------
# async_sync_files
# ---------------------------------------------------------------------------


class TestAsyncSyncFiles:
    def test_async_transfer(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
        dst.mkdir()
        (src / "file.txt").write_text("async test")

        async def do_transfer() -> SyncResult:
            opts = TransferOptions(
                source=[str(src / "file.txt")],
                dest=str(dst),
            )
            return await async_sync_files(opts)

        result = asyncio.run(do_transfer())
        assert result.files_transferred == 1
        assert (dst / "file.txt").read_text() == "async test"


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


class TestVersion:
    def test_version_exists(self) -> None:
        assert ferrosync.__version__
        assert isinstance(ferrosync.__version__, str)
        assert ferrosync.__version__ != "0.0.0-dev"
