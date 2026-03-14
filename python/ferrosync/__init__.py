"""ferrosync - rsync wire protocol implementation with Python bindings."""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Callable

try:
    from ferrosync._ferrosync import (
        __version__,
        # Enums
        ChecksumType,
        DeleteMode,
        Verbosity,
        # Classes
        FileEntry,
        SyncResult,
        TransferOptions,
        # Functions
        sync_files,
        # Exceptions
        ChecksumMismatchError,
        FerrosyncError,
        FilesystemError,
        FilterError,
        ProtocolError,
        TransportError,
    )
except ImportError:
    __version__ = "0.0.0-dev"

logger = logging.getLogger("ferrosync")


def logging_progress_callback(event: dict[str, Any]) -> None:
    """Progress callback that logs events via the ``ferrosync`` logger."""
    event_type = event.get("type", "")
    if event_type == "file_start":
        logger.info("Transferring %s (%d bytes)", event["name"], event["size"])
    elif event_type == "file_complete":
        logger.info(
            "Completed %s (literal=%d, matched=%d)",
            event["name"],
            event["literal_bytes"],
            event["matched_bytes"],
        )
    elif event_type == "file_skipped":
        logger.debug("Skipped %s (up to date)", event["name"])
    elif event_type == "file_deleted":
        logger.info("Deleted %s", event["name"])
    elif event_type == "overall_progress":
        logger.info(
            "Progress: %d/%d files, %d/%d bytes",
            event["files_done"],
            event["files_total"],
            event["bytes_transferred"],
            event["bytes_total"],
        )


async def async_sync_files(
    options: TransferOptions,
    *,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    checksum_seed: int = 0,
    checksum_type: ChecksumType = ChecksumType.Md5,
) -> SyncResult:
    """Async wrapper around :func:`sync_files`.

    Runs the transfer in a thread pool to avoid blocking the event loop.
    The function signature mirrors :func:`sync_files` exactly.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        functools.partial(
            sync_files,
            options,
            progress_callback=progress_callback,
            checksum_seed=checksum_seed,
            checksum_type=checksum_type,
        ),
    )


__all__ = [
    "__version__",
    # Enums
    "ChecksumType",
    "DeleteMode",
    "Verbosity",
    # Classes
    "FileEntry",
    "SyncResult",
    "TransferOptions",
    # Functions
    "sync_files",
    "async_sync_files",
    "logging_progress_callback",
    # Exceptions
    "ChecksumMismatchError",
    "FerrosyncError",
    "FilesystemError",
    "FilterError",
    "ProtocolError",
    "TransportError",
]
