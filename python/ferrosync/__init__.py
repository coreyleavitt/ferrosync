"""ferrosync - rsync wire protocol implementation with Python bindings."""

from __future__ import annotations

try:
    from ferrosync._ferrosync import __version__
except ImportError:
    __version__ = "0.0.0-dev"

__all__ = ["__version__"]
