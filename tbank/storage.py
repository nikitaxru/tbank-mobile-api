"""
Pluggable storage for persistent client state.

The library needs to survive across process restarts — the ``refresh_token``
is meaningless if you lose it on ``SIGTERM``. :class:`Storage` is the
abstract interface for "somewhere I can keep a few small JSON blobs"; the
default :class:`FileStorage` writes to disk, :class:`MemoryStorage` keeps
everything in-process (useful for tests), and callers can plug in their own
backend to use OS keychains, encrypted vaults, etc.

Typed accessors — ``load_identity``, ``save_tokens`` etc. — live on
:class:`State`, which wraps a ``Storage`` and hides the string-key layout.
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from tbank.models.auth import Tokens

# -----------------------------------------------------------------------------
# Storage backends
# -----------------------------------------------------------------------------

class Storage(ABC):
    """
    Abstract key/value blob store.

    All values are ``bytes``. Callers are responsible for serialization —
    :class:`State` in this module uses UTF-8 JSON.
    """

    @abstractmethod
    def read(self, key: str) -> bytes | None:
        """Return the value for ``key`` or ``None`` if it's missing."""

    @abstractmethod
    def write(self, key: str, data: bytes) -> None:
        """Persist ``data`` under ``key``, overwriting any existing value."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Remove ``key`` if present; no-op otherwise."""

    @abstractmethod
    def keys(self) -> Iterable[str]:
        """Enumerate all keys currently stored."""


class MemoryStorage(Storage):
    """
    In-process dict-backed :class:`Storage`. For tests and short-lived
    scripts where you don't want to touch the disk.
    """

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}

    def read(self, key: str) -> bytes | None:
        return self._data.get(key)

    def write(self, key: str, data: bytes) -> None:
        self._data[key] = data

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def keys(self) -> Iterable[str]:
        return list(self._data.keys())


class FileStorage(Storage):
    """
    File-backed :class:`Storage`. One file per key under a directory.

    - Directory is created if it doesn't exist, with ``mode=0o700``.
    - Each file is written atomically via rename — a crash mid-write
      either leaves the old content intact or replaces it entirely.
    - On write, the file is chmod'd to ``0o600`` so that other local
      users can't read credentials.
    """

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self._dir = Path(directory).expanduser()
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, key: str) -> Path:
        if "/" in key or "\\" in key or ".." in key or not key:
            raise ValueError(f"Invalid storage key: {key!r}")
        return self._dir / f"{key}.json"

    def read(self, key: str) -> bytes | None:
        path = self._path(key)
        if not path.exists():
            return None
        return path.read_bytes()

    def write(self, key: str, data: bytes) -> None:
        path = self._path(key)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_bytes(data)
        tmp.chmod(0o600)
        tmp.replace(path)  # atomic on POSIX

    def delete(self, key: str) -> None:
        path = self._path(key)
        path.unlink(missing_ok=True)

    def keys(self) -> Iterable[str]:
        return [p.stem for p in self._dir.glob("*.json")]


# -----------------------------------------------------------------------------
# Typed state layer
# -----------------------------------------------------------------------------

KEY_IDENTITY = "identity"
KEY_TOKENS = "tokens"
KEY_PKCE = "pkce"
KEY_FLOW = "flow"


class State:
    """
    Typed accessor over a :class:`Storage`.

    Provides get/set for each piece of state we need: device identity,
    tokens, current auth flow, PKCE pair. Handles JSON (de)serialization
    so the ``Storage`` implementation only has to worry about bytes.

    State is designed to be mostly independent per key — writing tokens
    doesn't touch identity, so a partial corruption of one file doesn't
    destroy the rest.
    """

    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    # ------------------- identity -------------------

    def read_identity(self) -> dict[str, Any] | None:
        return self._read_json(KEY_IDENTITY)

    def write_identity(self, data: dict[str, Any]) -> None:
        self._write_json(KEY_IDENTITY, data)

    # ------------------- tokens -------------------

    def read_tokens(self) -> Tokens | None:
        data = self._read_json(KEY_TOKENS)
        if data is None:
            return None
        return Tokens.from_dict(data)

    def write_tokens(self, tokens: Tokens) -> None:
        self._write_json(KEY_TOKENS, tokens.to_dict())

    def clear_tokens(self) -> None:
        self._storage.delete(KEY_TOKENS)

    # ------------------- transient auth flow -------------------

    def read_flow(self) -> dict[str, Any] | None:
        return self._read_json(KEY_FLOW)

    def write_flow(self, data: dict[str, Any]) -> None:
        self._write_json(KEY_FLOW, data)

    def clear_flow(self) -> None:
        self._storage.delete(KEY_FLOW)

    # ------------------- PKCE (per-flow secret) -------------------

    def read_pkce(self) -> dict[str, Any] | None:
        return self._read_json(KEY_PKCE)

    def write_pkce(self, data: dict[str, Any]) -> None:
        self._write_json(KEY_PKCE, data)

    def clear_pkce(self) -> None:
        self._storage.delete(KEY_PKCE)

    # ------------------- JSON helpers -------------------

    def _read_json(self, key: str) -> dict[str, Any] | None:
        raw = self._storage.read(key)
        if raw is None:
            return None
        decoded = json.loads(raw.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise TypeError(f"Stored value under {key!r} is not a dict")
        return decoded

    def _write_json(self, key: str, data: dict[str, Any]) -> None:
        encoded = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self._storage.write(key, encoded)
