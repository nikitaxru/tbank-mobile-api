"""Unit tests for :mod:`tbank.storage`."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from tbank.models.auth import Tokens
from tbank.storage import FileStorage, MemoryStorage, State

# =============================================================================
# MemoryStorage
# =============================================================================

class TestMemoryStorage:
    def test_write_and_read(self) -> None:
        s = MemoryStorage()
        s.write("foo", b"bar")
        assert s.read("foo") == b"bar"

    def test_read_missing_returns_none(self) -> None:
        s = MemoryStorage()
        assert s.read("missing") is None

    def test_delete(self) -> None:
        s = MemoryStorage()
        s.write("foo", b"bar")
        s.delete("foo")
        assert s.read("foo") is None

    def test_delete_missing_is_noop(self) -> None:
        MemoryStorage().delete("never_existed")  # must not raise

    def test_keys(self) -> None:
        s = MemoryStorage()
        s.write("a", b"1")
        s.write("b", b"2")
        assert sorted(s.keys()) == ["a", "b"]

    def test_overwrite(self) -> None:
        s = MemoryStorage()
        s.write("foo", b"first")
        s.write("foo", b"second")
        assert s.read("foo") == b"second"


# =============================================================================
# FileStorage
# =============================================================================

class TestFileStorage:
    def test_round_trip(self, tmp_path: Path) -> None:
        s = FileStorage(tmp_path / "dir")
        s.write("foo", b"bar")
        assert s.read("foo") == b"bar"

    def test_creates_directory(self, tmp_path: Path) -> None:
        target = tmp_path / "does" / "not" / "exist"
        FileStorage(target)
        assert target.is_dir()

    def test_atomic_overwrite(self, tmp_path: Path) -> None:
        """A second write replaces the first atomically (tmp + rename)."""
        s = FileStorage(tmp_path / "dir")
        s.write("foo", b"first")
        s.write("foo", b"second")
        assert s.read("foo") == b"second"

    def test_delete(self, tmp_path: Path) -> None:
        s = FileStorage(tmp_path / "dir")
        s.write("foo", b"bar")
        s.delete("foo")
        assert s.read("foo") is None

    def test_delete_missing_is_noop(self, tmp_path: Path) -> None:
        FileStorage(tmp_path / "dir").delete("never_existed")

    def test_keys(self, tmp_path: Path) -> None:
        s = FileStorage(tmp_path / "dir")
        s.write("alpha", b"1")
        s.write("beta", b"2")
        assert sorted(s.keys()) == ["alpha", "beta"]

    def test_file_mode_is_restrictive(self, tmp_path: Path) -> None:
        """Files must be mode 0o600 so other local users can't read secrets."""
        root = tmp_path / "dir"
        s = FileStorage(root)
        s.write("foo", b"bar")
        mode = (root / "foo.json").stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"

    def test_rejects_path_traversal(self, tmp_path: Path) -> None:
        s = FileStorage(tmp_path / "dir")
        for bad_key in ("..", "../escape", "foo/bar", "foo\\bar", ""):
            with pytest.raises(ValueError):
                s.write(bad_key, b"x")
            with pytest.raises(ValueError):
                s.read(bad_key)

    def test_survives_process_restart(self, tmp_path: Path) -> None:
        """Two separate FileStorage instances over the same dir see the same data."""
        dir_ = tmp_path / "dir"
        FileStorage(dir_).write("foo", b"first")
        assert FileStorage(dir_).read("foo") == b"first"


# =============================================================================
# State — typed layer on top of Storage
# =============================================================================

class TestState:
    def test_identity_round_trip(self) -> None:
        state = State(MemoryStorage())
        data = {"device_id": "x", "tinkoff_device_id": "y", "stable_id": "z"}
        state.write_identity(data)
        assert state.read_identity() == data

    def test_identity_missing_returns_none(self) -> None:
        assert State(MemoryStorage()).read_identity() is None

    def test_tokens_round_trip(self) -> None:
        state = State(MemoryStorage())
        now = dt.datetime.now(dt.UTC).replace(microsecond=0)
        tokens = Tokens(
            access_token="t.aaa",
            refresh_token="r.bbb",
            token_type="Bearer",
            issued_at=now,
            expires_at=now + dt.timedelta(hours=2),
            id_token="id.ccc",
            scope="openid",
        )
        state.write_tokens(tokens)
        loaded = state.read_tokens()
        assert loaded == tokens

    def test_tokens_missing_returns_none(self) -> None:
        assert State(MemoryStorage()).read_tokens() is None

    def test_clear_tokens(self) -> None:
        state = State(MemoryStorage())
        now = dt.datetime.now(dt.UTC)
        state.write_tokens(
            Tokens(
                access_token="t",
                refresh_token="r",
                token_type="Bearer",
                issued_at=now,
                expires_at=now + dt.timedelta(hours=1),
            )
        )
        state.clear_tokens()
        assert state.read_tokens() is None

    def test_pkce_round_trip_via_state(self) -> None:
        state = State(MemoryStorage())
        state.write_pkce({"verifier": "v", "challenge": "c", "method": "S256"})
        assert state.read_pkce() == {"verifier": "v", "challenge": "c", "method": "S256"}

    def test_flow_round_trip(self) -> None:
        state = State(MemoryStorage())
        state.write_flow({"cid": "xyz", "action": "step"})
        assert state.read_flow() == {"cid": "xyz", "action": "step"}
        state.clear_flow()
        assert state.read_flow() is None

    def test_stored_json_is_utf8_and_pretty(self, tmp_path: Path) -> None:
        """Stored JSON must be UTF-8 encoded and human-readable
        (for manual inspection and backup tools)."""
        state = State(FileStorage(tmp_path / "dir"))
        state.write_identity({"name": "Никита", "device_id": "X"})
        path = tmp_path / "dir" / "identity.json"
        raw = path.read_text(encoding="utf-8")
        assert "Никита" in raw  # not escaped
        assert "\n" in raw  # pretty-printed
        parsed = json.loads(raw)
        assert parsed == {"name": "Никита", "device_id": "X"}


def test_read_json_rejects_non_dict(tmp_path: Path) -> None:
    """State refuses to parse a stored JSON list/scalar as identity/tokens etc."""
    storage = FileStorage(tmp_path / "dir")
    storage.write("identity", b"[1, 2, 3]")
    state = State(storage)
    with pytest.raises(TypeError):
        state.read_identity()
