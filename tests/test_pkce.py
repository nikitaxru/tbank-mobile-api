"""Unit tests for :mod:`tbank.auth.pkce`."""
from __future__ import annotations

import base64
import hashlib

from tbank.auth import PkcePair
from tbank.storage import MemoryStorage, State


def test_generate_produces_expected_lengths() -> None:
    """Verifier and challenge are both 43 base64url-nopad chars (32 raw bytes)."""
    pair = PkcePair.generate()
    assert len(pair.verifier) == 43
    assert len(pair.challenge) == 43
    assert pair.method == "S256"


def test_generate_uses_url_safe_alphabet() -> None:
    """Neither verifier nor challenge may contain characters requiring
    URL-encoding when placed into a form body."""
    pair = PkcePair.generate()
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert set(pair.verifier) <= allowed
    assert set(pair.challenge) <= allowed


def test_challenge_is_sha256_of_verifier() -> None:
    """RFC 7636: challenge = BASE64URL(SHA256(ASCII(verifier)))."""
    pair = PkcePair.generate()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(pair.verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    assert pair.challenge == expected


def test_generate_is_unique() -> None:
    """Two consecutive generations must not collide (entropy sanity check)."""
    a = PkcePair.generate()
    b = PkcePair.generate()
    assert a.verifier != b.verifier
    assert a.challenge != b.challenge


def test_state_round_trip() -> None:
    """save() then load() returns an equal pair."""
    state = State(MemoryStorage())
    original = PkcePair.generate()
    original.save(state)
    loaded = PkcePair.load(state)
    assert loaded == original


def test_load_returns_none_for_empty_state() -> None:
    state = State(MemoryStorage())
    assert PkcePair.load(state) is None


def test_load_or_generate_returns_existing() -> None:
    state = State(MemoryStorage())
    first = PkcePair.load_or_generate(state)
    second = PkcePair.load_or_generate(state)
    assert first == second


def test_load_or_generate_creates_when_missing() -> None:
    state = State(MemoryStorage())
    assert state.read_pkce() is None
    pair = PkcePair.load_or_generate(state)
    assert state.read_pkce() is not None
    assert PkcePair.load(state) == pair
