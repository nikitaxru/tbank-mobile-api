"""Unit tests for :class:`tbank.models.Tokens`."""
from __future__ import annotations

import datetime as dt

from tbank.models.auth import Tokens


def _api_response() -> dict[str, object]:
    return {
        "access_token": "t.aaaa",
        "refresh_token": "r.bbbb",
        "id_token": "id.cccc",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid profile",
    }


def test_from_api_computes_expires_at() -> None:
    issued = dt.datetime(2026, 4, 10, 12, 0, 0, tzinfo=dt.UTC)
    tokens = Tokens.from_api(_api_response(), issued_at=issued)
    assert tokens.issued_at == issued
    assert tokens.expires_at == issued + dt.timedelta(hours=1)


def test_from_api_defaults_expires_in_when_missing() -> None:
    """When the server omits expires_in we fall back to +2h (observed default)."""
    data = _api_response()
    data.pop("expires_in")
    issued = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    tokens = Tokens.from_api(data, issued_at=issued)
    assert tokens.expires_at == issued + dt.timedelta(hours=2)


def test_from_api_preserves_raw() -> None:
    tokens = Tokens.from_api(_api_response())
    assert tokens.raw["access_token"] == "t.aaaa"
    assert tokens.raw["scope"] == "openid profile"


def test_is_expired() -> None:
    now = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.UTC)
    tokens = Tokens(
        access_token="t",
        refresh_token="r",
        token_type="Bearer",
        issued_at=now - dt.timedelta(hours=3),
        expires_at=now - dt.timedelta(minutes=1),
    )
    assert tokens.is_expired(now=now)

    still_valid = Tokens(
        access_token="t",
        refresh_token="r",
        token_type="Bearer",
        issued_at=now,
        expires_at=now + dt.timedelta(hours=1),
    )
    assert not still_valid.is_expired(now=now)


def test_expires_within() -> None:
    now = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.UTC)
    tokens = Tokens(
        access_token="t",
        refresh_token="r",
        token_type="Bearer",
        issued_at=now,
        expires_at=now + dt.timedelta(seconds=45),
    )
    assert tokens.expires_within(60, now=now)
    assert not tokens.expires_within(10, now=now)


def test_dict_round_trip() -> None:
    """to_dict → from_dict preserves equality (except raw is compared separately)."""
    now = dt.datetime(2026, 4, 10, 12, 0, 0, tzinfo=dt.UTC)
    tokens = Tokens(
        access_token="t.aaaa",
        refresh_token="r.bbbb",
        id_token="id.cccc",
        token_type="Bearer",
        scope="openid",
        issued_at=now,
        expires_at=now + dt.timedelta(hours=2),
        raw={"access_token": "t.aaaa", "extra": "field"},
    )
    clone = Tokens.from_dict(tokens.to_dict())
    assert clone == tokens
    assert clone.raw == tokens.raw
