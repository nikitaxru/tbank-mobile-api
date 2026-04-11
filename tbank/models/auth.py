"""
Auth-layer value objects: :class:`Tokens`.

The step-hierarchy types used during interactive login live in
:mod:`tbank.auth.flow` — they carry mutable state and behaviour rather than
being pure data, so they don't belong in this package.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any


@dataclass(frozen=True, slots=True)
class Tokens:
    """
    OAuth 2 / OIDC token triple plus metadata.

    Returned by the :meth:`tbank.TBankClient.exchange_code` step and by
    every successful refresh. Immutable by design: each refresh produces a
    new :class:`Tokens` instance — the old one is replaced atomically in
    the client's storage.

    Fields mirror the ``auth/token`` response body verbatim except
    ``expires_at`` which is computed at construction time for convenience.
    """

    access_token: str
    refresh_token: str
    token_type: str          # "Bearer"
    issued_at: datetime
    expires_at: datetime
    id_token: str | None = None
    scope: str | None = None
    # Keep the raw server response around for forward-compat.
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    # -------------------------------------------------------------------------
    # Construction
    # -------------------------------------------------------------------------

    @classmethod
    def from_api(
        cls,
        data: dict[str, Any],
        *,
        issued_at: datetime | None = None,
    ) -> Tokens:
        """
        Parse an ``auth/token`` response body into a :class:`Tokens`.

        ``issued_at`` defaults to ``now()`` in UTC. The ``expires_at`` is
        computed from ``issued_at + expires_in``; if the server omits
        ``expires_in``, we fall back to +2 hours (the observed default).
        """
        issued = issued_at or datetime.now(tz=UTC)
        expires_in_raw = data.get("expires_in")
        expires_in = int(expires_in_raw) if expires_in_raw is not None else 7200
        return cls(
            access_token=str(data["access_token"]),
            refresh_token=str(data["refresh_token"]),
            token_type=str(data.get("token_type", "Bearer")),
            issued_at=issued,
            expires_at=issued + timedelta(seconds=expires_in),
            id_token=data.get("id_token"),
            scope=data.get("scope"),
            raw=dict(data),
        )

    # -------------------------------------------------------------------------
    # Serialization for Storage layer
    # -------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serializable dict for persistence via :class:`tbank.storage.Storage`."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "id_token": self.id_token,
            "scope": self.scope,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Tokens:
        """Inverse of :meth:`to_dict`."""
        return cls(
            access_token=str(data["access_token"]),
            refresh_token=str(data["refresh_token"]),
            token_type=str(data.get("token_type", "Bearer")),
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            id_token=data.get("id_token"),
            scope=data.get("scope"),
            raw=dict(data.get("raw") or {}),
        )

    # -------------------------------------------------------------------------
    # Lifecycle helpers
    # -------------------------------------------------------------------------

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """True once the access_token has passed its declared expiry."""
        return (now or datetime.now(tz=UTC)) >= self.expires_at

    def expires_within(self, seconds: int, *, now: datetime | None = None) -> bool:
        """
        True if the access_token will be expired within ``seconds``.

        Callers use this to decide whether to refresh proactively before
        making a request — avoids racing an in-flight request to a 401.
        """
        cutoff = (now or datetime.now(tz=UTC)) + timedelta(seconds=seconds)
        return cutoff >= self.expires_at
