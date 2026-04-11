"""
RFC 7636 Proof Key for Code Exchange (PKCE) generator.

The T-Bank mobile app uses standard OAuth2 PKCE with the ``S256``
challenge method. This module produces the code_verifier / code_challenge
pair, stores it through :class:`~tbank.storage.State`, and reconstructs
it on subsequent runs so the original verifier survives a process restart
between ``auth/authorize`` and ``auth/token``.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

from tbank.storage import State


def _b64url_nopad(raw: bytes) -> str:
    """Base64url encode without padding — the OAuth PKCE format."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True)
class PkcePair:
    """
    A PKCE ``(verifier, challenge, method)`` triple.

    - ``verifier`` is the secret (43 URL-safe base64 chars, 32 random bytes).
    - ``challenge`` is ``base64url(sha256(verifier))`` — 43 chars.
    - ``method`` is always ``"S256"`` (RFC 7636 recommends it for all
      non-trivial clients, and the T-Bank SSO accepts it in practice).

    Immutable by design. Generate new pairs with :meth:`generate`;
    persist with :meth:`save`; reload with :meth:`load`.
    """

    verifier: str
    challenge: str
    method: str = "S256"

    @classmethod
    def generate(cls) -> PkcePair:
        """Create a fresh, cryptographically random PKCE pair."""
        verifier = _b64url_nopad(secrets.token_bytes(32))
        challenge = _b64url_nopad(hashlib.sha256(verifier.encode("ascii")).digest())
        return cls(verifier=verifier, challenge=challenge, method="S256")

    # -------------------------------------------------------------------------
    # State persistence
    # -------------------------------------------------------------------------

    def to_dict(self) -> dict[str, str]:
        return {
            "verifier": self.verifier,
            "challenge": self.challenge,
            "method": self.method,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PkcePair:
        return cls(
            verifier=str(data["verifier"]),
            challenge=str(data["challenge"]),
            method=str(data.get("method", "S256")),
        )

    def save(self, state: State) -> None:
        """Persist the pair through the state layer."""
        state.write_pkce(self.to_dict())

    @classmethod
    def load(cls, state: State) -> PkcePair | None:
        """Return the persisted pair, or ``None`` if nothing is saved."""
        raw = state.read_pkce()
        if raw is None:
            return None
        return cls.from_dict(raw)

    @classmethod
    def load_or_generate(cls, state: State) -> PkcePair:
        """
        Return the persisted pair, or generate-and-save a new one.

        The typical login flow calls this once before ``auth/authorize``,
        then reads it back (via :meth:`load`) before ``auth/token`` to
        supply the ``code_verifier``.
        """
        existing = cls.load(state)
        if existing is not None:
            return existing
        fresh = cls.generate()
        fresh.save(state)
        return fresh
