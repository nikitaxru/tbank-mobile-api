"""
Low-level shared value types: :class:`Currency`, :class:`Money`, and
helpers for the server's Joda-style timestamps.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any


@dataclass(frozen=True, slots=True)
class Currency:
    """
    ISO 4217 currency descriptor.

    The server sends currencies as::

        {"code": 643, "name": "RUB", "strCode": "643"}

    We keep ``code`` (numeric, ISO 4217) and ``name`` (alpha, e.g. ``"RUB"``).
    The redundant ``strCode`` is discarded.
    """

    code: int
    name: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Currency:
        return cls(code=int(data["code"]), name=str(data["name"]))


@dataclass(frozen=True, slots=True)
class Money:
    """
    Precise monetary amount in a specific currency.

    Values are stored as :class:`decimal.Decimal` to avoid the classic
    float/rounding errors that plague financial code. Parsing from the
    server uses ``Decimal(str(value))`` so that ``1.10`` stays ``1.10``
    instead of becoming ``1.1000000000000000888...``.
    """

    amount: Decimal
    currency: Currency

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Money:
        # The API sends floats like 221112.99; go via str for decimal safety.
        raw_amount = data["value"]
        return cls(
            amount=Decimal(str(raw_amount)),
            currency=Currency.from_api(data["currency"]),
        )

    def __str__(self) -> str:  # pragma: no cover — trivial formatting
        return f"{self.amount} {self.currency.name}"


# -----------------------------------------------------------------------------
# Timestamp parsing
# -----------------------------------------------------------------------------

def parse_ms_timestamp(data: dict[str, Any] | None) -> datetime | None:
    """
    Parse the server's Joda-style wrapped timestamp into a UTC ``datetime``.

    The T-Bank API wraps all date-time values in an envelope::

        {"milliseconds": 1775688320000}

    Timezone hints that some fields carry alongside the millis envelope
    are ignored — values are always interpreted as UTC. Returns ``None``
    if ``data`` is ``None`` or missing the ``milliseconds`` key.
    """
    if not data:
        return None
    ms = data.get("milliseconds")
    if ms is None:
        return None
    return datetime.fromtimestamp(int(ms) / 1000, tz=UTC)
