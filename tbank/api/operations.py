"""
``OperationsAPI`` namespace — accessed as ``client.operations`` on a
:class:`~tbank.TBankClient` instance.

Implements the basic transaction listing at ``GET /v1/operations`` —
the same endpoint the mobile app uses for its main transaction feed.
Currently exposes only the core ``list(account, start, end)`` variant;
the underlying server endpoint accepts many more filters that aren't
modeled yet.
"""
from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

from tbank.errors import TBankAPIError
from tbank.models.accounts import Account
from tbank.models.operations import Operation

if TYPE_CHECKING:
    from tbank.client import TBankClient


def _format_joda_datetime(value: dt.datetime) -> str:
    """
    Format a :class:`datetime.datetime` in the shape the server expects:
    ISO-8601 with millisecond precision and a UTC ``Z`` suffix, e.g.
    ``2026-04-10T22:30:49.123Z`` (matches what Joda's ``DateTime.toString()``
    emits, which is what the server's Retrofit converter consumes).

    Naive datetimes (``tzinfo is None``) are interpreted as local time
    before conversion to UTC; pass a timezone-aware datetime to avoid
    surprises.
    """
    value = value.astimezone(dt.UTC)
    millis = value.microsecond // 1000
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}Z"


class OperationsAPI:
    """
    Operations namespace. Never constructed by user code — see
    ``client.operations`` on :class:`tbank.TBankClient`.
    """

    def __init__(self, client: TBankClient) -> None:
        self._client = client

    def list(
        self,
        *,
        account: Account | str,
        start: dt.datetime,
        end: dt.datetime,
    ) -> list[Operation]:
        """
        Fetch operations (transactions) for a single account in a date range.

        Wraps ``GET /v1/operations?accounts=<id>&start=<iso>&end=<iso>``.
        The server endpoint accepts many optional filters; this method
        exposes only the three required in practice.

        :param account: Either an :class:`~tbank.models.Account` or a
            raw ``id`` string. The account must belong to the user
            that's currently authenticated.
        :param start: Range start, inclusive.
        :param end: Range end, inclusive.

        :returns: List of :class:`~tbank.models.Operation`. Order
            follows the server's (usually newest-first within the range).
        """
        account_id = account.id if isinstance(account, Account) else str(account)
        params = {
            "accounts": account_id,
            "start": _format_joda_datetime(start),
            "end": _format_joda_datetime(end),
        }
        data, _ = self._client._request_api_json(
            "GET",
            "v1/operations",
            params=params,
            label="operations",
            timeout=60.0,  # large result sets can take a few seconds
        )

        if not isinstance(data, dict):
            raise TBankAPIError(
                "operations response was not a JSON object",
                status_code=200,
                response_text=str(data),
            )

        result_code = data.get("resultCode")
        if result_code != "OK":
            raise TBankAPIError(
                f"operations: server resultCode={result_code!r}",
                status_code=200,
                error_code=result_code,
                error_description=data.get("errorMessage"),
                response_text=str(data),
            )

        payload = data.get("payload") or []
        if not isinstance(payload, list):
            raise TBankAPIError(
                f"operations: expected payload list, got {type(payload).__name__}",
                status_code=200,
            )

        out: list[Operation] = []
        for raw in payload:
            if not isinstance(raw, dict):
                raise TBankAPIError(
                    f"operations payload item is {type(raw).__name__}, expected dict",
                    status_code=200,
                )
            out.append(Operation.from_api(raw))
        return out
