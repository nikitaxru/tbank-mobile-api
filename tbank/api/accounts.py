"""
``AccountsAPI`` namespace — accessed as ``client.accounts`` on a
:class:`~tbank.TBankClient` instance.

Currently exposes the read path only: :meth:`AccountsAPI.list` against
``GET /v1/accounts_light``. Account-management endpoints
(``close_account``, ``set_account_name``, etc.) are out of scope for now.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tbank.errors import TBankAPIError
from tbank.models.accounts import Account

if TYPE_CHECKING:
    from tbank.client import TBankClient


class AccountsAPI:
    """
    Accounts namespace. Never constructed by user code — see
    ``client.accounts`` on :class:`tbank.TBankClient`.
    """

    def __init__(self, client: TBankClient) -> None:
        self._client = client

    def list(self, *, with_digital_rub: bool = False) -> list[Account]:
        """
        Fetch the list of the authenticated user's accounts.

        Wraps ``GET /v1/accounts_light?withDigitalRub=<bool>`` — the same
        endpoint the mobile app's home screen uses.

        The returned list includes every account visible to the user:
        current accounts, savings, credit cards, telecom (mobile
        subscription), and *external accounts* (linked cards from other
        banks via open banking). External accounts have
        ``balance is None``; filter them out if you only want your
        T-Bank-held balances.

        :param with_digital_rub: Whether to include the digital ruble
            account (``CBDC``) if the user has one. The app toggles this
            based on a feature flag; the default ``False`` matches a
            baseline user.
        """
        params = {"withDigitalRub": "true" if with_digital_rub else "false"}
        data, _ = self._client._request_api_json(
            "GET",
            "v1/accounts_light",
            params=params,
            label="accounts_light",
        )
        if not isinstance(data, dict):
            raise TBankAPIError(
                "accounts_light response was not a JSON object",
                status_code=200,
                response_text=str(data),
            )

        result_code = data.get("resultCode")
        if result_code != "OK":
            raise TBankAPIError(
                f"accounts_light: server resultCode={result_code!r}",
                status_code=200,
                error_code=result_code,
                error_description=data.get("errorMessage"),
                response_text=str(data),
            )

        payload = data.get("payload") or []
        if not isinstance(payload, list):
            raise TBankAPIError(
                f"accounts_light: expected payload list, got {type(payload).__name__}",
                status_code=200,
            )

        return [Account.from_api(raw) for raw in _iter_dicts(payload)]


def _iter_dicts(items: list[Any]) -> list[dict[str, Any]]:
    """Small sanity check: every item in the payload list is a dict."""
    out: list[dict[str, Any]] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise TBankAPIError(
                f"payload[{i}] is {type(item).__name__}, expected dict",
                status_code=200,
            )
        out.append(item)
    return out
