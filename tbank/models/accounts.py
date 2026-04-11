"""
Account-related data models.

:class:`Account` is the typed representation of one row from the
``GET /v1/accounts_light`` response. We hand-pick the fields that are
broadly useful; the full raw dict is retained in ``Account.raw`` for
callers that need edge-case fields we haven't modeled.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from tbank.models.common import Currency, Money, parse_ms_timestamp


class AccountType(StrEnum):
    """
    Known values of the server's ``accountType`` field.

    This is not an exhaustive list — the server can return strings we
    haven't observed. :meth:`Account.from_api` keeps unknown values as
    plain ``str`` rather than raising, so ``Account.type`` is typed
    ``AccountType | str``.
    """

    CURRENT = "Current"
    SAVING = "Saving"
    CREDIT_CARD = "CreditCard"
    TELECOM = "Telecom"
    EXTERNAL_ACCOUNT = "ExternalAccount"
    DEPOSIT = "Deposit"
    LOAN = "Loan"
    SHARED_ACCOUNT = "SharedAccount"


@dataclass(frozen=True, slots=True)
class Loyalty:
    """
    T-Bank loyalty / cashback program descriptor attached to an account.

    Example::

        {"programName": "Black",
         "programCode": "TINKOFF_BLACK_USD_DEBIT",
         "coreGroup": "BLACK",
         "cashbackProgram": true,
         "loyaltyPointsId": 10,
         "accrualBonuses": 0}
    """

    program_name: str
    program_code: str
    core_group: str | None
    cashback_program: bool
    points_id: int | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Loyalty:
        return cls(
            program_name=str(data.get("programName", "")),
            program_code=str(data.get("programCode", "")),
            core_group=data.get("coreGroup"),
            cashback_program=bool(data.get("cashbackProgram", False)),
            points_id=data.get("loyaltyPointsId"),
            raw=dict(data),
        )


@dataclass(frozen=True, slots=True)
class Account:
    """
    A single user account returned by ``GET /v1/accounts_light``.

    Most fields are self-explanatory. Two quirks worth calling out:

    - :attr:`currency` and :attr:`balance` are **optional**. T-Bank's
      accounts list also returns "external accounts" (linked cards from
      other banks via open banking) that have neither — such entries
      carry only ``card`` info and no balance of their own. Filter them
      out with ``if account.balance is not None``.
    - :attr:`type` is typed ``AccountType | str`` — the enum lists known
      values but the parser preserves unknown strings rather than raising,
      so the library doesn't break when T-Bank adds a new account type.
    """

    id: str
    name: str
    type: AccountType | str
    currency: Currency | None
    balance: Money | None
    credit_limit: Money | None
    hidden: bool
    shared_by_me: bool
    created_at: datetime | None
    loyalty: Loyalty | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Account:
        raw_type = str(data.get("accountType", ""))
        typed: AccountType | str
        try:
            typed = AccountType(raw_type)
        except ValueError:
            typed = raw_type

        currency_raw = data.get("currency")
        currency = Currency.from_api(currency_raw) if currency_raw else None

        balance_raw = data.get("moneyAmount")
        balance = Money.from_api(balance_raw) if balance_raw else None

        credit_limit_raw = data.get("creditLimit")
        credit_limit: Money | None = None
        if credit_limit_raw and credit_limit_raw.get("value") is not None:
            credit_limit = Money.from_api(credit_limit_raw)

        loyalty_raw = data.get("loyalty")
        loyalty = Loyalty.from_api(loyalty_raw) if loyalty_raw else None

        return cls(
            id=str(data["id"]),
            name=str(data.get("name", "")),
            type=typed,
            currency=currency,
            balance=balance,
            credit_limit=credit_limit,
            hidden=bool(data.get("hidden", False)),
            shared_by_me=bool(data.get("sharedByMeFlag", False)),
            created_at=parse_ms_timestamp(data.get("creationDate")),
            loyalty=loyalty,
            raw=dict(data),
        )
