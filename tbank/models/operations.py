"""
Operation-related data models — transactions returned by
``GET /v1/operations``.

The server returns roughly 65 fields per operation. This module models
the ~20 most useful ones explicitly and preserves the full original dict
in :attr:`Operation.raw`, so power users can access anything we haven't
typed without dropping out of the typed API.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from tbank.models.common import Money, parse_ms_timestamp


class OperationType(StrEnum):
    """Direction of money flow from the account owner's point of view."""

    CREDIT = "Credit"   # money in
    DEBIT = "Debit"     # money out


class OperationGroup(StrEnum):
    """Business-level bucket the server assigns to each operation."""

    PAY = "PAY"              # purchases, subscriptions, services
    INCOME = "INCOME"        # incoming payments (salary, transfers TO you)
    TRANSFER = "TRANSFER"    # outgoing transfers, bank details / SBP
    # Other server-side buckets are kept as plain strings on Operation.group.


@dataclass(frozen=True, slots=True)
class Brand:
    """
    Merchant / brand attached to an operation.

    Example from the server::

        {"id": "11242",
         "name": "Сбербанк",
         "logo": "https://brands-prod.cdn-tinkoff.ru/general_logo/sber.png",
         "baseColor": "21A038"}
    """

    id: str
    name: str
    logo_url: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Brand:
        logo = data.get("logo")
        return cls(
            id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            logo_url=str(logo) if logo else None,
            raw=dict(data),
        )


@dataclass(frozen=True, slots=True)
class Category:
    """
    Spending/income category such as ``{"id": "24", "name": "Переводы"}``.

    Two category views exist in the raw operation:

    - ``spendingCategory`` — the one shown in the app UI (more accurate)
    - ``categoryInfo.bankCategory`` — the business / analytics category

    :class:`Operation` exposes them as :attr:`Operation.category` and
    :attr:`Operation.bank_category` respectively.
    """

    id: str
    name: str
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Category:
        return cls(
            id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            raw=dict(data),
        )


@dataclass(frozen=True, slots=True)
class Operation:
    """
    A single operation (transaction) as returned by ``GET /v1/operations``.

    Attributes are grouped by concern:

    Core identification
        :attr:`id`, :attr:`account_id`, :attr:`time`, :attr:`debiting_time`,
        :attr:`status`

    Direction & classification
        :attr:`type`, :attr:`group`

    Amounts
        :attr:`amount` (in operation currency), :attr:`account_amount`
        (in the account's currency). These differ when a foreign-currency
        purchase is debited from a RUB account — the ratio tells you the
        applied FX rate. :meth:`is_conversion` is ``True`` in that case.
        :attr:`cashback` carries the accrued reward.

    Narrative
        :attr:`description`, :attr:`merchant`, :attr:`category`,
        :attr:`bank_category`, :attr:`subgroup_name`, :attr:`mcc`

    Card & payment
        :attr:`card_number_masked`, :attr:`payment_type`

    Transfers
        :attr:`sender`, :attr:`receiver` (personal transfers), plus the
        inner-transfer pair: :attr:`is_inner` and
        :attr:`inner_counterpart_id` (the id of the OTHER account, so
        you can build proper two-sided postings for accounting tools).
    """

    id: str
    account_id: str
    time: datetime
    debiting_time: datetime | None
    status: str
    type: OperationType | str
    group: OperationGroup | str
    amount: Money
    account_amount: Money
    description: str
    merchant: Brand | None
    category: Category | None
    bank_category: Category | None
    mcc: int | None
    cashback: Money | None
    is_inner: bool
    inner_counterpart_id: str | None
    card_number_masked: str | None
    payment_type: str | None
    sender: str | None
    receiver: str | None
    subgroup_name: str | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> Operation:
        raw_type = str(data.get("type", ""))
        op_type: OperationType | str
        try:
            op_type = OperationType(raw_type)
        except ValueError:
            op_type = raw_type

        raw_group = str(data.get("group", ""))
        op_group: OperationGroup | str
        try:
            op_group = OperationGroup(raw_group)
        except ValueError:
            op_group = raw_group

        time = parse_ms_timestamp(data.get("operationTime"))
        if time is None:
            raise ValueError(f"Operation {data.get('id')!r} is missing operationTime")

        merchant: Brand | None = None
        brand = data.get("brand")
        if brand:
            merchant = Brand.from_api(brand)

        category: Category | None = None
        spending = data.get("spendingCategory")
        if spending:
            category = Category.from_api(spending)

        bank_category: Category | None = None
        ci = data.get("categoryInfo") or {}
        bc = ci.get("bankCategory") if isinstance(ci, dict) else None
        if bc:
            bank_category = Category.from_api(bc)

        cashback: Money | None = None
        cashback_raw = data.get("cashbackAmount")
        if cashback_raw:
            cashback = Money.from_api(cashback_raw)

        payment = data.get("payment") if isinstance(data.get("payment"), dict) else None
        payment_type = payment.get("paymentType") if payment else None

        # Own-accounts transfer: the counterpart account id lives in
        # `senderAgreement` on the credit side of the pair.
        is_inner = bool(data.get("isInner", False))
        inner_counterpart_id: str | None = None
        if is_inner:
            sender_agreement = data.get("senderAgreement")
            if sender_agreement:
                inner_counterpart_id = str(sender_agreement)

        subgroup_name: str | None = None
        subgroup = data.get("subgroup")
        if isinstance(subgroup, dict):
            name = subgroup.get("name")
            if name:
                subgroup_name = str(name)

        return cls(
            id=str(data["id"]),
            account_id=str(data.get("account", "")),
            time=time,
            debiting_time=parse_ms_timestamp(data.get("debitingTime")),
            status=str(data.get("status", "")),
            type=op_type,
            group=op_group,
            amount=Money.from_api(data["amount"]),
            account_amount=Money.from_api(data["accountAmount"]),
            description=str(data.get("description", "")),
            merchant=merchant,
            category=category,
            bank_category=bank_category,
            mcc=int(data["mcc"]) if data.get("mcc") is not None else None,
            cashback=cashback,
            is_inner=is_inner,
            inner_counterpart_id=inner_counterpart_id,
            card_number_masked=data.get("cardNumber"),
            payment_type=payment_type,
            sender=data.get("senderDetails"),
            receiver=data.get("receiverDetails"),
            subgroup_name=subgroup_name,
            raw=dict(data),
        )

    @property
    def is_conversion(self) -> bool:
        """
        True when the operation currency differs from the account currency
        (foreign-currency purchase, FX between own accounts, etc.).
        """
        return self.amount.currency != self.account_amount.currency
