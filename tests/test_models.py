"""
Unit tests for the typed API models.

The fixtures here are hand-crafted minimal-valid examples based on
real server responses. They're not byte-for-byte copies of captured
live data (that has personal IDs + balances) — they're synthetic but
shaped identically.
"""
from __future__ import annotations

import datetime as dt
from decimal import Decimal

import pytest

from tbank.models.accounts import Account, AccountType
from tbank.models.common import Currency, Money, parse_ms_timestamp
from tbank.models.operations import (
    Operation,
    OperationGroup,
    OperationType,
)

# =============================================================================
# Currency / Money / timestamp helpers
# =============================================================================

class TestMoney:
    def test_decimal_precision_via_string_conversion(self) -> None:
        """
        Parsing uses Decimal(str(value)) so a server float like 221112.99
        doesn't become 221112.98999999... or similar float artifacts.
        """
        money = Money.from_api(
            {
                "value": 221112.99,
                "currency": {"code": 643, "name": "RUB", "strCode": "643"},
            }
        )
        assert money.amount == Decimal("221112.99")
        assert money.currency.name == "RUB"
        assert money.currency.code == 643

    def test_zero_balance(self) -> None:
        money = Money.from_api(
            {"value": 0.0, "currency": {"code": 840, "name": "USD", "strCode": "840"}}
        )
        assert money.amount == Decimal("0")
        assert money.currency.name == "USD"

    def test_negative_amount(self) -> None:
        money = Money.from_api(
            {"value": -150.5, "currency": {"code": 643, "name": "RUB", "strCode": "643"}}
        )
        assert money.amount == Decimal("-150.5")


class TestCurrency:
    def test_from_api(self) -> None:
        c = Currency.from_api({"code": 978, "name": "EUR", "strCode": "978"})
        assert c.code == 978
        assert c.name == "EUR"

    def test_equality(self) -> None:
        assert Currency(code=643, name="RUB") == Currency(code=643, name="RUB")


class TestTimestamp:
    def test_parses_joda_millis_envelope(self) -> None:
        ts = parse_ms_timestamp({"milliseconds": 1775688320000})
        assert ts == dt.datetime(2026, 4, 8, 22, 45, 20, tzinfo=dt.UTC)

    def test_returns_none_for_none(self) -> None:
        assert parse_ms_timestamp(None) is None

    def test_returns_none_for_empty(self) -> None:
        assert parse_ms_timestamp({}) is None


# =============================================================================
# Account
# =============================================================================

def _current_account_fixture() -> dict[str, object]:
    return {
        "id": "1234567890",
        "name": "Black",
        "accountType": "Current",
        "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        "moneyAmount": {
            "value": 100000.50,
            "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        },
        "creditLimit": {
            "value": 0.0,
            "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        },
        "creationDate": {"milliseconds": 1618444800000},
        "hidden": False,
        "sharedByMeFlag": False,
        "loyalty": {
            "programName": "Black",
            "programCode": "TINKOFF_BLACK_RUB_DEBIT",
            "coreGroup": "BLACK",
            "cashbackProgram": True,
            "loyaltyPointsId": 10,
        },
        "cards": [],
    }


def _external_account_fixture() -> dict[str, object]:
    """ExternalAccount — linked card from another bank, no balance/currency."""
    return {
        "id": "99999999",
        "name": "Сбербанк *7080",
        "accountType": "ExternalAccount",
        "creationDate": {"milliseconds": 1567976400000},
        "hidden": False,
        "card": {
            "id": "99999999",
            "status": "A",
            "value": "546938******7080",
            "paymentSystem": "MASTERCARD",
        },
    }


class TestAccount:
    def test_parse_current_account(self) -> None:
        acc = Account.from_api(_current_account_fixture())
        assert acc.id == "1234567890"
        assert acc.name == "Black"
        assert acc.type == AccountType.CURRENT
        assert acc.currency is not None
        assert acc.currency.name == "RUB"
        assert acc.balance is not None
        assert acc.balance.amount == Decimal("100000.50")
        assert acc.credit_limit is not None
        assert acc.credit_limit.amount == Decimal("0")
        assert acc.hidden is False
        assert acc.shared_by_me is False
        assert acc.created_at == dt.datetime(2021, 4, 15, tzinfo=dt.UTC)

    def test_parse_external_account_has_no_balance(self) -> None:
        """External cards from other banks have no currency/balance."""
        acc = Account.from_api(_external_account_fixture())
        assert acc.id == "99999999"
        assert acc.type == AccountType.EXTERNAL_ACCOUNT
        assert acc.currency is None
        assert acc.balance is None

    def test_unknown_account_type_falls_back_to_string(self) -> None:
        """Library doesn't crash on new server-side account types."""
        data = _current_account_fixture()
        data["accountType"] = "SomeFutureType"
        acc = Account.from_api(data)
        assert acc.type == "SomeFutureType"
        assert not isinstance(acc.type, AccountType)

    def test_loyalty_parsed(self) -> None:
        acc = Account.from_api(_current_account_fixture())
        assert acc.loyalty is not None
        assert acc.loyalty.program_name == "Black"
        assert acc.loyalty.core_group == "BLACK"
        assert acc.loyalty.cashback_program is True

    def test_account_without_loyalty(self) -> None:
        data = _current_account_fixture()
        data.pop("loyalty")
        acc = Account.from_api(data)
        assert acc.loyalty is None

    def test_raw_is_preserved(self) -> None:
        """Full server dict is kept on `raw` for forward compat."""
        data = _current_account_fixture()
        # Add a fake future field
        data["futureField"] = {"some": "value"}
        acc = Account.from_api(data)
        assert acc.raw["futureField"] == {"some": "value"}
        assert acc.raw["accountType"] == "Current"


# =============================================================================
# Operation
# =============================================================================

def _pay_operation_fixture() -> dict[str, object]:
    return {
        "id": "op-1",
        "account": "1234567890",
        "operationTime": {"milliseconds": 1775688320000},
        "debitingTime": {"milliseconds": 1775688340000},
        "type": "Debit",
        "status": "OK",
        "group": "PAY",
        "amount": {
            "value": 499.0,
            "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        },
        "accountAmount": {
            "value": 499.0,
            "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        },
        "description": "Подписка Pro",
        "mcc": 5411,
        "cardNumber": "553691******3557",
        "brand": {
            "id": "100240",
            "name": "Подписка Pro",
            "logo": "https://brands.example/tinkoff-pro.png",
        },
        "spendingCategory": {"id": "45", "name": "Другое"},
        "categoryInfo": {
            "bankCategory": {
                "id": "1",
                "name": "Финансы",
            }
        },
        "subgroup": {"id": "A1", "name": "Подписка"},
        "cashbackAmount": {
            "value": 5.0,
            "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        },
        "payment": {"paymentType": "Payment"},
    }


def _inner_transfer_fixture() -> dict[str, object]:
    return {
        "id": "op-2",
        "account": "1234567890",
        "operationTime": {"milliseconds": 1775688320000},
        "type": "Credit",
        "status": "OK",
        "group": "INCOME",
        "isInner": True,
        "senderAgreement": "9876543210",
        "amount": {
            "value": 5000.0,
            "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        },
        "accountAmount": {
            "value": 5000.0,
            "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        },
        "description": "Между своими счетами",
        "merchant": {"name": "Внутрибанковский перевод"},
        "subcategory": "Между своими счетами",
    }


def _currency_conversion_fixture() -> dict[str, object]:
    """Foreign-currency purchase debited from a RUB account."""
    return {
        "id": "op-3",
        "account": "1234567890",
        "operationTime": {"milliseconds": 1775688320000},
        "type": "Debit",
        "status": "OK",
        "group": "PAY",
        "amount": {
            "value": 10.0,
            "currency": {"code": 840, "name": "USD", "strCode": "840"},
        },
        "accountAmount": {
            "value": 930.0,
            "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        },
        "description": "Apple.com",
    }


def _incoming_transfer_fixture() -> dict[str, object]:
    return {
        "id": "op-4",
        "account": "1234567890",
        "operationTime": {"milliseconds": 1775688320000},
        "type": "Credit",
        "status": "OK",
        "group": "INCOME",
        "senderDetails": "Татьяна М.",
        "amount": {
            "value": 1500.0,
            "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        },
        "accountAmount": {
            "value": 1500.0,
            "currency": {"code": 643, "name": "RUB", "strCode": "643"},
        },
        "description": "Входящий перевод",
    }


class TestOperation:
    def test_parse_pay_operation(self) -> None:
        op = Operation.from_api(_pay_operation_fixture())
        assert op.id == "op-1"
        assert op.account_id == "1234567890"
        assert op.type == OperationType.DEBIT
        assert op.group == OperationGroup.PAY
        assert op.amount.amount == Decimal("499")
        assert op.amount.currency.name == "RUB"
        assert op.description == "Подписка Pro"
        assert op.merchant is not None
        assert op.merchant.name == "Подписка Pro"
        assert op.category is not None
        assert op.category.name == "Другое"
        assert op.bank_category is not None
        assert op.bank_category.name == "Финансы"
        assert op.mcc == 5411
        assert op.cashback is not None
        assert op.cashback.amount == Decimal("5")
        assert op.payment_type == "Payment"
        assert op.subgroup_name == "Подписка"
        assert op.card_number_masked == "553691******3557"

    def test_inner_transfer_extracts_counterpart(self) -> None:
        op = Operation.from_api(_inner_transfer_fixture())
        assert op.is_inner is True
        assert op.inner_counterpart_id == "9876543210"

    def test_regular_op_has_no_counterpart(self) -> None:
        op = Operation.from_api(_pay_operation_fixture())
        assert op.is_inner is False
        assert op.inner_counterpart_id is None

    def test_currency_conversion_detection(self) -> None:
        op = Operation.from_api(_currency_conversion_fixture())
        assert op.amount.currency.name == "USD"
        assert op.account_amount.currency.name == "RUB"
        assert op.is_conversion is True

    def test_same_currency_is_not_conversion(self) -> None:
        op = Operation.from_api(_pay_operation_fixture())
        assert op.is_conversion is False

    def test_incoming_transfer_has_sender(self) -> None:
        op = Operation.from_api(_incoming_transfer_fixture())
        assert op.sender == "Татьяна М."
        assert op.type == OperationType.CREDIT
        assert op.group == OperationGroup.INCOME

    def test_unknown_type_falls_back_to_string(self) -> None:
        data = _pay_operation_fixture()
        data["type"] = "Hold"
        op = Operation.from_api(data)
        assert op.type == "Hold"

    def test_missing_operation_time_raises(self) -> None:
        data = _pay_operation_fixture()
        data.pop("operationTime")
        with pytest.raises(ValueError):
            Operation.from_api(data)

    def test_raw_preserved(self) -> None:
        data = _pay_operation_fixture()
        data["someFutureField"] = "xyz"
        op = Operation.from_api(data)
        assert op.raw["someFutureField"] == "xyz"
