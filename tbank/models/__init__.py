"""
Typed data models returned by the library.

Each model has a :meth:`from_api` classmethod that parses a raw server JSON
dict into a typed instance. Parsers are forgiving: unknown fields are
preserved in the model's ``raw`` attribute so callers can access
yet-unmodeled data without dropping out of the typed API.
"""
from tbank.models.accounts import Account, AccountType, Loyalty
from tbank.models.auth import Tokens
from tbank.models.common import Currency, Money
from tbank.models.operations import (
    Brand,
    Category,
    Operation,
    OperationGroup,
    OperationType,
)

__all__ = [
    "Account",
    "AccountType",
    "Brand",
    "Category",
    "Currency",
    "Loyalty",
    "Money",
    "Operation",
    "OperationGroup",
    "OperationType",
    "Tokens",
]
