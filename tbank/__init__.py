"""
tbank-mobile-api — unofficial T-Bank (Tinkoff) mobile API client.

The public surface is re-exported from :mod:`tbank.client`,
:mod:`tbank.models`, and :mod:`tbank.auth`. The typical entry point
is :class:`TBankClient`:

.. code-block:: python

    from tbank import TBankClient
    from tbank.storage import FileStorage

    with TBankClient(storage=FileStorage("~/.tbank")) as client:
        if not client.is_authenticated():
            client.login_interactive()
        for account in client.accounts.list():
            print(account)
"""
from tbank.auth import (
    PIXEL_7_PANTHER_A14,
    AnyAuthStep,
    AuthComplete,
    AuthStep,
    DeviceProfile,
    EntryStep,
    OtpStep,
    PasswordStep,
    PkcePair,
    SelfieSkipReason,
    SelfieStep,
    UnknownStep,
)
from tbank.client import TBankClient
from tbank.errors import (
    TBankAPIError,
    TBankAuthError,
    TBankAuthFlowError,
    TBankConversationExpiredError,
    TBankError,
    TBankInvalidStateError,
    TBankRateLimitError,
    TBankRefreshFailedError,
    TBankTokenExpiredError,
    TBankTransportError,
)
from tbank.identity import Identity
from tbank.models import (
    Account,
    AccountType,
    Brand,
    Category,
    Currency,
    Loyalty,
    Money,
    Operation,
    OperationGroup,
    OperationType,
    Tokens,
)

__version__ = "0.1.0"

__all__ = [
    "PIXEL_7_PANTHER_A14",
    # Models
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
    # Auth
    "AnyAuthStep",
    "AuthComplete",
    "AuthStep",
    "DeviceProfile",
    "EntryStep",
    "Identity",
    "OtpStep",
    "PasswordStep",
    "PkcePair",
    "SelfieSkipReason",
    "SelfieStep",
    "UnknownStep",
    # Client
    "TBankClient",
    # Errors
    "TBankAPIError",
    "TBankAuthError",
    "TBankAuthFlowError",
    "TBankConversationExpiredError",
    "TBankError",
    "TBankInvalidStateError",
    "TBankRateLimitError",
    "TBankRefreshFailedError",
    "TBankTokenExpiredError",
    "TBankTransportError",
    "__version__",
]
