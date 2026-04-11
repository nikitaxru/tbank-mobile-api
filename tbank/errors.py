"""
Exception hierarchy for tbank-mobile-api.

All library-raised exceptions inherit from :class:`TBankError`. Catch that
at the top level to distinguish this library's errors from unrelated ones.

Structure::

    TBankError
    ├── TBankTransportError            (network, TLS, DNS, timeout)
    ├── TBankAPIError                  (HTTP 4xx/5xx from the server)
    │   ├── TBankRateLimitError        (HTTP 429)
    │   └── TBankConversationExpiredError   (conversation_not_found)
    └── TBankAuthError
        ├── TBankInvalidStateError     (calling an operation in wrong state)
        ├── TBankTokenExpiredError     (access_token past its lifetime)
        ├── TBankRefreshFailedError    (refresh_token call rejected)
        └── TBankAuthFlowError         (unexpected server step / bad OTP / etc.)
"""
from __future__ import annotations


class TBankError(Exception):
    """Base class for every error raised by this library."""


# -----------------------------------------------------------------------------
# Transport
# -----------------------------------------------------------------------------


class TBankTransportError(TBankError):
    """
    Network-level failure before the server could answer.

    Wraps the underlying ``httpx.HTTPError``/``ssl.SSLError`` etc. Retrying
    may be appropriate.
    """


# -----------------------------------------------------------------------------
# API (server returned an HTTP response)
# -----------------------------------------------------------------------------


class TBankAPIError(TBankError):
    """
    The server answered with a 4xx/5xx HTTP status (or a 2xx body that
    contains an application-level error envelope).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        error_code: str | None = None,
        error_description: str | None = None,
        response_text: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.error_description = error_description
        self.response_text = response_text

    def __str__(self) -> str:  # pragma: no cover — trivial formatting
        bits = [super().__str__()]
        if self.error_code:
            bits.append(f"error_code={self.error_code!r}")
        if self.error_description:
            bits.append(f"error_description={self.error_description!r}")
        bits.append(f"status={self.status_code}")
        return " ".join(bits)


class TBankRateLimitError(TBankAPIError):
    """Server rejected with 429 Too Many Requests."""


class TBankConversationExpiredError(TBankAPIError):
    """
    The SSO ``cid`` (conversation) is no longer valid on the server —
    typically after more than a few minutes of inactivity between steps.
    Caller should start a fresh :meth:`tbank.TBankClient.begin_auth`.
    """


# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------


class TBankAuthError(TBankError):
    """Base class for auth-related failures."""


class TBankInvalidStateError(TBankAuthError):
    """
    The caller invoked an operation that isn't valid for the current state.

    Example: calling ``operations.list()`` before authentication, or trying
    to submit a password on an OTP step.
    """


class TBankTokenExpiredError(TBankAuthError):
    """
    ``access_token`` has expired and was not automatically refreshed
    (because ``auto_refresh=False`` on the client, or because refresh
    itself failed — in the latter case see :class:`TBankRefreshFailedError`).
    """


class TBankRefreshFailedError(TBankAuthError):
    """
    Refresh with the stored ``refresh_token`` failed. The token may be
    revoked, expired, or the server's anti-fraud system may be blocking
    this device. Caller should drop the tokens and restart the interactive
    login flow via :meth:`tbank.TBankClient.begin_auth`.
    """


class TBankAuthFlowError(TBankAuthError):
    """
    Unexpected state during an interactive auth flow — e.g. the server
    returned an unknown ``step`` value, a required field is missing, or
    the submitted OTP/password was rejected.
    """

    def __init__(self, message: str, *, step: str | None = None) -> None:
        super().__init__(message)
        self.step = step
