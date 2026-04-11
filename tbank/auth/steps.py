"""
Typed hierarchy of auth flow steps.

Each step is a frozen dataclass carrying the server's response fields plus
methods that advance the flow. Methods return a union of all possible next
steps (:data:`AnyAuthStep`), letting callers ``match`` on the type:

.. code-block:: python

    step = client.begin_auth()
    while not isinstance(step, AuthComplete):
        match step:
            case EntryStep():
                step = step.submit_phone("+79991234567")
            case OtpStep():
                step = step.submit_code(input(f"code ({step.length}d): "))
            case SelfieStep() if step.can_skip:
                step = step.skip()
            case PasswordStep():
                step = step.submit_password(getpass.getpass())
            case _:
                raise RuntimeError(f"unhandled step: {step!r}")
    tokens = step.exchange_for_tokens()

Each step instance is self-contained: it holds a reference to the internal
transport and the cookie jar accumulated up to that point, so nothing lives
in global state and two concurrent flows wouldn't interfere.

The :class:`_StepTransport` :class:`~typing.Protocol` is the narrow contract
between this module and :mod:`tbank.auth.flow`. Using a Protocol (not a
concrete import) keeps these files decoupled and avoids a circular import.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, TypeAlias

if TYPE_CHECKING:
    from tbank.models.auth import Tokens


# -----------------------------------------------------------------------------
# Selfie skip reason
# -----------------------------------------------------------------------------

class SelfieSkipReason(StrEnum):
    """
    Values accepted by the server for ``POST /auth/step`` when skipping a
    selfie step.

    .. list-table::
       :header-rows: 1

       * - Value
         - Meaning in the app
       * - ``CAMERA_UNAVAILABLE``
         - Device has no working camera. **Use this for headless Python clients.**
       * - ``SKIPPED_BY_USER``
         - User tapped the "Skip" button on the selfie UI.
       * - ``CANCELLED_BY_USER``
         - User closed the selfie screen without interacting.
       * - ``ERROR``
         - Selfie capture failed (network, ML model load, etc.).
    """

    CAMERA_UNAVAILABLE = "camera_unavailable"
    SKIPPED_BY_USER = "skipped_by_user"
    CANCELLED_BY_USER = "cancelled_by_user"
    ERROR = "error"


# -----------------------------------------------------------------------------
# Transport protocol — narrow contract used by steps to advance the flow
# -----------------------------------------------------------------------------

class _StepTransport(Protocol):
    """
    Internal protocol: what a step needs from the transport layer.

    Implemented by :class:`tbank.auth.flow._AuthTransport`. Declared as a
    Protocol (structural typing) so :mod:`tbank.auth.steps` and
    :mod:`tbank.auth.flow` don't have to import each other at runtime.
    """

    def submit_subaction(
        self,
        *,
        current_action: str,
        cid: str,
        current_cookies: dict[str, str],
        subaction: str,
        form: dict[str, str],
        sensitive_fields: frozenset[str] = frozenset(),
    ) -> AnyAuthStep: ...

    def exchange_code(
        self,
        *,
        code: str,
        cookies: dict[str, str],
    ) -> Tokens: ...


# -----------------------------------------------------------------------------
# Base
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class AuthStep:
    """
    Base class for interactive-flow steps.

    All steps carry:

    - :attr:`cid` — the server's "conversation id", echoed back in the
      query string of every subsequent ``POST /auth/<action>`` call. The
      server sometimes rotates it between steps; each new step carries
      the latest value.
    - :attr:`action` — the URL path segment of the *next* request
      (``"step"``, ``"entry"``, etc.). Comes from the server response
      ``action`` field.
    - :attr:`token` — continuation token the server hands over (``token``
      field in the response). OTP and security-question submissions echo
      this back in their form body; other submissions ignore it.
    - :attr:`auth_id`, :attr:`session_state` — OAuth bookkeeping.
    - :attr:`raw` — the complete response body, for forward-compat access
      to fields we haven't modeled.

    The two fields with a leading underscore — :attr:`_transport` and
    :attr:`_cookies` — are internal plumbing. They're excluded from
    ``__eq__``/``__repr__`` so step objects compare and print cleanly in
    tests.
    """

    cid: str
    action: str
    auth_id: str | None = None
    token: str | None = None
    session_state: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    # Internal plumbing — not part of the public equality.
    _transport: _StepTransport = field(repr=False, compare=False)
    _cookies: dict[str, str] = field(default_factory=dict, repr=False, compare=False)


# -----------------------------------------------------------------------------
# EntryStep — server expects a phone number
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class EntryStep(AuthStep):
    """
    Starting step of the interactive auth flow.

    Returned directly by :meth:`tbank.TBankClient.begin_auth`. Corresponds
    to the server's ``step: "entry"`` (or ``"phone"``) response — both
    are aliases for the same phone-submission step.

    Use :meth:`submit_phone` to send the user's phone number — this is
    the call that triggers the SMS.
    """

    app_name: str | None = None
    theme: str | None = None
    collect_fingerprint: bool = False
    """
    If ``True``, the server expects the next request to carry the full
    64-field device fingerprint JSON. The transport handles the
    building automatically — callers don't need to think about it.
    """

    def submit_phone(self, phone: str) -> AnyAuthStep:
        """
        Submit the phone number and trigger the SMS.

        The phone must be in **E.164** format, e.g. ``"+79991234567"``.
        Server-side, this step uses the action ``"phone"`` regardless of
        whether the current ``action`` field was ``"step"`` or ``"entry"``.

        The transport builds the fingerprint payload internally (using
        the device identity it was constructed with), so callers don't
        need to pass it.
        """
        form = {"phone": phone}
        return self._transport.submit_subaction(
            current_action=self.action,
            cid=self.cid,
            current_cookies=self._cookies,
            subaction="phone",
            form=form,
            sensitive_fields=frozenset(),
        )


# -----------------------------------------------------------------------------
# OtpStep — server expects an SMS OTP code
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class OtpStep(AuthStep):
    """
    Server expects the SMS code just sent to the user's phone.

    :attr:`length` tells you how many digits the server expects —
    T-Bank sometimes uses 4-digit codes rather than the typical 6.
    :attr:`phone_masked` echoes the phone the code was sent to, for
    display in UI.
    """

    length: int = 6
    phone_masked: str | None = None
    keyboard: str | None = None
    resend_allowed: bool = False
    recall_allowed: bool = False

    def submit_code(self, code: str) -> AnyAuthStep:
        """
        Submit the OTP code. Raises via the transport on server rejection.

        Retries aren't handled automatically — if the code is wrong the
        server will return an error; the caller decides whether to
        prompt again. For a fresh code (SMS rate limits allowing) use
        :meth:`resend` instead.
        """
        if self.token is None:
            from tbank.errors import TBankAuthFlowError

            raise TBankAuthFlowError(
                "OtpStep is missing the continuation 'token' — cannot submit code",
                step="otp",
            )
        form = {"otp": code, "token": self.token}
        return self._transport.submit_subaction(
            current_action=self.action,
            cid=self.cid,
            current_cookies=self._cookies,
            subaction="otp",
            form=form,
        )


# -----------------------------------------------------------------------------
# SelfieStep — biometric verification
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class SelfieStep(AuthStep):
    """
    Server asks for a biometric selfie (recorded via a separate
    biometric backend, not the SSO endpoint).

    Python clients have no camera and can't record the actual video. If
    :attr:`can_skip` is ``True`` — which it usually is on first login
    from a new device — the caller should invoke :meth:`skip` with a
    reason and the flow continues. If :attr:`can_skip` is ``False``,
    there's no way forward from a headless client; the caller must fall
    back to the real mobile app once and retry.
    """

    can_skip: bool = False
    selfie_source: str | None = None
    jwt: str | None = None

    def skip(
        self,
        reason: SelfieSkipReason = SelfieSkipReason.CAMERA_UNAVAILABLE,
    ) -> AnyAuthStep:
        """
        Skip the selfie step.

        :raises tbank.errors.TBankAuthFlowError: if the server set
            ``can_skip=False`` on this step.
        """
        if not self.can_skip:
            from tbank.errors import TBankAuthFlowError

            raise TBankAuthFlowError(
                "server does not allow skipping this selfie step "
                "(can_skip=False). Use the real mobile app once and "
                "retry afterwards.",
                step="selfie",
            )
        return self._transport.submit_subaction(
            current_action=self.action,
            cid=self.cid,
            current_cookies=self._cookies,
            subaction="selfie",
            form={"skipped": reason.value},
        )


# -----------------------------------------------------------------------------
# PasswordStep — server expects the user's password
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class PasswordStep(AuthStep):
    """
    Server expects the user's T-Bank account password.

    The password is sent in plaintext over TLS — there is no client-side
    hashing. The library's HTTP layer redacts it from any exchange logs
    written to disk, but callers should still treat it as highly sensitive.

    :attr:`name` may contain the user's first name — the server includes
    it in the response when it recognizes the phone ("Hi, Никита!").
    """

    name: str | None = None

    def submit_password(self, password: str) -> AnyAuthStep:
        """
        Submit the password. On success the server usually returns a
        terminal :class:`AuthComplete` with the authorization code.
        """
        return self._transport.submit_subaction(
            current_action=self.action,
            cid=self.cid,
            current_cookies=self._cookies,
            subaction="password",
            form={"password": password},
            sensitive_fields=frozenset({"password"}),
        )


# -----------------------------------------------------------------------------
# AuthComplete — terminal success state
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class AuthComplete:
    """
    Terminal successful state of the interactive flow.

    The server has accepted all prior steps and handed over an OAuth 2
    authorization code (:attr:`code`). One final call —
    :meth:`exchange_for_tokens` — swaps the code for the actual
    access / refresh / id tokens.

    AuthComplete is **not** a subclass of :class:`AuthStep` because it
    doesn't have a ``cid`` / ``action`` (the conversation is done) and
    its only operation is the token exchange.
    """

    code: str
    is_authorization_finished: bool = True
    session_state: str | None = None
    auth_id: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    _transport: _StepTransport = field(repr=False, compare=False)
    _cookies: dict[str, str] = field(default_factory=dict, repr=False, compare=False)

    def exchange_for_tokens(self) -> Tokens:
        """
        Exchange the authorization code for an access_token +
        refresh_token + id_token bundle.

        Calls ``POST /auth/token`` with ``grant_type=authorization_code``
        and the saved PKCE verifier. The caller is expected to persist
        the returned :class:`~tbank.models.auth.Tokens` —
        :class:`tbank.TBankClient` does this automatically.
        """
        return self._transport.exchange_code(
            code=self.code,
            cookies=self._cookies,
        )


# -----------------------------------------------------------------------------
# UnknownStep — catch-all for server steps we haven't modeled
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True, kw_only=True)
class UnknownStep(AuthStep):
    """
    Catch-all for server responses whose ``step`` field doesn't match a
    known :class:`AuthStep` subclass.

    The library models only the steps it has seen and tested
    (entry/phone/otp/selfie/password/complete). When the server returns
    a different step, the parser yields :class:`UnknownStep` instead of
    crashing — callers can inspect :attr:`raw` and decide whether to
    fall back to the real mobile app or open an issue against this
    library.
    """

    step_name: str = ""


# -----------------------------------------------------------------------------
# Union alias
# -----------------------------------------------------------------------------

AnyAuthStep: TypeAlias = (
    EntryStep
    | OtpStep
    | SelfieStep
    | PasswordStep
    | AuthComplete
    | UnknownStep
)
"""
Discriminated union of every possible auth flow state the library
returns. Use it as the return type of methods that advance the flow;
use Python's ``match`` statement to dispatch on the concrete type.
"""
