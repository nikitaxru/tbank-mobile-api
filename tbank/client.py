"""
:class:`TBankClient` — the single entry point for library users.

Holds an :class:`~tbank.http.HttpClient`, the persistent
:class:`~tbank.storage.State`, the device :class:`~tbank.identity.Identity`,
and the internal auth transport. Exposes namespaced business APIs
(``client.accounts``, ``client.operations``) and high-level auth
helpers (:meth:`begin_auth`, :meth:`login_interactive`,
:meth:`refresh`).

Typical usage::

    from tbank import TBankClient
    from tbank.storage import FileStorage

    with TBankClient(storage=FileStorage("~/.tbank")) as client:
        if not client.is_authenticated():
            client.login_interactive()
        for account in client.accounts.list():
            print(account)
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from getpass import getpass
from pathlib import Path
from types import TracebackType
from typing import Any

from tbank.api.accounts import AccountsAPI
from tbank.api.operations import OperationsAPI
from tbank.auth import constants as C
from tbank.auth.fingerprint import DeviceProfile
from tbank.auth.flow import _AuthTransport
from tbank.auth.steps import (
    AnyAuthStep,
    AuthComplete,
    EntryStep,
    OtpStep,
    PasswordStep,
    SelfieSkipReason,
    SelfieStep,
    UnknownStep,
)
from tbank.errors import (
    TBankAPIError,
    TBankAuthFlowError,
    TBankInvalidStateError,
    TBankRefreshFailedError,
)
from tbank.http import HttpClient, HttpResponse
from tbank.identity import Identity
from tbank.models.auth import Tokens
from tbank.storage import State, Storage

PhonePrompt = Callable[[], str]
OtpPrompt = Callable[[OtpStep], str]
PasswordPrompt = Callable[[PasswordStep], str]


class TBankClient:
    """
    Main library entry point.

    Constructor parameters are keyword-only for forward compatibility.
    The only strictly required argument is ``storage`` — everything
    else has a sensible default.

    :param storage: Backing store for persistent state (device identity
        + tokens + transient auth flow). Supply a
        :class:`~tbank.storage.FileStorage` for normal use or a
        :class:`~tbank.storage.MemoryStorage` for tests.
    :param auto_refresh: When ``True`` (default), business API calls
        transparently refresh the access_token before it expires, and
        retry once on a 401 response. Set to ``False`` to manage
        refresh manually via :meth:`refresh`.
    :param rate_limit_interval: Minimum seconds between requests to any
        single host. Defaults to ``1.0`` — polite enough for normal
        interactive use and still quick. Pass ``0`` to disable.
    :param log_exchanges: Enable per-request JSON dumps to
        ``exchange_log_dir``. Disabled by default; useful during
        development.
    :param exchange_log_dir: Directory for exchange logs. Required
        when ``log_exchanges=True``.
    :param device_profile: Override the default "Pixel 7 on Android 14"
        device profile used for the User-Agent and device fingerprint
        JSON. Supply your own :class:`~tbank.auth.DeviceProfile` only
        if you understand the implications — mismatched ``Build.*``
        fields can trigger server-side heuristics.
    :param timeout: Default per-request timeout in seconds.
    :param http_client: **Advanced.** Inject a pre-configured
        :class:`~tbank.http.HttpClient`. When provided, the client does
        not own its lifecycle — :meth:`close` will NOT close it. Use
        this to share a connection pool between multiple clients, or
        to inject a mock in tests.
    """

    def __init__(
        self,
        *,
        storage: Storage,
        auto_refresh: bool = True,
        rate_limit_interval: float = 1.0,
        log_exchanges: bool = False,
        exchange_log_dir: Path | None = None,
        device_profile: DeviceProfile | None = None,
        timeout: float = 30.0,
        http_client: HttpClient | None = None,
    ) -> None:
        self._storage = storage
        self._auto_refresh = auto_refresh
        self._state = State(storage)
        self._identity = Identity.load_or_create(self._state)
        if http_client is None:
            self._http = HttpClient(
                rate_limit_interval=rate_limit_interval,
                log_exchanges=log_exchanges,
                exchange_log_dir=exchange_log_dir,
                timeout=timeout,
            )
            self._owns_http = True
        else:
            self._http = http_client
            self._owns_http = False
        self._auth_transport = _AuthTransport(
            http=self._http,
            identity=self._identity,
            state=self._state,
            device_profile=device_profile,
        )
        self._accounts = AccountsAPI(self)
        self._operations = OperationsAPI(self)

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def close(self) -> None:
        """
        Release the underlying HTTP connection pool.

        Only closes the :class:`~tbank.http.HttpClient` if this
        :class:`TBankClient` created it; a client injected via the
        ``http_client`` constructor parameter is left alone (the
        caller owns its lifecycle).

        Idempotent.
        """
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> TBankClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -------------------------------------------------------------------------
    # Identity / state accessors (mostly for tests and debugging)
    # -------------------------------------------------------------------------

    @property
    def identity(self) -> Identity:
        """The persistent device identity used by this client."""
        return self._identity

    @property
    def tokens(self) -> Tokens | None:
        """
        Return the currently persisted tokens, or ``None`` if the user
        hasn't logged in yet.

        This reads from storage on every access — fresh process
        restarts see rotated tokens immediately.
        """
        return self._state.read_tokens()

    def is_authenticated(self) -> bool:
        """
        True iff we have tokens that are usable for business API calls.

        When ``auto_refresh=True``, an expired access_token still
        counts as "authenticated" because :meth:`refresh` can recover
        it transparently. When ``auto_refresh=False``, expired tokens
        count as unauthenticated and the caller must explicitly refresh
        or re-authenticate.
        """
        tokens = self.tokens
        if tokens is None:
            return False
        return not (tokens.is_expired() and not self._auto_refresh)

    # -------------------------------------------------------------------------
    # Business API namespaces
    # -------------------------------------------------------------------------

    @property
    def accounts(self) -> AccountsAPI:
        """Namespace with account-related endpoints."""
        return self._accounts

    @property
    def operations(self) -> OperationsAPI:
        """Namespace with transaction-related endpoints."""
        return self._operations

    # -------------------------------------------------------------------------
    # Auth flow — programmatic
    # -------------------------------------------------------------------------

    def begin_auth(self) -> AnyAuthStep:
        """
        Start a fresh interactive auth flow.

        Clears any half-finished flow state (leftover PKCE, cookies)
        before calling ``POST /auth/authorize``. Returns the server's
        first step — typically an :class:`~tbank.auth.EntryStep` that
        expects a phone number.

        Previous tokens (if any) are **not** touched: callers can still
        run authenticated API calls in parallel with an ongoing login.
        Only after :meth:`AuthComplete.exchange_for_tokens` returns do
        the new tokens overwrite the old ones.
        """
        self._state.clear_pkce()
        self._state.clear_flow()
        return self._auth_transport.begin_authorize()

    def login_interactive(
        self,
        *,
        phone_prompt: PhonePrompt | None = None,
        otp_prompt: OtpPrompt | None = None,
        password_prompt: PasswordPrompt | None = None,
        selfie_skip_reason: SelfieSkipReason = SelfieSkipReason.CAMERA_UNAVAILABLE,
    ) -> Tokens:
        """
        Walk the user through the interactive SMS+password flow end to end.

        Uses ``stdin``/``getpass`` by default — supply your own prompt
        callables to integrate with a different UI (a GUI, a Telegram
        bot, etc.):

        .. code-block:: python

            client.login_interactive(
                phone_prompt=lambda: "+79991234567",
                otp_prompt=lambda step: input(
                    f"SMS code ({step.length} digits, "
                    f"sent to {step.phone_masked}): "
                ),
                password_prompt=lambda step: getpass(
                    f"Password for {step.name or 'your account'}: "
                ),
            )

        :param selfie_skip_reason: Reason to send on the selfie step.
            Defaults to ``CAMERA_UNAVAILABLE`` which is the truth for
            a headless Python client. Only used if the server allows
            skipping (``SelfieStep.can_skip == True``); otherwise a
            :class:`~tbank.errors.TBankAuthFlowError` is raised.

        :raises TBankAuthFlowError: On an unexpected step (e.g.
            birthday / card / security question — not yet modeled),
            or on a selfie step that doesn't allow skipping.
        """
        phone_prompt = phone_prompt or _default_phone_prompt
        otp_prompt = otp_prompt or _default_otp_prompt
        password_prompt = password_prompt or _default_password_prompt

        step: AnyAuthStep = self.begin_auth()

        while True:
            if isinstance(step, EntryStep):
                phone = phone_prompt()
                step = step.submit_phone(phone)
            elif isinstance(step, OtpStep):
                code = otp_prompt(step)
                step = step.submit_code(code)
            elif isinstance(step, SelfieStep):
                if not step.can_skip:
                    raise TBankAuthFlowError(
                        "server requires an actual selfie capture "
                        "(can_skip=False); cannot continue from a headless client",
                        step="selfie",
                    )
                step = step.skip(selfie_skip_reason)
            elif isinstance(step, PasswordStep):
                password = password_prompt(step)
                step = step.submit_password(password)
            elif isinstance(step, AuthComplete):
                break
            elif isinstance(step, UnknownStep):
                raise TBankAuthFlowError(
                    f"server returned an unknown step {step.step_name!r}; "
                    f"the library does not model this yet. "
                    f"Raw response: {step.raw}",
                    step=step.step_name,
                )
            else:  # pragma: no cover — exhaustive match, mypy helps
                raise TBankAuthFlowError(f"unhandled step type: {type(step).__name__}")

        tokens = step.exchange_for_tokens()
        self._state.write_tokens(tokens)
        return tokens

    # -------------------------------------------------------------------------
    # Token refresh
    # -------------------------------------------------------------------------

    def refresh(self) -> Tokens:
        """
        Force a token refresh right now.

        Calls ``POST /auth/token`` with ``grant_type=refresh_token``
        using the currently stored :attr:`Tokens.refresh_token`, saves
        the rotated tokens to state, and returns them.

        :raises TBankInvalidStateError: If there are no tokens to refresh.
        :raises TBankRefreshFailedError: If the server rejects the
            refresh (revoked token, expired token, anti-fraud block,
            etc.). The caller should typically drop the tokens and
            restart the interactive login.
        """
        current = self._state.read_tokens()
        if current is None:
            raise TBankInvalidStateError(
                "no tokens to refresh — run begin_auth() or login_interactive() first"
            )
        try:
            fresh = self._auth_transport.refresh(refresh_token=current.refresh_token)
        except TBankAPIError as e:
            raise TBankRefreshFailedError(
                f"refresh failed: {e.error_code or ''} "
                f"{e.error_description or ''} "
                f"(status {e.status_code})".strip()
            ) from e
        self._state.write_tokens(fresh)
        return fresh

    # -------------------------------------------------------------------------
    # Internal — authenticated request used by api/ namespaces
    # -------------------------------------------------------------------------

    def _request_api_json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        label: str | None = None,
        timeout: float | None = None,
        _retry_on_401: bool = True,
    ) -> tuple[Any, HttpResponse]:
        """
        Issue an authenticated request to the business API and parse
        the JSON body.

        Handles the auto-refresh logic centrally:

        1. Loads current tokens; refreshes proactively if they expire
           within 60 seconds and ``auto_refresh=True``.
        2. Builds headers with ``Authorization: Bearer …`` and
           ``X-MB-Authorized: true``.
        3. On a 401 response, if ``auto_refresh=True`` and we haven't
           already retried, refresh once and retry the request.

        :param path: Path relative to :data:`~tbank.auth.constants.API_BASE_URL`.
            Leading slash is stripped.
        """
        tokens = self._ensure_fresh_tokens()
        url = C.API_BASE_URL + path.lstrip("/")
        headers = self._build_business_headers(tokens)

        try:
            return self._http.request_json(
                method,
                url,
                headers=headers,
                params=params,
                label=label or path.replace("/", "_"),
                timeout=timeout,
            )
        except TBankAPIError as e:
            if (
                e.status_code == 401
                and _retry_on_401
                and self._auto_refresh
            ):
                self.refresh()
                return self._request_api_json(
                    method,
                    path,
                    params=params,
                    label=label,
                    timeout=timeout,
                    _retry_on_401=False,
                )
            raise

    def _ensure_fresh_tokens(self) -> Tokens:
        """
        Load tokens from state; refresh proactively if they're close
        to expiring and ``auto_refresh`` is on.
        """
        tokens = self._state.read_tokens()
        if tokens is None:
            raise TBankInvalidStateError(
                "not authenticated — run login_interactive() first"
            )
        if self._auto_refresh and tokens.expires_within(60):
            tokens = self.refresh()
        return tokens

    def _build_business_headers(self, tokens: Tokens) -> dict[str, str]:
        """
        Assemble the header set attached to every authenticated request.

        ``X-MB-Authorized: true`` is the marker the mobile app's auth
        interceptor checks before attaching the Bearer token; we set
        the flag to match the wire shape the server expects.
        """
        return {
            **C.build_base_headers(self._identity),
            "X-MB-Authorized": "true",
            "Authorization": f"{tokens.token_type} {tokens.access_token}",
        }


# -----------------------------------------------------------------------------
# Default interactive prompts
# -----------------------------------------------------------------------------

def _default_phone_prompt() -> str:
    phone = input("Phone number (+7…): ").strip()
    if not (phone.startswith("+") and phone[1:].isdigit() and len(phone) >= 11):
        raise TBankAuthFlowError(
            f"invalid E.164 phone number: {phone!r}",
            step="phone",
        )
    return phone


def _default_otp_prompt(step: OtpStep) -> str:
    prompt = f"SMS code ({step.length} digits"
    if step.phone_masked:
        prompt += f", sent to {step.phone_masked}"
    prompt += "): "
    return input(prompt).strip()


def _default_password_prompt(step: PasswordStep) -> str:
    name = step.name or "your account"
    return getpass(f"Password for {name}: ")
