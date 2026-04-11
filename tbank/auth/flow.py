"""
Internal auth flow transport and response parser.

This module implements the concrete :class:`_AuthTransport` class that
the step objects in :mod:`tbank.auth.steps` dispatch into, plus the
``_parse_step_response`` function that turns raw server JSON into the
right typed step. Both are library-internal — callers don't construct
them directly; they come out of :class:`tbank.TBankClient`.
"""
from __future__ import annotations

from collections.abc import Mapping
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import quote

from tbank.auth import constants as C
from tbank.auth.fingerprint import DeviceProfile, build_fingerprint_json
from tbank.auth.pkce import PkcePair
from tbank.auth.steps import (
    AnyAuthStep,
    AuthComplete,
    EntryStep,
    OtpStep,
    PasswordStep,
    SelfieStep,
    UnknownStep,
)
from tbank.errors import TBankAuthFlowError, TBankRefreshFailedError
from tbank.http import HttpClient
from tbank.identity import Identity
from tbank.models.auth import Tokens
from tbank.storage import State

# -----------------------------------------------------------------------------
# Cookie helpers
# -----------------------------------------------------------------------------

def _parse_set_cookie(header_value: str | None) -> dict[str, str]:
    """
    Turn a ``Set-Cookie`` header (possibly concatenated by httpx) into a
    flat ``{name: value}`` dict.

    httpx normalizes multiple ``Set-Cookie`` lines into one comma-joined
    header — :class:`http.cookies.SimpleCookie` handles that format
    correctly.
    """
    if not header_value:
        return {}
    jar: SimpleCookie = SimpleCookie()
    jar.load(header_value)
    return {name: morsel.value for name, morsel in jar.items()}


def _merge_cookies(
    existing: dict[str, str],
    response_headers: Mapping[str, str],
) -> dict[str, str]:
    """Return a new dict: old cookies + any ``Set-Cookie`` from the response."""
    merged = dict(existing)
    merged.update(_parse_set_cookie(response_headers.get("set-cookie")))
    return merged


# -----------------------------------------------------------------------------
# Response → typed step
# -----------------------------------------------------------------------------

def _parse_step_response(
    data: dict[str, Any],
    *,
    transport: _AuthTransport,
    cookies: dict[str, str],
) -> AnyAuthStep:
    """
    Translate a raw ``auth/*`` response body into the right
    :class:`~tbank.auth.steps.AuthStep` subclass.

    The server signals completion by returning a ``code`` field and
    setting ``isAuthorizationFinished: true`` (at which point the
    ``step`` field is absent). Otherwise it sets ``step`` to one of the
    known values.

    Unrecognized steps become :class:`~tbank.auth.steps.UnknownStep` so
    the library doesn't crash on server-side changes it doesn't model.
    """
    if data.get("code"):
        return AuthComplete(
            code=str(data["code"]),
            is_authorization_finished=bool(data.get("isAuthorizationFinished", True)),
            session_state=data.get("session_state"),
            auth_id=data.get("authId"),
            raw=dict(data),
            _transport=transport,
            _cookies=cookies,
        )

    step_name = str(data.get("step", ""))
    action = str(data.get("action", "step"))
    cid = str(data.get("cid", ""))
    if not cid:
        raise TBankAuthFlowError(
            f"server response missing 'cid' (step={step_name!r})",
            step=step_name,
        )

    common: dict[str, Any] = {
        "cid": cid,
        "action": action,
        "auth_id": data.get("authId"),
        "token": data.get("token"),
        "session_state": data.get("session_state"),
        "raw": dict(data),
        "_transport": transport,
        "_cookies": cookies,
    }

    if step_name in ("entry", "phone"):
        return EntryStep(
            **common,
            app_name=data.get("app_name"),
            theme=data.get("theme"),
            collect_fingerprint=bool(data.get("collectFingerprint", False)),
        )

    if step_name == "otp":
        length_raw = data.get("length")
        return OtpStep(
            **common,
            length=int(length_raw) if length_raw is not None else 6,
            phone_masked=data.get("phone"),
            keyboard=data.get("keyboard"),
            resend_allowed=bool(data.get("resend", False)),
            recall_allowed=bool(data.get("recall", False)),
        )

    if step_name == "selfie":
        return SelfieStep(
            **common,
            can_skip=bool(data.get("canSkip", False)),
            selfie_source=data.get("selfieSource"),
            jwt=data.get("jwt"),
        )

    if step_name == "password":
        return PasswordStep(
            **common,
            name=data.get("name"),
        )

    return UnknownStep(**common, step_name=step_name)


# -----------------------------------------------------------------------------
# Transport
# -----------------------------------------------------------------------------

class _AuthTransport:
    """
    Concrete implementation of the :class:`~tbank.auth.steps._StepTransport`
    protocol. Internal — callers interact via
    :class:`tbank.TBankClient` and the returned step objects.

    Holds the three dependencies the auth flow needs: an
    :class:`~tbank.http.HttpClient` for wire traffic, a
    :class:`~tbank.identity.Identity` for device fingerprint / UA, and
    a :class:`~tbank.storage.State` for PKCE + token persistence.

    The transport is stateless apart from those dependencies. All flow
    state (cid, cookies, continuation token) lives on the step objects
    returned from :meth:`begin_authorize` / :meth:`submit_subaction`.
    """

    def __init__(
        self,
        *,
        http: HttpClient,
        identity: Identity,
        state: State,
        device_profile: DeviceProfile | None = None,
    ) -> None:
        self._http = http
        self._identity = identity
        self._state = state
        self._device_profile = device_profile

    # -------------------------------------------------------------------------
    # Step 1 — begin_authorize
    # -------------------------------------------------------------------------

    def begin_authorize(self) -> AnyAuthStep:
        """
        Start a fresh auth flow by POSTing to ``/auth/authorize``.

        Generates a new PKCE pair (or reuses a saved one), builds the
        OAuth2 form body, and parses the server's first ``step`` response.
        """
        pkce = PkcePair.load_or_generate(self._state)
        headers = self._auth_headers()
        body = {
            "client_id": C.CLIENT_ID,
            "redirect_uri": C.REDIRECT_URI,
            "response_type": C.RESPONSE_TYPE,
            "response_mode": C.RESPONSE_MODE,
            "display": C.DISPLAY,
            "device_id": self._identity.tinkoff_device_id,
            "client_version": C.CLIENT_VERSION,
            "vendor": C.VENDOR,
            "claims": C.CLAIMS,
            "code_challenge": pkce.challenge,
            "code_challenge_method": pkce.method,
        }
        data, response = self._http.request_json(
            "POST",
            C.SSO_BASE_URL + "auth/authorize",
            headers=headers,
            data=body,
            label="auth_authorize",
        )
        if not isinstance(data, dict):
            raise TBankAuthFlowError(
                f"authorize response was not a JSON object: {type(data).__name__}"
            )
        cookies = _parse_set_cookie(response.headers.get("set-cookie"))
        return _parse_step_response(data, transport=self, cookies=cookies)

    # -------------------------------------------------------------------------
    # Step N — submit_subaction
    # -------------------------------------------------------------------------

    def submit_subaction(
        self,
        *,
        current_action: str,
        cid: str,
        current_cookies: dict[str, str],
        subaction: str,
        form: dict[str, str],
        sensitive_fields: frozenset[str] = frozenset(),
    ) -> AnyAuthStep:
        """
        Continue the flow by POSTing ``/auth/<current_action>?cid=<cid>``.

        Handles two subtleties that step classes shouldn't have to know
        about:

        - **Fingerprint injection**: if ``subaction == "phone"`` we
          compute the ssoData hash from the current ``cid`` and attach
          the full 64-field fingerprint JSON to the form body. All other
          subactions pass the form through unchanged.
        - **``step`` form field**: the server expects a ``step=<name>``
          form field alongside the user-provided values. We add it here
          based on ``subaction``.
        """
        body: dict[str, str] = dict(form)
        body["step"] = subaction

        if subaction == "phone":
            user_agent = self._http_user_agent()
            fp_kwargs: dict[str, Any] = {
                "identity": self._identity,
                "cid": cid,
                "user_agent": user_agent,
            }
            if self._device_profile is not None:
                fp_kwargs["profile"] = self._device_profile
            body["fingerprint"] = build_fingerprint_json(**fp_kwargs)

        url = C.SSO_BASE_URL + f"auth/{quote(current_action, safe='')}"
        headers = self._auth_headers()

        data, response = self._http.request_json(
            "POST",
            url,
            headers=headers,
            params={"cid": cid},
            data=body,
            cookies=current_cookies,
            sensitive_fields=set(sensitive_fields),
            label=f"auth_step_{subaction}",
        )
        if not isinstance(data, dict):
            raise TBankAuthFlowError(
                f"step {subaction!r} response was not a JSON object: {type(data).__name__}"
            )

        new_cookies = _merge_cookies(current_cookies, response.headers)
        return _parse_step_response(data, transport=self, cookies=new_cookies)

    # -------------------------------------------------------------------------
    # Terminal — exchange_code / refresh
    # -------------------------------------------------------------------------

    def exchange_code(
        self,
        *,
        code: str,
        cookies: dict[str, str],
    ) -> Tokens:
        """
        Exchange the OAuth authorization code for tokens.

        POST ``/auth/token`` with ``grant_type=authorization_code``. The
        ``code_verifier`` is read from the PKCE pair saved earlier —
        without it (e.g. if storage was wiped mid-flow) we raise
        :class:`~tbank.errors.TBankAuthFlowError`.

        On success, the PKCE state is cleared — the verifier is
        single-use and keeping it around is a minor security risk.
        """
        pkce = PkcePair.load(self._state)
        if pkce is None:
            raise TBankAuthFlowError(
                "no saved PKCE pair — cannot exchange code without the code_verifier"
            )

        headers = {
            **self._auth_headers(),
            "X-SSO-No-Adapter": "true",
            "Authorization": C.BASIC_AUTH,
        }
        body = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": C.REDIRECT_URI,
            "client_version": C.CLIENT_VERSION,
            "vendor": C.VENDOR,
            "code_verifier": pkce.verifier,
        }
        data, _ = self._http.request_json(
            "POST",
            C.SSO_BASE_URL + "auth/token",
            headers=headers,
            data=body,
            cookies=cookies,
            sensitive_fields={"code_verifier"},
            label="auth_token_exchange",
        )
        if not isinstance(data, dict) or "access_token" not in data:
            raise TBankAuthFlowError(
                f"auth/token response missing access_token: {data!r}"
            )

        tokens = Tokens.from_api(data)
        # Single-use: drop the verifier so it cannot be replayed.
        self._state.clear_pkce()
        return tokens

    def refresh(self, *, refresh_token: str) -> Tokens:
        """
        Refresh the access_token via
        ``POST /auth/token grant_type=refresh_token``.

        Uses the classic SSO endpoint, not the ``/auth/token/mobile`` BFF
        variant — the latter rejects refresh requests with this client_id.

        ``refresh_token`` is rotated on every successful call: the new
        ``refresh_token`` is a different string and the old one is
        invalidated server-side.
        """
        headers = {
            **self._auth_headers(),
            "X-SSO-No-Adapter": "true",
            "Authorization": C.BASIC_AUTH,
            "x-content-id": self._identity.stable_id,
        }
        body = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "device_id": self._identity.tinkoff_device_id,
            "old_device_id": self._identity.tinkoff_device_id,
            # Refresh wants a UUID-shaped fingerprint slot;
            # the persistent stable_id is the natural fit.
            "fingerprint": self._identity.stable_id,
            "client_version": C.CLIENT_VERSION,
            "vendor": C.VENDOR,
        }
        data, _ = self._http.request_json(
            "POST",
            C.SSO_BASE_URL + "auth/token",
            headers=headers,
            data=body,
            sensitive_fields={"refresh_token"},
            label="auth_token_refresh",
        )
        if not isinstance(data, dict) or "access_token" not in data:
            raise TBankRefreshFailedError(
                f"refresh response did not contain access_token: {data!r}"
            )
        return Tokens.from_api(data)

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        return {
            **C.build_base_headers(self._identity),
            "Content-Type": "application/x-www-form-urlencoded",
        }

    def _http_user_agent(self) -> str:
        return C.build_user_agent(self._identity)
