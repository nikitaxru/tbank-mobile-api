"""
Unit tests for the auth flow state machine: parser, step guard rails,
cookie handling.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from tbank.auth.flow import _merge_cookies, _parse_set_cookie, _parse_step_response
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
from tbank.errors import TBankAuthFlowError
from tbank.models.auth import Tokens

# -----------------------------------------------------------------------------
# Fake transport — only sees method calls, never hits the network.
# -----------------------------------------------------------------------------

class _FakeTransport:
    """Implements :class:`~tbank.auth.steps._StepTransport` structurally."""

    def __init__(self) -> None:
        self.submit_calls: list[dict[str, Any]] = []
        self.exchange_calls: list[dict[str, Any]] = []
        self._next_step: AnyAuthStep | None = None
        self._tokens: Tokens | None = None

    def set_next_step(self, step: AnyAuthStep) -> None:
        self._next_step = step

    def set_tokens(self, tokens: Tokens) -> None:
        self._tokens = tokens

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
        self.submit_calls.append(
            {
                "current_action": current_action,
                "cid": cid,
                "current_cookies": dict(current_cookies),
                "subaction": subaction,
                "form": dict(form),
                "sensitive_fields": set(sensitive_fields),
            }
        )
        assert self._next_step is not None, "fake transport: no next step configured"
        return self._next_step

    def exchange_code(self, *, code: str, cookies: dict[str, str]) -> Tokens:
        self.exchange_calls.append({"code": code, "cookies": dict(cookies)})
        assert self._tokens is not None, "fake transport: no tokens configured"
        return self._tokens


# =============================================================================
# _parse_step_response — covers every known step type
# =============================================================================

class TestStepParser:
    def _parse(self, data: dict[str, Any]) -> AnyAuthStep:
        return _parse_step_response(data, transport=_FakeTransport(), cookies={})

    def test_entry_step(self) -> None:
        step = self._parse(
            {
                "authId": "A1",
                "clientId": "tinkoff-mb-app",
                "action": "step",
                "step": "entry",
                "cid": "CID1",
                "collectFingerprint": True,
                "app_name": "Т-Банк",
                "theme": "default",
            }
        )
        assert isinstance(step, EntryStep)
        assert step.cid == "CID1"
        assert step.action == "step"
        assert step.auth_id == "A1"
        assert step.collect_fingerprint is True
        assert step.app_name == "Т-Банк"
        assert step.theme == "default"

    def test_phone_step_alias(self) -> None:
        """step='phone' parses as EntryStep (same PhoneOperation in the APK)."""
        step = self._parse({"action": "step", "step": "phone", "cid": "C"})
        assert isinstance(step, EntryStep)

    def test_otp_step(self) -> None:
        step = self._parse(
            {
                "authId": "A1",
                "action": "step",
                "step": "otp",
                "cid": "CID1",
                "token": "continuation-xyz",
                "length": 4,
                "phone": "+7 000 000-00-00",
                "keyboard": "numeric",
                "resend": True,
                "recall": False,
            }
        )
        assert isinstance(step, OtpStep)
        assert step.length == 4
        assert step.token == "continuation-xyz"
        assert step.phone_masked == "+7 000 000-00-00"
        assert step.keyboard == "numeric"
        assert step.resend_allowed is True
        assert step.recall_allowed is False

    def test_otp_step_default_length(self) -> None:
        """When the server omits length, we fall back to 6 (typical default)."""
        step = self._parse(
            {"action": "step", "step": "otp", "cid": "C", "token": "t"}
        )
        assert isinstance(step, OtpStep)
        assert step.length == 6

    def test_selfie_step(self) -> None:
        step = self._parse(
            {
                "action": "step",
                "step": "selfie",
                "cid": "CID1",
                "canSkip": True,
                "selfieSource": "crater",
                "jwt": "eyJ...",
            }
        )
        assert isinstance(step, SelfieStep)
        assert step.can_skip is True
        assert step.selfie_source == "crater"
        assert step.jwt == "eyJ..."

    def test_password_step(self) -> None:
        step = self._parse(
            {
                "action": "step",
                "step": "password",
                "cid": "CID1",
                "name": "Никита",
            }
        )
        assert isinstance(step, PasswordStep)
        assert step.name == "Никита"

    def test_auth_complete(self) -> None:
        """Presence of `code` signals completion regardless of step field."""
        step = self._parse(
            {
                "authId": "A1",
                "isAuthorizationFinished": True,
                "code": "c.abc123",
                "session_state": "session-state-xyz",
            }
        )
        assert isinstance(step, AuthComplete)
        assert step.code == "c.abc123"
        assert step.is_authorization_finished is True
        assert step.session_state == "session-state-xyz"

    def test_unknown_step_is_catch_all(self) -> None:
        """Unknown step names don't crash — they become UnknownStep."""
        step = self._parse(
            {"action": "step", "step": "some-new-step", "cid": "CID1"}
        )
        assert isinstance(step, UnknownStep)
        assert step.step_name == "some-new-step"

    def test_missing_cid_raises(self) -> None:
        with pytest.raises(TBankAuthFlowError):
            self._parse({"action": "step", "step": "otp"})


# =============================================================================
# Step guard rails — reject misuse before any network call
# =============================================================================

class TestStepGuardRails:
    def test_otp_without_token_raises_early(self) -> None:
        """submit_code() must refuse to run if the step lacks a token."""
        transport = _FakeTransport()
        step = OtpStep(
            cid="C",
            action="step",
            token=None,  # missing!
            length=4,
            _transport=transport,
        )
        with pytest.raises(TBankAuthFlowError) as exc_info:
            step.submit_code("1234")
        assert exc_info.value.step == "otp"
        assert transport.submit_calls == []  # must not have reached the network

    def test_selfie_no_skip_refuses(self) -> None:
        """skip() refuses when server set can_skip=False."""
        transport = _FakeTransport()
        step = SelfieStep(
            cid="C",
            action="step",
            can_skip=False,
            _transport=transport,
        )
        with pytest.raises(TBankAuthFlowError) as exc_info:
            step.skip()
        assert exc_info.value.step == "selfie"
        assert transport.submit_calls == []


# =============================================================================
# Step dispatch — steps forward the right payload to the transport
# =============================================================================

class TestStepDispatch:
    def test_entry_step_submits_phone(self) -> None:
        transport = _FakeTransport()
        next_step = OtpStep(
            cid="C2", action="step", token="t1", length=4, _transport=transport
        )
        transport.set_next_step(next_step)

        step = EntryStep(cid="C1", action="step", _transport=transport)
        result = step.submit_phone("+79991234567")

        assert result is next_step
        assert len(transport.submit_calls) == 1
        call = transport.submit_calls[0]
        assert call["current_action"] == "step"
        assert call["cid"] == "C1"
        assert call["subaction"] == "phone"
        assert call["form"]["phone"] == "+79991234567"

    def test_otp_step_submits_code_with_token(self) -> None:
        transport = _FakeTransport()
        transport.set_next_step(
            PasswordStep(cid="C", action="step", _transport=transport)
        )

        step = OtpStep(
            cid="C",
            action="step",
            token="continuation-xyz",
            length=4,
            _transport=transport,
        )
        step.submit_code("4242")

        form = transport.submit_calls[0]["form"]
        assert form["otp"] == "4242"
        assert form["token"] == "continuation-xyz"

    def test_selfie_skip_uses_reason_value(self) -> None:
        transport = _FakeTransport()
        transport.set_next_step(
            PasswordStep(cid="C", action="step", _transport=transport)
        )

        step = SelfieStep(
            cid="C", action="step", can_skip=True, _transport=transport
        )
        step.skip(SelfieSkipReason.CAMERA_UNAVAILABLE)

        form = transport.submit_calls[0]["form"]
        assert form["skipped"] == "camera_unavailable"

    def test_password_step_marks_password_sensitive(self) -> None:
        transport = _FakeTransport()
        transport.set_next_step(
            AuthComplete(code="c.xxx", _transport=transport)
        )

        step = PasswordStep(cid="C", action="step", _transport=transport)
        step.submit_password("super-secret")

        call = transport.submit_calls[0]
        assert call["form"]["password"] == "super-secret"
        assert "password" in call["sensitive_fields"]

    def test_auth_complete_exchange_for_tokens(self) -> None:
        import datetime as dt
        transport = _FakeTransport()
        issued = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
        transport.set_tokens(
            Tokens(
                access_token="t.aaa",
                refresh_token="r.bbb",
                token_type="Bearer",
                issued_at=issued,
                expires_at=issued + dt.timedelta(hours=2),
            )
        )

        complete = AuthComplete(code="c.xxx", _transport=transport)
        tokens = complete.exchange_for_tokens()

        assert tokens.access_token == "t.aaa"
        assert len(transport.exchange_calls) == 1
        assert transport.exchange_calls[0]["code"] == "c.xxx"


# =============================================================================
# Cookie helpers
# =============================================================================

class TestCookieHelpers:
    def test_parse_empty(self) -> None:
        assert _parse_set_cookie("") == {}
        assert _parse_set_cookie(None) == {}

    def test_parse_single_cookie(self) -> None:
        header = "sessionid=abc; Expires=Fri, 10 Apr 2026 23:31:16 GMT; Secure; HttpOnly"
        assert _parse_set_cookie(header) == {"sessionid": "abc"}

    def test_parse_multiple_cookies_joined(self) -> None:
        """
        httpx concatenates multiple Set-Cookie headers with ', ' — this
        is the real format we saw on the ``/auth/authorize`` response.
        """
        header = (
            "SSO_CONVERSATION_CSRF_abc=token1.1775862076; Expires=Fri, 10 Apr 2026 23:00:49 GMT; "
            "Max-Age=1800; Secure; HttpOnly; SameSite=None, "
            "__P__wuid=wuid-value; Expires=Sat, 10 Apr 2027 22:30:49 GMT; Domain=tbank.ru; Path=/; Secure; SameSite=None, "
            "sso_uaid=uaid.xyz; Expires=Wed, 07 Oct 2026 22:30:49 GMT; Path=/; Secure; HttpOnly; SameSite=None"
        )
        cookies = _parse_set_cookie(header)
        assert cookies == {
            "SSO_CONVERSATION_CSRF_abc": "token1.1775862076",
            "__P__wuid": "wuid-value",
            "sso_uaid": "uaid.xyz",
        }

    def test_merge_preserves_existing_when_no_set_cookie(self) -> None:
        existing = {"a": "1", "b": "2"}
        merged = _merge_cookies(existing, {"content-type": "application/json"})
        assert merged == existing
        # Must return a new dict — not mutate the input.
        assert merged is not existing

    def test_merge_overwrites_on_collision(self) -> None:
        existing = {"sessionid": "old"}
        merged = _merge_cookies(
            existing,
            {"set-cookie": "sessionid=new; Secure"},
        )
        assert merged["sessionid"] == "new"


# =============================================================================
# Equality / hashing
# =============================================================================

class TestStepEquality:
    def test_steps_with_same_public_fields_are_equal(self) -> None:
        """Internal plumbing (_transport, _cookies, raw) is excluded from equality."""
        t1 = _FakeTransport()
        t2 = _FakeTransport()
        a = EntryStep(
            cid="X",
            action="step",
            auth_id="A",
            _transport=t1,
            _cookies={"foo": "bar"},
            raw={"some": "raw"},
        )
        b = EntryStep(
            cid="X",
            action="step",
            auth_id="A",
            _transport=t2,
            _cookies={"different": "cookies"},
            raw={"completely": "different"},
        )
        assert a == b

    def test_replace_preserves_structural_identity(self) -> None:
        """dataclasses.replace() should work on step types."""
        t = _FakeTransport()
        original = OtpStep(cid="C", action="step", token="old", length=4, _transport=t)
        updated = replace(original, token="new")
        assert updated.token == "new"
        assert updated.cid == original.cid
