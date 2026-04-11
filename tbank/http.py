"""
HTTP transport for the library.

:class:`HttpClient` is the thin wrapper around ``httpx.Client`` used by
everything in the library that touches the network. Responsibilities:

1. Rate limit — at most one request per ``rate_limit_interval`` seconds
   to any given host. Enforced by sleeping, so back-to-back calls "just
   work" without the caller needing explicit delays. Set the interval
   to ``0`` to disable.

2. Exception mapping — ``httpx.HTTPError`` subclasses become
   :class:`~tbank.errors.TBankTransportError`; HTTP 4xx/5xx responses
   become :class:`~tbank.errors.TBankAPIError` or one of its more
   specific subclasses (:class:`~tbank.errors.TBankRateLimitError`
   for 429, :class:`~tbank.errors.TBankConversationExpiredError` for
   the common SSO ``conversation_not_found`` error).

3. Optional exchange logging — every request and its response can be
   dumped to a per-call JSON file under ``exchange_log_dir``. Useful
   during development; disable (``log_exchanges=False``, the default)
   for production.

4. Sensitive field redaction — ``password``, ``refresh_token``,
   ``code_verifier`` and friends can be stripped from the logged
   request body via the ``sensitive_fields`` argument. The actual HTTP
   request still carries the real value — only the on-disk log loses it.

The class is intentionally dumb about auth: it does not know about
tokens, refresh, or the auth flow. Those concerns live in
:class:`~tbank.client.TBankClient`.
"""
from __future__ import annotations

import datetime as dt
import json
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any

import httpx

from tbank.errors import (
    TBankAPIError,
    TBankConversationExpiredError,
    TBankRateLimitError,
    TBankTransportError,
)

_REDACTED = "<REDACTED>"


# -----------------------------------------------------------------------------
# Response envelope
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class HttpResponse:
    """
    Result of a :meth:`HttpClient.request` call.

    Frozen dataclass rather than a pass-through ``httpx.Response`` so that
    library users don't accidentally depend on httpx internals.
    """

    status_code: int
    headers: Mapping[str, str]
    body: bytes
    text: str
    url: str
    method: str
    elapsed: dt.timedelta
    request_headers: Mapping[str, str]
    request_body: dict[str, Any] | None = None

    def json(self) -> Any:
        """
        Parse the response body as JSON.

        Raises :class:`TBankAPIError` on JSON decode failure — the
        server promised JSON but delivered something else, which is a
        protocol error from our point of view.
        """
        try:
            return json.loads(self.text) if self.text else None
        except json.JSONDecodeError as e:
            raise TBankAPIError(
                f"server response was not valid JSON: {e}",
                status_code=self.status_code,
                response_text=self.text,
            ) from e


# -----------------------------------------------------------------------------
# Rate limit
# -----------------------------------------------------------------------------

class _RateLimiter:
    """
    Process-local per-host rate limit. Sleeps until the next request to
    a given host is allowed. Thread-safe.
    """

    def __init__(self, min_interval: float) -> None:
        self._min_interval = max(0.0, float(min_interval))
        self._last_request: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            last = self._last_request.get(host, 0.0)
            elapsed = now - last
            sleep_for = self._min_interval - elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.monotonic()
            self._last_request[host] = now


# -----------------------------------------------------------------------------
# Exchange logging
# -----------------------------------------------------------------------------

class _ExchangeLogger:
    """Numbered-file JSON sink for full request/response dumps."""

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)
        self._counter = self._initial_counter()
        self._lock = threading.Lock()

    def _initial_counter(self) -> int:
        existing = sorted(self._dir.glob("[0-9][0-9][0-9]_*.json"))
        if not existing:
            return 1
        last = existing[-1].name.split("_", 1)[0]
        try:
            return int(last) + 1
        except ValueError:
            return 1

    def dump(
        self,
        *,
        label: str,
        method: str,
        url: str,
        request_headers: Mapping[str, str],
        request_body: dict[str, Any] | None,
        sensitive_fields: set[str],
        status_code: int,
        response_headers: Mapping[str, str],
        response_text: str,
        elapsed: dt.timedelta,
    ) -> Path:
        """Write one exchange. Returns the path of the written file."""
        with self._lock:
            seq = self._counter
            self._counter += 1
        path = self._dir / f"{seq:03d}_{label}.json"
        payload = {
            "timestamp": dt.datetime.now(tz=dt.UTC).isoformat(),
            "label": label,
            "elapsed_ms": int(elapsed.total_seconds() * 1000),
            "request": {
                "method": method,
                "url": url,
                "headers": dict(request_headers),
                "body": _redact(request_body, sensitive_fields) if request_body else None,
            },
            "response": {
                "status_code": status_code,
                "headers": dict(response_headers),
                "text": response_text,
            },
        }
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return path


def _redact(data: dict[str, Any], fields: set[str]) -> dict[str, Any]:
    if not fields:
        return dict(data)
    return {k: (_REDACTED if k in fields else v) for k, v in data.items()}


# -----------------------------------------------------------------------------
# HttpClient
# -----------------------------------------------------------------------------

@dataclass
class HttpClient:
    """
    Library HTTP client. Wraps a single ``httpx.Client`` instance with
    rate limiting, optional exchange logging, and error mapping.

    Thread-safety: ``httpx.Client`` is thread-safe, the rate limiter and
    exchange logger both use locks, so concurrent ``request()`` calls
    are allowed.
    """

    rate_limit_interval: float = 1.0
    """Minimum seconds between requests to the same host. Set to 0 to disable."""

    log_exchanges: bool = False
    """Enable per-call JSON dumps under :attr:`exchange_log_dir`."""

    exchange_log_dir: Path | None = None
    """Directory for exchange dumps. Required when :attr:`log_exchanges` is True."""

    timeout: float = 30.0
    """Default request timeout in seconds."""

    follow_redirects: bool = False
    """Whether to follow 3xx redirects. Usually off — we want to see them."""

    verify_tls: bool = True
    """TLS certificate verification. Keep on unless you know what you're doing."""

    _httpx: httpx.Client = field(init=False, repr=False)
    _rate_limiter: _RateLimiter = field(init=False, repr=False)
    _exchange_logger: _ExchangeLogger | None = field(init=False, repr=False, default=None)
    _closed: bool = field(init=False, repr=False, default=False)

    def __post_init__(self) -> None:
        self._httpx = httpx.Client(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            verify=self.verify_tls,
        )
        self._rate_limiter = _RateLimiter(self.rate_limit_interval)
        if self.log_exchanges:
            if self.exchange_log_dir is None:
                raise ValueError("log_exchanges=True requires exchange_log_dir")
            self._exchange_logger = _ExchangeLogger(self.exchange_log_dir)

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def close(self) -> None:
        """Release the underlying ``httpx.Client``. Idempotent."""
        if not self._closed:
            self._httpx.close()
            self._closed = True

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -------------------------------------------------------------------------
    # request / request_json
    # -------------------------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        cookies: Mapping[str, str] | None = None,
        sensitive_fields: set[str] | None = None,
        label: str | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        """
        Issue one HTTP request.

        :param method: ``"GET"``, ``"POST"``, etc.
        :param url: Absolute URL. The library builds these via
            ``tbank.auth.constants.SSO_BASE_URL`` / ``API_BASE_URL``.
        :param headers: Additional headers to send. The client does NOT
            add anything on its own — the caller is responsible for
            providing ``Accept``, ``User-Agent``, ``Authorization`` etc.
        :param params: Query string params. Values are stringified.
        :param data: Form body — sent as
            ``application/x-www-form-urlencoded`` when set.
        :param cookies: Request cookies.
        :param sensitive_fields: Names of ``data`` keys whose values
            must never appear in exchange logs or raised exception
            messages. They are still sent over the wire.
        :param label: Short identifier used to name the exchange log
            file. Defaults to ``"{METHOD}_host_path_first_segment"``.
        :param timeout: Per-request override of :attr:`timeout`.

        :raises TBankTransportError: Network failure (DNS, TLS, connect
            error, idle timeout, etc.).
        :raises TBankRateLimitError: Server returned HTTP 429.
        :raises TBankConversationExpiredError: Server returned 4xx with
            ``error: conversation_not_found`` body — caller should
            start a new auth flow.
        :raises TBankAPIError: Any other HTTP 4xx/5xx response.
        """
        if self._closed:
            raise RuntimeError("HttpClient is closed")

        sensitive_fields = sensitive_fields or set()
        label = label or _default_label(method, url)
        host = httpx.URL(url).host
        self._rate_limiter.wait(host)

        request_headers: dict[str, str] = dict(headers or {})
        request_body: dict[str, Any] | None = dict(data) if data is not None else None

        try:
            httpx_response = self._httpx.request(
                method,
                url,
                headers=request_headers,
                params=params,
                data=data,
                cookies=dict(cookies) if cookies is not None else None,
                timeout=timeout if timeout is not None else self.timeout,
            )
        except httpx.HTTPError as e:
            raise TBankTransportError(f"{method} {url} failed: {e}") from e

        response = HttpResponse(
            status_code=httpx_response.status_code,
            headers=_normalize_headers(httpx_response.headers),
            body=httpx_response.content,
            text=httpx_response.text,
            url=str(httpx_response.url),
            method=method.upper(),
            elapsed=httpx_response.elapsed,
            request_headers=_normalize_headers(httpx_response.request.headers),
            request_body=request_body,
        )

        if self._exchange_logger is not None:
            self._exchange_logger.dump(
                label=label,
                method=response.method,
                url=response.url,
                request_headers=response.request_headers,
                request_body=response.request_body,
                sensitive_fields=sensitive_fields,
                status_code=response.status_code,
                response_headers=response.headers,
                response_text=response.text,
                elapsed=response.elapsed,
            )

        _raise_for_status(response)
        return response

    def request_json(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> tuple[Any, HttpResponse]:
        """
        Convenience wrapper: :meth:`request` plus JSON parse of the body.

        Returns a ``(parsed_json, response)`` tuple so the caller can
        still inspect headers / status on success. JSON parse errors
        raise :class:`TBankAPIError`.
        """
        response = self.request(method, url, **kwargs)
        return response.json(), response


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _normalize_headers(headers: httpx.Headers | Mapping[str, str]) -> dict[str, str]:
    """Lowercase keys; if a key repeats, the last value wins."""
    out: dict[str, str] = {}
    for k, v in headers.items():
        out[k.lower()] = v
    return out


def _default_label(method: str, url: str) -> str:
    """Build a short default label for exchange log files."""
    parsed = httpx.URL(url)
    path_part = parsed.path.strip("/").replace("/", "_") or "root"
    return f"{method.lower()}_{path_part}"


def _raise_for_status(response: HttpResponse) -> None:
    """
    Map non-2xx responses to the right exception class.

    The library treats 3xx as a protocol error because we run with
    ``follow_redirects=False`` — a redirect from T-Bank means something
    unusual happened (login failed, CSRF expired, etc.) and the caller
    should see it rather than have it silently followed.
    """
    if 200 <= response.status_code < 300:
        return

    error_code: str | None = None
    error_description: str | None = None
    body_for_error = response.text

    try:
        parsed = json.loads(response.text) if response.text else None
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        error_code = parsed.get("error")
        error_description = parsed.get("error_description")

    if response.status_code == 429:
        raise TBankRateLimitError(
            "rate-limited by server",
            status_code=429,
            error_code=error_code,
            error_description=error_description,
            response_text=body_for_error,
        )

    if error_code == "conversation_not_found":
        raise TBankConversationExpiredError(
            "SSO conversation expired or invalid",
            status_code=response.status_code,
            error_code=error_code,
            error_description=error_description,
            response_text=body_for_error,
        )

    raise TBankAPIError(
        f"{response.method} {response.url} returned {response.status_code}",
        status_code=response.status_code,
        error_code=error_code,
        error_description=error_description,
        response_text=body_for_error,
    )
