"""
Constants used by the T-Bank mobile auth flow.

Every value in this module was extracted from the decompiled Android
app (``com.idamob.tinkoff.android``, versionName 7.32.1, versionCode
12278) and cross-verified against live server responses.

Callers should not change these casually — the server checks several
of them and will refuse traffic that doesn't match.
"""
from __future__ import annotations

from tbank.identity import Identity

# -----------------------------------------------------------------------------
# Base URLs
# -----------------------------------------------------------------------------

SSO_BASE_URL = "https://id.tbank.ru/"
"""SSO endpoint host. All ``auth/*`` paths are relative to this."""

API_BASE_URL = "https://api.tbank.ru/"
"""Business API host. All ``v1/*`` business endpoints live here."""


# -----------------------------------------------------------------------------
# OAuth2 client identity
# -----------------------------------------------------------------------------

CLIENT_ID = "tinkoff-mb-app"
"""OAuth2 ``client_id`` of the mobile app."""

BASIC_AUTH = "Basic dGlua29mZi1tYi1hcHA6"
"""
HTTP ``Authorization`` header for the ``auth/token`` endpoint — base64
of ``"tinkoff-mb-app:"`` (yes, empty password).
"""

REDIRECT_URI = "mobile://"
"""
OAuth2 ``redirect_uri``. The ``tinkoffbank://`` / ``tbank://`` URI
schemes registered in the AndroidManifest are for inter-app deep
linking, *not* the OAuth redirect.
"""

VENDOR = "tinkoff_android"
"""``vendor`` form field sent on every auth request."""

CLIENT_VERSION = "18.1.3-hotfix"
"""
``client_version`` form field. A **hardcoded SDK version**, not the
Android app's user-facing versionName (which is 7.32.1).
"""

CLAIMS = (
    '{"id_token":{"given_name":null, "phone_number": null, "picture": null}}'
)
"""
OIDC ``claims`` parameter sent to ``auth/authorize`` — asks the ID
token to include these three fields. Must be sent verbatim; the server
rejects reformatted variants.
"""

# OAuth2 fixed parameters for ``auth/authorize``
RESPONSE_TYPE = "code"
RESPONSE_MODE = "json"
DISPLAY = "json"


# -----------------------------------------------------------------------------
# Mobile-BFF fields
# -----------------------------------------------------------------------------

APP_NAME = "mobile"
"""BFF-only ``appName`` form field."""

PLATFORM = "android"
"""BFF-only ``platform`` form field."""


# -----------------------------------------------------------------------------
# App version metadata
# -----------------------------------------------------------------------------

APP_VERSION_NAME = "7.32.1"
"""User-facing ``versionName``. Used in User-Agent / X-Client-Info."""

APP_VERSION_CODE = "12278"
"""``versionCode``. Used in X-Client-Info."""

BUNDLE_ID = "com.idamob.tinkoff.android"
"""Android package id. Used in the fingerprint JSON sent during phone submission."""


# -----------------------------------------------------------------------------
# Header factories
# -----------------------------------------------------------------------------

def build_user_agent(identity: Identity) -> str:
    """
    Build the ``User-Agent`` string in the format the app uses::

        "<deviceModel>/android: <appVersion>/TCSMB/<buildFingerprint>"

    The real app NFD-normalizes the device-model part and replaces
    non-ASCII with ``?``. The default profile (Pixel 7) is pure ASCII
    so the normalization is a no-op. If you supply a custom
    :class:`~tbank.identity.Identity` with a non-ASCII model name,
    normalize it yourself before passing it in.
    """
    return (
        f"{identity.device_model}/android: "
        f"{APP_VERSION_NAME}/TCSMB/"
        f"{identity.build_fingerprint}"
    )


def build_x_client_info() -> str:
    """
    Build the ``X-Client-Info`` header value: ``"/android/<versionName>-<versionCode>"``.
    """
    return f"/android/{APP_VERSION_NAME}-{APP_VERSION_CODE}"


def build_base_headers(identity: Identity) -> dict[str, str]:
    """
    Build the header set every mobile request carries.

    Used by both the auth flow (``auth/*`` endpoints) and business API
    calls (``v1/*`` endpoints). Returns a new dict each call so callers
    can freely mutate / extend it.
    """
    return {
        "Accept": "application/json",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "User-Agent": build_user_agent(identity),
        "X-Client-Info": build_x_client_info(),
    }
