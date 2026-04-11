"""
Device fingerprint JSON sent to ``POST /auth/step`` during phone submission.

Two moving parts:

- :func:`compute_sso_data` — the deterministic SHA-512 proof-of-possession
  that the app places in the ``ssoData`` slot of the fingerprint payload
  when the server asked for ``collectFingerprint: true`` in its previous
  response.
- :func:`build_fingerprint_payload` — assembles the full 64-field
  :class:`dict` that gets serialized to JSON and stuffed into the
  ``fingerprint`` form field. Field names, order, and types match the
  serializer in the Android app.

The reference ground-truth test vector for the hash lives in
``tests/test_fingerprint.py`` and is asserted byte-for-byte against a
known-good output.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from tbank.auth import constants as C
from tbank.identity import Identity

# -----------------------------------------------------------------------------
# Anti-DDoS ssoData hash (SHA-512 proof of possession)
# -----------------------------------------------------------------------------

def _sha512_b64url(s: str) -> str:
    """SHA-512 of UTF-8 ``s``, base64url-encoded without padding."""
    digest = hashlib.sha512(s.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _take(s: str, n: int) -> str:
    """Kotlin ``String.take(n)`` — first ``n`` chars, capped at len(s)."""
    if n <= 0:
        return ""
    return s[:n] if n < len(s) else s


def _take_last(s: str, n: int) -> str:
    """
    Kotlin ``String.takeLast(n)`` — the **last** ``n`` chars. Note: this
    is *not* ``s[n:]``. For a 36-char UUID, ``takeLast(27)`` returns
    the slice ``s[9:36]``, NOT ``s[27:]``.
    """
    if n <= 0:
        return ""
    if n >= len(s):
        return s
    return s[-n:]


def compute_sso_data(
    *,
    cid: str,
    client_id: str,
    tinkoff_device_id: str,
) -> str:
    """
    Compute the anti-DDoS proof-of-possession hash for the ``ssoData``
    slot of the fingerprint payload.

    The formula::

        input  = take(cid, |cid|/2)
               + take(tDev, |tDev|/4)
               + client_id
               + takeLast(cid, |cid|/2)
               + takeLast(tDev, |tDev|*3/4)
               + sha512_b64url(tDev)
        output = sha512_b64url(input)

    For a 36-char UUID ``tDev``, ``take(tDev, 9) + takeLast(tDev, 27)``
    yields the full UUID with no gap — it looks redundant but the
    server-side verifier checks byte-for-byte.
    """
    n = len(cid)
    m = len(tinkoff_device_id)
    inner = (
        _take(cid, n // 2)
        + _take(tinkoff_device_id, m // 4)
        + client_id
        + _take_last(cid, n // 2)
        + _take_last(tinkoff_device_id, (m * 3) // 4)
        + _sha512_b64url(tinkoff_device_id)
    )
    return _sha512_b64url(inner)


# -----------------------------------------------------------------------------
# Device profile (the "I am a Pixel 7" shape)
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class DeviceProfile:
    """
    Internally-consistent Android device profile used to populate the
    ``Build.*`` slots and screen/locale fields of the fingerprint JSON.

    The default :data:`PIXEL_7_PANTHER_A14` is a plausible recent Google
    device on factory Android 14. Supplying your own profile is supported
    but all fields are required — the goal is byte-level consistency with
    a real device so the server's heuristics don't flag you.

    Fields named ``Build.*`` mirror the Android system properties of the
    same name read from ``android.os.Build`` on a real device.
    """

    # Build.*
    board: str
    bootloader: str
    brand: str
    device: str
    display: str
    fingerprint: str          # Build.FINGERPRINT
    hardware: str
    id: str                   # Build.ID
    manufacturer: str
    model: str                # Build.MODEL — human-readable name
    product: str
    radio: str
    version_release: str      # Android version, e.g. "14"

    # Display
    screen_width: int
    screen_height: int
    screen_dpi: int
    density: float

    # Locale / time
    language: str             # "ru"
    locale: str               # "ru_RU"
    timezone_name: str        # "Europe/Moscow"
    timezone_offset_minutes: int  # see note in build_fingerprint_payload


PIXEL_7_PANTHER_A14 = DeviceProfile(
    board="panther",
    bootloader="panther-1.4-10951672",
    brand="google",
    device="panther",
    display="UP1A.231105.003",
    fingerprint="google/panther/panther:14/UP1A.231105.003/11010452:user/release-keys",
    hardware="panther",
    id="UP1A.231105.003",
    manufacturer="Google",
    model="Pixel 7",
    product="panther",
    radio="g5300q-231016-240218-B-11266013",
    version_release="14",
    screen_width=1080,
    screen_height=2400,
    screen_dpi=411,
    density=2.625,
    language="ru",
    locale="ru_RU",
    timezone_name="Europe/Moscow",
    timezone_offset_minutes=-180,
)
"""
Default device profile — Google Pixel 7 (codename ``panther``) on
Android 14, build ``UP1A.231105.003``. Matches real system property
values published by Google, so the fingerprint JSON is internally
consistent.
"""


# -----------------------------------------------------------------------------
# 64-field fingerprint payload
# -----------------------------------------------------------------------------

def build_fingerprint_payload(
    *,
    identity: Identity,
    sso_data: str,
    user_agent: str,
    profile: DeviceProfile = PIXEL_7_PANTHER_A14,
) -> dict[str, Any]:
    """
    Assemble the 64-field dict that the app serializes to JSON and sends
    as the ``fingerprint`` form field of ``POST /auth/step`` during phone
    submission.

    Field names, types, and **order** match the serializer descriptor in
    the Android app. JSON is order-agnostic at the protocol level, but
    the order is preserved here so diffs against reference captures stay
    readable.

    Semantic fields fall into a few buckets:

    - **App metadata**: ``appVersion``, ``bundleId``, ``userAgent``,
      ``clientLanguage``, ``locale``, ``timeZoneName``, ``clientTimezone``.
    - **Device identity**: ``mobileDeviceId``, ``tDeviceId``,
      ``identifierForVendor``, ``advertisingID``. We pull these from the
      supplied :class:`Identity`.
    - **Anti-DDoS proof**: ``ssoData`` — a SHA-512 hash computed by
      :func:`compute_sso_data` from the current ``cid``.
    - **``Build.*`` slots**: from the :class:`DeviceProfile`.
    - **Everything else**: best-effort plausible defaults (non-root, no
      emulator, keyguard set, both cameras available, …). The server
      does not strictly validate most of these, but the fields must be
      *present* — the serializer treats all 64 elements as required.

    Runtime-dependent fields we stub with empty strings (SIM / IMSI /
    IMEI / serial number / phone number / MarketingID) are unobservable
    on modern Android without elevated permissions anyway, so the app
    itself usually sends empty values.
    """
    return {
        # 0–8 — app + locale + device basics
        "appVersion": C.APP_VERSION_NAME,
        "clientLanguage": profile.language,
        "clientTimezone": profile.timezone_offset_minutes,
        "timeZoneName": profile.timezone_name,
        "latitude": None,
        "longitude": None,
        "mobileDeviceModel": profile.model,
        "mobileDeviceOs": "Android",
        "mobileDeviceOsVersion": profile.version_release,
        # 9–11 — telephony (empty on modern Android without permissions)
        "mobilePhoneNumber": "",
        "imei": "",
        "subscriptionId": "",
        # 12–15 — screen
        "screenDpi": profile.screen_dpi,
        "screenHeight": profile.screen_height,
        "screenWidth": profile.screen_width,
        "screenResolution": f"{profile.screen_width}x{profile.screen_height}",
        # 16–18 — client metadata
        "userAgent": user_agent,
        "authType": "",
        "authTypeSetDate": "",
        # 19–22 — identifiers
        "mobileDeviceId": identity.device_id,
        "tDeviceId": identity.tinkoff_device_id,
        "connectionType": "wifi",
        "MarketingID": "",
        # 23–27 — flags (NB: int 0/1 except root_flag which is bool)
        "root_flag": False,
        "emulator": 0,
        "debug": 0,
        "lockedDevice": 1,
        "biometricsSupport": 1,
        # 28–31 — booleans
        "autologinOn": False,
        "autologinUsed": False,
        "frontCameraAvailable": True,
        "backCameraAvailable": True,
        # 32–33 — bundle + anti-DDoS proof
        "bundleId": C.BUNDLE_ID,
        "ssoData": sso_data,
        # 34–42 — SIM / locale / system
        "ICCID": "",
        "IMSI": "",
        "serialNumber": "",
        "mobileDeviceName": profile.model,
        "locale": profile.locale,
        "familyNames": (
            "sans-serif,sans-serif-condensed,sans-serif-light,"
            "sans-serif-medium,sans-serif-black,sans-serif-thin,"
            "sans-serif-smallcaps,serif,monospace,serif-monospace,"
            "casual,cursive"
        ),
        "identifierForVendor": identity.stable_id,
        "systemFont": "sans-serif",
        "systemFontSize": "1.0",
        # 43–52 — Build.* (mirrors android.os.Build on a real device)
        "buildBoard": profile.board,
        "buildBootloader": profile.bootloader,
        "buildBrand": profile.brand,
        "buildDevice": profile.device,
        "buildDisplay": profile.display,
        "buildFingerprint": profile.fingerprint,
        "buildHardware": profile.hardware,
        "buildID": profile.id,
        "buildManufacturer": profile.manufacturer,
        "buildProduct": profile.product,
        # 53–63 — tail
        "buildRadio": profile.radio,
        "displayMetricsDensity": f"{profile.density}",
        "displayMetricsScaledDensity": f"{profile.density}",
        "packageManagerGetSystemAvailableFeatures": (
            "android.hardware.bluetooth,android.hardware.camera,"
            "android.hardware.camera.autofocus,android.hardware.camera.flash,"
            "android.hardware.camera.front,android.hardware.location,"
            "android.hardware.location.gps,android.hardware.location.network,"
            "android.hardware.microphone,android.hardware.nfc,"
            "android.hardware.screen.landscape,android.hardware.screen.portrait,"
            "android.hardware.sensor.accelerometer,android.hardware.sensor.gyroscope,"
            "android.hardware.sensor.proximity,android.hardware.telephony,"
            "android.hardware.touchscreen,android.hardware.touchscreen.multitouch,"
            "android.hardware.wifi,android.software.app_widgets,"
            "android.software.backup,android.software.connectionservice,"
            "android.software.device_admin,android.software.home_screen,"
            "android.software.input_methods,android.software.print,"
            "android.software.webview"
        ),
        "packageManagerGetSystemSharedLibraryNames": (
            "android.test.runner,android.test.mock,javax.obex,android.test.base,"
            "com.android.location.provider,android.ext.shared,"
            "com.android.nfc_extras,com.android.media.remotedisplay,"
            "com.android.future.usb.accessory"
        ),
        "statFsGetTotalBytes": "120000000000",
        "telephonyManagerGroupIdentifierLevel1": "",
        "isVpnConnected": False,
        "deviceOs": "Android",
        "advertisingID": identity.stable_id,
        "contacts": 0,
    }


def build_fingerprint_json(
    *,
    identity: Identity,
    cid: str,
    user_agent: str,
    profile: DeviceProfile = PIXEL_7_PANTHER_A14,
) -> str:
    """
    High-level convenience: compute the ssoData hash from the supplied
    ``cid``, assemble the 64-field payload, and serialize it to the
    compact JSON string the server expects.

    Most callers want this form — the return value goes straight into
    the ``fingerprint`` form field of ``POST /auth/step``.
    """
    sso_data = compute_sso_data(
        cid=cid,
        client_id=C.CLIENT_ID,
        tinkoff_device_id=identity.tinkoff_device_id,
    )
    payload = build_fingerprint_payload(
        identity=identity,
        sso_data=sso_data,
        user_agent=user_agent,
        profile=profile,
    )
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
