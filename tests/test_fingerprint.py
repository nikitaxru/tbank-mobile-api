"""
Unit tests for :mod:`tbank.auth.fingerprint`.

The key test is :func:`test_compute_sso_data_ground_truth` — it pins
:func:`compute_sso_data` against a known value computed by a reference
Java implementation of the same formula. The hash, inputs, and Python
output have been verified to match byte-for-byte. If this test starts
failing, the formula has drifted.
"""
from __future__ import annotations

import json

from tbank.auth import (
    PIXEL_7_PANTHER_A14,
    build_fingerprint_json,
    build_fingerprint_payload,
    compute_sso_data,
)
from tbank.auth.fingerprint import _take, _take_last
from tbank.identity import Identity

# -----------------------------------------------------------------------------
# Ground truth inputs — re-run the Java reference implementation if you
# need to change either the inputs or the expected hash below.
# -----------------------------------------------------------------------------

_GT_CID = "r7XclqFAE9s0AcOf5g"
_GT_CLIENT_ID = "tinkoff-mb-app"
_GT_TINKOFF_DEVICE_ID = "c371229f-319c-4f39-b9b5-45d87808c95b"
_GT_EXPECTED_HASH = (
    "ZW_xd1P02YCFp44YcJ-kObtUi4d0wz9mgeAaJLh2WlYqENsavaU5LB9xi07AFMYTQJGaScUkOAXMMGE8tKHYTQ"
)


def test_compute_sso_data_ground_truth() -> None:
    """
    Reference snapshot — must match the Java implementation byte-for-byte.

    If this test starts failing, somebody changed the formula in
    :func:`compute_sso_data` and the library can no longer produce
    the anti-DDoS proof that the T-Bank SSO server expects.
    """
    result = compute_sso_data(
        cid=_GT_CID,
        client_id=_GT_CLIENT_ID,
        tinkoff_device_id=_GT_TINKOFF_DEVICE_ID,
    )
    assert result == _GT_EXPECTED_HASH


def test_compute_sso_data_is_deterministic() -> None:
    """Same inputs always produce the same hash."""
    inputs = dict(
        cid="someCid",
        client_id="tinkoff-mb-app",
        tinkoff_device_id="11111111-2222-3333-4444-555555555555",
    )
    first = compute_sso_data(**inputs)
    second = compute_sso_data(**inputs)
    assert first == second


def test_compute_sso_data_hash_is_86_chars() -> None:
    """SHA-512 → base64url-nopad is always 86 chars."""
    result = compute_sso_data(
        cid="abc",
        client_id="def",
        tinkoff_device_id="ghi",
    )
    assert len(result) == 86


def test_take_helper() -> None:
    """Kotlin-style String.take(n)."""
    assert _take("abcdef", 3) == "abc"
    assert _take("abc", 10) == "abc"
    assert _take("abc", 0) == ""
    assert _take("abc", -1) == ""


def test_take_last_helper() -> None:
    """
    Kotlin-style ``String.takeLast(n)`` — the **last** n characters,
    NOT ``s[n:]``. For a 36-char UUID, ``takeLast(27)`` returns
    ``s[9:36]``, not ``s[27:36]``. The ssoData hash depends on this.
    """
    assert _take_last("abcdef", 3) == "def"
    assert _take_last("abcdef", 0) == ""
    assert _take_last("abcdef", 10) == "abcdef"
    uuid = "c371229f-319c-4f39-b9b5-45d87808c95b"  # 36 chars
    assert _take_last(uuid, 27) == uuid[9:]  # NOT uuid[27:]


# -----------------------------------------------------------------------------
# Payload assembly
# -----------------------------------------------------------------------------

def _fake_identity() -> Identity:
    """Deterministic identity for snapshot tests."""
    return Identity(
        device_id="00000000-0000-0000-0000-000000000001",
        tinkoff_device_id="00000000-0000-0000-0000-000000000002",
        stable_id="00000000-0000-0000-0000-000000000003",
        old_device_id="00000000-0000-0000-0000-000000000001",
        device_model="Pixel 7",
        build_fingerprint="google/panther/panther:14/UP1A.231105.003/11010452:user/release-keys",
    )


def test_fingerprint_payload_has_64_fields() -> None:
    """
    The mobile app's serializer declares exactly 64 fingerprint fields.
    Missing or extra keys both risk parser rejection on the server side.
    """
    payload = build_fingerprint_payload(
        identity=_fake_identity(),
        sso_data="dummyHash",
        user_agent="dummy UA",
    )
    assert len(payload) == 64


def test_fingerprint_payload_contains_critical_keys() -> None:
    """Spot-check that the fields we care most about are present."""
    payload = build_fingerprint_payload(
        identity=_fake_identity(),
        sso_data="dummyHash",
        user_agent="dummy UA",
    )
    required = {
        "appVersion",
        "bundleId",
        "userAgent",
        "mobileDeviceId",
        "tDeviceId",
        "ssoData",
        "buildFingerprint",
        "buildBoard",
        "buildBrand",
        "buildManufacturer",
        "isVpnConnected",
        "contacts",
    }
    assert required.issubset(payload.keys())


def test_fingerprint_payload_types() -> None:
    """
    Verify that int-typed fields are int (not bool, not str), that
    root_flag is a plain bool, and that optional floats are None when
    not provided.
    """
    payload = build_fingerprint_payload(
        identity=_fake_identity(),
        sso_data="dummyHash",
        user_agent="dummy UA",
    )
    # int-typed slots
    for key in ("screenDpi", "screenHeight", "screenWidth", "emulator", "debug", "lockedDevice", "biometricsSupport"):
        assert isinstance(payload[key], int), f"{key} must be int"
        assert not isinstance(payload[key], bool), f"{key} must be int, not bool"

    # bool-typed slots
    for key in ("root_flag", "autologinOn", "autologinUsed", "frontCameraAvailable", "backCameraAvailable", "isVpnConnected"):
        assert isinstance(payload[key], bool), f"{key} must be bool"

    # Optional float slots
    assert payload["latitude"] is None
    assert payload["longitude"] is None


def test_fingerprint_injects_identity_uuids() -> None:
    """The identity's device/tinkoff/stable IDs must land in the payload."""
    identity = _fake_identity()
    payload = build_fingerprint_payload(
        identity=identity,
        sso_data="dummy",
        user_agent="dummy",
    )
    assert payload["mobileDeviceId"] == identity.device_id
    assert payload["tDeviceId"] == identity.tinkoff_device_id
    assert payload["identifierForVendor"] == identity.stable_id
    assert payload["advertisingID"] == identity.stable_id


def test_fingerprint_injects_device_profile() -> None:
    """Build.* slots come from the DeviceProfile."""
    payload = build_fingerprint_payload(
        identity=_fake_identity(),
        sso_data="dummy",
        user_agent="dummy",
        profile=PIXEL_7_PANTHER_A14,
    )
    assert payload["buildBoard"] == "panther"
    assert payload["buildBrand"] == "google"
    assert payload["buildManufacturer"] == "Google"
    assert payload["mobileDeviceModel"] == "Pixel 7"


def test_fingerprint_json_is_compact() -> None:
    """JSON output uses compact separators, no whitespace."""
    js = build_fingerprint_json(
        identity=_fake_identity(),
        cid=_GT_CID,
        user_agent="dummy",
    )
    assert ", " not in js
    assert ": " not in js
    assert json.loads(js)["ssoData"]  # parse round-trip works
