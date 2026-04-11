"""
Auth subpackage — constants, primitives, and the typed interactive flow.

Public names re-exported here:

Flow
    :class:`EntryStep`, :class:`OtpStep`, :class:`SelfieStep`,
    :class:`PasswordStep`, :class:`AuthComplete`, :class:`UnknownStep`,
    :data:`AnyAuthStep`, :class:`SelfieSkipReason`.

Primitives
    :class:`PkcePair`, :class:`DeviceProfile`, :data:`PIXEL_7_PANTHER_A14`,
    and the lower-level :func:`compute_sso_data`,
    :func:`build_fingerprint_json`, :func:`build_fingerprint_payload`.

Constants
    The :mod:`tbank.auth.constants` module stays as a top-level import
    for callers that want to reach in for individual literals, e.g.
    ``from tbank.auth import constants as C`` then ``C.CLIENT_ID``.
"""
from tbank.auth.fingerprint import (
    PIXEL_7_PANTHER_A14,
    DeviceProfile,
    build_fingerprint_json,
    build_fingerprint_payload,
    compute_sso_data,
)
from tbank.auth.pkce import PkcePair
from tbank.auth.steps import (
    AnyAuthStep,
    AuthComplete,
    AuthStep,
    EntryStep,
    OtpStep,
    PasswordStep,
    SelfieSkipReason,
    SelfieStep,
    UnknownStep,
)

__all__ = [
    "PIXEL_7_PANTHER_A14",
    "AnyAuthStep",
    "AuthComplete",
    "AuthStep",
    "DeviceProfile",
    "EntryStep",
    "OtpStep",
    "PasswordStep",
    "PkcePair",
    "SelfieSkipReason",
    "SelfieStep",
    "UnknownStep",
    "build_fingerprint_json",
    "build_fingerprint_payload",
    "compute_sso_data",
]
