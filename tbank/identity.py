"""
Persistent device identity — the long-lived "this is the same device" handle
that the library sends to the server on every auth flow.

Generated once on first run (random UUIDs + a chosen device profile) and
then reused forever. Rotating it looks like a new device to T-Bank, which
may trigger extra verification; callers should leave it alone unless they
really want a fresh identity.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from typing import Any

from tbank.storage import State

DEFAULT_DEVICE_MODEL = "Pixel 7"
DEFAULT_BUILD_FINGERPRINT = (
    "google/panther/panther:14/UP1A.231105.003/11010452:user/release-keys"
)


@dataclass(frozen=True, slots=True)
class Identity:
    """
    Everything that identifies this "virtual phone" to the T-Bank backend.

    All four IDs are random UUIDv4 strings by default. They serve different
    roles in the auth flow:

    - :attr:`device_id` — sent as the ``device_id`` form field to
      ``auth/token`` and ``auth/token/mobile``.
    - :attr:`tinkoff_device_id` — sent as the ``device_id`` form field in
      ``auth/authorize``. The app sources this from a different provider
      than :attr:`device_id`, so they're kept separate even though both
      look like UUIDs.
    - :attr:`stable_id` — sent as the ``x-content-id`` header on
      authenticated endpoints. The real app fetches this from
      ``GET get_content``; for our purposes a random UUID is accepted.
    - :attr:`old_device_id` — sent alongside ``device_id`` to the refresh
      endpoint. On first use it's the same value as ``device_id``; when
      the app rotates device_id, the old one goes here.

    :attr:`device_model` and :attr:`build_fingerprint` are rendered into
    the ``User-Agent`` and the ``Build.*`` slots of the device fingerprint
    JSON sent during phone submission.
    """

    device_id: str
    tinkoff_device_id: str
    stable_id: str
    old_device_id: str
    device_model: str
    build_fingerprint: str

    # -------------------------------------------------------------------------
    # Construction
    # -------------------------------------------------------------------------

    @classmethod
    def generate(
        cls,
        *,
        device_model: str = DEFAULT_DEVICE_MODEL,
        build_fingerprint: str = DEFAULT_BUILD_FINGERPRINT,
    ) -> Identity:
        """Create a fresh :class:`Identity` with random UUIDs."""
        new = str(uuid.uuid4())
        return cls(
            device_id=new,
            tinkoff_device_id=str(uuid.uuid4()),
            stable_id=str(uuid.uuid4()),
            old_device_id=new,
            device_model=device_model,
            build_fingerprint=build_fingerprint,
        )

    # -------------------------------------------------------------------------
    # Storage helpers
    # -------------------------------------------------------------------------

    @classmethod
    def load_or_create(cls, state: State) -> Identity:
        """
        Return the persisted identity from ``state``, generating and
        saving a fresh one on first use. The persisted format is a plain
        dict with the same field names.
        """
        raw = state.read_identity()
        if raw is not None:
            return cls.from_dict(raw)
        identity = cls.generate()
        state.write_identity(asdict(identity))
        return identity

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Identity:
        return cls(
            device_id=str(data["device_id"]),
            tinkoff_device_id=str(data["tinkoff_device_id"]),
            stable_id=str(data["stable_id"]),
            old_device_id=str(data.get("old_device_id", data["device_id"])),
            device_model=str(data.get("device_model", DEFAULT_DEVICE_MODEL)),
            build_fingerprint=str(
                data.get("build_fingerprint", DEFAULT_BUILD_FINGERPRINT)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
