#!/usr/bin/env python3
"""
First-time interactive login.

Walks through phone → SMS OTP → selfie skip → password and persists
the resulting tokens to ``./state/`` for the other examples to reuse.

Usage::

    python examples/login_interactive.py

You'll be prompted for phone, OTP, and password on stdin. Subsequent
runs of ``fetch_all.py`` will pick up the stored tokens automatically
and refresh them transparently as needed.
"""
from __future__ import annotations

from pathlib import Path

from tbank import TBankClient
from tbank.storage import FileStorage


def main() -> None:
    state_dir = Path(__file__).resolve().parent.parent / "state"
    with TBankClient(storage=FileStorage(state_dir)) as client:
        if client.is_authenticated():
            print(f"Already authenticated; tokens at {state_dir}/tokens.json")
            return

        tokens = client.login_interactive()
        print()
        print("Login successful.")
        print(f"  access_token  expires at {tokens.expires_at.isoformat()}")
        print("  refresh_token expires later (server keeps it valid for weeks)")
        print(f"  stored in    {state_dir}")


if __name__ == "__main__":
    main()
