#!/usr/bin/env python3
"""
Drive ``login_interactive`` with custom prompt callables.

Useful when integrating into a non-stdin UI (Telegram bot, GUI, web
form, long-lived service): each prompt receives the typed step object
and returns the user's input string.

Run this with stub values to see the wiring; replace the lambdas with
your real I/O when integrating.
"""
from __future__ import annotations

from getpass import getpass
from pathlib import Path

from tbank import OtpStep, PasswordStep, TBankClient
from tbank.storage import FileStorage


def phone_prompt() -> str:
    return input("Phone (+7…): ").strip()


def otp_prompt(step: OtpStep) -> str:
    masked = step.phone_masked or "your phone"
    return input(f"Enter the {step.length}-digit code we sent to {masked}: ").strip()


def password_prompt(step: PasswordStep) -> str:
    return getpass(f"Password for {step.name or 'your account'}: ")


def main() -> None:
    state_dir = Path(__file__).resolve().parent.parent / "state"
    with TBankClient(storage=FileStorage(state_dir)) as client:
        if client.is_authenticated():
            print("Already authenticated.")
            return

        client.login_interactive(
            phone_prompt=phone_prompt,
            otp_prompt=otp_prompt,
            password_prompt=password_prompt,
        )
        print("Login complete.")


if __name__ == "__main__":
    main()
