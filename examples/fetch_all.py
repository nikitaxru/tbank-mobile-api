#!/usr/bin/env python3
"""
Fetch all accounts and their operations for the last 30 days.

Reads the tokens previously persisted by ``login_interactive.py`` and
prints a per-account summary plus the most recent operations on each
non-external account. Auto-refreshes tokens transparently when they
are close to expiring.

Usage::

    python examples/fetch_all.py
    python examples/fetch_all.py --days 7
"""
from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path

from tbank import AccountType, OperationType, TBankClient
from tbank.errors import TBankInvalidStateError
from tbank.storage import FileStorage


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=30, help="lookback window in days (default 30)")
    parser.add_argument("--limit", type=int, default=10, help="max ops to print per account (default 10)")
    args = parser.parse_args()

    state_dir = Path(__file__).resolve().parent.parent / "state"
    with TBankClient(storage=FileStorage(state_dir)) as client:
        if not client.is_authenticated():
            print("Not authenticated. Run examples/login_interactive.py first.")
            return 1

        try:
            accounts = client.accounts.list()
        except TBankInvalidStateError as e:
            print(f"State error: {e}")
            return 1

        print(f"=== {len(accounts)} accounts ===")
        for acc in accounts:
            balance = f"{acc.balance.amount} {acc.balance.currency.name}" if acc.balance else "n/a"
            print(f"  [{acc.type}] {acc.name!r:<32} id={acc.id}  balance={balance}")

        end = dt.datetime.now(dt.UTC)
        start = end - dt.timedelta(days=args.days)

        for acc in accounts:
            if acc.type == AccountType.EXTERNAL_ACCOUNT:
                continue
            print()
            print(f"=== {acc.name} ({acc.id}) — last {args.days}d ===")
            ops = client.operations.list(account=acc.id, start=start, end=end)
            for op in ops[: args.limit]:
                sign = "-" if op.type == OperationType.DEBIT else "+"
                amount = f"{sign}{op.amount.amount} {op.amount.currency.name}"
                merchant = op.merchant.name if op.merchant else (op.description or "")
                print(f"  {op.time.strftime('%Y-%m-%d %H:%M')}  {amount:>18}  {merchant}")
            if len(ops) > args.limit:
                print(f"  … and {len(ops) - args.limit} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
