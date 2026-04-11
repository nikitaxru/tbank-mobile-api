# Examples

End-to-end demos of `tbank-mobile-api`.

| File | What it shows |
| --- | --- |
| [`login_interactive.py`](login_interactive.py) | First-time login. Walks the SMS flow on stdin and persists tokens to `./state/`. |
| [`custom_prompts.py`](custom_prompts.py) | Same flow, but with your own prompt callables — the integration shape for bots, GUIs, or web forms. |
| [`fetch_all.py`](fetch_all.py) | Reads stored tokens, lists all accounts, and prints the last 30 days of operations on each one. Auto-refresh handles expired access tokens. |

Run order on a fresh checkout:

```bash
python examples/login_interactive.py    # one-time
python examples/fetch_all.py             # repeat as needed
python examples/fetch_all.py --days 7
```

State (device identity + rotated tokens) lives under `./state/` next
to this directory. Move or delete it to reset.

