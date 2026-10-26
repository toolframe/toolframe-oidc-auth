# Development and verification

With matching SDK, Auth and SQLite packages installed in a Python 3.14 venv:

```sh
uv pip install --python .venv/bin/python --find-links ../wheelhouse -e .
uv pip install --python .venv/bin/python pytest pytest-asyncio ruff
.venv/bin/pytest -q
.venv/bin/ruff check src tests examples
```

Tests use real managed SQLite and Authlib grants. They cover PKCE rejection,
resource binding, one-use codes, refresh rotation/replay, browser-bound consent,
explicit denial, client registration and revocation. Core's coordinated suite
covers real workers, discovery, proxy authority and optional-provider outages;
the fixture script exercises an installed app through real FastMCP OAuth.
