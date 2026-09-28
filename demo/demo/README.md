# Local demonstration (safe fake data)

This folder is intentionally insecure **only as a scanner target**. It contains a
plainly fake key-like string and an old pinned dependency for lookup. Do not use
these examples as application code or install the pinned package. Nothing here
is a live credential. Scanning it makes a network request only if dependency
checking is enabled; the secrets-only path is fully offline.

From the repository root, install with `python -m pip install -e ".[dev]"` in a
virtual environment, then try:

```bash
sentinel-scan demo --no-deps --json
sentinel-scan demo --no-deps --fail-on medium
printf 'exit code: %s\n' "$?"   # 1 because the fake key-like string was found
sentinel-scan demo --markdown    # also queries OSV.dev for requests==2.6.0
```

In JSON, check `secrets`, `risk_score`, and `dependency_check_ok`. The offline
scan should show a `generic_secret_assignment` finding on `demo/example.py`.
The online result can change as OSV data changes. If OSV fails, the output
warns that the check is incomplete and the command exits 2. No known
vulnerabilities found is **not** a claim that the package is safe.

Run the automated checks with `ruff check .` and `pytest -q`. For your own
repository, replace `demo` with the directory to check and use `--history`
only when it is a git repository. The tool does not verify live credentials,
cover every dependency format, or replace a production secrets scanner.
