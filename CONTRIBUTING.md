# Contributing to volt-watch

Thanks for contributing. `volt-watch` is a read-only security/health auditor; changes should be safe, testable, and evidence-backed.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip pytest
python -m pip install -e .
python -m pytest -q
```

## Expectations

- **TDD first**: write a failing test, implement the minimal fix, then verify.
- **Read-only by default**: checks must not change host state.
- **No secrets in evidence**: never include file contents, tokens, passwords, or private keys.
- **Unknown is not clean**: unreadable/failed readers should produce scoped unknown/degraded findings, not silent pass.
- **Small PRs**: include problem, acceptance criteria, tests, docs updates, and verification output.

## Reporting security issues

If you find a vulnerability in volt-watch itself or an unsafe reporting behavior (e.g. secret leakage in evidence), please avoid posting exploit details in a public issue before maintainers can assess. Open a private security advisory if available, or contact the maintainer through GitHub.

## Pull requests

- Add/update tests for behavior changes.
- Update `README.md` Checks/Privileges tables when adding or changing findings.
- Keep CI green on Python 3.10-3.14.
